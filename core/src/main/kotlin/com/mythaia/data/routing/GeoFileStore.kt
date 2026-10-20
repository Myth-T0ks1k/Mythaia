package com.mythaia.data.routing

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.FrontedHttpClient
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

private val logger = MythaiaLogger("Routing")

/**
 * The geosite and geoip files routing profiles name, one file per URL in
 * [dir], so two profiles naming the same release share one download.
 */
class GeoFileStore(val dir: File) {

    private val locks = ConcurrentHashMap<String, Mutex>()

    /** Where [url]'s file lives, whether or not it has been fetched. */
    fun fileFor(url: String): File = File(dir, "geo-" + sha256(url).take(16) + ".dat")

    fun has(url: String): Boolean = fileFor(url).let { it.isFile && it.length() > 0 }

    /** Whether every file [profile] needs is on disk. */
    fun ready(profile: RoutingProfile): Boolean = profile.geoFileUrls.all { has(it) }

    /** [profile]'s geosite file, when it has one on disk. */
    fun geosite(profile: RoutingProfile): File? = profile.geositeUrl?.let { fileFor(it) }?.takeIf { it.isFile }

    /** [profile]'s geoip file, when it has one on disk. */
    fun geoip(profile: RoutingProfile): File? = profile.geoipUrl?.let { fileFor(it) }?.takeIf { it.isFile }

    /**
     * Fetches every file [profile] needs. Each is tried directly, then
     * through the servers [via] returns (asked only when the direct fetch
     * failed), and replaces the old file only once it is whole and reads as
     * a rule file. Returns null when all arrived, else why not.
     */
    suspend fun fetch(
        profile: RoutingProfile,
        via: suspend () -> List<ProxyConfiguration> = { emptyList() }
    ): String? {
        var servers: List<ProxyConfiguration>? = null
        for (url in profile.geoFileUrls) {
            var error = runCatching { download(url, null) }.exceptionOrNull()
            if (error is CancellationException) throw error
            if (error != null) {
                logger.warning("[Routing] $url directly: ${error.message ?: error}")
                val list = servers ?: runCatching { via() }.getOrDefault(emptyList()).also { servers = it }
                for (server in list) {
                    val failure = runCatching { download(url, server) }.exceptionOrNull()
                    if (failure == null) {
                        error = null
                        break
                    }
                    if (failure is CancellationException) throw failure
                    error = failure
                    logger.warning("[Routing] $url through ${server.name}: ${failure.message ?: failure}")
                }
            }
            if (error != null) return "${url.substringAfterLast('/')}: ${error.message ?: error}"
        }
        return null
    }

    /** Deletes the files no URL in [keep] points at. */
    fun prune(keep: Collection<String>) {
        val wanted = keep.map { fileFor(it).name }.toSet()
        dir.listFiles()?.forEach { file ->
            if (file.name.startsWith("geo-") && !file.name.endsWith(".tmp") && file.name !in wanted) {
                runCatching { file.delete() }
            }
        }
    }

    private suspend fun download(url: String, via: ProxyConfiguration?) {
        val target = fileFor(url)
        val mutex = locks.computeIfAbsent(target.name) { Mutex() }
        mutex.withLock {
            withContext(Dispatchers.IO) {
                dir.mkdirs()
                val temp = File(dir, target.name + ".tmp")
                try {
                    // A timeout is this fetch failing, not the caller being cancelled.
                    val size = withTimeoutOrNull(TIMEOUT_MS) {
                        if (via == null) runInterruptible { fetchDirect(url, temp) } else fetchThrough(url, via, temp)
                    } ?: throw IOException("no answer within ${TIMEOUT_MS / 60_000} minutes")
                    installVerified(temp, target)
                    logger.info("[Routing] Fetched ${url.substringAfterLast('/')} (${size / 1024} KiB)")
                } finally {
                    if (temp.exists()) runCatching { temp.delete() }
                }
            }
        }
    }

    private fun fetchDirect(url: String, dest: File): Long {
        var current = URL(url)
        repeat(MAX_REDIRECTS) {
            if (!current.protocol.equals("https", ignoreCase = true)) throw IOException("not HTTPS")
            val connection = current.openConnection() as HttpURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = CONNECT_TIMEOUT_MS
                connection.readTimeout = READ_TIMEOUT_MS
                connection.setRequestProperty("User-Agent", "Mythaia")
                val status = connection.responseCode
                if (status in 300..399) {
                    val location = connection.getHeaderField("Location") ?: throw IOException("HTTP $status without Location")
                    current = URL(current, location)
                    return@repeat
                }
                if (status !in 200..299) throw IOException("HTTP $status")
                val length = connection.contentLengthLong
                if (length > MAX_BYTES) throw IOException("file of $length bytes")
                return connection.inputStream.use { streamBounded(it, dest, length) }
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("too many redirects")
    }

    private suspend fun fetchThrough(url: String, server: ProxyConfiguration, dest: File): Long {
        var current = URL(url)
        repeat(MAX_REDIRECTS) {
            if (!current.protocol.equals("https", ignoreCase = true)) throw IOException("not HTTPS")
            val target = if (current.port > 0) "${current.host}:${current.port}" else current.host
            val response = try {
                FrontedHttpClient.get(
                    current, current.host, target, emptyMap(), allowInsecure = false,
                    maxBody = MAX_BYTES.toInt(), via = server, timeoutMs = TIMEOUT_MS
                )
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                throw IOException("timed out")
            }
            if (response.status in 300..399) {
                val location = response.header("location") ?: throw IOException("HTTP ${response.status} without Location")
                current = URL(current, location)
                return@repeat
            }
            if (response.status !in 200..299) throw IOException("HTTP ${response.status}")
            return response.body.inputStream().use { streamBounded(it, dest) }
        }
        throw IOException("too many redirects")
    }

    internal fun streamBounded(input: java.io.InputStream, dest: File, expectedLength: Long = -1L): Long {
        dest.outputStream().use { out ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                total += n
                if (total > MAX_BYTES) throw IOException("file larger than $MAX_BYTES bytes")
                out.write(buffer, 0, n)
            }
            if (expectedLength > 0 && total != expectedLength) {
                throw IOException("truncated download ($total of $expectedLength bytes)")
            }
            return total
        }
    }

    /**
     * Checks that [temp] is a valid rule file and atomically replaces
     * [target] with it, leaving an existing [target] untouched on failure.
     */
    internal fun installVerified(temp: File, target: File) {
        if (!temp.isFile || !temp.inputStream().use { V2rayGeoFile.looksValid(it) }) {
            temp.delete()
            throw IOException("not a geosite/geoip file")
        }
        val src = temp.toPath()
        val dst = target.toPath()
        try {
            Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: IOException) {
            Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    companion object {
        /** Happ gives a download three minutes. */
        const val TIMEOUT_MS = 3 * 60 * 1000L
        private const val CONNECT_TIMEOUT_MS = 20_000
        private const val READ_TIMEOUT_MS = 60_000
        private const val MAX_REDIRECTS = 6
        /** The largest published geoip.dat is about 20 MB. */
        const val MAX_BYTES = 64L * 1024 * 1024

        private fun sha256(text: String): String =
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
    }
}
