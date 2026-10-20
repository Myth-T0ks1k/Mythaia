package com.mythaia.data.routing

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.FrontedHttpClient
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

private val logger = MythaiaLogger("Routing")

/**
 * The geosite and geoip files routing profiles name, one file per URL in
 * [dir], so two profiles naming the same release share one download.
 */
class GeoFileStore(val dir: File) {

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
            if (file.name.startsWith("geo-") && file.name !in wanted) runCatching { file.delete() }
        }
    }

    private suspend fun download(url: String, via: ProxyConfiguration?) = withContext(Dispatchers.IO) {
        // A timeout is this fetch failing, not the caller being cancelled.
        val bytes = withTimeoutOrNull(TIMEOUT_MS) {
            if (via == null) runInterruptible { fetchDirect(url) } else fetchThrough(url, via)
        } ?: throw IOException("no answer within ${TIMEOUT_MS / 60_000} minutes")
        run {
            if (!V2rayGeoFile.looksValid(bytes.inputStream())) throw IOException("not a geosite/geoip file")
            dir.mkdirs()
            val target = fileFor(url)
            val temp = File(dir, target.name + ".tmp")
            temp.writeBytes(bytes)
            if (target.exists() && !target.delete()) {
                temp.delete()
                throw IOException("the old file is in use")
            }
            if (!temp.renameTo(target)) {
                temp.delete()
                throw IOException("could not move the file into place")
            }
            logger.info("[Routing] Fetched ${url.substringAfterLast('/')} (${bytes.size / 1024} KiB)")
        }
    }

    private fun fetchDirect(url: String): ByteArray {
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
                return connection.inputStream.use { readBounded(it) }
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("too many redirects")
    }

    private suspend fun fetchThrough(url: String, server: ProxyConfiguration): ByteArray {
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
            return response.body
        }
        throw IOException("too many redirects")
    }

    private fun readBounded(input: java.io.InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            total += n
            if (total > MAX_BYTES) throw IOException("file larger than $MAX_BYTES bytes")
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
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
