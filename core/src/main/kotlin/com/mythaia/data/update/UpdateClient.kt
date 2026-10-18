package com.mythaia.data.update

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.FrontedHttpClient
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import kotlin.coroutines.coroutineContext

private val logger = MythaiaLogger("Update")

/**
 * A way to reach GitHub: straight out, through a local proxy port (the
 * Windows app's own), or through one of the user's servers. GitHub is not
 * reachable from every network, so an update goes down the list until one
 * answers.
 */
sealed class UpdateRoute {
    object Direct : UpdateRoute() {
        override fun toString() = "direct"
    }

    class LocalProxy(val proxy: Proxy) : UpdateRoute() {
        override fun toString() = "local proxy ${proxy.address()}"
    }

    class Through(val server: ProxyConfiguration) : UpdateRoute() {
        override fun toString() = "through ${server.name}"
    }
}

/** What went wrong, in words the update screen can show as they are. */
open class UpdateException(message: String, cause: Throwable? = null) : IOException(message, cause)

/** A file that arrived whole but is not the one the release lists. Another route would bring the same file. */
class ChecksumMismatch(message: String) : UpdateException(message)

/**
 * The network half of the self-updater, shared by the phone and the desktop:
 * read the latest release, its checksums, and download one asset with its
 * SHA-256 checked before anything else sees the file.
 */
object UpdateClient {

    const val MAX_RELEASE_BYTES = 1L shl 20
    const val MAX_CHECKSUM_BYTES = 64L * 1024
    const val MAX_APK_BYTES = 128L shl 20
    const val MAX_WINDOWS_BYTES = 512L shl 20

    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 30_000
    private const val THROUGH_TIMEOUT_MS = 10 * 60_000L
    private const val MAX_REDIRECTS = 5

    /** Lets the tests serve files over plain HTTP from a local server. Never set in the apps. */
    internal var allowPlainHttp = false

    /** The latest published release, by the first route that answers. */
    suspend fun latest(routes: List<UpdateRoute>): Release {
        val body = firstThatWorks(routes) { route ->
            String(fetchBytes(route, Releases.LATEST_API_URL, MAX_RELEASE_BYTES, mapOf("Accept" to "application/vnd.github+json")), Charsets.UTF_8)
        }.first
        return try {
            Releases.parse(body)
        } catch (e: IllegalArgumentException) {
            throw UpdateException(e.message ?: "Not a release", e)
        }
    }

    /** The release's SHA256SUMS.txt, file name to hex. */
    suspend fun checksums(release: Release, routes: List<UpdateRoute>): Map<String, String> {
        val asset = release.asset(Releases.CHECKSUMS_ASSET)
            ?: throw UpdateException("The release has no ${Releases.CHECKSUMS_ASSET}")
        val text = firstThatWorks(routes) { route ->
            String(fetchBytes(route, asset.downloadUrl, MAX_CHECKSUM_BYTES), Charsets.UTF_8)
        }.first
        return Releases.parseChecksums(text)
    }

    /**
     * The SHA-256 [asset] must have: the one in the release's checksum file,
     * which GitHub's own digest of the upload, when it gives one, has to agree
     * with. A release without a checksum for the file is not installed.
     */
    fun expectedSha256(asset: ReleaseAsset, checksums: Map<String, String>): String {
        val listed = checksums[asset.name]
            ?: throw UpdateException("${Releases.CHECKSUMS_ASSET} has no entry for ${asset.name}")
        if (asset.sha256 != null && asset.sha256 != listed) {
            throw UpdateException("${asset.name}: GitHub's digest and ${Releases.CHECKSUMS_ASSET} disagree")
        }
        return listed
    }

    /**
     * Downloads [asset] to [dest] by the first route that delivers a file
     * with [expectedSha256]. A file that arrives with any other hash is
     * deleted, never kept "to try anyway".
     *
     * @param onProgress bytes so far and the total, or -1 when unknown.
     * @return the route that worked.
     */
    suspend fun download(
        asset: ReleaseAsset,
        expectedSha256: String,
        dest: File,
        routes: List<UpdateRoute>,
        maxBytes: Long,
        onProgress: (Long, Long) -> Unit = { _, _ -> }
    ): UpdateRoute {
        if (asset.size > maxBytes) throw UpdateException("${asset.name} is too large (${asset.size} bytes)")
        dest.parentFile?.mkdirs()
        val partial = File(dest.parentFile, dest.name + ".part")
        return firstThatWorks(routes) { route ->
            try {
                val hash = when (route) {
                    is UpdateRoute.Through -> {
                        onProgress(0, -1)
                        val bytes = fetchBytes(route, asset.downloadUrl, maxBytes)
                        partial.writeBytes(bytes)
                        onProgress(bytes.size.toLong(), bytes.size.toLong())
                        sha256Hex(bytes)
                    }
                    else -> streamToFile(route, asset.downloadUrl, partial, maxBytes, onProgress)
                }
                if (hash != expectedSha256) {
                    throw ChecksumMismatch("${asset.name}: the checksum does not match")
                }
                if (dest.exists()) dest.delete()
                if (!partial.renameTo(dest)) throw UpdateException("Could not save ${asset.name}")
            } finally {
                partial.delete()
            }
        }.second
    }

    /** Runs [block] on each route in turn; the last failure is the one reported. */
    private suspend fun <T> firstThatWorks(
        routes: List<UpdateRoute>,
        block: suspend (UpdateRoute) -> T
    ): Pair<T, UpdateRoute> {
        require(routes.isNotEmpty())
        var last: Exception? = null
        for (route in routes) {
            try {
                return block(route) to route
            } catch (e: CancellationException) {
                throw e
            } catch (e: ChecksumMismatch) {
                throw e
            } catch (e: Exception) {
                logger.warning("[Update] $route: ${e.message ?: e}")
                last = e
            }
        }
        throw last as? UpdateException ?: UpdateException(describe(last), last)
    }

    private fun describe(e: Exception?): String = when (e) {
        null -> "No route to GitHub"
        is java.net.UnknownHostException -> "GitHub could not be resolved"
        is java.net.SocketTimeoutException -> "GitHub did not answer in time"
        is javax.net.ssl.SSLException -> "The secure connection to GitHub failed"
        else -> e.message ?: e.toString()
    }

    private suspend fun fetchBytes(
        route: UpdateRoute,
        url: String,
        maxBytes: Long,
        headers: Map<String, String> = emptyMap()
    ): ByteArray = when (route) {
        is UpdateRoute.Through -> fetchThrough(route.server, url, maxBytes)
        else -> {
            val sink = java.io.ByteArrayOutputStream()
            withContext(Dispatchers.IO) {
                open(route, url, headers).useBody(maxBytes, { _, _ -> }) { chunk, length -> sink.write(chunk, 0, length) }
            }
            sink.toByteArray()
        }
    }

    private suspend fun streamToFile(
        route: UpdateRoute,
        url: String,
        file: File,
        maxBytes: Long,
        onProgress: (Long, Long) -> Unit
    ): String = withContext(Dispatchers.IO) {
        val digest = MessageDigest.getInstance("SHA-256")
        file.outputStream().buffered().use { out ->
            open(route, url, emptyMap()).useBody(maxBytes, onProgress) { chunk, length ->
                digest.update(chunk, 0, length)
                out.write(chunk, 0, length)
            }
        }
        digest.digest().toHex()
    }

    private fun open(route: UpdateRoute, url: String, headers: Map<String, String>): HttpURLConnection {
        val proxy = (route as? UpdateRoute.LocalProxy)?.proxy ?: Proxy.NO_PROXY
        val connection = URL(url).openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.instanceFollowRedirects = true
        connection.setRequestProperty("User-Agent", "Mythaia")
        for ((k, v) in headers) connection.setRequestProperty(k, v)
        return connection
    }

    private suspend fun HttpURLConnection.useBody(
        maxBytes: Long,
        onProgress: (Long, Long) -> Unit,
        consume: (ByteArray, Int) -> Unit
    ) {
        try {
            val status = responseCode
            if (status != 200) throw UpdateException(statusMessage(status))
            // A redirect may only ever land on HTTPS.
            if (url.protocol != "https" && !allowPlainHttp) throw UpdateException("GitHub redirected to an insecure address")
            val total = contentLengthLong
            if (total > maxBytes) throw UpdateException("The file is too large ($total bytes)")
            var done = 0L
            val buffer = ByteArray(64 * 1024)
            inputStream.use { input ->
                while (true) {
                    coroutineContext.ensureActive()
                    val n = input.read(buffer)
                    if (n < 0) break
                    done += n
                    if (done > maxBytes) throw UpdateException("The file is too large")
                    consume(buffer, n)
                    onProgress(done, total)
                }
            }
            if (total >= 0 && done != total) throw UpdateException("The download was cut short")
        } finally {
            disconnect()
        }
    }

    /**
     * The same GET through [server], following GitHub's redirect to its file
     * host by hand: the fronted client does not follow them itself.
     */
    private suspend fun fetchThrough(server: ProxyConfiguration, url: String, maxBytes: Long): ByteArray {
        var current = URL(url)
        repeat(MAX_REDIRECTS + 1) {
            if (current.protocol != "https") throw UpdateException("GitHub redirected to an insecure address")
            val response = FrontedHttpClient.get(
                url = current,
                sni = current.host,
                target = current.host,
                extraHeaders = emptyMap(),
                allowInsecure = false,
                maxBody = maxBytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                via = server,
                timeoutMs = THROUGH_TIMEOUT_MS
            )
            when (response.status) {
                200 -> return response.body
                301, 302, 303, 307, 308 -> {
                    val location = response.header("location") ?: throw UpdateException("Redirect without a location")
                    current = URL(current, location)
                }
                else -> throw UpdateException(statusMessage(response.status))
            }
        }
        throw UpdateException("Too many redirects")
    }

    private fun statusMessage(status: Int): String = when (status) {
        403, 429 -> "GitHub refused the request for now (HTTP $status); try again later"
        404 -> "Not found on GitHub (HTTP 404)"
        else -> "GitHub answered HTTP $status"
    }

    fun sha256Hex(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return digest.digest().toHex()
    }

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
