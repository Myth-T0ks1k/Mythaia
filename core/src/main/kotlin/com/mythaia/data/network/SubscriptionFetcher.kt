package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.zip.GZIPInputStream
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import com.mythaia.vpn.util.decodeBase64Lenient

object SubscriptionFetcher {

    /**
     * What a panel says about the subscription besides the servers: the keys
     * Remnawave, Marzban and 3x-ui send and Happ reads, from the headers or
     * from `#key: value` lines in the body. [SubscriptionMetadata] reads them
     * and folds them into the stored subscription.
     */
    data class PanelInfo(
        val title: String? = null,
        val userInfo: String? = null,
        val announce: String? = null,
        val supportUrl: String? = null,
        val webPageUrl: String? = null,
        val updateIntervalHours: Int? = null,
        val updateOnOpen: Boolean? = null,
        val autoUpdate: Boolean? = null,
        val requestTimeoutSeconds: Int? = null,
        val newUrl: String? = null,
        val newDomain: String? = null,
        val fallbackUrl: String? = null,
        /** Hosts to dial instead of the panel; null when the panel did not say. */
        val frontTargets: List<String>? = null,
        /** `fronting-target: off`: fetch straight from the panel again. */
        val frontingOff: Boolean = false,
        val frontSni: String? = null,
        /** Happ's `host`, beside a target: the panel's real host. */
        val frontHost: String? = null,
        val subInfo: Subscription.SubInfo? = null,
        val expireNotice: Boolean? = null,
        val expireButtonLink: String? = null
    )

    data class Result(
        val configurations: List<ProxyConfiguration>,
        val name: String?,
        val upload: Long?,
        val download: Long?,
        val total: Long?,
        val expire: Long?,
        val panel: PanelInfo = PanelInfo()
    )

    sealed class FetchError(message: String) : Exception(message) {
        class InvalidUrl : FetchError("Invalid subscription URL.")
        class NoConfigurations : FetchError("No valid configurations found in subscription.")
        class NetworkError(val detail: String) : FetchError("Network error: $detail")
    }

    private const val DEFAULT_TIMEOUT_MS = 30_000

    /** How long the main URL gets when there is a fallback to try; Happ moves on after about nine seconds. */
    private const val FALLBACK_AFTER_MS = 10_000

    /**
     * Fetches with the subscription's own fronting, timeout and fallback URL.
     *
     * @param via one of the user's servers to fetch through, for a panel that
     *   cannot be reached from here at all; null to fetch directly.
     * @param timeoutMs how long each URL gets; by default the panel's own
     *   `subscription-request-timeout`, shorter when a fallback URL waits.
     */
    suspend fun fetch(
        subscription: Subscription,
        remnawaveHWID: String? = null,
        via: ProxyConfiguration? = null,
        timeoutMs: Int? = null
    ): Result {
        val fallback = subscription.fallbackUrl?.takeIf { it != subscription.url }?.let { SubscriptionLink.parse(it) }
        val mainTimeoutMs = timeoutMs
            ?: subscription.requestTimeoutSeconds?.let { it * 1000 }
            ?: if (fallback != null) FALLBACK_AFTER_MS else DEFAULT_TIMEOUT_MS
        try {
            return fetch(
                urlString = subscription.url,
                remnawaveHWID = remnawaveHWID,
                frontSni = subscription.frontSni,
                frontTargets = subscription.frontTargets,
                via = via,
                timeoutMs = mainTimeoutMs
            )
        } catch (e: FetchError.NetworkError) {
            if (fallback == null) throw e
            try {
                return fetch(
                    urlString = fallback.url,
                    remnawaveHWID = remnawaveHWID,
                    frontSni = fallback.frontSni,
                    frontTargets = fallback.frontTargets,
                    via = via,
                    timeoutMs = timeoutMs ?: DEFAULT_TIMEOUT_MS
                )
            } catch (fallbackError: FetchError) {
                val why = (fallbackError as? FetchError.NetworkError)?.detail ?: fallbackError.message
                throw FetchError.NetworkError("${e.detail}; fallback URL: $why")
            }
        }
    }

    /**
     * @param allowInsecure skip certificate and hostname checks. Never tied
     *   to the proxy-server "allow insecure" setting: that one is about the
     *   user's own self-signed server, whereas an unverified subscription
     *   download lets anyone on the path replace every server in the list.
     * @param via see the overload above.
     */
    suspend fun fetch(
        urlString: String,
        allowInsecure: Boolean = false,
        remnawaveHWID: String? = null,
        frontSni: String? = null,
        frontTargets: List<String> = emptyList(),
        via: ProxyConfiguration? = null,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): Result = withContext(Dispatchers.IO) {
        val url = runCatching { URL(urlString) }.getOrNull()
            ?: throw FetchError.InvalidUrl()
        // URL() also accepts file: and ftp:, whose connections are not HTTP
        // and would fail the cast below with a ClassCastException.
        val https = url.protocol.equals("https", ignoreCase = true)
        if (!https && !url.protocol.equals("http", ignoreCase = true)) {
            throw FetchError.InvalidUrl()
        }

        val targets = frontTargets.map { it.trim() }.filter { it.isNotEmpty() }
        if (targets.isNotEmpty() && https) {
            return@withContext fetchFronted(url, frontSni?.trim()?.takeIf { it.isNotEmpty() } ?: url.host,
                targets, allowInsecure, remnawaveHWID, via, timeoutMs)
        }
        if (via != null) {
            // The server dials the panel itself; nothing else changes.
            val target = if (url.port > 0) "${url.host}:${url.port}" else url.host
            return@withContext fetchFronted(url, url.host, listOf(target), allowInsecure, remnawaveHWID, via, timeoutMs)
        }

        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.setRequestProperty("User-Agent", "Mythaia")
            if (remnawaveHWID != null) {
                connection.setRequestProperty("x-hwid", remnawaveHWID)
            }
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs

            // Accept self-signed certificates only when the caller has indicated allowInsecure.
            if (connection is HttpsURLConnection && allowInsecure) {
                val trustAllManager = object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}

                    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
                connection.sslSocketFactory = sslContext.socketFactory
                connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }

            val responseCode = try {
                connection.responseCode
            } catch (e: Exception) {
                throw FetchError.NetworkError(e.message ?: "Unknown error")
            }

            if (responseCode !in 200..299) {
                throw FetchError.NetworkError("HTTP $responseCode")
            }

            val data = gunzipIfNeeded(
                readBounded(connection.inputStream, MAX_BODY_BYTES),
                connection.getHeaderField("Content-Encoding")
            )

            // The same parsing the fronted path and a pasted body get; a copy
            // of it here once missed JSON subscriptions entirely. Secure is
            // judged on the URL the answer came from: redirects are followed.
            parseBody(
                data = data,
                header = { connection.getHeaderField(it) },
                secure = !allowInsecure && connection.url.protocol.equals("https", ignoreCase = true)
            )
        } finally {
            connection.disconnect()
        }
    }

    /** Panels do not serve lists this large; anything bigger is a misconfiguration, not a subscription. */
    private const val MAX_BODY_BYTES = 16 * 1024 * 1024

    /**
     * [body] decompressed when [contentEncoding] says it is gzip.
     *
     * Neither transport asks for compression, but some panels (and the CDNs
     * in front of them) gzip regardless, and HttpURLConnection only
     * decompresses on Android, and only when it added the Accept-Encoding
     * itself. The decoded size is bounded like the raw one.
     */
    internal fun gunzipIfNeeded(body: ByteArray, contentEncoding: String?): ByteArray {
        val encoding = contentEncoding?.trim()?.lowercase() ?: return body
        if (encoding != "gzip" && encoding != "x-gzip") return body
        return try {
            GZIPInputStream(body.inputStream()).use { readBounded(it, MAX_BODY_BYTES) }
        } catch (e: FetchError) {
            throw e
        } catch (e: java.io.IOException) {
            throw FetchError.NetworkError("Response is not valid gzip: ${e.message ?: e}")
        }
    }

    /**
     * Downloads through each front in turn until one answers.
     *
     * The response is parsed exactly as the direct path parses it; only the
     * transport differs. A target that fails moves on to the next; when all
     * fail, the error names the last one so the user can see which front is
     * dead rather than a generic "network error".
     */
    private suspend fun fetchFronted(
        url: URL,
        sni: String,
        targets: List<String>,
        allowInsecure: Boolean,
        remnawaveHWID: String?,
        via: ProxyConfiguration?,
        timeoutMs: Int
    ): Result {
        val extra = buildMap {
            if (remnawaveHWID != null) put("x-hwid", remnawaveHWID)
        }
        var lastError: String? = null
        for (target in targets) {
            val response = try {
                FrontedHttpClient.get(url, sni, target, extra, allowInsecure, MAX_BODY_BYTES, via, timeoutMs.toLong())
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                // withTimeout's own: this front was slow, the caller was not cancelled.
                lastError = FrontedHttpClient.describe(target, Exception("timed out"))
                continue
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                lastError = FrontedHttpClient.describe(target, e)
                continue
            }
            if (response.status !in 200..299) {
                lastError = "$target: HTTP ${response.status}"
                continue
            }
            return parseBody(
                data = gunzipIfNeeded(response.body, response.header("content-encoding")),
                header = { response.header(it) },
                secure = !allowInsecure && url.protocol.equals("https", ignoreCase = true)
            )
        }
        throw FetchError.NetworkError(lastError ?: "No front answered")
    }

    /** Parses a subscription body already in hand (pasted text, a file), exactly as a fetch would. */
    fun parse(data: ByteArray): Result = parseBody(data, header = { null }, secure = false)

    /**
     * The parsing shared by every transport. [header] reads the response
     * headers (case-insensitively); [secure] is whether they and the body
     * came over verified TLS.
     */
    private fun parseBody(data: ByteArray, header: (String) -> String?, secure: Boolean): Result {
        val (raw, bodyString) = decodeBodyText(data)
        // Metadata lines may sit inside a base64 body or above it in plain text.
        val fields = SubscriptionMetadata.bodyFields(bodyString).let { inner ->
            if (raw === bodyString) inner else SubscriptionMetadata.bodyFields(raw) + inner
        }
        val panel = SubscriptionMetadata.read(header, fields, secure)
        val profileTitle = panel.title
        val userInfo = parseUserInfoValue(panel.userInfo)

        // Built at most once and shared by the checks and importers below,
        // which each parsed the body again: three trees for a JSON
        // subscription of thousands of outbounds.
        val json by lazy { runCatching { XrayJsonImporter.parseJson(bodyString) }.getOrNull() }

        // sing-box first: its configs have `outbounds` too, and only the
        // shape of each outbound tells the two apart.
        if (SingBoxJsonImporter.looksLikeSingBox(bodyString) { json }) {
            val configurations = runCatching { json?.let { SingBoxJsonImporter.parse(it) } }.getOrNull().orEmpty()
            if (configurations.isEmpty()) throw FetchError.NoConfigurations()
            return Result(
                configurations = configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire,
                panel = panel
            )
        }

        if (XrayJsonImporter.looksLikeJson(bodyString)) {
            val configurations = runCatching { json?.let { XrayJsonImporter.parse(it) } }.getOrNull().orEmpty()
            if (configurations.isEmpty()) throw FetchError.NoConfigurations()
            return Result(
                configurations = configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire,
                panel = panel
            )
        }

        if (looksLikeClash(bodyString)) {
            val result = ClashProxyParser.parse(bodyString)
            if (result.configurations.isEmpty()) throw FetchError.NoConfigurations()
            return Result(
                configurations = result.configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire,
                panel = panel
            )
        }

        val parsablePrefixes = ProxyConfiguration.parsableUrlPrefixes
        // A line at a time: lines() split the whole body into a list up
        // front, and each step after it built another list.
        val configurations = bodyString
            .lineSequence()
            .map { it.trim() }
            .filter { line -> parsablePrefixes.any { line.startsWith(it) } }
            .mapNotNull { runCatching { ProxyConfiguration.fromUrl(it) }.getOrNull() }
            .toList()

        if (configurations.isEmpty()) throw FetchError.NoConfigurations()

        return Result(
            configurations = configurations,
            name = profileTitle,
            upload = userInfo.upload,
            download = userInfo.download,
            total = userInfo.total,
            expire = userInfo.expire,
            panel = panel
        )
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        // Filled chunk by chunk and joined once, at the exact size. A
        // ByteArrayOutputStream copied everything each time it grew and then
        // once more to hand it out, which near the cap is tens of megabytes
        // shuffled on a phone for one list of servers.
        val chunks = ArrayList<ByteArray>()
        var chunk = ByteArray(64 * 1024)
        var used = 0
        var total = 0
        while (true) {
            if (used == chunk.size) {
                chunks += chunk
                chunk = ByteArray(chunk.size)
                used = 0
            }
            val n = input.read(chunk, used, chunk.size - used)
            if (n < 0) break
            if (total + n > limit) throw FetchError.NetworkError("Response larger than $limit bytes")
            used += n
            total += n
        }
        val out = ByteArray(total)
        var at = 0
        for (full in chunks) {
            full.copyInto(out, at)
            at += full.size
        }
        chunk.copyInto(out, at, 0, used)
        return out
    }

    /**
     * The body as text: base64 (either alphabet) when decoding yields
     * something that reads as a share-link list or a Clash document, raw
     * UTF-8 otherwise.
     */
    internal fun decodeBody(data: ByteArray): String = decodeBodyText(data).second

    /**
     * The body as received, and as the list to parse: without its metadata
     * lines, and decoded when it was base64. The same instance twice when
     * there was nothing to take away.
     */
    private fun decodeBodyText(data: ByteArray): Pair<String, String> {
        val raw = String(data, Charsets.UTF_8)
        val prefixes = ProxyConfiguration.parsableUrlPrefixes
        fun recognisable(text: String) =
            prefixes.any { text.contains(it) } || looksLikeClash(text) || XrayJsonImporter.looksLikeJson(text)

        // Metadata lines (`#key: value`) are not the list: their links would
        // pass for share links, and around base64 they break the decoding.
        val payload = if (!raw.trimStart().startsWith('#') && !raw.contains("\n#")) raw
        else raw.lineSequence().filterNot { it.trimStart().startsWith('#') }.joinToString("\n")
        if (recognisable(payload)) return raw to payload

        for (urlSafe in booleanArrayOf(false, true)) {
            val decoded = runCatching { decodeBase64Lenient(payload, urlSafe) }.getOrNull() ?: continue
            val text = String(decoded, Charsets.UTF_8)
            if (recognisable(text)) return raw to text
        }
        return raw to raw
    }

    /** A Clash document has a top-level `proxies:` key, not merely the word somewhere. */
    internal fun looksLikeClash(text: String): Boolean =
        text.lineSequence().any { line ->
            val t = line.trimStart()
            t.startsWith("proxies:") || t.startsWith("proxy-providers:")
        }

    data class UserInfo(
        val upload: Long? = null,
        val download: Long? = null,
        val total: Long? = null,
        val expire: Long? = null
    )

    private fun parseUserInfoValue(value: String?): UserInfo {
        if (value == null) return UserInfo()

        var upload: Long? = null
        var download: Long? = null
        var total: Long? = null
        var expire: Long? = null

        for (part in value.split(";")) {
            val trimmed = part.trim()
            val kv = trimmed.split("=", limit = 2)
            if (kv.size != 2) continue
            val key = kv[0].trim()
            val v = kv[1].trim()

            when (key) {
                "upload" -> upload = v.toLongOrNull()
                "download" -> download = v.toLongOrNull()
                "total" -> total = v.toLongOrNull()
                "expire" -> expire = v.toLongOrNull()?.let { it * 1000 }
            }
        }

        return UserInfo(upload, download, total, expire)
    }
}
