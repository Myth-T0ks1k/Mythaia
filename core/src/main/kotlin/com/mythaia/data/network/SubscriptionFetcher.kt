package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import com.mythaia.vpn.util.decodeBase64Lenient

object SubscriptionFetcher {

    data class Result(
        val configurations: List<ProxyConfiguration>,
        val name: String?,
        val upload: Long?,
        val download: Long?,
        val total: Long?,
        val expire: Long?
    )

    sealed class FetchError(message: String) : Exception(message) {
        class InvalidUrl : FetchError("Invalid subscription URL.")
        class NoConfigurations : FetchError("No valid configurations found in subscription.")
        class NetworkError(message: String) : FetchError("Network error: $message")
    }

    /** Fetches with the subscription's own fronting settings. */
    suspend fun fetch(
        subscription: com.mythaia.data.model.Subscription,
        remnawaveHWID: String? = null
    ): Result = fetch(
        urlString = subscription.url,
        remnawaveHWID = remnawaveHWID,
        frontSni = subscription.frontSni,
        frontTargets = subscription.frontTargets
    )

    suspend fun fetch(
        urlString: String,
        allowInsecure: Boolean = CertificatePolicy.allowInsecure,
        remnawaveHWID: String? = null,
        frontSni: String? = null,
        frontTargets: List<String> = emptyList()
    ): Result = withContext(Dispatchers.IO) {
        val url = runCatching { URL(urlString) }.getOrNull()
            ?: throw FetchError.InvalidUrl()

        val targets = frontTargets.map { it.trim() }.filter { it.isNotEmpty() }
        if (targets.isNotEmpty() && url.protocol.equals("https", ignoreCase = true)) {
            return@withContext fetchFronted(url, frontSni?.trim()?.takeIf { it.isNotEmpty() } ?: url.host,
                targets, allowInsecure, remnawaveHWID)
        }

        val connection = url.openConnection() as HttpURLConnection
        try {
            connection.setRequestProperty("User-Agent", "Mythaia")
            if (remnawaveHWID != null) {
                connection.setRequestProperty("x-hwid", remnawaveHWID)
            }
            connection.connectTimeout = 30_000
            connection.readTimeout = 30_000

            // Accept self-signed certificates only when the caller has indicated allowInsecure.
            if (connection is HttpsURLConnection && allowInsecure) {
                // Reached only when the user has turned "allow insecure" on
                // for a panel on a self-signed host. Refusing to build it
                // would make that setting do nothing.
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

            val data = readBounded(connection.inputStream, MAX_BODY_BYTES)

            val profileTitle = parseProfileTitle(connection)
            val userInfo = parseSubscriptionUserInfo(connection)

            val bodyString = decodeBody(data)

            if (looksLikeClash(bodyString)) {
                val result = ClashProxyParser.parse(bodyString)
                if (result.configurations.isEmpty()) throw FetchError.NoConfigurations()
                return@withContext Result(
                    configurations = result.configurations,
                    name = profileTitle,
                    upload = userInfo.upload,
                    download = userInfo.download,
                    total = userInfo.total,
                    expire = userInfo.expire
                )
            }

            val parsablePrefixes = ProxyConfiguration.parsableUrlPrefixes
            val configurations = bodyString
                .lines()
                .map { it.trim() }
                .filter { line -> parsablePrefixes.any { line.startsWith(it) } }
                .mapNotNull { runCatching { ProxyConfiguration.fromUrl(it) }.getOrNull() }

            if (configurations.isEmpty()) throw FetchError.NoConfigurations()

            Result(
                configurations = configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire
            )
        } finally {
            connection.disconnect()
        }
    }

    /** Panels do not serve lists this large; anything bigger is a misconfiguration, not a subscription. */
    private const val MAX_BODY_BYTES = 16 * 1024 * 1024

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
        remnawaveHWID: String?
    ): Result {
        val extra = buildMap {
            if (remnawaveHWID != null) put("x-hwid", remnawaveHWID)
        }
        var lastError: String? = null
        for (target in targets) {
            val response = try {
                FrontedHttpClient.get(url, sni, target, extra, allowInsecure, MAX_BODY_BYTES)
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
                data = response.body,
                profileTitle = decodeProfileTitle(response.header("profile-title")),
                userInfo = parseUserInfoValue(response.header("subscription-userinfo"))
            )
        }
        throw FetchError.NetworkError(lastError ?: "No front answered")
    }

    /** The parsing shared by both transports. */
    private fun parseBody(data: ByteArray, profileTitle: String?, userInfo: UserInfo): Result {
        val bodyString = decodeBody(data)

        if (XrayJsonImporter.looksLikeJson(bodyString)) {
            val configurations = runCatching { XrayJsonImporter.parse(bodyString) }.getOrNull().orEmpty()
            if (configurations.isEmpty()) throw FetchError.NoConfigurations()
            return Result(
                configurations = configurations,
                name = profileTitle,
                upload = userInfo.upload,
                download = userInfo.download,
                total = userInfo.total,
                expire = userInfo.expire
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
                expire = userInfo.expire
            )
        }

        val parsablePrefixes = ProxyConfiguration.parsableUrlPrefixes
        val configurations = bodyString
            .lines()
            .map { it.trim() }
            .filter { line -> parsablePrefixes.any { line.startsWith(it) } }
            .mapNotNull { runCatching { ProxyConfiguration.fromUrl(it) }.getOrNull() }

        if (configurations.isEmpty()) throw FetchError.NoConfigurations()

        return Result(
            configurations = configurations,
            name = profileTitle,
            upload = userInfo.upload,
            download = userInfo.download,
            total = userInfo.total,
            expire = userInfo.expire
        )
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            if (out.size() + n > limit) throw FetchError.NetworkError("Response larger than $limit bytes")
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    /**
     * The body as text: base64 (either alphabet) when decoding yields
     * something that reads as a share-link list or a Clash document, raw
     * UTF-8 otherwise.
     */
    internal fun decodeBody(data: ByteArray): String {
        val raw = String(data, Charsets.UTF_8)
        val prefixes = ProxyConfiguration.parsableUrlPrefixes
        fun recognisable(text: String) =
            prefixes.any { text.contains(it) } || looksLikeClash(text) || XrayJsonImporter.looksLikeJson(text)
        if (recognisable(raw)) return raw

        for (urlSafe in booleanArrayOf(false, true)) {
            val decoded = runCatching { decodeBase64Lenient(raw, urlSafe) }.getOrNull() ?: continue
            val text = String(decoded, Charsets.UTF_8)
            if (recognisable(text)) return text
        }
        return raw
    }

    /** A Clash document has a top-level `proxies:` key, not merely the word somewhere. */
    internal fun looksLikeClash(text: String): Boolean =
        text.lineSequence().any { line ->
            val t = line.trimStart()
            t.startsWith("proxies:") || t.startsWith("proxy-providers:")
        }

    private fun parseProfileTitle(connection: HttpURLConnection): String? =
        decodeProfileTitle(connection.getHeaderField("profile-title"))

    private fun decodeProfileTitle(value: String?): String? {
        if (value == null) return null
        val decoded = if (value.startsWith("base64:")) {
            val encoded = value.removePrefix("base64:")
            runCatching {
                String(decodeBase64Lenient(encoded), Charsets.UTF_8)
            }.getOrNull()
        } else {
            value
        }
        // Servers commonly send an empty `Profile-Title: base64:` for unnamed
        // subscriptions. Treat blank results as missing so the call site falls
        // back to the URL host instead of an empty string.
        return decoded?.takeIf { it.isNotBlank() }
    }

    data class UserInfo(
        val upload: Long? = null,
        val download: Long? = null,
        val total: Long? = null,
        val expire: Long? = null
    )

    private fun parseSubscriptionUserInfo(connection: HttpURLConnection): UserInfo =
        parseUserInfoValue(connection.getHeaderField("subscription-userinfo"))

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
