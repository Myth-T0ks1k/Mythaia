package com.mythaia.data.network

import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.net.URL

private val logger = MythaiaLogger("FrontedHttp")

/**
 * A small HTTPS/1.1 GET that connects to one host while naming another.
 *
 * The platform client cannot do this: `HttpsURLConnection` derives the SNI
 * and the `Host` header from the URL, and neither can be pointed elsewhere.
 * The app's own TLS client can, so a subscription behind a blocked domain is
 * fetched by dialling the front (a CDN edge, an IP) with the front's name in
 * the ClientHello and the panel's name only inside the encrypted request.
 *
 * Deliberately minimal: one request, `Connection: close`, no redirects
 * followed (a redirect would leave the front), no compression asked for.
 */
object FrontedHttpClient {

    class Response(val status: Int, val headers: Map<String, String>, val body: ByteArray) {
        fun header(name: String): String? = headers[name.lowercase()]
    }

    private const val TIMEOUT_MS = 30_000L
    private const val MAX_HEADER_BYTES = 64 * 1024

    /**
     * @param url the subscription URL; its host goes in the `Host` header.
     * @param sni the name presented in TLS and used to verify the certificate.
     * @param target `host` or `host:port` to actually connect to.
     */
    suspend fun get(
        url: URL,
        sni: String,
        target: String,
        extraHeaders: Map<String, String>,
        allowInsecure: Boolean,
        maxBody: Int
    ): Response = withTimeout(TIMEOUT_MS) {
        val (targetHost, targetPort) = splitTarget(target, if (url.port > 0) url.port else 443)
        val tls = TlsConfiguration(
            serverName = sni,
            alpn = listOf("http/1.1"),
            allowInsecure = allowInsecure
        )
        val client = TlsClient(tls)
        val connection: TlsRecordConnection = client.connect(targetHost, targetPort)
        try {
            val path = buildString {
                append(url.path.ifEmpty { "/" })
                url.query?.let { append('?').append(it) }
            }
            val hostHeader = if (url.port > 0 && url.port != 443) "${url.host}:${url.port}" else url.host
            val request = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(hostHeader).append("\r\n")
                append("User-Agent: Mythaia\r\n")
                append("Accept: */*\r\n")
                for ((k, v) in extraHeaders) append(k).append(": ").append(v).append("\r\n")
                append("Connection: close\r\n\r\n")
            }
            connection.send(request.toByteArray(Charsets.US_ASCII))
            readResponse(connection, maxBody)
        } finally {
            runCatching { connection.cancel() }
        }
    }

    private fun splitTarget(target: String, defaultPort: Int): Pair<String, Int> {
        val t = target.trim()
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close > 0) {
                val host = t.substring(1, close)
                val rest = t.substring(close + 1)
                val port = rest.removePrefix(":").toIntOrNull() ?: defaultPort
                return host to port
            }
        }
        val colon = t.lastIndexOf(':')
        // One colon is host:port; more than one is a bare IPv6 literal.
        if (colon > 0 && t.indexOf(':') == colon) {
            val port = t.substring(colon + 1).toIntOrNull()
            if (port != null) return t.substring(0, colon) to port
        }
        return t to defaultPort
    }

    private suspend fun readResponse(connection: TlsRecordConnection, maxBody: Int): Response {
        val buffer = ByteArrayOutputStream()
        var headerEnd = -1
        while (headerEnd < 0) {
            val chunk = connection.receive() ?: break
            buffer.write(chunk)
            headerEnd = indexOfHeaderEnd(buffer.toByteArray())
            if (headerEnd < 0 && buffer.size() > MAX_HEADER_BYTES) {
                throw SubscriptionFetcher.FetchError.NetworkError("Response headers too large")
            }
        }
        if (headerEnd < 0) throw SubscriptionFetcher.FetchError.NetworkError("Connection closed before headers")

        val all = buffer.toByteArray()
        val headerText = String(all, 0, headerEnd, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        val statusLine = lines.firstOrNull() ?: ""
        val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull()
            ?: throw SubscriptionFetcher.FetchError.NetworkError("Malformed status line")
        val headers = HashMap<String, String>()
        for (line in lines.drop(1)) {
            val idx = line.indexOf(':')
            if (idx <= 0) continue
            headers[line.substring(0, idx).trim().lowercase()] = line.substring(idx + 1).trim()
        }

        val bodyStart = headerEnd + 4
        val body = ByteArrayOutputStream()
        body.write(all, bodyStart, all.size - bodyStart)

        val contentLength = headers["content-length"]?.toIntOrNull()
        val chunked = headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true

        fun ensureBounded() {
            if (body.size() > maxBody) {
                throw SubscriptionFetcher.FetchError.NetworkError("Response larger than $maxBody bytes")
            }
        }

        if (chunked) {
            while (!chunkedComplete(body.toByteArray())) {
                val chunk = connection.receive() ?: break
                body.write(chunk)
                ensureBounded()
            }
            return Response(status, headers, decodeChunked(body.toByteArray()))
        }

        if (contentLength != null) {
            while (body.size() < contentLength) {
                val chunk = connection.receive() ?: break
                body.write(chunk)
                ensureBounded()
            }
            val bytes = body.toByteArray()
            return Response(status, headers, if (bytes.size > contentLength) bytes.copyOf(contentLength) else bytes)
        }

        // Neither: the body runs until the server closes.
        while (true) {
            val chunk = connection.receive() ?: break
            body.write(chunk)
            ensureBounded()
        }
        return Response(status, headers, body.toByteArray())
    }

    private fun indexOfHeaderEnd(bytes: ByteArray): Int {
        for (i in 0..bytes.size - 4) {
            if (bytes[i] == '\r'.code.toByte() && bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() && bytes[i + 3] == '\n'.code.toByte()
            ) return i
        }
        return -1
    }

    /** True once the terminating zero-length chunk has arrived. */
    private fun chunkedComplete(bytes: ByteArray): Boolean =
        runCatching { decodeChunked(bytes); true }.getOrDefault(false)

    private fun decodeChunked(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        var pos = 0
        while (true) {
            val lineEnd = indexOfCrlf(bytes, pos)
            if (lineEnd < 0) throw IllegalStateException("incomplete chunk size")
            val sizeText = String(bytes, pos, lineEnd - pos, Charsets.ISO_8859_1).substringBefore(';').trim()
            val size = sizeText.toIntOrNull(16) ?: throw IllegalStateException("bad chunk size")
            pos = lineEnd + 2
            if (size == 0) return out.toByteArray()
            if (pos + size + 2 > bytes.size) throw IllegalStateException("incomplete chunk")
            out.write(bytes, pos, size)
            pos += size + 2
        }
    }

    private fun indexOfCrlf(bytes: ByteArray, from: Int): Int {
        for (i in from..bytes.size - 2) {
            if (bytes[i] == '\r'.code.toByte() && bytes[i + 1] == '\n'.code.toByte()) return i
        }
        return -1
    }

    /** Whether [message] looks like a failure of the front rather than of the panel. */
    fun describe(target: String, e: Throwable): String {
        logger.warning("Front $target failed: ${e.message ?: e}")
        return "$target: ${e.message ?: e.javaClass.simpleName}"
    }
}
