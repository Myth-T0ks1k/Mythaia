package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.util.DnsCache
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
 * The same request can also go through one of the user's servers (`via`),
 * which is how a subscription whose panel is blocked outright still updates:
 * the server dials the panel, and TLS runs end to end inside the tunnel.
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
     * @param via a server of the user's to send the request through, or null
     *   to connect directly. Only with [via] may [url] be plain `http`.
     */
    suspend fun get(
        url: URL,
        sni: String,
        target: String,
        extraHeaders: Map<String, String>,
        allowInsecure: Boolean,
        maxBody: Int,
        via: ProxyConfiguration? = null,
        timeoutMs: Long = TIMEOUT_MS,
        userAgent: String = "Mythaia"
    ): Response = withTimeout(timeoutMs) {
        val https = url.protocol.equals("https", ignoreCase = true)
        require(https || via != null) { "plain HTTP needs a server to go through" }
        val (targetHost, targetPort) = splitTarget(target, if (url.port > 0) url.port else url.defaultPort)
        val opened = ArrayList<ProxyConnection>()
        var tlsClient: TlsClient? = null
        var record: TlsRecordConnection? = null
        try {
            val tunnel = via?.let { openTunnel(it, targetHost, targetPort, opened) }
            val send: suspend (ByteArray) -> Unit
            val receive: suspend () -> ByteArray?
            if (https) {
                val client = TlsClient(TlsConfiguration(serverName = sni, alpn = listOf("http/1.1"), allowInsecure = allowInsecure))
                tlsClient = client
                val connection = if (tunnel != null) client.connect(TunneledTransport(tunnel))
                else client.connect(targetHost, targetPort)
                record = connection
                send = { connection.send(it) }
                receive = { connection.receive() }
            } else {
                val plain = checkNotNull(tunnel)
                send = { plain.send(it) }
                receive = { plain.receive() }
            }
            val path = buildString {
                append(url.path.ifEmpty { "/" })
                url.query?.let { append('?').append(it) }
            }
            val hostHeader = if (url.port > 0 && url.port != url.defaultPort) "${url.host}:${url.port}" else url.host
            val request = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(hostHeader).append("\r\n")
                append("User-Agent: ").append(userAgent).append("\r\n")
                append("Accept: */*\r\n")
                for ((k, v) in extraHeaders) append(k).append(": ").append(v).append("\r\n")
                append("Connection: close\r\n\r\n")
            }
            send(request.toByteArray(Charsets.US_ASCII))
            readResponse(receive, maxBody)
        } finally {
            record?.let { runCatching { it.cancel() } } ?: tlsClient?.let { runCatching { it.cancel() } }
            opened.asReversed().forEach { runCatching { it.cancel() } }
        }
    }

    /**
     * A stream to [host]:[port] through [config], hop by hop when it is a
     * chain. Server names are resolved first, as the latency test does, so
     * the dial does not wait on DNS through a tunnel that may be the problem.
     */
    private suspend fun openTunnel(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        opened: MutableList<ProxyConnection>
    ): ProxyConnection {
        fun resolved(c: ProxyConfiguration): ProxyConfiguration =
            if (c.resolvedIP != null || DnsCache.isIpAddress(c.serverAddress)) c
            else DnsCache.resolveHost(c.serverAddress)?.let { c.copy(resolvedIP = it) } ?: c
        val last = resolved(config)
        val chain = config.chain.orEmpty().map { resolved(it) }
        var tunnel: ProxyConnection? = null
        for (i in chain.indices) {
            val next = if (i + 1 < chain.size) chain[i + 1] else last
            tunnel = ProxyClientFactory.connect(chain[i], next.connectAddress, next.serverPort.toInt(), tunnel = tunnel)
                .also { opened += it }
        }
        return ProxyClientFactory.connect(last, host, port, tunnel = tunnel).also { opened += it }
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

    private suspend fun readResponse(receive: suspend () -> ByteArray?, maxBody: Int): Response {
        val buffer = ByteArrayOutputStream()
        var headerEnd = -1
        while (headerEnd < 0) {
            val chunk = receive() ?: break
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
        val body = BodyBuffer()
        body.write(all, bodyStart, all.size - bodyStart)

        val contentLength = headers["content-length"]?.toIntOrNull()
        val chunked = headers["transfer-encoding"]?.contains("chunked", ignoreCase = true) == true

        fun ensureBounded() {
            if (body.size() > maxBody) {
                throw SubscriptionFetcher.FetchError.NetworkError("Response larger than $maxBody bytes")
            }
        }

        if (chunked) {
            // The full check walks the whole body, so it only runs once the
            // tail looks like the end of one; before the gate it ran after
            // every TLS record, quadratic in the body size.
            while (!(mayEndChunkedBody(body) && chunkedComplete(body.toByteArray()))) {
                val chunk = receive() ?: break
                body.write(chunk)
                ensureBounded()
            }
            return Response(status, headers, decodeChunked(body.toByteArray()))
        }

        if (contentLength != null) {
            while (body.size() < contentLength) {
                val chunk = receive() ?: break
                body.write(chunk)
                ensureBounded()
            }
            val bytes = body.toByteArray()
            return Response(status, headers, if (bytes.size > contentLength) bytes.copyOf(contentLength) else bytes)
        }

        // Neither: the body runs until the server closes.
        while (true) {
            val chunk = receive() ?: break
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

    /** A body buffer whose tail can be inspected without copying the whole thing. */
    private class BodyBuffer : ByteArrayOutputStream() {
        fun byteAt(index: Int): Byte = buf[index]
    }

    private const val CR = '\r'.code.toByte()
    private const val LF = '\n'.code.toByte()

    /** How far back from the end a zero-size chunk line is looked for; trailers, if any, sit in between. */
    private const val CHUNK_END_WINDOW = 4096

    /**
     * Whether [body] could be a complete chunked body: it ends with the blank
     * line that closes one, and a line that is just `0` (or `0;extension`)
     * sits within the last stretch. Chunk data can mimic that, so it is a
     * gate in front of [chunkedComplete], not a replacement for it.
     */
    private fun mayEndChunkedBody(body: BodyBuffer): Boolean {
        val n = body.size()
        if (n < 5) return false
        if (body.byteAt(n - 4) != CR || body.byteAt(n - 3) != LF ||
            body.byteAt(n - 2) != CR || body.byteAt(n - 1) != LF
        ) return false
        val earliest = maxOf(0, n - CHUNK_END_WINDOW)
        for (i in n - 5 downTo earliest) {
            if (body.byteAt(i) != '0'.code.toByte()) continue
            if (i > 0 && body.byteAt(i - 1) != LF) continue
            val next = body.byteAt(i + 1)
            if (next == CR || next == ';'.code.toByte()) return true
        }
        return false
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
        val why = (e as? SubscriptionFetcher.FetchError.NetworkError)?.detail ?: e.message ?: e.javaClass.simpleName
        return "$target: $why"
    }
}
