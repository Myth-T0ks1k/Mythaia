package com.mythaia.vpn.protocol

import com.mythaia.data.model.HttpTransportConfiguration
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.naive.http2.HpackEncoder
import com.mythaia.vpn.protocol.naive.http2.Http2PoolKey
import com.mythaia.vpn.protocol.naive.http2.Http2Session
import com.mythaia.vpn.protocol.naive.http2.Http2Stream
import com.mythaia.vpn.protocol.naive.http2.Http2StreamPool
import com.mythaia.vpn.protocol.naive.http2.Http2Wire
import com.mythaia.vpn.protocol.naive.http2.TlsRecordWire
import com.mythaia.vpn.protocol.reality.RealityClient
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap

/**
 * The V2Ray / sing-box `http` transport (`transport/v2rayhttp`):
 * - With TLS (or REALITY): a multiplexed HTTP/2 request stream (ALPN `h2`),
 *   default method `PUT` and default `:authority` `www.example.com` when no
 *   host list is configured.
 * - Without TLS: an HTTP/1.1 connection (`NewHTTP1Conn`) whose first write
 *   prepends `{method} {path} HTTP/1.1\r\nHost: {host}\r\n…\r\n\r\n` to the
 *   first payload in one write and whose first read consumes the `200 OK`
 *   response header before streaming raw bytes on the hijacked socket.
 */
object V2RayHttpTransport {

    private val unpooledScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private val pooledTlsVersions = ConcurrentHashMap<String, TlsVersion>()

    suspend fun open(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?,
        reality: RealityConfiguration? = configuration.reality
    ): StreamTransports.Opened {
        val http = configuration.httpTransport ?: HttpTransportConfiguration()
        return when {
            reality != null -> openHttp2Reality(configuration, http, reality, tunnel)
            tls != null -> openHttp2Tls(configuration, http, tls, tunnel)
            else -> openHttp1Plain(configuration, http, tunnel)
        }
    }

    private suspend fun openHttp2Tls(
        configuration: ProxyConfiguration,
        http: HttpTransportConfiguration,
        baseTls: TlsConfiguration,
        tunnel: ProxyConnection?
    ): StreamTransports.Opened {
        val h2Tls = baseTls.copy(alpn = listOf("h2"))
        val authority = pickAuthority(http, secure = true, configuration.serverAddress)
        val headers = encodeHttp2Headers(http, authority)
        val path = normalizedPath(http.path)

        if (tunnel == null) {
            val key = "http|" + Http2PoolKey.of(configuration, h2Tls, authority)
            val stream = Http2StreamPool.reserve(key, path) {
                val conn = TlsClient(h2Tls).connect(configuration.serverAddress, configuration.serverPort.toInt())
                pooledTlsVersions[key] = if (conn.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12
                TlsRecordWire(conn)
            }
            try {
                stream.openRequest(headers, endStream = false, awaitResponse = false)
            } catch (e: Exception) {
                stream.close()
                throw e
            }
            return StreamTransports.Opened(
                Http2StreamTransport(stream),
                pooledTlsVersions[key] ?: TlsVersion.TLS13
            )
        }

        var tlsVersion: TlsVersion = TlsVersion.TLS13
        return openUnpooledHttp2(headers, path) {
            val conn = TlsClient(h2Tls).connect(TunneledTransport(tunnel))
            tlsVersion = if (conn.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12
            TlsRecordWire(conn)
        }.let { StreamTransports.Opened(it, tlsVersion) }
    }

    private suspend fun openHttp2Reality(
        configuration: ProxyConfiguration,
        http: HttpTransportConfiguration,
        reality: RealityConfiguration,
        tunnel: ProxyConnection?
    ): StreamTransports.Opened {
        val authority = pickAuthority(http, secure = true, configuration.serverAddress)
        val headers = encodeHttp2Headers(http, authority)
        val path = normalizedPath(http.path)

        if (tunnel == null) {
            val key = "http|reality|${configuration.serverAddress}|${configuration.serverPort}|${reality.serverName}|$authority"
            val stream = Http2StreamPool.reserve(key, path) {
                TlsRecordWire(
                    RealityClient(reality).connect(configuration.serverAddress, configuration.serverPort.toInt())
                )
            }
            try {
                stream.openRequest(headers, endStream = false, awaitResponse = false)
            } catch (e: Exception) {
                stream.close()
                throw e
            }
            return StreamTransports.Opened(Http2StreamTransport(stream), TlsVersion.TLS13)
        }

        val transport = openUnpooledHttp2(headers, path) {
            TlsRecordWire(RealityClient(reality).connect(TunneledTransport(tunnel)))
        }
        return StreamTransports.Opened(transport, TlsVersion.TLS13)
    }

    internal suspend fun openUnpooledHttp2(
        headers: ByteArray,
        path: String,
        dial: suspend () -> Http2Wire
    ): Transport {
        val session = Http2Session(null, unpooledScope, null, null, dial)
        try {
            val stream = session.acquireStream(path)
            try {
                stream.openRequest(headers, endStream = false, awaitResponse = false)
            } catch (e: Exception) {
                stream.close()
                throw e
            }
            return Http2StreamTransport(stream, session)
        } catch (e: Exception) {
            runCatching { session.close() }
            throw e
        }
    }

    private suspend fun openHttp1Plain(
        configuration: ProxyConfiguration,
        http: HttpTransportConfiguration,
        tunnel: ProxyConnection?
    ): StreamTransports.Opened {
        val inner: Transport = if (tunnel != null) {
            TunneledTransport(tunnel)
        } else {
            NioSocket().also {
                it.connect(configuration.serverAddress, configuration.serverPort.toInt())
            }
        }
        val host = pickAuthority(http, secure = false, configuration.serverAddress)
        val prefix = encodeHttp1RequestPrefix(http, host)
        return StreamTransports.Opened(Http1ConnTransport(inner, prefix), null)
    }

    internal fun pickAuthority(
        http: HttpTransportConfiguration,
        secure: Boolean,
        serverAddress: String
    ): String {
        if (http.hosts.isNotEmpty()) return http.pickHost(secure, serverAddress)
        val headerHost = http.headers.entries.firstOrNull { it.key.equals("Host", ignoreCase = true) }?.value
            ?.trim()?.takeIf { it.isNotEmpty() }
        return headerHost ?: http.pickHost(secure, serverAddress)
    }

    internal fun normalizedPath(path: String): String {
        val trimmed = path.trim()
        return when {
            trimmed.isEmpty() -> "/"
            trimmed.startsWith("/") -> trimmed
            else -> "/$trimmed"
        }
    }

    internal fun encodeHttp2Headers(
        http: HttpTransportConfiguration,
        authority: String
    ): ByteArray {
        val method = http.method.trim().uppercase().ifEmpty { HttpTransportConfiguration.DEFAULT_METHOD }
        val path = normalizedPath(http.path)
        val list = ArrayList<Pair<String, String>>(4 + http.headers.size)
        list.add(":authority" to authority)
        list.add(":method" to method)
        list.add(":path" to path)
        list.add(":scheme" to "https")
        for ((k, v) in http.headers) {
            val name = k.trim().lowercase()
            if (name.isEmpty() || name == "host" || name.startsWith(":")) continue
            list.add(name to v)
        }
        return HpackEncoder.encodeHeaderBlock(list)
    }

    internal fun encodeHttp1RequestPrefix(
        http: HttpTransportConfiguration,
        host: String
    ): ByteArray {
        val method = http.method.trim().uppercase().ifEmpty { HttpTransportConfiguration.DEFAULT_METHOD }
        val path = normalizedPath(http.path)
        val sb = StringBuilder(128)
        sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(host).append("\r\n")
        for ((k, v) in http.headers) {
            val name = k.trim()
            if (name.isEmpty() || name.equals("Host", ignoreCase = true)) continue
            sb.append(name).append(": ").append(v).append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString().toByteArray(Charsets.UTF_8)
    }
}

internal class Http2StreamTransport(
    private val stream: Http2Stream,
    private val ownedSession: Http2Session? = null
) : Transport {
    private val asyncScope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1) + com.mythaia.vpn.tunnelCrashGuard)

    override suspend fun send(data: ByteArray) = stream.sendData(data)

    override fun sendAsync(data: ByteArray) {
        asyncScope.launch {
            runCatching { stream.sendData(data) }
        }
    }

    override suspend fun receive(): ByteArray? = stream.receiveData()

    override fun forceCancel() {
        asyncScope.cancel()
        stream.close()
        ownedSession?.close()
    }
}

/**
 * Plaintext HTTP/1.1 carrier matching sing-box's `v2rayhttp.HTTPConn`:
 * - First [send] prepends [requestPrefix] to the payload in a single write.
 * - First [receive] reads the HTTP/1.x response header, verifies status 200,
 *   and returns any bytes buffered after `\r\n\r\n`.
 */
internal class Http1ConnTransport(
    private val inner: Transport,
    private val requestPrefix: ByteArray
) : Transport {

    private val writeMutex = Mutex()
    private val readMutex = Mutex()
    private val asyncScope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1) + com.mythaia.vpn.tunnelCrashGuard)

    @Volatile
    private var requestWritten = false

    @Volatile
    private var responseRead = false

    override suspend fun send(data: ByteArray) {
        writeMutex.withLock {
            if (!requestWritten) {
                val combined = ByteArray(requestPrefix.size + data.size)
                System.arraycopy(requestPrefix, 0, combined, 0, requestPrefix.size)
                System.arraycopy(data, 0, combined, requestPrefix.size, data.size)
                inner.send(combined)
                requestWritten = true
            } else {
                inner.send(data)
            }
        }
    }

    override fun sendAsync(data: ByteArray) {
        asyncScope.launch {
            runCatching { send(data) }
        }
    }

    override suspend fun receive(): ByteArray? {
        readMutex.withLock {
            if (!responseRead) {
                val leftover = readResponseHeader()
                responseRead = true
                if (leftover.isNotEmpty()) return leftover
            }
            return inner.receive()
        }
    }

    private suspend fun readResponseHeader(): ByteArray {
        val buf = ByteArrayOutputStream(256)
        while (true) {
            val chunk = inner.receive()
                ?: throw ProxyError.ConnectionFailed("v2ray-http: unexpected EOF before response header")
            if (chunk.isEmpty()) {
                throw ProxyError.ConnectionFailed("v2ray-http: unexpected empty read before response header")
            }
            buf.write(chunk)
            val bytes = buf.toByteArray()
            val end = findHeaderEnd(bytes)
            if (end >= 0) {
                val headerText = String(bytes, 0, end, Charsets.ISO_8859_1)
                val statusLine = headerText.lineSequence().firstOrNull().orEmpty().trim()
                val parts = statusLine.split(' ', limit = 3)
                val code = if (parts.size >= 2 && parts[0].startsWith("HTTP/1.")) parts[1].toIntOrNull() else null
                if (code != 200) {
                    throw ProxyError.ProtocolError("v2ray-http: unexpected status: $statusLine")
                }
                val bodyStart = end + 4
                return if (bodyStart < bytes.size) bytes.copyOfRange(bodyStart, bytes.size) else ByteArray(0)
            }
            if (bytes.size > MAX_HEADER_BYTES) {
                throw ProxyError.ProtocolError("v2ray-http: response header exceeds $MAX_HEADER_BYTES bytes")
            }
        }
    }

    private fun findHeaderEnd(bytes: ByteArray): Int {
        for (i in 0..bytes.size - 4) {
            if (bytes[i] == '\r'.code.toByte() &&
                bytes[i + 1] == '\n'.code.toByte() &&
                bytes[i + 2] == '\r'.code.toByte() &&
                bytes[i + 3] == '\n'.code.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    override fun forceCancel() {
        asyncScope.cancel()
        inner.forceCancel()
    }

    private companion object {
        const val MAX_HEADER_BYTES = 16 * 1024
    }
}
