package com.mythaia.vpn.protocol

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.XHttpMode
import com.mythaia.vpn.protocol.grpc.GrpcClient
import com.mythaia.vpn.protocol.grpc.GrpcConnection
import com.mythaia.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordTransport
import com.mythaia.vpn.protocol.websocket.WebSocketConnection
import com.mythaia.vpn.protocol.xhttp.TransportClosures
import com.mythaia.vpn.protocol.xhttp.XHttpConnection
import com.mythaia.vpn.util.NioSocket
import java.util.UUID

/**
 * The byte pipe a stream protocol (VMess, Trojan) runs on: TCP or the chain
 * tunnel, TLS when asked, and the configured transport on top — WebSocket,
 * HTTPUpgrade, gRPC or XHTTP — the same four VLESS speaks. Reality is
 * VLESS-only and is not offered here.
 */
object StreamTransports {

    /** An open pipe and the TLS version it runs over, when it does. */
    class Opened(val transport: Transport, val tlsVersion: TlsVersion?)

    suspend fun open(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?
    ): Opened {
        val transport = configuration.transport.ifEmpty { "tcp" }
        return when (transport) {
            "tcp" -> stream(configuration, tls, tunnel)
            "ws" -> {
                val ws = configuration.websocket
                    ?: throw ProxyError.ConnectionFailed("ws transport with no WebSocket configuration")
                val inner = stream(configuration, tls?.let(::http11Only), tunnel)
                wrap(inner) {
                    val connection = WebSocketConnection(transport = inner.transport, configuration = ws)
                    connection.performUpgrade()
                    object : Transport {
                        override suspend fun send(data: ByteArray) = connection.send(data)
                        override fun sendAsync(data: ByteArray) = connection.sendAsync(data)
                        override suspend fun receive(): ByteArray? = connection.receive()
                        override fun forceCancel() = connection.cancel()
                    }
                }
            }
            "httpupgrade" -> {
                val hu = configuration.httpUpgrade
                    ?: throw ProxyError.ConnectionFailed("httpupgrade transport with no configuration")
                val inner = stream(configuration, tls?.let(::http11Only), tunnel)
                wrap(inner) {
                    val connection = HttpUpgradeConnection(transport = inner.transport, configuration = hu)
                    connection.performUpgrade()
                    object : Transport {
                        override suspend fun send(data: ByteArray) = connection.send(data)
                        override fun sendAsync(data: ByteArray) = connection.sendAsync(data)
                        override suspend fun receive(): ByteArray? = connection.receive()
                        override fun forceCancel() = connection.cancel()
                    }
                }
            }
            "grpc" -> {
                val grpc = configuration.grpc
                    ?: throw ProxyError.ConnectionFailed("grpc transport with no configuration")
                val authority = GrpcClient.resolveAuthority(grpc, configuration)
                val h2Tls = tls?.let { GrpcClient.sanitizedTlsConfiguration(it) }
                if (tunnel == null) {
                    // A stream on the pooled connection to this server; see GrpcMux.
                    val key = GrpcClient.muxKey(configuration, grpc, authority)
                    val pooled = com.mythaia.vpn.protocol.grpc.GrpcMux.open(key, grpc, authority, secure = h2Tls != null) {
                        val inner = stream(configuration, h2Tls, null)
                        inner.tlsVersion?.let { pooledTlsVersions[key] = it }
                        com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                    }
                    return Opened(grpcTransport(pooled), pooledTlsVersions[key] ?: h2Tls?.let { TlsVersion.TLS13 })
                }
                val inner = stream(configuration, h2Tls, tunnel)
                wrap(inner) {
                    val connection = GrpcConnection(inner.transport, grpc, authority)
                    connection.performSetup()
                    grpcTransport(connection)
                }
            }
            "xhttp" -> openXHttp(configuration, tls, tunnel)
            else -> throw ProxyError.ConnectionFailed("$transport transport is not supported")
        }
    }

    private suspend fun openXHttp(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?
    ): Opened {
        val xhttp = configuration.xhttp
            ?: throw ProxyError.ConnectionFailed("xhttp transport with no configuration")
        // Over TLS the ALPN decides the HTTP version; h3 would need QUIC.
        val alpn = tls?.alpn.orEmpty().map { it.lowercase() }
        val useHTTP2 = tls != null && !(alpn.size == 1 && alpn[0] == "http/1.1")
        if (tls != null && alpn.size == 1 && alpn[0] == "h3") {
            throw ProxyError.ConnectionFailed("XHTTP over HTTP/3 is not implemented")
        }
        val sanitizedTls = tls?.let { base ->
            val wanted = if (useHTTP2) listOf("h2", "http/1.1") else listOf("http/1.1")
            base.copy(alpn = wanted)
        }
        val mode = if (xhttp.mode == XHttpMode.AUTO) XHttpMode.PACKET_UP else xhttp.mode
        val sessionId = if (mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP) UUID.randomUUID().toString() else ""
        val needsUpload = !useHTTP2 && (mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP)

        if (tunnel == null && useHTTP2) {
            // Every request a stream of the pooled connection to this server.
            val key = "xhttp|" + com.mythaia.vpn.protocol.naive.http2.Http2PoolKey.of(configuration, sanitizedTls, xhttp.host)
            val connection = XHttpConnection.pooled(xhttp, mode, sessionId) {
                com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.reserve(key, "xhttp") {
                    val inner = stream(configuration, sanitizedTls, null)
                    inner.tlsVersion?.let { pooledTlsVersions[key] = it }
                    com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                }
            }
            connection.performSetup()
            return Opened(xhttpTransport(connection), pooledTlsVersions[key] ?: TlsVersion.TLS13)
        }

        val inner = stream(configuration, sanitizedTls, tunnel)
        return wrap(inner) {
            val uploadFactory: (suspend () -> TransportClosures)? = if (needsUpload) {
                {
                    val upload = stream(configuration, sanitizedTls, tunnel).transport
                    TransportClosures(
                        send = { data -> upload.send(data) },
                        sendAsync = { data -> upload.sendAsync(data) },
                        receive = { upload.receive() },
                        cancel = { upload.forceCancel() }
                    )
                }
            } else null
            val connection = XHttpConnection(
                transport = inner.transport,
                configuration = xhttp,
                mode = mode,
                sessionId = sessionId,
                useHTTP2 = useHTTP2,
                uploadConnectionFactory = uploadFactory
            )
            connection.performSetup()
            xhttpTransport(connection)
        }
    }

    private fun xhttpTransport(connection: XHttpConnection): Transport = object : Transport {
        override suspend fun send(data: ByteArray) = connection.send(data)
        override fun sendAsync(data: ByteArray) = connection.sendAsync(data)
        override suspend fun receive(): ByteArray? = connection.receive()
        override fun forceCancel() = connection.cancel()
    }

    /** Runs the transport handshake; the inner stream is closed if it fails, since no one else holds it. */
    /**
     * WebSocket and HTTPUpgrade are HTTP/1.1 upgrades. Offering h2 lets a
     * server that prefers it (any CDN, Xray with the default ALPN) select h2,
     * after which the upgrade request arrives as a bogus HTTP/2 preface and the
     * server hangs up — what VLESS already avoids by pinning the same ALPN.
     */
    private fun http11Only(tls: TlsConfiguration): TlsConfiguration = tls.copy(alpn = listOf("http/1.1"))

    /** The TLS version each pooled gRPC connection was dialled with, for [Opened.tlsVersion]. */
    private val pooledTlsVersions = java.util.concurrent.ConcurrentHashMap<String, TlsVersion>()

    private fun grpcTransport(connection: com.mythaia.vpn.protocol.grpc.GrpcTunnel): Transport = object : Transport {
        override suspend fun send(data: ByteArray) = connection.send(data)
        override fun sendAsync(data: ByteArray) {
            // gRPC frames carry sequence state, so the write goes
            // through the ordered suspend path.
            kotlinx.coroutines.runBlocking { connection.send(data) }
        }
        override suspend fun receive(): ByteArray? = connection.receive()
        override fun forceCancel() = connection.cancel()
    }

    private inline fun wrap(inner: Opened, build: () -> Transport): Opened = try {
        Opened(build(), inner.tlsVersion)
    } catch (e: Exception) {
        runCatching { inner.transport.forceCancel() }
        throw e
    }

    /** TCP or the tunnel, wrapped in TLS when [tls] is set. */
    private suspend fun stream(configuration: ProxyConfiguration, tls: TlsConfiguration?, tunnel: ProxyConnection?): Opened {
        if (tls != null) {
            val client = TlsClient(tls)
            val connection = if (tunnel != null) client.connect(TunneledTransport(tunnel))
            else client.connect(configuration.serverAddress, configuration.serverPort.toInt())
            return Opened(TlsRecordTransport(connection), if (connection.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12)
        }
        if (tunnel != null) return Opened(TunneledTransport(tunnel), null)
        val socket = NioSocket()
        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
        return Opened(socket, null)
    }
}
