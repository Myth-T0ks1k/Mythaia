package com.mythaia.vpn.protocol

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.vpn.protocol.grpc.GrpcClient
import com.mythaia.vpn.protocol.grpc.GrpcConnection
import com.mythaia.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.mythaia.vpn.protocol.reality.RealityClient
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordTransport
import com.mythaia.vpn.protocol.websocket.WebSocketConnection
import com.mythaia.vpn.protocol.xhttp.TransportClosures
import com.mythaia.vpn.protocol.xhttp.XHttpConnection
import com.mythaia.vpn.util.NioSocket
import java.util.UUID

/**
 * The byte pipe a stream protocol (VMess, Trojan) runs on: TCP or the chain
 * tunnel, TLS or REALITY when asked, and the configured transport on top —
 * WebSocket, HTTPUpgrade, gRPC, HTTP, QUIC, or XHTTP.
 */
object StreamTransports {

    /** An open pipe and the TLS version it runs over, when it does. */
    class Opened(val transport: Transport, val tlsVersion: TlsVersion?)

    suspend fun open(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?
    ): Opened {
        val reality = if (configuration.security == "reality") configuration.reality else null
        val transport = configuration.transport.ifEmpty { "tcp" }
        return when (transport) {
            "tcp" -> stream(configuration, tls, tunnel, reality)
            "ws" -> {
                val ws = configuration.websocket
                    ?: throw ProxyError.ConnectionFailed("ws transport with no WebSocket configuration")
                val inner = stream(configuration, tls?.let(::http11Only), tunnel, reality)
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
                val inner = stream(configuration, tls?.let(::http11Only), tunnel, reality)
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
                val secure = h2Tls != null || reality != null
                if (tunnel == null) {
                    // A stream on the pooled connection to this server; see GrpcMux.
                    val key = GrpcClient.muxKey(configuration, grpc, authority)
                    val pooled = com.mythaia.vpn.protocol.grpc.GrpcMux.open(key, grpc, authority, secure = secure) {
                        val inner = stream(configuration, h2Tls, null, reality)
                        inner.tlsVersion?.let { pooledTlsVersions[key] = it }
                        com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                    }
                    return Opened(grpcTransport(pooled), pooledTlsVersions[key] ?: if (secure) TlsVersion.TLS13 else null)
                }
                val inner = stream(configuration, h2Tls, tunnel, reality)
                wrap(inner) {
                    val connection = GrpcConnection(inner.transport, grpc, authority)
                    connection.performSetup()
                    grpcTransport(connection)
                }
            }
            "http" -> V2RayHttpTransport.open(configuration, tls, tunnel, reality)
            "quic" -> {
                if (tunnel != null) {
                    throw ProxyError.ConnectionFailed("quic transport cannot be dialled through a proxy chain")
                }
                if (reality != null) {
                    throw ProxyError.ConnectionFailed("quic transport does not support REALITY")
                }
                val quicTls = tls
                    ?: throw ProxyError.ConnectionFailed("quic transport requires TLS")
                val stream = com.mythaia.vpn.protocol.quic.QuicClientPool.openTransportStream(configuration, quicTls)
                Opened(TunneledTransport(stream), TlsVersion.TLS13)
            }
            "xhttp" -> openXHttp(configuration, tls, tunnel, reality)
            else -> throw ProxyError.ConnectionFailed("$transport transport is not supported")
        }
    }

    private fun decideXHttpUseHttp2(tls: TlsConfiguration?, reality: RealityConfiguration?): Boolean {
        if (reality != null) return true
        if (tls == null) return false
        val alpn = tls.alpn.orEmpty().map { it.lowercase() }
        if (alpn.size == 1 && alpn[0] == "h3") {
            throw ProxyError.ConnectionFailed("XHTTP over HTTP/3 is not implemented")
        }
        return !(alpn.size == 1 && alpn[0] == "http/1.1")
    }

    private fun sanitizeXHttpTls(tls: TlsConfiguration?, useHTTP2: Boolean): TlsConfiguration? = tls?.let { base ->
        val wanted = if (useHTTP2) listOf("h2", "http/1.1") else listOf("http/1.1")
        base.copy(alpn = wanted)
    }

    private suspend fun openXHttp(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?,
        reality: RealityConfiguration? = if (configuration.security == "reality") configuration.reality else null
    ): Opened {
        val xhttp = configuration.xhttp
            ?: throw ProxyError.ConnectionFailed("xhttp transport with no configuration")
        val useHTTP2 = decideXHttpUseHttp2(tls, reality)
        val sanitizedTls = sanitizeXHttpTls(tls, useHTTP2)
        val mode = if (xhttp.mode == XHttpMode.AUTO) {
            if (reality != null) {
                if (!xhttp.downloadSettingsJson.isNullOrBlank()) XHttpMode.STREAM_UP else XHttpMode.STREAM_ONE
            } else {
                XHttpMode.PACKET_UP
            }
        } else {
            xhttp.mode
        }
        val sessionId = if (mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP) UUID.randomUUID().toString() else ""
        val needsUpload = !useHTTP2 && (mode == XHttpMode.PACKET_UP || mode == XHttpMode.STREAM_UP)

        val splitDownload = if (mode != XHttpMode.STREAM_ONE) xhttp.resolveDownloadConfiguration(configuration) else null
        if (splitDownload != null && tunnel == null) {
            return openSplitXHttp(
                upProxyConfig = configuration,
                upTls = sanitizedTls,
                upReality = reality,
                upXHttp = xhttp,
                upUseHTTP2 = useHTTP2,
                downProxyConfig = splitDownload.first,
                downXHttp = splitDownload.second,
                mode = mode,
                sessionId = sessionId
            )
        }

        if (tunnel == null && useHTTP2) {
            // Every request a stream of the pooled connection to this server.
            val key = "xhttp|" + com.mythaia.vpn.protocol.naive.http2.Http2PoolKey.of(configuration, sanitizedTls, xhttp.host)
            val connection = XHttpConnection.pooled(xhttp, mode, sessionId, stream = {
                com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.reserve(key, "xhttp") {
                    val inner = stream(configuration, sanitizedTls, null, reality)
                    inner.tlsVersion?.let { pooledTlsVersions[key] = it }
                    com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                }
            })
            connection.performSetup()
            return Opened(xhttpTransport(connection), pooledTlsVersions[key] ?: TlsVersion.TLS13)
        }

        val inner = stream(configuration, sanitizedTls, tunnel, reality)
        return wrap(inner) {
            val uploadFactory: (suspend () -> TransportClosures)? = if (needsUpload) {
                {
                    val upTunnel = if (tunnel != null) buildUploadTunnel(configuration, tunnel) else null
                    val upload = stream(configuration, sanitizedTls, upTunnel, reality).transport
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

    private suspend fun openSplitXHttp(
        upProxyConfig: ProxyConfiguration,
        upTls: TlsConfiguration?,
        upReality: RealityConfiguration?,
        upXHttp: XHttpConfiguration,
        upUseHTTP2: Boolean,
        downProxyConfig: ProxyConfiguration,
        downXHttp: XHttpConfiguration,
        mode: XHttpMode,
        sessionId: String
    ): Opened {
        val downTls = if (downProxyConfig.security == "tls") downProxyConfig.tls else null
        val downReality = if (downProxyConfig.security == "reality") downProxyConfig.reality else null
        val downUseHTTP2 = decideXHttpUseHttp2(downTls, downReality)
        val downSanitizedTls = sanitizeXHttpTls(downTls, downUseHTTP2)

        val upKey = "xhttp|up|" + com.mythaia.vpn.protocol.naive.http2.Http2PoolKey.of(upProxyConfig, upTls, upXHttp.host)
        val downKey = "xhttp|down|" + com.mythaia.vpn.protocol.naive.http2.Http2PoolKey.of(downProxyConfig, downSanitizedTls, downXHttp.host)

        val uploadStream: (suspend () -> com.mythaia.vpn.protocol.naive.http2.Http2Stream)? = if (upUseHTTP2) {
            {
                com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.reserve(upKey, "xhttp") {
                    val inner = stream(upProxyConfig, upTls, null, upReality)
                    inner.tlsVersion?.let { pooledTlsVersions[upKey] = it }
                    com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                }
            }
        } else null

        val downloadStream: (suspend () -> com.mythaia.vpn.protocol.naive.http2.Http2Stream)? = if (downUseHTTP2) {
            {
                com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.reserve(downKey, "xhttp") {
                    val inner = stream(downProxyConfig, downSanitizedTls, null, downReality)
                    inner.tlsVersion?.let { pooledTlsVersions[downKey] = it }
                    com.mythaia.vpn.protocol.naive.http2.TransportWire(inner.transport)
                }
            }
        } else null

        val uploadFactory: (suspend () -> TransportClosures)? = if (!upUseHTTP2) {
            {
                val upload = stream(upProxyConfig, upTls, null, upReality).transport
                TransportClosures(
                    send = { data -> upload.send(data) },
                    sendAsync = { data -> upload.sendAsync(data) },
                    receive = { upload.receive() },
                    cancel = { upload.forceCancel() }
                )
            }
        } else null

        val downInner = if (!downUseHTTP2) stream(downProxyConfig, downSanitizedTls, null, downReality) else null
        try {
            val connection = XHttpConnection.split(
                configuration = upXHttp,
                downloadConfiguration = downXHttp,
                mode = mode,
                sessionId = sessionId,
                uploadStream = uploadStream,
                downloadStream = downloadStream,
                downloadSend = downInner?.let { inner -> { data -> inner.transport.send(data) } } ?: { throw com.mythaia.vpn.protocol.xhttp.XHttpError.ConnectionClosed },
                downloadSendAsync = downInner?.let { inner -> { data -> inner.transport.sendAsync(data) } } ?: {},
                downloadReceive = downInner?.let { inner -> { inner.transport.receive() } } ?: { null },
                downloadCancel = downInner?.let { inner -> { inner.transport.forceCancel() } } ?: {},
                uploadConnectionFactory = uploadFactory
            )
            connection.performSetup()
            val tlsVer = pooledTlsVersions[upKey] ?: pooledTlsVersions[downKey] ?: downInner?.tlsVersion
                ?: if (upUseHTTP2 || downUseHTTP2) TlsVersion.TLS13 else null
            return Opened(xhttpTransport(connection), tlsVer)
        } catch (e: Exception) {
            runCatching { downInner?.transport?.forceCancel() }
            throw e
        }
    }

    private suspend fun buildUploadTunnel(configuration: ProxyConfiguration, fallbackTunnel: ProxyConnection): ProxyConnection {
        val chain = configuration.chain
        if (chain.isNullOrEmpty()) return fallbackTunnel
        var previousConnection: ProxyConnection? = null
        for (i in chain.indices) {
            val hopConfig = chain[i]
            val nextConfig = if (i + 1 < chain.size) chain[i + 1] else configuration
            previousConnection = ProxyClientFactory.connect(
                hopConfig,
                nextConfig.serverAddress,
                nextConfig.serverPort.toInt(),
                tunnel = previousConnection
            )
        }
        return previousConnection ?: fallbackTunnel
    }

    private fun xhttpTransport(connection: XHttpConnection): Transport = object : Transport {
        override suspend fun send(data: ByteArray) = connection.send(data)
        override fun sendAsync(data: ByteArray) = connection.sendAsync(data)
        override suspend fun receive(): ByteArray? = connection.receive()
        override fun forceCancel() = connection.cancel()
    }

    /**
     * WebSocket and HTTPUpgrade are HTTP/1.1 upgrades. Offering h2 lets a
     * server that prefers it (any CDN, Xray with the default ALPN) select h2,
     * after which the upgrade request arrives as a bogus HTTP/2 preface and the
     * server hangs up — what VLESS already avoids by pinning the same ALPN.
     */
    private fun http11Only(tls: TlsConfiguration): TlsConfiguration = tls.copy(alpn = listOf("http/1.1"))

    /** The TLS version each pooled gRPC/XHTTP connection was dialled with, for [Opened.tlsVersion]. */
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

    /** TCP or the tunnel, wrapped in TLS or REALITY when set. */
    private suspend fun stream(
        configuration: ProxyConfiguration,
        tls: TlsConfiguration?,
        tunnel: ProxyConnection?,
        reality: RealityConfiguration? = null
    ): Opened {
        if (reality != null) {
            val client = RealityClient(reality)
            val connection = if (tunnel != null) client.connect(TunneledTransport(tunnel))
            else client.connect(configuration.serverAddress, configuration.serverPort.toInt())
            return Opened(TlsRecordTransport(connection), TlsVersion.TLS13)
        }
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

