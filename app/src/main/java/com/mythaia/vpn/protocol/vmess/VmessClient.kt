package com.mythaia.vpn.protocol.vmess

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsError
import com.mythaia.vpn.protocol.tls.TlsRecordTransport
import com.mythaia.vpn.protocol.websocket.WebSocketConnection
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.delay

private val logger = MythaiaLogger("VMessClient")

/**
 * Client for VMess (AEAD, `alterId` 0).
 *
 * Runs over TCP, TLS, WebSocket and WebSocket-over-TLS — between them, what
 * VMess is actually deployed on. Both the request header and the first payload
 * ride the first write, so a dial costs no extra round trip.
 *
 * Retry logic matches the other clients: 5 attempts with linear backoff.
 */
class VmessClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {
    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L
    }

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection = dial(destinationHost, destinationPort, VmessProtocol.COMMAND_TCP, initialData)

    /**
     * VMess carries UDP by declaring the UDP command and then treating the
     * stream as one datagram per chunk, which is what the server does on the
     * other side.
     */
    suspend fun connectUDP(
        destinationHost: String,
        destinationPort: Int
    ): ProxyConnection = dial(destinationHost, destinationPort, VmessProtocol.COMMAND_UDP, null)

    private suspend fun dial(
        destinationHost: String,
        destinationPort: Int,
        command: Byte,
        initialData: ByteArray?
    ): ProxyConnection {
        val security = VmessSecurity.fromRaw(configuration.vmessSecurity)
        val sealed = VmessProtocol.sealRequest(
            id = configuration.uuid,
            host = destinationHost,
            port = destinationPort,
            command = command,
            security = security
        )

        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (tunnel != null && attempt > 0) break
            if (attempt > 0) delay(RETRY_BASE_DELAY_MS * attempt)

            var transport: Transport? = null
            try {
                transport = openTransport()
                val connection = VmessConnection(transport, sealed.session, sealed.bytes)
                // The header is only actually written by the first send, so an
                // empty initialData still has to flush it.
                connection.send(initialData ?: ByteArray(0))
                return connection
            } catch (e: Exception) {
                // A transport that never became a returned connection owns a
                // socket nobody else will close; five failing attempts would
                // otherwise leak five of them per dial.
                runCatching { transport?.forceCancel() }
                if (e is TlsError.CertificateValidationFailed) throw e
                logger.debug("VMess attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS failed: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ConnectionFailed("All retry attempts failed")
    }

    /** The byte pipe the VMess stream runs on, per the configured transport. */
    private suspend fun openTransport(): Transport {
        val useTls = configuration.security == "tls" && configuration.tls != null

        return when (configuration.transport) {
            "ws" -> {
                val wsConfig = configuration.websocket
                    ?: throw ProxyError.ConnectionFailed("VMess: ws transport with no WebSocket configuration")
                val inner = openByteStream(useTls)
                try {
                    val ws = WebSocketConnection(transport = inner, configuration = wsConfig)
                    ws.performUpgrade()
                    WebSocketTransport(ws)
                } catch (e: Exception) {
                    // The upgrade can fail after the socket is connected — a 503
                    // from a CDN, say — and the caller never sees this inner
                    // stream, so nothing else would close it.
                    runCatching { inner.forceCancel() }
                    throw e
                }
            }
            "tcp" -> openByteStream(useTls)
            else -> throw ProxyError.ConnectionFailed(
                "VMess: ${configuration.transport} transport is not supported yet"
            )
        }
    }

    /** A plain or TLS-wrapped stream to the server. */
    private suspend fun openByteStream(useTls: Boolean): Transport {
        if (useTls) {
            val tlsConfig = configuration.tls
                ?: throw ProxyError.ConnectionFailed("VMess: TLS selected with no TLS configuration")
            val client = TlsClient(tlsConfig)
            val tls = if (tunnel != null) {
                client.connect(TunneledTransport(tunnel))
            } else {
                client.connect(configuration.serverAddress, configuration.serverPort.toInt())
            }
            return TlsRecordTransport(tls)
        }

        if (tunnel != null) return TunneledTransport(tunnel)

        val socket = NioSocket()
        socket.connect(configuration.serverAddress, configuration.serverPort.toInt())
        return socket
    }
}

/** Adapts a [WebSocketConnection] to [Transport]. */
private class WebSocketTransport(private val ws: WebSocketConnection) : Transport {
    override suspend fun send(data: ByteArray) = ws.send(data)
    override fun sendAsync(data: ByteArray) = ws.sendAsync(data)
    override suspend fun receive(): ByteArray? = ws.receive()
    override fun forceCancel() = ws.cancel()
}
