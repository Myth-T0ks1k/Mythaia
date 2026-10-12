package com.mythaia.vpn.protocol.naive

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.NioSocket
import java.io.IOException

private val logger = MythaiaLogger("NaiveTLS")

sealed class NaiveTlsError(message: String) : IOException(message) {
    class ConnectionFailed(msg: String) : NaiveTlsError("Naive TLS connection failed: $msg")
    class NotConnected : NaiveTlsError("Naive TLS not connected")
}

/**
 * TLS transport for NaiveProxy. ALPN is configurable per HTTP version
 * (`["h2"]` or `["http/1.1"]`). Supports direct connections and tunneled
 * connections through an existing [ProxyConnection].
 */
class NaiveTlsTransport(
    private val host: String,
    private val port: Int,
    private val sni: String?,
    private val alpn: List<String> = listOf("h2"),
    private val tunnel: ProxyConnection? = null
) : com.mythaia.vpn.protocol.naive.http2.Http2Wire {
    private var tlsConnection: TlsRecordConnection? = null
    var isReady = false
        private set

    suspend fun connect() {
        val config = TlsConfiguration(
            serverName = sni ?: host,
            alpn = alpn
        )
        val client = TlsClient(config)

        try {
            val connection = if (tunnel != null) {
                client.connect(TunneledTransport(tunnel))
            } else {
                client.connect(host, port)
            }
            tlsConnection = connection
            isReady = true
        } catch (e: Exception) {
            logger.error("Connection failed: ${e.message}")
            throw NaiveTlsError.ConnectionFailed(e.message ?: "Unknown error")
        }
    }

    override suspend fun send(data: ByteArray) {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        conn.send(data)
    }

    override suspend fun receive(): ByteArray? {
        val conn = tlsConnection
        if (conn == null || !isReady) throw NaiveTlsError.NotConnected()
        return conn.receive()
    }

    override fun cancel() {
        isReady = false
        tlsConnection?.cancel()
        tlsConnection = null
    }
}
