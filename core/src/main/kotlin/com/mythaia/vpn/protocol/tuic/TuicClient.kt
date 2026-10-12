package com.mythaia.vpn.protocol.tuic

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.quic.QuicConnection
import com.mythaia.vpn.protocol.quic.QuicTuning
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val logger = MythaiaLogger("Tuic")

/**
 * TUIC v5 over QUIC.
 *
 * What makes TUIC quick is what it leaves out: there are no responses. The
 * client sends `Connect` and begins relaying on the same stream immediately,
 * without waiting to hear that the far side succeeded — a server that cannot
 * reach the target says so by closing the stream. That saves a round trip on
 * every connection and means a failure surfaces as a closed stream rather than
 * as an error message.
 *
 * Authentication is equally unusual. The password never goes on the wire:
 * it becomes a token through the TLS exporter, keyed to this session, so a
 * token captured from one connection is worthless on any other.
 *
 * Written from the TUIC specification (protocol version 0x05).
 */
class TuicClient(private val configuration: ProxyConfiguration) {

    private val lock = Mutex()
    private var quic: QuicConnection? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Opens a relayed TCP stream.
     *
     * The initial data rides out behind the command on the same stream, which
     * is the point of a protocol that does not wait for an answer.
     */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        val session = ensureSession()

        val stream = session.openStream()
            ?: throw ProxyError.ProtocolError("TUIC: no stream credit left")

        stream.send(TuicProtocol.connect(host, port))
        if (initialData != null && initialData.isNotEmpty()) {
            stream.send(initialData)
        }
        return stream
    }

    fun close() {
        scope.cancel()
        quic?.close()
        quic = null
    }

    // MARK: - Session

    private suspend fun ensureSession(): QuicConnection = lock.withLock {
        quic?.takeIf { it.isConnected }?.let { return it }

        close()

        val tls = configuration.tls
        val connection = QuicConnection(
            serverName = configuration.serverAddress,
            serverPort = configuration.serverPort.toInt(),
            alpn = listOf(ALPN),
            tuning = QuicTuning.NAIVE,
            fingerprint = tls?.fingerprint ?: com.mythaia.data.model.TlsFingerprint.CHROME_133,
            tlsServerName = tls?.serverName?.takeIf { it.isNotBlank() } ?: configuration.serverAddress,
            allowInsecure = tls?.allowInsecure == true,
            pinnedCertSha256 = tls?.pinnedCertSha256,
            verifyName = tls?.verifyName
        )
        if (!connection.connect()) {
            connection.close()
            throw ProxyError.ProtocolError("TUIC: QUIC handshake failed")
        }

        authenticate(connection)
        startHeartbeat(connection)

        quic = connection
        return connection
    }

    /**
     * Sends the `Authenticate` command on a unidirectional stream.
     *
     * The token is the TLS exporter's output with the UUID's raw bytes as the label and the
     * raw password as the context, which is what binds it to this session. It
     * is fire-and-forget: the specification defines no response, and a server
     * that rejects it simply stops relaying.
     */
    private suspend fun authenticate(connection: QuicConnection) {
        val uuid = configuration.uuid
        val password = configuration.password
            ?: configuration.trojanPassword
            ?: throw ProxyError.ProtocolError("TUIC password not set")

        // The label is the UUID's 16 raw bytes, as tuic-rs (`uuid.as_ref()`)
        // and sing-quic (`string(uuid[:])`) both use — not its text form,
        // which every server rejects as a token mismatch.
        val uuidBytes = java.nio.ByteBuffer.allocate(16)
            .putLong(uuid.mostSignificantBits).putLong(uuid.leastSignificantBits).array()
        val token = connection.exportKeyingMaterial(
            label = uuidBytes,
            context = password.toByteArray(Charsets.UTF_8),
            length = TuicProtocol.TOKEN_LENGTH
        ) ?: throw ProxyError.ProtocolError("TUIC: no keying material to build a token from")

        val stream = connection.openUniStream()
            ?: throw ProxyError.ProtocolError("TUIC: no stream for authentication")

        stream.send(TuicProtocol.authenticate(uuid, token))
        stream.finish()
        logger.debug("[TUIC] Authenticated as $uuid")
    }

    /**
     * Keeps the connection alive while anything is relaying.
     *
     * A datagram rather than a stream, because losing one costs nothing: the
     * next tick sends another, and a heartbeat that had to be retransmitted
     * would be measuring the wrong thing anyway.
     */
    private fun startHeartbeat(connection: QuicConnection) {
        scope.launch {
            while (connection.isConnected) {
                delay(HEARTBEAT_INTERVAL_MS)
                if (!connection.isConnected) break
                connection.sendDatagram(TuicProtocol.heartbeat())
            }
        }
    }

    private companion object {
        const val ALPN = "h3"
        const val HEARTBEAT_INTERVAL_MS = 10_000L
    }
}
