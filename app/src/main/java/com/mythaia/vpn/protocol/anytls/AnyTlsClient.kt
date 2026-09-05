package com.mythaia.vpn.protocol.anytls

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsError
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

private val logger = MythaiaLogger("AnyTLS")

/**
 * Dials AnyTLS, reusing sessions.
 *
 * The protocol requires multiplexing rather than merely allowing it: a server
 * may refuse a client that opens a TLS connection per request, because that
 * pattern is exactly what the padding scheme exists to hide. So sessions live
 * in a pool keyed by profile, newest first — a fresh session is only built when
 * no idle one is available.
 */
class AnyTlsClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {

    suspend fun connect(
        destinationHost: String,
        destinationPort: Int,
        initialData: ByteArray? = null
    ): ProxyConnection {
        val stream = openStream(destinationHost, destinationPort)
        if (initialData != null && initialData.isNotEmpty()) {
            stream.send(initialData)
        }
        return stream
    }

    /**
     * UDP rides a stream addressed to a reserved name, which is how sing-box's
     * udp-over-tcp v2 is carried; the server recognises the name and switches.
     */
    suspend fun connectUDP(destinationHost: String, destinationPort: Int): ProxyConnection {
        val stream = openStream(AnyTlsProtocol.UDP_OVER_TCP_HOST, 443)
        return AnyTlsUdpConnection(stream, destinationHost, destinationPort)
    }

    private suspend fun openStream(host: String, port: Int): AnyTlsStream {
        val password = configuration.password
            ?: throw ProxyError.ProtocolError("AnyTLS password not set")
        val tlsConfig = configuration.tls
            ?: throw ProxyError.ProtocolError("AnyTLS requires TLS configuration")

        val pool = Pool.of(configuration.id)

        // A session that is alive and idle is always preferable: it costs no
        // handshake and keeps the connection count down, which is itself part
        // of what the protocol is trying to look ordinary about.
        pool.takeIdle()?.let { session ->
            return runCatching { session.openStream(host, port) }
                .getOrElse {
                    session.close()
                    newSession(pool, password, tlsConfig).openStream(host, port)
                }
        }

        return newSession(pool, password, tlsConfig).openStream(host, port)
    }

    private suspend fun newSession(
        pool: Pool,
        password: String,
        tlsConfig: TlsConfiguration
    ): AnyTlsSession {
        val tls = connectTls(tlsConfig)

        // Authentication rides in the same write as packet 0's padding, which
        // the scheme sizes; it is the one packet that cannot be split.
        val paddingLength = pool.scheme
            .recordSizes(0, java.security.SecureRandom())
            .firstOrNull()
            ?.takeIf { it != AnyTlsPaddingScheme.CHECK }
            ?: 0
        tls.send(AnyTlsProtocol.authentication(password, paddingLength))

        val session = AnyTlsSession(
            tls = tls,
            padding = pool.scheme,
            clientName = CLIENT_NAME,
            onPaddingScheme = { pool.scheme = it }
        )
        session.start()
        pool.register(session)
        return session
    }

    private suspend fun connectTls(tlsConfig: TlsConfiguration): TlsRecordConnection {
        if (tunnel != null) {
            return TlsClient(tlsConfig).connect(TunneledTransport(tunnel))
        }

        var lastError: Exception? = null
        for (attempt in 0 until MAX_RETRY_ATTEMPTS) {
            if (attempt > 0) delay(RETRY_BASE_DELAY_MS * attempt)
            try {
                return TlsClient(tlsConfig).connect(
                    configuration.serverAddress,
                    configuration.serverPort.toInt()
                )
            } catch (e: Exception) {
                if (e is TlsError.CertificateValidationFailed) throw e
                logger.debug("[AnyTLS] TLS attempt ${attempt + 1}/$MAX_RETRY_ATTEMPTS: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: ProxyError.ProtocolError("AnyTLS could not reach the server")
    }

    /**
     * The live sessions for one profile.
     *
     * Also where the padding scheme lives: the server pushes it per client, and
     * it must outlast the session it arrived on — otherwise every new session
     * would announce the default digest again and be told to update again.
     */
    private class Pool {
        private val lock = Mutex()
        private val sessions = ArrayList<AnyTlsSession>()

        @Volatile
        var scheme: AnyTlsPaddingScheme = AnyTlsPaddingScheme.DEFAULT

        suspend fun register(session: AnyTlsSession) = lock.withLock {
            sessions.add(session)
        }

        /**
         * The newest session with no streams on it.
         *
         * Newest first is the protocol's own advice: an older session has been
         * visible for longer, and reusing the freshest keeps the oldest free to
         * be retired.
         */
        suspend fun takeIdle(): AnyTlsSession? = lock.withLock {
            sessions.removeAll { it.isClosed }
            sessions.lastOrNull { it.activeStreams == 0 }
        }

        companion object {
            private val pools = ConcurrentHashMap<UUID, Pool>()
            fun of(id: UUID): Pool = pools.getOrPut(id) { Pool() }
        }
    }

    private companion object {
        const val MAX_RETRY_ATTEMPTS = 5
        const val RETRY_BASE_DELAY_MS = 200L

        /**
         * Reported in the settings frame. The protocol asks third-party clients
         * to give their real name and version rather than impersonate the
         * reference one, so a server can tell implementations apart.
         */
        const val CLIENT_NAME = "mythaia/1.9"
    }
}
