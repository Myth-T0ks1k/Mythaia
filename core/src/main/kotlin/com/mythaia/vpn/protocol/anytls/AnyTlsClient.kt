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
            try {
                return session.openStream(host, port)
            } catch (_: Exception) {
                session.close()
            }
        }

        val session = newSession(pool, password, tlsConfig)
        return try {
            session.openStream(host, port)
        } catch (e: Exception) {
            // The session owns the TLS connection by now, so closing it is what
            // releases the socket.
            session.close()
            throw e
        }
    }

    private suspend fun newSession(
        pool: Pool,
        password: String,
        tlsConfig: TlsConfiguration
    ): AnyTlsSession {
        val tls = connectTls(tlsConfig)

        // Nothing else owns this socket until the session does, so every
        // failure between here and there has to release it by hand.
        try {
            // Authentication rides in the same write as packet 0's padding,
            // which the scheme sizes; it is the one packet that cannot be split.
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
        } catch (e: Throwable) {
            runCatching { tls.cancel() }
            throw e
        }
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
        /**
         * One monitor for every path into [sessions] and [idle], including
         * [markIdle], which a session invokes from its own stream-close path
         * — a plain callback that cannot take a suspending lock. The earlier
         * mutex left it writing the map unguarded while [takeIdle] and
         * [sweep] iterated it under the lock. Nothing in these critical
         * sections suspends, so a monitor serves them all.
         */
        private val lock = Any()
        private val sessions = ArrayList<AnyTlsSession>()

        /** Idle sessions and when each became idle; the oldest retire first. */
        private val idle = LinkedHashMap<AnyTlsSession, Long>()
        private var lastSweep = 0L

        @Volatile
        var scheme: AnyTlsPaddingScheme = AnyTlsPaddingScheme.DEFAULT

        fun register(session: AnyTlsSession) = synchronized(lock) {
            session.onIdle = { markIdle(session) }
            sessions.add(session)
            sweep()
        }

        /**
         * Claims the newest session with no streams on it.
         *
         * Newest first is the protocol's own advice: an older session has been
         * visible for longer, so reusing the freshest leaves the oldest free to
         * retire. The session is removed from the idle set rather than merely
         * read, because two dials that both saw it idle would each believe they
         * were opening its first stream — and the first stream is what composes
         * packet 1, whose shape the scheme defines.
         */
        fun takeIdle(): AnyTlsSession? = synchronized(lock) {
            sessions.removeAll { it.isClosed }
            sweep()
            val chosen = idle.keys.lastOrNull { !it.isClosed && it.activeStreams == 0 }
            if (chosen != null) idle.remove(chosen)
            chosen
        }

        private fun markIdle(session: AnyTlsSession) = synchronized(lock) {
            if (!session.isClosed) idle[session] = System.currentTimeMillis()
        }

        /**
         * Retires sessions that have been idle too long.
         *
         * A session is a live TLS connection: keeping one open forever is a
         * socket held for nothing, and a long-lived flow for an observer to
         * notice. A couple are kept back so the next request does not have to
         * pay for a handshake.
         */
        private fun sweep() {
            val now = System.currentTimeMillis()
            if (now - lastSweep < SWEEP_INTERVAL_MS) return
            lastSweep = now

            val stale = idle.entries
                .sortedBy { it.value }
                .filter { now - it.value > IDLE_TIMEOUT_MS }
                .dropLast(MIN_IDLE_SESSIONS.coerceAtMost(idle.size))
                .map { it.key }
            for (session in stale) {
                idle.remove(session)
                sessions.remove(session)
                session.close()
            }
        }

        fun shutdown() = synchronized(lock) {
            sessions.forEach { it.close() }
            sessions.clear()
            idle.clear()
        }

        companion object {
            private val pools = ConcurrentHashMap<UUID, Pool>()
            fun of(id: UUID): Pool = pools.getOrPut(id) { Pool() }

            fun shutdownAll() {
                pools.values.forEach { it.shutdown() }
                pools.clear()
            }
        }
    }

    companion object {
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BASE_DELAY_MS = 200L

        /** How often the pool looks for sessions to retire. */
        private const val SWEEP_INTERVAL_MS = 30_000L

        /** How long a session may sit idle before it is closed. */
        private const val IDLE_TIMEOUT_MS = 60_000L

        /** Kept back from retirement so the next request skips a handshake. */
        private const val MIN_IDLE_SESSIONS = 2

        /**
         * Reported in the settings frame. The protocol asks third-party clients
         * to give their real name and version rather than impersonate the
         * reference one, so a server can tell implementations apart.
         */
        private const val CLIENT_NAME = "mythaia/1.0"

        /** Releases every pooled session and its TLS connection. */
        suspend fun shutdown() = Pool.shutdownAll()
    }
}
