package com.mythaia.vpn.protocol.tuic

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.quic.QuicConnection
import com.mythaia.vpn.protocol.quic.QuicRedialBackoff
import com.mythaia.vpn.protocol.quic.QuicTuning
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import com.mythaia.vpn.protocol.quic.QuicUdpFlow
import com.mythaia.vpn.protocol.quic.UdpReassembler
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

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

    /**
     * The live session. Volatile because the UDP path and [dissociate] read
     * it without [lock], and because [close] runs without it too: a session
     * stored while [close] is running has to be seen by one side or the
     * other, see [openSession].
     */
    @Volatile
    private var quic: QuicConnection? = null

    /**
     * Set by [close] and never cleared. The pool has already let go of a
     * closed client, so a session brought up on it afterwards would belong to
     * nobody: its keep-alive (15 s) beats the idle timeout (30 s), and it
     * would hold a socket, two threads and a native connection for good.
     */
    @Volatile
    private var closed = false

    /** When the next attempt may dial after a failed one; see [QuicRedialBackoff]. */
    private val backoff = QuicRedialBackoff()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private val udpFlows = ConcurrentHashMap<Int, QuicUdpFlow>()
    private val nextAssociation = AtomicInteger((System.nanoTime() and 0xFFFF).toInt())
    private val nextPacketId = AtomicInteger(0)
    private val reassembler = UdpReassembler()

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

    /**
     * Opens a UDP flow to [host]:[port]: a TUIC association, relayed in QUIC
     * datagrams (the "native" relay mode every server speaks). There is no
     * setup message; the first packet opens it and `Dissociate` ends it.
     */
    suspend fun connectUDP(host: String, port: Int): ProxyConnection {
        ensureSession()
        var id: Int
        do {
            id = nextAssociation.incrementAndGet() and 0xFFFF
        } while (udpFlows.containsKey(id))
        val association = id
        val flow = QuicUdpFlow(
            scope = scope,
            transmit = { payload -> sendUdp(association, host, port, payload) },
            onClose = {
                udpFlows.remove(association)
                dissociate(association)
            }
        )
        udpFlows[association] = flow
        return flow
    }

    private suspend fun sendUdp(association: Int, host: String, port: Int, payload: ByteArray) {
        val session = udpSession() ?: run {
            logger.debug("[TUIC] UDP datagram dropped, no session (${payload.size} bytes to $host:$port)")
            return
        }
        val overhead = TuicProtocol.HEADER_SIZE + TuicProtocol.PACKET_HEADER_SIZE +
            TuicProtocol.encodeAddress(host, port).size
        // Split only above what one packet carries now, as tuic-rs does.
        val room = (session.maxDatagramPayload().takeIf { it > 0 } ?: MAX_UDP_DATAGRAM) - overhead
        val packetId = nextPacketId.getAndIncrement() and 0xFFFF
        val count = maxOf(1, (payload.size + room - 1) / room)
        if (count > 255) throw ProxyError.ProtocolError("TUIC: UDP payload too large")
        for (index in 0 until count) {
            val piece = if (count == 1) payload
            else payload.copyOfRange(index * room, minOf(payload.size, (index + 1) * room))
            session.sendDatagram(
                TuicProtocol.packet(TuicProtocol.Packet(association, packetId, count, index, host, port, piece))
            )
        }
    }

    /** Routes a datagram from the server to its association, reassembling fragments. */
    private fun onDatagram(bytes: ByteArray) {
        val packet = TuicProtocol.parsePacket(bytes) ?: return
        val flow = udpFlows[packet.associationId] ?: return
        val key = (packet.associationId.toLong() shl 16) or packet.packetId.toLong()
        val whole = reassembler.add(key, packet.fragmentId, packet.fragmentTotal, packet.payload) ?: return
        flow.deliver(whole)
    }

    /** Tells the server an association is over, so it can free the socket now rather than on timeout. */
    private fun dissociate(association: Int) {
        val session = quic?.takeIf { it.isConnected } ?: return
        scope.launch {
            runCatching {
                val stream = session.openUniStream() ?: return@runCatching
                stream.send(TuicProtocol.dissociate(association))
                stream.finish()
            }
        }
    }

    /** Drops the QUIC session; the next dial brings a new one up. Flows and the scope survive. */
    private fun resetSession() {
        quic?.close()
        quic = null
    }

    /** Ends everything: the session, the heartbeat, every UDP flow. */
    fun close() {
        // First, so a dial queued on the lock or halfway through a handshake
        // sees it and closes what it built instead of storing it.
        closed = true
        resetSession()
        udpFlows.values.toList().forEach { it.cancel() }
        udpFlows.clear()
        scope.cancel()
    }

    // MARK: - Session

    /** The live session, or a new one; every dial waits here while one comes up. */
    private suspend fun ensureSession(): QuicConnection {
        if (closed) throw clientClosed()
        return lock.withLock { sessionLocked() }
    }

    /**
     * The session a UDP datagram can leave on now, or null to drop it.
     *
     * Never waits for [lock]: a datagram parked there for every packet of a
     * call held its payload for as long as the server stayed unreachable. One
     * that finds no session is dropped, as UDP may be. When nobody else is
     * bringing a session up and the backoff has run out, this datagram's
     * sender brings one up itself, so a UDP-only flow still recovers.
     */
    private suspend fun udpSession(): QuicConnection? {
        quic?.takeIf { it.isConnected }?.let { return it }
        if (closed || backoff.remainingNanos() > 0 || !lock.tryLock()) return null
        return try {
            sessionLocked()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.debug("[TUIC] No session for UDP: ${e.message}")
            null
        } finally {
            lock.unlock()
        }
    }

    /**
     * [ensureSession] for a caller that already holds [lock].
     *
     * A failed attempt is put on record, and until [backoff] allows another,
     * every dial that reaches here fails at once with its reason instead of
     * dialling again. A cancelled attempt says nothing about the server and is
     * not recorded.
     */
    private suspend fun sessionLocked(): QuicConnection {
        if (closed) throw clientClosed()
        quic?.takeIf { it.isConnected }?.let { return it }
        backoff.check("TUIC")

        // Not close(): that cancels the scope the heartbeat runs in, so after
        // the first reconnect the session went silent and the server dropped it.
        resetSession()

        val connection = try {
            openSession()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            if (!closed) backoff.failed(e)
            throw e
        }
        backoff.succeeded()
        return connection
    }

    /**
     * Dials, authenticates, starts the heartbeat, and stores the session.
     *
     * Whatever ends this early — a failure, the caller being cancelled, or
     * [close] — closes the connection before it propagates. It is a socket,
     * two threads and an ngtcp2 handle; left behind, it lives until the idle
     * timeout, or for good once its handshake has completed and the
     * keep-alive holds it open.
     */
    private suspend fun openSession(): QuicConnection {
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
        connection.onDatagramReceived = ::onDatagram

        try {
            if (!connection.connect()) {
                throw ProxyError.ProtocolError("TUIC: QUIC handshake failed")
            }
            if (closed) throw clientClosed()

            // Bounded, because this runs under the lock: the command waits for
            // congestion window like any stream write, and a server that went
            // silent straight after the handshake would otherwise hold every
            // queued dial until the 30 s idle timer.
            withTimeoutOrNull(AUTH_TIMEOUT_MS) { authenticate(connection); true }
                ?: throw ProxyError.ProtocolError("TUIC: authentication could not be sent")
        } catch (e: Throwable) {
            connection.close()
            throw e
        }
        startHeartbeat(connection)

        quic = connection
        // close() may have run between the check above and this store. It
        // sets its flag before it reads the field, and this stores before it
        // reads the flag, so one side or the other always sees the session.
        // This side closes its own connection rather than whatever the field
        // holds now, which close() may already have cleared.
        if (closed) {
            connection.close()
            throw clientClosed()
        }
        return connection
    }

    private fun clientClosed() = ProxyError.ConnectionFailed("TUIC: client closed")

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

        /**
         * tuic-client's own default. The server's `max_idle_time` defaults to
         * 10 s, so a 10 s heartbeat raced the server's idle timer and often
         * arrived after it had already dropped the association; 3 s stays well
         * inside it.
         */
        const val HEARTBEAT_INTERVAL_MS = 3_000L

        /** The TUIC packet size assumed while QUIC cannot say yet; see Hysteria's. */
        const val MAX_UDP_DATAGRAM = 1100

        /** How long the `Authenticate` command may take to leave once QUIC is up. */
        const val AUTH_TIMEOUT_MS = 10_000L
    }
}
