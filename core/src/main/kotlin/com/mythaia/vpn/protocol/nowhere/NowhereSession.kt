package com.mythaia.vpn.protocol.nowhere

import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.quic.QuicConnection
import com.mythaia.vpn.protocol.quic.QuicStream
import com.mythaia.vpn.protocol.quic.QuicTuning
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

private val logger = MythaiaLogger("Nowhere")

/**
 * The pure half of opening a flow: what goes on the wire first, and how the
 * portal's answer is read back.
 *
 * Kept apart from the session so the two things that are easy to get subtly
 * wrong — the bootstrap write, which is the only place the auth frame ever
 * appears, and the split of a read into status byte and trailing payload — can
 * be checked against literal bytes without a QUIC connection under them.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object NowhereFlowOpen {

    /** What a flow request was answered with, once enough bytes are there. */
    sealed class Outcome {
        /**
         * The flow is up. [pending] is whatever the portal sent behind the
         * status byte: a fast server can have the first response bytes in the
         * same packet, and dropping them would corrupt the stream.
         */
        class Ready(val pending: ByteArray) : Outcome()

        class Rejected(val code: NowhereProtocol.FlowRejectCode) : Outcome()
    }

    /**
     * The first bytes written on a fresh session.
     *
     * The auth frame and the first flow request go out in one write rather
     * than as an auth round trip followed by a request: the portal reads the
     * frame, checks the tag and, if it holds, keeps reading the request from
     * the same stream, so authentication costs no round trip of its own.
     */
    fun bootstrapPayload(authFrame: ByteArray, request: ByteArray): ByteArray {
        if (authFrame.size != NowhereProtocol.AUTH_FRAME_SIZE) {
            throw NowhereError.AuthenticationRejected("Invalid authentication material")
        }
        return authFrame + request
    }

    /**
     * Reads the portal's answer, or null while no byte has arrived.
     *
     * The answer is a single status byte, so "incomplete" can only mean an
     * empty buffer; anything after the first byte is payload, not part of the
     * answer. A status byte naming no known code is an error rather than a
     * reject, since the portal is then not speaking this protocol.
     */
    fun decode(buffer: ByteArray): Outcome? {
        if (buffer.isEmpty()) return null
        return when (val result = NowhereProtocol.decodeFlowResult(buffer)) {
            null -> throw NowhereError.InvalidFlow("Invalid flow result")
            is NowhereProtocol.FlowResult.Ready ->
                Outcome.Ready(buffer.copyOfRange(NowhereProtocol.FLOW_RESULT_SIZE, buffer.size))
            is NowhereProtocol.FlowResult.Reject -> Outcome.Rejected(result.code)
        }
    }
}

/**
 * One authenticated QUIC connection to a portal, shared by every flow the
 * same identity opens.
 *
 * Sharing is not an optimisation here but a requirement of the protocol. The
 * auth frame carries a session id that names this client, and a portal that
 * sees a second connection claim the same id treats the first as replaced —
 * so a connection per flow would have each new dial kill the previous one.
 * One session per identity is therefore the only correct shape, and the
 * registry in the companion is what enforces it.
 *
 * Authentication is unusual in having no exchange of its own. The auth frame
 * is bound to this handshake through the TLS exporter and goes out on the
 * first bidirectional stream, in the same write as the first flow request;
 * the portal's answer to that request is also its answer to the credentials.
 * Until it comes, every later dial waits, because a portal that refuses the
 * frame closes the bootstrap stream rather than saying anything, and opening
 * further streams into that silence would only multiply the failure.
 *
 * Stream credit is the other thing the portal withholds until it is
 * satisfied: it grants a single stream at first and more only after the
 * bootstrap. [QuicConnection.openStream] returns null when the credit is
 * spent, so a later flow polls for a stream rather than failing on the first
 * refusal.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereSession(val configuration: NowhereConfiguration) {

    /** A flow the portal accepted, and any payload that arrived behind READY. */
    class OpenedFlow(val stream: ProxyConnection, val pending: ByteArray)

    /** A QUIC-backed UDP flow handle: control stream and datagram send/receive. */
    class OpenedUdpFlow internal constructor(
        val flowId: Long,
        val controlStream: ProxyConnection,
        private val incoming: Channel<ByteArray>,
        private val session: NowhereSession
    ) {
        private val closed = AtomicBoolean(false)

        val isConnected: Boolean
            get() = !closed.get() && session.isUsable

        fun send(payload: ByteArray) {
            if (closed.get()) return
            session.sendUdp(flowId, payload)
        }

        suspend fun receive(): ByteArray? {
            if (closed.get()) return null
            val result = incoming.receiveCatching()
            result.exceptionOrNull()?.let { err ->
                close(sendCloseControl = false)
                throw err
            }
            val packet = result.getOrNull()
            if (packet == null) {
                close(sendCloseControl = false)
            }
            return packet
        }

        fun close(sendCloseControl: Boolean = true) {
            if (!closed.compareAndSet(false, true)) return
            session.closeUdpFlow(flowId, controlStream, sendCloseControl)
        }
    }

    /**
     * The session cannot carry a flow and will not recover.
     *
     * Distinct from a protocol error so that the caller can tell "this
     * connection is gone, open another" from "the portal said no".
     */
    class Unavailable(detail: String) : IOException(detail)

    /** The portal read the request and refused it, naming a reason. */
    class FlowRejected(val code: NowhereProtocol.FlowRejectCode) :
        IOException("Portal rejected the flow: ${code.description}")

    private enum class Phase { IDLE, TRANSPORT_READY, AUTHENTICATING, READY, CLOSED }

    private val phase = AtomicReference(Phase.IDLE)

    /** Serialises bringing the transport up and claiming the bootstrap. */
    private val lock = Mutex()

    @Volatile
    private var quic: QuicConnection? = null

    /** Built once the handshake has produced an exporter; sent exactly once. */
    private var authFrame: ByteArray? = null

    /**
     * Completed when the portal answers the bootstrap flow, however it
     * answers: a reject code proves the credentials were accepted just as a
     * READY does, since a portal that refuses the auth frame says nothing.
     */
    private val authenticated = CompletableDeferred<Unit>()

    private val activeFlows = AtomicInteger(0)

    @Volatile
    private var idleSince = 0L

    private val udpFlows = ConcurrentHashMap<Long, Channel<ByteArray>>()
    private val reassembler = NowhereFragmentReassembler()
    private val packetIdLock = Any()
    private var nextPacketId = 1L

    /** Hooks for unit tests to exercise flow/datagram framing without native ngtcp2. */
    internal var streamOpener: (suspend (ByteArray) -> OpenedFlow)? = null
    internal var datagramSender: ((ByteArray) -> Unit)? = null
    internal var maxDatagramPayloadProvider: (() -> Int)? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    val isClosed: Boolean get() = phase.get() == Phase.CLOSED

    /**
     * Whether a new flow could be opened here.
     *
     * A connection can die without any callback reaching this layer, so the
     * QUIC handle is consulted directly rather than trusting the phase.
     */
    val isUsable: Boolean
        get() = phase.get() != Phase.CLOSED && (quic?.isConnected ?: true)

    /** How many flows are riding this session right now. */
    val flowCount: Int get() = activeFlows.get()

    /**
     * Opens one flow with [request], which must already be a complete flow
     * request for a role that expects an answer.
     *
     * Returns once the portal has said READY. A [FlowRejected] means the
     * request was understood and refused; an [Unavailable] means this session
     * is finished and the caller should build another before giving up.
     */
    suspend fun openFlow(request: ByteArray): OpenedFlow {
        streamOpener?.let { opener ->
            if (phase.get() == Phase.CLOSED) throw Unavailable("Nowhere: session closed")
            activeFlows.incrementAndGet()
            idleSince = 0L
            return try {
                opener(request)
            } catch (e: Exception) {
                flowEnded()
                throw e
            }
        }

        val bootstrap: Boolean
        var stream: QuicStream? = null
        val payload: ByteArray

        lock.withLock {
            val connection = ensureTransportLocked()
            when (phase.get()) {
                Phase.TRANSPORT_READY -> {
                    // The first stream is the only one that carries the auth
                    // frame, and it must be the first stream the portal sees;
                    // claiming it under the lock is what guarantees that.
                    val frame = authFrame
                        ?: throw Unavailable("Nowhere: no authentication frame for the bootstrap")
                    stream = connection.openStream()
                        ?: run {
                            fail(Unavailable("Nowhere: failed to open the bootstrap stream"))
                            throw Unavailable("Nowhere: failed to open the bootstrap stream")
                        }
                    phase.set(Phase.AUTHENTICATING)
                    payload = NowhereFlowOpen.bootstrapPayload(frame, request)
                    bootstrap = true
                }

                Phase.AUTHENTICATING, Phase.READY -> {
                    payload = request
                    bootstrap = false
                }

                Phase.IDLE, Phase.CLOSED ->
                    throw Unavailable("Nowhere: session is not ready")
            }
        }

        if (!bootstrap) {
            // Whatever ends the bootstrap — READY, a reject, or the portal
            // going quiet — lands here, as a value or as the failure.
            authenticated.await()
            stream = openStreamWhenCreditAvailable()
        }
        val opened = stream ?: throw Unavailable("Nowhere: no stream for the flow")

        activeFlows.incrementAndGet()
        idleSince = 0L
        try {
            opened.send(payload)
            val outcome = readOutcome(opened)
            if (bootstrap) becomeReady()
            return when (outcome) {
                is NowhereFlowOpen.Outcome.Ready -> OpenedFlow(opened, outcome.pending)
                is NowhereFlowOpen.Outcome.Rejected -> throw FlowRejected(outcome.code)
            }
        } catch (e: Exception) {
            opened.cancel()
            flowEnded()
            if (bootstrap && !authenticated.isCompleted) {
                // The portal never answered the auth frame, so nothing else
                // on this connection can succeed either.
                val failure = Unavailable(
                    "Nowhere: portal closed the bootstrap stream before answering; " +
                        "check the key (${e.message})"
                )
                fail(failure)
                throw failure
            }
            throw e
        }
    }

    /**
     * Opens a QUIC-backed UDP flow for [flowId].
     *
     * The stream opened by [request] is the UDP control stream; datagrams carry
     * the packets themselves. The datagram channel is registered before the
     * request goes out so a packet arriving right behind READY is not dropped.
     */
    suspend fun openUdpFlow(flowId: Long, request: ByteArray): OpenedUdpFlow {
        val channel = Channel<ByteArray>(Channel.UNLIMITED)
        udpFlows[flowId] = channel
        val opened = try {
            openFlow(request)
        } catch (e: Exception) {
            udpFlows.remove(flowId)?.close()
            synchronized(reassembler) { reassembler.forget(flowId) }
            throw e
        }
        if (opened.pending.isNotEmpty()) {
            udpFlows.remove(flowId)?.close()
            synchronized(reassembler) { reassembler.forget(flowId) }
            opened.stream.cancel()
            flowEnded()
            throw NowhereError.ProtocolViolation("Unexpected data on Nowhere UDP control stream")
        }
        val handle = OpenedUdpFlow(flowId, opened.stream, channel, this)
        monitorUdpControlStream(flowId, opened.stream, channel)
        return handle
    }

    private fun monitorUdpControlStream(
        flowId: Long,
        controlStream: ProxyConnection,
        channel: Channel<ByteArray>
    ) {
        scope.launch {
            try {
                val chunk = controlStream.receiveRaw()
                if (chunk != null && chunk.isNotEmpty()) {
                    channel.close(NowhereError.ProtocolViolation("Unexpected data on Nowhere UDP control stream"))
                } else {
                    channel.close()
                }
            } catch (_: Exception) {
                channel.close()
            } finally {
                synchronized(reassembler) { reassembler.forget(flowId) }
            }
        }
    }

    /**
     * Sends one UDP packet for [flowId] as a QUIC datagram (or a sequence of
     * `FRAGMENT` datagrams when [payload] + header exceeds the negotiated
     * datagram budget). Packets exceeding the protocol's 64 KiB cap are
     * dropped, matching the reference implementation.
     */
    fun sendUdp(flowId: Long, payload: ByteArray) {
        if (phase.get() == Phase.CLOSED) throw Unavailable("Nowhere: session closed")
        val negotiatedMax = maxDatagramPayloadProvider?.invoke()
            ?: quic?.maxDatagramPayload()
            ?: 0
        val maxDatagramSize = if (negotiatedMax > 0) negotiatedMax else DEFAULT_MAX_DATAGRAM_PAYLOAD
        val needsFragmentation = payload.size + NowhereProtocol.UDP_HEADER_SIZE > maxDatagramSize
        val packetId = if (needsFragmentation) nextUdpPacketId() else 0L
        val frames = try {
            NowhereProtocol.encodeUdpDataFragments(
                flowId = flowId,
                packetId = packetId,
                payload = payload,
                maxDatagramSize = maxDatagramSize
            )
        } catch (_: NowhereError.PacketTooLarge) {
            return
        }
        val sender = datagramSender
        if (sender != null) {
            for (frame in frames) sender(frame)
        } else {
            val connection = quic ?: throw Unavailable("Nowhere: session is not ready")
            for (frame in frames) connection.sendDatagram(frame)
        }
    }

    internal fun handleDatagram(bytes: ByteArray) {
        val message = try {
            NowhereProtocol.decodeUdpDatagram(bytes)
        } catch (_: Exception) {
            null
        } ?: return
        val channel = udpFlows[message.flowId] ?: return
        when (message.type) {
            NowhereProtocol.UdpType.DATA -> {
                channel.trySend(message.payload)
            }
            NowhereProtocol.UdpType.FRAGMENT -> {
                val reassembled = synchronized(reassembler) {
                    reassembler.accept(message)
                }
                if (reassembled != null) {
                    channel.trySend(reassembled)
                }
            }
            NowhereProtocol.UdpType.CLOSE -> {
                synchronized(reassembler) {
                    reassembler.forget(message.flowId)
                }
                udpFlows.remove(message.flowId)?.close()
            }
        }
    }

    internal fun closeUdpFlow(
        flowId: Long,
        controlStream: ProxyConnection?,
        sendCloseControl: Boolean = true
    ) {
        udpFlows.remove(flowId)?.close()
        synchronized(reassembler) {
            reassembler.forget(flowId)
        }
        if (sendCloseControl && phase.get() != Phase.CLOSED) {
            val closeFrame = NowhereProtocol.encodeUdpControl(
                type = NowhereProtocol.UdpType.CLOSE,
                flowId = flowId
            )
            runCatching {
                val sender = datagramSender
                if (sender != null) {
                    sender(closeFrame)
                } else {
                    quic?.sendDatagram(closeFrame)
                }
            }
        }
        runCatching { controlStream?.cancel() }
        flowEnded()
    }

    internal fun nextUdpPacketId(): Long = synchronized(packetIdLock) {
        val current = if (nextPacketId <= 0L || nextPacketId > 0xFFFFFFFFL) 1L else nextPacketId
        var next = (current + 1L) and 0xFFFFFFFFL
        if (next == 0L) next = 1L
        nextPacketId = next
        current
    }

    /**
     * Tells the session a flow it handed out has finished, so that an idle
     * session can be retired and a busy one kept.
     */
    fun flowEnded() {
        if (activeFlows.decrementAndGet() <= 0) {
            activeFlows.set(0)
            idleSince = System.nanoTime()
        }
    }

    /** Closes the connection and every flow on it. */
    fun close() {
        fail(Unavailable("Nowhere: session closed"))
    }

    // MARK: - Transport

    /**
     * Brings the QUIC connection up and derives the auth frame from it.
     *
     * Called under [lock]. The exporter is asked for immediately after the
     * handshake because it is the only thing that ties the auth frame to this
     * connection: a frame built from any other material would be replayable.
     */
    private suspend fun ensureTransportLocked(): QuicConnection {
        when (phase.get()) {
            Phase.CLOSED -> throw Unavailable("Nowhere: session closed")
            Phase.IDLE -> Unit
            else -> {
                val existing = quic
                if (existing != null && existing.isConnected) return existing
                val failure = Unavailable("Nowhere: QUIC connection lost")
                fail(failure)
                throw failure
            }
        }

        val connection = QuicConnection(
            serverName = configuration.proxyHost,
            serverPort = configuration.proxyPort,
            alpn = listOf(configuration.alpn),
            tuning = QuicTuning.NOWHERE,
            fingerprint = configuration.tls.fingerprint,
            tlsServerName = configuration.tls.serverName.takeIf { it.isNotBlank() } ?: configuration.proxyHost,
            allowInsecure = configuration.tls.allowInsecure,
            pinnedCertSha256 = configuration.tls.pinnedCertSha256,
            verifyName = configuration.tls.verifyName
        )
        connection.onDatagramReceived = { bytes -> handleDatagram(bytes) }
        if (!connection.connect()) {
            connection.close()
            val failure = Unavailable("Nowhere: QUIC handshake failed")
            fail(failure)
            throw failure
        }

        // The TLS handshake refuses a server that selects an ALPN we did not
        // offer, and we offer exactly one, so a completed handshake is also
        // the ALPN check the protocol asks for.
        val exporter = connection.exportKeyingMaterial(
            label = NowhereProtocol.EXPORTER_LABEL.toByteArray(Charsets.US_ASCII),
            context = ByteArray(0),
            length = NowhereProtocol.EXPORTER_LENGTH
        ) ?: run {
            connection.close()
            val failure = Unavailable("Nowhere: no keying material to authenticate with")
            fail(failure)
            throw failure
        }

        authFrame = try {
            NowhereProtocol.makeAuthFrame(
                authKey = configuration.authKey,
                transport = NowhereProtocol.AuthTransport.QUIC,
                exporter = exporter,
                sessionId = configuration.sessionId
            )
        } catch (e: NowhereError) {
            connection.close()
            val failure = Unavailable("Nowhere: ${e.message}")
            fail(failure)
            throw failure
        }

        quic = connection
        phase.set(Phase.TRANSPORT_READY)
        logger.debug("[Nowhere] QUIC transport ready to ${configuration.proxyHost}")
        return connection
    }

    /**
     * Opens a stream, waiting for the portal to grant one.
     *
     * The portal hands out stream credit in its own time — one stream before
     * authentication, more after — and QUIC has no way to ask for more than
     * to wait for a MAX_STREAMS frame. Polling is bounded so a portal that
     * never grants any does not hold a dial forever.
     */
    private suspend fun openStreamWhenCreditAvailable(): QuicStream {
        val deadline = System.nanoTime() + STREAM_CREDIT_TIMEOUT_NANOS
        while (true) {
            if (phase.get() == Phase.CLOSED) throw Unavailable("Nowhere: session closed")
            val connection = quic ?: throw Unavailable("Nowhere: session is not ready")
            if (!connection.isConnected) {
                val failure = Unavailable("Nowhere: QUIC connection lost")
                fail(failure)
                throw failure
            }
            connection.openStream()?.let { return it }
            if (System.nanoTime() >= deadline) {
                throw NowhereError.ProtocolViolation("Nowhere: portal granted no stream credit")
            }
            connection.awaitCreditReady(STREAM_CREDIT_POLL_MS)
        }
    }

    /** Reads until the status byte is in, then splits off what followed it. */
    private suspend fun readOutcome(stream: QuicStream): NowhereFlowOpen.Outcome {
        var buffer = ByteArray(0)
        while (true) {
            NowhereFlowOpen.decode(buffer)?.let { return it }
            val chunk = stream.receive()
                ?: throw NowhereError.InvalidFlow("Stream closed before complete READY")
            buffer += chunk
        }
    }

    private fun becomeReady() {
        if (phase.compareAndSet(Phase.AUTHENTICATING, Phase.READY)) {
            authenticated.complete(Unit)
            startIdleSweep()
            logger.debug("[Nowhere] Authenticated with ${configuration.proxyHost}")
        }
    }

    // MARK: - Lifetime

    /**
     * Retires the session once nothing has used it for a while.
     *
     * A session is a live QUIC connection with its own keep-alives; one held
     * open with no flows on it is a socket spent on nothing and a steady
     * trickle of traffic for an observer to notice.
     */
    private fun startIdleSweep() {
        scope.launch {
            while (phase.get() != Phase.CLOSED) {
                delay(IDLE_SWEEP_MS)
                val since = idleSince
                if (activeFlows.get() == 0 && since != 0L &&
                    System.nanoTime() - since >= IDLE_CLOSE_NANOS
                ) {
                    logger.debug("[Nowhere] Closing idle session to ${configuration.proxyHost}")
                    close()
                    return@launch
                }
            }
        }
    }

    /**
     * Ends the session with [error], which every waiter then sees.
     *
     * Streams are closed by the connection itself; a flow reading one gets
     * end-of-stream and its owner releases whatever it leased.
     */
    private fun fail(error: Throwable) {
        val previous = phase.getAndSet(Phase.CLOSED)
        if (previous == Phase.CLOSED) return
        authenticated.completeExceptionally(error)
        val flows = udpFlows.keys.toList()
        for (flowId in flows) {
            udpFlows.remove(flowId)?.close()
            synchronized(reassembler) {
                reassembler.forget(flowId)
            }
        }
        scope.cancel()
        quic?.close()
        quic = null
        authFrame = null
        sessions.remove(configuration, this)
    }

    companion object {
        /** A portal that has not granted a stream in this long is not going to. */
        private const val STREAM_CREDIT_TIMEOUT_NANOS = 10_000_000_000L
        private const val STREAM_CREDIT_POLL_MS = 5L

        /** Fallback QUIC datagram payload budget when peer transport parameters report 0. */
        internal const val DEFAULT_MAX_DATAGRAM_PAYLOAD = 1200

        /** How long a session may sit without a flow before it is closed. */
        private const val IDLE_CLOSE_NANOS = 60_000_000_000L
        private const val IDLE_SWEEP_MS = 5_000L

        private val sessions = ConcurrentHashMap<NowhereConfiguration, NowhereSession>()

        /**
         * The session for [configuration], made if there is none alive.
         *
         * [NowhereConfiguration] compares by value, session id included, so
         * two dials for the same identity share a connection and a profile
         * whose key or carriers were edited gets a new one.
         */
        fun shared(configuration: NowhereConfiguration): NowhereSession {
            var stale: NowhereSession? = null
            val session = sessions.compute(configuration) { _, existing ->
                if (existing != null && existing.isUsable) {
                    existing
                } else {
                    stale = existing
                    NowhereSession(configuration)
                }
            }!!
            // Closed outside the compute: closing removes the session from
            // this map, and a ConcurrentHashMap refuses a recursive update of
            // the key it is already computing.
            stale?.close()
            return session
        }

        /** Drops [session] from the registry and closes it. */
        fun invalidate(session: NowhereSession) {
            sessions.remove(session.configuration, session)
            session.close()
        }

        /** Closes the session for [configuration], if there is one. */
        fun evict(configuration: NowhereConfiguration) {
            sessions.remove(configuration)?.close()
        }

        /** Closes every session, for a tunnel that is going down. */
        fun closeAll() {
            val all = sessions.values.toList()
            sessions.clear()
            all.forEach { it.close() }
        }
    }
}
