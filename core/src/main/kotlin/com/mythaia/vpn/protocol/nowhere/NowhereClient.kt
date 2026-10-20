package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Nowhere")

/**
 * Dials Nowhere over its QUIC and TLS-on-TCP carriers.
 *
 * A dial classifies the destination, leases a flow id, builds the flow request
 * (or the `OPEN` and `ATTACH` pair when uplink and downlink carriers differ),
 * and opens the flow over the configured carrier(s).
 *
 * The identity outlives any one connection on purpose. The portal pairs
 * everything a client does by session id, so a reconnect that chose a fresh
 * id would look like a second client; and a flow id must not be reused while
 * the flow it named is alive, which is why ids are leased and released rather
 * than counted.
 *
 * A dial is retried once when the session proved dead underneath it, or when
 * the portal answered `session replaced` — which is what a portal says after
 * it has lost this session and been told about it by another connection.
 * The retry is skipped when the request carried payload, because a request
 * the portal may already have acted on must not be sent twice.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {

    /**
     * Optional transport factory for unit tests to exercise the TLS carrier
     * (symmetric and asymmetric) against an in-memory [com.mythaia.vpn.protocol.tls.TlsServer].
     */
    internal var tlsTransportFactory: (() -> Transport)? = null

    /**
     * Opens a proxied TCP flow to [host]:[port].
     *
     * [initialData], when given, rides inside the flow request: the portal
     * holds it until the dial succeeds, so the first bytes cost no round
     * trip beyond the one the READY already costs.
     */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        val identity = Identity.of(configuration)
        val settings = settings(configuration, identity.sessionId)
        if (tunnel != null && (settings.uplink == NowhereNetwork.UDP || settings.downlink == NowhereNetwork.UDP)) {
            throw ProxyError.ProtocolError("Nowhere does not support proxy chains over QUIC")
        }

        val target = try {
            NowhereProtocol.Target.of(host, port)
        } catch (e: NowhereError) {
            throw ProxyError.ProtocolError("Nowhere: ${e.message}")
        }
        val carriesPayload = initialData != null && initialData.isNotEmpty()

        var retriesLeft = 1
        while (true) {
            val lease = identity.lease()
            val usesQuic = settings.uplink == NowhereNetwork.UDP || settings.downlink == NowhereNetwork.UDP
            val session = if (usesQuic) NowhereSession.shared(settings) else null
            try {
                if (settings.uplink == settings.downlink) {
                    val request = NowhereProtocol.encodeFlowRequest(
                        header = duplexHeader(lease.flowId, settings, NowhereProtocol.FlowKind.TCP),
                        target = target,
                        initialData = initialData
                    )
                    return when (settings.uplink) {
                        NowhereNetwork.UDP -> {
                            val flow = session!!.openFlow(request)
                            NowhereStreamConnection(flow.stream, flow.pending) {
                                lease.release()
                                session.flowEnded()
                            }
                        }
                        NowhereNetwork.TCP -> {
                            val flow = openTlsFlow(settings, request)
                            NowhereStreamConnection(flow.connection, flow.pending) {
                                lease.release()
                                flow.onClosed()
                            }
                        }
                    }
                } else {
                    val openRequest = NowhereProtocol.encodeFlowRequest(
                        header = NowhereProtocol.FlowHeader(
                            role = NowhereProtocol.FlowRole.OPEN,
                            flowId = lease.flowId,
                            kind = NowhereProtocol.FlowKind.TCP,
                            uplink = settings.uplink,
                            downlink = settings.downlink
                        ),
                        target = target,
                        initialData = initialData
                    )
                    val attachRequest = NowhereProtocol.encodeFlowRequest(
                        header = NowhereProtocol.FlowHeader(
                            role = NowhereProtocol.FlowRole.ATTACH,
                            flowId = lease.flowId,
                            kind = NowhereProtocol.FlowKind.TCP,
                            uplink = settings.uplink,
                            downlink = settings.downlink
                        ),
                        target = null,
                        initialData = null
                    )
                    val (upFlow, downFlow) = openAsymmetricStreamFlows(
                        settings = settings,
                        session = session,
                        openRequest = openRequest,
                        attachRequest = attachRequest
                    )
                    if (upFlow.pending.isNotEmpty()) {
                        upFlow.close()
                        downFlow.close()
                        throw NowhereError.ProtocolViolation(
                            "Unexpected downlink payload on Nowhere uplink stream"
                        )
                    }
                    return NowhereAsymmetricStreamConnection(
                        uplink = upFlow.connection,
                        downlink = downFlow.connection,
                        pending = downFlow.pending
                    ) {
                        lease.release()
                        upFlow.onClosed()
                        downFlow.onClosed()
                    }
                }
            } catch (e: Exception) {
                lease.release()
                val replaced = e is NowhereSession.FlowRejected &&
                    e.code == NowhereProtocol.FlowRejectCode.SESSION_REPLACED
                val stale = e is NowhereSession.Unavailable
                if (session != null && (replaced || stale)) NowhereSession.invalidate(session)

                // A stale session is safe to retry only if the portal cannot
                // have acted on the request; a replaced one told us it did
                // not, which makes the retry safe regardless.
                val replaySafe = !carriesPayload || replaced
                if (retriesLeft > 0 && tunnel == null && replaySafe && (replaced || stale)) {
                    retriesLeft -= 1
                    logger.debug("[Nowhere] Retrying $host:$port after: ${e.message}")
                    continue
                }
                throw when (e) {
                    is ProxyError -> e
                    is NowhereSession.FlowRejected ->
                        ProxyError.ProtocolError("Nowhere refused $host:$port: ${e.code.description}")
                    else -> ProxyError.ProtocolError(e.message ?: "Nowhere: dial failed")
                }
            }
        }
    }

    /**
     * Opens a proxied UDP flow to [host]:[port].
     *
     * Over the QUIC carrier (`UDP`), packets ride QUIC datagrams (with
     * fragmentation and reassembly) alongside a dedicated control stream.
     * Over the TLS carrier (`TCP`), packets ride the stream with a 2-byte
     * big-endian length prefix ([NowhereProtocol.encodeUdpStreamPacket]).
     * Asymmetric configurations (`up=tcp, down=udp` or `up=udp, down=tcp`)
     * pair an `OPEN` uplink half-flow with an `ATTACH` downlink half-flow.
     */
    suspend fun connectUDP(host: String, port: Int): ProxyConnection {
        val identity = Identity.of(configuration)
        val settings = settings(configuration, identity.sessionId)
        if (tunnel != null && (settings.uplink == NowhereNetwork.UDP || settings.downlink == NowhereNetwork.UDP)) {
            throw ProxyError.ProtocolError("Nowhere does not support proxy chains over QUIC")
        }

        val target = try {
            NowhereProtocol.Target.of(host, port)
        } catch (e: NowhereError) {
            throw ProxyError.ProtocolError("Nowhere: ${e.message}")
        }

        var retriesLeft = 1
        while (true) {
            val lease = identity.lease()
            val usesQuic = settings.uplink == NowhereNetwork.UDP || settings.downlink == NowhereNetwork.UDP
            val session = if (usesQuic) NowhereSession.shared(settings) else null
            try {
                if (settings.uplink == settings.downlink) {
                    val request = NowhereProtocol.encodeFlowRequest(
                        header = duplexHeader(lease.flowId, settings, NowhereProtocol.FlowKind.UDP),
                        target = target,
                        initialData = null
                    )
                    return when (settings.uplink) {
                        NowhereNetwork.UDP -> {
                            val quicUdp = session!!.openUdpFlow(lease.flowId, request)
                            NowhereQuicUdpConnection(quicUdp) {
                                lease.release()
                            }
                        }
                        NowhereNetwork.TCP -> {
                            val tlsFlow = openTlsFlow(settings, request)
                            NowhereUdpStreamConnection(tlsFlow.connection, tlsFlow.pending) {
                                lease.release()
                                tlsFlow.onClosed()
                            }
                        }
                    }
                } else {
                    val openRequest = NowhereProtocol.encodeFlowRequest(
                        header = NowhereProtocol.FlowHeader(
                            role = NowhereProtocol.FlowRole.OPEN,
                            flowId = lease.flowId,
                            kind = NowhereProtocol.FlowKind.UDP,
                            uplink = settings.uplink,
                            downlink = settings.downlink
                        ),
                        target = target,
                        initialData = null
                    )
                    val attachRequest = NowhereProtocol.encodeFlowRequest(
                        header = NowhereProtocol.FlowHeader(
                            role = NowhereProtocol.FlowRole.ATTACH,
                            flowId = lease.flowId,
                            kind = NowhereProtocol.FlowKind.UDP,
                            uplink = settings.uplink,
                            downlink = settings.downlink
                        ),
                        target = null,
                        initialData = null
                    )
                    return openAsymmetricUdpFlow(
                        flowId = lease.flowId,
                        settings = settings,
                        session = session!!,
                        openRequest = openRequest,
                        attachRequest = attachRequest,
                        onClosed = { lease.release() }
                    )
                }
            } catch (e: Exception) {
                lease.release()
                val replaced = e is NowhereSession.FlowRejected &&
                    e.code == NowhereProtocol.FlowRejectCode.SESSION_REPLACED
                val stale = e is NowhereSession.Unavailable
                if (session != null && (replaced || stale)) NowhereSession.invalidate(session)

                if (retriesLeft > 0 && tunnel == null && (replaced || stale)) {
                    retriesLeft -= 1
                    logger.debug("[Nowhere] Retrying UDP $host:$port after: ${e.message}")
                    continue
                }
                throw when (e) {
                    is ProxyError -> e
                    is NowhereSession.FlowRejected ->
                        ProxyError.ProtocolError("Nowhere refused UDP $host:$port: ${e.code.description}")
                    else -> ProxyError.ProtocolError(e.message ?: "Nowhere: UDP dial failed")
                }
            }
        }
    }

    private class OpenedCarrierFlow(
        val connection: ProxyConnection,
        val pending: ByteArray,
        val onClosed: () -> Unit
    ) {
        fun close() {
            runCatching { connection.cancel() }
            runCatching { onClosed() }
        }
    }

    private suspend fun openStreamHalf(
        carrier: NowhereNetwork,
        settings: NowhereConfiguration,
        session: NowhereSession?,
        request: ByteArray
    ): OpenedCarrierFlow = when (carrier) {
        NowhereNetwork.UDP -> {
            val s = session ?: throw NowhereSession.Unavailable("Nowhere: missing QUIC session")
            val flow = s.openFlow(request)
            OpenedCarrierFlow(
                connection = flow.stream,
                pending = flow.pending,
                onClosed = { s.flowEnded() }
            )
        }
        NowhereNetwork.TCP -> openTlsFlow(settings, request)
    }

    private suspend fun openAsymmetricStreamFlows(
        settings: NowhereConfiguration,
        session: NowhereSession?,
        openRequest: ByteArray,
        attachRequest: ByteArray
    ): Pair<OpenedCarrierFlow, OpenedCarrierFlow> {
        var openedUp: OpenedCarrierFlow? = null
        var openedDown: OpenedCarrierFlow? = null
        val refLock = Any()
        return try {
            coroutineScope {
                val upJob = async {
                    openStreamHalf(settings.uplink, settings, session, openRequest).also {
                        synchronized(refLock) { openedUp = it }
                    }
                }
                val downJob = async {
                    openStreamHalf(settings.downlink, settings, session, attachRequest).also {
                        synchronized(refLock) { openedDown = it }
                    }
                }
                Pair(upJob.await(), downJob.await())
            }
        } catch (e: Exception) {
            synchronized(refLock) {
                openedUp?.close()
                openedDown?.close()
            }
            throw e
        }
    }

    private suspend fun openAsymmetricUdpFlow(
        flowId: Long,
        settings: NowhereConfiguration,
        session: NowhereSession,
        openRequest: ByteArray,
        attachRequest: ByteArray,
        onClosed: () -> Unit
    ): ProxyConnection {
        val refLock = Any()
        if (settings.uplink == NowhereNetwork.TCP && settings.downlink == NowhereNetwork.UDP) {
            var upTls: OpenedCarrierFlow? = null
            var downQuic: NowhereSession.OpenedUdpFlow? = null
            return try {
                coroutineScope {
                    val upJob = async {
                        openTlsFlow(settings, openRequest).also { synchronized(refLock) { upTls = it } }
                    }
                    val downJob = async {
                        session.openUdpFlow(flowId, attachRequest).also { synchronized(refLock) { downQuic = it } }
                    }
                    val up = upJob.await()
                    val down = downJob.await()
                    if (up.pending.isNotEmpty()) {
                        throw NowhereError.ProtocolViolation(
                            "Unexpected downlink payload on Nowhere UDP uplink stream"
                        )
                    }
                    val streamUp = NowhereUdpStreamConnection(up.connection, ByteArray(0), up.onClosed)
                    val quicDown = NowhereQuicUdpConnection(down) {}
                    NowhereAsymmetricStreamConnection(
                        uplink = streamUp,
                        downlink = quicDown,
                        pending = ByteArray(0),
                        onClosed = onClosed
                    )
                }
            } catch (e: Exception) {
                synchronized(refLock) {
                    upTls?.close()
                    downQuic?.close(sendCloseControl = true)
                }
                throw e
            }
        } else {
            var upQuic: NowhereSession.OpenedUdpFlow? = null
            var downTls: OpenedCarrierFlow? = null
            return try {
                coroutineScope {
                    val upJob = async {
                        session.openUdpFlow(flowId, openRequest).also { synchronized(refLock) { upQuic = it } }
                    }
                    val downJob = async {
                        openTlsFlow(settings, attachRequest).also { synchronized(refLock) { downTls = it } }
                    }
                    val up = upJob.await()
                    val down = downJob.await()
                    val quicUp = NowhereQuicUdpConnection(up) {}
                    val streamDown = NowhereUdpStreamConnection(down.connection, down.pending, down.onClosed)
                    NowhereAsymmetricStreamConnection(
                        uplink = quicUp,
                        downlink = streamDown,
                        pending = ByteArray(0),
                        onClosed = onClosed
                    )
                }
            } catch (e: Exception) {
                synchronized(refLock) {
                    upQuic?.close(sendCloseControl = true)
                    downTls?.close()
                }
                throw e
            }
        }
    }

    /**
     * Opens one authenticated Nowhere flow over the TLS-on-TCP carrier.
     *
     * Every TLS carrier connection is authenticated with a 32-byte frame bound
     * to its own TLS 1.3 exporter (`EXPORTER-Nowhere-Auth`) and sent in one
     * write with [request].
     */
    private suspend fun openTlsFlow(
        settings: NowhereConfiguration,
        request: ByteArray
    ): OpenedCarrierFlow {
        val client = TlsClient(settings.tcpTlsConfiguration)
        val record = when {
            tlsTransportFactory != null -> client.connect(tlsTransportFactory!!.invoke())
            tunnel != null -> client.connect(TunneledTransport(tunnel))
            else -> client.connect(settings.proxyHost, settings.proxyPort)
        }
        try {
            val negotiatedAlpn = record.negotiatedAlpn
            if (negotiatedAlpn == null || !settings.acceptsNegotiatedAlpn(negotiatedAlpn)) {
                throw NowhereError.ProtocolViolation("Invalid Nowhere ALPN")
            }
            val exporter = record.exportKeyingMaterial(
                label = NowhereProtocol.EXPORTER_LABEL.toByteArray(Charsets.US_ASCII),
                context = ByteArray(0),
                length = NowhereProtocol.EXPORTER_LENGTH
            ) ?: throw NowhereError.AuthenticationRejected("Missing TLS exporter material")
            val authFrame = NowhereProtocol.makeAuthFrame(
                authKey = settings.authKey,
                transport = NowhereProtocol.AuthTransport.TLS_TCP,
                exporter = exporter,
                sessionId = settings.sessionId
            )
            val payload = NowhereFlowOpen.bootstrapPayload(authFrame, request)
            record.send(payload)

            var buffer = ByteArray(0)
            val outcome: NowhereFlowOpen.Outcome
            while (true) {
                val decoded = NowhereFlowOpen.decode(buffer)
                if (decoded != null) {
                    outcome = decoded
                    break
                }
                val chunk = record.receive()
                if (chunk == null || chunk.isEmpty()) {
                    throw NowhereError.InvalidFlow("Stream closed before complete READY")
                }
                buffer += chunk
            }
            return when (outcome) {
                is NowhereFlowOpen.Outcome.Ready -> OpenedCarrierFlow(
                    connection = TlsCarrierConnection(record),
                    pending = outcome.pending,
                    onClosed = {}
                )
                is NowhereFlowOpen.Outcome.Rejected -> throw NowhereSession.FlowRejected(outcome.code)
            }
        } catch (e: Exception) {
            runCatching { record.cancel() }
            throw e
        }
    }

    /**
     * One client's identity at a portal: its session id, and which flow ids
     * are in use under it.
     *
     * Keyed by everything that makes a profile a distinct client — the id and
     * every field the auth frame or the flow header depends on — so editing a
     * profile's key or carriers starts a new identity while a mere rename
     * keeps the old one.
     */
    internal class Identity private constructor(val sessionId: ByteArray) {

        private val active = HashSet<Long>()
        private var nextFlowId = 1L

        /**
         * Leases the next free flow id.
         *
         * Ids run upward and wrap past 2^32 - 1 back to 1, skipping zero,
         * which the protocol reserves, and anything still leased. The search
         * is bounded by the number of leases plus one, which is enough to
         * find a free id if one exists.
         */
        @Synchronized
        fun lease(): Lease {
            var candidate = if (nextFlowId < 1L) 1L else nextFlowId
            for (attempt in 0..active.size) {
                if (candidate != 0L && candidate !in active) {
                    active.add(candidate)
                    nextFlowId = candidate + 1
                    if (nextFlowId > MAX_FLOW_ID) nextFlowId = 1L
                    return Lease(candidate, this)
                }
                candidate += 1
                if (candidate > MAX_FLOW_ID) candidate = 1L
            }
            throw ProxyError.ProtocolError("Nowhere flow ID space exhausted")
        }

        @Synchronized
        internal fun release(flowId: Long) {
            active.remove(flowId)
        }

        /** How many ids are leased right now. */
        val leased: Int
            @Synchronized get() = active.size

        /**
         * A flow id held until released. Releasing twice is harmless, since
         * both the connection's end and its owner's cancel may get there.
         */
        class Lease internal constructor(val flowId: Long, private val identity: Identity) {
            private val released = AtomicBoolean(false)

            fun release() {
                if (released.compareAndSet(false, true)) identity.release(flowId)
            }
        }

        private data class Key(
            val id: UUID,
            val host: String,
            val port: UShort,
            val key: String,
            val uplink: String?,
            val downlink: String?,
            val multiplex: Boolean,
            val tls: TlsConfiguration?
        )

        companion object {
            /** The largest value four bytes of flow id can carry. */
            const val MAX_FLOW_ID = 0xFFFFFFFFL

            private val identities = ConcurrentHashMap<Key, Identity>()
            private val random = SecureRandom()

            fun of(configuration: ProxyConfiguration): Identity =
                identities.getOrPut(key(configuration)) { fresh() }

            /** The identity [configuration] already has, without making one. */
            fun existing(configuration: ProxyConfiguration): Identity? = identities[key(configuration)]

            /** What makes two profiles one client, and so share one session. */
            fun keyOf(configuration: ProxyConfiguration): Any = key(configuration)

            private fun key(configuration: ProxyConfiguration) = Key(
                id = configuration.id,
                host = configuration.serverAddress,
                port = configuration.serverPort,
                key = configuration.password.orEmpty(),
                uplink = configuration.nowhereUplink,
                downlink = configuration.nowhereDownlink,
                multiplex = configuration.nowhereMultiplex,
                tls = configuration.tls
            )

            /** An identity nobody else holds, for tests and for a new profile. */
            fun fresh(): Identity =
                Identity(ByteArray(NowhereProtocol.SESSION_ID_SIZE).also { random.nextBytes(it) })

            fun reset() {
                identities.clear()
            }
        }
    }

    companion object {
        /**
         * Turns a profile into the carrier's own configuration.
         *
         * Carriers are stored as the link spelled them; an absent one is
         * `udp`, the reference default. An unknown spelling is refused here
         * rather than defaulted, because the flow header would otherwise name
         * a carrier the user never asked for.
         */
        internal fun settings(
            configuration: ProxyConfiguration,
            sessionId: ByteArray
        ): NowhereConfiguration {
            val key = configuration.password?.takeIf { it.isNotEmpty() }
                ?: throw ProxyError.ProtocolError("Nowhere key not set")
            val tls = configuration.tls
                ?: throw ProxyError.ProtocolError("Nowhere requires TLS configuration")
            return try {
                NowhereConfiguration(
                    proxyHost = configuration.serverAddress,
                    proxyPort = configuration.serverPort.toInt(),
                    key = key,
                    uplink = carrier(configuration.nowhereUplink, "up"),
                    downlink = carrier(configuration.nowhereDownlink, "down"),
                    requestedMultiplex = configuration.nowhereMultiplex,
                    sessionId = sessionId,
                    tls = tls
                )
            } catch (e: NowhereError) {
                throw ProxyError.ProtocolError("Nowhere: ${e.message}")
            }
        }

        private fun carrier(spelling: String?, name: String): NowhereNetwork {
            if (spelling == null) return NowhereNetwork.UDP
            return NowhereNetwork.fromWireName(spelling)
                ?: throw ProxyError.ProtocolError("Nowhere: invalid $name carrier '$spelling'")
        }

        /**
         * The header of a flow that rides one carrier both ways.
         *
         * A client always emits a hop count of zero; portals raise it as they
         * forward.
         */
        internal fun duplexHeader(
            flowId: Long,
            settings: NowhereConfiguration,
            kind: NowhereProtocol.FlowKind = NowhereProtocol.FlowKind.TCP
        ): NowhereProtocol.FlowHeader =
            NowhereProtocol.FlowHeader(
                role = NowhereProtocol.FlowRole.DUPLEX,
                flowId = flowId,
                kind = kind,
                uplink = settings.uplink,
                downlink = settings.downlink
            )

        /**
         * Releases every session and forgets every identity, for a tunnel
         * that is going down. A fresh tunnel then presents fresh session ids,
         * as the reference does when its transport pool is reclaimed.
         */
        fun shutdown() {
            NowhereSession.closeAll()
            Identity.reset()
        }

        /** Where a profile's session is pooled: under its identity, which a session belongs to. */
        internal fun poolKey(configuration: ProxyConfiguration): Any = Identity.keyOf(configuration)

        /**
         * Closes the session a latency test dialled for [configuration].
         *
         * Its own idle sweep takes a minute, and a test across a subscription
         * opens a QUIC connection — a socket and two threads — per server far
         * faster than that. The identity is kept, as an idle close keeps it.
         */
        internal fun release(configuration: ProxyConfiguration) {
            val identity = Identity.existing(configuration) ?: return
            val settings = runCatching { settings(configuration, identity.sessionId) }.getOrNull() ?: return
            NowhereSession.evict(settings)
        }
    }
}

/**
 * Adapts a [TlsRecordConnection] to [ProxyConnection] for the Nowhere TLS carrier.
 */
private class TlsCarrierConnection(
    private val record: TlsRecordConnection
) : ProxyConnection() {

    private val closed = AtomicBoolean(false)

    override val outerTlsVersion: TlsVersion?
        get() = if (record.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12

    override val isConnected: Boolean
        get() = !closed.get() && record.connection != null

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        record.send(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        record.sendAsync(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        val data = record.receive()
        if (data == null || data.isEmpty()) {
            closed.set(true)
            return null
        }
        return data
    }

    override fun cancel() {
        if (closed.compareAndSet(false, true)) {
            record.cancel()
        }
    }
}

/**
 * A flow presented as a proxy connection.
 *
 * Two things sit between the caller and the stream underneath. The portal
 * may send payload in the same packet as READY, and those bytes belong to
 * the caller, so they are handed out before anything more is read. And the
 * flow id leased for this connection must go back when the flow ends,
 * whether it ends by cancel or by the far side finishing; [onClosed] runs
 * exactly once for either.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereStreamConnection(
    private val inner: ProxyConnection,
    pending: ByteArray,
    private val onClosed: () -> Unit
) : ProxyConnection() {

    private var pending: ByteArray? = pending.takeIf { it.isNotEmpty() }
    private val pendingLock = Any()
    private val closed = AtomicBoolean(false)

    /** Both QUIC and Nowhere's TLS carrier use TLS 1.3 exclusively. */
    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = !closed.get() && inner.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        inner.sendRaw(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        inner.sendRawAsync(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        synchronized(pendingLock) {
            val held = pending
            if (held != null) {
                pending = null
                return held
            }
        }
        if (closed.get()) return null
        return try {
            val data = inner.receiveRaw()
            if (data == null) finish()
            data
        } catch (e: Throwable) {
            finish()
            throw e
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        inner.cancel()
        onClosed()
    }

    private fun finish() {
        if (closed.compareAndSet(false, true)) onClosed()
    }
}

/**
 * An asymmetric flow where writes go out on [uplink] (`OPEN`) and reads come
 * back on [downlink] (`ATTACH`).
 */
class NowhereAsymmetricStreamConnection(
    private val uplink: ProxyConnection,
    private val downlink: ProxyConnection,
    pending: ByteArray,
    private val onClosed: () -> Unit
) : ProxyConnection() {

    private var pending: ByteArray? = pending.takeIf { it.isNotEmpty() }
    private val pendingLock = Any()
    private val closed = AtomicBoolean(false)

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = !closed.get() && uplink.isConnected && downlink.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        uplink.sendRaw(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        uplink.sendRawAsync(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        synchronized(pendingLock) {
            val held = pending
            if (held != null) {
                pending = null
                return held
            }
        }
        if (closed.get()) return null
        return try {
            val data = downlink.receiveRaw()
            if (data == null) {
                finish()
            }
            data
        } catch (e: Throwable) {
            finish()
            throw e
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { uplink.cancel() }
        runCatching { downlink.cancel() }
        onClosed()
    }

    private fun finish() {
        if (closed.compareAndSet(false, true)) {
            runCatching { uplink.cancel() }
            runCatching { downlink.cancel() }
            onClosed()
        }
    }
}

/**
 * A UDP flow carried over a stream (TLS carrier), where each datagram is
 * prefixed with a 2-byte big-endian length ([NowhereProtocol.encodeUdpStreamPacket]
 * and [NowhereProtocol.decodeUdpStreamPacket]).
 */
class NowhereUdpStreamConnection(
    private val inner: ProxyConnection,
    pending: ByteArray,
    private val onClosed: () -> Unit
) : ProxyConnection() {

    private var readBuffer: ByteArray = pending.copyOf()
    private var readOffset: Int = 0
    private val readMutex = Mutex()
    private val closed = AtomicBoolean(false)

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = !closed.get() && inner.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        val framed = try {
            NowhereProtocol.encodeUdpStreamPacket(data)
        } catch (_: NowhereError.PacketTooLarge) {
            return
        }
        inner.sendRaw(framed)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        val framed = try {
            NowhereProtocol.encodeUdpStreamPacket(data)
        } catch (_: NowhereError.PacketTooLarge) {
            return
        }
        inner.sendRawAsync(framed)
    }

    override suspend fun receiveRaw(): ByteArray? {
        readMutex.withLock {
            while (true) {
                val decoded = NowhereProtocol.decodeUdpStreamPacket(readBuffer, readOffset)
                if (decoded != null) {
                    readOffset += decoded.consumed
                    compactReadBufferIfNeeded()
                    return decoded.payload
                }
                if (closed.get()) return null
                val chunk = inner.receiveRaw()
                if (chunk == null || chunk.isEmpty()) {
                    val unconsumed = readBuffer.size - readOffset
                    readBuffer = ByteArray(0)
                    readOffset = 0
                    finish()
                    if (unconsumed > 0) {
                        throw NowhereError.ProtocolViolation("Truncated Nowhere UDP stream packet")
                    }
                    return null
                }
                if (readOffset > 0) {
                    readBuffer = readBuffer.copyOfRange(readOffset, readBuffer.size)
                    readOffset = 0
                }
                readBuffer += chunk
            }
        }
    }

    private fun compactReadBufferIfNeeded() {
        if (readOffset == readBuffer.size) {
            readBuffer = ByteArray(0)
            readOffset = 0
        } else if (readOffset >= 4096 && readOffset * 2 >= readBuffer.size) {
            readBuffer = readBuffer.copyOfRange(readOffset, readBuffer.size)
            readOffset = 0
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        inner.cancel()
        onClosed()
    }

    private fun finish() {
        if (closed.compareAndSet(false, true)) onClosed()
    }
}

/**
 * A UDP flow carried over QUIC datagrams and a dedicated control stream.
 */
class NowhereQuicUdpConnection(
    private val flow: NowhereSession.OpenedUdpFlow,
    private val onClosed: () -> Unit
) : ProxyConnection() {

    private val closed = AtomicBoolean(false)

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = !closed.get() && flow.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        flow.send(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        flow.send(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        return try {
            val packet = flow.receive()
            if (packet == null) finish()
            packet
        } catch (e: Throwable) {
            finish()
            throw e
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        flow.close(sendCloseControl = true)
        onClosed()
    }

    private fun finish() {
        if (closed.compareAndSet(false, true)) {
            flow.close(sendCloseControl = false)
            onClosed()
        }
    }
}

