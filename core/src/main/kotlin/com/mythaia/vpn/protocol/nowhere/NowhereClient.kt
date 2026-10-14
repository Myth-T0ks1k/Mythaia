package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Nowhere")

/**
 * Dials Nowhere over its QUIC carrier.
 *
 * A dial is short: classify the destination, lease a flow id, build the
 * duplex flow request, and hand it to the shared [NowhereSession], which
 * owns the connection and the authentication. What is left for this layer is
 * the identity — the session id and the flow ids that are unique within it —
 * and the decision to try again.
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
 * Only a duplex flow on the QUIC carrier (`up=udp`, `down=udp`) is dialled.
 * The TLS-on-TCP carrier, the asymmetric shapes and the multiplexer pool the
 * reference builds on it are not wired; a profile asking for them is refused
 * with a message saying so rather than dialled wrongly.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereClient(
    private val configuration: ProxyConfiguration,
    private val tunnel: ProxyConnection? = null
) {

    /**
     * Opens a proxied TCP flow to [host]:[port].
     *
     * [initialData], when given, rides inside the flow request: the portal
     * holds it until the dial succeeds, so the first bytes cost no round
     * trip beyond the one the READY already costs.
     */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        if (tunnel != null) {
            throw ProxyError.ProtocolError("Nowhere does not support proxy chains yet")
        }
        val identity = Identity.of(configuration)
        val settings = settings(configuration, identity.sessionId)
        carrierRefusal(settings.uplink, settings.downlink)?.let {
            throw ProxyError.ProtocolError(it)
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
            val session = NowhereSession.shared(settings)
            try {
                val request = NowhereProtocol.encodeFlowRequest(
                    header = duplexHeader(lease.flowId, settings),
                    target = target,
                    initialData = initialData
                )
                val flow = session.openFlow(request)
                return NowhereStreamConnection(flow.stream, flow.pending) {
                    lease.release()
                    session.flowEnded()
                }
            } catch (e: Exception) {
                lease.release()
                val replaced = e is NowhereSession.FlowRejected &&
                    e.code == NowhereProtocol.FlowRejectCode.SESSION_REPLACED
                val stale = e is NowhereSession.Unavailable
                if (replaced || stale) NowhereSession.invalidate(session)

                // A stale session is safe to retry only if the portal cannot
                // have acted on the request; a replaced one told us it did
                // not, which makes the retry safe regardless.
                val replaySafe = !carriesPayload || replaced
                if (retriesLeft > 0 && replaySafe && (replaced || stale)) {
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
     * UDP over Nowhere rides QUIC datagrams with its own control stream,
     * fragmentation and reassembly budget; none of that is wired to the flow
     * layer here yet.
     */
    suspend fun connectUDP(host: String, port: Int): ProxyConnection {
        throw ProxyError.ProtocolError("Nowhere UDP is not wired to the flow layer yet")
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
         * Why this build cannot dial the given carriers, or null when it can.
         *
         * Only the QUIC carrier in both directions is implemented. The TLS
         * carrier needs an exporter from the TLS record layer, and every
         * other shape is built on that carrier.
         */
        internal fun carrierRefusal(uplink: NowhereNetwork, downlink: NowhereNetwork): String? {
            if (uplink == NowhereNetwork.UDP && downlink == NowhereNetwork.UDP) return null
            return "Nowhere over a TLS carrier is not wired yet; this build dials the QUIC " +
                "carrier only (up=udp, down=udp), not up=${uplink.wireName} down=${downlink.wireName}"
        }

        /**
         * The header of a TCP flow that rides one carrier both ways.
         *
         * A client always emits a hop count of zero; portals raise it as they
         * forward.
         */
        internal fun duplexHeader(flowId: Long, settings: NowhereConfiguration): NowhereProtocol.FlowHeader =
            NowhereProtocol.FlowHeader(
                role = NowhereProtocol.FlowRole.DUPLEX,
                flowId = flowId,
                kind = NowhereProtocol.FlowKind.TCP,
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

    /** The carrier is QUIC, whose TLS is 1.3 by definition. */
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
        val data = inner.receiveRaw()
        if (data == null) finish()
        return data
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
