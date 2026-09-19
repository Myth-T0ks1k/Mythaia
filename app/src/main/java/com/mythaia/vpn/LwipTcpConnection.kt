package com.mythaia.vpn

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.TlsClientHelloSniffer
import com.mythaia.vpn.util.TransportErrorLogger
import com.mythaia.vpn.mitm.MitmByteLeg
import com.mythaia.vpn.mitm.MitmRuleStore
import com.mythaia.vpn.mitm.MitmSession
import com.mythaia.vpn.mitm.TlsRecordByteLeg
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.direct.DirectTcpRelay
import com.mythaia.vpn.protocol.tls.TlsClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import com.mythaia.vpn.util.TransportLogLevel

/**
 * Represents a single TCP connection through the VPN.
 *
 * Bridges between the lwIP PCB (protocol control block) on the local side
 * and either a VLESS proxy connection or a direct TCP relay on the remote side.
 *
 * All lwIP calls must happen on the lwIP executor thread.
 * Protocol connect/send/receive use coroutines dispatched on the lwIP executor.
 */
class LwipTcpConnection(
    val connId: Long,
    val pcb: Long,
    dstHost: String,
    val dstPort: Int,
    configuration: ProxyConfiguration,
    forceBypass: Boolean,
    sniffSNI: Boolean,
    private val lwipExecutor: ScheduledExecutorService
) {
    /**
     * Destination the proxy will be asked to connect to. Initialized from
     * the tcp_accept signal and may be replaced with the SNI hostname
     * once sniffing resolves.
     */
    var dstHost: String = dstHost
        private set

    /**
     * Routing configuration for this connection. Mutable because a
     * successful SNI sniff can re-match a domain rule that points to a
     * different proxy.
     */
    var configuration: ProxyConfiguration = configuration
        private set

    // Coroutine scope for protocol operations, dispatched on the lwIP executor
    private val scopeJob = SupervisorJob()
    private val scope = CoroutineScope(lwipExecutor.asCoroutineDispatcher() + scopeJob)

    // Connection paths (mutually exclusive)
    private var vlessConnection: ProxyConnection? = null
    private var directRelay: DirectTcpRelay? = null

    private var vlessConnecting = false
    private var directConnecting = false

    /**
     * When set, this connection is being MITM-intercepted: the client TLS is
     * terminated locally and the exchange runs through [MitmSession]. Non-null
     * only after [beginMitmIfConfigured] commits, which happens solely when the
     * shared [MitmRuleStore] holds both a matching enabled rule set AND a CA. On
     * the default (empty) store it stays null, so every path below behaves
     * byte-for-byte as it did before the MITM hook existed.
     */
    private var mitmInner: MitmInnerTransport? = null

    // Upload coalescing: accumulates multiple TCP segments into a single batch
    // before sending to the proxy protocol, reducing per-segment encryption overhead.
    private var coalesceBuffer: ByteArrayOutputStream? = null
    private var coalesceScheduled = false
    private var coalesceFlushInFlight = false

    /**
     * Whether the connection should bypass the configured proxy and connect
     * directly. May flip after SNI sniff resolves a routing rule.
     */
    private var bypass: Boolean = forceBypass ||
        (LwipStack.instance?.shouldBypass(dstHost) == true)

    private var pendingData = ByteArrayOutputStream()
    var closed = false
        private set

    // When present, the connection is in the "sniff" phase: inbound bytes
    // are buffered (in `pendingData`) and fed to the sniffer before the
    // proxy is dialed. The first terminal state (Found / NotTls /
    // Unavailable) commits the route and kicks off the proxy connect.
    // Cleared to null once the route is committed.
    private var sniffer: TlsClientHelloSniffer? =
        if (sniffSNI) TlsClientHelloSniffer() else null

    /**
     * Fires if the sniff phase doesn't resolve within [TunnelConstants.sniffDeadlineMs]
     * — commits the IP-based route so server-speaks-first protocols
     * (SSH, SMTP, FTP) don't stall waiting for a ClientHello.
     */
    private var sniffDeadline: ScheduledFuture<*>? = null

    /**
     * Downlink bytes received from the proxy that haven't been pushed into
     * lwIP's TCP send buffer yet. Holds ALL outstanding downlink bytes —
     * a concurrently prefetched receive appends here without racing the
     * ongoing drain.
     */
    private var pendingWrite = ByteArrayOutputStream()

    /**
     * True while a proxy receive is in flight. Guards against issuing a
     * parallel receive on top of an existing one.
     */
    private var receiveInFlight = false

    private var activityTimer: ActivityTimer? = null
    private var handshakeTimer: ScheduledFuture<*>? = null
    private var uplinkDone = false
    private var downlinkDone = false

    init {
        // Handshake timeout (60s) — covers both the SNI-sniff wait and the
        // proxy dial, so a stalled client can't hold a connection open
        // indefinitely before we ever call connect.
        handshakeTimer = lwipExecutor.schedule({
            if (!closed && isEstablishing) {
                val phase = if (sniffer != null) "TLS ClientHello sniff" else "proxy dial"
                logger.error("[TCP] Handshake timeout during $phase: $dstHost:$dstPort")
                abort()
            }
        }, TunnelConstants.handshakeTimeoutMs, TimeUnit.MILLISECONDS)

        // If we're sniffing, wait for the first ClientHello bytes in
        // handleReceivedData before choosing a route. Otherwise commit
        // immediately using the IP-derived configuration.
        if (sniffer == null) {
            beginConnecting()
        } else {
            // Safety net: non-TLS protocols where the server speaks first
            // (SSH, SMTP, FTP) never send client bytes of their own accord.
            // If we haven't decided by TunnelConstants.sniffDeadlineMs, commit the IP-
            // based route and proceed.
            sniffDeadline = lwipExecutor.schedule({
                if (!closed && sniffer != null) {
                    sniffer = null
                    beginConnecting()
                }
            }, TunnelConstants.sniffDeadlineMs, TimeUnit.MILLISECONDS)
        }
    }

    private val isEstablishing: Boolean
        get() = vlessConnecting || directConnecting || sniffer != null

    /** Cancels the sniff deadline timer. Called whenever the sniff phase
     *  resolves (successful SNI, fast reject, cap reached, close, abort). */
    private fun cancelSniffDeadline() {
        sniffDeadline?.cancel(false)
        sniffDeadline = null
    }

    /**
     * Appends to `pendingData` and enforces [TunnelConstants.tcpMaxPendingDataSize].
     * Aborts the connection if the cap would be exceeded and returns
     * `false` so callers can bail out early.
     */
    private fun appendPendingData(data: ByteArray): Boolean {
        if (pendingData.size() + data.size > TunnelConstants.tcpMaxPendingDataSize) {
            logger.warning(
                "[TCP] pendingData cap exceeded for $dstHost:$dstPort " +
                "(${pendingData.size()} + ${data.size} > ${TunnelConstants.tcpMaxPendingDataSize}), aborting"
            )
            abort()
            return false
        }
        pendingData.write(data)
        return true
    }

    /**
     * Kicks off the outbound connection using the currently committed
     * routing (configuration, bypass, dstHost). Idempotent — no-op once
     * the connect has started or completed.
     */
    private fun beginConnecting() {
        if (closed || vlessConnecting || directConnecting) return
        if (vlessConnection != null || directRelay != null) return
        if (bypass) connectDirect() else connectProxy()
    }

    /**
     * If the shared [MitmRuleStore] is configured to intercept [sni], commits
     * this connection to a local MITM session and returns `true`; otherwise
     * disturbs nothing and returns `false`, leaving the caller to run the normal
     * [beginConnecting].
     *
     * The two `?: return false` guards below are the whole inertness contract:
     * on the default (empty) store [MitmRuleStore.interceptionFor] returns `null`
     * for every host and [MitmRuleStore.authority] is `null`, so this returns
     * `false` before reading or mutating any connection state — the store-empty
     * path is byte-for-byte the pre-hook behaviour.
     *
     * When it does commit, it plays the same post-route setup the normal dial
     * paths do: it consumes the buffered ClientHello from [pendingData] and acks
     * it (so a later `close()` sends a FIN, not an RST — see [rejectGracefully]),
     * cancels the handshake timer, installs the activity timer, snapshots the
     * post-[applySNI] route, and launches [MitmSession.intercept] OFF the lwIP
     * thread (see below), returning `true`.
     */
    private fun beginMitmIfConfigured(sni: String): Boolean {
        val ruleSet = MitmRuleStore.shared.interceptionFor(sni) ?: return false
        val authority = MitmRuleStore.shared.authority() ?: return false

        // Take the buffered ClientHello (and anything the sniffer read alongside
        // it) and ack it: those bytes are consumed by the local TLS termination,
        // never forwarded upstream, so lwIP must be told or close() emits an RST.
        val clientHello = pendingData.toByteArray()
        pendingData.reset()
        ackBytesToLwip(clientHello.size)

        // Replace the handshake-timeout safety net with the activity timer, just
        // as the normal dial paths do once they connect.
        handshakeTimer?.cancel(false)
        handshakeTimer = null
        activityTimer = ActivityTimer(lwipExecutor, TunnelConstants.connectionIdleTimeoutMs) {
            if (!closed) close()
        }

        val inner = MitmInnerTransport()
        mitmInner = inner

        // Snapshot the route the sniff committed (post-applySNI) so the outer
        // dial to the real origin uses the same configuration/bypass decision.
        val routeConfig = configuration
        val routeBypass = bypass
        val port = dstPort

        // CORRECTION #1: run the interception on Dispatchers.IO, NOT the lwIP
        // executor. The bridge blocks its thread (MitmRegexGuard Future.get up to
        // 1s/message, TLS crypto, decompression, per-leaf P-256 keygen); on the
        // single lwIP thread that would freeze every flow. The launch is still a
        // child of scopeJob (so releaseProtocol's scopeJob.cancel tears it down),
        // it just runs on IO. MitmInnerTransport marshals send()/receive()-ack/
        // forceCancel() back onto lwipExecutor, so only the blocking body moves off.
        scope.launch(Dispatchers.IO) {
            try {
                MitmSession.intercept(
                    clientTransport = inner,
                    bufferedClientHello = clientHello,
                    host = sni,
                    port = port,
                    ruleSet = ruleSet,
                    authority = authority,
                    dialUpstream = { dialHost, dialPort, alpn ->
                        dialUpstreamLeg(dialHost, dialPort, alpn, routeConfig, routeBypass)
                    }
                )
            } catch (_: CancellationException) {
                return@launch  // torn down by releaseProtocol
            } catch (e: Exception) {
                // CORRECTION #4: intercept() owns teardown and does not throw for
                // ordinary failures, but guard defensively so an unexpected throw
                // cannot escape as an uncaught coroutine exception.
                logger.warning("[TCP] MITM interception errored for $sni:$port: ${e.message}")
            }
            // intercept() has already torn its own legs down; close the PCB back
            // on the lwIP thread (CORRECTION #1: marshal the teardown there).
            lwipExecutor.execute { if (!closed) close() }
        }
        return true
    }

    /**
     * The OUTER dial for an intercepted connection: opens a TLS client to the
     * real origin [host]:[port] offering exactly [alpn] (`["http/1.1"]`), either
     * directly when [routeBypass] is set or over the committed proxy route, and
     * returns the leg the bridge exchanges the (possibly rewritten) HTTP/1.1 with.
     *
     * Runs on the interception coroutine (Dispatchers.IO), so its socket connect
     * and TLS handshake never touch the lwIP thread.
     */
    private suspend fun dialUpstreamLeg(
        host: String,
        port: Int,
        alpn: List<String>,
        routeConfig: ProxyConfiguration,
        routeBypass: Boolean
    ): MitmByteLeg {
        // Mirror how the codebase builds a plain TLS origin dial (see
        // NaiveTlsTransport): serverName = the origin host, ALPN offered exactly
        // as requested. Pin a sane TLS 1.2–1.3 window and a non-browser device
        // fingerprint (this is an on-device Android re-origination, not a browser).
        val tlsConfig = TlsConfiguration(
            serverName = host,
            alpn = alpn,
            fingerprint = TlsFingerprint.ANDROID_11,
            minVersion = TlsVersion.TLS12,
            maxVersion = TlsVersion.TLS13
        )
        val client = TlsClient(tlsConfig)
        val record = if (routeBypass) {
            client.connect(host, port)
        } else {
            val proxy = ProxyClientFactory.connect(routeConfig, host, port, null)
            client.connect(TunneledTransport(proxy))
        }
        return TlsRecordByteLeg(record)
    }

    /**
     * Bridges lwIP's push model to the pull model [MitmSession] / `TlsServer`
     * expect for the client side of an intercepted connection.
     *
     * Client uplink bytes are pushed in with [feed] on the lwIP thread and pulled
     * out by the session through [receive] on the IO dispatcher; downlink bytes
     * the session writes with [send]/[sendAsync] are marshalled back onto the lwIP
     * executor via [writeToLwip], and [forceCancel] aborts the PCB there too.
     *
     * CORRECTION #3: the queue is bounded (not UNLIMITED) as a second layer of
     * defence, and client bytes are NOT acked when enqueued. Real backpressure
     * comes from acking each chunk to lwIP only as [receive] hands it to the
     * session, so lwIP's receive window reopens in step with how fast the origin
     * is read rather than the instant bytes are buffered.
     */
    private inner class MitmInnerTransport : Transport {
        private val queue = Channel<ByteArray>(MITM_INNER_QUEUE_CAPACITY)

        /**
         * Set (on the lwIP thread) when a downlink [send] is parked because the
         * client-facing backlog is full; completed when it drains or on teardown.
         * A single waiter suffices because writes to this leg are serialized (the
         * h1 bridge is sequential, the h2 server holds a write mutex).
         */
        private var drainWaiter: kotlinx.coroutines.CompletableDeferred<Unit>? = null

        /** Enqueues client bytes (lwIP thread). Does NOT ack — see class note. */
        fun feed(data: ByteArray) {
            if (data.isEmpty()) return
            val result = queue.trySend(data)
            if (result.isSuccess || result.isClosed) return
            // Full despite the ack-on-consume window: a backstop, not expected in
            // practice. Fail closed rather than drop bytes from a TLS stream.
            logger.warning("[TCP] MITM uplink queue overflow: $endpointDescription; aborting")
            abort()
        }

        override suspend fun receive(): ByteArray? {
            val chunk = queue.receiveCatching().getOrNull() ?: return null
            // Ack only now that the session has consumed the chunk — this is the
            // restored client-uplink backpressure. Marshalled onto the lwIP thread.
            lwipExecutor.execute { if (!closed) ackBytesToLwip(chunk.size) }
            return chunk
        }

        override suspend fun send(data: ByteArray) {
            if (data.isEmpty()) return
            // Backpressure: park until the client-facing backlog is below the
            // water mark, so a fast origin cannot grow pendingWrite without bound
            // while the client drains slowly (the normal relay path gets this from
            // tryArmReceive, which the pull-model bridge does not go through).
            awaitDrainRoom()
            // Refresh the activity timer on every downlink write, as the normal
            // relay path does when it reads from the proxy: origin bytes flowing
            // to the client are activity, and after a client FIN the downlink-only
            // timeout would otherwise truncate a still-streaming response.
            lwipExecutor.execute {
                if (closed) return@execute
                activityTimer?.update()
                writeToLwip(data)
            }
        }

        /**
         * Suspends the caller until the client-facing backlog ([pendingWrite]) is
         * below [TunnelConstants.drainLowWaterMark] — the same threshold the normal
         * path's [tryArmReceive] uses to stop fetching. The check runs on the lwIP
         * thread that owns [pendingWrite]; a parked sender is woken by
         * [onDrainProgress] as the backlog clears, or by [forceCancel] on teardown
         * (and the idle timer closes a connection whose client stopped reading, so
         * a park is always eventually released).
         */
        private suspend fun awaitDrainRoom() {
            while (true) {
                val gate = kotlinx.coroutines.CompletableDeferred<kotlinx.coroutines.CompletableDeferred<Unit>?>()
                lwipExecutor.execute {
                    if (closed || pendingWrite.size() < TunnelConstants.drainLowWaterMark) {
                        gate.complete(null)
                    } else {
                        gate.complete(
                            drainWaiter ?: kotlinx.coroutines.CompletableDeferred<Unit>().also { drainWaiter = it }
                        )
                    }
                }
                val waiter = gate.await() ?: return
                waiter.await()
                // Re-check on the lwIP thread: the backlog may have refilled.
            }
        }

        /** Wakes a parked [send] once the backlog has drained; call on the lwIP thread. */
        fun onDrainProgress() {
            val waiter = drainWaiter ?: return
            if (pendingWrite.size() < TunnelConstants.drainLowWaterMark) {
                drainWaiter = null
                waiter.complete(Unit)
            }
        }

        override fun sendAsync(data: ByteArray) {
            if (data.isEmpty()) return
            lwipExecutor.execute {
                if (closed) return@execute
                activityTimer?.update()
                writeToLwip(data)
            }
        }

        /**
         * Signals a clean end of the client uplink (the client half-closed) so the
         * session's [receive] returns null after draining, letting the bridge
         * finish the in-flight request rather than block. Distinct from
         * [forceCancel], which also aborts the PCB.
         */
        fun feedEof() {
            queue.close()
        }

        override fun forceCancel() {
            queue.close()
            // Release a sender parked on backpressure so its coroutine can unwind
            // rather than hang on a connection that is going away.
            drainWaiter?.complete(Unit)
            drainWaiter = null
            lwipExecutor.execute { if (!closed) abort() }
        }
    }

    /**
     * Re-evaluates routing using the hostname extracted from the TLS
     * ClientHello. Updates [dstHost], [configuration], and [bypass] in
     * place so the subsequent [beginConnecting] sees the SNI-based decision.
     *
     *   - Found a matching domain rule: apply it (may switch proxy, flip
     *     bypass, or reject the connection) and swap [dstHost] to the SNI
     *     so the new route resolves the name itself.
     *   - No rule matches: keep the IP-derived [dstHost] and
     *     configuration. Rewriting to the SNI hostname would force the
     *     outbound proxy to re-resolve via its own DNS, which can land on
     *     a different CDN IP than the one the caller already chose.
     */
    private fun applySNI(sni: String) {
        val stack = LwipStack.instance ?: return
        val action = stack.domainRouter.matchDomain(sni) ?: return

        // Rule matched: the sniffed hostname drives the new route, so
        // forward the proxy CONNECT to the name rather than the tentative
        // IP.
        dstHost = sni

        when (action) {
            RouteAction.Direct -> {
                bypass = true
            }
            RouteAction.Reject -> {
                logger.debug("[TCP] SNI rejected by routing rule: $sni ($dstHost:$dstPort)")
                rejectGracefully()
            }
            is RouteAction.Proxy -> {
                val resolved = stack.domainRouter.resolveConfiguration(action)
                if (resolved != null) {
                    // Preserve the ambient chain from the default
                    // configuration if the rule-targeted configuration
                    // didn't specify one.
                    val defaultChain = configuration.chain
                    configuration = if (!defaultChain.isNullOrEmpty() && resolved.chain == null) {
                        resolved.withChain(defaultChain)
                    } else {
                        resolved
                    }
                } else {
                    logger.warning("[TCP] SNI routing configuration not found for $sni")
                }
                bypass = stack.shouldBypass(sni)
            }
        }
    }

    /** Handles data received from the local app via lwIP. */
    fun handleReceivedData(data: ByteArray) {
        if (closed) return
        activityTimer?.update()

        // SNI sniff phase: buffer bytes and feed the sniffer before
        // dialing. Once a terminal state is reached we re-evaluate
        // routing (if SNI was found) and then kick off the proxy /
        // direct connect.
        val snifferRef = sniffer
        if (snifferRef != null) {
            val state = snifferRef.feed(data)
            if (!appendPendingData(data)) return
            when (state) {
                is TlsClientHelloSniffer.State.NeedMore -> return
                is TlsClientHelloSniffer.State.Found -> {
                    sniffer = null
                    cancelSniffDeadline()
                    applySNI(state.serverName)
                    if (closed) return  // rule may have rejected
                    // Route through MITM only when the shared store is configured
                    // for this host; otherwise dial exactly as before. The gate is
                    // inert (returns false without touching state) on the empty
                    // default store — see [beginMitmIfConfigured].
                    if (!beginMitmIfConfigured(state.serverName)) beginConnecting()
                    return
                }
                is TlsClientHelloSniffer.State.NotTls,
                is TlsClientHelloSniffer.State.Unavailable -> {
                    sniffer = null
                    cancelSniffDeadline()
                    beginConnecting()
                    return
                }
            }
        }

        // MITM interception in progress: hand later client bytes straight to the
        // inner transport the session reads from. No ack here — client-uplink
        // backpressure is restored by acking each chunk only once the session
        // consumes it (MitmInnerTransport.receive). Inert while mitmInner is null.
        val inner = mitmInner
        if (inner != null) {
            inner.feed(data)
            return
        }

        // Buffer data while outbound connection is being established
        if (vlessConnecting || directConnecting) {
            appendPendingData(data)
            return
        }

        if (directRelay != null || vlessConnection != null) {
            // Always coalesce — even while a flush is in-flight. This is a
            // buffered-pipe design where data accumulates during the
            // scMinPostsIntervalMs sleep and is sent as one large POST.
            //
            // Strict single-flight: every byte for this connection flows
            // through the same `flushCoalesceBuffer` coroutine chain. Concurrent
            // `connection.send()` calls would interleave inside protocols
            // whose framing can't tolerate it (Vision/HTTP-2/gRPC), so we
            // never spawn a parallel send. Mirrors iOS `UploadPipeline`'s
            // `sendInFlight` invariant in LWIPTCPConnection.swift:71-95.
            if (coalesceBuffer == null) coalesceBuffer = ByteArrayOutputStream()
            coalesceBuffer!!.write(data)

            // Schedule flush only when no send is in-flight (data accumulated
            // during an in-flight send will be flushed when it completes).
            if (!coalesceFlushInFlight && !coalesceScheduled) {
                coalesceScheduled = true
                lwipExecutor.execute { flushCoalesceBuffer() }
            }
        } else {
            if (!appendPendingData(data)) return
            beginConnecting()
        }
    }

    /**
     * Called when the local app acknowledges receipt of data sent via lwIP.
     * Drains the overflow buffer into the now-available send buffer space.
     */
    fun handleSent(len: Int) {
        if (closed) return
        drainPendingWrite()
    }

    /** Called when the local app closes its write side (TCP FIN from app). */
    fun handleRemoteClose() {
        if (closed) return

        // Client FIN'd before we finished sniffing. If we never received
        // any bytes, there's nothing to forward — drop the connection.
        // Otherwise commit the tentative IP-based route and forward what
        // we have.
        if (sniffer != null) {
            sniffer = null
            cancelSniffDeadline()
            if (pendingData.size() == 0) {
                close()
                return
            }
            beginConnecting()
        }

        // A MITM session pulls the client uplink through the inner queue; a client
        // FIN is a clean end-of-request, so close the queue (drains, then EOF)
        // rather than leaving the session's receive() blocked. Null-safe, so inert
        // when this is not an intercepted connection.
        mitmInner?.feedEof()

        uplinkDone = true
        if (downlinkDone) {
            close()
        } else {
            activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeoutMs)
        }
    }

    /**
     * Surfaces why lwIP tore this connection down. Without this log the
     * connection simply vanishes from the user's perspective — no send /
     * receive error fires because the PCB has already been freed by the
     * time tcp_err runs.
     */
    fun handleError(err: Int) {
        val reason = TransportErrorLogger.describeLwIPError(err)
        when {
            err == -15 ->  // ERR_CLSD — orderly close, not a failure
                logger.debug("[TCP] lwIP closed connection: $endpointDescription: $reason")
            err == -14 ->  // ERR_RST — always local-app-initiated in TUN mode
                logger.debug("[TCP] lwIP peer reset: $endpointDescription: $reason")
            err == -13 && LwipStack.instance?.isTearingDown == true ->
                // ERR_ABRT during a deliberate stack teardown
                // (shutdown/restart/wake). Outside teardown, ERR_ABRT
                // indicates lwIP's own pressure aborts (tcp_kill_prio /
                // tcp_kill_timewait) — those stay at warning below.
                logger.debug("[TCP] lwIP aborted connection (tunnel teardown): $endpointDescription: $reason")
            else ->
                logger.warning("[TCP] lwIP aborted connection: $endpointDescription: $reason")
        }
        if (closed) return
        closed = true
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    private val endpointDescription: String
        get() = "$dstHost:$dstPort"

    private fun logTransportFailure(
        operation: String,
        error: Throwable,
        defaultLevel: TransportLogLevel = TransportLogLevel.ERROR
    ) {
        TransportErrorLogger.log(
            operation = operation,
            endpoint = endpointDescription,
            error = error,
            logger = logger,
            prefix = "[TCP]",
            defaultLevel = defaultLevel
        )
    }

    private fun connectDirect() {
        if (directConnecting || directRelay != null || closed) return
        directConnecting = true

        val initialData = if (pendingData.size() > 0) pendingData.toByteArray() else null
        if (initialData != null) pendingData.reset()

        val relay = DirectTcpRelay()
        directRelay = relay

        scope.launch {
            try {
                relay.connect(dstHost, dstPort)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    directConnecting = false
                    if (!closed) {
                        logTransportFailure("Connect", e)
                        abort()
                    }
                }
                return@launch
            }

            lwipExecutor.execute {
                directConnecting = false
                if (closed) return@execute

                handshakeTimer?.cancel(false)
                handshakeTimer = null
                activityTimer = ActivityTimer(lwipExecutor, TunnelConstants.connectionIdleTimeoutMs) {
                    if (!closed) close()
                }

                // Drain initialData + any pendingData that arrived during connect.
                // Send sequentially in one coroutine so byte order is preserved
                // (mirrors iOS UploadPipeline's strict single-flight semantics).
                val followup = if (pendingData.size() > 0) {
                    val data = pendingData.toByteArray()
                    pendingData.reset()
                    data
                } else null

                if (initialData != null || followup != null) {
                    scope.launch {
                        try {
                            if (initialData != null) relay.send(initialData)
                            if (followup != null) relay.send(followup)
                            val totalAck = (initialData?.size ?: 0) + (followup?.size ?: 0)
                            lwipExecutor.execute {
                                if (closed) return@execute
                                ackBytesToLwip(totalAck)
                            }
                        } catch (_: CancellationException) {
                        } catch (e: Exception) {
                            if (!closed) logTransportFailure("Send", e, TransportLogLevel.WARNING)
                            lwipExecutor.execute { abort() }
                        }
                    }
                }

                tryArmReceive()
            }
        }
    }

    /**
     * Acknowledges [bytes] to lwIP in 65535-byte chunks (UInt16 cap), then
     * forces an immediate window-update output flush. Mirrors iOS
     * `acknowledgeReceivedBytes` (LWIPTCPConnection.swift:332-342).
     */
    private fun ackBytesToLwip(bytes: Int) {
        if (bytes <= 0) return
        var remaining = bytes
        while (remaining > 0) {
            val chunk = remaining.coerceAtMost(65535)
            NativeBridge.nativeTcpRecved(pcb, chunk)
            remaining -= chunk
        }
        NativeBridge.nativeTcpOutput(pcb)
        LwipStack.instance?.flushOutputInline()
    }

    /**
     * Connects to the proxy using the appropriate protocol (VLESS, Shadowsocks, NaiveProxy).
     * Uses [ProxyClientFactory] for protocol selection.
     */
    private fun connectProxy() {
        if (vlessConnecting || vlessConnection != null || closed) return
        vlessConnecting = true

        // Only protocols that embed the first bytes inside their handshake
        // (VLESS + transports) consume `pendingData` here. For everything
        // else (Trojan, Shadowsocks, SOCKS5, NaiveProxy), leave
        // `pendingData` intact — `onProxyConnected` will forward it via the
        // proxy connection AND ACK it back to lwIP via `nativeTcpRecved`.
        val initialData = if (configuration.outboundProtocol.handshakeCarriesInitialData
            && pendingData.size() > 0) {
            val data = pendingData.toByteArray()
            pendingData.reset()
            data
        } else null

        // If config has a chain, build chained connections first
        val chain = configuration.chain
        if (!chain.isNullOrEmpty()) {
            connectChain(chain, initialData)
            return
        }

        scope.launch {
            try {
                val connection = ProxyClientFactory.connect(
                    configuration, dstHost, dstPort, initialData
                )
                onProxyConnected(connection, handshakeAckBytes = initialData?.size ?: 0)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logTransportFailure("Connect", e)
                        abort()
                    }
                }
            }
        }
    }

    /**
     * Handles post-connection setup common to all protocol paths.
     * Sets up activity timer, flushes pending data, and starts the receive loop.
     *
     * [handshakeAckBytes] is the byte count of any initialData that the protocol
     * consumed inside its handshake (extracted by `connectProxy` for VLESS-style
     * protocols where `handshakeCarriesInitialData` is true). Those bytes were
     * never `nativeTcpRecved`'d; ack them here so lwIP's recv window reopens.
     * Mirrors iOS `LWIPTCPConnection.swift:602-606`.
     */
    private fun onProxyConnected(connection: ProxyConnection, handshakeAckBytes: Int = 0) {
        lwipExecutor.execute {
            vlessConnecting = false
            if (closed) {
                connection.cancel()
                return@execute
            }

            vlessConnection = connection
            handshakeTimer?.cancel(false)
            handshakeTimer = null
            activityTimer = ActivityTimer(lwipExecutor, TunnelConstants.connectionIdleTimeoutMs) {
                if (!closed) close()
            }

            // Drain any pendingData arrived during connect, then ack the
            // combined byte count (handshake-carried + pendingData) in one shot.
            val followup = if (pendingData.size() > 0) {
                val data = pendingData.toByteArray()
                pendingData.reset()
                data
            } else null

            if (followup != null) {
                scope.launch {
                    try {
                        connection.send(followup)
                        lwipExecutor.execute {
                            if (closed) return@execute
                            ackBytesToLwip(handshakeAckBytes + followup.size)
                        }
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        if (!closed) logTransportFailure("Send", e, TransportLogLevel.WARNING)
                        lwipExecutor.execute { abort() }
                    }
                }
            } else if (handshakeAckBytes > 0) {
                ackBytesToLwip(handshakeAckBytes)
            }

            tryArmReceive()
        }
    }

    /**
     * Builds a chain of proxy connections: entry → intermediate → ... → exit → target.
     *
     * Each intermediate hop creates a VLESS tunnel to the next proxy's server.
     * The final hop uses [ProxyClientFactory] for protocol selection, allowing
     * the exit proxy to use any supported protocol (VLESS, Shadowsocks, NaiveProxy).
     */
    private fun connectChain(
        chain: List<ProxyConfiguration>,
        initialData: ByteArray?
    ) {
        scope.launch {
            try {
                var previousConnection: ProxyConnection? = null

                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else configuration
                    val conn = ProxyClientFactory.connect(
                        hopConfig,
                        nextConfig.serverAddress,
                        nextConfig.serverPort.toInt(),
                        tunnel = previousConnection
                    )
                    previousConnection = conn
                }

                // Final hop: use factory for protocol selection, tunneled through the chain
                val connection = ProxyClientFactory.connect(
                    configuration, dstHost, dstPort, initialData, tunnel = previousConnection
                )
                onProxyConnected(connection, handshakeAckBytes = initialData?.size ?: 0)
            } catch (_: CancellationException) {
                return@launch
            } catch (e: Exception) {
                lwipExecutor.execute {
                    vlessConnecting = false
                    if (!closed) {
                        logTransportFailure("Connect", e)
                        abort()
                    }
                }
            }
        }
    }

    /**
     * Flushes the coalesce buffer, sending accumulated segments through the
     * proxy in `tcpMaxCoalesceSize` chunks. All chunks for a single flush
     * land in one coroutine so the proxy connection sees strictly serial
     * `send` calls — a hard requirement for protocols whose framing uses
     * 2-byte length fields (Vision padding) or shared sequence numbers
     * (HTTP/2, gRPC). Mirrors iOS `UploadPipeline.pumpUploadSends`
     * (LWIPTCPConnection.swift:299-326).
     *
     * Called on the lwIP executor thread after the current processing cycle completes.
     */
    private fun flushCoalesceBuffer() {
        val buf = coalesceBuffer
        coalesceBuffer = null
        coalesceScheduled = false

        if (closed || buf == null || buf.size() == 0) return

        val relay = directRelay
        val connection = vlessConnection
        if (relay == null && connection == null) return

        val dataToSend = buf.toByteArray()
        coalesceFlushInFlight = true
        scope.launch {
            try {
                var sent = 0
                while (sent < dataToSend.size) {
                    val chunkSize = minOf(
                        dataToSend.size - sent,
                        TunnelConstants.tcpMaxCoalesceSize
                    )
                    val chunk = if (sent == 0 && chunkSize == dataToSend.size) {
                        dataToSend
                    } else {
                        dataToSend.copyOfRange(sent, sent + chunkSize)
                    }
                    if (relay != null) {
                        relay.send(chunk)
                    } else {
                        connection!!.send(chunk)
                    }
                    // Per-chunk ack mirrors iOS — keeps lwIP's recv window
                    // opening in step with upstream throughput rather than
                    // batching the whole buffer's worth of credit at once.
                    lwipExecutor.execute {
                        if (!closed) ackBytesToLwip(chunkSize)
                    }
                    sent += chunkSize
                }
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    if (!closed) {
                        // Immediately flush data that accumulated during the in-flight send.
                        // Data coalesces while the previous POST + delay runs, then flushes
                        // as one large POST instead of many small per-segment POSTs.
                        if (coalesceBuffer != null && coalesceBuffer!!.size() > 0) {
                            flushCoalesceBuffer()
                        }
                    }
                }
            } catch (_: CancellationException) {
                lwipExecutor.execute { coalesceFlushInFlight = false }
            } catch (e: Exception) {
                if (!closed) logTransportFailure("Send", e, TransportLogLevel.WARNING)
                lwipExecutor.execute {
                    coalesceFlushInFlight = false
                    abort()
                }
            }
        }
    }

    /**
     * Feeds as many bytes as possible from [data] (starting at [dataOffset]) into
     * lwIP's TCP send buffer. Returns bytes written, or -1 on fatal (non-transient)
     * tcp_write error. ERR_MEM is treated as transient (breaks out of the loop).
     *
     * When [retryOnEmpty] is true, calls tcp_output once to flush if the send
     * buffer is initially full, then retries — used by the initial write path.
     */
    private fun feedLwip(data: ByteArray, dataOffset: Int, count: Int, retryOnEmpty: Boolean = false): Int {
        var offset = 0
        while (offset < count) {
            var sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
            if (sndbuf <= 0) {
                if (retryOnEmpty) {
                    NativeBridge.nativeTcpOutput(pcb)
                    sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
                }
                if (sndbuf <= 0) break
            }
            val chunkSize = minOf(sndbuf, count - offset, TunnelConstants.tcpMaxWriteSize)
            val err = NativeBridge.nativeTcpWrite(pcb, data, dataOffset + offset, chunkSize)
            if (err != 0) {
                if (err == -1) break  // ERR_MEM: transient — remaining data goes to overflow
                return -1             // fatal error
            }
            offset += chunkSize
        }
        return offset
    }

    /**
     * Appends data received from the proxy onto [pendingWrite], then drains
     * as much as lwIP will accept. All order-preservation lives in
     * [pendingWrite], so a concurrently prefetched receive can land without
     * racing ahead of the chunk currently being drained.
     */
    fun writeToLwip(data: ByteArray) {
        if (closed || data.isEmpty()) return
        pendingWrite.write(data)
        drainPendingWrite()
    }

    /**
     * Drains [pendingWrite] into lwIP's TCP send buffer and, on progress,
     * arms the next proxy receive if we've dropped below
     * [TunnelConstants.drainLowWaterMark].
     *
     * Called from [handleSent] on every client ACK, from [writeToLwip]
     * after new proxy data is appended, and from a [TunnelConstants.drainRetryDelayMs]
     * fallback timer when `tcp_write` couldn't place any bytes (snd_buf
     * full / zero window).
     */
    private fun drainPendingWrite() {
        if (closed) return

        if (pendingWrite.size() > 0) {
            val data = pendingWrite.backingArray()
            val dataSize = pendingWrite.size()
            val written = feedLwip(data, 0, dataSize, retryOnEmpty = true)
            if (written == -1) {
                val sndbuf = NativeBridge.nativeTcpSndbuf(pcb)
                logger.error("[TCP] tcp_write fatal: $dstHost:$dstPort (pending=$dataSize, sndbuf=$sndbuf)")
                abort()
                return
            }
            if (closed) return

            if (written > 0) {
                if (written >= dataSize) {
                    pendingWrite.reset()
                } else {
                    pendingWrite.consume(written)
                }
                NativeBridge.nativeTcpOutput(pcb)
                // Flush the egress queue inline so freed pbufs leave the host
                // within the same drain cycle that consumed them.
                LwipStack.instance?.flushOutputInline()
            } else {
                // Nothing drained (ERR_MEM / zero window) — schedule a delayed
                // retry. Skip `tryArmReceive` on purpose: piling more upstream
                // bytes onto a stalled connection only grows `pendingWrite`.
                // Once the retry makes progress, the tail call re-arms.
                lwipExecutor.schedule(
                    { if (!closed) drainPendingWrite() },
                    TunnelConstants.drainRetryDelayMs,
                    TimeUnit.MILLISECONDS
                )
                return
            }
        }

        // Made progress (or nothing was pending): prefetch the next chunk if
        // the backlog is below the low-water mark.
        tryArmReceive()
        // Same signal for a MITM downlink sender parked on backpressure (null on
        // every non-intercepted connection, so this is a no-op there).
        mitmInner?.onDrainProgress()
    }

    /**
     * Issues the next proxy receive if the downlink backlog is below the
     * low-water mark and no receive is already in flight.
     *
     * Overlapping the next receive with the ongoing drain keeps lwIP's send
     * buffer saturated: by the time a client ACK frees space, a fresh chunk
     * is already queued in [pendingWrite] ready to push. Without this
     * overlap, a big receive (e.g. a speed-test server pushing >1 MB per
     * read) forces stop-and-wait — the proxy socket's receive window stays
     * closed for the entire drain, and upstream throttles.
     *
     * Backpressure still applies: when `pendingWrite.size()` is at or above
     * [TunnelConstants.drainLowWaterMark], this is a no-op, so receives
     * naturally pause whenever lwIP can't keep up.
     */
    private fun tryArmReceive() {
        if (closed || receiveInFlight) return
        if (pendingWrite.size() >= TunnelConstants.drainLowWaterMark) return

        val relay = directRelay
        val connection = vlessConnection
        if (relay == null && connection == null) return

        receiveInFlight = true
        scope.launch {
            var data: ByteArray? = null
            var error: Throwable? = null
            var cancelled = false
            try {
                data = relay?.receive() ?: connection?.receive()
            } catch (_: CancellationException) {
                cancelled = true
            } catch (e: Exception) {
                error = e
            }

            lwipExecutor.execute {
                receiveInFlight = false
                if (closed || cancelled) return@execute

                if (error != null) {
                    logTransportFailure("Receive", error, TransportLogLevel.WARNING)
                    abort()
                    return@execute
                }

                if (data == null || data.isEmpty()) {
                    downlinkDone = true
                    if (uplinkDone) {
                        close()
                    } else {
                        activityTimer?.setTimeout(TunnelConstants.uplinkOnlyTimeoutMs)
                    }
                    return@execute
                }

                activityTimer?.update()
                writeToLwip(data)
            }
        }
    }

    /** Best-effort flush of pending data into lwIP send buffer before close. */
    private fun flushPendingToLwip() {
        if (pendingWrite.size() == 0) return
        val written = feedLwip(pendingWrite.backingArray(), 0, pendingWrite.size())
        if (written > 0) {
            NativeBridge.nativeTcpOutput(pcb)
        }
    }

    fun close() {
        if (closed) return
        closed = true
        flushPendingToLwip()
        NativeBridge.nativeTcpClose(pcb)
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    /**
     * Tears the connection down with a clean FIN instead of a RST.
     *
     * `tcp_close` in lwIP downgrades to RST whenever the receive window
     * is below `TCP_WND_MAX` — i.e. when bytes were delivered via
     * `tcp_recv_cb` but never acknowledged via `tcp_recved`. The sniffed
     * ClientHello in `pendingData` is exactly that: received but
     * unacknowledged because we never forwarded it upstream. A mid-
     * handshake RST is widely interpreted by TLS stacks as a transient
     * failure, which drives browsers and HTTP clients to retry
     * aggressively — defeating the point of the reject rule. Advancing
     * the window first lets `close()` send a real FIN, which clients
     * treat as a deliberate peer close and don't retry.
     */
    private fun rejectGracefully() {
        if (closed) return
        var remaining = pendingData.size()
        while (remaining > 0) {
            val chunk = remaining.coerceAtMost(65535)
            NativeBridge.nativeTcpRecved(pcb, chunk)
            remaining -= chunk
        }
        close()
    }

    fun abort() {
        if (closed) return
        closed = true
        NativeBridge.nativeTcpAbort(pcb)
        releaseProtocol()
        LwipStack.instance?.removeConnection(connId)
    }

    private fun releaseProtocol() {
        // Cancel all in-flight coroutines first to prevent them from using freed resources
        scopeJob.cancel()

        handshakeTimer?.cancel(false)
        handshakeTimer = null
        cancelSniffDeadline()
        sniffer = null
        activityTimer?.cancel()
        activityTimer = null
        val relay = directRelay
        val connection = vlessConnection
        val inner = mitmInner
        directRelay = null
        vlessConnection = null
        mitmInner = null
        vlessConnecting = false
        directConnecting = false
        pendingData.reset()
        pendingWrite.reset()
        coalesceBuffer = null
        coalesceScheduled = false
        receiveInFlight = false

        relay?.cancel()
        connection?.cancel()
        // Closes the inner queue so a session blocked in receive() unblocks; the
        // scopeJob.cancel() above already cancels an in-flight intercept coroutine.
        inner?.forceCancel()
    }

    companion object {
        private val logger = MythaiaLogger("LWIP-TCP")

        /**
         * Bound on the MITM uplink queue ([MitmInnerTransport]). The live queue
         * depth is held far below this by the ack-on-consume backpressure in
         * [MitmInnerTransport.receive] (lwIP's own receive window is the real
         * limit); the bound is only a backstop, so it is set generously.
         */
        private const val MITM_INNER_QUEUE_CAPACITY = 1024
    }
}

/** Simple ByteArrayOutputStream replacement for buffer management. */
private class ByteArrayOutputStream {
    private var buf = ByteArray(256)
    private var count = 0
    companion object {
        private const val SHRINK_THRESHOLD = 8192
    }

    fun write(data: ByteArray) {
        write(data, 0, data.size)
    }

    fun write(data: ByteArray, off: Int, len: Int) {
        ensureCapacity(count + len)
        System.arraycopy(data, off, buf, count, len)
        count += len
    }

    fun toByteArray(): ByteArray = buf.copyOf(count)

    /** Direct access to backing array (valid up to [size] bytes). Avoids copy. */
    fun backingArray(): ByteArray = buf

    fun size(): Int = count

    fun reset() {
        count = 0
        // Shrink backing array if it grew well beyond the initial size,
        // preventing long-lived connections from retaining peak memory.
        if (buf.size > SHRINK_THRESHOLD) {
            buf = ByteArray(256)
        }
    }

    /** Removes the first [n] bytes, shifting remaining data to the front. */
    fun consume(n: Int) {
        if (n >= count) {
            count = 0
        } else {
            System.arraycopy(buf, n, buf, 0, count - n)
            count -= n
        }
    }

    private fun ensureCapacity(minCapacity: Int) {
        if (minCapacity > buf.size) {
            val newSize = maxOf(buf.size * 2, minCapacity)
            buf = buf.copyOf(newSize)
        }
    }
}
