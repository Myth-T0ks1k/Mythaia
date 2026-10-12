package com.mythaia.vpn.tun

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.LwipDomainRoute
import com.mythaia.vpn.LwipHost
import com.mythaia.vpn.LwipTcpConnection
import com.mythaia.vpn.LwipUdpFlow
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.TunnelConstants
import com.mythaia.vpn.protocol.mux.MuxManager
import com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.IcmpPackets
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.PacketUtil
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * The lwIP flow driver with no platform in it.
 *
 * Packets from a TUN interface go in through [input]; lwIP reassembles
 * them into TCP connections and UDP flows, each of which is answered by a
 * [LwipTcpConnection] or [LwipUdpFlow] dialling the proxy or the
 * destination directly, as the [TunHost]'s router says. Packets lwIP wants
 * on the wire come back out through [TunHost.writePacket]. DNS on port 53
 * is intercepted and answered from the fake-IP pool so the router sees
 * domain names, exactly as the Android `LwipStack` does.
 *
 * Everything lwIP touches runs on [lwipExecutor], a single thread, because
 * lwIP is not thread-safe.
 */
class TunStack(private val host: TunHost) : NativeBridge.LwipCallback, LwipHost {

    /** DiscardPolicy: tasks submitted after shutdown are dropped, not thrown at in-flight coroutines. */
    override val lwipExecutor: ScheduledExecutorService = ScheduledThreadPoolExecutor(1) { r ->
        Thread(r, "lwip-thread").apply { isDaemon = true }
    }.apply {
        rejectedExecutionHandler = ThreadPoolExecutor.DiscardPolicy()
    }

    @Volatile
    final override var configuration: ProxyConfiguration? = null
        private set

    @Volatile
    override var isTearingDown: Boolean = false

    final override var muxManager: MuxManager? = null
        private set

    @Volatile
    var settings: TunSettings = TunSettings()
        private set

    @Volatile
    private var running = false

    val isRunning: Boolean get() = running

    /** Bytes lwIP sent to the interface (downlink) and bytes read from it (uplink). */
    val totalBytesIn = AtomicLong(0)
    val totalBytesOut = AtomicLong(0)

    val fakeIpPool = FakeIpPool()

    private val tcpConnections = ConcurrentHashMap<Long, LwipTcpConnection>()
    private val udpFlows = ConcurrentHashMap<String, LwipUdpFlow>()
    private val nextConnId = AtomicLong(1)
    /** Shadowsocks UDP sessions by configuration id and local socket; see [LwipHost.shadowsocksUDPSession]. */
    private val ssUDPSessions = HashMap<String, ShadowsocksUdpSession>()

    /** Every proxy server address (names and resolved IPs), which must never be routed into the tunnel. */
    @Volatile
    private var proxyServerAddresses: Set<String> = emptySet()

    private var timeoutTimer: ScheduledFuture<*>? = null
    private var udpCleanupTimer: ScheduledFuture<*>? = null

    // Output batching; only touched on lwipExecutor.
    private val outputPackets = ArrayList<ByteArray>()
    private var outputFlushScheduled = false
    private var outputWriteInFlight = false

    /** Resolves the names in [TunSettings.realAnswerDomains] off the lwIP thread. */
    private val resolver = ThreadPoolExecutor(0, 4, 30L, TimeUnit.SECONDS, java.util.concurrent.LinkedBlockingQueue(64)) { r ->
        Thread(r, "tun-dns").apply { isDaemon = true }
    }

    val tcpConnectionCount: Int get() = tcpConnections.size
    val udpFlowCount: Int get() = udpFlows.size

    // ------------------------------------------------------------ lifecycle

    /** Brings lwIP up for [config]. Packets may be fed in as soon as this returns. */
    fun start(config: ProxyConfiguration, settings: TunSettings) {
        this.settings = settings
        NativeBridge.callback = this
        lwipExecutor.execute {
            running = true
            totalBytesIn.set(0)
            totalBytesOut.set(0)
            bringUp(config)
            logger.info("Started for ${config.name}, mux=${muxManager != null}, ipv6dns=${settings.ipv6Dns}, blockQuic=${settings.blockQuic}")
        }
    }

    /**
     * Tears everything down. Non-blocking; [onComplete] runs on the lwIP
     * thread once every flow is closed and lwIP is shut, after which the
     * executor terminates. Release the interface from [onComplete], not before.
     */
    fun stop(onComplete: (() -> Unit)? = null) {
        lwipExecutor.execute {
            running = false
            try {
                shutdownInternal()
            } catch (t: Throwable) {
                logger.error("Shutdown failed: ${t.message ?: t}")
            } finally {
                fakeIpPool.reset()
                if (NativeBridge.callback === this) NativeBridge.callback = null
                outputPackets.clear()
                outputFlushScheduled = false
                configuration = null
                onComplete?.invoke()
            }
        }
        lwipExecutor.shutdown()
        resolver.shutdownNow()
    }

    /** Switches the default outbound; every open flow is re-established through it. */
    fun switchConfiguration(config: ProxyConfiguration) {
        lwipExecutor.execute {
            if (!running) return@execute
            logger.info("Switching to ${config.name}; reconnecting active connections")
            shutdownInternal()
            bringUp(config)
        }
    }

    /** Tears every flow down so it is re-routed under new rules. */
    fun restart() {
        lwipExecutor.execute {
            val config = configuration ?: return@execute
            if (!running) return@execute
            logger.info("Routing changed; reconnecting active connections")
            shutdownInternal()
            bringUp(config)
        }
    }

    /** New per-packet knobs; takes effect on the next packet, no flows are dropped. */
    fun updateSettings(settings: TunSettings) {
        this.settings = settings
    }

    /**
     * Feeds packets read from the interface. Each array holds exactly one
     * IP packet; a batch costs one hop to the lwIP thread. Any thread.
     */
    fun input(packets: List<ByteArray>) {
        if (packets.isEmpty() || !running) return
        var bytes = 0L
        for (p in packets) bytes += p.size
        totalBytesOut.addAndGet(bytes)
        lwipExecutor.execute {
            if (!running) return@execute
            for (p in packets) NativeBridge.nativeInput(p, p.size)
            if (outputPackets.isNotEmpty()) flushOutputPackets()
        }
    }

    private fun bringUp(config: ProxyConfiguration) {
        configuration = config
        seedProxyServerAddresses(config)
        muxManager = if (config.outboundProtocol == OutboundProtocol.VLESS && config.muxEnabled &&
            (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")
        ) MuxManager(config, lwipExecutor.asCoroutineDispatcher()) else null
        NativeBridge.nativeInit()
        timeoutTimer = lwipExecutor.scheduleWithFixedDelay({
            if (running) NativeBridge.nativeTimerPoll()
        }, TunnelConstants.lwipTimeoutIntervalMs, TunnelConstants.lwipTimeoutIntervalMs, TimeUnit.MILLISECONDS)
        udpCleanupTimer = lwipExecutor.scheduleWithFixedDelay({
            if (!running) return@scheduleWithFixedDelay
            val now = System.nanoTime() / 1_000_000_000.0
            val stale = udpFlows.filterValues { now - it.lastActivity > TunnelConstants.udpIdleTimeoutSec }
            for ((key, flow) in stale) {
                flow.close()
                udpFlows.remove(key)
            }
        }, TunnelConstants.udpCleanupIntervalSec, TunnelConstants.udpCleanupIntervalSec, TimeUnit.SECONDS)
    }

    /** Must run on lwipExecutor. Leaves [running] alone. */
    private fun shutdownInternal() {
        timeoutTimer?.cancel(false); timeoutTimer = null
        udpCleanupTimer?.cancel(false); udpCleanupTimer = null
        outputPackets.clear()
        outputFlushScheduled = false

        muxManager?.closeAll()
        muxManager = null
        com.mythaia.vpn.protocol.naive.http2.Http2SessionPool.closeAll()
        com.mythaia.vpn.protocol.quic.QuicClientPool.closeAll()
        com.mythaia.vpn.protocol.nowhere.NowhereClient.shutdown()
        com.mythaia.vpn.protocol.vless.encryption.VlessEncryption0RttCache.shared.clear()

        val flowCount = udpFlows.size
        for (flow in udpFlows.values) flow.close()
        udpFlows.clear()
        for (session in ssUDPSessions.values) session.cancel()
        ssUDPSessions.clear()

        // lwip_bridge_shutdown() aborts every PCB; each abort fires tcp_err →
        // onTcpErr → handleError, which releases the proxy side and sends
        // the RST that makes apps drop the old connection and retry.
        isTearingDown = true
        try {
            NativeBridge.nativeShutdown()
        } finally {
            isTearingDown = false
        }
        for (conn in tcpConnections.values) if (!conn.closed) conn.handleError(-1)
        tcpConnections.clear()
        host.onConnectionCount(0)
        logger.debug("Shutdown complete, closed $flowCount UDP flows")
    }

    // ------------------------------------------------- proxy server addresses

    private fun seedProxyServerAddresses(config: ProxyConfiguration) {
        val names = LinkedHashSet<String>()
        fun collect(c: ProxyConfiguration) {
            names.add(c.serverAddress.trim().lowercase())
            c.resolvedIP?.trim()?.takeIf { it.isNotEmpty() }?.let(names::add)
            c.chain?.forEach(::collect)
        }
        collect(config)
        proxyServerAddresses = proxyServerAddresses + names
        // Resolved IPs too, so a client that already holds the server's address
        // (a latency test, the app's own probes) is also kept out of the tunnel.
        val domains = names.filterNot { DnsCache.isIpAddress(it) }
        if (domains.isNotEmpty()) runCatching {
            resolver.execute {
                val ips = domains.flatMap { runCatching { DnsCache.resolveAll(it) }.getOrDefault(emptyList()) }.toSet()
                if (ips.isNotEmpty()) lwipExecutor.execute { proxyServerAddresses = proxyServerAddresses + ips }
            }
        }
    }

    /** The domains answered with real addresses: the proxy servers plus whatever the platform added. */
    private fun isRealAnswerDomain(domain: String): Boolean =
        domain in settings.realAnswerDomains || (domain in proxyServerAddresses && !DnsCache.isIpAddress(domain))

    // --------------------------------------------------------------- LwipHost

    override fun shouldBypass(host: String): Boolean {
        val h = host.trim().lowercase()
        if (h in proxyServerAddresses) return true
        val config = configuration ?: return false
        if (h == config.serverAddress.lowercase() || h == config.resolvedIP) return true
        return config.chain?.any { h == it.serverAddress.lowercase() || h == it.resolvedIP } == true
    }

    override fun routeDomain(domain: String): LwipDomainRoute? {
        val config = configuration ?: return null
        return when (val route = host.route(domain, 0, udp = false)) {
            TunRoute.Direct -> LwipDomainRoute.Direct
            TunRoute.Block -> LwipDomainRoute.Reject
            is TunRoute.Proxy -> LwipDomainRoute.Proxy(inheritChain(config, route.configuration))
        }
    }

    override fun shadowsocksUDPSession(config: ProxyConfiguration, source: String): ShadowsocksUdpSession? {
        val key = "${config.id}|$source"
        ssUDPSessions[key]?.let { existing ->
            if (existing.isUsable) return existing
            ssUDPSessions.remove(key)
        }
        val mode = ShadowsocksUdpSession.modeFor(config) ?: return null
        val session = ShadowsocksUdpSession(
            mode = mode,
            serverHost = config.serverAddress,
            serverPort = config.serverPort.toInt(),
            executor = lwipExecutor
        )
        ssUDPSessions[key] = session
        return session
    }

    override fun releaseShadowsocksUDPSession(session: ShadowsocksUdpSession) {
        if (!session.isIdle) return
        session.cancel()
        ssUDPSessions.values.remove(session)
    }

    override fun removeConnection(connId: Long) {
        if (tcpConnections.remove(connId) != null) host.onConnectionCount(tcpConnections.size)
    }

    override fun removeUdpFlow(flowKey: String) {
        udpFlows.remove(flowKey)
    }

    override fun flushOutputInline() {
        flushOutputPackets()
    }

    // ---------------------------------------------------------------- output

    override fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean) {
        totalBytesIn.addAndGet(length.toLong())
        // The native side reuses its buffer after the callback returns.
        outputPackets.add(packet.copyOf(length))
        scheduleOutputFlush()
    }

    private fun scheduleOutputFlush() {
        if (!outputFlushScheduled) {
            outputFlushScheduled = true
            lwipExecutor.execute { flushOutputPackets() }
        }
    }

    /** Capped batches with a single-in-flight gate, so a re-entrant flush cannot interleave. */
    private fun flushOutputPackets() {
        outputFlushScheduled = false
        if (outputPackets.isEmpty()) return
        if (outputWriteInFlight) {
            scheduleOutputFlush()
            return
        }
        outputWriteInFlight = true
        try {
            val cap = TunnelConstants.tunnelMaxPacketsPerWrite
            var written = 0
            val it = outputPackets.iterator()
            while (it.hasNext() && written < cap) {
                val p = it.next()
                it.remove()
                host.writePacket(p, p.size)
                written++
            }
        } catch (e: Exception) {
            logger.debug("Interface write error: $e")
            outputPackets.clear()
        } finally {
            outputWriteInFlight = false
        }
        if (outputPackets.isNotEmpty()) scheduleOutputFlush()
    }

    // ------------------------------------------------------------------- TCP

    override fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, pcb: Long): Long {
        val defaultConfig = configuration ?: return 0L
        if (tcpConnections.size >= MAX_TCP_CONNECTIONS) return 0L

        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"
        val decision = decide(dstIpString, dstPort, udp = false, defaultConfig = defaultConfig) ?: return 0L

        val connId = nextConnId.getAndIncrement()
        val connection = LwipTcpConnection(
            connId = connId,
            pcb = pcb,
            dstHost = decision.host,
            dstPort = dstPort,
            configuration = decision.configuration,
            forceBypass = decision.direct,
            // Only real-IP connections are worth sniffing: a fake IP already names the domain.
            sniffSNI = decision.realIp,
            lwipExecutor = lwipExecutor,
            host = this
        )
        tcpConnections[connId] = connection
        host.onConnectionCount(tcpConnections.size)
        return connId
    }

    override fun onTcpRecv(connId: Long, data: ByteArray?) {
        val connection = tcpConnections[connId] ?: return
        if (data != null && data.isNotEmpty()) connection.handleReceivedData(data) else connection.handleRemoteClose()
    }

    override fun onTcpSent(connId: Long, length: Int) {
        tcpConnections[connId]?.handleSent(length)
    }

    override fun onTcpErr(connId: Long, err: Int) {
        val connection = tcpConnections.remove(connId) ?: return
        host.onConnectionCount(tcpConnections.size)
        connection.handleError(err)
    }

    // ------------------------------------------------------------------- UDP

    override fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, data: ByteArray) {
        if (dstPort == 53 && handleDnsQuery(data, srcIp, srcPort, dstIp, dstPort, isIpv6)) return

        val s = settings
        if (s.blockQuic && dstPort == 443) {
            sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
            return
        }

        val srcHost = NativeBridge.nativeIpToString(srcIp, isIpv6) ?: "?"
        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"

        // An existing flow keeps its resolved domain even if the pool entry
        // has since been evicted; long-lived flows must not lose packets.
        val flowKey = "$srcHost:$srcPort-$dstIpString:$dstPort"
        udpFlows[flowKey]?.let { flow ->
            flow.handleReceivedData(data, data.size)
            return
        }

        val defaultConfig = configuration ?: return
        val decision = decide(dstIpString, dstPort, udp = true, defaultConfig = defaultConfig)
        if (decision == null) {
            sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
            return
        }
        if (udpFlows.size >= MAX_UDP_FLOWS) {
            logger.debug("UDP max flows reached ($MAX_UDP_FLOWS), dropping $flowKey")
            return
        }
        val flow = LwipUdpFlow(
            flowKey = flowKey,
            srcHost = srcHost, srcPort = srcPort,
            dstHost = decision.host, dstPort = dstPort,
            srcIpBytes = srcIp.copyOf(),
            dstIpBytes = dstIp.copyOf(),
            isIpv6 = isIpv6,
            configuration = decision.configuration,
            forceBypass = decision.direct,
            lwipExecutor = lwipExecutor,
            host = this
        )
        udpFlows[flowKey] = flow
        flow.handleReceivedData(data, data.size)
    }

    // --------------------------------------------------------------- routing

    private class Decision(val host: String, val configuration: ProxyConfiguration, val direct: Boolean, val realIp: Boolean)

    /** Null means drop: the route blocks it, or a fake IP no session knows about. */
    private fun decide(dstIp: String, dstPort: Int, udp: Boolean, defaultConfig: ProxyConfiguration): Decision? {
        var target = dstIp
        var realIp = true
        if (FakeIpPool.isFakeIp(dstIp)) {
            val entry = fakeIpPool.lookup(dstIp)
            if (entry == null) {
                logger.debug("Stale fake IP $dstIp:$dstPort (no pool entry)")
                return null
            }
            target = entry.domain
            realIp = false
        }
        return when (val route = host.route(target, dstPort, udp)) {
            TunRoute.Block -> {
                logger.debug("${if (udp) "UDP" else "TCP"} to $target:$dstPort blocked by rule")
                null
            }
            TunRoute.Direct -> Decision(target, defaultConfig, direct = true, realIp = realIp)
            is TunRoute.Proxy -> Decision(target, inheritChain(defaultConfig, route.configuration), direct = false, realIp = realIp)
        }
    }

    /** A rule-selected proxy without a chain of its own inherits the default outbound's. */
    private fun inheritChain(defaultConfig: ProxyConfiguration, override: ProxyConfiguration): ProxyConfiguration {
        val chain = defaultConfig.chain
        return if (!chain.isNullOrEmpty() && override.chain == null) override.withChain(chain) else override
    }

    // ------------------------------------------------------------------- DNS

    /** True when answered here (fake IP, NODATA, or a real answer on its way); false to open a flow. */
    private fun handleDnsQuery(payload: ByteArray, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean): Boolean {
        val s = settings
        val parsed = PacketUtil.parseDnsQueryExt(payload)
        if (parsed != null && (parsed.qtype == 1 || parsed.qtype == 28) && isRealAnswerDomain(parsed.domain.lowercase())) {
            answerWithRealAddress(payload, parsed.domain.lowercase(), parsed.qtype, srcIp, srcPort, dstIp, dstPort, isIpv6)
            return true
        }
        val reply = FakeIpDns.answer(payload, fakeIpPool, s.ipv6Dns, s.encryptedDnsEnabled) as? FakeIpDns.Answer.Reply
            ?: return false
        NativeBridge.nativeUdpSendto(dstIp, dstPort, srcIp, srcPort, isIpv6, reply.response, reply.response.size)
        reply.reason?.let { logger.debug("Blocked $it query") }
        return true
    }

    /**
     * The proxy server (or another name the platform excluded) must resolve
     * to where it really is: a fake answer would send the app's own
     * connection to it back into the tunnel. Resolution blocks, so it runs
     * off the lwIP thread and the reply hops back.
     */
    private fun answerWithRealAddress(
        payload: ByteArray, domain: String, qtype: Int,
        srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean
    ) {
        val submitted = runCatching {
            resolver.execute {
                val ips = runCatching { DnsCache.resolveAll(domain) }.getOrDefault(emptyList())
                val wantV6 = qtype == 28
                val chosen = ips.firstOrNull { (it.contains(':')) == wantV6 }
                val bytes = chosen?.let { runCatching { java.net.InetAddress.getByName(it).address }.getOrNull() }
                    ?.takeIf { it.size == (if (wantV6) 16 else 4) }
                val response = PacketUtil.generateDnsResponse(payload, bytes, qtype) ?: return@execute
                lwipExecutor.execute {
                    if (!running) return@execute
                    NativeBridge.nativeUdpSendto(dstIp, dstPort, srcIp, srcPort, isIpv6, response, response.size)
                    flushOutputPackets()
                }
            }
        }.isSuccess
        if (!submitted) {
            // Resolver saturated: NODATA now beats a query that never returns.
            val response = PacketUtil.generateDnsResponse(payload, null, qtype) ?: return
            NativeBridge.nativeUdpSendto(dstIp, dstPort, srcIp, srcPort, isIpv6, response, response.size)
        }
    }

    // ------------------------------------------------------------------ ICMP

    /** Must run on lwipExecutor. */
    private fun sendIcmpPortUnreachable(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, udpPayloadLength: Int) {
        val packet = if (isIpv6) IcmpPackets.portUnreachableV6(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        else IcmpPackets.portUnreachableV4(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        totalBytesIn.addAndGet(packet.size.toLong())
        outputPackets.add(packet)
        scheduleOutputFlush()
    }

    companion object {
        private val logger = MythaiaLogger("TunStack")
        private const val MAX_TCP_CONNECTIONS = 128
        private const val MAX_UDP_FLOWS = 200
    }
}
