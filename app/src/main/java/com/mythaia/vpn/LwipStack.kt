package com.mythaia.vpn

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.os.ParcelFileDescriptor
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.SplitTunnelSettings
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.tun.FakeIpDns
import com.mythaia.vpn.util.IcmpPackets
import com.mythaia.vpn.util.PacketUtil
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.LinkedBlockingQueue
import com.mythaia.vpn.protocol.mux.MuxManager
import kotlinx.coroutines.asCoroutineDispatcher
import org.json.JSONArray
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload

/**
 * Main coordinator for the lwIP TCP/IP stack on Android.
 *
 * All lwIP calls run on a single-threaded [lwipExecutor] (lwIP is not thread-safe).
 * One instance per VPN service, accessible via [instance].
 *
 * Reads IP packets from the TUN file descriptor, feeds them into lwIP for TCP/UDP
 * reassembly, and dispatches resulting connections through VLESS proxy clients.
 * Response data is written back to the TUN fd.
 */
class LwipStack(private val context: Context) : NativeBridge.LwipCallback, LwipHost {

    /** Single-threaded executor for all lwIP operations (lwIP is not thread-safe).
     *  DiscardPolicy silently drops tasks submitted after shutdown(), preventing
     *  RejectedExecutionException from in-flight coroutines that resume during teardown. */
    override val lwipExecutor: ScheduledExecutorService = ScheduledThreadPoolExecutor(1) { r ->
        Thread(r, "lwip-thread").apply { isDaemon = true }
    }.apply {
        rejectedExecutionHandler = ThreadPoolExecutor.DiscardPolicy()
        // Without this, a cancelled ScheduledFuture (idle/handshake/sniff timer)
        // stays queued up to its full delay (≤300 s), pinning the closed
        // connection it references. Drop cancelled tasks from the queue at once.
        removeOnCancelPolicy = true
    }

    /** Pool of reusable MTU-sized byte arrays to avoid per-packet allocation in the TUN reader. */
    private val packetPool = ConcurrentLinkedQueue<ByteArray>()
    private val packetPoolSize = java.util.concurrent.atomic.AtomicInteger(0)

    private class InboundPacket(val buffer: ByteArray, val length: Int)
    private val inboundPackets = ConcurrentLinkedQueue<InboundPacket>()
    private val inboundDrainScheduled = java.util.concurrent.atomic.AtomicBoolean(false)

    private var tunFd: ParcelFileDescriptor? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null
    /** The current TUN reader thread, tracked so a swap can retire its predecessor. */
    @Volatile
    private var tunReaderThread: Thread? = null
    // Read off the lwIP thread too: the latency tester asks LiveTunnel which
    // server is live before it releases a pooled session.
    @Volatile
    final override var configuration: ProxyConfiguration? = null
        private set

    // `ipv6DNSEnabled` is a single knob that controls both IPv6 routes on the
    // TUN interface and whether AAAA queries resolve to fake IPv6 addresses.
    var ipv6DNSEnabled: Boolean = false
        private set
    var encryptedDnsEnabled: Boolean = false
        private set
    var encryptedDnsProtocol: String = "doh"
        private set
    var encryptedDnsServer: String = ""
        private set
    /** When true, drop UDP/443 with ICMP port-unreachable so HTTP/3 clients fall back
     *  to HTTP/2. Defaults to true. */
    var blockQuicEnabled: Boolean = true
        private set
    /** Proxy mode: "global" sends all traffic through proxy, "rule" applies routing rules. */
    var proxyMode: String = "rule"
        private set
    /**
     * Which apps the TUN carries. Tracked here only so a change can be
     * detected; applying it is MythaiaVpnService's job, since it lives on
     * VpnService.Builder.
     */
    var splitTunnel: SplitTunnelSettings = SplitTunnelSettings()
        private set

    /** The provider's excluded routes as stored, to tell when the TUN must be rebuilt. */
    private var excludedRoutes: String = ""

    @Volatile
    private var running = false
    @Volatile
    private var tunFdSwapped = false

    // Timers
    private var timeoutTimer: ScheduledFuture<*>? = null
    private var udpCleanupTimer: ScheduledFuture<*>? = null

    // Restart throttling for handleNetworkPathChange.
    private var lastRestartNanos: Long = 0
    private var deferredRestart: ScheduledFuture<*>? = null
    private val restartThrottleNanos: Long = TunnelConstants.restartThrottleNanos

    /** Active country bypass selection (empty = disabled). Used only for change
     *  detection and log strings; the actual bypass rules are compiled into
     *  routing.json (`bypassRules`) by the app and consumed via DomainRouter. */
    var bypassCountryCode: String = ""
        private set

    /** Global traffic counters. */
    val totalBytesIn = AtomicLong(0)
    val totalBytesOut = AtomicLong(0)

    /**
     * Every proxy server the app has asked about (domains and resolved IPs,
     * lower-case): their names get real DNS answers, so a latency test or a
     * dial resolves a server to where it really is rather than to a fake IP.
     */
    private var proxyServerAddresses: Set<String> = emptySet()

    /**
     * The tunnel's own server and its chain, with what their names resolved
     * to: the only addresses that go around the tunnel. See [isProxyServerAddress].
     */
    @Volatile
    private var activeServerAddresses: Set<String> = emptySet()

    /** Mux manager for multiplexing UDP flows (created when Vision+Mux is active). */
    override var muxManager: MuxManager? = null

    /** Shadowsocks UDP sessions keyed by configuration id and local socket; see
     *  [LwipHost.shadowsocksUDPSession]. Only mutated on [lwipExecutor]. */
    private val ssUDPSessions = HashMap<String, com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession>()

    /**
     * True while a deliberate TCP teardown is in progress (stack shutdown,
     * restart, or wake handling). Set around [NativeBridge.nativeAbortAllTcp]
     * calls so [LwipTcpConnection.handleError] can demote the resulting
     * ERR_ABRT flood to debug — while still surfacing lwIP's own internal
     * aborts (e.g. tcp_kill_prio under PCB pool exhaustion) as warnings.
     */
    @Volatile
    override var isTearingDown: Boolean = false

    /** Active UDP flows keyed by 5-tuple string. */
    val udpFlows = ConcurrentHashMap<String, LwipUdpFlow>()

    /** Batched output packets awaiting flush to TUN fd (only accessed on lwipExecutor). */
    private val outputPackets = mutableListOf<ByteArray>()
    private var outputFlushScheduled = false

    /**
     * Single-in-flight gate for `flushOutputPackets`. Prevents the inline drain
     * path (called from TCP/UDP send callbacks via `flushOutputInline`) from
     * recursing into a partially-completed batch. Mirrors iOS
     * `outputWriteInFlight` flag in LWIPStack+IO.swift:46.
     */
    private var outputWriteInFlight = false

    /** Active TCP connections keyed by connection ID. */
    private val tcpConnections = ConcurrentHashMap<Long, LwipTcpConnection>()
    private val nextConnId = AtomicLong(1)

    /** Rate-limits the "TCP cap reached" warning (only touched on lwipExecutor). */
    private var lastTcpCapWarnNanos = 0L

    private fun warnTcpCapReached() {
        val now = System.nanoTime()
        if (now - lastTcpCapWarnNanos < TCP_CAP_WARN_INTERVAL_NANOS) return
        lastTcpCapWarnNanos = now
        logger.warning("[TCP] Connection cap ($MAX_TCP_CONNECTIONS) reached; refusing new connections (RST)")
    }

    /** Domain-based DNS routing. */
    val domainRouter = DomainRouter(context)

    /** Fake-IP pool for mapping domains to synthetic IPs. */
    val fakeIpPool = FakeIpPool()

    /**
     * Resolves real-answer domains (the proxy servers, the encrypted-DNS
     * bootstrap, bypass-by-domain names) off the lwIP thread so a blocking
     * lookup never stalls packet processing.
     */
    private val dnsResolver = ThreadPoolExecutor(
        0, 4, 30L, TimeUnit.SECONDS, LinkedBlockingQueue(64)
    ) { r -> Thread(r, "lwip-dns").apply { isDaemon = true } }

    /** SharedPreferences for settings. */
    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    }

    /** Callback to request VPN tunnel settings reapply (e.g. for IPv6 toggle). */
    var onTunnelSettingsNeedReapply: (() -> Unit)? = null

    private sealed class FakeIpResolution {
        data object Passthrough : FakeIpResolution()
        data class Resolved(
            val domain: String,
            val configurationOverride: ProxyConfiguration?,
            val forceBypass: Boolean
        ) : FakeIpResolution()
        data object Drop : FakeIpResolution()
        data object Unreachable : FakeIpResolution()
    }

    // Each signal type is coalesced through its own [SignalThrottler]
    // (throttleInterval = 1 s). At most one handler invocation per second per
    // signal, with a trailing edge so the final state always propagates.
    private val settingsThrottler = SignalThrottler(lwipExecutor, TunnelConstants.settingsThrottleNanos)
    private val routingThrottler = SignalThrottler(lwipExecutor, TunnelConstants.settingsThrottleNanos)
    private val certificateThrottler = SignalThrottler(lwipExecutor, TunnelConstants.settingsThrottleNanos)

    private val prefsListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        when (key) {
            "ipv6DnsEnabled",
            "bypassCountryCode",
            "encryptedDnsEnabled",
            "encryptedDnsProtocol",
            "encryptedDnsServer",
            "blockQuicEnabled",
            "splitTunnelMode",
            "splitTunnelPackages",
            "excludedRoutes",
            "proxyMode" -> settingsThrottler.submit(::handleSettingsChanged)
            // `routingChanged` restarts the lwIP stack so all in-flight connections re-evaluate
            // against the new rules (matching iOS LWIPStack+Lifecycle.swift:325-331).
            "routingChanged" -> routingThrottler.submit(::handleRoutingChanged)
            // `certificatePolicyChanged` re-reads allowInsecure + trusted certs and reapplies to
            // live connections.
            "certificatePolicyChanged" -> certificateThrottler.submit(::handleCertificatePolicyChanged)
        }
    }

    /** Returns true if traffic to the given host should bypass the tunnel.
     *  Only checks proxy-server-address. Country-based bypass is compiled into
     *  DomainRouter rules (`bypassRules` in routing.json) by the app, so all
     *  routing decisions go through DomainRouter consistently — runtime GeoIP
     *  would override user routing rules. */
    override fun shouldBypass(host: String): Boolean {
        return isProxyServerAddress(host)
    }

    /** The domain router's verdict for a sniffed SNI, in the form the shared flow code understands. */
    override fun routeDomain(domain: String): LwipDomainRoute? =
        when (val action = domainRouter.matchDomain(domain)) {
            null -> null
            RouteAction.Direct -> LwipDomainRoute.Direct
            RouteAction.Reject -> LwipDomainRoute.Reject
            RouteAction.DefaultProxy -> LwipDomainRoute.Proxy(configuration)
            is RouteAction.Proxy -> LwipDomainRoute.Proxy(domainRouter.resolveConfiguration(action))
        }

    /**
     * The routing profile's default for a destination no rule names, except
     * the tunnel's own DNS address, whose queries are answered here whatever
     * the profile says.
     */
    private fun defaultRouteFor(ip: String): RouteAction? =
        if (ip == TunnelConstants.dnsSentinelV4 || ip == TunnelConstants.dnsSentinelV6) null else domainRouter.defaultAction

    override fun removeUdpFlow(flowKey: String) {
        udpFlows.remove(flowKey)
    }

    /**
     * Whether [host] is the tunnel's own server (or a hop of its chain), whose
     * traffic must go around the tunnel.
     *
     * Only the live server counts. Every server the app had measured used to:
     * with a big subscription fronted by a CDN, those addresses are the CDN's
     * shared ones, so ordinary websites on the same CDN left the tunnel in
     * the clear. The app's own sockets (latency tests, dials) are protected
     * and never enter the tunnel, so they need no bypass.
     */
    private fun isProxyServerAddress(host: String): Boolean {
        val key = host.lowercase()
        if (activeServerAddresses.contains(key)) return true
        // Covers a switch whose names have not been resolved here yet.
        val config = configuration ?: return false
        return isAddressOf(config, key)
    }

    private fun isAddressOf(config: ProxyConfiguration, host: String): Boolean {
        if (host.equals(config.serverAddress, ignoreCase = true) || host == config.resolvedIP) return true
        if (DnsCache.cachedIPs(config.serverAddress)?.contains(host) == true) return true
        return config.chain?.any { isAddressOf(it, host) } == true
    }

    /** Updates the set of proxy server addresses from the app.
     *  The app persists domains plus any already-resolved IPs, so the VPN process
     *  can restore them without triggering fresh DNS lookups inside the tunnel. */
    fun updateProxyServerAddresses(addresses: List<String>) {
        lwipExecutor.execute {
            proxyServerAddresses = normalizeProxyServerAddresses(addresses)
        }
    }

    private fun loadProxyServerAddresses() {
        // Kept in a file of its own since thousands of servers made it a
        // megabyte inside the settings; the old key is read once after an update.
        val stored = context.getSharedPreferences(PROXY_ADDRESSES_PREFS, Context.MODE_PRIVATE)
            .getString("proxyServerAddresses", null)
            ?: prefs.getString("proxyServerAddresses", null)
            ?: return
        val parsed = runCatching {
            val array = JSONArray(stored)
            buildList(array.length()) {
                for (index in 0 until array.length()) {
                    val value = array.optString(index, "")
                    if (value.isNotBlank()) add(value)
                }
            }
        }.getOrElse {
            logger.debug("[LWIPStack] Failed to parse proxyServerAddresses: $it")
            emptyList()
        }
        proxyServerAddresses = normalizeProxyServerAddresses(parsed)
    }

    private fun seedProxyServerAddresses(config: ProxyConfiguration) {
        val addresses = normalizeProxyServerAddresses(collectProxyServerAddresses(config))
        proxyServerAddresses = proxyServerAddresses + addresses
        activeServerAddresses = addresses
        // Resolve domain names in background to catch DNS-resolved IPs.
        resolveProxyDomains(addresses)
    }

    /** Resolves the live server's domain names in background and adds the IPs to its bypass. */
    private fun resolveProxyDomains(addresses: Set<String>) {
        Thread {
            for (address in addresses) {
                // Skip if already an IP address
                if (address.contains(':') || address.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))) continue
                try {
                    val resolved = java.net.InetAddress.getAllByName(address)
                    val ips = resolved.mapNotNull { it.hostAddress?.lowercase() }.toSet()
                    if (ips.isNotEmpty()) {
                        lwipExecutor.execute {
                            proxyServerAddresses = proxyServerAddresses + ips
                            // Only while that server is still the live one.
                            if (activeServerAddresses.contains(address)) {
                                activeServerAddresses = activeServerAddresses + ips
                            }
                        }
                    }
                } catch (_: Exception) {
                    // DNS resolution failure is not fatal
                }
            }
        }.start()
    }

    private fun collectProxyServerAddresses(config: ProxyConfiguration): Set<String> {
        val addresses = linkedSetOf<String>()
        addresses.add(config.serverAddress)
        config.resolvedIP?.let(addresses::add)
        config.chain?.forEach { hop ->
            addresses.addAll(collectProxyServerAddresses(hop))
        }
        return addresses
    }

    private fun normalizeProxyServerAddresses(addresses: Collection<String>): Set<String> {
        // Lower-case, so a lookup is one set probe: the DNS path used to scan
        // the whole list per query, thousands of entries with a bulk list.
        return addresses.asSequence()
            .map { it.trim().lowercase() }
            .filter(String::isNotEmpty)
            .toCollection(HashSet())
    }

    private fun loadBypassCountry() {
        bypassCountryCode = prefs.getString("bypassCountryCode", "") ?: ""
        if (bypassCountryCode.isNotEmpty()) {
            logger.debug("[LWIPStack] Bypass country: $bypassCountryCode")
        }
    }

    private fun loadEncryptedDnsSettings() {
        encryptedDnsEnabled = prefs.getBoolean("encryptedDnsEnabled", false)
        encryptedDnsProtocol = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        encryptedDnsServer = prefs.getString("encryptedDnsServer", "") ?: ""
        // Publish to the resolver DnsCache consults. Every path that changes
        // these prefs comes through here, on start and on restart alike.
        EncryptedDnsPolicy.reload(context)
    }

    private fun loadBlockQuicSetting() {
        blockQuicEnabled = prefs.getBoolean("blockQuicEnabled", true)
    }

    private fun loadProxyModeSetting() {
        proxyMode = prefs.getString("proxyMode", "rule") ?: "rule"
    }

    private fun loadSplitTunnelSetting() {
        splitTunnel = SplitTunnelSettings.read(prefs)
        excludedRoutes = prefs.getString("excludedRoutes", "") ?: ""
    }

    private fun loadRoutingConfigurationForMode() {
        if (proxyMode == "global") {
            // Global mode sends everything through the proxy, the home
            // country included: no rules and no country bypass, which applies
            // in rule mode only (the settings hide it in global mode).
            domainRouter.reset()
            // MITM interception is gated independently of proxy mode, so prime
            // the store here too or a UI-less global-mode start would never
            // pick up a configured CA/rules.
            domainRouter.primeMitmStore()
        } else {
            domainRouter.loadRoutingConfiguration()
        }
        bypassAnsweredIps.clear()
    }

    /**
     * Addresses this tunnel's DNS handed out for country-bypass names, with
     * when they stop counting. Such a name gets its real address instead of a
     * fake one, so the connection that follows arrives by IP and the name is
     * gone; without this, a `.tm` site hosted outside the country's ranges
     * went through the proxy unless its SNI could be read (plain HTTP, QUIC).
     */
    private val bypassAnsweredIps = java.util.concurrent.ConcurrentHashMap<String, Long>()

    private fun rememberBypassAnswer(ip: String) {
        val now = android.os.SystemClock.elapsedRealtime()
        if (bypassAnsweredIps.size >= MAX_BYPASS_ANSWERS) {
            bypassAnsweredIps.entries.removeIf { it.value < now }
            if (bypassAnsweredIps.size >= MAX_BYPASS_ANSWERS) bypassAnsweredIps.clear()
        }
        bypassAnsweredIps[ip] = now + BYPASS_ANSWER_TTL_MS
    }

    /** Whether [ip] is a country-bypass address: in the bypass ranges, or one our DNS gave a bypass name. */
    private fun isBypassAddress(ip: String): Boolean {
        if (domainRouter.isBypassIp(ip)) return true
        val until = bypassAnsweredIps[ip] ?: return false
        return until > android.os.SystemClock.elapsedRealtime()
    }

    /**
     * Returns the SS UDP session for [config] and the local socket [source],
     * creating one on first use. Must be called on [lwipExecutor].
     *
     * Every flow of one local socket shares the session, so one sessionID
     * and one upstream socket serve all of that socket's destinations, which
     * keeps its NAT mapping full-cone. A session that has reached a terminal
     * (failed/cancelled) state is evicted and replaced transparently.
     *
     * @return The session, or `null` if [config] is missing / has malformed
     *   Shadowsocks credentials. Caller should treat null as a fatal flow
     *   misconfiguration.
     */
    override fun shadowsocksUDPSession(
        config: ProxyConfiguration,
        source: String
    ): com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession? {
        val key = "${config.id}|$source"
        ssUDPSessions[key]?.let { existing ->
            if (existing.isUsable) return existing
            ssUDPSessions.remove(key)
        }

        val mode = com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession.modeFor(config)
            ?: return null

        val session = com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession(
            mode = mode,
            serverHost = config.serverAddress,
            serverPort = config.serverPort.toInt(),
            executor = lwipExecutor
        )
        ssUDPSessions[key] = session
        return session
    }

    /** Ends [session] once its last flow has let go of it. Must be called on [lwipExecutor]. */
    override fun releaseShadowsocksUDPSession(session: com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession) {
        if (!session.isIdle) return
        session.cancel()
        ssUDPSessions.values.remove(session)
    }

    /**
     * Cancels and forgets every SS UDP session. Must be called on [lwipExecutor].
     * Called on stack shutdown, configuration switch, and device wake (the
     * kernel tears down our UDP sockets during sleep).
     */
    private fun purgeShadowsocksUDPSessions() {
        for (session in ssUDPSessions.values) {
            session.cancel()
        }
        ssUDPSessions.clear()
    }

    // -- Lifecycle --

    /**
     * Starts the lwIP stack and begins reading packets from the TUN.
     *
     * @param fd          The TUN file descriptor from VpnService.establish()
     * @param config      The VLESS proxy configuration
     * @param ipv6Dns     Whether IPv6 routes and AAAA fake-IP resolution are enabled
     */
    fun start(fd: ParcelFileDescriptor, config: ProxyConfiguration, ipv6Dns: Boolean = false) {
        logger.debug("[LWIPStack] Starting, ipv6Dns=$ipv6Dns")
        instance = this
        this.tunFd = fd
        this.tunInput = FileInputStream(fd.fileDescriptor)
        this.tunOutput = FileOutputStream(fd.fileDescriptor)
        this.configuration = config
        com.mythaia.vpn.protocol.LiveTunnel.register(this) { configuration }
        this.ipv6DNSEnabled = ipv6Dns

        // Register as lwIP callback handler
        NativeBridge.callback = this

        lwipExecutor.execute {
            running = true
            totalBytesIn.set(0)
            totalBytesOut.set(0)

            loadBypassCountry()
            loadEncryptedDnsSettings()
            loadBlockQuicSetting()
            loadProxyModeSetting()
            loadSplitTunnelSetting()

            // Create MuxManager when Vision+Mux is active (VLESS only)
            if (config.outboundProtocol == com.mythaia.data.model.OutboundProtocol.VLESS && config.muxEnabled && (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")) {
                muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
            }

            loadProxyServerAddresses()
            seedProxyServerAddresses(config)
            loadRoutingConfigurationForMode()
            NativeBridge.nativeInit()
            startTimeoutTimer()
            startUdpCleanupTimer()
            startReadingPackets()
            logger.debug("[LWIPStack] Started, mode=$proxyMode, mux=${muxManager != null}, ipv6dns=$ipv6DNSEnabled, encryptedDNS=$encryptedDnsEnabled, bypass=${bypassCountryCode.isNotEmpty()}")
        }

        startObservingSettings()
    }

    /** Stops the lwIP stack and closes all active flows.
     *
     * Non-blocking: submits cleanup to the lwIP executor and shuts the executor
     * down without waiting.
     *
     * @param onComplete Optional callback invoked on the executor thread after
     *   all cleanup is finished.  Callers that need to close shared resources
     *   (e.g., the TUN file descriptor) should do so inside this callback to
     *   avoid racing with in-flight I/O — resources must only be released
     *   after the queue drains. */
    fun stop(onComplete: (() -> Unit)? = null) {
        logger.debug("[LWIPStack] Stopping")
        stopObservingSettings()

        // All state clearing happens on the lwipExecutor to avoid races with
        // in-flight callbacks (e.g., onOutput() reading tunOutput).
        lwipExecutor.execute {
            running = false
            try {
                shutdownInternal()
            } catch (t: Throwable) {
                // The rest of the cleanup, and the caller's completion, must
                // still run: skipping them leaves the foreground notification
                // and the service alive with no tunnel behind them.
                logger.error("[LWIPStack] Shutdown failed: ${t.message ?: t}")
            } finally {
                fakeIpPool.reset()
                // Only our own registration: a stack started after this stop
                // was queued has already put itself here.
                if (NativeBridge.callback === this) NativeBridge.callback = null
                outputPackets.clear()
                outputFlushScheduled = false
                tunInput = null
                tunOutput = null
                tunFd = null
                configuration = null
                com.mythaia.vpn.protocol.LiveTunnel.unregister(this)
                dnsResolver.shutdownNow()
                if (instance === this) instance = null
                onComplete?.invoke()
            }
        }

        // Orderly shutdown: the executor finishes the queued cleanup task,
        // then terminates. Does NOT block the calling thread.
        lwipExecutor.shutdown()
    }

    /**
     * Tears down all active connections and re-creates them through the current
     * configuration. Called when the network path changes significantly
     * (interface switch, restored from unavailable, long sleep) so that stale
     * connections bound to the old interface are replaced immediately.
     *
     * Throttled to at most one restart per second; bursty path changes
     * (e.g. flapping) collapse into a single deferred restart.
     */
    fun handleNetworkPathChange(summary: String) {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            logger.warning("[VPN] Restarting stack after $summary")
            restartStack(config, ipv6DNSEnabled)
        }
    }

    /**
     * Invalidates outbound proxy state after the device wakes from sleep.
     *
     * The lwIP netif, listeners, timers, and routing state all survive
     * suspension intact — they live in our own memory, not the kernel's.
     * What the kernel does tear down is outbound sockets: the Vision mux's
     * long-lived TCP, per-flow UDP proxy connections, and the transport
     * sockets held by each [LwipTcpConnection]. Those are what this method
     * invalidates, leaving the rest of the stack running so idle flows and
     * the FakeIP pool are preserved.
     *
     * TCP flows are aborted via [NativeBridge.nativeAbortAllTcp] so each
     * PCB's err callback releases its Kotlin side (which closes the
     * now-dead proxy socket). The netif and listener PCBs stay up, so new
     * client activity is served without waiting on a netif rebuild.
     */
    fun handleWake() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            logger.info("[VPN] Device wake: invalidating outbound proxy state")

            muxManager?.closeAll()
            // Recreate MuxManager when Vision+Mux is active (VLESS only).
            muxManager = if (
                config.outboundProtocol == com.mythaia.data.model.OutboundProtocol.VLESS &&
                config.muxEnabled &&
                (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")
            ) {
                MuxManager(config, lwipExecutor.asCoroutineDispatcher())
            } else {
                null
            }

            // Purge SS sessions BEFORE closing UDP flows so flow.close() doesn't
            // reach into a session that's already being torn down. Mirrors iOS
            // LWIPStack+Lifecycle.swift:109-117.
            purgeShadowsocksUDPSessions()
            // The kernel dropped the QUIC sockets during sleep too; a pooled
            // Hysteria/TUIC session would otherwise be reused dead.
            com.mythaia.vpn.protocol.quic.QuicClientPool.closeAll()
            // So did the pooled HTTP/2 (gRPC, XHTTP) connections.
            com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.closeAll()

            for (flow in udpFlows.values) {
                flow.close()
            }
            udpFlows.clear()

            isTearingDown = true
            try {
                NativeBridge.nativeAbortAllTcp()
            } finally {
                isTearingDown = false
            }
        }
    }

    /** Switches to a new configuration, tearing down all active connections.
     *
     * Only restarts the lwIP stack — does NOT reapply tunnel network settings.
     * The TUN fd stays open and the packet read loop continues uninterrupted.
     * `onTunnelSettingsNeedReapply` is only called when IPv6/DNS settings change. */
    fun switchConfiguration(newConfig: ProxyConfiguration) {
        lwipExecutor.execute {
            logger.info("[VPN] Configuration switched; reconnecting active connections")
            restartStack(newConfig, ipv6DNSEnabled)
        }
    }

    /**
     * Swaps the TUN file descriptor (called from VpnService when tunnel settings
     * are reapplied, e.g. IPv6 toggle). Updates the input/output streams so the
     * next read loop uses the new fd. The old read thread will die naturally when
     * the old fd is closed by the caller.
     *
     * Must be called before [restartStack] so the flag is set.
     */
    fun swapTunFd(newFd: ParcelFileDescriptor) {
        // Hold on to the previous reader and its input so we can retire it:
        // closing only the old ParcelFileDescriptor (as the caller does) drops
        // the fd number but leaves the old reader parked in read(2) forever —
        // a thread and a kernel tun leaked on every IPv6/DNS/split-tunnel toggle.
        val oldInput = this.tunInput
        val oldThread = this.tunReaderThread

        this.tunFd = newFd
        this.tunInput = FileInputStream(newFd.fileDescriptor)
        this.tunOutput = FileOutputStream(newFd.fileDescriptor)

        // Start reading the new fd here rather than waiting for the restart.
        // restartStack is throttled to once every two seconds, so coupling the
        // two left a window with no reader at all — every packet an app sent in
        // it was dropped.
        if (running) {
            startReadingPackets()
        } else {
            tunFdSwapped = true
        }

        // Closing the old FileInputStream wakes its blocked read on Android
        // (libcore signals threads blocked on the fd), so the old reader throws,
        // sees the stream gone, and exits. Join to confirm it's gone before the
        // caller closes the old ParcelFileDescriptor.
        runCatching { oldInput?.close() }
        oldThread?.let { t -> runCatching { t.join(1000) } }
    }

    /**
     * Shuts down the lwIP stack and all active flows. Must be called on lwipExecutor.
     * Does NOT change [running] — callers manage it.
     */
    private fun shutdownInternal() {
        totalBytesIn.set(0)
        totalBytesOut.set(0)

        timeoutTimer?.cancel(false)
        timeoutTimer = null
        udpCleanupTimer?.cancel(false)
        udpCleanupTimer = null
        deferredRestart?.cancel(false)
        deferredRestart = null

        // Clear stale output and queued input packets before shutdown.
        outputPackets.clear()
        outputFlushScheduled = false
        inboundPackets.clear()
        inboundDrainScheduled.set(false)

        muxManager?.closeAll()
        muxManager = null

        com.mythaia.vpn.protocol.naive.http2.Http2SessionPool.closeAll()
        com.mythaia.vpn.protocol.quic.QuicClientPool.closeAll()
        com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.closeAll()

        // Close every shared Nowhere QUIC session and forget its identities, so a
        // fresh tunnel presents fresh session ids rather than reviving a portal's
        // view of the old client.
        com.mythaia.vpn.protocol.nowhere.NowhereClient.shutdown()

        // Drop VLESS post-quantum 0-RTT tickets: they are single-use handshake
        // state, and replaying one from a previous tunnel across a new connection
        // would weaken the very forward secrecy 0-RTT trades against.
        com.mythaia.vpn.protocol.vless.encryption.VlessEncryption0RttCache.shared.clear()

        val flowCount = udpFlows.size
        for (flow in udpFlows.values) {
            flow.close()
        }
        udpFlows.clear()

        // Drop SS UDP sessions before nativeShutdown so each session's recv
        // thread exits via socket close rather than racing the executor shutdown.
        purgeShadowsocksUDPSessions()

        // Do NOT explicitly close TCP connections here.  nativeShutdown() calls
        // lwip_bridge_shutdown() which tcp_abort()s every active PCB.  The abort
        // fires tcp_err_cb → onTcpErr → handleError, which properly releases the
        // proxy connection (NioSocket, ProxyConnection, etc.) and removes the entry
        // from tcpConnections.  This ensures clean RSTs are sent to the TUN
        // (apps see RST → close old connections → retry).
        //
        // The previous approach called conn.close() → tcp_close() (FIN) first,
        // which cleared tcp_arg/callbacks to NULL.  The subsequent tcp_abort()
        // inside lwip_bridge_shutdown() then fired tcp_err_cb with NULL arg,
        // silently swallowing the error.  While proxy cleanup still happened via
        // releaseProtocol(), the FIN packets were never flushed to TUN before
        // the stack was torn down, leaving apps hanging on dead connections.
        isTearingDown = true
        try {
            NativeBridge.nativeShutdown()
        } finally {
            isTearingDown = false
        }

        // Clean up any connections that weren't in tcp_active_pcbs (e.g. still
        // connecting) and therefore didn't receive an error callback.
        for (conn in tcpConnections.values) {
            if (!conn.closed) {
                conn.handleError(-1)
            }
        }
        tcpConnections.clear()

        logger.debug("[LWIPStack] Shutdown complete, closed $flowCount UDP flows")
    }

    /**
     * Tears down all connections and restarts the lwIP stack. Must be called on lwipExecutor.
     *
     * Throttled to at most once per [restartThrottleNanos] (2s). When a restart
     * is requested within the cooldown window the request is deferred; only the
     * last deferred request executes (earlier ones are cancelled and replaced).
     * All restart entry points (handleNetworkPathChange, switchConfiguration,
     * handleSettingsChanged, handleRoutingChanged, handleCertificatePolicyChanged)
     * flow through here.
     */
    private fun restartStack(config: ProxyConfiguration, ipv6Dns: Boolean) {
        val now = System.nanoTime()
        val elapsed = now - lastRestartNanos
        if (elapsed < restartThrottleNanos) {
            deferredRestart?.cancel(false)
            val delayMs = (restartThrottleNanos - elapsed) / 1_000_000L
            deferredRestart = lwipExecutor.schedule({
                deferredRestart = null
                if (!running) return@schedule
                restartStackNow(config, ipv6Dns)
            }, delayMs, TimeUnit.MILLISECONDS)
            logger.debug("[LWIPStack] Restart throttled, deferred by ${delayMs}ms")
            return
        }
        restartStackNow(config, ipv6Dns)
    }

    /** Performs the actual stack restart unconditionally. Must be called on lwipExecutor. */
    private fun restartStackNow(config: ProxyConfiguration, ipv6Dns: Boolean) {
        deferredRestart?.cancel(false)
        deferredRestart = null
        lastRestartNanos = System.nanoTime()

        shutdownInternal()

        this.configuration = config
        this.ipv6DNSEnabled = ipv6Dns
        loadBypassCountry()
        loadEncryptedDnsSettings()
        loadBlockQuicSetting()
        loadProxyModeSetting()
        loadSplitTunnelSetting()

        if (config.outboundProtocol == com.mythaia.data.model.OutboundProtocol.VLESS &&
            config.muxEnabled &&
            (config.flow == "xtls-rprx-vision" || config.flow == "xtls-rprx-vision-udp443")
        ) {
            muxManager = MuxManager(config, lwipExecutor.asCoroutineDispatcher())
        }

        // The full list is not reloaded on restart: it is populated once on
        // start() and refreshed via updateProxyServerAddresses(). The live
        // server's own bypass follows the new configuration.
        seedProxyServerAddresses(config)
        loadRoutingConfigurationForMode()
        NativeBridge.nativeInit()
        startTimeoutTimer()
        startUdpCleanupTimer()
        // Normally swapTunFd has already started the new reader; this covers
        // the case where the swap arrived while the stack was down.
        if (tunFdSwapped) {
            tunFdSwapped = false
            startReadingPackets()
        }
        logger.debug("[LWIPStack] Restarted, mode=$proxyMode, mux=${muxManager != null}, bypass=${bypassCountryCode.isNotEmpty()}, encryptedDns=$encryptedDnsEnabled, ipv6dns=$ipv6DNSEnabled")
    }

    private fun startObservingSettings() {
        prefs.registerOnSharedPreferenceChangeListener(prefsListener)
    }

    private fun stopObservingSettings() {
        prefs.unregisterOnSharedPreferenceChangeListener(prefsListener)
        settingsThrottler.reset()
        routingThrottler.reset()
        certificateThrottler.reset()
    }

    /**
     * Coalesces rapid bursts of signal notifications into at most one handler
     * invocation per [intervalNanos]. Fires immediately if the interval has
     * elapsed since the last fire, otherwise schedules a trailing-edge
     * invocation so the most recent state always lands on the VPN service.
     * A pending invocation is cancelled and replaced if a new signal arrives
     * before it runs.
     */
    private class SignalThrottler(
        private val scheduler: ScheduledExecutorService,
        private val intervalNanos: Long,
    ) {
        private val lock = Any()
        private var lastFireNanos: Long = Long.MIN_VALUE
        private var pending: ScheduledFuture<*>? = null

        fun submit(handler: () -> Unit) {
            synchronized(lock) {
                val now = System.nanoTime()
                val elapsed = if (lastFireNanos == Long.MIN_VALUE) intervalNanos else now - lastFireNanos
                pending?.cancel(false)
                pending = null
                if (elapsed >= intervalNanos) {
                    lastFireNanos = now
                    scheduler.execute { handler() }
                } else {
                    val delay = intervalNanos - elapsed
                    pending = scheduler.schedule({
                        synchronized(lock) {
                            lastFireNanos = System.nanoTime()
                            pending = null
                        }
                        handler()
                    }, delay, TimeUnit.NANOSECONDS)
                }
            }
        }

        fun reset() {
            synchronized(lock) {
                pending?.cancel(false)
                pending = null
                lastFireNanos = Long.MIN_VALUE
            }
        }
    }

    private fun handleSettingsChanged() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute

            val newIpv6Dns = prefs.getBoolean("ipv6DnsEnabled", false)
            val newBypassCode = prefs.getString("bypassCountryCode", "") ?: ""
            val newEncryptedDnsEnabled = prefs.getBoolean("encryptedDnsEnabled", false)
            val newEncryptedDnsProtocol = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
            val newEncryptedDnsServer = prefs.getString("encryptedDnsServer", "") ?: ""
            val newBlockQuicEnabled = prefs.getBoolean("blockQuicEnabled", true)
            val newProxyMode = prefs.getString("proxyMode", "rule") ?: "rule"
            val newSplitTunnel = SplitTunnelSettings.read(prefs)
            val newExcludedRoutes = prefs.getString("excludedRoutes", "") ?: ""

            val ipv6DnsChanged = newIpv6Dns != ipv6DNSEnabled
            val bypassChanged = newBypassCode != bypassCountryCode
            val encryptedDnsEnabledChanged = newEncryptedDnsEnabled != encryptedDnsEnabled
            val encryptedDnsProtocolChanged = newEncryptedDnsProtocol != encryptedDnsProtocol
            val encryptedDnsServerChanged = newEncryptedDnsServer != encryptedDnsServer
            val blockQuicChanged = newBlockQuicEnabled != blockQuicEnabled
            val proxyModeChanged = newProxyMode != proxyMode
            val splitTunnelChanged = newSplitTunnel != splitTunnel
            val excludedRoutesChanged = newExcludedRoutes != excludedRoutes

            if (!ipv6DnsChanged &&
                !bypassChanged &&
                !encryptedDnsEnabledChanged &&
                !encryptedDnsProtocolChanged &&
                !encryptedDnsServerChanged &&
                !blockQuicChanged &&
                !proxyModeChanged &&
                !splitTunnelChanged &&
                !excludedRoutesChanged
            ) return@execute

            // Re-apply the tunnel network settings whenever IPv6 changes
            // (adds/removes IPv6 routes and IPv6 DNS servers) or encrypted DNS
            // changes (switches between DoH/DoT).
            // A split-tunnel change is only expressible on VpnService.Builder,
            // so like the IPv6 and DNS changes it needs the TUN re-established.
            if (ipv6DnsChanged ||
                encryptedDnsEnabledChanged ||
                encryptedDnsProtocolChanged ||
                encryptedDnsServerChanged ||
                splitTunnelChanged ||
                excludedRoutesChanged
            ) {
                splitTunnel = newSplitTunnel
                excludedRoutes = newExcludedRoutes
                onTunnelSettingsNeedReapply?.invoke()
            }

            logger.info("[VPN] Settings changed (bypass=${newBypassCode.isNotEmpty()}, ipv6dns=$newIpv6Dns, encryptedDns=$newEncryptedDnsEnabled, blockQuic=$newBlockQuicEnabled); reconnecting active connections")
            restartStack(config, newIpv6Dns)
        }
    }

    private fun handleRoutingChanged() {
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            logger.info("[VPN] Routing changed; reconnecting active connections")
            // Restart the stack: closes all connections using outdated proxy configurations,
            // rebuilds the FakeIPPool, and reloads DomainRouter rules from routing.json.
            restartStack(config, ipv6DNSEnabled)
        }
    }

    /**
     * Called when the user toggles `allowInsecure` or updates trusted certificates.
     * Existing proxy connections are torn down and rebuilt on demand; new connections
     * observe the fresh policy via applyGlobalAllowInsecure() / TlsClient.trustedFingerprints.
     */
    private fun handleCertificatePolicyChanged() {
        // Refresh the cached policy first so any new connections (including the
        // ones created during restartStack) observe the latest allowInsecure +
        // trusted-fingerprint values.
        CertificatePolicy.reload(context)
        FragmentPolicy.reload(context)
        lwipExecutor.execute {
            if (!running) return@execute
            val config = configuration ?: return@execute
            logger.info("[VPN] Certificate policy changed; reconnecting active connections")
            restartStack(config, ipv6DNSEnabled)
        }
    }

    override fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean) {
        totalBytesIn.addAndGet(length.toLong())
        // Accumulate packets for batched write. onOutput is called from within
        // nativeInput/nativeTimerPoll on the lwipExecutor; the deferred flush runs
        // after the current lwIP processing cycle completes, reducing per-packet
        // syscall overhead.
        val copy = ByteArray(length)
        System.arraycopy(packet, 0, copy, 0, length)
        outputPackets.add(copy)
        scheduleOutputFlush()
    }

    /**
     * Flushes accumulated output packets to the TUN fd in capped batches with a
     * single-in-flight gate. Caps each pass at [TunnelConstants.tunnelMaxPacketsPerWrite]
     * to keep the lwIP executor from monopolizing the TUN fd; if more remain,
     * re-schedules itself on the executor so other work (timer, JNI callbacks)
     * gets a turn. Mirrors iOS LWIPStack+IO.swift:49-77.
     */
    private fun flushOutputPackets() {
        outputFlushScheduled = false
        if (outputPackets.isEmpty()) return
        if (outputWriteInFlight) {
            // Another flush is mid-batch on this thread (re-entry from inline drain
            // path) or the previous batch hasn't released the gate yet — defer.
            scheduleOutputFlush()
            return
        }
        val out = tunOutput ?: return
        outputWriteInFlight = true
        try {
            val cap = TunnelConstants.tunnelMaxPacketsPerWrite
            var written = 0
            val it = outputPackets.iterator()
            while (it.hasNext() && written < cap) {
                out.write(it.next())
                it.remove()
                written++
            }
        } catch (e: Exception) {
            logger.debug("[LWIPStack] TUN write error: $e")
            outputPackets.clear()
        } finally {
            outputWriteInFlight = false
        }
        if (outputPackets.isNotEmpty()) {
            scheduleOutputFlush()
        }
    }

    private fun scheduleOutputFlush() {
        if (!outputFlushScheduled) {
            outputFlushScheduled = true
            lwipExecutor.execute { flushOutputPackets() }
        }
    }

    /**
     * Drains the pending output buffer immediately on the calling thread.
     * Connection write paths (TCP send / UDP sendto) call this right after
     * `nativeTcpOutput` so the egress packet leaves the TUN within the
     * same lwIP cycle instead of waiting for the deferred flush to run on
     * the next executor tick.
     *
     * Safe to call from the lwIP executor or from inline JNI callbacks
     * — `flushOutputPackets()` is a single-shot drain that clears
     * [outputFlushScheduled] so the deferred path becomes a no-op.
     */
    override fun flushOutputInline() {
        flushOutputPackets()
    }

    override fun onTcpAccept(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, pcb: Long
    ): Long {
        // IPv6 is only served when IPv6 DNS is on. When it is off the TUN still
        // carries a ::/0 route (so IPv6 can't leak outside the tunnel), but any
        // IPv6 flow that arrives is dropped quietly here. (N4)
        if (isIpv6 && !ipv6DNSEnabled) {
            logger.debug("[TCP] Dropping IPv6 connection while IPv6 is disabled")
            return 0L
        }

        val defaultConfig = configuration ?: run {
            logger.debug("[LWIPStack] tcp_accept: no configuration")
            return 0L
        }

        // Prevent lwIP resource exhaustion (TCP segment pool, heap) under
        // heavy load.
        if (tcpConnections.size >= MAX_TCP_CONNECTIONS) {
            warnTcpCapReached()
            return 0L
        }

        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"

        // RST any TCP to the DNS sentinel so Android's Private DNS DoT/DoH probes
        // (853/443) fail fast and the system falls back to plain Do53, which our
        // UDP/53 interception handles. (N5)
        if (dstIpString == TunnelConstants.dnsSentinelV4 || dstIpString == TunnelConstants.dnsSentinelV6) {
            logger.debug("[TCP] RST to DNS sentinel $dstIpString:$dstPort (DoT/DoH blocked)")
            return 0L
        }
        var dstHost = dstIpString
        var connectionConfig = defaultConfig
        var forceBypass = false
        // Enable TLS ClientHello sniffing only on real-IP connections.
        // Fake-IP connections already know the domain via the fake-IP
        // pool; sniffing would add latency for no benefit (and could
        // miscategorize if the SNI disagrees with the DNS-resolved name).
        var sniffSNI = false

        when (val resolution = resolveFakeIp(dstIpString, dstPort, "TCP")) {
            FakeIpResolution.Passthrough -> {
                // Global mode skips IP routing rules and the country bypass:
                // all traffic goes through the proxy.
                if (proxyMode != "global") {
                    val ipAction = domainRouter.matchIP(dstIpString)
                    if (isBypassAddress(dstIpString) && ipAction == null) {
                        // A bypass name answered with its real address: no rule names
                        // this IP, but the name it came from goes direct.
                        forceBypass = true
                    } else {
                        (ipAction ?: defaultRouteFor(dstIpString))?.let { action ->
                            when (action) {
                                RouteAction.Direct -> forceBypass = true
                                RouteAction.Reject -> {
                                    logger.debug("[TCP] IP rejected by routing rule: $dstIpString:$dstPort")
                                    return 0L
                                }
                                RouteAction.DefaultProxy -> Unit
                                is RouteAction.Proxy -> {
                                    val resolved = domainRouter.resolveConfiguration(action)
                                    if (resolved != null) {
                                        connectionConfig = inheritChain(defaultConfig, resolved)
                                    } else {
                                        logger.warning("[TCP] Routing config not found for $dstIpString")
                                    }
                                }
                            }
                        }
                    }
                }
                sniffSNI = true
            }
            is FakeIpResolution.Resolved -> {
                dstHost = resolution.domain
                forceBypass = resolution.forceBypass
                connectionConfig = resolution.configurationOverride?.let {
                    inheritChain(defaultConfig, it)
                } ?: defaultConfig
            }
            FakeIpResolution.Drop, FakeIpResolution.Unreachable -> return 0L
        }

        // One line per connection in debug builds: whether a country or rule
        // bypass caught it is otherwise invisible from the outside.
        logger.debug("[TCP] $dstIpString:$dstPort ($dstHost) -> ${if (forceBypass) "direct" else "proxy"} [$proxyMode]")

        val connId = nextConnId.getAndIncrement()
        val connection = LwipTcpConnection(
            connId = connId,
            pcb = pcb,
            dstHost = dstHost,
            dstPort = dstPort,
            configuration = connectionConfig,
            forceBypass = forceBypass,
            sniffSNI = sniffSNI,
            lwipExecutor = lwipExecutor,
            host = this
        )
        tcpConnections[connId] = connection
        return connId
    }

    override fun onTcpRecv(connId: Long, data: ByteArray?) {
        val connection = tcpConnections[connId] ?: run {
            logger.debug("[LWIPStack] tcp_recv: connection $connId not found")
            return
        }
        if (data != null && data.isNotEmpty()) {
            connection.handleReceivedData(data)
        } else {
            connection.handleRemoteClose()
        }
    }

    override fun onTcpSent(connId: Long, length: Int) {
        val connection = tcpConnections[connId] ?: return
        connection.handleSent(length)
    }

    override fun onTcpErr(connId: Long, err: Int) {
        val connection = tcpConnections.remove(connId) ?: run {
            logger.debug("[LWIPStack] tcp_err: connection $connId not found, err=$err")
            return
        }
        connection.handleError(err)
    }

    override fun onUdpRecv(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean, data: ByteArray
    ) {
        // Drop IPv6 datagrams while IPv6 is disabled — the ::/0 route captures
        // them only to keep them out of the physical network. (N4)
        if (isIpv6 && !ipv6DNSEnabled) {
            logger.debug("[UDP] Dropping IPv6 datagram while IPv6 is disabled")
            return
        }

        // DNS interception: intercept port-53 queries for matched domains
        if (dstPort == 53) {
            if (handleDnsQuery(data, srcIp, srcPort, dstIp, dstPort, isIpv6)) {
                return  // Fake response sent, no flow needed
            }
            // No rule match — fall through, create normal UDP flow to proxy DNS
        }

        // QUIC blocking: drop UDP/443 with ICMP port-unreachable so HTTP/3 clients
        // fail fast on the first datagram and fall back to HTTP/2.
        if (blockQuicEnabled && dstPort == 443) {
            sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
            return
        }

        val srcHost = NativeBridge.nativeIpToString(srcIp, isIpv6) ?: "?"
        val dstIpString = NativeBridge.nativeIpToString(dstIp, isIpv6) ?: "?"

        // Fast path: deliver to an existing flow without re-resolving the fake IP.
        // The flow already has the resolved domain from when it was created.
        // This avoids dropping packets for long-lived flows (e.g. QUIC) whose
        // fake-IP pool entries may have been evicted by newer DNS allocations.
        // flowKey uses dstIpString (not domain) for consistency with lwIP packet delivery.
        val flowKey = "$srcHost:$srcPort-$dstIpString:$dstPort"
        udpFlows[flowKey]?.let { flow ->
            flow.handleReceivedData(data, data.size)
            return
        }

        // New flow — resolve fake IP to domain and determine routing
        var dstHost = dstIpString
        val defaultConfig = configuration ?: return
        var flowConfig = defaultConfig
        var forceBypass = false

        when (val resolution = resolveFakeIp(dstIpString, dstPort, "UDP")) {
            FakeIpResolution.Passthrough -> {
                // Global mode skips IP routing rules and the country bypass:
                // all traffic goes through the proxy.
                if (proxyMode != "global") {
                    val ipAction = domainRouter.matchIP(dstIpString)
                    if (isBypassAddress(dstIpString) && ipAction == null) {
                        // A bypass name answered with its real address: no rule names
                        // this IP, but the name it came from goes direct.
                        forceBypass = true
                    } else {
                        (ipAction ?: defaultRouteFor(dstIpString))?.let { action ->
                            when (action) {
                                RouteAction.Direct -> forceBypass = true
                                RouteAction.Reject -> {
                                    sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                                    return
                                }
                                RouteAction.DefaultProxy -> Unit
                                is RouteAction.Proxy -> {
                                    val resolved = domainRouter.resolveConfiguration(action)
                                    if (resolved != null) {
                                        flowConfig = inheritChain(defaultConfig, resolved)
                                    } else {
                                        logger.warning("[UDP] Routing config not found for $dstIpString")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            is FakeIpResolution.Resolved -> {
                dstHost = resolution.domain
                forceBypass = resolution.forceBypass
                flowConfig = resolution.configurationOverride?.let {
                    inheritChain(defaultConfig, it)
                } ?: defaultConfig
            }
            FakeIpResolution.Drop -> {
                sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                return
            }
            FakeIpResolution.Unreachable -> {
                logger.debug("[FakeIP] UDP to $dstIpString:$dstPort — stale DNS cache (no pool entry)")
                sendIcmpPortUnreachable(srcIp, srcPort, dstIp, dstPort, isIpv6, data.size)
                return
            }
        }

        if (udpFlows.size >= MAX_UDP_FLOWS) {
            logger.debug("[LWIPStack] UDP max flows reached ($MAX_UDP_FLOWS), dropping $flowKey")
            return
        }

        logger.debug("[UDP] $dstIpString:$dstPort -> ${if (forceBypass) "direct" else "proxy"} [$proxyMode]")
        val flow = LwipUdpFlow(
            flowKey = flowKey,
            srcHost = srcHost, srcPort = srcPort,
            dstHost = dstHost, dstPort = dstPort,
            srcIpBytes = srcIp.copyOf(),
            dstIpBytes = dstIp.copyOf(),
            isIpv6 = isIpv6,
            configuration = flowConfig,
            forceBypass = forceBypass,
            lwipExecutor = lwipExecutor,
            host = this
        )
        udpFlows[flowKey] = flow
        flow.handleReceivedData(data, data.size)
    }

    private fun resolveFakeIp(ip: String, dstPort: Int, proto: String): FakeIpResolution {
        if (!FakeIpPool.isFakeIp(ip)) return FakeIpResolution.Passthrough

        val entry = fakeIpPool.lookup(ip) ?: return FakeIpResolution.Unreachable
        // In global mode, skip routing rules and the country bypass — all
        // traffic goes through the proxy.
        if (proxyMode == "global") {
            return FakeIpResolution.Resolved(entry.domain, null, false)
        }

        // A name no rule speaks of: what its address said when the profile
        // asked (IPIfNonMatch), else the profile's default.
        val action = domainRouter.matchDomain(entry.domain)
            ?: domainRouter.addressVerdict(entry.domain)
            ?: domainRouter.defaultAction
        return when (action) {
            RouteAction.Direct -> FakeIpResolution.Resolved(entry.domain, null, true)
            RouteAction.DefaultProxy -> FakeIpResolution.Resolved(entry.domain, null, false)
            RouteAction.Reject -> {
                logger.debug("[FakeIP] $proto to ${entry.domain}:$dstPort — REJECT")
                FakeIpResolution.Drop
            }
            is RouteAction.Proxy -> {
                val resolved = domainRouter.resolveConfiguration(action)
                if (resolved == null) {
                    logger.warning("[$proto] Routing config not found for ${entry.domain}")
                }
                FakeIpResolution.Resolved(entry.domain, resolved, false)
            }
            null -> FakeIpResolution.Resolved(entry.domain, null, false)
        }
    }

    private fun inheritChain(
        defaultConfig: ProxyConfiguration,
        overrideConfig: ProxyConfiguration
    ): ProxyConfiguration {
        val chain = defaultConfig.chain
        return if (!chain.isNullOrEmpty() && overrideConfig.chain == null) {
            overrideConfig.withChain(chain)
        } else {
            overrideConfig
        }
    }

    /**
     * Intercepts a DNS query. Returns true if handled (no UDP flow needed).
     * The decision itself lives in the shared [FakeIpDns].
     */
    private fun handleDnsQuery(
        payload: ByteArray,
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean
    ): Boolean {
        // A/AAAA for a real-answer domain (the proxy server's own name, the
        // encrypted-DNS bootstrap, a bypass-by-domain name) must resolve to its
        // real address: fake-IP'ing it would route the app's own direct
        // connection to it back into the tunnel. Mirrors TunStack.
        val parsed = PacketUtil.parseDnsQueryExt(payload)
        if (parsed != null && (parsed.qtype == 1 || parsed.qtype == 28) &&
            isRealAnswerDomain(parsed.domain.lowercase())
        ) {
            answerWithRealAddress(payload, parsed.domain.lowercase(), parsed.qtype, srcIp, srcPort, dstIp, dstPort, isIpv6)
            return true
        }

        // The routing profile wants this name's address checked against its
        // address rules first; the answer waits for the check, so the
        // connection that follows finds the verdict.
        if (parsed != null && (parsed.qtype == 1 || parsed.qtype == 28) && proxyMode != "global" &&
            domainRouter.wantsAddressCheck(parsed.domain.lowercase())
        ) {
            checkAddressThenAnswer(payload, parsed.domain.lowercase(), srcIp, srcPort, dstIp, dstPort, isIpv6)
            return true
        }

        return answerWithFakeIp(payload, srcIp, srcPort, dstIp, dstPort, isIpv6)
    }

    /** The usual answer: a fake address from the pool, or a refusal [FakeIpDns] decides on. */
    private fun answerWithFakeIp(
        payload: ByteArray,
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean
    ): Boolean {
        val answer = FakeIpDns.answer(payload, fakeIpPool, ipv6DNSEnabled, encryptedDnsEnabled)
        val reply = answer as? FakeIpDns.Answer.Reply ?: return false

        // Send response back via lwIP (swap src/dst)
        NativeBridge.nativeUdpSendto(
            dstIp, dstPort,     // original dst becomes response src
            srcIp, srcPort,     // original src becomes response dst
            isIpv6,
            reply.response, reply.response.size
        )
        reply.reason?.let { logger.debug("[FakeIP] Blocked $it query") }
        return true
    }

    /**
     * Resolves [domain] off the lwIP thread for the routing profile's address
     * rules, then answers as usual. A saturated resolver answers at once
     * without the check: the name then takes the profile's default.
     */
    private fun checkAddressThenAnswer(
        payload: ByteArray, domain: String,
        srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean
    ) {
        val submitted = runCatching {
            dnsResolver.execute {
                runCatching { domainRouter.checkAddress(domain) }
                lwipExecutor.execute {
                    if (!running) return@execute
                    if (answerWithFakeIp(payload, srcIp, srcPort, dstIp, dstPort, isIpv6)) flushOutputInline()
                }
            }
        }.isSuccess
        if (!submitted) answerWithFakeIp(payload, srcIp, srcPort, dstIp, dstPort, isIpv6)
    }


    /** Names that must resolve to their real address, never a fake IP. [domain] is lower-case. */
    private fun isRealAnswerDomain(domain: String): Boolean {
        if (domain.isEmpty()) return false
        if (proxyServerAddresses.contains(domain) && !DnsCache.isIpAddress(domain)) return true
        if (EncryptedDnsPolicy.upstream.bootstrapHost?.equals(domain, ignoreCase = true) == true) return true
        return domainRouter.isBypassDomain(domain)
    }

    /**
     * Resolves [domain] to its real address off the lwIP thread and writes the
     * answer back. Resolution blocks, so it runs on [dnsResolver] and the reply
     * hops back onto the lwIP executor. If the resolver is saturated or the
     * lookup fails, NODATA is returned rather than a fake IP — a real name must
     * never be pinned to the synthetic range. Mirrors TunStack.answerWithRealAddress.
     */
    private fun answerWithRealAddress(
        payload: ByteArray, domain: String, qtype: Int,
        srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean
    ) {
        val submitted = runCatching {
            dnsResolver.execute {
                val ips = runCatching { DnsCache.resolveAll(domain) }.getOrDefault(emptyList())
                val wantV6 = qtype == 28
                val chosen = ips.firstOrNull { it.contains(':') == wantV6 }
                val bytes = chosen?.let { runCatching { InetAddress.getByName(it).address }.getOrNull() }
                    ?.takeIf { it.size == (if (wantV6) 16 else 4) }
                val response = PacketUtil.generateDnsResponse(payload, bytes, qtype) ?: return@execute
                if (chosen != null && domainRouter.isBypassDomain(domain)) rememberBypassAnswer(chosen)
                lwipExecutor.execute {
                    if (!running) return@execute
                    NativeBridge.nativeUdpSendto(dstIp, dstPort, srcIp, srcPort, isIpv6, response, response.size)
                    flushOutputInline()
                }
            }
        }.isSuccess
        if (!submitted) {
            val response = PacketUtil.generateDnsResponse(payload, null, qtype) ?: return
            NativeBridge.nativeUdpSendto(dstIp, dstPort, srcIp, srcPort, isIpv6, response, response.size)
        }
    }

    // ICMP Destination Unreachable (Port Unreachable) is sent when UDP arrives
    // at a stale fake IP no longer in the pool (e.g. from a previous VPN
    // session) or at a rejected domain. The ICMP response causes UDP clients
    // to abandon the stale connection and re-resolve DNS instead of retrying
    // indefinitely.

    /**
     * Crafts and writes an ICMP Destination Unreachable (Port Unreachable) response.
     * Must be called on lwipExecutor.
     */
    private fun sendIcmpPortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean,
        udpPayloadLength: Int
    ) {
        val packet = if (isIpv6) {
            buildIcmpv6PortUnreachable(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        } else {
            buildIcmpv4PortUnreachable(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)
        }
        outputPackets.add(packet)
        if (!outputFlushScheduled) {
            outputFlushScheduled = true
            lwipExecutor.execute { flushOutputPackets() }
        }
    }

    /** IPv4 ICMP Port Unreachable; see [IcmpPackets.portUnreachableV4]. */
    private fun buildIcmpv4PortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray = IcmpPackets.portUnreachableV4(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)

    /** IPv6 ICMPv6 Port Unreachable; see [IcmpPackets.portUnreachableV6]. */
    private fun buildIcmpv6PortUnreachable(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray = IcmpPackets.portUnreachableV6(srcIp, srcPort, dstIp, dstPort, udpPayloadLength)


    /** Continuously reads IP packets from the TUN fd and feeds them into lwIP.
     *  Batches multiple packets per executor dispatch to reduce task overhead. */
    private fun startReadingPackets() {
        val thread = Thread({
            val buffer = ByteArray(1500)  // MTU-sized read buffer
            // Bind to the stream captured at start: a later swapTunFd installs a
            // new reader for the new stream and closes this one to wake us.
            val input = tunInput ?: return@Thread

            while (running) {
                try {
                    // No input.available() probe: the TUN driver returns EINVAL for
                    // it, which used to raise (and discard) an IOException per packet.
                    val length = input.read(buffer)
                    if (length <= 0) {
                        if (!running) break
                        continue
                    }

                    totalBytesOut.addAndGet(length.toLong())

                    val packet = packetPool.poll()?.also { packetPoolSize.decrementAndGet() } ?: ByteArray(1500)
                    System.arraycopy(buffer, 0, packet, 0, length)
                    inboundPackets.offer(InboundPacket(packet, length))
                    scheduleInboundDrain()
                } catch (e: Exception) {
                    if (running) {
                        logger.debug("[LWIPStack] TUN read error: $e")
                    }
                    break
                }
            }
        }, "tun-reader").apply { isDaemon = true }
        tunReaderThread = thread
        thread.start()
    }

    private fun scheduleInboundDrain() {
        if (inboundDrainScheduled.compareAndSet(false, true)) {
            lwipExecutor.execute { drainInboundPackets() }
        }
    }

    private fun drainInboundPackets() {
        inboundDrainScheduled.set(false)
        val cap = TunnelConstants.tunnelMaxPacketsPerWrite
        var processed = 0
        while (processed < cap) {
            val item = inboundPackets.poll() ?: break
            if (running) {
                NativeBridge.nativeInput(item.buffer, item.length)
            }
            if (packetPoolSize.get() < MAX_PACKET_POOL_SIZE) {
                packetPoolSize.incrementAndGet()
                packetPool.offer(item.buffer)
            }
            processed++
        }
        // Inline flush once per batch: drain output packets (including coalesced
        // TCP ACKs) accumulated across the batch without per-packet syscalls.
        if (running && outputPackets.isNotEmpty()) {
            flushOutputPackets()
        }
        if (running && inboundPackets.isNotEmpty()) {
            scheduleInboundDrain()
        }
    }

    /** Starts the lwIP periodic timeout timer (100ms interval). */
    private fun startTimeoutTimer() {
        // Fixed delay, not rate: coming back from a cached state must not
        // replay every tick the process slept through in one burst.
        timeoutTimer = lwipExecutor.scheduleWithFixedDelay({
            if (running) {
                NativeBridge.nativeTimerPoll()
            }
        }, TunnelConstants.lwipTimeoutIntervalMs, TunnelConstants.lwipTimeoutIntervalMs, TimeUnit.MILLISECONDS)
    }

    /** Starts the UDP flow cleanup timer. */
    private fun startUdpCleanupTimer() {
        udpCleanupTimer = lwipExecutor.scheduleWithFixedDelay({
            if (!running) return@scheduleWithFixedDelay
            val now = System.nanoTime() / 1_000_000_000.0
            val keysToRemove = mutableListOf<String>()
            for ((key, flow) in udpFlows) {
                if (now - flow.lastActivity > TunnelConstants.udpIdleTimeoutSec) {
                    flow.close()
                    keysToRemove.add(key)
                }
            }
            for (key in keysToRemove) {
                udpFlows.remove(key)
            }
        }, TunnelConstants.udpCleanupIntervalSec, TunnelConstants.udpCleanupIntervalSec, TimeUnit.SECONDS)
    }

    /** Called by LwipTcpConnection when it closes/aborts itself. */
    override fun removeConnection(connId: Long) {
        tcpConnections.remove(connId)
    }

    companion object {
        private val logger = MythaiaLogger("LWIPStack")

        /** The preferences file holding the proxy server address list, apart from the settings. */
        const val PROXY_ADDRESSES_PREFS = "mythaia_addresses"

        /** How long an address our DNS gave a bypass name keeps routing direct. */
        private const val BYPASS_ANSWER_TTL_MS = 30 * 60 * 1000L
        private const val MAX_BYPASS_ANSWERS = 4096
        private const val MAX_PACKET_POOL_SIZE = 256
        // Kept in sync with lwipopts.h MEMP_NUM_TCP_PCB (512). A PCB is small,
        // so a higher ceiling costs little and avoids silently RST'ing the
        // 129th concurrent connection on a busy device.
        private const val MAX_TCP_CONNECTIONS = 512
        private const val MAX_UDP_FLOWS = 200
        private const val TCP_CAP_WARN_INTERVAL_NANOS = 5_000_000_000L

        /**
         * Singleton for callback access.
         *
         * The context behind it is the VPN service, not an Activity, and the
         * reference is set in start() and cleared in stop() — so it lives
         * exactly as long as the tunnel does, which is the service's own
         * lifetime.
         */
        @SuppressLint("StaticFieldLeak")
        @Volatile
        var instance: LwipStack? = null
            private set
    }
}
