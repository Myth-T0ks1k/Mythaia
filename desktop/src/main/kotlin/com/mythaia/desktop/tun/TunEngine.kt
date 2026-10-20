package com.mythaia.desktop.tun

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.engine.Router
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.model.RouteTarget
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig
import com.mythaia.vpn.protocol.wireguard.WireGuardTunnel
import com.mythaia.vpn.tun.TunHost
import com.mythaia.vpn.tun.TunRoute
import com.mythaia.vpn.tun.TunSettings
import com.mythaia.vpn.tun.TunStack
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * The all-traffic mode: a Wintun adapter takes the default route, its
 * packets go through lwIP ([TunStack]) and every resulting flow is routed
 * exactly as the local-proxy mode routes its connections — rule or global
 * mode, direct / proxy / block — then dialled through the same protocol
 * clients.
 *
 * Same lifecycle shape as `ProxyEngine`: [start] with the settings and the
 * server, [switchTo] to change the server while up, [stop] to tear down.
 * [start] blocks for the second or two the system configuration takes and
 * throws [IOException] with a user-readable reason when it cannot come up
 * (not elevated, no wintun.dll, no default route, netsh refused). All of
 * that is undone before the exception leaves.
 *
 * A WireGuard or AmneziaWG profile is layer 3: there is no stream to
 * route, so instead of lwIP the profile's own interface is built — its
 * addresses, DNS and MTU on the adapter, its AllowedIPs as the routes — and
 * [WireGuardTunnel] carries whole packets to the peer, whose address keeps
 * a host route through the physical gateway. A watcher moves that route and
 * the peer socket when the physical network changes.
 *
 * Needs an elevated process: see [isElevated] and [relaunchElevated].
 */
class TunEngine(val stats: TrafficStats) {
    enum class Status { STOPPED, STARTING, RUNNING, STOPPING }

    private val logger = MythaiaLogger("TunEngine")
    private val lock = Any()

    private val _status = MutableStateFlow(Status.STOPPED)
    val status: StateFlow<Status> = _status

    /** The reason the last [start] failed or the stack died; null after a clean start. */
    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError

    @Volatile
    var configuration: ProxyConfiguration? = null
        private set

    val isRunning: Boolean get() = _status.value == Status.RUNNING

    @Volatile
    private var router: Router = Router(emptyList(), global = false, bypassCountries = listOf("TM"))

    @Volatile
    private var settings: DesktopSettings = DesktopSettings()

    private var stack: TunStack? = null
    private var adapter: WintunAdapter? = null

    // Read by the lwIP thread in [host].
    @Volatile
    private var session: WintunAdapter.Session? = null
    private var reader: Thread? = null
    private val routes = WindowsRoutes(AppPaths.tunRouteSnapshot)
    // Read by the WireGuard tunnel's threads when it opens a socket.
    @Volatile
    private var physical: PhysicalPath? = null

    @Volatile
    private var readerRunning = false

    /** The WireGuard tunnel, when the profile is layer 3; [stack] is null then. */
    @Volatile
    private var wireGuard: WireGuardTunnel? = null
    private var wireGuardDevice: WintunPacketDevice? = null
    private var pathWatcher: Thread? = null

    /** The adapter's interface index while up, for telling it from the physical network. */
    @Volatile
    private var adapterIndex = 0

    /** Same contract as `ProxyEngine.updateRouting`: new flows use the new rules, open ones finish as they were. */
    fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings) {
        this.settings = settings
        router = Router(rules, settings.isGlobal, if (settings.bypassTurkmenistan) listOf("TM") else emptyList())
        stack?.updateSettings(tunSettings(settings, configuration))
    }

    /**
     * Brings the tunnel up for [configuration], or switches to it when
     * already up. Blocking; throws with the reason on failure.
     */
    @Throws(IOException::class)
    fun start(settings: DesktopSettings, configuration: ProxyConfiguration) {
        synchronized(lock) {
            this.settings = settings
            if (_status.value == Status.RUNNING) {
                if (this.configuration != configuration) switchTo(configuration)
                return
            }
            if (_status.value != Status.STOPPED) throw IOException("TUN engine is busy")
            _status.value = Status.STARTING
            _lastError.value = null
            try {
                startLocked(settings, configuration)
                _status.value = Status.RUNNING
            } catch (e: Throwable) {
                // Throwable, not Exception: a JNA link error (jnidispatch.dll
                // blocked by antivirus) is an Error, and letting it past here
                // left the engine in STARTING, "busy" until the app restarted.
                val message = e.message ?: e.toString()
                logger.error("TUN start failed: $message")
                _lastError.value = message
                runCatching { teardownLocked() }
                _status.value = Status.STOPPED
                if (e is VirtualMachineError) throw e
                throw (e as? IOException) ?: IOException(message, e)
            }
        }
    }

    /**
     * Changes the outbound; open flows are re-established through the new
     * server. Throws when a switch to or from WireGuard, which rebuilds the
     * adapter, fails; the engine is stopped then.
     */
    @Throws(IOException::class)
    fun switchTo(configuration: ProxyConfiguration) {
        synchronized(lock) {
            // To or from a WireGuard profile, the adapter itself changes
            // (its addresses and routes come from the profile): start over.
            val layer3 = configuration.outboundProtocol.isLayer3 || this.configuration?.outboundProtocol?.isLayer3 == true
            if (layer3 && _status.value == Status.RUNNING) {
                restartLocked(configuration)
                return
            }
            this.configuration = configuration
            DnsCache.setActiveProxyDomain(configuration.serverAddress)
            if (_status.value != Status.RUNNING) return
            for (ip in exclusionsFor(configuration)) routes.excludeHost(ip)
            stack?.updateSettings(tunSettings(settings, configuration))
            stack?.switchConfiguration(configuration)
            logger.info("Switched to ${configuration.name}")
        }
    }

    /** Tears everything down and restores the routes and DNS. Blocking, a few seconds at most. */
    fun stop() {
        val watcher: Thread?
        synchronized(lock) {
            if (_status.value == Status.STOPPED) {
                routes.cleanupLeftovers()
                return
            }
            _status.value = Status.STOPPING
            watcher = pathWatcher
            try {
                teardownLocked()
            } finally {
                _status.value = Status.STOPPED
            }
        }
        // Joined outside lock so an in-flight path check blocked on lock can
        // see the interrupted/stopped state and exit without deadlocking stop().
        watcher?.let { w ->
            try {
                w.join(READER_JOIN_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    /** Tears down and comes up again for [config]; a failure leaves the engine stopped with the reason. */
    private fun restartLocked(config: ProxyConfiguration) {
        logger.info("Rebuilding the tunnel for ${config.name}")
        _status.value = Status.STARTING
        try {
            teardownLocked()
            startLocked(settings, config)
            _status.value = Status.RUNNING
        } catch (e: Throwable) {
            val message = e.message ?: e.toString()
            logger.error("TUN restart failed: $message")
            _lastError.value = message
            runCatching { teardownLocked() }
            _status.value = Status.STOPPED
            if (e is VirtualMachineError) throw e
            throw (e as? IOException) ?: IOException(message, e)
        }
    }

    // ---------------------------------------------------------------- start

    private fun startLocked(settings: DesktopSettings, config: ProxyConfiguration) {
        if (!WindowsNet.isWindows) throw IOException("TUN mode is only available on Windows")
        val dll = AppPaths.wintunLibrary() ?: throw IOException("wintun.dll not found (expected in ${AppPaths.resourcesDir ?: "resources/windows-x64"})")
        if (!isElevated()) throw IOException("TUN mode needs administrator rights")
        if (config.outboundProtocol.isLayer3) {
            startWireGuardLocked(dll, config)
            return
        }
        if (!NativeBridge.isLoaded) throw IOException("The native library (mythaia_native.dll) is not loaded")

        routes.cleanupLeftovers()

        // Learn the physical path before the default route moves.
        val path = WindowsNet.physicalPath() ?: throw IOException("No default route: is the computer online?")
        physical = path
        logger.info("Physical interface ${path.interfaceIndex} at ${path.address.hostAddress} via ${path.gateway ?: "on-link"}, DNS ${path.dnsServers}")

        // The app's own traffic bypasses the tunnel from this point on:
        // sockets bind to the physical address and names resolve there.
        WindowsSocketProtector.install(path.address)
        DnsCache.setUnderlyingNetwork(WindowsUnderlyingNetwork(path.dnsServers.ifEmpty { FALLBACK_DNS }))
        DnsCache.setActiveProxyDomain(config.serverAddress)
        this.configuration = config

        val excluded = LinkedHashSet<String>()
        excluded += exclusionsFor(config)
        excluded += path.dnsServers
        excluded += FALLBACK_DNS
        EncryptedDnsPolicy.upstream.bootstrapHost?.let { excluded += WindowsNet.resolveV4(it) }
        excluded.removeAll { ip -> runCatching { path.isOnLink(java.net.InetAddress.getByName(ip)) }.getOrDefault(false) }

        val created = WintunAdapter.create(dll, ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)
        adapter = created
        val ifIndex = created.interfaceIndex()
        adapterIndex = ifIndex
        logger.info("Wintun adapter '$ADAPTER_NAME' is interface $ifIndex (driver ${WintunAdapter.runningDriverVersion(dll) ?: "?"})")

        val networks = ArrayList(TunNetConfig.PRIVATE_NETWORKS)
        if (settings.bypassTurkmenistan) networks += turkmenNetworks()
        routes.apply(
            TunNetConfig(
                interfaceIndex = ifIndex,
                physicalInterfaceIndex = path.interfaceIndex,
                physicalGateway = path.gateway,
                excludedHosts = excluded.toList(),
                excludedNetworks = networks
            )
        )

        val newStack = TunStack(host)
        stack = newStack
        stats.reset()
        newStack.start(config, tunSettings(settings, config))

        val newSession = created.startSession()
        session = newSession
        readerRunning = true
        reader = Thread({
            try {
                newSession.readLoop(keepRunning = { readerRunning }) { batch ->
                    var bytes = 0L
                    for (p in batch) bytes += p.size
                    stats.up.addAndGet(bytes)
                    try {
                        newStack.input(batch)
                    } catch (e: RejectedExecutionException) {
                        // The stack's executor shut down between teardown's
                        // stop() and this batch; the reader is about to quit.
                    }
                }
                logger.debug("Reader finished")
            } catch (t: Throwable) {
                logger.error("Reader failed: ${t.message ?: t}")
            }
        }, "wintun-reader").apply { isDaemon = true }
        reader?.start()
        logger.info("TUN up: ${config.name} (${config.outboundProtocol.displayName}), mode=${if (settings.isGlobal) "global" else "rule"}")
    }

    /**
     * A WireGuard or AmneziaWG profile: the adapter laid out from its
     * `[Interface]`, AllowedIPs routed into it, and the tunnel's socket bound
     * to the physical address. Returns once the first handshake is done, so
     * a peer that does not answer fails the start with the reason instead of
     * leaving every program without a network behind a "connected" tunnel.
     */
    private fun startWireGuardLocked(dll: File, config: ProxyConfiguration) {
        // A chain dials a stream through each hop; WireGuard sends packets and has nowhere to put one.
        if (!config.chain.isNullOrEmpty()) throw IOException("WireGuard cannot be the exit of a proxy chain")
        val text = config.wireGuardConfig?.takeIf { it.isNotBlank() }
            ?: throw IOException("${config.name} has no WireGuard configuration")
        val profile = try {
            WireGuardConfig.parse(text)
        } catch (e: Exception) {
            throw IOException("WireGuard configuration is not usable: ${e.message ?: e}")
        }
        if (profile.addresses.none { com.mythaia.vpn.util.Cidr.split(it) != null }) {
            throw IOException("The WireGuard configuration has no usable [Interface] Address")
        }

        routes.cleanupLeftovers()
        val path = WindowsNet.physicalPath() ?: throw IOException("No default route: is the computer online?")
        physical = path
        logger.info("Physical interface ${path.interfaceIndex} at ${path.address.hostAddress} via ${path.gateway ?: "on-link"}, DNS ${path.dnsServers}")

        // Names the app itself looks up (the peer's) go to the physical resolvers.
        WindowsSocketProtector.install(path.address)
        DnsCache.setUnderlyingNetwork(WindowsUnderlyingNetwork(path.dnsServers.ifEmpty { FALLBACK_DNS }))
        DnsCache.setActiveProxyDomain(profile.peer.endpointHost)
        this.configuration = config

        // The socket is bound to the physical IPv4 address, so the peer must have one.
        if (profile.peer.endpointHost.contains(':')) {
            throw IOException("IPv6 WireGuard endpoints are not supported on Windows yet: ${profile.peer.endpointHost}")
        }
        val peerHosts = peerExclusions(profile, path)
        if (peerHosts.isEmpty() && !DnsCache.isIpAddress(profile.peer.endpointHost)) {
            throw IOException("Cannot resolve the WireGuard peer ${profile.peer.endpointHost} to an IPv4 address")
        }

        val created = WintunAdapter.create(dll, ADAPTER_NAME, TUNNEL_TYPE, ADAPTER_GUID)
        adapter = created
        val ifIndex = created.interfaceIndex()
        adapterIndex = ifIndex
        logger.info("Wintun adapter '$ADAPTER_NAME' is interface $ifIndex for WireGuard (driver ${WintunAdapter.runningDriverVersion(dll) ?: "?"})")

        routes.apply(
            TunNetConfig(
                interfaceIndex = ifIndex,
                dnsServers = profile.dnsServers,
                physicalInterfaceIndex = path.interfaceIndex,
                physicalGateway = path.gateway,
                excludedHosts = peerHosts,
                excludedNetworks = emptyList(),
                interfaceAddresses = profile.addresses,
                tunnelRoutes = profile.peer.allowedIps,
                mtu = profile.mtu
            )
        )

        stats.reset()
        val newSession = created.startSession()
        session = newSession
        val device = WintunPacketDevice(
            newSession,
            stats,
            dropIpv6 = !RoutePlan.carriesIpv6(profile.addresses, profile.peer.allowedIps)
        )
        wireGuardDevice = device
        val tunnel = WireGuardTunnel(
            profile,
            openSocket = { physicalSocket { physical?.address } },
            resolve = { host -> WindowsNet.resolveV4(host).firstOrNull() }
        )
        tunnel.onFailure = { reason ->
            logger.error("WireGuard peer not answering: $reason")
            _lastError.value = "WireGuard: $reason"
        }
        wireGuard = tunnel
        tunnel.start(device)

        val deadline = System.currentTimeMillis() + HANDSHAKE_WAIT_MS
        while (!tunnel.hasHandshake && System.currentTimeMillis() < deadline) Thread.sleep(100)
        if (!tunnel.hasHandshake) {
            throw IOException("The WireGuard peer ${profile.peer.endpointHost}:${profile.peer.endpointPort} did not answer the handshake in ${HANDSHAKE_WAIT_MS / 1000} s")
        }
        _lastError.value = null
        startPathWatcher(profile)
        logger.info("TUN up: ${config.name} (${if (profile.amnezia.isEnabled) "AmneziaWG" else "WireGuard"}), routes ${profile.peer.allowedIps}, DNS ${profile.dnsServers}")
    }

    /** The peer's IPv4 addresses that need a host route through the physical gateway. */
    private fun peerExclusions(profile: WireGuardConfig, path: PhysicalPath): List<String> =
        WindowsNet.resolveV4(profile.peer.endpointHost)
            .filterNot { ip -> runCatching { path.isOnLink(java.net.InetAddress.getByName(ip)) }.getOrDefault(false) }

    /**
     * Roaming: every two seconds, the physical path as it is now. When the
     * interface, gateway or address changed (another Wi-Fi, a cable, a new
     * DHCP lease), the peer's host route moves, sockets bind to the new
     * address, names resolve on the new network's DNS and the tunnel opens a
     * new socket and handshakes again. With no network at all it waits.
     */
    private fun startPathWatcher(profile: WireGuardConfig) {
        val watcher = Thread({
            while (!Thread.currentThread().isInterrupted) {
                try {
                    Thread.sleep(PATH_CHECK_MS)
                } catch (e: InterruptedException) {
                    return@Thread
                }
                val tunnel = wireGuard ?: return@Thread
                val current = physical ?: continue
                val now = runCatching { WindowsNet.physicalPathExcluding(adapterIndex) }.getOrNull() ?: continue
                val same = now.interfaceIndex == current.interfaceIndex && now.gateway == current.gateway &&
                    now.address == current.address
                if (same) continue
                synchronized(lock) {
                    if (Thread.currentThread().isInterrupted || wireGuard !== tunnel) return@Thread
                    logger.info("Network changed: interface ${now.interfaceIndex} at ${now.address.hostAddress} via ${now.gateway ?: "on-link"}")
                    physical = now
                    WindowsSocketProtector.install(now.address)
                    DnsCache.setUnderlyingNetwork(WindowsUnderlyingNetwork(now.dnsServers.ifEmpty { FALLBACK_DNS }))
                    routes.repointPhysical(now.interfaceIndex, now.gateway, peerExclusions(profile, now))
                    tunnel.handleNetworkPathChange("physical network changed")
                }
            }
        }, "wg-path-watch").apply { isDaemon = true }
        pathWatcher = watcher
        watcher.start()
    }

    private fun teardownLocked() {
        pathWatcher?.interrupt()
        pathWatcher = null
        // WireGuard first, while the session can still take its last packets.
        wireGuard?.let { runCatching { it.stop() }.onFailure { e -> logger.warning("WireGuard stop: ${e.message}") } }
        wireGuard = null
        wireGuardDevice?.close()
        wireGuardDevice = null
        readerRunning = false
        // Flows first, while the session can still carry their RSTs.
        stack?.let { s ->
            val done = CountDownLatch(1)
            try {
                s.stop { done.countDown() }
                if (!done.await(5, TimeUnit.SECONDS)) logger.warning("lwIP shutdown did not finish in time")
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            } catch (t: Throwable) {
                logger.warning("lwIP shutdown: ${t.message ?: t}")
            }
        }
        stack = null
        // The reader sees readerRunning within one read wait (250 ms) and
        // leaves; join it before the session goes, since WintunEndSession
        // frees the ring it reads. A reader still busy after the wait (stuck
        // handing a batch to the stack) is not inside the session: end()
        // waits for it to be out of the ring, and it then finds the session
        // ended and quits.
        reader?.let { r ->
            try {
                r.join(READER_JOIN_MS)
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
            }
            if (r.isAlive) logger.warning("Reader did not finish in ${READER_JOIN_MS} ms; ending the session under it")
        }
        reader = null
        session?.end()
        session = null
        adapter?.close()
        adapter = null
        runCatching { routes.restore() }.onFailure { logger.warning("Route restore: ${it.message}") }
        WindowsSocketProtector.clear()
        DnsCache.setUnderlyingNetwork(null)
        DnsCache.setActiveProxyDomain(null)
        configuration = null
        physical = null
        stats.connections.set(0)
        adapterIndex = 0
        logger.info("TUN down")
    }

    // ------------------------------------------------------------- helpers

    /** The proxy servers' IPv4 addresses (every chain hop too), which must stay off the tunnel. */
    private fun exclusionsFor(config: ProxyConfiguration): List<String> {
        val out = ArrayList<String>()
        fun collect(c: ProxyConfiguration) {
            out += WindowsNet.resolveV4(c.serverAddress)
            c.resolvedIP?.takeIf { !it.contains(':') }?.let(out::add)
            c.chain?.forEach(::collect)
        }
        collect(config)
        return out.distinct()
    }

    private fun tunSettings(settings: DesktopSettings, config: ProxyConfiguration?): TunSettings {
        val realNames = LinkedHashSet<String>()
        EncryptedDnsPolicy.upstream.bootstrapHost?.let { realNames += it.lowercase() }
        return TunSettings(
            ipv6Dns = false,
            blockQuic = true,
            encryptedDnsEnabled = settings.dohEnabled,
            realAnswerDomains = realNames
        )
    }

    private fun turkmenNetworks(): List<String> =
        com.mythaia.data.rules.CountryBypassExtras.rulesFor("TM")
            .filter { it.type == com.mythaia.data.model.DomainRuleType.IP_CIDR }
            .mapNotNull { RoutePlan.splitCidr(it.value)?.let { (net, prefix) -> "$net/$prefix" } }

    private val host = object : TunHost {
        override fun writePacket(packet: ByteArray, length: Int) {
            val s = session ?: return
            if (s.send(packet, length)) stats.down.addAndGet(length.toLong())
        }

        override fun route(host: String, port: Int, udp: Boolean): TunRoute =
            when (router.decide(host)) {
                RouteTarget.BLOCK -> TunRoute.Block
                RouteTarget.DIRECT -> TunRoute.Direct
                RouteTarget.PROXY -> configuration?.let { TunRoute.Proxy(it) } ?: TunRoute.Block
            }

        override fun onConnectionCount(count: Int) {
            stats.connections.set(count)
        }
    }

    companion object {
        const val ADAPTER_NAME = "Mythaia"
        private const val TUNNEL_TYPE = "Mythaia"
        /** Fixed so Windows keeps one network profile for the adapter across runs. */
        private const val ADAPTER_GUID = "{9E2F1A8C-4B6D-4C3E-9F0A-2D7B5C1E8A4F}"
        private val FALLBACK_DNS = listOf("1.1.1.1", "8.8.8.8")
        private const val READER_JOIN_MS = 2_000L
        /** A WireGuard start waits this long for the first handshake (three attempts). */
        private const val HANDSHAKE_WAIT_MS = 15_000L
        private const val PATH_CHECK_MS = 2_000L

        /** Whether this process may create the adapter. */
        fun isElevated(): Boolean = Elevation.isElevated()

        /**
         * Starts an elevated copy of the app with [args] (UAC prompt).
         * True once it is running; the caller then exits this instance.
         * False when declined or failed — [Elevation.lastError] has the reason.
         */
        fun relaunchElevated(args: List<String> = listOf("--tun")): Boolean = Elevation.relaunchElevated(args)

        /** Whether `wintun.dll` and the JNI library are both where the app can load them. */
        fun isAvailable(): Boolean = WindowsNet.isWindows && NativeBridge.isLoaded && AppPaths.wintunLibrary() != null

        /** The wintun.dll this run would load, or null. */
        fun wintunLibrary(): File? = AppPaths.wintunLibrary()

        /**
         * Removes routes a crashed run may have left; call once at startup.
         * Only with the rights to do it: a plain process would fail every
         * delete and then discard the snapshot an elevated start could act on.
         */
        fun cleanupLeftovers() {
            if (!WindowsNet.isWindows || !isElevated()) return
            WindowsRoutes(AppPaths.tunRouteSnapshot).cleanupLeftovers()
        }
    }
}
