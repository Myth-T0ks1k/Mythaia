package com.mythaia.desktop.tun

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.engine.Router
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.model.RouteTarget
import com.mythaia.vpn.NativeBridge
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
import java.util.concurrent.TimeUnit

/**
 * The all-traffic mode: a TUN interface takes the default route, its
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
 * What is system-specific — the interface, its routes and DNS, the rights
 * it takes — sits behind [platform]: Wintun on Windows, utun on macOS.
 * Needs an elevated process: see [isElevated] and [relaunchElevated].
 */
class TunEngine(val stats: TrafficStats, private val platform: TunPlatform = defaultPlatform()) {
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
    private var device: TunDevice? = null
    private var reader: Thread? = null
    private var physical: PhysicalPath? = null

    @Volatile
    private var readerRunning = false

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
                if (this.configuration?.id != configuration.id) switchTo(configuration)
                return
            }
            if (_status.value != Status.STOPPED) throw IOException("TUN engine is busy")
            _status.value = Status.STARTING
            _lastError.value = null
            try {
                startLocked(settings, configuration)
                _status.value = Status.RUNNING
            } catch (e: Exception) {
                val message = e.message ?: e.toString()
                logger.error("TUN start failed: $message")
                _lastError.value = message
                runCatching { teardownLocked() }
                _status.value = Status.STOPPED
                throw (e as? IOException) ?: IOException(message, e)
            }
        }
    }

    /** Changes the outbound; open flows are re-established through the new server. */
    fun switchTo(configuration: ProxyConfiguration) {
        synchronized(lock) {
            this.configuration = configuration
            DnsCache.setActiveProxyDomain(configuration.serverAddress)
            if (_status.value != Status.RUNNING) return
            for (ip in exclusionsFor(configuration)) platform.excludeHost(ip)
            stack?.updateSettings(tunSettings(settings, configuration))
            stack?.switchConfiguration(configuration)
            logger.info("Switched to ${configuration.name}")
        }
    }

    /** Tears everything down and restores the routes and DNS. Blocking, a few seconds at most. */
    fun stop() {
        synchronized(lock) {
            if (_status.value == Status.STOPPED) {
                platform.cleanupLeftovers()
                return
            }
            _status.value = Status.STOPPING
            try {
                teardownLocked()
            } finally {
                _status.value = Status.STOPPED
            }
        }
    }

    // ---------------------------------------------------------------- start

    private fun startLocked(settings: DesktopSettings, config: ProxyConfiguration) {
        platform.checkReady()

        platform.cleanupLeftovers()

        // Learn the physical path before the default route moves.
        val path = platform.physicalPath() ?: throw IOException("No default route: is the computer online?")
        physical = path
        logger.info("Physical interface ${path.label} at ${path.address.hostAddress} via ${path.gateway ?: "on-link"}, DNS ${path.dnsServers}")

        // The app's own traffic bypasses the tunnel from this point on:
        // sockets bind to the physical address and names resolve there.
        PhysicalSocketProtector.install(path.address)
        DnsCache.setUnderlyingNetwork(PhysicalUnderlyingNetwork(path.dnsServers.ifEmpty { FALLBACK_DNS }))
        DnsCache.setActiveProxyDomain(config.serverAddress)
        this.configuration = config

        val excluded = LinkedHashSet<String>()
        excluded += exclusionsFor(config)
        excluded += path.dnsServers
        excluded += FALLBACK_DNS
        EncryptedDnsPolicy.upstream.bootstrapHost?.let { excluded += PhysicalNet.resolveV4(it) }
        excluded.removeAll { ip -> runCatching { path.isOnLink(java.net.InetAddress.getByName(ip)) }.getOrDefault(false) }

        val created = platform.openDevice()
        device = created

        val networks = ArrayList(TunNetConfig.PRIVATE_NETWORKS)
        if (settings.bypassTurkmenistan) networks += turkmenNetworks()
        platform.configure(created, path, excluded.toList(), networks)

        val newStack = TunStack(host)
        stack = newStack
        stats.reset()
        newStack.start(config, tunSettings(settings, config))

        created.start()
        readerRunning = true
        reader = Thread({
            created.readLoop(keepRunning = { readerRunning }) { batch ->
                var bytes = 0L
                for (p in batch) bytes += p.size
                stats.up.addAndGet(bytes)
                newStack.input(batch)
            }
            logger.debug("Reader finished")
        }, "tun-reader").apply { isDaemon = true }
        reader?.start()
        logger.info("TUN up on ${created.name}: ${config.name} (${config.outboundProtocol.displayName}), mode=${if (settings.isGlobal) "global" else "rule"}")
    }

    private fun teardownLocked() {
        readerRunning = false
        // Flows first, while the session can still carry their RSTs.
        stack?.let { s ->
            val done = CountDownLatch(1)
            s.stop { done.countDown() }
            if (!done.await(5, TimeUnit.SECONDS)) logger.warning("lwIP shutdown did not finish in time")
        }
        stack = null
        device?.stop()
        reader?.let { runCatching { it.join(2000) } }
        reader = null
        device?.close()
        device = null
        runCatching { platform.restore() }.onFailure { logger.warning("Route restore: ${it.message}") }
        PhysicalSocketProtector.clear()
        DnsCache.setUnderlyingNetwork(null)
        DnsCache.setActiveProxyDomain(null)
        configuration = null
        physical = null
        stats.connections.set(0)
        logger.info("TUN down")
    }

    // ------------------------------------------------------------- helpers

    /** The proxy servers' IPv4 addresses (every chain hop too), which must stay off the tunnel. */
    private fun exclusionsFor(config: ProxyConfiguration): List<String> {
        val out = ArrayList<String>()
        fun collect(c: ProxyConfiguration) {
            out += PhysicalNet.resolveV4(c.serverAddress)
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
            val d = device ?: return
            if (d.send(packet, length)) stats.down.addAndGet(length.toLong())
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
        const val ADAPTER_NAME = WindowsTunPlatform.ADAPTER_NAME
        private val FALLBACK_DNS = listOf("1.1.1.1", "8.8.8.8")

        /** The system side for the system this runs on. */
        fun defaultPlatform(): TunPlatform = WindowsTunPlatform(AppPaths.tunRouteSnapshot)

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
