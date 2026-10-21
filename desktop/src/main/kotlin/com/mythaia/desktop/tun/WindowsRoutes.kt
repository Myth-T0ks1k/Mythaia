package com.mythaia.desktop.tun

import com.mythaia.vpn.util.Cidr
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * How the TUN adapter is to be addressed and what must stay off it.
 *
 * [address]/[prefixLength] is the adapter's own IPv4 address, [gateway] the
 * on-link next hop the default routes point at (any address in the subnet
 * works: Wintun has no link layer, so nothing is ever ARPed). [dnsServers]
 * are handed to Windows as the adapter's resolvers; every query to them is
 * intercepted by the stack, so which addresses they are hardly matters —
 * public ones let a query the stack declines still reach a real resolver
 * through the tunnel.
 */
data class TunNetConfig(
    val interfaceIndex: Int,
    val address: String = "10.8.0.2",
    val prefixLength: Int = 24,
    val gateway: String = "10.8.0.1",
    val dnsServers: List<String> = listOf("1.1.1.1", "1.0.0.1"),
    val interfaceMetric: Int = 1,
    /** Null leaves IPv6 alone (and leaking); otherwise ::/1 and 8000::/1 are routed into the adapter. */
    val ipv6Address: String? = DEFAULT_IPV6_ADDRESS,
    val ipv6PrefixLength: Int = 64,
    val physicalInterfaceIndex: Int,
    /** Null when the physical interface has no gateway; exclusions then rely on on-link routes and socket binding. */
    val physicalGateway: String?,
    /** IPv4 hosts that must keep going out the physical interface: proxy servers, DNS resolvers. */
    val excludedHosts: List<String> = emptyList(),
    /** IPv4 networks (`a.b.c.d/n`) that stay on the physical interface: private ranges, country bypass. */
    val excludedNetworks: List<String> = PRIVATE_NETWORKS,
    /**
     * WireGuard: the profile's own addresses (`a.b.c.d/n`, IPv6 too), in
     * place of [address], [prefixLength], [gateway] and [ipv6Address]; its
     * [dnsServers] may then be of either family. Null for the lwIP tunnel.
     */
    val interfaceAddresses: List<String>? = null,
    /** WireGuard: the peer's AllowedIPs, routed on-link into the adapter instead of everything. */
    val tunnelRoutes: List<String> = emptyList(),
    /** WireGuard: the profile's MTU; null leaves the adapter's. */
    val mtu: Int? = null
) {
    /** Whether this is a WireGuard interface, laid out from the profile rather than the fixed plan. */
    val isLayer3: Boolean get() = interfaceAddresses != null

    companion object {
        const val DEFAULT_IPV6_ADDRESS = "fd00:6d79:7468::2"
        /** RFC 1918, link-local, carrier NAT: a proxy cannot reach these, so they never enter the tunnel. */
        val PRIVATE_NETWORKS = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")
    }
}

/** One command line, and whether its failure aborts the setup. */
data class NetCommand(val argv: List<String>, val essential: Boolean = true) {
    override fun toString(): String = argv.joinToString(" ")
}

/**
 * One route the crash-recovery snapshot remembers — data, never a command.
 * The service acts on the snapshot as SYSTEM out of ProgramData, which any
 * local user could write to before the service first locked it down, so the
 * file must not be able to say anything but "delete this route": the argv is
 * rebuilt from a fixed template by [deleteCommand] and every field is checked
 * by [WindowsRoutes.parseSnapshot] before it gets that far.
 */
@Serializable
data class RouteEntry(
    /** [IPV4]: a `route delete`; [IPV6]: a `netsh interface ipv6 delete route`. */
    val kind: String,
    val destination: String,
    val prefix: Int,
    /** The next hop; IPv4 routes only, an IPv6 route is on-link. */
    val gateway: String? = null,
    val interfaceIndex: Int
) {
    /** The command that deletes this route. argv[0] is a literal here, never from the data. */
    fun deleteCommand(): NetCommand = NetCommand(
        when (kind) {
            IPV6 -> listOf("netsh", "interface", "ipv6", "delete", "route", "$destination/$prefix", "interface=$interfaceIndex", "store=active")
            else -> listOf("route", "delete", destination, "mask", RoutePlan.maskOf(prefix), gateway ?: "", "if", interfaceIndex.toString())
        },
        essential = false
    )

    companion object {
        const val IPV4 = "route"
        const val IPV6 = "route6"

        fun v4(destination: String, prefix: Int, gateway: String, interfaceIndex: Int) =
            RouteEntry(IPV4, destination, prefix, gateway, interfaceIndex)

        fun v6(destination: String, prefix: Int, interfaceIndex: Int) =
            RouteEntry(IPV6, destination, prefix, null, interfaceIndex)
    }
}

/**
 * Turns a [TunNetConfig] into the `netsh` and `route` commands that apply
 * it and the ones that undo it. Pure: nothing here touches the system, so
 * the exact command lines are unit-tested.
 *
 * The default route is taken over with two /1 routes rather than by
 * replacing 0.0.0.0/0: they are more specific than the physical default,
 * which stays in place untouched, and removing the adapter removes them.
 * What has to be undone explicitly is the physical-side part — host and
 * network routes through the original gateway — which is why those come
 * back separately from [teardown].
 */
object RoutePlan {

    fun setup(c: TunNetConfig): List<NetCommand> {
        if (c.isLayer3) return layer3Setup(c)
        val idx = c.interfaceIndex.toString()
        val out = ArrayList<NetCommand>()
        out += NetCommand(listOf(
            "netsh", "interface", "ipv4", "set", "address", "name=$idx", "source=static",
            "address=${c.address}", "mask=${maskOf(c.prefixLength)}", "store=active"
        ))
        c.dnsServers.forEachIndexed { i, server ->
            out += if (i == 0) NetCommand(listOf(
                "netsh", "interface", "ipv4", "set", "dnsservers", "name=$idx", "source=static",
                "address=$server", "register=none", "validate=no"
            ), essential = false)
            else NetCommand(listOf(
                "netsh", "interface", "ipv4", "add", "dnsservers", "name=$idx", "address=$server", "index=${i + 1}", "validate=no"
            ), essential = false)
        }
        out += NetCommand(listOf(
            "netsh", "interface", "ipv4", "set", "interface", "interface=$idx", "metric=${c.interfaceMetric}", "store=active"
        ), essential = false)

        // Everything in, through the adapter.
        out += NetCommand(routeAdd("0.0.0.0", "128.0.0.0", c.gateway, c.interfaceIndex))
        out += NetCommand(routeAdd("128.0.0.0", "128.0.0.0", c.gateway, c.interfaceIndex))

        // ...except what stays on the physical interface.
        out += physicalSide(c).map { NetCommand(it, essential = false) }

        c.ipv6Address?.let { v6 ->
            out += NetCommand(listOf(
                "netsh", "interface", "ipv6", "add", "address", "interface=$idx", "address=$v6/${c.ipv6PrefixLength}", "store=active"
            ), essential = false)
            out += NetCommand(listOf(
                "netsh", "interface", "ipv6", "set", "interface", "interface=$idx", "metric=${c.interfaceMetric}", "store=active"
            ), essential = false)
            for (prefix in listOf("::/1", "8000::/1")) {
                out += NetCommand(listOf(
                    "netsh", "interface", "ipv6", "add", "route", prefix, "interface=$idx", "metric=${c.interfaceMetric}", "store=active"
                ), essential = false)
            }
        }
        return out
    }

    /**
     * A WireGuard interface: the profile's addresses, DNS and MTU on the
     * adapter, and only the peer's AllowedIPs routed into it, on-link (a
     * point-to-point interface has no next hop). `0.0.0.0/0` and `::/0` go
     * in as two halves, like the lwIP plan's default, so the physical
     * default route stays as it was. Nothing stays out but [TunNetConfig.excludedHosts]
     * (the peer itself) and [TunNetConfig.excludedNetworks]: AllowedIPs is
     * the profile's own word on what the tunnel carries, and the physical
     * network's on-link routes are more specific than any half anyway.
     * IPv6 routes are added only with an IPv6 address to send them from.
     */
    private fun layer3Setup(c: TunNetConfig): List<NetCommand> {
        val idx = c.interfaceIndex.toString()
        val out = ArrayList<NetCommand>()
        val entries = c.interfaceAddresses.orEmpty().mapNotNull { Cidr.split(it) }
        val v4 = entries.filter { !it.address.contains(':') }
        val v6 = entries.filter { it.address.contains(':') }
        val v4Routes = layer3Routes(c.tunnelRoutes, v6 = false)
        val v6Routes = if (v6.isNotEmpty()) layer3Routes(c.tunnelRoutes, v6 = true) else emptyList()
        val carriesV6 = v6.isNotEmpty() && v6Routes.isNotEmpty()
        val v4Full = "0.0.0.0/1" in v4Routes && "128.0.0.0/1" in v4Routes
        val v6Full = "::/1" in v6Routes && "8000::/1" in v6Routes
        // A full-tunnel IPv4 profile without an IPv6 default route would leave
        // IPv6 escaping on the physical interface; give the adapter the ULA
        // sinkhole address and route ::/1 + 8000::/1 into it, where
        // WintunPacketDevice drops the packets when the peer carries no IPv6.
        val blockIpv6 = v4Full && !v6Full
        val sinkholeV6 = c.ipv6Address ?: TunNetConfig.DEFAULT_IPV6_ADDRESS

        v4.forEachIndexed { i, a ->
            out += NetCommand(
                if (i == 0) listOf("netsh", "interface", "ipv4", "set", "address", "name=$idx", "source=static",
                    "address=${a.address}", "mask=${maskOf(a.prefix)}", "store=active")
                else listOf("netsh", "interface", "ipv4", "add", "address", "name=$idx",
                    "address=${a.address}", "mask=${maskOf(a.prefix)}", "store=active")
            )
        }
        v6.forEach { a ->
            out += NetCommand(listOf(
                "netsh", "interface", "ipv6", "add", "address", "interface=$idx", "address=${a.address}/${a.prefix}", "store=active"
            ), essential = v4.isEmpty())
        }
        if (v6.isEmpty() && blockIpv6) {
            out += NetCommand(listOf(
                "netsh", "interface", "ipv6", "add", "address", "interface=$idx", "address=$sinkholeV6/${c.ipv6PrefixLength}", "store=active"
            ), essential = false)
        }

        val dns = c.dnsServers.map { it.trim() }.filter { com.mythaia.vpn.util.DnsCache.isIpAddress(it) }
        val dns4 = dns.filter { !it.contains(':') }
        val dns6 = dns.filter { it.contains(':') }
        out += dnsCommands("ipv4", idx, dns4)
        if (carriesV6) out += dnsCommands("ipv6", idx, dns6)

        val hasV6OnInterface = v6.isNotEmpty() || blockIpv6
        out += NetCommand(listOf(
            "netsh", "interface", "ipv4", "set", "interface", "interface=$idx", "metric=${c.interfaceMetric}", "store=active"
        ), essential = false)
        if (hasV6OnInterface) out += NetCommand(listOf(
            "netsh", "interface", "ipv6", "set", "interface", "interface=$idx", "metric=${c.interfaceMetric}", "store=active"
        ), essential = false)
        c.mtu?.let { mtu ->
            out += NetCommand(listOf("netsh", "interface", "ipv4", "set", "subinterface", idx, "mtu=$mtu", "store=active"), essential = false)
            // IPv6 needs at least 1280.
            if (carriesV6 && mtu >= 1280) {
                out += NetCommand(listOf("netsh", "interface", "ipv6", "set", "subinterface", idx, "mtu=$mtu", "store=active"), essential = false)
            }
        }

        for (route in v4Routes) {
            out += NetCommand(listOf(
                "netsh", "interface", "ipv4", "add", "route", "prefix=$route", "interface=$idx", "nexthop=0.0.0.0", "metric=0", "store=active"
            ))
        }
        val effectiveV6Routes = if (blockIpv6) (v6Routes + listOf("::/1", "8000::/1")).distinct() else v6Routes
        for (route in effectiveV6Routes) {
            out += NetCommand(listOf(
                "netsh", "interface", "ipv6", "add", "route", "prefix=$route", "interface=$idx", "metric=0", "store=active"
            ), essential = false)
        }

        out += physicalSide(c).map { NetCommand(it, essential = false) }
        return out
    }

    /** Whether a layer-3 profile has both an IPv6 address on the adapter and an IPv6 route into the peer. */
    fun carriesIpv6(interfaceAddresses: List<String>?, tunnelRoutes: List<String>): Boolean {
        val hasV6Address = interfaceAddresses.orEmpty().any { Cidr.split(it)?.address?.contains(':') == true }
        return hasV6Address && layer3Routes(tunnelRoutes, v6 = true).isNotEmpty()
    }

    /**
     * AllowedIPs of one family as `network/prefix`: host bits cleared (wg-quick
     * takes `10.0.0.2/24` to mean the subnet), each once, a whole-family
     * default as its two halves.
     */
    fun layer3Routes(allowed: List<String>, v6: Boolean): List<String> {
        val out = LinkedHashSet<String>()
        for (entry in allowed) {
            val (address, prefix) = Cidr.split(entry) ?: continue
            if (address.contains(':') != v6) continue
            if (prefix == 0) {
                if (v6) { out += "::/1"; out += "8000::/1" } else { out += "0.0.0.0/1"; out += "128.0.0.0/1" }
                continue
            }
            val network = Cidr.networkOf(address, prefix) ?: continue
            out += "$network/$prefix"
        }
        return out.toList()
    }

    private fun dnsCommands(family: String, idx: String, servers: List<String>): List<NetCommand> =
        servers.mapIndexed { i, server ->
            if (i == 0) NetCommand(listOf(
                "netsh", "interface", family, "set", "dnsservers", "name=$idx", "source=static",
                "address=$server", "register=none", "validate=no"
            ), essential = false)
            else NetCommand(listOf(
                "netsh", "interface", family, "add", "dnsservers", "name=$idx", "address=$server", "index=${i + 1}", "validate=no"
            ), essential = false)
        }

    /** The routes that outlive the adapter and so must be deleted by hand, plus the adapter's own for tidiness. */
    fun teardown(c: TunNetConfig): List<NetCommand> = teardownEntries(c).map { it.deleteCommand() }

    /**
     * [teardown] as data, for the snapshot a crash leaves behind. The
     * adapter's own routes — the IPv4 halves and the IPv6 ::/1 and 8000::/1
     * — are in it too: they go with the adapter, but an adapter a dead
     * process left behind is exactly what the next start finds.
     */
    fun teardownEntries(c: TunNetConfig): List<RouteEntry> {
        // A WireGuard adapter's own routes are on-link and go with it; the
        // leftover adapter of a dead run is replaced, with them, on the next start.
        if (c.isLayer3) return physicalSideTeardown(c)
        val out = ArrayList<RouteEntry>()
        out += RouteEntry.v4("0.0.0.0", 1, c.gateway, c.interfaceIndex)
        out += RouteEntry.v4("128.0.0.0", 1, c.gateway, c.interfaceIndex)
        out += physicalSideTeardown(c)
        if (c.ipv6Address != null) {
            out += RouteEntry.v6("::", 1, c.interfaceIndex)
            out += RouteEntry.v6("8000::", 1, c.interfaceIndex)
        }
        return out
    }

    /** The physical-side routes alone, for moving them to another network ([WindowsRoutes.repointPhysical]). */
    fun physicalSideCommands(c: TunNetConfig): List<NetCommand> = physicalSide(c).map { NetCommand(it, essential = false) }

    /** The commands that keep one more host on the physical side, added while running. */
    fun excludeHost(c: TunNetConfig, ip: String): NetCommand? {
        if (ip.contains(':')) return null
        val gw = c.physicalGateway ?: return null
        return NetCommand(routeAdd(ip, "255.255.255.255", gw, c.physicalInterfaceIndex), essential = false)
    }

    fun includeHost(c: TunNetConfig, ip: String): NetCommand? = includeHostEntry(c, ip)?.deleteCommand()

    fun includeHostEntry(c: TunNetConfig, ip: String): RouteEntry? {
        if (ip.contains(':')) return null
        val gw = c.physicalGateway ?: return null
        return RouteEntry.v4(ip, 32, gw, c.physicalInterfaceIndex)
    }

    private fun physicalSide(c: TunNetConfig): List<List<String>> {
        val gw = c.physicalGateway ?: return emptyList()
        val out = ArrayList<List<String>>()
        for (network in c.excludedNetworks) {
            val (net, prefix) = splitCidr(network) ?: continue
            out += routeAdd(net, maskOf(prefix), gw, c.physicalInterfaceIndex)
        }
        for (host in c.excludedHosts.distinct()) {
            if (!host.contains(':')) out += routeAdd(host, "255.255.255.255", gw, c.physicalInterfaceIndex)
        }
        return out
    }

    private fun physicalSideTeardown(c: TunNetConfig): List<RouteEntry> {
        val gw = c.physicalGateway ?: return emptyList()
        val out = ArrayList<RouteEntry>()
        for (host in c.excludedHosts.distinct()) {
            if (!host.contains(':')) out += RouteEntry.v4(host, 32, gw, c.physicalInterfaceIndex)
        }
        for (network in c.excludedNetworks) {
            val (net, prefix) = splitCidr(network) ?: continue
            out += RouteEntry.v4(net, prefix, gw, c.physicalInterfaceIndex)
        }
        return out
    }

    private fun routeAdd(dest: String, mask: String, gateway: String, ifIndex: Int) =
        listOf("route", "add", dest, "mask", mask, gateway, "metric", "1", "if", ifIndex.toString())

    /** `a.b.c.d/n` → (`a.b.c.d`, n); null for anything else. */
    fun splitCidr(text: String): Pair<String, Int>? {
        val parts = text.trim().split('/')
        if (parts.size != 2) return null
        val prefix = parts[1].toIntOrNull() ?: return null
        if (prefix !in 0..32 || !parts[0].matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) return null
        return parts[0] to prefix
    }

    /** The dotted mask of an IPv4 prefix length. */
    fun maskOf(prefix: Int): String {
        require(prefix in 0..32) { "prefix $prefix" }
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return "${(mask shr 24) and 0xFF}.${(mask shr 16) and 0xFF}.${(mask shr 8) and 0xFF}.${mask and 0xFF}"
    }
}

/**
 * Applies a [RoutePlan] to the running system and remembers, on disk, what
 * has to be undone — so a crash leaves nothing behind that the next start
 * cannot clean up.
 */
class WindowsRoutes(
    private val snapshot: File,
    private val runCommand: (List<String>) -> WindowsNet.Result = { WindowsNet.run(it) },
    private val ownerSid: (File) -> String? = { if (WindowsNet.isWindows) WindowsNet.fileOwnerSid(it) else null },
    private val retryDelayMs: Long = 400L
) {
    private val logger = MythaiaLogger("Routes")

    /** `version` defaults to nothing so a file from an older format, which held command lines, is rejected. */
    @Serializable
    private data class Snapshot(val version: Int = 0, val routes: List<RouteEntry> = emptyList())

    /** What is currently applied; null when nothing is. */
    @Volatile
    var applied: TunNetConfig? = null
        private set

    private val extraHosts = LinkedHashSet<String>()

    /** Runs the setup; an essential command failing rolls back and throws. */
    @Throws(IOException::class)
    fun apply(config: TunNetConfig) {
        val plan = RoutePlan.setup(config)
        // Everything that survives the adapter is written down before it is done.
        writeSnapshot(RoutePlan.teardownEntries(config))
        for (command in plan) {
            val result = runWithRetry(command)
            if (!result.ok) {
                val text = "${command.argv.take(4).joinToString(" ")}: ${result.output.lineSequence().firstOrNull { it.isNotBlank() } ?: "exit ${result.exitCode}"}"
                if (command.essential) {
                    logger.error("Failed: $text")
                    applied = config
                    restore()
                    throw IOException("Network setup failed: $text")
                }
                logger.warning("Ignored: $text")
            }
        }
        applied = config
        logger.info("Routes installed on interface ${config.interfaceIndex} (physical ${config.physicalInterfaceIndex} via ${config.physicalGateway ?: "on-link"})")
    }

    /** Keeps [ip] on the physical side from now on (a newly selected proxy server, say). */
    fun excludeHost(ip: String) {
        val config = applied ?: return
        if (ip in config.excludedHosts || ip in extraHosts) return
        val command = RoutePlan.excludeHost(config, ip) ?: return
        extraHosts.add(ip)
        val result = runCommand(command.argv)
        if (!result.ok) logger.warning("Could not exclude $ip: ${result.output.lineSequence().firstOrNull()}")
        writeSnapshot(currentTeardown(config))
    }

    /**
     * The physical network changed under a running tunnel (another Wi-Fi,
     * a cable plugged in): the routes that keep hosts off the tunnel move to
     * [interfaceIndex] and [gateway]. Returns false when nothing is applied.
     */
    fun repointPhysical(interfaceIndex: Int, gateway: String?, excludedHosts: List<String>): Boolean {
        val old = applied ?: return false
        for (command in currentTeardown(old).filter { it.interfaceIndex == old.physicalInterfaceIndex }.map { it.deleteCommand() }) {
            runCommand(command.argv)
        }
        extraHosts.clear()
        val moved = old.copy(physicalInterfaceIndex = interfaceIndex, physicalGateway = gateway, excludedHosts = excludedHosts)
        writeSnapshot(RoutePlan.teardownEntries(moved))
        for (command in RoutePlan.physicalSideCommands(moved)) {
            val result = runCommand(command.argv)
            if (!result.ok) logger.warning("Route on the new network refused: ${command.argv.take(3).joinToString(" ")}: ${result.output.lineSequence().firstOrNull()}")
        }
        applied = moved
        logger.info("Routes moved to interface $interfaceIndex via ${gateway ?: "on-link"}")
        return true
    }

    /** Undoes [apply]. Safe to call twice. */
    fun restore() {
        val config = applied ?: run {
            snapshot.delete()
            return
        }
        for (command in currentTeardown(config).map { it.deleteCommand() }) {
            val result = runCommand(command.argv)
            if (!result.ok) logger.debug("Teardown (ignored): $command -> ${result.output.lineSequence().firstOrNull()}")
        }
        extraHosts.clear()
        applied = null
        snapshot.delete()
        logger.info("Routes removed")
    }

    /**
     * Deletes what a previous run left in the routing table, if its snapshot
     * is still there. The snapshot is only believed when it was written by
     * SYSTEM, an administrator or the account this process runs as — in
     * ProgramData that means the service itself — and when every entry in it
     * validates; anything else is discarded unread.
     */
    fun cleanupLeftovers() {
        if (!snapshot.isFile) return
        val owner = ownerSid(snapshot)
        val trusted = !WindowsNet.isWindows || (owner != null && (owner in TRUSTED_OWNERS || owner == WindowsNet.currentUserSid))
        val routes = if (trusted) parseSnapshot(runCatching { snapshot.readText() }.getOrNull()) else null
        when {
            !trusted -> logger.warning("Ignoring the route snapshot: written by ${owner ?: "an unknown account"}")
            routes == null -> logger.warning("Ignoring the route snapshot: not in this version's format")
            else -> {
                logger.info("Removing ${routes.size} routes left by a previous run")
                for (route in routes) runCommand(route.deleteCommand().argv)
            }
        }
        snapshot.delete()
    }

    private fun currentTeardown(config: TunNetConfig): List<RouteEntry> {
        val extras = extraHosts.mapNotNull { RoutePlan.includeHostEntry(config, it) }
        return extras + RoutePlan.teardownEntries(config)
    }

    private fun writeSnapshot(routes: List<RouteEntry>) {
        runCatching { snapshot.writeText(encodeSnapshot(routes)) }
            .onFailure { logger.warning("Could not write the route snapshot: ${it.message}") }
    }

    companion object {
        const val SNAPSHOT_VERSION = 2
        private val json = Json { ignoreUnknownKeys = true }

        /** SYSTEM and BUILTIN\Administrators; SIDs because the names are localised. */
        private val TRUSTED_OWNERS = setOf("S-1-5-18", "S-1-5-32-544")

        private val ipv4Form = Regex("""(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}""")
        private val ipv6Form = Regex("""[0-9A-Fa-f:]{2,39}""")

        internal fun encodeSnapshot(routes: List<RouteEntry>): String =
            json.encodeToString(Snapshot.serializer(), Snapshot(SNAPSHOT_VERSION, routes))

        /**
         * The routes in a snapshot [text], or null when anything about it is
         * not what this version writes: wrong version, unknown kind, an
         * address that is not a literal of the right family, a prefix or
         * interface index out of range. One bad entry rejects the file.
         */
        internal fun parseSnapshot(text: String?): List<RouteEntry>? {
            if (text == null) return null
            val snapshot = runCatching { json.decodeFromString(Snapshot.serializer(), text) }.getOrNull() ?: return null
            if (snapshot.version != SNAPSHOT_VERSION) return null
            return snapshot.routes.map { validated(it) ?: return null }
        }

        private fun validated(e: RouteEntry): RouteEntry? {
            if (e.interfaceIndex <= 0) return null
            return when (e.kind) {
                RouteEntry.IPV4 -> {
                    if (e.prefix !in 0..32) return null
                    val destination = ipv4Literal(e.destination) ?: return null
                    val gateway = ipv4Literal(e.gateway ?: return null) ?: return null
                    RouteEntry.v4(destination, e.prefix, gateway, e.interfaceIndex)
                }
                RouteEntry.IPV6 -> {
                    if (e.prefix !in 0..128 || e.gateway != null) return null
                    RouteEntry.v6(ipv6Literal(e.destination) ?: return null, e.prefix, e.interfaceIndex)
                }
                else -> null
            }
        }

        /** [text] as a dotted IPv4 address, or null. The regex comes first so InetAddress never resolves a name. */
        private fun ipv4Literal(text: String): String? {
            if (!ipv4Form.matches(text)) return null
            return (runCatching { InetAddress.getByName(text) }.getOrNull() as? Inet4Address)?.hostAddress
        }

        /** [text] as an IPv6 address, or null; hex and colons only, so it is safe as an argument once it parses. */
        private fun ipv6Literal(text: String): String? {
            if (!ipv6Form.matches(text) || !text.contains(':')) return null
            if (runCatching { InetAddress.getByName(text) }.getOrNull() !is Inet6Address) return null
            return text.lowercase()
        }
    }

    /** A freshly created adapter is not always addressable at once; the essentials get a few tries. */
    private fun runWithRetry(command: NetCommand): WindowsNet.Result {
        var result = runCommand(command.argv)
        var attempt = 0
        while (!result.ok && command.essential && attempt < 5) {
            attempt++
            if (retryDelayMs > 0) Thread.sleep(retryDelayMs)
            result = runCommand(command.argv)
        }
        return result
    }
}
