package com.mythaia.desktop.tun

import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
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
    val ipv6Address: String? = "fd00:6d79:7468::2",
    val ipv6PrefixLength: Int = 64,
    val physicalInterfaceIndex: Int,
    /** Null when the physical interface has no gateway; exclusions then rely on on-link routes and socket binding. */
    val physicalGateway: String?,
    /** IPv4 hosts that must keep going out the physical interface: proxy servers, DNS resolvers. */
    val excludedHosts: List<String> = emptyList(),
    /** IPv4 networks (`a.b.c.d/n`) that stay on the physical interface: private ranges, country bypass. */
    val excludedNetworks: List<String> = PRIVATE_NETWORKS
) {
    companion object {
        /** RFC 1918, link-local, carrier NAT: a proxy cannot reach these, so they never enter the tunnel. */
        val PRIVATE_NETWORKS = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10")
    }
}

/** One command line, and whether its failure aborts the setup. */
data class NetCommand(val argv: List<String>, val essential: Boolean = true) {
    override fun toString(): String = argv.joinToString(" ")
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

    /** The routes that outlive the adapter and so must be deleted by hand, plus the adapter's own for tidiness. */
    fun teardown(c: TunNetConfig): List<NetCommand> {
        val out = ArrayList<NetCommand>()
        out += NetCommand(routeDelete("0.0.0.0", "128.0.0.0", c.gateway, c.interfaceIndex), essential = false)
        out += NetCommand(routeDelete("128.0.0.0", "128.0.0.0", c.gateway, c.interfaceIndex), essential = false)
        out += physicalSideTeardown(c).map { NetCommand(it, essential = false) }
        return out
    }

    /** The commands that keep one more host on the physical side, added while running. */
    fun excludeHost(c: TunNetConfig, ip: String): NetCommand? {
        val gw = c.physicalGateway ?: return null
        return NetCommand(routeAdd(ip, "255.255.255.255", gw, c.physicalInterfaceIndex), essential = false)
    }

    fun includeHost(c: TunNetConfig, ip: String): NetCommand? {
        val gw = c.physicalGateway ?: return null
        return NetCommand(routeDelete(ip, "255.255.255.255", gw, c.physicalInterfaceIndex), essential = false)
    }

    private fun physicalSide(c: TunNetConfig): List<List<String>> {
        val gw = c.physicalGateway ?: return emptyList()
        val out = ArrayList<List<String>>()
        for (network in c.excludedNetworks) {
            val (net, prefix) = splitCidr(network) ?: continue
            out += routeAdd(net, maskOf(prefix), gw, c.physicalInterfaceIndex)
        }
        for (host in c.excludedHosts.distinct()) out += routeAdd(host, "255.255.255.255", gw, c.physicalInterfaceIndex)
        return out
    }

    private fun physicalSideTeardown(c: TunNetConfig): List<List<String>> {
        val gw = c.physicalGateway ?: return emptyList()
        val out = ArrayList<List<String>>()
        for (host in c.excludedHosts.distinct()) out += routeDelete(host, "255.255.255.255", gw, c.physicalInterfaceIndex)
        for (network in c.excludedNetworks) {
            val (net, prefix) = splitCidr(network) ?: continue
            out += routeDelete(net, maskOf(prefix), gw, c.physicalInterfaceIndex)
        }
        return out
    }

    private fun routeAdd(dest: String, mask: String, gateway: String, ifIndex: Int) =
        listOf("route", "add", dest, "mask", mask, gateway, "metric", "1", "if", ifIndex.toString())

    private fun routeDelete(dest: String, mask: String, gateway: String, ifIndex: Int) =
        listOf("route", "delete", dest, "mask", mask, gateway, "if", ifIndex.toString())

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
class WindowsRoutes(private val snapshot: File) {
    private val logger = MythaiaLogger("Routes")
    private val json = Json { ignoreUnknownKeys = true }

    @Serializable
    private data class Snapshot(val teardown: List<List<String>>)

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
        writeSnapshot(RoutePlan.teardown(config).map { it.argv })
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
        if (ip in config.excludedHosts || !extraHosts.add(ip)) return
        val command = RoutePlan.excludeHost(config, ip) ?: return
        val result = WindowsNet.run(command.argv)
        if (!result.ok) logger.warning("Could not exclude $ip: ${result.output.lineSequence().firstOrNull()}")
        writeSnapshot(currentTeardown(config).map { it.argv })
    }

    /** Undoes [apply]. Safe to call twice. */
    fun restore() {
        val config = applied ?: run {
            snapshot.delete()
            return
        }
        for (command in currentTeardown(config)) {
            val result = WindowsNet.run(command.argv)
            if (!result.ok) logger.debug("Teardown (ignored): $command -> ${result.output.lineSequence().firstOrNull()}")
        }
        extraHosts.clear()
        applied = null
        snapshot.delete()
        logger.info("Routes removed")
    }

    /** Deletes what a previous run left in the routing table, if its snapshot is still there. */
    fun cleanupLeftovers() {
        if (!snapshot.isFile) return
        val commands = runCatching { json.decodeFromString(Snapshot.serializer(), snapshot.readText()).teardown }.getOrNull()
        if (commands != null) {
            logger.info("Removing ${commands.size} routes left by a previous run")
            for (argv in commands) WindowsNet.run(argv)
        }
        snapshot.delete()
    }

    private fun currentTeardown(config: TunNetConfig): List<NetCommand> {
        val extras = extraHosts.mapNotNull { RoutePlan.includeHost(config, it) }
        return extras + RoutePlan.teardown(config)
    }

    private fun writeSnapshot(commands: List<List<String>>) {
        runCatching { snapshot.writeText(json.encodeToString(Snapshot.serializer(), Snapshot(commands))) }
            .onFailure { logger.warning("Could not write the route snapshot: ${it.message}") }
    }

    /** A freshly created adapter is not always addressable at once; the essentials get a few tries. */
    private fun runWithRetry(command: NetCommand): WindowsNet.Result {
        var result = WindowsNet.run(command.argv)
        var attempt = 0
        while (!result.ok && command.essential && attempt < 5) {
            attempt++
            Thread.sleep(400)
            result = WindowsNet.run(command.argv)
        }
        return result
    }
}
