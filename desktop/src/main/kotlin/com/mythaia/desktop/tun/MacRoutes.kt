package com.mythaia.desktop.tun

import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.TunnelConstants
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * How the utun is to be addressed on macOS and what goes through it.
 *
 * The utun is point-to-point and has no link layer, so [address] and
 * [peer] only have to be distinct and unused: they sit at the top of the
 * benchmark range 198.18.0.0/15, which no LAN uses, above the fake-IP pool
 * (198.18.0.1 to 198.18.64.0) — the pool's first address must stay
 * routable into the tunnel, not be the interface's own.
 */
data class MacNetConfig(
    /** The utun's name, `utun5`. */
    val interfaceName: String,
    val address: String = ADDRESS,
    val peer: String = PEER,
    val mtu: Int = 1500,
    /** Null leaves IPv6 alone (there is no IPv6 default route to take); otherwise the utun gets this address and [tunnelledNetworks6]. */
    val ipv6Address: String? = null,
    /** IPv4 networks routed into the utun: the default route in two halves, which outrank the real default without touching it. */
    val tunnelledNetworks: List<String> = listOf("0.0.0.0/1", "128.0.0.0/1"),
    val tunnelledNetworks6: List<String> = listOf("::/1", "8000::/1"),
    /** The physical interface (`en0`) the exclusions go out of. */
    val physicalInterface: String,
    /** Its next hop; null when the default route is an interface route, and then the exclusions name the interface. */
    val physicalGateway: String?,
    /** IPv4 hosts that must keep going out the physical interface: proxy servers, DNS resolvers. */
    val excludedHosts: List<String> = emptyList(),
    /** IPv4 networks (`a.b.c.d/n`) that stay on the physical interface: private ranges, country bypass. */
    val excludedNetworks: List<String> = TunNetConfig.PRIVATE_NETWORKS,
    /** The resolver every network service is pointed at while up, or null to leave DNS alone. */
    val dnsServer: String? = TunnelConstants.dnsSentinelV4,
    /** The network services (`Wi-Fi`, `Ethernet` ...) whose DNS servers are replaced and later restored. */
    val services: List<String> = emptyList()
) {
    companion object {
        const val ADDRESS = "198.19.255.1"
        const val PEER = "198.19.255.2"
        const val ADDRESS6 = "fd00:6d79:7468::2"
    }
}

/**
 * One route on the physical side that TUN mode added and must delete —
 * data, never a command. The daemon reads these back as root after a
 * crash, so the argv is rebuilt from a fixed template and every field is
 * checked by [MacNetwork.parseSnapshot] first. Routes on the utun itself are
 * never in here: they go with the interface.
 */
@Serializable
data class MacRouteEntry(
    /** [HOST] (`-host a.b.c.d`) or [NET] (`-net a.b.c.d/n`). */
    val kind: String,
    val destination: String,
    val prefix: Int,
    /** The next hop, or null when the route names [interfaceName] instead. */
    val gateway: String? = null,
    val interfaceName: String? = null
) {
    private fun target(): List<String> =
        if (kind == HOST) listOf("-host", destination) else listOf("-net", "$destination/$prefix")

    private fun via(): List<String> =
        gateway?.let { listOf(it) } ?: listOf("-interface", interfaceName ?: "")

    fun addCommand(): List<String> = listOf(MacNet.ROUTE, "-q", "-n", "add") + target() + via()

    fun deleteCommand(): List<String> = listOf(MacNet.ROUTE, "-q", "-n", "delete") + target() + via()

    companion object {
        const val HOST = "host"
        const val NET = "net"
    }
}

/** A network service's DNS servers as they were; empty means none set by hand (DHCP's are used). */
@Serializable
data class ServiceDns(val service: String, val servers: List<String>)

/** One command line, whether its failure aborts the setup, and the route it adds, if any, to delete later. */
data class MacStep(val argv: List<String>, val essential: Boolean = true, val undo: MacRouteEntry? = null) {
    override fun toString(): String = argv.joinToString(" ")
}

/**
 * Turns a [MacNetConfig] into the `ifconfig`, `route` and `networksetup`
 * commands that apply it. Pure, so the exact command lines are pinned by
 * tests; [MacNetwork] runs them and remembers what to undo.
 *
 * The physical-side routes come first, so at no moment does the proxy
 * server's address lead into the tunnel; the DNS switch comes last, once
 * the sentinel it points at is routed into the utun.
 */
object MacRoutePlan {

    fun setup(c: MacNetConfig): List<MacStep> {
        val out = ArrayList<MacStep>()
        out += MacStep(listOf(
            MacNet.IFCONFIG, c.interfaceName, "inet", c.address, c.peer,
            "netmask", "255.255.255.255", "mtu", c.mtu.toString(), "up"
        ))
        c.ipv6Address?.let { v6 ->
            out += MacStep(listOf(MacNet.IFCONFIG, c.interfaceName, "inet6", v6, "prefixlen", "64", "alias"), essential = false)
        }

        for (network in c.excludedNetworks) {
            val entry = networkEntry(c, network) ?: continue
            out += MacStep(entry.addCommand(), essential = false, undo = entry)
        }
        for (host in c.excludedHosts.distinct()) {
            val entry = hostEntry(c, host) ?: continue
            out += MacStep(entry.addCommand(), essential = false, undo = entry)
        }

        for (network in c.tunnelledNetworks) {
            out += MacStep(listOf(MacNet.ROUTE, "-q", "-n", "add", "-net", network, "-interface", c.interfaceName))
        }
        if (c.ipv6Address != null) {
            for (network in c.tunnelledNetworks6) {
                out += MacStep(listOf(MacNet.ROUTE, "-q", "-n", "add", "-inet6", network, "-interface", c.interfaceName), essential = false)
            }
        }

        c.dnsServer?.let { server ->
            for (service in c.services) out += MacStep(setDns(service, listOf(server)), essential = false)
            if (c.services.isNotEmpty()) out += flushDnsCache()
        }
        return out
    }

    /** A route keeping [ip] on the physical side, or null when [ip] is not an IPv4 literal. */
    fun hostEntry(c: MacNetConfig, ip: String): MacRouteEntry? {
        if (!isIpv4(ip)) return null
        return MacRouteEntry(MacRouteEntry.HOST, ip, 32, c.physicalGateway, if (c.physicalGateway == null) c.physicalInterface else null)
    }

    fun networkEntry(c: MacNetConfig, cidr: String): MacRouteEntry? {
        val (net, prefix) = RoutePlan.splitCidr(cidr) ?: return null
        return MacRouteEntry(MacRouteEntry.NET, net, prefix, c.physicalGateway, if (c.physicalGateway == null) c.physicalInterface else null)
    }

    /** `networksetup -setdnsservers`; an empty list hands the service back to DHCP. */
    fun setDns(service: String, servers: List<String>): List<String> =
        listOf(MacNet.NETWORKSETUP, "-setdnsservers", service) + servers.ifEmpty { listOf("Empty") }

    /** The resolver caches answers from before the switch; without a flush they would bypass the tunnel. */
    fun flushDnsCache(): List<MacStep> = listOf(
        MacStep(listOf("/usr/bin/dscacheutil", "-flushcache"), essential = false),
        MacStep(listOf("/usr/bin/killall", "-HUP", "mDNSResponder"), essential = false)
    )

    private fun isIpv4(text: String): Boolean = RoutePlan.splitCidr("$text/32") != null
}

/**
 * Applies a [MacRoutePlan] and remembers, on disk, what has to be undone:
 * the physical-side routes that were actually added (one that already
 * existed belongs to someone else and is left alone) and every service's
 * DNS servers as they were before. A crash leaves the snapshot behind and
 * the next start ([cleanupLeftovers]) puts both back.
 *
 * The system calls go through [runner], [readDns] and [trusted], so the
 * bookkeeping is tested without a Mac.
 */
class MacNetwork(
    private val snapshot: File,
    private val runner: (List<String>) -> MacNet.Result = { MacNet.run(it) },
    private val readDns: (String) -> List<String>? = { MacNet.dnsServers(it) },
    private val trusted: (File) -> Boolean = { MacNet.isTrusted(it) }
) {
    private val logger = MythaiaLogger("Routes")
    private val lock = Any()

    @Serializable
    private data class Snapshot(val version: Int = 0, val routes: List<MacRouteEntry> = emptyList(), val dns: List<ServiceDns> = emptyList())

    /** What is currently applied; null when nothing is. */
    @Volatile
    var applied: MacNetConfig? = null
        private set

    private val added = ArrayList<MacRouteEntry>()
    private var savedDns: List<ServiceDns> = emptyList()

    /** Runs the setup; an essential command failing rolls back and throws. */
    @Throws(IOException::class)
    fun apply(config: MacNetConfig) {
        synchronized(lock) { applyLocked(config) }
    }

    private fun applyLocked(config: MacNetConfig) {
        // The DNS servers as they are, written down before anything changes.
        savedDns = if (config.dnsServer == null) emptyList() else config.services.mapNotNull { service ->
            readDns(service)?.let { servers -> ServiceDns(service, servers.filterNot(::isOurs)) }
        }
        writeSnapshot(added, savedDns)
        for (step in MacRoutePlan.setup(config)) {
            // A route is on record before it exists, so a crash between the two still cleans it up.
            step.undo?.let { writeSnapshot(added + it, savedDns) }
            val result = runWithRetry(step)
            if (result.ok) {
                step.undo?.let(added::add)
                continue
            }
            val text = "$step: ${result.output.lineSequence().firstOrNull { it.isNotBlank() } ?: "exit ${result.exitCode}"}"
            if (step.essential) {
                logger.error("Failed: $text")
                restoreLocked()
                throw IOException("Network setup failed: $text")
            }
            // The link-local range, say, is always routed already; that is no news.
            if (result.output.contains("File exists")) logger.debug("Already routed: $text") else logger.warning("Ignored: $text")
        }
        writeSnapshot(added, savedDns)
        applied = config
        logger.info("Routes installed on ${config.interfaceName} (physical ${config.physicalInterface} via ${config.physicalGateway ?: "on-link"}), DNS of ${savedDns.size} services")
    }

    /** Keeps [ip] on the physical side from now on (a newly selected proxy server, say). */
    fun excludeHost(ip: String) {
        synchronized(lock) { excludeHostLocked(ip) }
    }

    private fun excludeHostLocked(ip: String) {
        val config = applied ?: return
        if (ip in config.excludedHosts || added.any { it.kind == MacRouteEntry.HOST && it.destination == ip }) return
        val entry = MacRoutePlan.hostEntry(config, ip) ?: return
        writeSnapshot(added + entry, savedDns)
        val result = runner(entry.addCommand())
        if (result.ok) added += entry
        else logger.warning("Could not exclude $ip: ${result.output.lineSequence().firstOrNull()}")
        writeSnapshot(added, savedDns)
    }

    /** Undoes [apply]: DNS first, while the resolver can still reach something, then the routes. Safe to call twice. */
    fun restore() {
        synchronized(lock) { restoreLocked() }
    }

    /**
     * Undoes what a previous run left, if its snapshot is still there. The
     * snapshot is believed only when root or this account wrote it and every
     * entry in it validates; anything else is discarded unread.
     */
    fun cleanupLeftovers() {
        synchronized(lock) { cleanupLeftoversLocked() }
    }

    private fun cleanupLeftoversLocked() {
        if (!snapshot.isFile) return
        val ok = trusted(snapshot)
        val parsed = if (ok) parseSnapshot(runCatching { snapshot.readText() }.getOrNull()) else null
        when {
            !ok -> logger.warning("Ignoring the network snapshot: not written by root or this account")
            parsed == null -> logger.warning("Ignoring the network snapshot: not in this version's format")
            else -> {
                logger.info("Undoing a previous run: ${parsed.routes.size} routes, DNS of ${parsed.dns.size} services")
                added.clear()
                added += parsed.routes
                savedDns = parsed.dns
                restoreLocked()
                return
            }
        }
        snapshot.delete()
    }

    private fun restoreLocked() {
        val failedDns = ArrayList<ServiceDns>()
        for (dns in savedDns) {
            val result = runner(MacRoutePlan.setDns(dns.service, dns.servers))
            if (!result.ok) {
                logger.warning("Could not restore the DNS of ${dns.service}: ${result.output.lineSequence().firstOrNull()}")
                // A service that is gone cannot be restored, and need not be.
                if (!result.output.contains("not a recognized network service", ignoreCase = true)) failedDns += dns
            }
        }
        if (savedDns.isNotEmpty()) MacRoutePlan.flushDnsCache().forEach { runner(it.argv) }
        for (entry in added.asReversed()) {
            val result = runner(entry.deleteCommand())
            if (!result.ok) logger.debug("Teardown (ignored): ${entry.deleteCommand().joinToString(" ")} -> ${result.output.lineSequence().firstOrNull()}")
        }
        val hadSomething = applied != null || added.isNotEmpty() || savedDns.isNotEmpty()
        added.clear()
        savedDns = emptyList()
        applied = null
        // DNS that could not be put back is kept on record for the next start to retry.
        if (failedDns.isEmpty()) snapshot.delete() else writeSnapshot(emptyList(), failedDns)
        if (hadSomething) logger.info("Routes and DNS restored")
    }

    private fun writeSnapshot(routes: List<MacRouteEntry>, dns: List<ServiceDns>) {
        runCatching { snapshot.writeText(encodeSnapshot(routes, dns)) }
            .onFailure { logger.warning("Could not write the network snapshot: ${it.message}") }
    }

    /** A freshly created utun is addressable at once, but the essentials get a few tries as on Windows. */
    private fun runWithRetry(step: MacStep): MacNet.Result {
        var result = runner(step.argv)
        var attempt = 0
        while (!result.ok && step.essential && attempt < 3) {
            attempt++
            Thread.sleep(300)
            result = runner(step.argv)
        }
        return result
    }

    companion object {
        const val SNAPSHOT_VERSION = 1
        private val json = Json { ignoreUnknownKeys = true }
        private val ipv4Form = Regex("""(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}""")
        private val ipv6Form = Regex("""[0-9A-Fa-f:.]{2,45}""")
        private val interfaceForm = Regex("""[a-z][a-z0-9]{0,14}""")

        /** The sentinel or a fake address: what this app set, never what the user had. */
        private fun isOurs(server: String): Boolean =
            server == TunnelConstants.dnsSentinelV4 || server == TunnelConstants.dnsSentinelV6 || FakeIpPool.isFakeIp(server)

        internal fun encodeSnapshot(routes: List<MacRouteEntry>, dns: List<ServiceDns>): String =
            json.encodeToString(Snapshot.serializer(), Snapshot(SNAPSHOT_VERSION, routes, dns))

        /** What a snapshot [text] holds, or null when anything in it is not what this version writes. */
        internal data class Parsed(val routes: List<MacRouteEntry>, val dns: List<ServiceDns>)

        internal fun parseSnapshot(text: String?): Parsed? {
            if (text == null) return null
            val snapshot = runCatching { json.decodeFromString(Snapshot.serializer(), text) }.getOrNull() ?: return null
            if (snapshot.version != SNAPSHOT_VERSION) return null
            val routes = snapshot.routes.map { validated(it) ?: return null }
            val dns = snapshot.dns.map { validated(it) ?: return null }
            return Parsed(routes, dns)
        }

        private fun validated(e: MacRouteEntry): MacRouteEntry? {
            val destination = ipv4Literal(e.destination) ?: return null
            when (e.kind) {
                MacRouteEntry.HOST -> if (e.prefix != 32) return null
                MacRouteEntry.NET -> if (e.prefix !in 0..32) return null
                else -> return null
            }
            val gateway = e.gateway?.let { ipv4Literal(it) ?: return null }
            val nic = e.interfaceName?.takeIf { interfaceForm.matches(it) }
            if (e.interfaceName != null && nic == null) return null
            if ((gateway == null) == (nic == null)) return null
            return MacRouteEntry(e.kind, destination, e.prefix, gateway, nic)
        }

        /** A service name goes to networksetup as one argument, never through a shell; it only has to be a plain line. */
        private fun validated(d: ServiceDns): ServiceDns? {
            if (d.service.isEmpty() || d.service.length > 128 || d.service.any { it.isISOControl() } || d.service.startsWith("-")) return null
            val servers = d.servers.map { ipLiteral(it) ?: return null }
            return ServiceDns(d.service, servers)
        }

        /** [text] as a dotted IPv4 address, or null. The regex comes first so InetAddress never resolves a name. */
        private fun ipv4Literal(text: String): String? {
            if (!ipv4Form.matches(text)) return null
            return (runCatching { InetAddress.getByName(text) }.getOrNull() as? Inet4Address)?.hostAddress
        }

        private fun ipLiteral(text: String): String? {
            ipv4Literal(text)?.let { return it }
            if (!ipv6Form.matches(text) || !text.contains(':')) return null
            return if (runCatching { InetAddress.getByName(text) }.getOrNull() is Inet6Address) text.lowercase() else null
        }
    }
}
