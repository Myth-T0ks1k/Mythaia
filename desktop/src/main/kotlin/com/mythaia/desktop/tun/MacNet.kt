package com.mythaia.desktop.tun

import com.mythaia.desktop.Platform
import com.mythaia.desktop.engine.MacSystemProxy
import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.io.IOException
import java.net.Inet4Address
import java.net.NetworkInterface
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.concurrent.TimeUnit

/** Reading the macOS network state and running its configuration tools. */
object MacNet {
    const val ROUTE = "/sbin/route"
    const val IFCONFIG = "/sbin/ifconfig"
    const val NETWORKSETUP = "/usr/sbin/networksetup"
    private const val RESOLV_CONF = "/etc/resolv.conf"

    private val logger = MythaiaLogger("MacNet")
    private val ipv4Literal = Regex("""^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
    private val ipv6Literal = Regex("""^[0-9A-Fa-f:.]{2,45}$""")

    /** The result of one external command. */
    data class Result(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
    }

    /** `route -n get` reduced to what matters: the next hop (an IPv4 literal, or null for an interface route) and the interface. */
    data class RouteGet(val gateway: String?, val interfaceName: String)

    /** Runs [argv] (an absolute tool path first) and waits at most [timeoutSec]. */
    fun run(argv: List<String>, timeoutSec: Long = 20): Result = try {
        val process = ProcessBuilder(argv).redirectErrorStream(true).start()
        runCatching { process.outputStream.close() }
        val output = process.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        if (!process.waitFor(timeoutSec, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            Result(-1, "timed out: ${argv.joinToString(" ")}")
        } else Result(process.exitValue(), output.trim())
    } catch (e: Exception) {
        Result(-1, e.message ?: e.toString())
    }

    /**
     * The path the default route takes now: the interface and next hop from
     * `route -n get default`, its addresses from the JDK, the resolvers from
     * `/etc/resolv.conf` (which configd keeps to the primary service's).
     * Must be read before the TUN routes exist, or it finds the utun.
     */
    fun physicalPath(): PhysicalPath? {
        val result = run(listOf(ROUTE, "-n", "get", "default"))
        if (!result.ok) {
            logger.warning("No default route: ${result.output.lineSequence().firstOrNull()}")
            return null
        }
        val route = parseRouteGet(result.output) ?: return null
        val nic = runCatching { NetworkInterface.getByName(route.interfaceName) }.getOrNull() ?: return null
        val v4 = nic.interfaceAddresses.filter { it.address is Inet4Address }
        val address = v4.firstOrNull()?.address ?: return null
        val networks = v4.map { it.address to it.networkPrefixLength.toInt() }
        val dns = runCatching { parseResolvConf(File(RESOLV_CONF).readText()) }.getOrDefault(emptyList())
        val v6 = run(listOf(ROUTE, "-n", "get", "-inet6", "default")).let { it.ok && parseRouteGet(it.output) != null }
        return PhysicalPath(nic.index, route.gateway, address, networks, dns, route.interfaceName, v6)
    }

    /**
     * ```
     *    route to: default
     * destination: default
     *     gateway: 192.168.1.1
     *   interface: en0
     * ```
     * A gateway that is not an IPv4 literal (`link#5`, an IPv6 next hop) means
     * the route names its interface only.
     */
    internal fun parseRouteGet(text: String?): RouteGet? {
        val fields = text.orEmpty().lines().mapNotNull { line ->
            val i = line.indexOf(':')
            if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
        }.toMap()
        val nic = fields["interface"]?.takeIf { it.matches(Regex("[a-z][a-z0-9]{0,14}")) } ?: return null
        val gateway = fields["gateway"]?.takeIf { ipv4Literal.matches(it) }
        return RouteGet(gateway, nic)
    }

    /** The IPv4 `nameserver` lines, without loopback and without this app's own sentinel and fake range. */
    internal fun parseResolvConf(text: String?): List<String> =
        text.orEmpty().lines()
            .map { it.trim() }
            .filter { it.startsWith("nameserver") }
            .mapNotNull { it.removePrefix("nameserver").trim().split(Regex("\\s+")).firstOrNull() }
            .filter { ipv4Literal.matches(it) && !it.startsWith("127.") && !FakeIpPool.isFakeIp(it) }
            .distinct()

    /** The enabled network services, as `networksetup` lists them. */
    fun services(): List<String> {
        val result = run(listOf(NETWORKSETUP, "-listallnetworkservices"))
        return if (result.ok) MacSystemProxy.parseServices(result.output) else emptyList()
    }

    /** The DNS servers set by hand on [service]; empty when it uses DHCP's, null when they could not be read. */
    fun dnsServers(service: String): List<String>? {
        val result = run(listOf(NETWORKSETUP, "-getdnsservers", service))
        return if (result.ok) parseDnsServers(result.output) else null
    }

    /** One address per line, or a sentence ("There aren't any DNS Servers set on Wi-Fi."). */
    internal fun parseDnsServers(text: String?): List<String> =
        text.orEmpty().lines().map { it.trim() }
            .filter { ipv4Literal.matches(it) || (ipv6Literal.matches(it) && it.contains(':')) }

    /** Whether [file] was written by root or by the account this process runs as, and is not a link. */
    fun isTrusted(file: File): Boolean = runCatching {
        val path = file.toPath()
        if (Files.isSymbolicLink(path)) return@runCatching false
        val owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).name
        owner == "root" || owner == System.getProperty("user.name")
    }.getOrDefault(false)
}

/**
 * TUN mode on macOS: a utun interface, addressed and routed with
 * `ifconfig` and `route`, every network service's DNS pointed at the
 * stack's fake-IP resolver with `networksetup` ([MacNetwork]), all of it
 * snapshotted in [snapshot] so a crash is undone on the next start. Needs
 * root, which on macOS means the service daemon.
 */
class MacTunPlatform(snapshot: File) : TunPlatform {
    private val network = MacNetwork(snapshot)

    override fun checkReady() {
        if (!Platform.isMac) throw IOException("utun TUN mode is only available on macOS")
        if (!NativeBridge.isLoaded) throw IOException("The native library (${Platform.nativeLibraryName}) is not loaded")
        if (!MacUtun.isRoot()) throw IOException("TUN mode needs root; on macOS it runs in the Mythaia service")
    }

    override fun cleanupLeftovers() = network.cleanupLeftovers()

    override fun physicalPath(): PhysicalPath? = MacNet.physicalPath()

    override fun openDevice(): TunDevice = MacUtun.open()

    override fun configure(device: TunDevice, path: PhysicalPath, excludedHosts: List<String>, excludedNetworks: List<String>) {
        val physical = path.interfaceName ?: throw IOException("The physical interface has no name")
        network.apply(
            MacNetConfig(
                interfaceName = device.name,
                ipv6Address = if (path.hasIpv6) MacNetConfig.ADDRESS6 else null,
                physicalInterface = physical,
                physicalGateway = path.gateway,
                excludedHosts = excludedHosts,
                excludedNetworks = excludedNetworks,
                services = MacNet.services()
            )
        )
    }

    override fun excludeHost(ip: String) = network.excludeHost(ip)

    override fun restore() = network.restore()
}
