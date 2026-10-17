package com.mythaia.desktop.tun

import com.mythaia.vpn.SocketProtector
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.DnsUpstream
import com.mythaia.vpn.util.DnsUpstreamClient
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.UnderlyingNetwork
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.net.URLConnection
import java.net.UnknownHostException

/**
 * What the TUN engine needs to know about the physical network before it
 * takes the default route over: which interface carries it, through which
 * gateway, with which address, and which DNS servers it was using.
 */
data class PhysicalPath(
    val interfaceIndex: Int,
    /** Null when the best route is on-link (no gateway). */
    val gateway: String?,
    /** The interface's IPv4 address, for binding sockets to it. */
    val address: InetAddress,
    /** The interface's IPv4 networks, as `address/prefix`, so on-link hosts are not given host routes. */
    val networks: List<Pair<InetAddress, Int>>,
    /** IPv4 DNS servers configured on that interface (static or DHCP). */
    val dnsServers: List<String>,
    /** The interface's name (`en0`); macOS routes name it, Windows uses [interfaceIndex]. */
    val interfaceName: String? = null,
    /** Whether the system has an IPv6 default route too, so IPv6 must be taken over as well. */
    val hasIpv6: Boolean = false
) {
    /** Whether [ip] is already reachable on-link through this interface. */
    fun isOnLink(ip: InetAddress): Boolean {
        val bytes = ip.address
        return networks.any { (net, prefix) ->
            val n = net.address
            if (n.size != bytes.size) return@any false
            var bits = prefix
            for (i in n.indices) {
                if (bits <= 0) return@any true
                val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
                if ((n[i].toInt() and mask) != (bytes[i].toInt() and mask)) return@any false
                bits -= 8
            }
            true
        }
    }

    /** How the log names the interface. */
    val label: String get() = interfaceName ?: interfaceIndex.toString()
}

/** Helpers both platforms' TUN code shares. */
object PhysicalNet {
    /** Resolves [host] to IPv4 literals, through the app's own cache (which is on the physical network once set). */
    fun resolveV4(host: String): List<String> {
        if (DnsCache.isIpAddress(host)) return if (host.contains(':')) emptyList() else listOf(host)
        return runCatching { DnsCache.resolveAll(host) }.getOrDefault(emptyList()).filterNot { it.contains(':') }
    }
}

/**
 * The physical network as the core sees it while the TUN is up.
 *
 * Name resolution asks the interface's original DNS servers directly
 * (plain UDP, which the routes keep on the physical side) instead of the
 * system resolver — that one now asks the TUN's DNS, which is us, and would
 * hand the app fake addresses for its own proxy server.
 */
class PhysicalUnderlyingNetwork(private val dnsServers: List<String>) : UnderlyingNetwork {
    private val logger = MythaiaLogger("PhysicalDNS")

    override fun getAllByName(host: String): Array<InetAddress> {
        for (server in dnsServers) {
            val ips = runCatching {
                DnsUpstreamClient.resolve(host, DnsUpstream.Plain(server), null, DnsUpstreamClient.Family.BOTH, timeoutMs = 3000)
            }.getOrDefault(emptyList())
            if (ips.isNotEmpty()) {
                return ips.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }.toTypedArray()
            }
        }
        logger.warning("No physical resolver answered for $host")
        throw UnknownHostException(host)
    }

    /** Plain JDK connections; the encrypted-DNS server's address is kept on the physical side by a route. */
    override fun openConnection(url: URL): URLConnection = url.openConnection()
}

/**
 * Keeps the app's own sockets off the tunnel by binding them to the
 * physical interface's address. Under Windows' strong-host model a bound
 * socket only consults that interface's routes; macOS scopes the route
 * lookup of a socket bound to an address to the interface owning it, which
 * has a scoped default route of its own. Either way the TUN's default
 * routes never apply to it. Sockets that are already bound (a plain
 * `DatagramSocket()`) are left alone and rely on the host routes instead.
 */
object PhysicalSocketProtector {
    private val logger = MythaiaLogger("Protector")

    fun install(physicalAddress: InetAddress) {
        SocketProtector.setProtector(
            fdFn = { true },
            socketFn = { socket -> bind(socket, physicalAddress) },
            datagramFn = { socket -> bind(socket, physicalAddress) }
        )
    }

    fun clear() = SocketProtector.clearProtector()

    private fun bind(socket: Socket, address: InetAddress): Boolean {
        if (socket.isBound || socket.isConnected) return true
        return try {
            socket.bind(InetSocketAddress(address, 0))
            true
        } catch (e: Exception) {
            logger.debug("Could not bind a TCP socket to ${address.hostAddress}: ${e.message}")
            false
        }
    }

    private fun bind(socket: DatagramSocket, address: InetAddress): Boolean {
        if (socket.isBound) return true
        return try {
            socket.bind(InetSocketAddress(address, 0))
            true
        } catch (e: Exception) {
            logger.debug("Could not bind a UDP socket to ${address.hostAddress}: ${e.message}")
            false
        }
    }
}
