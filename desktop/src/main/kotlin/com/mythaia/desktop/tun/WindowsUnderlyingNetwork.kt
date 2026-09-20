package com.mythaia.desktop.tun

import com.mythaia.vpn.SocketProtector
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
 * The physical network as the core sees it while the TUN is up.
 *
 * Name resolution asks the interface's original DNS servers directly
 * (plain UDP, which the routes keep on the physical side) instead of the
 * Windows resolver — that one now asks the TUN adapter's DNS, which is us,
 * and would hand the app fake addresses for its own proxy server.
 */
class WindowsUnderlyingNetwork(private val dnsServers: List<String>) : UnderlyingNetwork {
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
 * physical interface's address: under Windows' strong-host model a bound
 * socket only consults that interface's routes, so the TUN's default route
 * never applies to it. Sockets that are already bound (a plain
 * `DatagramSocket()`) are left alone and rely on the host routes instead.
 */
object WindowsSocketProtector {
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
