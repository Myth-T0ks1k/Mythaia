package com.mythaia.vpn.tun

import com.mythaia.data.model.ProxyConfiguration

/** Where one flow goes, as the platform's router decides it. */
sealed class TunRoute {
    data object Direct : TunRoute()
    data object Block : TunRoute()
    data class Proxy(val configuration: ProxyConfiguration) : TunRoute()
}

/** The knobs a [TunStack] reads on every packet; replaceable at runtime. */
data class TunSettings(
    /** Answer AAAA queries with fake IPv6 addresses; otherwise NODATA keeps clients on IPv4. */
    val ipv6Dns: Boolean = false,
    /** Drop UDP/443 with ICMP port-unreachable so HTTP/3 clients fall back to HTTP/2. */
    val blockQuic: Boolean = true,
    /** When false, DDR (RFC 9462) discovery is refused so the OS cannot escape port-53 interception. */
    val encryptedDnsEnabled: Boolean = false,
    /**
     * Domains whose A/AAAA queries are answered with their real addresses
     * rather than fake IPs: the proxy servers themselves are always in this
     * set, and the platform adds whatever else must never enter the tunnel
     * (an encrypted-DNS resolver's own name, for instance). Lower-case.
     */
    val realAnswerDomains: Set<String> = emptySet()
)

/**
 * What the platform gives a [TunStack]: a way to write packets to the
 * interface and a routing verdict for each new flow.
 *
 * Both are called on the lwIP thread and must not block.
 */
interface TunHost {
    /** Write the first [length] bytes of [packet], an IPv4 or IPv6 packet, to the interface. */
    fun writePacket(packet: ByteArray, length: Int)

    /**
     * Where a flow to [host]:[port] goes. [host] is a domain name when the
     * client resolved it through the stack's own DNS (a fake IP) or when a
     * TLS ClientHello named it, and an IP literal otherwise.
     */
    fun route(host: String, port: Int, udp: Boolean): TunRoute

    /** The number of open TCP connections changed; for the UI's counter. */
    fun onConnectionCount(count: Int) {}
}
