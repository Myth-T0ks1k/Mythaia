package com.mythaia.vpn.util

import java.net.InetAddress

/**
 * The CIDR arithmetic a WireGuard profile needs.
 *
 * `wg-quick` is relaxed about what it accepts — a bare address, or a prefix
 * with host bits still set — while `VpnService.Builder.addRoute` refuses both.
 * Turning one into the other is small enough to get wrong quietly, which is
 * why it lives here with tests rather than inline in the service.
 */
object Cidr {

    /** One entry of an `Address` or `AllowedIPs` list. */
    data class Entry(val address: String, val prefix: Int)

    /**
     * Splits `10.0.0.2/24`, or a bare address, which is a host route.
     *
     * Null for anything that is not an address and a prefix within range, so a
     * typo costs one entry rather than the whole tunnel.
     */
    fun split(entry: String): Entry? {
        val text = entry.trim()
        if (text.isEmpty()) return null

        val slash = text.lastIndexOf('/')
        if (slash < 0) {
            if (!isAddress(text)) return null
            return Entry(text, if (text.contains(':')) 128 else 32)
        }

        val address = text.substring(0, slash)
        if (address.isEmpty() || !isAddress(address)) return null

        val prefix = text.substring(slash + 1).toIntOrNull() ?: return null
        val limit = if (address.contains(':')) 128 else 32
        if (prefix !in 0..limit) return null

        return Entry(address, prefix)
    }

    /**
     * The network [address] belongs to, with every bit below [prefix] cleared.
     *
     * `addRoute` rejects an address with host bits set, so `AllowedIPs =
     * 10.0.0.2/24` would otherwise drop the whole subnet from the tunnel.
     */
    fun networkOf(address: String, prefix: Int): String? = try {
        val bytes = InetAddress.getByName(address).address
        for (bit in prefix until bytes.size * 8) {
            val index = bit / 8
            bytes[index] = (bytes[index].toInt() and (1 shl (7 - bit % 8)).inv()).toByte()
        }
        InetAddress.getByAddress(bytes).hostAddress
    } catch (_: Exception) {
        null
    }

    /**
     * Whether this is a literal address rather than a name.
     *
     * `InetAddress.getByName` would look a name up, and a lookup on the thread
     * bringing a tunnel up is exactly what must not happen here.
     */
    private fun isAddress(text: String): Boolean =
        DnsCache.isIpAddress(text)
}
