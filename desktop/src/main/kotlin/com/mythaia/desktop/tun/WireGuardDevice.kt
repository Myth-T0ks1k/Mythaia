package com.mythaia.desktop.tun

import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.vpn.protocol.wireguard.PacketDevice
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * A Wintun session as the WireGuard tunnel's [PacketDevice]. The engine
 * owns the session and ends it; [close] only lets a blocked read return.
 * When [dropIpv6] is set (an IPv4-only profile whose adapter still captures
 * `::/1` and `8000::/1` so IPv6 cannot leak out the physical interface),
 * IPv6 packets are discarded here rather than sent to the peer.
 */
internal class WintunPacketDevice(
    private val receivePacket: (ByteArray, () -> Boolean) -> Int,
    private val sendPacket: (ByteArray, Int) -> Boolean,
    private val stats: TrafficStats,
    private val dropIpv6: Boolean = false
) : PacketDevice {

    constructor(
        session: WintunAdapter.Session,
        stats: TrafficStats,
        dropIpv6: Boolean = false
    ) : this(
        receivePacket = { buf, keepRunning -> session.receive(buf, keepRunning) },
        sendPacket = { pkt, len -> session.send(pkt, len) },
        stats = stats,
        dropIpv6 = dropIpv6
    )

    @Volatile
    private var open = true

    override fun read(buffer: ByteArray): Int {
        if (buffer.isEmpty()) return -1
        while (open) {
            val n = receivePacket(buffer) { open }
            if (n <= 0) return if (open) n else -1
            if (dropIpv6 && (buffer[0].toInt() and 0xF0) == 0x60) continue
            stats.up.addAndGet(n.toLong())
            return n
        }
        return -1
    }

    override fun write(packet: ByteArray, length: Int) {
        if (!open || length <= 0 || length > packet.size) return
        if (dropIpv6 && (packet[0].toInt() and 0xF0) == 0x60) return
        if (sendPacket(packet, length)) stats.down.addAndGet(length.toLong())
    }

    override fun close() {
        open = false
    }
}

/**
 * The socket to the WireGuard peer, bound to the physical interface's
 * address: under Windows' strong-host model it then never takes the
 * tunnel's routes, whatever AllowedIPs covers. [address] is read on every
 * call, so a socket made after a network change binds to the new one.
 */
internal fun physicalSocket(address: () -> InetAddress?): DatagramSocket {
    val bind = address()
    return if (bind != null) DatagramSocket(InetSocketAddress(bind, 0)) else DatagramSocket()
}
