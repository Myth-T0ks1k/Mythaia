package com.mythaia.vpn.util

/**
 * ICMP Destination Unreachable (Port Unreachable) packets, ready to be
 * written to a TUN interface.
 *
 * Sent when UDP arrives at a stale fake IP no longer in the pool (a previous
 * session's answer), at a rejected domain, or at UDP/443 while QUIC is
 * blocked. The client abandons the stale destination and re-resolves — or,
 * for QUIC, falls back to HTTP/2 — instead of retrying into a black hole.
 *
 * [srcIp]/[srcPort] are the original datagram's sender, [dstIp]/[dstPort]
 * its destination; the reply is built from the destination back to the
 * sender and quotes the reconstructed IP + UDP header the way RFC 792 /
 * RFC 4443 require.
 */
object IcmpPackets {

    /** IPv4 ICMP Type 3 Code 3, 56 bytes: outer IPv4 (20) + ICMP (8) + inner IPv4 (20) + UDP (8). */
    fun portUnreachableV4(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4) { "IPv4 addresses are 4 bytes" }
        val packetLen = 56
        val p = ByteArray(packetLen)

        // Outer IPv4 header (src=fake IP, dst=sender)
        p[0] = 0x45.toByte()                                   // Version 4, IHL 5
        p[1] = 0x00                                             // TOS
        p[2] = (packetLen shr 8).toByte()                       // Total length
        p[3] = (packetLen and 0xFF).toByte()
        p[8] = 64                                               // TTL
        p[9] = 1                                                // Protocol: ICMP
        System.arraycopy(dstIp, 0, p, 12, 4)                   // Src = fake IP
        System.arraycopy(srcIp, 0, p, 16, 4)                   // Dst = sender

        val ipCksum = checksum(p, 0, 20)
        p[10] = (ipCksum shr 8).toByte()
        p[11] = (ipCksum and 0xFF).toByte()

        // ICMP header (Type 3 = Dest Unreachable, Code 3 = Port Unreachable)
        p[20] = 3; p[21] = 3                                   // Type, Code

        // Reconstructed original IPv4 header
        val udpTotalLen = 8 + udpPayloadLength
        val innerTotalLen = 20 + udpTotalLen
        p[28] = 0x45.toByte(); p[29] = 0x00                    // Version 4, IHL 5, TOS
        p[30] = ((innerTotalLen shr 8) and 0xFF).toByte()       // Total length
        p[31] = (innerTotalLen and 0xFF).toByte()
        p[36] = 64; p[37] = 17                                 // TTL, Protocol: UDP
        System.arraycopy(srcIp, 0, p, 40, 4)                   // Src = original sender
        System.arraycopy(dstIp, 0, p, 44, 4)                   // Dst = fake IP

        // First 8 bytes of original UDP
        p[48] = (srcPort shr 8).toByte(); p[49] = (srcPort and 0xFF).toByte()
        p[50] = (dstPort shr 8).toByte(); p[51] = (dstPort and 0xFF).toByte()
        p[52] = ((udpTotalLen shr 8) and 0xFF).toByte()
        p[53] = (udpTotalLen and 0xFF).toByte()

        // ICMP checksum (over ICMP header + data, offset 20..55)
        val icmpCksum = checksum(p, 20, packetLen)
        p[22] = (icmpCksum shr 8).toByte()
        p[23] = (icmpCksum and 0xFF).toByte()

        return p
    }

    /** IPv6 ICMPv6 Type 1 Code 4, 96 bytes: outer IPv6 (40) + ICMPv6 (8) + inner IPv6 (40) + UDP (8). */
    fun portUnreachableV6(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        udpPayloadLength: Int
    ): ByteArray {
        require(srcIp.size == 16 && dstIp.size == 16) { "IPv6 addresses are 16 bytes" }
        val icmpLen = 56  // 8 + 40 + 8
        val packetLen = 40 + icmpLen
        val p = ByteArray(packetLen)

        // Outer IPv6 header (src=fake IP, dst=sender)
        p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0            // Version 6, TC, Flow Label
        p[4] = (icmpLen shr 8).toByte()                         // Payload length
        p[5] = (icmpLen and 0xFF).toByte()
        p[6] = 58                                               // Next Header: ICMPv6
        p[7] = 64                                               // Hop Limit
        System.arraycopy(dstIp, 0, p, 8, 16)                   // Src = fake IP
        System.arraycopy(srcIp, 0, p, 24, 16)                  // Dst = sender

        // ICMPv6 header (Type 1 = Dest Unreachable, Code 4 = Port Unreachable)
        p[40] = 1; p[41] = 4                                   // Type, Code

        // Reconstructed original IPv6 header
        val udpTotalLen = 8 + udpPayloadLength
        p[48] = 0x60; p[49] = 0; p[50] = 0; p[51] = 0         // Version 6
        p[52] = (udpTotalLen shr 8).toByte()                    // Payload length
        p[53] = (udpTotalLen and 0xFF).toByte()
        p[54] = 17; p[55] = 64                                 // Next Header: UDP, Hop Limit
        System.arraycopy(srcIp, 0, p, 56, 16)                  // Src = original sender
        System.arraycopy(dstIp, 0, p, 72, 16)                  // Dst = fake IP

        // First 8 bytes of original UDP
        p[88] = (srcPort shr 8).toByte(); p[89] = (srcPort and 0xFF).toByte()
        p[90] = (dstPort shr 8).toByte(); p[91] = (dstPort and 0xFF).toByte()
        p[92] = ((udpTotalLen shr 8) and 0xFF).toByte()
        p[93] = (udpTotalLen and 0xFF).toByte()

        // ICMPv6 checksum (includes pseudo-header per RFC 4443 §2.3)
        var sum = 0L
        // Pseudo-header: source address (outer src = dstIp)
        for (i in 8 until 24 step 2) sum += word(p, i)
        // Pseudo-header: destination address (outer dst = srcIp)
        for (i in 24 until 40 step 2) sum += word(p, i)
        // Pseudo-header: upper-layer packet length + next header (58)
        sum += icmpLen.toLong()
        sum += 58
        // ICMPv6 header + data
        for (i in 40 until packetLen step 2) sum += word(p, i)
        val cksum = fold(sum)
        p[42] = (cksum shr 8).toByte()
        p[43] = (cksum and 0xFF).toByte()

        return p
    }

    /** The one's-complement checksum of [buf] over `[from, to)`, [to] - [from] even. */
    fun checksum(buf: ByteArray, from: Int, to: Int): Int {
        var sum = 0L
        for (i in from until to step 2) sum += word(buf, i)
        return fold(sum)
    }

    private fun word(p: ByteArray, i: Int): Long =
        (((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)).toLong()

    private fun fold(total: Long): Int {
        var sum = total
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.toInt().inv() and 0xFFFF
    }
}
