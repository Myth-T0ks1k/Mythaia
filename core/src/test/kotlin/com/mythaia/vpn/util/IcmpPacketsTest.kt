package com.mythaia.vpn.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The ICMP port-unreachable packets the TUN stacks write back when a UDP
 * flow cannot be served. A wrong checksum is silently dropped by the OS
 * and the client keeps retrying into nothing, so the bytes are pinned.
 */
class IcmpPacketsTest {

    private val sender = byteArrayOf(10, 8, 0, 2)
    private val fake = byteArrayOf(198.toByte(), 18, 0, 5)

    @Test
    fun `IPv4 reply is addressed from the destination back to the sender`() {
        val p = IcmpPackets.portUnreachableV4(sender, 51000, fake, 443, 100)
        assertEquals(56, p.size)
        assertEquals(0x45, p[0].toInt() and 0xFF)
        assertEquals(1, p[9].toInt())                                     // ICMP
        assertArrayEquals(fake, p.copyOfRange(12, 16))                     // outer src = fake IP
        assertArrayEquals(sender, p.copyOfRange(16, 20))                   // outer dst = sender
        assertEquals(3, p[20].toInt()); assertEquals(3, p[21].toInt())    // type 3 code 3
        assertArrayEquals(sender, p.copyOfRange(40, 44))                   // quoted src = sender
        assertArrayEquals(fake, p.copyOfRange(44, 48))                     // quoted dst = fake IP
        assertEquals(51000, ((p[48].toInt() and 0xFF) shl 8) or (p[49].toInt() and 0xFF))
        assertEquals(443, ((p[50].toInt() and 0xFF) shl 8) or (p[51].toInt() and 0xFF))
        assertEquals(108, ((p[52].toInt() and 0xFF) shl 8) or (p[53].toInt() and 0xFF))   // UDP length = 8 + 100
    }

    @Test
    fun `IPv4 header and ICMP checksums verify to zero`() {
        val p = IcmpPackets.portUnreachableV4(sender, 1234, fake, 53, 40)
        assertEquals(0, IcmpPackets.checksum(p, 0, 20))    // a correct checksum sums to zero
        assertEquals(0, IcmpPackets.checksum(p, 20, 56))
    }

    @Test
    fun `IPv6 reply carries the pseudo-header checksum`() {
        val src = ByteArray(16).also { it[0] = 0x20; it[1] = 0x01; it[15] = 1 }
        val dst = ByteArray(16).also { it[0] = 0xFC.toByte(); it[15] = 7 }
        val p = IcmpPackets.portUnreachableV6(src, 4000, dst, 443, 50)
        assertEquals(96, p.size)
        assertEquals(0x60, p[0].toInt() and 0xFF)
        assertEquals(58, p[6].toInt())                                    // ICMPv6
        assertArrayEquals(dst, p.copyOfRange(8, 24))
        assertArrayEquals(src, p.copyOfRange(24, 40))
        assertEquals(1, p[40].toInt()); assertEquals(4, p[41].toInt())    // type 1 code 4

        // Recompute over pseudo-header + ICMPv6 body; must fold to zero.
        var sum = 0L
        for (i in 8 until 40 step 2) sum += (((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)).toLong()
        sum += 56; sum += 58
        for (i in 40 until 96 step 2) sum += (((p[i].toInt() and 0xFF) shl 8) or (p[i + 1].toInt() and 0xFF)).toLong()
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum.toInt())
    }
}
