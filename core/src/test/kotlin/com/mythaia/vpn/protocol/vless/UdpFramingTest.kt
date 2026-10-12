package com.mythaia.vpn.protocol.vless

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UdpFramingTest {

    private fun packet(n: Int, size: Int) = ByteArray(size) { (n + it).toByte() }

    @Test
    fun `every packet of a stream comes out, one chunk at a time`() {
        val state = UdpBufferState()
        for (n in 0 until 50) {
            val p = packet(n, 20 + n)
            state.append(UdpFraming.frame(p))
            assertArrayEquals("packet $n", p, UdpFraming.extract(state))
            assertNull(UdpFraming.extract(state))
        }
    }

    @Test
    fun `packets split across chunks and several in one chunk`() {
        val packets = (0 until 30).map { packet(it, 1 + it * 37 % 1200) }
        val wire = packets.fold(ByteArray(0)) { acc, p -> acc + UdpFraming.frame(p) }
        val state = UdpBufferState()
        val out = mutableListOf<ByteArray>()
        var at = 0
        val sizes = listOf(1, 3, 700, 2, 1500, 5, 9000)
        var i = 0
        while (at < wire.size) {
            val end = minOf(wire.size, at + sizes[i++ % sizes.size])
            state.append(wire.copyOfRange(at, end))
            at = end
            while (true) out += UdpFraming.extract(state) ?: break
        }
        packets.forEachIndexed { n, p -> assertArrayEquals("packet $n", p, out[n]) }
    }
}
