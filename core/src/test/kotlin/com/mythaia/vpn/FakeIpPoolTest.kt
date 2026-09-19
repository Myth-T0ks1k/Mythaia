package com.mythaia.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The fake-IP pool, which turns every routed DNS answer into a synthetic
 * address and turns it back into a domain when the connection arrives.
 *
 * If a lookup ever returns the wrong domain, traffic goes to the wrong server
 * under the wrong rules — so the round trip and the eviction behaviour are
 * worth pinning down.
 */
class FakeIpPoolTest {

    @Test
    fun `the same domain keeps its offset`() {
        val pool = FakeIpPool()
        val first = pool.allocate("example.com")
        val second = pool.allocate("example.com")
        assertEquals(first, second)
    }

    @Test
    fun `different domains get different offsets`() {
        val pool = FakeIpPool()
        val a = pool.allocate("a.example")
        val b = pool.allocate("b.example")
        assertNotEquals(a, b)
    }

    @Test
    fun `an allocated address resolves back to its domain`() {
        val pool = FakeIpPool()
        val offset = pool.allocate("example.com")

        val v4 = FakeIpPool.ipv4Bytes(offset)
        val v4Text = "${v4[0].toInt() and 0xFF}.${v4[1].toInt() and 0xFF}." +
            "${v4[2].toInt() and 0xFF}.${v4[3].toInt() and 0xFF}"
        assertEquals("example.com", pool.lookup(v4Text)?.domain)
    }

    @Test
    fun `an address outside the pool resolves to nothing`() {
        val pool = FakeIpPool()
        pool.allocate("example.com")

        assertNull(pool.lookup("8.8.8.8"))
        assertNull(pool.lookup("192.168.1.1"))
        assertNull(pool.lookup("not an ip"))
        // In range, but never handed out.
        assertNull(pool.lookup("198.19.255.254"))
    }

    @Test
    fun `offsets convert to addresses in the documented ranges`() {
        // 198.18.0.0/15 for v4, fc00:: + offset for v6. isFakeIp keys off those
        // prefixes, so an offset that fell outside would be routed as a real
        // address.
        for (offset in listOf(1, 2, 255, 256, 65535, 100000)) {
            val v4 = FakeIpPool.ipv4Bytes(offset)
            val text = "${v4[0].toInt() and 0xFF}.${v4[1].toInt() and 0xFF}." +
                "${v4[2].toInt() and 0xFF}.${v4[3].toInt() and 0xFF}"
            assertTrue("offset $offset gave $text", FakeIpPool.isFakeIp(text))

            val v6 = FakeIpPool.ipv6Bytes(offset)
            assertEquals(16, v6.size)
            assertEquals(0xFC.toByte(), v6[0])
            assertEquals(0x00.toByte(), v6[1])
            // The offset occupies the last four bytes, big-endian.
            assertEquals(((offset shr 24) and 0xFF).toByte(), v6[12])
            assertEquals((offset and 0xFF).toByte(), v6[15])
        }
    }

    @Test
    fun `an IPv6 fake address resolves back to its domain`() {
        val pool = FakeIpPool()
        val offset = pool.allocate("example.com")
        val v6 = FakeIpPool.ipv6Bytes(offset)

        // Presentation form of fc00:: + offset, as the tunnel would hand it in.
        val groups = (0 until 8).map {
            ((v6[it * 2].toInt() and 0xFF) shl 8) or (v6[it * 2 + 1].toInt() and 0xFF)
        }
        val text = groups.joinToString(":") { it.toString(16) }
        assertEquals("example.com", pool.lookup(text)?.domain)
    }

    @Test
    fun `reset forgets everything`() {
        val pool = FakeIpPool()
        val offset = pool.allocate("example.com")
        pool.reset()

        val v4 = FakeIpPool.ipv4Bytes(offset)
        val text = "${v4[0].toInt() and 0xFF}.${v4[1].toInt() and 0xFF}." +
            "${v4[2].toInt() and 0xFF}.${v4[3].toInt() and 0xFF}"
        assertNull(pool.lookup(text))
    }

    @Test
    fun `a full pool evicts the least recently used domain`() {
        // Filling the pool is what a long session does. The oldest entry has to
        // go, and it has to be the oldest by USE, not by allocation — otherwise
        // a busy domain gets evicted while an idle one survives.
        val pool = FakeIpPool()
        val size = FakeIpPool.POOL_SIZE

        val firstOffset = pool.allocate("first.example")
        pool.allocate("second.example")

        // Touch the first so the second becomes least-recently-used.
        pool.allocate("first.example")

        // Fill the rest of the pool, forcing evictions.
        for (i in 0 until size) {
            pool.allocate("filler$i.example")
        }

        // The pool never grows past its size, and the offsets stay in range.
        val offset = pool.allocate("after.example")
        assertTrue("offset $offset out of range", offset in 1..size)
        assertTrue(firstOffset in 1..size)
    }

    @Test
    fun `a reused offset no longer answers for the evicted domain`() {
        // The failure this guards against is the worst one the pool can have:
        // an address that still resolves to a domain it was taken away from,
        // sending traffic to the wrong server under the wrong rules.
        val pool = FakeIpPool()
        val size = FakeIpPool.POOL_SIZE

        val victimOffset = pool.allocate("victim.example")
        for (i in 0 until size + 2) {
            pool.allocate("filler$i.example")
        }

        val v4 = FakeIpPool.ipv4Bytes(victimOffset)
        val text = "${v4[0].toInt() and 0xFF}.${v4[1].toInt() and 0xFF}." +
            "${v4[2].toInt() and 0xFF}.${v4[3].toInt() and 0xFF}"
        assertNotEquals("victim.example", pool.lookup(text)?.domain)
    }

    @Test
    fun `isFakeIp does not claim real addresses`() {
        for (real in listOf(
            "8.8.8.8", "1.1.1.1", "192.168.0.1", "198.20.0.1", "198.17.255.255",
            "2001:4860:4860::8888", "::1", ""
        )) {
            assertTrue(real, !FakeIpPool.isFakeIp(real))
        }
        for (fake in listOf("198.18.0.1", "198.19.255.255", "fc00::1")) {
            assertTrue(fake, FakeIpPool.isFakeIp(fake))
        }
    }
}
