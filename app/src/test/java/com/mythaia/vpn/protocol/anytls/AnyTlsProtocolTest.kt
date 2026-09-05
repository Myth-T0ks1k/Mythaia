package com.mythaia.vpn.protocol.anytls

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The AnyTLS wire format, against the reference implementation rather than
 * against itself.
 *
 * The MD5 below is the one anytls-go computes over its own default scheme. It
 * is the whole point of the test: the server compares that digest to decide
 * whether to push a replacement, so a scheme that differs by a single newline
 * still works — it just triggers an update on every session and marks the
 * client as not quite the thing it claims to be.
 */
class AnyTlsProtocolTest {

    private val random = SecureRandom()

    // MARK: - Padding scheme

    @Test
    fun `the default scheme is byte-identical to the reference`() {
        assertEquals(137, AnyTlsPaddingScheme.DEFAULT.raw.size)
        assertEquals("75cff2ad89aadf5e257059ee571ebe11", AnyTlsPaddingScheme.DEFAULT.md5)
    }

    @Test
    fun `stop bounds which packets are shaped`() {
        val scheme = AnyTlsPaddingScheme.DEFAULT
        assertTrue(scheme.shapes(0))
        assertTrue(scheme.shapes(7))
        // stop=8 means packets 0..7, so 8 onwards go out unshaped.
        assertTrue(!scheme.shapes(8))
        assertTrue(!scheme.shapes(9))
    }

    @Test
    fun `a fixed range yields exactly that size`() {
        // "0=30-30" — the padding that rides along with authentication.
        assertEquals(listOf(30), AnyTlsPaddingScheme.DEFAULT.recordSizes(0, random))
    }

    @Test
    fun `a range stays inside itself over many draws`() {
        repeat(200) {
            val sizes = AnyTlsPaddingScheme.DEFAULT.recordSizes(1, random)
            assertEquals(1, sizes.size)
            assertTrue("out of range: ${sizes[0]}", sizes[0] in 100..400)
        }
    }

    @Test
    fun `check marks are kept in order among the sizes`() {
        // "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000"
        val sizes = AnyTlsPaddingScheme.DEFAULT.recordSizes(2, random)
        assertEquals(9, sizes.size)
        assertTrue(sizes[0] in 400..500)
        for (i in listOf(1, 3, 5, 7)) {
            assertEquals("position $i should be a check mark", AnyTlsPaddingScheme.CHECK, sizes[i])
        }
        for (i in listOf(2, 4, 6, 8)) {
            assertTrue("position $i out of range: ${sizes[i]}", sizes[i] in 500..1000)
        }
    }

    @Test
    fun `an unshaped packet has no sizes`() {
        assertEquals(emptyList<Int>(), AnyTlsPaddingScheme.DEFAULT.recordSizes(42, random))
    }

    @Test
    fun `a server scheme replaces the default and carries its own digest`() {
        val text = "stop=2\n0=10-10\n1=20-30"
        val scheme = AnyTlsPaddingScheme.parse(text.toByteArray())!!
        assertEquals(listOf(10), scheme.recordSizes(0, random))
        assertTrue(scheme.shapes(1))
        assertTrue(!scheme.shapes(2))
        assertTrue(scheme.md5 != AnyTlsPaddingScheme.DEFAULT.md5)
    }

    @Test
    fun `nonsense is refused so the working scheme survives`() {
        assertNull(AnyTlsPaddingScheme.parse(ByteArray(0)))
        // No stop, no scheme.
        assertNull(AnyTlsPaddingScheme.parse("0=30-30".toByteArray()))
        assertNull(AnyTlsPaddingScheme.parse("stop=x\n0=30-30".toByteArray()))
    }

    // MARK: - Frames

    @Test
    fun `a frame header is big-endian in both fields`() {
        val f = AnyTlsProtocol.frame(AnyTlsProtocol.CMD_PSH, 0x01020304, byteArrayOf(9, 9, 9))
        assertEquals(AnyTlsProtocol.HEADER_SIZE + 3, f.size)
        assertEquals(AnyTlsProtocol.CMD_PSH, f[0])
        assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04), f.copyOfRange(1, 5))
        assertArrayEquals(byteArrayOf(0x00, 0x03), f.copyOfRange(5, 7))
        assertArrayEquals(byteArrayOf(9, 9, 9), f.copyOfRange(7, 10))
    }

    @Test
    fun `a header reads back what was written, including a high stream id`() {
        // Stream ids are an unsigned 32-bit counter; the top bit must survive.
        val f = AnyTlsProtocol.frame(AnyTlsProtocol.CMD_SYN, -1, ByteArray(0))
        val h = AnyTlsProtocol.readHeader(f)
        assertEquals(AnyTlsProtocol.CMD_SYN, h.command)
        assertEquals(-1, h.streamId)
        assertEquals(0, h.length)
    }

    @Test
    fun `a full-length frame encodes its length correctly`() {
        val f = AnyTlsProtocol.frame(AnyTlsProtocol.CMD_PSH, 1, ByteArray(65535))
        assertEquals(65535, AnyTlsProtocol.readHeader(f).length)
    }

    // MARK: - Authentication

    @Test
    fun `authentication is the password digest then the padding length`() {
        val auth = AnyTlsProtocol.authentication("hunter2", 30)
        assertEquals(32 + 2 + 30, auth.size)

        val expected = java.security.MessageDigest.getInstance("SHA-256")
            .digest("hunter2".toByteArray())
        assertArrayEquals(expected, auth.copyOfRange(0, 32))

        // Big-endian uint16, then that many zero bytes.
        assertEquals(0.toByte(), auth[32])
        assertEquals(30.toByte(), auth[33])
        assertTrue(auth.copyOfRange(34, auth.size).all { it == 0.toByte() })
    }

    @Test
    fun `no padding still carries the length field`() {
        val auth = AnyTlsProtocol.authentication("x", 0)
        assertEquals(34, auth.size)
        assertEquals(0.toByte(), auth[32])
        assertEquals(0.toByte(), auth[33])
    }

    // MARK: - Settings

    @Test
    fun `settings name the version, the client and the scheme digest`() {
        val text = String(AnyTlsProtocol.settings("mythaia/1.9", AnyTlsPaddingScheme.DEFAULT.md5))
        assertEquals(
            "v=2\nclient=mythaia/1.9\npadding-md5=75cff2ad89aadf5e257059ee571ebe11",
            text
        )
    }

    @Test
    fun `server settings parse, and an unknown key is not fatal`() {
        val parsed = AnyTlsProtocol.parseSettings("v=2\nsomething=else".toByteArray())
        assertEquals("2", parsed["v"])
        assertEquals("else", parsed["something"])
        assertNull(parsed["absent"])
    }

    // MARK: - Addresses

    @Test
    fun `an address is SOCKS5 form`() {
        assertArrayEquals(
            byteArrayOf(0x01, 1, 2, 3, 4, 0x01, 0xBB.toByte()),
            AnyTlsProtocol.encodeAddress("1.2.3.4", 443)
        )

        val domain = AnyTlsProtocol.encodeAddress("example.com", 80)
        assertEquals(0x03.toByte(), domain[0])
        assertEquals(11.toByte(), domain[1])
        assertEquals("example.com", String(domain.copyOfRange(2, 13)))
        assertArrayEquals(byteArrayOf(0x00, 0x50), domain.copyOfRange(13, 15))

        val v6 = AnyTlsProtocol.encodeAddress("2001:db8::1", 443)
        assertEquals(0x04.toByte(), v6[0])
        assertEquals(1 + 16 + 2, v6.size)
    }

    @Test
    fun `the udp-over-tcp host is the one sing-box expects`() {
        assertEquals("sp.v2.udp-over-tcp.arpa", AnyTlsProtocol.UDP_OVER_TCP_HOST)
    }
}
