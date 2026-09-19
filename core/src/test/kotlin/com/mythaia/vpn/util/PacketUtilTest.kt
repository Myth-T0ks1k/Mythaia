package com.mythaia.vpn.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The packet helpers, which sit directly on untrusted input: every DNS query
 * an app on the device sends arrives here first.
 */
class PacketUtilTest {

    // MARK: - Builders

    private fun query(
        domain: String,
        qtype: Int = 1,
        id: Int = 0x1234,
        qdcount: Int = 1
    ): ByteArray {
        val out = ArrayList<Byte>()
        out.add(((id shr 8) and 0xFF).toByte()); out.add((id and 0xFF).toByte())
        out.add(0x01); out.add(0x00)                         // RD
        out.add(((qdcount shr 8) and 0xFF).toByte()); out.add((qdcount and 0xFF).toByte())
        out.add(0); out.add(0)                               // ANCOUNT
        out.add(0); out.add(0)                               // NSCOUNT
        out.add(0); out.add(0)                               // ARCOUNT

        for (label in domain.split(".")) {
            out.add(label.length.toByte())
            for (b in label.toByteArray(Charsets.US_ASCII)) out.add(b)
        }
        out.add(0)
        out.add(((qtype shr 8) and 0xFF).toByte()); out.add((qtype and 0xFF).toByte())
        out.add(0); out.add(1)                               // QCLASS IN
        return out.toByteArray()
    }

    // MARK: - parseDnsQueryExt

    @Test
    fun `parses a query`() {
        val parsed = PacketUtil.parseDnsQueryExt(query("example.com", qtype = 1))
        assertNotNull(parsed)
        assertEquals("example.com", parsed!!.domain)
        assertEquals(1, parsed.qtype)

        assertEquals(28, PacketUtil.parseDnsQueryExt(query("a.b.example", qtype = 28))!!.qtype)
        assertEquals("a.b.example", PacketUtil.parseDnsQueryExt(query("a.b.example"))!!.domain)
    }

    @Test
    fun `on-wire case is preserved for the caller to fold`() {
        // The doc says callers lowercase; a parser that folded here would make
        // that promise silently untrue and break anything comparing raw names.
        assertEquals("ExAmPlE.CoM", PacketUtil.parseDnsQueryExt(query("ExAmPlE.CoM"))!!.domain)
    }

    @Test
    fun `malformed queries are refused rather than half-parsed`() {
        // Truncated header.
        assertNull(PacketUtil.parseDnsQueryExt(ByteArray(11)))
        // No question.
        assertNull(PacketUtil.parseDnsQueryExt(query("example.com", qdcount = 0)))
        // Empty name.
        assertNull(PacketUtil.parseDnsQueryExt(ByteArray(12) + byteArrayOf(0, 0, 1, 0, 1)))

        // A label that runs past the buffer.
        val overrun = query("example.com")
        overrun[12] = 0x7F
        assertNull(PacketUtil.parseDnsQueryExt(overrun))

        // A compression pointer, which a query should not carry.
        val compressed = query("example.com")
        compressed[12] = 0xC0.toByte()
        assertNull(PacketUtil.parseDnsQueryExt(compressed))
    }

    @Test
    fun `every truncation of a valid query is handled`() {
        val good = query("example.com")
        for (cut in 0 until good.size) {
            // No exception, and no answer invented from bytes that are not there.
            PacketUtil.parseDnsQueryExt(good.copyOfRange(0, cut))
        }
    }

    // MARK: - generateDnsResponse

    @Test
    fun `an A answer carries the address and echoes the question`() {
        val q = query("example.com", qtype = 1)
        val fakeIp = byteArrayOf(198.toByte(), 18, 0, 7)
        val response = PacketUtil.generateDnsResponse(q, fakeIp, 1)
        assertNotNull(response)
        response!!

        // Same transaction id, so the resolver in the app matches it up.
        assertEquals(q[0], response[0])
        assertEquals(q[1], response[1])
        // QR and RA set, one answer.
        assertTrue("QR not set", response[2].toInt() and 0x80 != 0)
        assertEquals(1, be16(response, 6))
        // The question is echoed verbatim.
        assertArrayEquals(q.copyOfRange(12, q.size), response.copyOfRange(12, q.size))

        // The answer: a pointer to the question name, then type A, then the address.
        val ans = q.size
        assertEquals(0xC0.toByte(), response[ans])
        assertEquals(0x0C.toByte(), response[ans + 1])
        assertEquals(1, be16(response, ans + 2))
        assertEquals(1, be16(response, ans + 4))                 // class IN
        assertEquals(4, be16(response, ans + 10))                // RDLENGTH
        assertArrayEquals(fakeIp, response.copyOfRange(ans + 12, ans + 16))
    }

    @Test
    fun `an AAAA answer carries sixteen bytes`() {
        val q = query("example.com", qtype = 28)
        val fakeIp = ByteArray(16).also { it[0] = 0xFC.toByte(); it[15] = 7 }
        val response = PacketUtil.generateDnsResponse(q, fakeIp, 28)!!

        val ans = q.size
        assertEquals(28, be16(response, ans + 2))
        assertEquals(16, be16(response, ans + 10))
        assertArrayEquals(fakeIp, response.copyOfRange(ans + 12, ans + 28))
    }

    @Test
    fun `a null address produces NODATA, not a bogus answer`() {
        // NODATA is how AAAA is refused when IPv6 is off, and how SVCB and DDR
        // are blocked. An answer count above zero here would be a lie.
        val q = query("example.com", qtype = 28)
        val response = PacketUtil.generateDnsResponse(q, null, 28)!!
        assertEquals(0, be16(response, 6))
        assertTrue("QR not set", response[2].toInt() and 0x80 != 0)
        assertEquals(q.size, response.size)
    }

    @Test
    fun `an address of the wrong length is refused rather than truncated`() {
        val q = query("example.com", qtype = 28)
        // Four bytes offered for a AAAA answer: too short, so no answer.
        val response = PacketUtil.generateDnsResponse(q, byteArrayOf(1, 2, 3, 4), 28)!!
        assertEquals(0, be16(response, 6))
    }

    @Test
    fun `a malformed query produces no response`() {
        assertNull(PacketUtil.generateDnsResponse(ByteArray(11), byteArrayOf(1, 2, 3, 4), 1))
    }

    // MARK: - xorNonce

    @Test
    fun `the sequence number is XORed into the tail of the IV`() {
        val iv = ByteArray(12) { 0 }
        assertArrayEquals(ByteArray(12), PacketUtil.xorNonce(iv, 0))

        val one = PacketUtil.xorNonce(iv, 1)
        assertEquals(1.toByte(), one[11])
        assertEquals(0.toByte(), one[10])

        val big = PacketUtil.xorNonce(iv, 0x0102030405060708L)
        assertEquals(0x01.toByte(), big[4])
        assertEquals(0x08.toByte(), big[11])
        // The first four bytes never carry the counter.
        assertArrayEquals(ByteArray(4), big.copyOfRange(0, 4))

        // The input is not modified in place — a shared IV would corrupt every
        // later record.
        assertArrayEquals(ByteArray(12), iv)
    }

    // MARK: - tls13UnwrapContent

    @Test
    fun `unwrapping strips the trailing zero padding and moves the content type to the front`() {
        // The inner plaintext on the wire is content ‖ type ‖ zero padding.
        // The result puts the type first so callers can switch on byte 0.
        val inner = "hello".toByteArray() + byteArrayOf(0x17) + ByteArray(10)
        val unwrapped = PacketUtil.tls13UnwrapContent(inner)
        assertNotNull(unwrapped)
        assertArrayEquals(byteArrayOf(0x17) + "hello".toByteArray(), unwrapped)

        // No padding at all is the same shape.
        assertArrayEquals(
            byteArrayOf(0x16, 1, 2, 3),
            PacketUtil.tls13UnwrapContent(byteArrayOf(1, 2, 3, 0x16))
        )
        // A record that is only a content type unwraps to just that.
        assertArrayEquals(byteArrayOf(0x17), PacketUtil.tls13UnwrapContent(byteArrayOf(0x17)))
    }

    @Test
    fun `all-zero or empty input unwraps to nothing`() {
        assertNull(PacketUtil.tls13UnwrapContent(ByteArray(0)))
        assertNull(PacketUtil.tls13UnwrapContent(ByteArray(8)))
    }

    // MARK: - frameUdpPayload

    @Test
    fun `a UDP payload is length-prefixed big-endian`() {
        val payload = ByteArray(300) { it.toByte() }
        val framed = PacketUtil.frameUdpPayload(payload)
        assertEquals(302, framed.size)
        assertEquals(300, be16(framed, 0))
        assertArrayEquals(payload, framed.copyOfRange(2, framed.size))

        val empty = PacketUtil.frameUdpPayload(ByteArray(0))
        assertEquals(2, empty.size)
        assertEquals(0, be16(empty, 0))
    }

    private fun be16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
}
