package com.mythaia.vpn.protocol.tuic

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.UUID

/**
 * The TUIC v5 wire format, against the field widths its specification prints.
 *
 * Every expected byte here is written out by hand from SPEC.md rather than
 * taken from the encoder, because an encoder and a decoder that were written
 * together agree with each other whether or not either agrees with a server.
 */
class TuicProtocolTest {

    private fun hex(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun `the command and address type numbers are the ones the spec assigns`() {
        assertEquals(0x05.toByte(), TuicProtocol.VERSION)
        assertEquals(0x00.toByte(), TuicProtocol.CMD_AUTHENTICATE)
        assertEquals(0x01.toByte(), TuicProtocol.CMD_CONNECT)
        assertEquals(0x02.toByte(), TuicProtocol.CMD_PACKET)
        assertEquals(0x03.toByte(), TuicProtocol.CMD_DISSOCIATE)
        assertEquals(0x04.toByte(), TuicProtocol.CMD_HEARTBEAT)

        assertEquals(0xFF.toByte(), TuicProtocol.ADDR_NONE)
        assertEquals(0x00.toByte(), TuicProtocol.ADDR_DOMAIN)
        assertEquals(0x01.toByte(), TuicProtocol.ADDR_IPV4)
        assertEquals(0x02.toByte(), TuicProtocol.ADDR_IPV6)
    }

    @Test
    fun `authenticate is version, type, sixteen bytes of uuid, then the token`() {
        val uuid = UUID.fromString("01020304-0506-0708-090a-0b0c0d0e0f10")
        val token = ByteArray(32) { 0xAB.toByte() }
        val encoded = TuicProtocol.authenticate(uuid, token)

        assertEquals(2 + 16 + 32, encoded.size)
        assertEquals(0x05.toByte(), encoded[0])
        assertEquals(0x00.toByte(), encoded[1])
        // The UUID goes on the wire big-endian, most significant byte first.
        assertArrayEquals(
            hex(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10),
            encoded.copyOfRange(2, 18)
        )
        assertArrayEquals(token, encoded.copyOfRange(18, 50))
    }

    @Test
    fun `a token of the wrong length is refused rather than padded`() {
        try {
            TuicProtocol.authenticate(UUID.randomUUID(), ByteArray(16))
            throw AssertionError("expected a refusal")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `connect carries the address and nothing else`() {
        val encoded = TuicProtocol.connect("1.2.3.4", 443)
        assertArrayEquals(hex(0x05, 0x01, 0x01, 1, 2, 3, 4, 0x01, 0xBB), encoded)
    }

    @Test
    fun `a domain address is a length byte then the name then the port`() {
        val encoded = TuicProtocol.connect("example.com", 80)
        assertArrayEquals(
            hex(0x05, 0x01, 0x00, 11) + "example.com".toByteArray() + hex(0x00, 0x50),
            encoded
        )
    }

    @Test
    fun `an IPv6 address takes sixteen bytes under its own type`() {
        val encoded = TuicProtocol.connect("2001:db8::1", 443)
        assertEquals(2 + 1 + 16 + 2, encoded.size)
        assertEquals(0x02.toByte(), encoded[2])
    }

    @Test
    fun `a hostname is never resolved while encoding`() {
        // InetAddress.getByName on a name performs a DNS lookup; doing that
        // here would resolve on whichever thread happened to send a packet.
        val encoded = TuicProtocol.connect("localhost", 80)
        assertEquals(TuicProtocol.ADDR_DOMAIN, encoded[2])
    }

    @Test
    fun `dissociate and heartbeat are the shortest commands there are`() {
        assertArrayEquals(hex(0x05, 0x03, 0x12, 0x34), TuicProtocol.dissociate(0x1234))
        assertArrayEquals(hex(0x05, 0x04), TuicProtocol.heartbeat())
    }

    @Test
    fun `a packet header is eight bytes in the order the spec prints`() {
        val packet = TuicProtocol.Packet(
            associationId = 0x0102,
            packetId = 0x0304,
            fragmentTotal = 3,
            fragmentId = 0,
            host = "1.2.3.4",
            port = 53,
            payload = byteArrayOf(9, 9)
        )
        val encoded = TuicProtocol.packet(packet)

        // ver type assoc(2) pkt(2) total(1) frag(1) size(2) then the address.
        assertArrayEquals(
            hex(0x05, 0x02, 0x01, 0x02, 0x03, 0x04, 0x03, 0x00, 0x00, 0x02),
            encoded.copyOfRange(0, 10)
        )
        assertArrayEquals(hex(0x01, 1, 2, 3, 4, 0x00, 0x35), encoded.copyOfRange(10, 17))
        assertArrayEquals(hex(9, 9), encoded.copyOfRange(17, 19))
    }

    @Test
    fun `only the first fragment carries an address`() {
        // Repeating it would waste room in every fragment of a datagram that
        // was split precisely because room was short.
        val later = TuicProtocol.packet(
            TuicProtocol.Packet(1, 1, 3, 1, "example.com", 53, byteArrayOf(7))
        )
        assertEquals(TuicProtocol.ADDR_NONE, later[10])
        assertEquals(2 + 8 + 1 + 1, later.size)
    }

    @Test
    fun `a packet decodes back to what was encoded`() {
        val original = TuicProtocol.Packet(
            associationId = 65535,
            packetId = 4242,
            fragmentTotal = 1,
            fragmentId = 0,
            host = "example.com",
            port = 5353,
            payload = ByteArray(100) { it.toByte() }
        )
        assertEquals(original, TuicProtocol.parsePacket(TuicProtocol.packet(original)))
    }

    @Test
    fun `a later fragment decodes with no address`() {
        val original = TuicProtocol.Packet(1, 2, 4, 2, null, 0, byteArrayOf(1, 2, 3))
        val decoded = TuicProtocol.parsePacket(TuicProtocol.packet(original))
        assertNull(decoded!!.host)
        assertEquals(2, decoded.fragmentId)
        assertArrayEquals(byteArrayOf(1, 2, 3), decoded.payload)
    }

    @Test
    fun `a truncated or wrong-typed packet is dropped, not misread`() {
        // These arrive in unreliable datagrams, so a short one is ordinary.
        assertNull(TuicProtocol.parsePacket(ByteArray(0)))
        assertNull(TuicProtocol.parsePacket(hex(0x05, 0x02, 0x00)))
        // A size field claiming more payload than the datagram holds.
        assertNull(TuicProtocol.parsePacket(hex(0x05, 0x02, 0, 1, 0, 1, 1, 0, 0xFF, 0xFF, 0xFF)))
        // Wrong version.
        assertNull(TuicProtocol.parsePacket(hex(0x04, 0x02, 0, 1, 0, 1, 1, 0, 0, 0, 0xFF)))
        // Wrong command.
        assertNull(TuicProtocol.parsePacket(hex(0x05, 0x01, 0, 1, 0, 1, 1, 0, 0, 0, 0xFF)))
    }

    @Test
    fun `an address type the spec does not define is refused`() {
        assertNull(TuicProtocol.parseAddress(hex(0x7F, 1, 2, 3, 4, 0, 80), 0))
    }

    @Test
    fun `an address that runs past the buffer is refused`() {
        assertNull(TuicProtocol.parseAddress(hex(0x01, 1, 2), 0))
        assertNull(TuicProtocol.parseAddress(hex(0x00, 20, 0x61), 0))
        assertNull(TuicProtocol.parseAddress(ByteArray(0), 0))
    }

    @Test
    fun `a none address occupies exactly one byte`() {
        val address = TuicProtocol.parseAddress(hex(0xFF), 0)
        assertNull(address!!.host)
        assertEquals(1, address.size)
    }
}
