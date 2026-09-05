package com.mythaia.vpn.protocol.hysteria

import com.mythaia.vpn.protocol.quic.QuicVarInt
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

/**
 * The expectations here are written out from the Hysteria 2 specification and
 * from the reference implementation's own constants, byte by byte, rather than
 * captured from this encoder. A codec compared only against itself agrees with
 * its own mistakes, and the wire format is the whole contract with the server.
 */
class HysteriaProtocolTest {

    /** Builds a buffer from literal bytes, ASCII/UTF-8 text and other buffers. */
    private fun wire(vararg parts: Any): ByteArray {
        val out = ByteArrayOutputStream()
        for (part in parts) when (part) {
            is Int -> out.write(part)
            is String -> out.write(part.toByteArray(Charsets.UTF_8))
            is ByteArray -> out.write(part)
            else -> throw IllegalArgumentException("unsupported part: $part")
        }
        return out.toByteArray()
    }

    private fun ascii(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    // Constants.

    @Test
    fun `the protocol's numbers are the ones the specification names`() {
        assertEquals(0x401L, HysteriaProtocol.TCP_REQUEST_FRAME_TYPE)
        assertEquals(0x100L, HysteriaProtocol.CLOSE_ERR_CODE_OK)
        assertEquals(0x101L, HysteriaProtocol.CLOSE_ERR_CODE_PROTOCOL_ERROR)
        assertEquals(0.toByte(), HysteriaProtocol.TCP_RESPONSE_STATUS_OK)
        assertEquals(233, HysteriaProtocol.AUTH_SUCCESS_STATUS)

        assertEquals("hysteria", HysteriaProtocol.AUTH_AUTHORITY)
        assertEquals("/auth", HysteriaProtocol.AUTH_PATH)
        assertEquals(":status", HysteriaProtocol.HEADER_STATUS)
        assertEquals("hysteria-auth", HysteriaProtocol.HEADER_AUTH)
        assertEquals("hysteria-cc-rx", HysteriaProtocol.HEADER_CC_RX)
        assertEquals("hysteria-padding", HysteriaProtocol.HEADER_PADDING)
        assertEquals("hysteria-udp", HysteriaProtocol.HEADER_UDP)
        assertEquals("content-length", HysteriaProtocol.HEADER_CONTENT_LENGTH)
        assertEquals("auto", HysteriaProtocol.CC_RX_AUTO)

        assertEquals(256..2047, HysteriaProtocol.AUTH_PADDING_RANGE)
        assertEquals(64..511, HysteriaProtocol.TCP_REQUEST_PADDING_RANGE)

        assertEquals(2048, HysteriaProtocol.MAX_ADDRESS_LENGTH)
        assertEquals(2048, HysteriaProtocol.MAX_RESPONSE_MESSAGE_LENGTH)
        assertEquals(4096, HysteriaProtocol.MAX_PADDING_LENGTH)

        assertEquals(8, HysteriaProtocol.UDP_HEADER_FIXED_SIZE)
        assertEquals(255, HysteriaProtocol.MAX_FRAGMENTS)
    }

    @Test
    fun `the TCP request frame type is two bytes on the wire`() {
        // 0x401 as a QUIC varint (RFC 9000 §16): the two-byte form, prefix 0b01
        // over the value, so 0x0401 becomes 0x4401.
        assertArrayEquals(
            ascii(0x44, 0x01),
            QuicVarInt.encode(HysteriaProtocol.TCP_REQUEST_FRAME_TYPE)
        )
    }

    // Addresses.

    @Test
    fun `an address is host colon port, with IPv6 in brackets`() {
        // RFC 3986 §3.2.2: an IPv6 literal is bracketed so its colons cannot be
        // read as the port separator.
        assertEquals("1.2.3.4:443", HysteriaProtocol.formatAddress("1.2.3.4", 443))
        assertEquals("example.com:80", HysteriaProtocol.formatAddress("example.com", 80))
        assertEquals("[2001:db8::1]:8443", HysteriaProtocol.formatAddress("2001:db8::1", 8443))
        assertEquals("[::1]:53", HysteriaProtocol.formatAddress("::1", 53))
        assertEquals("[fe80::1%eth0]:9", HysteriaProtocol.formatAddress("fe80::1%eth0", 9))
    }

    @Test
    fun `every address form survives a datagram round trip`() {
        val addresses = listOf(
            HysteriaProtocol.formatAddress("1.2.3.4", 443),
            HysteriaProtocol.formatAddress("255.255.255.255", 65535),
            HysteriaProtocol.formatAddress("2001:db8::1", 8443),
            HysteriaProtocol.formatAddress("::1", 53),
            HysteriaProtocol.formatAddress("example.com", 80),
            HysteriaProtocol.formatAddress("a-very-long-subdomain.".repeat(8) + "example.com", 1),
            "münchen.example:80"
        )
        for (address in addresses) {
            val message = HysteriaProtocol.UdpMessage(1, 1, 0, 1, address, ascii(0x01))
            val decoded = HysteriaProtocol.decodeUdpMessage(message.encode())
            assertEquals(address, decoded?.address)
        }
    }

    @Test
    fun `the address length counts bytes, not characters`() {
        // "münchen.example:80" is 18 characters but 19 bytes in UTF-8.
        val address = "münchen.example:80"
        assertEquals(18, address.length)
        assertEquals(19, address.toByteArray(Charsets.UTF_8).size)

        val encoded = HysteriaProtocol.UdpMessage(0, 0, 0, 1, address, ascii(0xFF)).encode()
        assertEquals(19, encoded[HysteriaProtocol.UDP_HEADER_FIXED_SIZE].toInt())
        assertEquals(address, HysteriaProtocol.decodeUdpMessage(encoded)?.address)
    }

    // TCP framing.

    @Test
    fun `a TCP request is the frame type, the address and the padding`() {
        // varint(0x401) | varint(15) | "example.com:443" | varint(4) | "PAD!"
        val expected = wire(0x44, 0x01, 0x0F, "example.com:443", 0x04, "PAD!")
        val actual = HysteriaProtocol.encodeTcpRequest(
            "example.com:443",
            padding = "PAD!".toByteArray(Charsets.US_ASCII)
        )
        assertArrayEquals(expected, actual)
    }

    @Test
    fun `a TCP request with no padding still carries a zero length`() {
        // The padding length field is not optional, so an unpadded request is
        // six bytes of prefix and a lone zero.
        val expected = wire(0x44, 0x01, 0x03, "a:1", 0x00)
        assertArrayEquals(expected, HysteriaProtocol.encodeTcpRequest("a:1", ByteArray(0)))
    }

    @Test
    fun `a long address uses the two-byte length form`() {
        val host = "h".repeat(200)
        val address = "$host:443" // 204 bytes
        assertEquals(204, address.toByteArray(Charsets.UTF_8).size)
        // 204 needs the two-byte varint form: 0x40 | (204 >> 8) = 0x40, then 204.
        val expected = wire(0x44, 0x01, 0x40, 0xCC, address, 0x00)
        assertArrayEquals(expected, HysteriaProtocol.encodeTcpRequest(address, ByteArray(0)))
    }

    @Test
    fun `the default TCP request padding stays inside the reference's range`() {
        repeat(50) {
            val request = HysteriaProtocol.encodeTcpRequest("a:1")
            // 2 (frame type) + 1 (address length) + 3 (address) = 6 bytes of prefix.
            val padLength = QuicVarInt.decode(request, 6)
                ?: throw AssertionError("no padding length in the request")
            assertTrue(
                "padding length ${padLength.value}",
                padLength.value.toInt() in HysteriaProtocol.TCP_REQUEST_PADDING_RANGE
            )
            assertEquals(6 + padLength.size + padLength.value.toInt(), request.size)
        }
    }

    @Test
    fun `a TCP response is a status, a message and padding`() {
        val buffer = wire(0x00, 0x02, "hi", 0x03, "xyz")
        val response = HysteriaProtocol.parseTcpResponse(buffer)
        assertEquals(HysteriaProtocol.TcpResponse(0, "hi", 8), response)
        assertTrue(response!!.isOk)
    }

    @Test
    fun `a non-zero status is a refusal that still carries its message`() {
        val buffer = wire(0x01, 0x0C, "no such host", 0x00)
        val response = HysteriaProtocol.parseTcpResponse(buffer)
        assertEquals(HysteriaProtocol.TcpResponse(1, "no such host", 15), response)
        assertFalse(response!!.isOk)
    }

    @Test
    fun `the consumed count stops at the end of the response`() {
        val payload = "proxied bytes"
        val buffer = wire(0x00, 0x00, 0x02, "ab", payload)
        val response = HysteriaProtocol.parseTcpResponse(buffer)!!
        assertEquals(5, response.consumed)
        assertEquals("", response.message)
        assertArrayEquals(
            payload.toByteArray(Charsets.UTF_8),
            buffer.copyOfRange(response.consumed, buffer.size)
        )
    }

    @Test
    fun `a TCP response is not parsed until every field has arrived`() {
        val whole = wire(0x00, 0x02, "hi", 0x03, "xyz")
        for (length in 0 until whole.size) {
            assertNull(
                "prefix of $length bytes must not parse",
                HysteriaProtocol.parseTcpResponse(whole.copyOfRange(0, length))
            )
        }
        assertNotNull(HysteriaProtocol.parseTcpResponse(whole))
    }

    @Test
    fun `a TCP response refuses lengths past the reference's limits`() {
        // 2049 > MAX_RESPONSE_MESSAGE_LENGTH; two-byte varint 0x48 0x01.
        assertNull(HysteriaProtocol.parseTcpResponse(wire(0x00, 0x48, 0x01)))
        // 4097 > MAX_PADDING_LENGTH; two-byte varint 0x50 0x01.
        assertNull(HysteriaProtocol.parseTcpResponse(wire(0x00, 0x00, 0x50, 0x01)))
    }

    @Test
    fun `a message of exactly the maximum length is still accepted`() {
        val message = "m".repeat(HysteriaProtocol.MAX_RESPONSE_MESSAGE_LENGTH)
        // 2048 as a two-byte varint: 0x40 | (2048 >> 8) = 0x48, then 0x00.
        val buffer = wire(0x00, 0x48, 0x00, message, 0x00)
        val response = HysteriaProtocol.parseTcpResponse(buffer)!!
        assertEquals(message, response.message)
        assertEquals(buffer.size, response.consumed)
    }

    // UDP datagram framing.

    @Test
    fun `a datagram is the fixed header, the address and the payload`() {
        // sessionId(4) | packetId(2) | fragId(1) | fragCount(1) |
        // varint(addrLen) | addr | payload
        val expected = wire(
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
            0x01,
            0x03,
            0x0A, "1.2.3.4:53",
            0xDE, 0xAD, 0xBE, 0xEF
        )
        val message = HysteriaProtocol.UdpMessage(
            sessionId = 0x01020304L,
            packetId = 0x0506,
            fragId = 1,
            fragCount = 3,
            address = "1.2.3.4:53",
            payload = ascii(0xDE, 0xAD, 0xBE, 0xEF)
        )
        assertArrayEquals(expected, message.encode())
        assertEquals(message, HysteriaProtocol.decodeUdpMessage(expected))
    }

    @Test
    fun `the header fields are big-endian at their spec offsets`() {
        val encoded = HysteriaProtocol.UdpMessage(
            sessionId = 0xDEADBEEFL,
            packetId = 0xBEEF,
            fragId = 0x7F,
            fragCount = 0x80,
            address = "a:1",
            payload = ascii(0x00)
        ).encode()
        assertArrayEquals(ascii(0xDE, 0xAD, 0xBE, 0xEF), encoded.copyOfRange(0, 4))
        assertArrayEquals(ascii(0xBE, 0xEF), encoded.copyOfRange(4, 6))
        assertEquals(0x7F, encoded[6].toInt() and 0xFF)
        assertEquals(0x80, encoded[7].toInt() and 0xFF)
    }

    @Test
    fun `the unsigned edges of the header round trip without going negative`() {
        val message = HysteriaProtocol.UdpMessage(
            sessionId = 0xFFFFFFFFL,
            packetId = 0xFFFF,
            fragId = 254,
            fragCount = 255,
            address = "[::1]:65535",
            payload = ascii(0x7F, 0x80)
        )
        val decoded = HysteriaProtocol.decodeUdpMessage(message.encode())!!
        assertEquals(0xFFFFFFFFL, decoded.sessionId)
        assertEquals(0xFFFF, decoded.packetId)
        assertEquals(254, decoded.fragId)
        assertEquals(255, decoded.fragCount)
        assertEquals(message, decoded)
    }

    @Test
    fun `an out of range header field is refused rather than truncated`() {
        for (sessionId in listOf(-1L, 0x1_0000_0000L)) {
            assertThrows { HysteriaProtocol.UdpMessage(sessionId, 0, 0, 1, "a:1", ByteArray(1)) }
        }
        assertThrows { HysteriaProtocol.UdpMessage(0, 0x1_0000, 0, 1, "a:1", ByteArray(1)) }
        assertThrows { HysteriaProtocol.UdpMessage(0, 0, 256, 1, "a:1", ByteArray(1)) }
        assertThrows { HysteriaProtocol.UdpMessage(0, 0, 0, 256, "a:1", ByteArray(1)) }
    }

    @Test
    fun `a truncated datagram is rejected rather than misparsed`() {
        val whole = wire(0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x03, "a:1", 0xAA)
        assertNotNull(HysteriaProtocol.decodeUdpMessage(whole))
        for (length in 0 until whole.size) {
            assertNull(
                "prefix of $length bytes must not parse",
                HysteriaProtocol.decodeUdpMessage(whole.copyOfRange(0, length))
            )
        }
    }

    @Test
    fun `a datagram whose address length overruns the buffer is rejected`() {
        // A two-byte varint saying 200 (0x40 0xC8), with three address bytes.
        assertNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x40, 0xC8, "a:1", 0xAA)))
        // An eight-byte length varint that the datagram is too short to hold.
        assertNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0xC0, 0x00, 0x00)))
    }

    @Test
    fun `a datagram with no payload after the address is rejected`() {
        // The address ends exactly at the end of the datagram, so there is
        // nothing to forward; a stream of these would otherwise take a
        // reassembly slot each.
        assertNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, "a:1")))
        // One payload byte is enough.
        assertNotNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, "a:1", 0x00)))
    }

    @Test
    fun `a datagram with an empty or oversized address is rejected`() {
        assertNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x00, 0xAA)))
        // 2049 > MAX_ADDRESS_LENGTH; two-byte varint 0x48 0x01.
        assertNull(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x48, 0x01, 0xAA)))
    }

    @Test
    fun `an address that is not valid UTF-8 is rejected, not replaced`() {
        // 0xFF and 0xFE never appear in UTF-8; substituting U+FFFD here would
        // mean proxying to a destination nobody named.
        assertNull(
            HysteriaProtocol.decodeUdpMessage(
                wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, ascii(0x61, 0xFF, 0xFE), 0xAA)
            )
        )
    }

    @Test
    fun `the header size matches what encoding actually spends`() {
        assertEquals(8 + 1 + 10, HysteriaProtocol.udpHeaderSize("1.2.3.4:53"))

        val longAddress = "h".repeat(96) + ":443" // 100 bytes, two-byte varint
        assertEquals(100, longAddress.toByteArray(Charsets.UTF_8).size)
        assertEquals(8 + 2 + 100, HysteriaProtocol.udpHeaderSize(longAddress))

        for (address in listOf("1.2.3.4:53", longAddress, "münchen.example:80")) {
            val payload = ByteArray(37) { it.toByte() }
            val encoded = HysteriaProtocol.UdpMessage(1, 1, 0, 1, address, payload).encode()
            assertEquals(HysteriaProtocol.udpHeaderSize(address), encoded.size - payload.size)
        }
    }

    // Fragmentation.

    @Test
    fun `a payload that fits is one unfragmented message`() {
        val address = "1.2.3.4:53"
        val headerSize = HysteriaProtocol.udpHeaderSize(address) // 19
        val payload = ByteArray(10) { it.toByte() }

        val fragments = HysteriaProtocol.fragmentUdp(7, 9, address, payload, headerSize + 10)
        assertEquals(1, fragments.size)
        assertEquals(0, fragments[0].fragId)
        assertEquals(1, fragments[0].fragCount)
        assertArrayEquals(payload, fragments[0].payload)
        assertEquals(headerSize + 10, fragments[0].encode().size)
    }

    @Test
    fun `one byte too many becomes two fragments`() {
        val address = "1.2.3.4:53"
        val headerSize = HysteriaProtocol.udpHeaderSize(address)
        val payload = ByteArray(11) { it.toByte() }

        val fragments = HysteriaProtocol.fragmentUdp(7, 9, address, payload, headerSize + 10)
        assertEquals(2, fragments.size)
        assertEquals(10, fragments[0].payload.size)
        assertEquals(1, fragments[1].payload.size)
        assertTrue(fragments.all { it.fragCount == 2 })
        assertEquals(listOf(0, 1), fragments.map { it.fragId })
    }

    @Test
    fun `fragments are numbered in order and none exceeds the datagram budget`() {
        val address = "1.2.3.4:53"
        val headerSize = HysteriaProtocol.udpHeaderSize(address)
        val maxDatagramSize = headerSize + 10
        val payload = ByteArray(25) { (it + 1).toByte() }

        val fragments = HysteriaProtocol.fragmentUdp(0x11223344, 0x0102, address, payload, maxDatagramSize)
        assertEquals(3, fragments.size)
        assertEquals(listOf(10, 10, 5), fragments.map { it.payload.size })

        fragments.forEachIndexed { index, fragment ->
            assertEquals(index, fragment.fragId)
            assertEquals(3, fragment.fragCount)
            assertEquals(0x11223344L, fragment.sessionId)
            assertEquals(0x0102, fragment.packetId)
            assertEquals(address, fragment.address)
            assertTrue(fragment.encode().size <= maxDatagramSize)
        }

        val rejoined = ByteArrayOutputStream()
        fragments.forEach { rejoined.write(it.payload) }
        assertArrayEquals(payload, rejoined.toByteArray())
    }

    @Test
    fun `a payload needing more than 255 fragments cannot be framed`() {
        val address = "1.2.3.4:53"
        val headerSize = HysteriaProtocol.udpHeaderSize(address)
        val maxDatagramSize = headerSize + 10

        // Exactly 255 chunks is the most a one-byte fragment count can express.
        val atLimit = HysteriaProtocol.fragmentUdp(1, 1, address, ByteArray(2550), maxDatagramSize)
        assertEquals(255, atLimit.size)
        assertEquals(255, atLimit.last().fragCount)

        val overLimit = HysteriaProtocol.fragmentUdp(1, 1, address, ByteArray(2551), maxDatagramSize)
        assertTrue(overLimit.isEmpty())
    }

    // Reassembly.

    @Test
    fun `the defragmenter's bounds are the reference's`() {
        assertEquals(32, HysteriaDefragmenter.MAX_SLOTS)
        assertEquals(10L * 1_000_000_000L, HysteriaDefragmenter.SLOT_TTL_NANOS)
    }

    @Test
    fun `an unfragmented message passes straight through`() {
        val defragmenter = HysteriaDefragmenter()
        val payload = ascii(0x01, 0x02)
        val whole = HysteriaProtocol.UdpMessage(1, 1, 0, 1, "a:1", payload)
        assertArrayEquals(payload, defragmenter.accept(whole))
        assertEquals(0, defragmenter.slotCount)
    }

    @Test
    fun `fragments arriving in order reassemble on the last one`() {
        val defragmenter = HysteriaDefragmenter()
        val payload = ByteArray(25) { (it + 1).toByte() }
        val fragments = HysteriaProtocol.fragmentUdp(1, 42, "a:1", payload, HysteriaProtocol.udpHeaderSize("a:1") + 10)

        assertNull(defragmenter.accept(fragments[0]))
        assertNull(defragmenter.accept(fragments[1]))
        assertArrayEquals(payload, defragmenter.accept(fragments[2]))
        assertEquals(0, defragmenter.slotCount)
    }

    @Test
    fun `fragments arriving out of order reassemble in the right order`() {
        val payload = ByteArray(25) { (it + 1).toByte() }
        val fragments = HysteriaProtocol.fragmentUdp(1, 42, "a:1", payload, HysteriaProtocol.udpHeaderSize("a:1") + 10)

        for (order in listOf(listOf(2, 0, 1), listOf(1, 2, 0), listOf(2, 1, 0))) {
            val defragmenter = HysteriaDefragmenter()
            val results = order.map { defragmenter.accept(fragments[it]) }
            assertNull(results[0])
            assertNull(results[1])
            assertArrayEquals("order $order", payload, results[2])
            assertEquals(0, defragmenter.slotCount)
        }
    }

    @Test
    fun `a repeated fragment cannot complete a packet that is still short`() {
        val defragmenter = HysteriaDefragmenter()
        val payload = ByteArray(25) { (it + 1).toByte() }
        val fragments = HysteriaProtocol.fragmentUdp(1, 42, "a:1", payload, HysteriaProtocol.udpHeaderSize("a:1") + 10)

        assertNull(defragmenter.accept(fragments[0]))
        assertNull(defragmenter.accept(fragments[0]))
        assertNull(defragmenter.accept(fragments[0]))
        assertNull(defragmenter.accept(fragments[1]))
        assertArrayEquals(payload, defragmenter.accept(fragments[2]))
    }

    @Test
    fun `two packets in flight at once stay apart`() {
        val defragmenter = HysteriaDefragmenter()
        val address = "a:1"
        val budget = HysteriaProtocol.udpHeaderSize(address) + 10
        val first = ByteArray(15) { 0x11.toByte() }
        val second = ByteArray(15) { 0x22.toByte() }
        val a = HysteriaProtocol.fragmentUdp(1, 100, address, first, budget)
        val b = HysteriaProtocol.fragmentUdp(1, 200, address, second, budget)

        assertNull(defragmenter.accept(a[0]))
        assertNull(defragmenter.accept(b[1]))
        assertEquals(2, defragmenter.slotCount)
        assertArrayEquals(second, defragmenter.accept(b[0]))
        assertArrayEquals(first, defragmenter.accept(a[1]))
        assertEquals(0, defragmenter.slotCount)
    }

    @Test
    fun `a fragment index past the fragment count opens no slot`() {
        val defragmenter = HysteriaDefragmenter()
        val bogus = HysteriaProtocol.UdpMessage(1, 5, fragId = 3, fragCount = 3, address = "a:1", payload = ascii(0x01))
        assertNull(defragmenter.accept(bogus))
        assertEquals(0, defragmenter.slotCount)
    }

    @Test
    fun `a stale half-assembled packet is dropped rather than joined years later`() {
        var now = 0L
        val defragmenter = HysteriaDefragmenter(clock = { now })
        val payload = ByteArray(15) { (it + 1).toByte() }
        val fragments = HysteriaProtocol.fragmentUdp(1, 42, "a:1", payload, HysteriaProtocol.udpHeaderSize("a:1") + 10)

        assertNull(defragmenter.accept(fragments[0]))
        now = HysteriaDefragmenter.SLOT_TTL_NANOS + 1

        // The slot has expired, so the second fragment starts a fresh one and
        // the packet is not completed by the piece that arrived too long ago.
        assertNull(defragmenter.accept(fragments[1]))
        assertEquals(1, defragmenter.slotCount)
        // The re-sent first fragment completes the new slot.
        assertArrayEquals(payload, defragmenter.accept(fragments[0]))
    }

    @Test
    fun `the reassembly table never grows past its bound`() {
        val defragmenter = HysteriaDefragmenter(maxSlots = 4, clock = { 0L })
        repeat(20) { index ->
            val fragment = HysteriaProtocol.UdpMessage(1, index, fragId = 0, fragCount = 2, address = "a:1", payload = ascii(index))
            assertNull(defragmenter.accept(fragment))
            assertTrue("after $index packets", defragmenter.slotCount <= 4)
        }
        assertEquals(4, defragmenter.slotCount)
    }

    @Test
    fun `clearing drops everything in flight`() {
        val defragmenter = HysteriaDefragmenter()
        val fragment = HysteriaProtocol.UdpMessage(1, 1, 0, 2, "a:1", ascii(0x01))
        assertNull(defragmenter.accept(fragment))
        assertEquals(1, defragmenter.slotCount)
        defragmenter.clear()
        assertEquals(0, defragmenter.slotCount)
    }

    @Test
    fun `a payload survives fragmentation, the wire and shuffled reassembly`() {
        val address = HysteriaProtocol.formatAddress("2001:db8::1", 5353)
        val budget = HysteriaProtocol.udpHeaderSize(address) + 64
        val payload = ByteArray(1000) { ((it * 31) and 0xFF).toByte() }

        val datagrams = HysteriaProtocol
            .fragmentUdp(0xFEEDFACEL, 0xABCD, address, payload, budget)
            .map { it.encode() }
        assertEquals(16, datagrams.size)
        assertTrue(datagrams.all { it.size <= budget })

        val defragmenter = HysteriaDefragmenter()
        var assembled: ByteArray? = null
        // Reversed, so the final fragment is the first one seen.
        for (datagram in datagrams.reversed()) {
            val message = HysteriaProtocol.decodeUdpMessage(datagram)!!
            assertEquals(0xFEEDFACEL, message.sessionId)
            assertEquals(0xABCD, message.packetId)
            assertEquals(address, message.address)
            val result = defragmenter.accept(message)
            if (result != null) {
                assertNull("completed more than once", assembled)
                assembled = result
            }
        }
        assertArrayEquals(payload, assembled)
    }

    // Padding.

    @Test
    fun `padding is drawn from the alphabet the reference uses`() {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        assertEquals(62, alphabet.length)

        val padding = HysteriaProtocol.randomPadding(4096)
        assertEquals(4096, padding.size)
        for (byte in padding) {
            assertTrue("byte $byte is outside the alphabet", alphabet.contains(byte.toInt().toChar()))
        }
    }

    @Test
    fun `no padding at all is an empty buffer, not a crash`() {
        assertEquals(0, HysteriaProtocol.randomPadding(0).size)
        assertEquals(0, HysteriaProtocol.randomPadding(-1).size)
    }

    @Test
    fun `the auth padding header stays inside the reference's range`() {
        repeat(50) {
            val padding = HysteriaProtocol.randomPaddingString()
            assertTrue("length ${padding.length}", padding.length in HysteriaProtocol.AUTH_PADDING_RANGE)
            assertTrue(padding.all { it.isLetterOrDigit() && it.code < 128 })
        }
    }

    @Test
    fun `padding differs between calls`() {
        val first = HysteriaProtocol.randomPadding(256)
        val second = HysteriaProtocol.randomPadding(256)
        assertFalse(first.contentEquals(second))
    }

    // Authentication.

    @Test
    fun `the auth request carries the password, the rate and the padding`() {
        val headers = HysteriaProtocol.authRequestHeaders("hunter2", 12_500_000L, padding = "PAD")
        assertEquals(
            listOf(
                "hysteria-auth" to "hunter2",
                "hysteria-cc-rx" to "12500000",
                "hysteria-padding" to "PAD",
                "content-length" to "0"
            ),
            headers
        )
    }

    @Test
    fun `a rate of zero is what asks the server to measure for itself`() {
        val headers = HysteriaProtocol.authRequestHeaders("p", 0L, padding = "")
        assertEquals("0", headers.first { it.first == "hysteria-cc-rx" }.second)
    }

    @Test
    fun `status 233 is the only acceptance`() {
        val accepted = HysteriaProtocol.parseAuthResponse(
            listOf(":status" to "233", "hysteria-udp" to "true", "hysteria-cc-rx" to "1000")
        )!!
        assertTrue(accepted.isAccepted)
        assertTrue(accepted.udpSupported)
        assertEquals(1000L, accepted.serverRxBytesPerSec)

        for (status in listOf("200", "232", "234", "404", "500")) {
            val response = HysteriaProtocol.parseAuthResponse(listOf(":status" to status))!!
            assertFalse("status $status", response.isAccepted)
            assertEquals(status.toInt(), response.status)
        }
    }

    @Test
    fun `UDP support is off unless the server says true`() {
        fun udp(value: String?) = HysteriaProtocol.parseAuthResponse(
            listOfNotNull(":status" to "233", value?.let { "hysteria-udp" to it })
        )!!.udpSupported

        assertTrue(udp("true"))
        assertTrue(udp("True"))
        assertTrue(udp("TRUE"))
        assertFalse(udp("false"))
        assertFalse(udp("1"))
        assertFalse(udp("yes"))
        assertFalse(udp(""))
        assertFalse(udp(null))
    }

    @Test
    fun `auto is a different answer from a declared rate of zero`() {
        fun rate(value: String?) = HysteriaProtocol.parseAuthResponse(
            listOfNotNull(":status" to "233", value?.let { "hysteria-cc-rx" to it })
        )!!.serverRxBytesPerSec

        assertNull(rate("auto"))
        assertNull(rate("AUTO"))
        assertEquals(0L, rate("0"))
        assertEquals(0L, rate("not a number"))
        assertEquals(0L, rate(null))
        assertEquals(4_294_967_296L, rate("4294967296"))
    }

    @Test
    fun `a reply without a usable status is a failure, not a refusal`() {
        assertNull(HysteriaProtocol.parseAuthResponse(emptyList()))
        assertNull(HysteriaProtocol.parseAuthResponse(listOf("hysteria-udp" to "true")))
        assertNull(HysteriaProtocol.parseAuthResponse(listOf(":status" to "two hundred")))
        assertNull(HysteriaProtocol.parseAuthResponse(listOf(":status" to "")))
        // HTTP/3 lowercases header names, so a capitalised one is not a match.
        assertNull(HysteriaProtocol.parseAuthResponse(listOf(":Status" to "233")))
    }

    private fun assertThrows(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        }
        throw AssertionError("expected the argument to be refused")
    }
}
