package com.mythaia.vpn.protocol.vless

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/**
 * The VLESS request header — the app's primary protocol.
 *
 * Every field is fixed width and there is no length prefix on the header as a
 * whole, so the server reads it positionally: a byte in the wrong place shifts
 * everything after it and the connection fails in a way that looks like a
 * network problem.
 */
class VlessProtocolTest {

    private val uuid: UUID = UUID.fromString("b831381d-6324-4d53-ad4f-8cda48b30811")

    // MARK: - uuidToBytes

    @Test
    fun `a UUID becomes its sixteen big-endian bytes`() {
        val bytes = VlessProtocol.uuidToBytes(uuid)
        assertEquals(16, bytes.size)
        assertEquals(0xb8.toByte(), bytes[0])
        assertEquals(0x31.toByte(), bytes[1])
        assertEquals(0x38.toByte(), bytes[2])
        assertEquals(0x1d.toByte(), bytes[3])
        assertEquals(0x11.toByte(), bytes[15])

        // Independently: the canonical text with its dashes removed is the hex
        // of these bytes.
        assertEquals(
            uuid.toString().replace("-", ""),
            bytes.joinToString("") { "%02x".format(it) }
        )
    }

    @Test
    fun `the all-zero and all-ones UUIDs survive the sign of a byte`() {
        assertArrayEquals(
            ByteArray(16),
            VlessProtocol.uuidToBytes(UUID(0L, 0L))
        )
        assertArrayEquals(
            ByteArray(16) { 0xFF.toByte() },
            VlessProtocol.uuidToBytes(UUID(-1L, -1L))
        )
    }

    // MARK: - Request header

    @Test
    fun `a TCP request to a hostname has the documented layout`() {
        val header = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "example.com", 443
        )

        var at = 0
        assertEquals(0x00.toByte(), header[at]); at += 1              // version
        assertArrayEquals(
            VlessProtocol.uuidToBytes(uuid),
            header.copyOfRange(at, at + 16)
        ); at += 16
        assertEquals(0, header[at].toInt()); at += 1                  // no addons
        assertEquals(VlessCommand.TCP.value, header[at]); at += 1
        // Port is big-endian, unlike the little-endian fields other protocols use.
        assertEquals(0x01.toByte(), header[at]); at += 1
        assertEquals(0xBB.toByte(), header[at]); at += 1
        assertEquals(VlessAddressType.DOMAIN.value, header[at]); at += 1
        assertEquals("example.com".length, header[at].toInt() and 0xFF); at += 1
        assertArrayEquals(
            "example.com".toByteArray(),
            header.copyOfRange(at, at + "example.com".length)
        ); at += "example.com".length

        assertEquals(header.size, at)
    }

    @Test
    fun `an IPv4 destination uses the address form, not the name form`() {
        val header = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "93.184.216.34", 80
        )
        // version + uuid + addons length + command + port
        val typeAt = 1 + 16 + 1 + 1 + 2
        assertEquals(VlessAddressType.IPV4.value, header[typeAt])
        assertArrayEquals(
            byteArrayOf(93, 184.toByte(), 216.toByte(), 34),
            header.copyOfRange(typeAt + 1, typeAt + 5)
        )
        assertEquals(typeAt + 5, header.size)
    }

    @Test
    fun `an IPv6 destination uses sixteen bytes`() {
        val header = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "2001:db8::1", 443
        )
        val typeAt = 1 + 16 + 1 + 1 + 2
        assertEquals(VlessAddressType.IPV6.value, header[typeAt])
        assertEquals(0x20.toByte(), header[typeAt + 1])
        assertEquals(0x01.toByte(), header[typeAt + 2])
        assertEquals(0x01.toByte(), header[typeAt + 16])
        assertEquals(typeAt + 17, header.size)
    }

    @Test
    fun `the port is big-endian across its range`() {
        for (port in listOf(1, 80, 443, 8080, 32768, 65535)) {
            val header = VlessProtocol.encodeRequestHeader(
                uuid, VlessCommand.TCP, "93.184.216.34", port
            )
            val portAt = 1 + 16 + 1 + 1
            val encoded = ((header[portAt].toInt() and 0xFF) shl 8) or
                (header[portAt + 1].toInt() and 0xFF)
            assertEquals("port $port", port, encoded)
        }
    }

    @Test
    fun `the MUX command carries no destination at all`() {
        // A mux session multiplexes many destinations, so the header must stop
        // after the command; sending an address would shift every later field
        // for the server.
        val header = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.MUX, "example.com", 443
        )
        assertEquals(1 + 16 + 1 + 1, header.size)
        assertEquals(VlessCommand.MUX.value, header[header.size - 1])
    }

    @Test
    fun `a flow is carried as a length-delimited protobuf field`() {
        val flow = "xtls-rprx-vision"
        val header = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "example.com", 443, flow
        )

        val addonsLengthAt = 1 + 16
        val addonsLength = header[addonsLengthAt].toInt() and 0xFF
        assertEquals(2 + flow.length, addonsLength)

        // Field 1, wire type 2 (length-delimited), then the length, then the text.
        assertEquals(0x0A.toByte(), header[addonsLengthAt + 1])
        assertEquals(flow.length, header[addonsLengthAt + 2].toInt() and 0xFF)
        assertArrayEquals(
            flow.toByteArray(),
            header.copyOfRange(addonsLengthAt + 3, addonsLengthAt + 3 + flow.length)
        )
        // The command follows the addons, not the addons-length byte.
        assertEquals(VlessCommand.TCP.value, header[addonsLengthAt + 1 + addonsLength])
    }

    @Test
    fun `no flow means a zero addons length and nothing else`() {
        val withoutFlow = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "example.com", 443, null
        )
        val withEmptyFlow = VlessProtocol.encodeRequestHeader(
            uuid, VlessCommand.TCP, "example.com", 443, ""
        )
        assertArrayEquals(withoutFlow, withEmptyFlow)
        assertEquals(0, withoutFlow[1 + 16].toInt())
    }

    // MARK: - Response header

    @Test
    fun `a response header reports the bytes it consumed`() {
        // version 0, no addons.
        assertEquals(2, VlessProtocol.decodeResponseHeader(byteArrayOf(0, 0, 1, 2, 3)))
        // version 0, three addon bytes.
        assertEquals(5, VlessProtocol.decodeResponseHeader(byteArrayOf(0, 3, 9, 9, 9, 1, 2)))
    }

    @Test
    fun `an incomplete response header consumes nothing`() {
        // Zero means "wait for more", so returning a length here would make the
        // caller skip bytes that had not arrived.
        assertEquals(0, VlessProtocol.decodeResponseHeader(byteArrayOf()))
        assertEquals(0, VlessProtocol.decodeResponseHeader(byteArrayOf(0)))
        assertEquals(0, VlessProtocol.decodeResponseHeader(byteArrayOf(0, 5, 1, 2)))
    }

    @Test
    fun `a response of another version consumes nothing`() {
        assertEquals(0, VlessProtocol.decodeResponseHeader(byteArrayOf(1, 0)))
        assertEquals(0, VlessProtocol.decodeResponseHeader(byteArrayOf(0xFF.toByte(), 0)))
    }

    @Test
    fun `the offset is honoured`() {
        val buffer = byteArrayOf(9, 9, 0, 0, 1, 2)
        assertEquals(2, VlessProtocol.decodeResponseHeader(buffer, offset = 2))
        assertEquals(0, VlessProtocol.decodeResponseHeader(buffer, offset = 5))
    }

    // MARK: - Enums

    @Test
    fun `command and address-type values match the wire`() {
        assertEquals(1.toByte(), VlessCommand.TCP.value)
        assertEquals(2.toByte(), VlessCommand.UDP.value)
        assertEquals(3.toByte(), VlessCommand.MUX.value)
        assertEquals(1.toByte(), VlessAddressType.IPV4.value)
        assertEquals(2.toByte(), VlessAddressType.DOMAIN.value)
        assertEquals(3.toByte(), VlessAddressType.IPV6.value)

        for (command in VlessCommand.entries) {
            assertEquals(command, VlessCommand.fromByte(command.value))
        }
        for (type in VlessAddressType.entries) {
            assertEquals(type, VlessAddressType.fromByte(type.value))
        }
        assertNull(VlessCommand.fromByte(9))
        assertNull(VlessAddressType.fromByte(9))
        assertTrue(true)
    }
}
