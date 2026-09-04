package com.mythaia.vpn.protocol.trojan

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Trojan's wire encoding.
 *
 * The server compares the password hash byte for byte and falls back to its
 * decoy site on any mismatch, so a wrong byte anywhere here looks like a
 * working connection to an unrelated website rather than an error.
 */
class TrojanProtocolTest {

    // MARK: - passwordKey

    @Test
    fun `the password key is SHA-224 as 56 lowercase hex bytes`() {
        val password = "correct horse battery staple"
        val key = TrojanProtocol.passwordKey(password)

        assertEquals(56, key.size)

        // Computed independently rather than by the same helper.
        val digest = MessageDigest.getInstance("SHA-224")
            .digest(password.toByteArray(Charsets.UTF_8))
        val expected = digest.joinToString("") { "%02x".format(it) }
        assertEquals(expected, String(key, Charsets.US_ASCII))

        // Lowercase specifically: an uppercase rendering hashes to a different
        // string on the server side and silently lands on the decoy site.
        assertTrue(key.none { it.toInt().toChar() in 'A'..'F' })
    }

    @Test
    fun `a non-ASCII password hashes its UTF-8 bytes`() {
        val password = "пароль密碼"
        val key = TrojanProtocol.passwordKey(password)
        val digest = MessageDigest.getInstance("SHA-224")
            .digest(password.toByteArray(Charsets.UTF_8))
        assertEquals(
            digest.joinToString("") { "%02x".format(it) },
            String(key, Charsets.US_ASCII)
        )
    }

    // MARK: - encodeAddressPort

    @Test
    fun `an IPv4 destination encodes as type 1 and four bytes`() {
        val encoded = TrojanProtocol.encodeAddressPort("93.184.216.34", 443)
        assertArrayEquals(
            byteArrayOf(0x01, 93, 184.toByte(), 216.toByte(), 34, 0x01, 0xBB.toByte()),
            encoded
        )
    }

    @Test
    fun `an IPv6 destination encodes as type 4 and sixteen bytes`() {
        val encoded = TrojanProtocol.encodeAddressPort("2001:db8::1", 8080)
        assertEquals(1 + 16 + 2, encoded.size)
        assertEquals(0x04.toByte(), encoded[0])
        assertEquals(0x20.toByte(), encoded[1])
        assertEquals(0x01.toByte(), encoded[2])
        assertEquals(0x1F.toByte(), encoded[17])          // 8080 = 0x1F90
        assertEquals(0x90.toByte(), encoded[18])
    }

    @Test
    fun `a hostname encodes as type 3 with a length prefix`() {
        val encoded = TrojanProtocol.encodeAddressPort("example.com", 443)
        assertEquals(0x03.toByte(), encoded[0])
        assertEquals("example.com".length, encoded[1].toInt() and 0xFF)
        assertArrayEquals(
            "example.com".toByteArray(),
            encoded.copyOfRange(2, 2 + "example.com".length)
        )
        assertEquals(0x01BB, be16(encoded, encoded.size - 2))
    }

    @Test
    fun `a name longer than a length byte can hold is trimmed, not overflowed`() {
        val long = "a".repeat(300) + ".example"
        val encoded = TrojanProtocol.encodeAddressPort(long, 443)
        assertEquals(0x03.toByte(), encoded[0])
        assertEquals(255, encoded[1].toInt() and 0xFF)
        assertEquals(1 + 1 + 255 + 2, encoded.size)
    }

    @Test
    fun `the port is big-endian across its whole range`() {
        for (port in listOf(1, 80, 443, 8080, 32768, 65535)) {
            val encoded = TrojanProtocol.encodeAddressPort("example.com", port)
            assertEquals("port $port", port, be16(encoded, encoded.size - 2))
        }
    }

    // MARK: - buildRequestHeader

    @Test
    fun `the request header is hash CRLF command address CRLF`() {
        val key = TrojanProtocol.passwordKey("pw")
        val header = TrojanProtocol.buildRequestHeader(
            key, TrojanProtocol.COMMAND_TCP, "example.com", 443
        )

        assertArrayEquals(key, header.copyOfRange(0, 56))
        assertEquals(0x0D.toByte(), header[56])
        assertEquals(0x0A.toByte(), header[57])
        assertEquals(TrojanProtocol.COMMAND_TCP, header[58])

        val address = TrojanProtocol.encodeAddressPort("example.com", 443)
        assertArrayEquals(address, header.copyOfRange(59, 59 + address.size))
        assertEquals(0x0D.toByte(), header[59 + address.size])
        assertEquals(0x0A.toByte(), header[60 + address.size])
        assertEquals(61 + address.size, header.size)
    }

    // MARK: - UDP framing

    @Test
    fun `a UDP packet round-trips through its own decoder`() {
        val payload = ByteArray(200) { it.toByte() }
        val packet = TrojanProtocol.encodeUDPPacket("example.com", 53, payload)

        val decoded = TrojanProtocol.tryDecodeUDPPacket(packet)
        assertNotNull(decoded)
        assertArrayEquals(payload, decoded!!.payload)
        assertEquals(packet.size, decoded.consumed)
    }

    @Test
    fun `a short buffer decodes to nothing rather than guessing`() {
        val packet = TrojanProtocol.encodeUDPPacket("example.com", 53, ByteArray(100))
        for (cut in 0 until packet.size) {
            assertNull("cut=$cut", TrojanProtocol.tryDecodeUDPPacket(packet.copyOfRange(0, cut)))
        }
        assertNotNull(TrojanProtocol.tryDecodeUDPPacket(packet))
    }

    @Test
    fun `two packets in one buffer are consumed one at a time`() {
        val first = TrojanProtocol.encodeUDPPacket("a.example", 53, ByteArray(10) { 1 })
        val second = TrojanProtocol.encodeUDPPacket("b.example", 53, ByteArray(20) { 2 })

        val decoded = TrojanProtocol.tryDecodeUDPPacket(first + second)!!
        assertEquals(first.size, decoded.consumed)
        assertArrayEquals(ByteArray(10) { 1 }, decoded.payload)

        val next = TrojanProtocol.tryDecodeUDPPacket((first + second).copyOfRange(decoded.consumed, first.size + second.size))!!
        assertArrayEquals(ByteArray(20) { 2 }, next.payload)
    }

    @Test
    fun `an oversized payload is capped at what a server accepts`() {
        val payload = ByteArray(TrojanProtocol.MAX_UDP_PAYLOAD_LENGTH + 500)
        val packet = TrojanProtocol.encodeUDPPacket("example.com", 53, payload)
        val decoded = TrojanProtocol.tryDecodeUDPPacket(packet)!!
        assertEquals(TrojanProtocol.MAX_UDP_PAYLOAD_LENGTH, decoded.payload.size)
    }

    private fun be16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
}
