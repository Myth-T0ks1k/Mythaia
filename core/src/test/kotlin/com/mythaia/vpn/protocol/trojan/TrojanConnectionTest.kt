package com.mythaia.vpn.protocol.trojan

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What a Trojan connection puts on the wire, write by write.
 *
 * The request header is the only thing that tells the server where to
 * connect, and it rides the first write. A flow whose server speaks first
 * (SSH, SMTP, IMAP) never produces a first write of its own, so the client
 * flushes the header with an empty payload — and that write has to be the
 * header exactly, nothing more and nothing less.
 */
class TrojanConnectionTest {

    private class RecordingTransport : Transport {
        val writes = ArrayList<ByteArray>()
        override suspend fun send(data: ByteArray) { writes.add(data) }
        override fun sendAsync(data: ByteArray) { writes.add(data) }
        override suspend fun receive(): ByteArray? = null
        override fun forceCancel() = Unit
    }

    @Test
    fun `an empty first write carries exactly the request header`() = runBlocking {
        val transport = RecordingTransport()
        val connection = TrojanConnection(transport, null, "pw", "example.com", 443)

        connection.send(ByteArray(0))

        val expected = TrojanProtocol.buildRequestHeader(
            TrojanProtocol.passwordKey("pw"), TrojanProtocol.COMMAND_TCP, "example.com", 443
        )
        assertEquals(1, transport.writes.size)
        assertArrayEquals(expected, transport.writes[0])

        // The header is spent: the next write is the payload alone.
        connection.send("hello".toByteArray())
        assertEquals(2, transport.writes.size)
        assertArrayEquals("hello".toByteArray(), transport.writes[1])
    }

    @Test
    fun `a first write with data puts the header and the data in one write`() = runBlocking {
        val transport = RecordingTransport()
        val connection = TrojanConnection(transport, null, "pw", "example.com", 443)

        connection.send("GET / HTTP/1.1\r\n".toByteArray())

        val header = TrojanProtocol.buildRequestHeader(
            TrojanProtocol.passwordKey("pw"), TrojanProtocol.COMMAND_TCP, "example.com", 443
        )
        assertEquals(1, transport.writes.size)
        assertArrayEquals(header + "GET / HTTP/1.1\r\n".toByteArray(), transport.writes[0])
    }

    @Test
    fun `an oversized datagram is dropped, not truncated and not fatal`() = runBlocking {
        val transport = RecordingTransport()
        val connection = TrojanUdpConnection(transport, null, "pw", "example.com", 53)

        connection.send(ByteArray(TrojanProtocol.MAX_UDP_PAYLOAD_LENGTH + 1))
        assertEquals("nothing goes out for a datagram the framing cannot carry", 0, transport.writes.size)

        // The association is still usable, and the request header still goes
        // out with the first datagram that is actually sent.
        connection.send(ByteArray(10) { 7 })
        assertEquals(1, transport.writes.size)
        val header = TrojanProtocol.buildRequestHeader(
            TrojanProtocol.passwordKey("pw"), TrojanProtocol.COMMAND_UDP, "example.com", 53
        )
        val packet = TrojanProtocol.encodeUDPPacket("example.com", 53, ByteArray(10) { 7 })
        assertArrayEquals(header + packet, transport.writes[0])
    }
}
