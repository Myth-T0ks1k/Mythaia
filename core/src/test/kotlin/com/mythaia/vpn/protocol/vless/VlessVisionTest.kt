package com.mythaia.vpn.protocol.vless

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.ArrayDeque
import java.util.UUID

/**
 * Vision's flow control against what Xray's VisionReader and VisionWriter do.
 *
 * Vision's whole value is switching the uplink to a raw copy once it has seen
 * a TLS 1.3 ServerHello; if that detection never fires, every byte stays
 * double-encrypted for the life of the connection and nothing visibly fails.
 * So the tests here drive a connection end to end and look at the commands
 * that come out, not at the state inside.
 */
class VlessVisionTest {

    private val uuid: UUID = UUID.fromString("b831381d-6324-4d53-ad4f-8cda48b30811")
    private val uuidBytes = VlessProtocol.uuidToBytes(uuid)

    /** Replays queued reads and records writes. */
    private class FakeTransport : Transport {
        val writes = ArrayList<ByteArray>()
        val reads = ArrayDeque<ByteArray>()
        override suspend fun send(data: ByteArray) { writes.add(data) }
        override fun sendAsync(data: ByteArray) { writes.add(data) }
        override suspend fun receive(): ByteArray? = reads.pollFirst()
        override fun forceCancel() = Unit
    }

    /**
     * A TLS 1.3 ServerHello record as the filter recognises it: record type
     * 0x16 (version 0x0303), handshake type 2, a 32-byte session id, the
     * TLS_AES_128_GCM_SHA256 suite and a supported_versions extension naming
     * 0x0304.
     */
    private fun serverHello13(): ByteArray {
        val body = byteArrayOf(0x03, 0x03) +                 // legacy_version
            ByteArray(32) { it.toByte() } +                  // random
            byteArrayOf(32) + ByteArray(32) { 9 } +          // session id
            byteArrayOf(0x13, 0x01) +                        // cipher suite
            byteArrayOf(0x00) +                              // compression
            byteArrayOf(0x00, 0x06) +                        // extensions length
            byteArrayOf(0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)  // supported_versions = 1.3
        val handshake = byteArrayOf(0x02, 0x00, (body.size shr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x03, (handshake.size shr 8).toByte(), handshake.size.toByte()) + handshake
    }

    private fun clientHello(): ByteArray {
        val body = ByteArray(100) { 1 }
        val handshake = byteArrayOf(0x01, 0x00, 0x00, body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x01, 0x00, handshake.size.toByte()) + handshake
    }

    private fun applicationData(length: Int): ByteArray =
        byteArrayOf(0x17, 0x03, 0x03, (length shr 8).toByte(), length.toByte()) + ByteArray(length) { 5 }

    private fun connection(transport: FakeTransport): VlessVisionConnection =
        VlessVisionConnection(VlessDirectConnection(transport), uuidBytes)

    @Test
    fun `the request header and the first padded frame share one write`() = runBlocking {
        val transport = FakeTransport()
        val vision = connection(transport)
        val header = VlessProtocol.encodeRequestHeader(uuid, VlessCommand.TCP, "example.com", 443, "xtls-rprx-vision")

        vision.sendRequest(header, null)

        // One write: a header in a record of its own has a size an observer
        // can read, which is exactly what the padding is there to hide.
        assertEquals(1, transport.writes.size)
        val write = transport.writes[0]
        assertArrayEquals(header, write.copyOfRange(0, header.size))

        var at = header.size
        assertArrayEquals(uuidBytes, write.copyOfRange(at, at + 16)); at += 16
        assertEquals(VisionCommand.PADDING_CONTINUE.value, write[at]); at += 1
        assertEquals("no content", 0, be16(write, at)); at += 2
        val padding = be16(write, at); at += 2
        assertTrue("long padding, got $padding", padding in 900..1400)
        assertEquals(at + padding, write.size)
    }

    @Test
    fun `first data rides the same write as the header`() = runBlocking {
        val transport = FakeTransport()
        val vision = connection(transport)
        val header = VlessProtocol.encodeRequestHeader(uuid, VlessCommand.TCP, "example.com", 443, "xtls-rprx-vision")
        val hello = clientHello()

        vision.sendRequest(header, hello)

        assertEquals(1, transport.writes.size)
        val write = transport.writes[0]
        assertArrayEquals(header, write.copyOfRange(0, header.size))
        var at = header.size
        assertArrayEquals(uuidBytes, write.copyOfRange(at, at + 16)); at += 16
        assertEquals(VisionCommand.PADDING_CONTINUE.value, write[at]); at += 1
        assertEquals(hello.size, be16(write, at)); at += 2
        val padding = be16(write, at); at += 2
        assertArrayEquals(hello, write.copyOfRange(at, at + hello.size))
        assertEquals(at + hello.size + padding, write.size)
    }

    @Test
    fun `a padded ServerHello is recognised and the uplink switches to direct copy`() = runBlocking {
        val transport = FakeTransport()
        val vision = connection(transport)
        val header = VlessProtocol.encodeRequestHeader(uuid, VlessCommand.TCP, "example.com", 443, "xtls-rprx-vision")
        vision.sendRequest(header, clientHello())

        // The server's first frame, padded as Xray's server pads it: UUID,
        // command END, the ServerHello as content. In front of it the VLESS
        // response header, which the inner connection strips.
        val serverSide = VisionTrafficState(uuidBytes)
        val frame = visionPadding(serverHello13(), VisionCommand.PADDING_END, serverSide, false)
        transport.reads.add(byteArrayOf(0x00, 0x00) + frame)

        assertArrayEquals(serverHello13(), vision.receive())

        // The filter must have seen the ServerHello, which only exists once the
        // padding is off: filtered on the padded bytes it never matches, TLS
        // 1.3 is never detected, and this write would go out as CONTINUE under
        // another layer of encryption for the connection's whole life.
        val record = applicationData(64)
        vision.send(record)
        val write = transport.writes.last()
        assertEquals(
            "a complete application-data record after a TLS 1.3 ServerHello is sent DIRECT",
            VisionCommand.PADDING_DIRECT.value, write[0]
        )
        assertEquals(record.size, be16(write, 1))
        assertArrayEquals(record, write.copyOfRange(5, 5 + record.size))

        // From here on the writer copies raw: no command, no padding.
        vision.send(record)
        assertArrayEquals(record, transport.writes.last())
    }

    @Test
    fun `a padded TLS 1_2 ServerHello ends padding without direct copy`() = runBlocking {
        val transport = FakeTransport()
        val vision = connection(transport)
        vision.sendRequest(
            VlessProtocol.encodeRequestHeader(uuid, VlessCommand.TCP, "example.com", 443, "xtls-rprx-vision"),
            clientHello()
        )

        // Same shape, but no supported_versions extension: TLS 1.2.
        val hello12 = serverHello13().let { h ->
            val trimmed = h.copyOfRange(0, h.size - 8)        // drop ext length + extension
            trimmed[3] = ((trimmed.size - 5) shr 8).toByte(); trimmed[4] = (trimmed.size - 5).toByte()
            trimmed[7] = ((trimmed.size - 9) shr 8).toByte(); trimmed[8] = (trimmed.size - 9).toByte()
            trimmed
        }
        val serverSide = VisionTrafficState(uuidBytes)
        transport.reads.add(byteArrayOf(0x00, 0x00) + visionPadding(hello12, VisionCommand.PADDING_END, serverSide, false))
        assertArrayEquals(hello12, vision.receive())

        vision.send(applicationData(64))
        assertEquals(VisionCommand.PADDING_END.value, transport.writes.last()[0])
    }

    private fun be16(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 8) or (bytes[at + 1].toInt() and 0xFF)
}
