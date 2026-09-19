package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * The record layer end to end: bytes a writer seals must decode on a reader that
 * shares its key, and the on-wire bytes must match a spec decode done by hand.
 *
 * The by-hand decode is the independence anchor — it parses the five-byte header
 * per the wire layout and opens the body with a bare cipher, a [Blake3Kdf]-derived
 * key, and the nonce the counter reaches first, so it does not lean on the read
 * path it is checking. The writer/reader round trip then confirms the two paths
 * are inverses across record boundaries, the header is bound so a tampered one is
 * refused, and a payloads over one chunk split into several records that
 * reassemble.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptedConnectionTest {

    private val context = "loopback-pfs".toByteArray()
    private val unitedKey = ByteArray(96) { it.toByte() }

    /** Collects everything written, to hand to a reader. */
    private class CaptureConnection : ProxyConnection() {
        var sent = ByteArray(0); private set
        override val isConnected: Boolean get() = true
        override suspend fun sendRaw(data: ByteArray) { sent += data }
        override fun sendRawAsync(data: ByteArray) { sent += data }
        override suspend fun receiveRaw(): ByteArray? = null
        override fun cancel() {}
    }

    /** Replays a fixed buffer once, then end-of-stream. */
    private class ReplayConnection(private var data: ByteArray) : ProxyConnection() {
        override val isConnected: Boolean get() = true
        override suspend fun sendRaw(data: ByteArray) {}
        override fun sendRawAsync(data: ByteArray) {}
        override suspend fun receiveRaw(): ByteArray? {
            if (data.isEmpty()) return null
            val d = data
            data = ByteArray(0)
            return d
        }
        override fun cancel() {}
    }

    /** A writer whose records a matching reader (same context + key) can open. */
    private fun writer(capture: CaptureConnection) = VlessEncryptedConnection(
        inner = capture,
        writeAead = VlessRecordAead(context, unitedKey),
        readAead = VlessRecordAead("unused".toByteArray(), unitedKey),
        unitedKey = unitedKey,
        preludeBytes = null,
        pendingServerPaddingLength = 0,
        carryOverBytes = ByteArray(0),
        xorConnection = null,
        zeroRttState = null
    )

    private fun reader(replay: ReplayConnection) = VlessEncryptedConnection(
        inner = replay,
        writeAead = VlessRecordAead("unused".toByteArray(), unitedKey),
        readAead = VlessRecordAead(context, unitedKey),
        unitedKey = unitedKey,
        preludeBytes = null,
        pendingServerPaddingLength = 0,
        carryOverBytes = ByteArray(0),
        xorConnection = null,
        zeroRttState = null
    )

    @Test
    fun `the first record decodes by hand from the wire bytes`() = runBlocking {
        val capture = CaptureConnection()
        writer(capture).sendRaw("hello".toByteArray())

        // Parse the header per the spec, then open the body with a bare cipher.
        val wire = capture.sent
        assertEquals(VlessWire.RECORD_TYPE, wire[0])
        assertEquals(VlessWire.VERSION_MAJOR, wire[1])
        assertEquals(VlessWire.VERSION_MINOR, wire[2])
        val payloadLength = ((wire[3].toInt() and 0xFF) shl 8) or (wire[4].toInt() and 0xFF)
        assertEquals("hello".length + VlessWire.AEAD_TAG_LENGTH, payloadLength)

        val header = wire.copyOfRange(0, VlessWire.HEADER_LENGTH)
        val sealed = wire.copyOfRange(VlessWire.HEADER_LENGTH, VlessWire.HEADER_LENGTH + payloadLength)
        val key = Blake3Kdf.deriveKey(context, unitedKey)
        val firstNonce = ByteArray(VlessWire.NONCE_LENGTH).also { it[11] = 1 }
        assertArrayEquals("hello".toByteArray(), VlessAeadCipher.open(key, firstNonce, header, sealed))
    }

    @Test
    fun `a reader opens the writer's records in order`() = runBlocking {
        val capture = CaptureConnection()
        val w = writer(capture)
        w.sendRaw("first".toByteArray())
        w.sendRaw("second".toByteArray())

        val r = reader(ReplayConnection(capture.sent))
        assertArrayEquals("first".toByteArray(), r.receiveRaw())
        assertArrayEquals("second".toByteArray(), r.receiveRaw())
        assertNull(r.receiveRaw())
    }

    @Test
    fun `a payload over one chunk splits into records that reassemble`() = runBlocking {
        val capture = CaptureConnection()
        val payload = ByteArray(20_000) { (it % 256).toByte() }
        writer(capture).sendRaw(payload)

        val r = reader(ReplayConnection(capture.sent))
        // 20000 = 8192 + 8192 + 3616 -> three records.
        val first = r.receiveRaw()!!
        val second = r.receiveRaw()!!
        val third = r.receiveRaw()!!
        assertEquals(VlessWire.MAX_CHUNK_PLAINTEXT, first.size)
        assertEquals(VlessWire.MAX_CHUNK_PLAINTEXT, second.size)
        assertEquals(20_000 - 2 * VlessWire.MAX_CHUNK_PLAINTEXT, third.size)
        assertArrayEquals(payload, first + second + third)
        assertNull(r.receiveRaw())
    }

    @Test
    fun `a flipped ciphertext byte fails the tag on read`() {
        val capture = CaptureConnection()
        runBlocking { writer(capture).sendRaw("tamper me".toByteArray()) }
        val wire = capture.sent.copyOf()
        // Flip a byte inside the sealed body (past the 5-byte header).
        wire[VlessWire.HEADER_LENGTH] = (wire[VlessWire.HEADER_LENGTH].toInt() xor 1).toByte()

        val r = reader(ReplayConnection(wire))
        assertThrows(AEADBadTagException::class.java) { runBlocking { r.receiveRaw() } }
    }

    @Test
    fun `a corrupted header is a framing error on read`() {
        val capture = CaptureConnection()
        runBlocking { writer(capture).sendRaw("hello".toByteArray()) }
        val wire = capture.sent.copyOf()
        wire[0] = 0x16 // no longer application_data

        val r = reader(ReplayConnection(wire))
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) { runBlocking { r.receiveRaw() } }
    }

    @Test
    fun `an empty send writes nothing`() = runBlocking {
        val capture = CaptureConnection()
        writer(capture).sendRaw(ByteArray(0))
        assertEquals(0, capture.sent.size)
    }
}
