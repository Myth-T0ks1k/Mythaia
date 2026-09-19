package com.mythaia.vpn.protocol.quic

import com.mythaia.vpn.protocol.tls.TlsCipherSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The handler's parsing, which reads bytes a server controls.
 *
 * The handshake itself cannot run here — it installs keys through JNI, and the
 * unit suite has no library to load — so what is tested is everything that
 * happens before a key is touched: the ClientHello this end builds, message
 * framing across CRYPTO frame boundaries, and refusing malformed input rather
 * than misreading it.
 */
class QuicTlsHandlerTest {

    private fun handler() = QuicTlsHandler(
        serverName = "example.com",
        alpn = listOf("h3"),
        tuning = QuicTuning.NAIVE
    )

    // MARK: - ClientHello

    @Test
    fun `the hello is a ClientHello carrying the transport parameters`() {
        val hello = handler().buildClientHello()
        assertNotNull(hello)

        // Handshake type 1, then a uint24 length that frames the rest exactly.
        assertEquals(1, hello!![0].toInt())
        val length = ((hello[1].toInt() and 0xFF) shl 16) or
            ((hello[2].toInt() and 0xFF) shl 8) or (hello[3].toInt() and 0xFF)
        assertEquals(hello.size - 4, length)

        // The extension must be present, under the assigned identifier.
        assertTrue(containsExtension(hello, QuicTransportParameters.EXTENSION_TYPE))
    }

    @Test
    fun `the same hello comes back on a repeat request`() {
        // ngtcp2 asks again when the first Initial is lost, and the transcript
        // is already committed to the first answer.
        val handler = handler()
        val first = handler.buildClientHello()
        val second = handler.buildClientHello()
        assertEquals(first!!.toList(), second!!.toList())
    }

    @Test
    fun `two handlers do not share a key share`() {
        // A reused ephemeral key would make two sessions decryptable together.
        val a = handler().buildClientHello()!!
        val b = handler().buildClientHello()!!
        assertTrue(!a.contentEquals(b))
    }

    @Test
    fun `building starts the transcript, so the phase moves on`() {
        val handler = handler()
        assertEquals(QuicTlsHandler.Phase.INITIAL, handler.phase)
        handler.buildClientHello()
        assertEquals(QuicTlsHandler.Phase.HELLO_SENT, handler.phase)
    }

    // MARK: - Message framing

    @Test
    fun `a message split across two frames waits for the rest`() {
        // A CRYPTO frame is not a message boundary: a ServerHello routinely
        // arrives in pieces, and treating a piece as a message loses the
        // handshake.
        val handler = handler()
        handler.buildClientHello()

        val half = byteArrayOf(2, 0, 0, 40, 3, 3)
        assertEquals(QuicTlsHandler.Outcome.NEED_MORE, handler.processCryptoData(0L, half))
        assertEquals(QuicTlsHandler.Phase.HELLO_SENT, handler.phase)
    }

    @Test
    fun `fewer than four bytes is not yet a header`() {
        val handler = handler()
        handler.buildClientHello()
        assertEquals(QuicTlsHandler.Outcome.NEED_MORE, handler.processCryptoData(0L, byteArrayOf(2, 0)))
    }

    @Test
    fun `an unknown message type is stepped over, not fatal`() {
        // TLS 1.3 adds message types over time and a middlebox can inject one;
        // the RFC says to ignore what is not understood.
        val handler = handler()
        handler.buildClientHello()

        val unknown = byteArrayOf(99, 0, 0, 2, 0xAA.toByte(), 0xBB.toByte())
        assertEquals(QuicTlsHandler.Outcome.OK, handler.processCryptoData(0L, unknown))
        assertNull(handler.failure)
    }

    @Test
    fun `an absurd length is refused rather than allocated`() {
        // The length field is 24 bits. Nothing in a real handshake approaches
        // it, and a corrupt one would otherwise ask for a 16 MB buffer.
        val handler = handler()
        handler.buildClientHello()

        val huge = byteArrayOf(2, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        assertEquals(QuicTlsHandler.Outcome.FAILED, handler.processCryptoData(0L, huge))
        assertEquals(QuicTlsHandler.Phase.FAILED, handler.phase)
        assertNotNull(handler.failure)
    }

    @Test
    fun `a truncated ServerHello is refused before any key is derived`() {
        val handler = handler()
        handler.buildClientHello()

        // Type 2, length 4, but a ServerHello needs at least 35 bytes of body.
        val short = byteArrayOf(2, 0, 0, 4, 3, 3, 0, 0)
        assertEquals(QuicTlsHandler.Outcome.FAILED, handler.processCryptoData(0L, short))
        assertTrue(handler.failure!!.contains("ServerHello"))
    }

    @Test
    fun `a ServerHello naming a suite we do not implement is refused`() {
        val handler = handler()
        handler.buildClientHello()

        // 35 bytes of body: version, random, empty session id, then a suite of
        // 0x0000 which is not one of the three TLS 1.3 AEADs.
        val body = ByteArray(38)
        body[0] = 3; body[1] = 3
        body[34] = 0            // session id length
        body[35] = 0; body[36] = 0  // cipher suite 0x0000
        val message = byteArrayOf(2, 0, 0, body.size.toByte()) + body

        assertEquals(QuicTlsHandler.Outcome.FAILED, handler.processCryptoData(0L, message))
        assertTrue(handler.failure!!.contains("cipher suite"))
    }

    @Test
    fun `a Finished before any ServerHello is refused, not crashed on`() {
        val handler = handler()
        handler.buildClientHello()

        val finished = byteArrayOf(20, 0, 0, 4, 1, 2, 3, 4)
        assertEquals(QuicTlsHandler.Outcome.FAILED, handler.processCryptoData(0L, finished))
        assertTrue(handler.failure!!.contains("ServerHello"))
    }

    // MARK: - Encryption levels

    @Test
    fun `the level numbers are contiguous and are not ngtcp2's own`() {
        // These are the bridge's numbering, translated to ngtcp2's enum in C.
        // Deliberately not ngtcp2's raw values: that enum has been renumbered
        // once already — ngtcp2_crypto_level ordered them initial, early,
        // handshake, app, while ngtcp2_encryption_level orders them initial,
        // handshake, 1-RTT, 0-RTT. Constants copied from the old order install
        // handshake keys as 1-RTT keys, the handshake never completes, and
        // nothing anywhere reports why. This exact mistake was in this file.
        assertEquals(0, QuicTlsHandler.LEVEL_INITIAL)
        assertEquals(1, QuicTlsHandler.LEVEL_HANDSHAKE)
        assertEquals(2, QuicTlsHandler.LEVEL_APPLICATION)
    }

    @Test
    fun `the suites the handler accepts are the three TLS 1_3 AEADs`() {
        assertTrue(TlsCipherSuite.isAEAD(0x1301))
        assertTrue(TlsCipherSuite.isAEAD(0x1302))
        assertTrue(TlsCipherSuite.isAEAD(0x1303))
        assertTrue(!TlsCipherSuite.isAEAD(0x0000))
    }

    /** Walks the ClientHello's extension list looking for [wanted]. */
    private fun containsExtension(hello: ByteArray, wanted: Int): Boolean {
        var at = 4 + 2 + 32                       // header, version, random
        at += 1 + (hello[at].toInt() and 0xFF)    // session id
        val suitesLength = ((hello[at].toInt() and 0xFF) shl 8) or (hello[at + 1].toInt() and 0xFF)
        at += 2 + suitesLength
        at += 1 + (hello[at].toInt() and 0xFF)    // compression methods
        if (at + 2 > hello.size) return false

        val extensionsLength = ((hello[at].toInt() and 0xFF) shl 8) or (hello[at + 1].toInt() and 0xFF)
        at += 2
        val end = minOf(at + extensionsLength, hello.size)

        while (at + 4 <= end) {
            val type = ((hello[at].toInt() and 0xFF) shl 8) or (hello[at + 1].toInt() and 0xFF)
            val length = ((hello[at + 2].toInt() and 0xFF) shl 8) or (hello[at + 3].toInt() and 0xFF)
            if (type == wanted) return true
            at += 4 + length
        }
        return false
    }
}
