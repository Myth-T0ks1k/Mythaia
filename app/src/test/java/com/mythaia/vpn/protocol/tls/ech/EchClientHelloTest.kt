package com.mythaia.vpn.protocol.tls.ech

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The ECH ClientHello construction.
 *
 * Worth testing carefully because every failure here is silent. A malformed
 * extension does not break the connection — the server ignores ECH and answers
 * the outer hello, so the handshake succeeds and the name the user was trying
 * to hide goes out in the clear anyway.
 */
class EchClientHelloTest {

    private fun hex(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // MARK: - The extension body

    @Test
    fun `the extension body is laid out in the order the draft prints`() {
        val body = EchClientHello.outerExtensionData(
            configId = 0x2A,
            kdfId = 0x0001,
            aeadId = 0x0002,
            encapsulatedKey = hex(0xAA, 0xBB),
            payload = hex(0x11, 0x22, 0x33)
        )
        // type, kdf(2), aead(2), configId, encLen(2), enc, payloadLen(2), payload
        assertArrayEquals(
            hex(0x00, 0x00, 0x01, 0x00, 0x02, 0x2A, 0x00, 0x02, 0xAA, 0xBB, 0x00, 0x03, 0x11, 0x22, 0x33),
            body
        )
    }

    @Test
    fun `the first byte says this is the outer half`() {
        // 0x00 is outer, 0x01 is inner. A client only ever sends outer, and
        // sending the wrong one makes the server treat it as a retry attempt.
        val body = EchClientHello.outerExtensionData(1, 1, 1, ByteArray(2), ByteArray(2))
        assertEquals(0x00.toByte(), body[0])
    }

    @Test
    fun `the extension wrapper carries the assigned type and a two-byte length`() {
        val extension = EchClientHello.asExtension(hex(0x01, 0x02, 0x03))
        assertArrayEquals(hex(0xFE, 0x0D, 0x00, 0x03, 0x01, 0x02, 0x03), extension)
        assertEquals(0xFE0D, EchClientHello.EXTENSION_TYPE)
    }

    // MARK: - Inner encoding

    @Test
    fun `the four-byte handshake header is stripped before encryption`() {
        // The server rebuilds the header itself, so sending it would put four
        // bytes in the ciphertext that the reconstruction does not expect.
        val inner = hex(0x01, 0x00, 0x00, 0x04) + hex(0xDE, 0xAD, 0xBE, 0xEF)
        val encoded = EchClientHello.encodeInner(inner, "a.com", 0)
        assertEquals(0xDE.toByte(), encoded[0])
    }

    @Test
    fun `the encoded inner is always a multiple of thirty-two bytes`() {
        // Otherwise the ciphertext length varies with the name inside it, which
        // is the very thing being hidden.
        for (bodyLength in 1..80) {
            val inner = ByteArray(4 + bodyLength)
            val encoded = EchClientHello.encodeInner(inner, "example.com", 64)
            assertEquals("body $bodyLength", 0, encoded.size % 32)
        }
    }

    @Test
    fun `two names of different lengths encode to the same size`() {
        // The whole point of the padding: a short domain and a long one must
        // not be distinguishable by ciphertext length.
        //
        // The body has to grow with the name for this to mean anything — a
        // real inner hello carries the name inside it, and the padding is
        // exactly what makes up the difference. Holding the body fixed while
        // varying the name measures nothing, which is what an earlier version
        // of this test did, and it read as a failure of the code.
        fun encodedSizeFor(name: String): Int {
            val inner = ByteArray(4 + 195 + name.length)
            return EchClientHello.encodeInner(inner, name, 64).size
        }

        val sizes = listOf("a.com", "example.com", "a-much-longer-name.example.com")
            .map { encodedSizeFor(it) }
            .distinct()
        assertEquals("every name should encode to one size, got $sizes", 1, sizes.size)
    }

    @Test
    fun `a name longer than the config allows is not padded negatively`() {
        val inner = ByteArray(4 + 50)
        val encoded = EchClientHello.encodeInner(inner, "a".repeat(200), 16)
        assertTrue(encoded.size >= 50)
        assertEquals(0, encoded.size % 32)
    }

    @Test
    fun `an empty name still pads as though it had one`() {
        // A hello with no SNI would otherwise be visibly shorter than one with.
        val inner = ByteArray(4 + 100)
        val named = EchClientHello.encodeInner(inner, "example.com", 64)
        val unnamed = EchClientHello.encodeInner(inner, "", 64)
        assertTrue("unnamed ${unnamed.size} vs named ${named.size}", unnamed.size >= named.size)
        assertEquals(0, unnamed.size % 32)
    }

    @Test
    fun `a message too short to have a header is refused`() {
        try {
            EchClientHello.encodeInner(hex(0x01, 0x00), "a.com", 32)
            throw AssertionError("expected a refusal")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    // MARK: - The two-pass construction

    @Test
    fun `the two passes differ only in the payload, never in length`() {
        // The server re-derives the associated data by zeroing the payload back
        // out, so the two must be byte-identical everywhere else. If they are
        // not, the tag fails and ECH is silently skipped.
        val enc = ByteArray(32) { 0x55 }
        val zeroed = EchClientHello.outerExtensionData(9, 1, 1, enc, ByteArray(120))
        val real = EchClientHello.outerExtensionData(9, 1, 1, enc, ByteArray(120) { 0x77 })

        assertEquals(zeroed.size, real.size)
        assertArrayEquals(zeroed.copyOfRange(0, zeroed.size - 120), real.copyOfRange(0, real.size - 120))
    }

    @Test
    fun `the payload length field matches the payload that follows it`() {
        val payload = ByteArray(300) { 0x01 }
        val body = EchClientHello.outerExtensionData(1, 1, 1, ByteArray(32), payload)

        val at = 1 + 2 + 2 + 1 + 2 + 32
        val declared = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
        assertEquals(300, declared)
        assertEquals(at + 2 + 300, body.size)
    }
}
