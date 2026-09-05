package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * RFC 9000 Appendix A.1 gives four worked examples of the varint encoding.
 * They are the test: a codec checked only against itself would agree with its
 * own mistakes.
 */
class QuicVarIntTest {

    private fun hex(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun `the eight-byte example from the RFC`() {
        val bytes = hex(0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C)
        assertEquals(QuicVarInt.Decoded(151_288_809_941_952_652L, 8), QuicVarInt.decode(bytes))
        assertArrayEquals(bytes, QuicVarInt.encode(151_288_809_941_952_652L))
    }

    @Test
    fun `the four-byte example from the RFC`() {
        val bytes = hex(0x9D, 0x7F, 0x3E, 0x7D)
        assertEquals(QuicVarInt.Decoded(494_878_333L, 4), QuicVarInt.decode(bytes))
        assertArrayEquals(bytes, QuicVarInt.encode(494_878_333L))
    }

    @Test
    fun `the two-byte example from the RFC`() {
        val bytes = hex(0x7B, 0xBD)
        assertEquals(QuicVarInt.Decoded(15_293L, 2), QuicVarInt.decode(bytes))
        assertArrayEquals(bytes, QuicVarInt.encode(15_293L))
    }

    @Test
    fun `the one-byte example from the RFC`() {
        assertEquals(QuicVarInt.Decoded(37L, 1), QuicVarInt.decode(hex(0x25)))
        assertArrayEquals(hex(0x25), QuicVarInt.encode(37L))
    }

    @Test
    fun `the RFC's two-byte encoding of a value that fits in one is still read`() {
        // 0x40 0x25 is 37 written the long way. A decoder must accept it even
        // though an encoder would not produce it.
        assertEquals(QuicVarInt.Decoded(37L, 2), QuicVarInt.decode(hex(0x40, 0x25)))
    }

    @Test
    fun `each size boundary picks the shortest form`() {
        assertEquals(1, QuicVarInt.sizeOf(0))
        assertEquals(1, QuicVarInt.sizeOf(63))
        assertEquals(2, QuicVarInt.sizeOf(64))
        assertEquals(2, QuicVarInt.sizeOf(16_383))
        assertEquals(4, QuicVarInt.sizeOf(16_384))
        assertEquals(4, QuicVarInt.sizeOf(1_073_741_823))
        assertEquals(8, QuicVarInt.sizeOf(1_073_741_824))
        assertEquals(8, QuicVarInt.sizeOf(QuicVarInt.MAX))
    }

    @Test
    fun `every boundary value survives a round trip`() {
        val values = listOf(
            0L, 1L, 63L, 64L, 16_383L, 16_384L,
            1_073_741_823L, 1_073_741_824L, QuicVarInt.MAX
        )
        for (value in values) {
            val encoded = QuicVarInt.encode(value)
            val decoded = QuicVarInt.decode(encoded)
            assertEquals("value $value", QuicVarInt.Decoded(value, encoded.size), decoded)
        }
    }

    @Test
    fun `a truncated varint is nothing rather than a guess`() {
        assertNull(QuicVarInt.decode(ByteArray(0)))
        assertNull(QuicVarInt.decode(hex(0x40)))
        assertNull(QuicVarInt.decode(hex(0x80, 0x00)))
        assertNull(QuicVarInt.decode(hex(0xC0, 0x00, 0x00, 0x00)))
        assertNull(QuicVarInt.decode(hex(0x25), offset = 1))
    }

    @Test
    fun `writing at an offset leaves the rest of the buffer alone`() {
        val buffer = ByteArray(6) { 0xEE.toByte() }
        val written = QuicVarInt.write(buffer, 2, 15_293L)
        assertEquals(2, written)
        assertArrayEquals(hex(0xEE, 0xEE, 0x7B, 0xBD, 0xEE, 0xEE), buffer)
        assertEquals(QuicVarInt.Decoded(15_293L, 2), QuicVarInt.decode(buffer, 2))
    }

    @Test
    fun `a value the encoding cannot express is refused`() {
        for (bad in listOf(-1L, QuicVarInt.MAX + 1, Long.MAX_VALUE)) {
            try {
                QuicVarInt.encode(bad)
                throw AssertionError("expected a refusal for $bad")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
    }
}
