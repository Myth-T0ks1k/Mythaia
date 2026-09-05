package com.mythaia.vpn.protocol.anytls

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The padding algorithm, checked against the reference implementation's
 * `Session.writeConn` case by case.
 *
 * Each case is worked out from the Go source rather than from this code, which
 * is the only way a test of a wire format means anything: a shaping bug that
 * both ends share would round-trip perfectly and still be visible to exactly
 * the observer the scheme exists to defeat.
 */
class AnyTlsShapingTest {

    private fun payload(n: Int) = ByteArray(n) { (it % 251).toByte() }

    @Test
    fun `a payload longer than the record is cut at the record size`() {
        val writes = AnyTlsProtocol.shapeWrites(payload(100), listOf(30))
        assertEquals(2, writes.size)
        assertEquals(30, writes[0].size)
        // The rest follows as its own write once the sizes run out.
        assertEquals(70, writes[1].size)
        assertArrayEquals(payload(100).copyOfRange(0, 30), writes[0])
        assertArrayEquals(payload(100).copyOfRange(30, 100), writes[1])
    }

    @Test
    fun `a short payload is topped up with a waste frame to the record size`() {
        // 20 bytes into a 100-byte record: 100 - 20 - 7 = 73 bytes of waste.
        val writes = AnyTlsProtocol.shapeWrites(payload(20), listOf(100))
        assertEquals(1, writes.size)
        assertEquals(100, writes[0].size)

        val waste = AnyTlsProtocol.readHeader(writes[0], 20)
        assertEquals(AnyTlsProtocol.CMD_WASTE, waste.command)
        assertEquals(0, waste.streamId)
        assertEquals(73, waste.length)
    }

    @Test
    fun `slack too small for a frame header is left alone rather than overflowed`() {
        // 96 into 100 leaves 4 bytes — less than a 7-byte header, so no waste
        // frame fits and the record simply goes out short.
        val writes = AnyTlsProtocol.shapeWrites(payload(96), listOf(100))
        assertEquals(1, writes.size)
        assertEquals(96, writes[0].size)
    }

    @Test
    fun `an exhausted payload produces a record of pure waste`() {
        val writes = AnyTlsProtocol.shapeWrites(payload(10), listOf(10, 50))
        assertEquals(2, writes.size)
        assertEquals(10, writes[0].size)

        // The second record carries nothing but a waste frame of that length.
        assertEquals(AnyTlsProtocol.HEADER_SIZE + 50, writes[1].size)
        val waste = AnyTlsProtocol.readHeader(writes[1])
        assertEquals(AnyTlsProtocol.CMD_WASTE, waste.command)
        assertEquals(50, waste.length)
    }

    @Test
    fun `a check mark stops the sequence once the payload is spent`() {
        // This is what keeps a small request from being followed by padding
        // that would itself be the signature.
        val writes = AnyTlsProtocol.shapeWrites(
            payload(10), listOf(10, AnyTlsProtocol.CHECK_MARK, 500, 500)
        )
        assertEquals(1, writes.size)
        assertEquals(10, writes[0].size)
    }

    @Test
    fun `a check mark is passed over while payload remains`() {
        val writes = AnyTlsProtocol.shapeWrites(
            payload(100), listOf(30, AnyTlsProtocol.CHECK_MARK, 30)
        )
        assertEquals(3, writes.size)
        assertEquals(30, writes[0].size)
        assertEquals(30, writes[1].size)
        assertEquals(40, writes[2].size)
    }

    @Test
    fun `no sizes means one write, unchanged`() {
        val writes = AnyTlsProtocol.shapeWrites(payload(1234), emptyList())
        assertEquals(1, writes.size)
        assertArrayEquals(payload(1234), writes[0])
    }

    @Test
    fun `an empty payload with no sizes writes nothing`() {
        assertEquals(0, AnyTlsProtocol.shapeWrites(ByteArray(0), emptyList()).size)
    }

    @Test
    fun `every byte of the payload survives the shaping`() {
        // Whatever the scheme does, it may only add waste — never drop or
        // reorder what the caller asked to send.
        val original = payload(3000)
        val sizes = listOf(400, AnyTlsProtocol.CHECK_MARK, 600, AnyTlsProtocol.CHECK_MARK, 900)
        val writes = AnyTlsProtocol.shapeWrites(original, sizes)

        val rebuilt = ArrayList<Byte>()
        for (w in writes) {
            var i = 0
            while (i < w.size) {
                // A waste frame is only ever appended whole at the end of a
                // record, so anything that is not one is payload.
                if (w.size - i >= AnyTlsProtocol.HEADER_SIZE) {
                    val h = AnyTlsProtocol.readHeader(w, i)
                    if (h.command == AnyTlsProtocol.CMD_WASTE &&
                        i + AnyTlsProtocol.HEADER_SIZE + h.length == w.size
                    ) break
                }
                rebuilt.add(w[i]); i++
            }
        }
        assertArrayEquals(original, rebuilt.toByteArray())
    }

    @Test
    fun `the default scheme shapes packet 2 into nine records at most`() {
        // "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000" — a large
        // payload uses every size; the checks never fire because data remains.
        val sizes = AnyTlsPaddingScheme.DEFAULT.recordSizes(2, java.security.SecureRandom())
        val writes = AnyTlsProtocol.shapeWrites(payload(60_000), sizes)
        // Five sized records, then the remainder.
        assertEquals(6, writes.size)
        assertTrue(writes[0].size in 400..500)
        for (i in 1..4) assertTrue(writes[i].size in 500..1000)
    }
}
