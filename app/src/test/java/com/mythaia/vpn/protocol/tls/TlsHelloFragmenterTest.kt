package com.mythaia.vpn.protocol.tls

import com.mythaia.data.model.FragmentSettings
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Ports `Mythaia Tests/TLSHelloFragmenterTests.swift`.
 *
 * The invariant that matters: however the record is cut, the bytes a server
 * reassembles must be exactly the bytes that were going to be sent.
 */
class TlsHelloFragmenterTest {

    /** A well-formed handshake record with a [payload]-byte body. */
    private fun hello(payload: Int): ByteArray {
        val record = ByteArray(5 + payload)
        record[0] = 0x16
        record[1] = 0x03
        record[2] = 0x01
        record[3] = ((payload shr 8) and 0xFF).toByte()
        record[4] = (payload and 0xFF).toByte()
        for (i in 0 until payload) record[5 + i] = (i and 0xFF).toByte()
        return record
    }

    private fun payloadOf(record: ByteArray): ByteArray = record.copyOfRange(5, record.size)

    private fun declaredLength(record: ByteArray): Int =
        ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)

    // MARK: - split(record, lengths)

    @Test
    fun `splits into the requested lengths and preserves the payload`() {
        val original = hello(payload = 300)
        val pieces = TlsHelloFragmenter.split(original, listOf(100, 120, 500))

        assertEquals(3, pieces.size)
        assertEquals(100, declaredLength(pieces[0]))
        assertEquals(120, declaredLength(pieces[1]))
        assertEquals(80, declaredLength(pieces[2]))

        // Every piece is a complete record with the same type and version.
        for (piece in pieces) {
            assertEquals(0x16.toByte(), piece[0])
            assertEquals(original[1], piece[1])
            assertEquals(original[2], piece[2])
            assertEquals(declaredLength(piece), piece.size - 5)
        }

        val rejoined = pieces.fold(ByteArray(0)) { acc, p -> acc + payloadOf(p) }
        assertArrayEquals(payloadOf(original), rejoined)
    }

    @Test
    fun `a short lengths list repeats its last value`() {
        val pieces = TlsHelloFragmenter.split(hello(payload = 250), listOf(100))
        assertEquals(3, pieces.size)
        assertEquals(100, declaredLength(pieces[0]))
        assertEquals(100, declaredLength(pieces[1]))
        assertEquals(50, declaredLength(pieces[2]))
    }

    @Test
    fun `a record no longer than one piece comes back whole`() {
        val original = hello(payload = 50)
        val pieces = TlsHelloFragmenter.split(original, listOf(100))
        assertEquals(1, pieces.size)
        assertArrayEquals(original, pieces[0])
    }

    @Test
    fun `non-handshake and malformed records pass through untouched`() {
        val applicationData = hello(payload = 100).also { it[0] = 0x17 }
        assertArrayEquals(
            applicationData,
            TlsHelloFragmenter.split(applicationData, listOf(1)).single()
        )

        // Declared length disagrees with the actual size.
        val truncated = hello(payload = 100).copyOfRange(0, 60)
        assertArrayEquals(truncated, TlsHelloFragmenter.split(truncated, listOf(1)).single())

        // Header only, no payload.
        val headerOnly = ByteArray(5) { if (it == 0) 0x16 else 0 }
        assertArrayEquals(headerOnly, TlsHelloFragmenter.split(headerOnly, listOf(1)).single())

        // Empty and zero/negative lengths are refused rather than looping.
        assertArrayEquals(
            hello(payload = 100),
            TlsHelloFragmenter.split(hello(payload = 100), emptyList()).single()
        )
        assertArrayEquals(
            hello(payload = 100),
            TlsHelloFragmenter.split(hello(payload = 100), listOf(0)).single()
        )
    }

    // MARK: - split(record, lengthRange)

    @Test
    fun `random lengths stay inside the range and cover the payload`() {
        val original = hello(payload = 1000)
        val pieces = TlsHelloFragmenter.split(original, 100..200, SecureRandom())

        assertTrue(pieces.size > 1)
        // Every piece but the last is a full draw from the range; the last takes
        // whatever remains and may be shorter.
        for (piece in pieces.dropLast(1)) {
            assertTrue("piece of ${declaredLength(piece)} outside 100..200",
                declaredLength(piece) in 100..200)
        }
        assertTrue(declaredLength(pieces.last()) in 1..200)

        val rejoined = pieces.fold(ByteArray(0)) { acc, p -> acc + payloadOf(p) }
        assertArrayEquals(payloadOf(original), rejoined)
    }

    @Test
    fun `a single-value range does not throw`() {
        // SecureRandom.nextInt rejects a non-positive bound, so an a..a range
        // must short-circuit rather than call it.
        val pieces = TlsHelloFragmenter.split(hello(payload = 300), 100..100, SecureRandom())
        assertEquals(3, pieces.size)
        assertTrue(pieces.all { declaredLength(it) == 100 })
    }

    // MARK: - FragmentSettings

    @Test
    fun `share link parses fixed and ranged forms`() {
        val fixed = FragmentSettings.fromShareLink("3,1,tlshello")!!
        assertEquals(3..3, fixed.lengthRange)
        assertEquals(1..1, fixed.intervalRange)

        val ranged = FragmentSettings.fromShareLink(" 1-10 , 5-20 , tlshello ")!!
        assertEquals(1..10, ranged.lengthRange)
        assertEquals(5..20, ranged.intervalRange)

        // A `packets` field other than tlshello is still taken as tlshello.
        val raw = FragmentSettings.fromShareLink("100-200,10-20,1-3")!!
        assertEquals(100..200, raw.lengthRange)
        assertEquals(10..20, raw.intervalRange)
    }

    @Test
    fun `share link rejects malformed values`() {
        for (bad in listOf(
            "", "3,1", "3,1,tlshello,extra", "a,1,tlshello", "3,b,tlshello",
            "3,1,", "0,1,tlshello", "10-1,1,tlshello", "-5,1,tlshello"
        )) {
            assertNull(bad, FragmentSettings.fromShareLink(bad))
        }
    }

    @Test
    fun `ranges are normalised whichever way round they were typed`() {
        val backwards = FragmentSettings(
            minLength = 300, maxLength = 100, minInterval = 30, maxInterval = 5
        )
        assertEquals(100..300, backwards.lengthRange)
        assertEquals(5..30, backwards.intervalRange)

        // Length never drops below one byte; interval may be zero.
        assertEquals(1..1, FragmentSettings(minLength = 0, maxLength = 0).lengthRange)
        assertEquals(0..0, FragmentSettings(minInterval = -5, maxInterval = 0).intervalRange)
    }

    @Test
    fun `share link value round-trips`() {
        val settings = FragmentSettings(
            minLength = 100, maxLength = 200, minInterval = 10, maxInterval = 20
        )
        assertEquals("100-200,10-20,tlshello", settings.toShareLinkValue())

        val reparsed = FragmentSettings.fromShareLink(settings.toShareLinkValue())!!
        assertEquals(settings.lengthRange, reparsed.lengthRange)
        assertEquals(settings.intervalRange, reparsed.intervalRange)

        val fixed = FragmentSettings(
            minLength = 3, maxLength = 3, minInterval = 1, maxInterval = 1
        )
        assertEquals("3,1,tlshello", fixed.toShareLinkValue())
    }
}
