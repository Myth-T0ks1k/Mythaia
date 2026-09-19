package com.mythaia.data.model

import com.mythaia.vpn.protocol.tls.TlsHelloFragmenter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * The formats a panel actually sends, checked against what a peer would see
 * on the wire rather than against a round trip through our own code.
 */
class FragmentSettingsTest {

    private val finalMask =
        """{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3"],"delays":["1"],"maxSplit":"2"}}]}"""

    @Test
    fun `fm document with lengths 3 and maxSplit 2 parses to three bytes then the rest`() {
        val settings = FragmentSettings.fromFinalMask(finalMask)
        assertNotNull(settings)
        settings!!
        assertTrue(settings.isEnabled)
        assertEquals(listOf(3..3), settings.lengthRanges)
        assertEquals(listOf(1..1), settings.delayRanges)
        assertEquals(2, settings.maxSplit)
    }

    @Test
    fun `fm with range texts and per-piece lists is kept per piece`() {
        val doc = """{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8","10-20"],"delays":["10-20"],"maxSplit":"3-6"}}]}"""
        val settings = FragmentSettings.fromFinalMask(doc)!!
        assertEquals(listOf(3..5, 6..8, 10..20), settings.lengthRanges)
        assertEquals(listOf(10..20), settings.delayRanges)
        assertEquals(6, settings.maxSplit)
    }

    @Test
    fun `fm without a tcp fragment mask is null`() {
        assertNull(FragmentSettings.fromFinalMask("""{"udp":[{"type":"salamander","settings":{"password":"x"}}]}"""))
        assertNull(FragmentSettings.fromFinalMask("not json"))
    }

    @Test
    fun `share link form accepts an optional maxSplit`() {
        val settings = FragmentSettings.fromShareLink("1-10,5-20,tlshello,2")!!
        assertEquals(1..10, settings.lengthRange)
        assertEquals(5..20, settings.intervalRange)
        assertEquals(2, settings.maxSplit)
        assertEquals(0, FragmentSettings.fromShareLink("1-10,5-20,tlshello")!!.maxSplit)
    }

    @Test
    fun `fragmenter honours maxSplit so the second piece carries the rest`() {
        val settings = FragmentSettings.fromFinalMask(finalMask)!!
        val record = handshakeRecord(payload = 300)
        val pieces = TlsHelloFragmenter.split(record, settings.lengthRanges, settings.maxSplit, SecureRandom())
        assertEquals(2, pieces.size)
        assertEquals(5 + 3, pieces[0].size)
        assertEquals(5 + 297, pieces[1].size)
        // A peer reassembles the payload bytes in order.
        val joined = pieces.flatMap { it.drop(5) }.toByteArray()
        assertTrue(joined.contentEquals(record.copyOfRange(5, record.size)))
    }

    @Test
    fun `fragmenter without a cap keeps drawing from the last range`() {
        val record = handshakeRecord(payload = 20)
        val pieces = TlsHelloFragmenter.split(record, listOf(3..3), 0, SecureRandom())
        assertEquals(7, pieces.size)
        assertEquals(5 + 2, pieces.last().size)
    }

    @Test
    fun `final mask export says what was parsed`() {
        val settings = FragmentSettings.fromFinalMask(finalMask)!!
        val back = FragmentSettings.fromFinalMask(settings.toFinalMaskJson())!!
        assertEquals(settings.lengthRanges, back.lengthRanges)
        assertEquals(settings.delayRanges, back.delayRanges)
        assertEquals(settings.maxSplit, back.maxSplit)
    }

    private fun handshakeRecord(payload: Int): ByteArray {
        val record = ByteArray(5 + payload)
        record[0] = 0x16
        record[1] = 0x03
        record[2] = 0x01
        record[3] = ((payload shr 8) and 0xFF).toByte()
        record[4] = (payload and 0xFF).toByte()
        for (i in 0 until payload) record[5 + i] = (i and 0xFF).toByte()
        return record
    }
}
