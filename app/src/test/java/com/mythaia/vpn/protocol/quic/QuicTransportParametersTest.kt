package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * RFC 9000 §18. The encoding is checked against bytes written out by hand from
 * the specification, not against the decoder in the same file — the two agree
 * with each other whether or not they agree with a server.
 */
class QuicTransportParametersTest {

    private fun hex(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun `an integer parameter is id, length, then the value as a varint`() {
        // initial_max_data (0x04) = 16384. 16384 needs the four-byte varint
        // form, so: id 04, length 04, value 80 00 40 00.
        val encoded = QuicTransportParameters.encode(
            listOf(QuicTuning.TransportParameter(QuicTransportParameterId.INITIAL_MAX_DATA, 16_384))
        )
        assertArrayEquals(hex(0x04, 0x04, 0x80, 0x00, 0x40, 0x00), encoded)
    }

    @Test
    fun `a small value takes the one-byte form and the whole parameter is three bytes`() {
        // initial_max_streams_uni (0x09) = 3 fits in one varint byte.
        val encoded = QuicTransportParameters.encode(
            listOf(QuicTuning.TransportParameter(QuicTransportParameterId.INITIAL_MAX_STREAMS_UNI, 3))
        )
        assertArrayEquals(hex(0x09, 0x01, 0x03), encoded)
    }

    @Test
    fun `a flag is written with a zero length rather than left out`() {
        // disable_active_migration carries no value; its presence is the whole
        // message, so omitting it would say the opposite of what was meant.
        val encoded = QuicTransportParameters.encode(
            listOf(QuicTuning.TransportParameter(QuicTransportParameterId.DISABLE_ACTIVE_MIGRATION, null))
        )
        assertArrayEquals(hex(0x0c, 0x00), encoded)
    }

    @Test
    fun `parameters keep the order they were given`() {
        val encoded = QuicTransportParameters.encode(
            listOf(
                QuicTuning.TransportParameter(QuicTransportParameterId.MAX_IDLE_TIMEOUT, 30_000),
                QuicTuning.TransportParameter(QuicTransportParameterId.INITIAL_MAX_STREAMS_BIDI, 1)
            )
        )
        // 30000 is a four-byte varint (80 00 75 30), then 08 01 01.
        assertArrayEquals(hex(0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x08, 0x01, 0x01), encoded)
    }

    @Test
    fun `what was encoded decodes back to the same parameters`() {
        val original = listOf(
            QuicTuning.TransportParameter(QuicTransportParameterId.MAX_IDLE_TIMEOUT, 30_000),
            QuicTuning.TransportParameter(QuicTransportParameterId.INITIAL_MAX_DATA, 64L * 1024 * 1024),
            QuicTuning.TransportParameter(QuicTransportParameterId.INITIAL_MAX_STREAMS_BIDI, 1024),
            QuicTuning.TransportParameter(QuicTransportParameterId.DISABLE_ACTIVE_MIGRATION, null)
        )
        val decoded = QuicTransportParameters.decode(QuicTransportParameters.encode(original))
        assertEquals(original, decoded)
    }

    @Test
    fun `a parameter this build does not know is kept, not dropped`() {
        // RFC 9000 18.1: an unknown transport parameter must be ignored rather
        // than treated as an error, and the caller may understand it even if
        // this object does not.
        // 0x3B is 59 in the one-byte form: the top two bits select the width,
        // so 0x7B would be a two-byte varint and mean something else entirely.
        val decoded = QuicTransportParameters.decode(hex(0x3B, 0x01, 0x05))
        assertNotNull(decoded)
        assertEquals(1, decoded!!.size)
        assertEquals(59, decoded[0].id)
        assertEquals(5L, decoded[0].value)
    }

    @Test
    fun `a truncated or over-long parameter is refused rather than guessed at`() {
        // Length runs past the end of the buffer.
        assertNull(QuicTransportParameters.decode(hex(0x04, 0x08, 0x00)))
        // Length claims one byte but the varint inside needs four.
        assertNull(QuicTransportParameters.decode(hex(0x04, 0x01, 0x80)))
        // A length that does not frame its value exactly.
        assertNull(QuicTransportParameters.decode(hex(0x04, 0x04, 0x01, 0x00, 0x00, 0x00)))
        // An identifier cut off mid-varint.
        assertNull(QuicTransportParameters.decode(hex(0x80)))
    }

    @Test
    fun `nothing at all decodes to nothing at all`() {
        assertEquals(emptyList<QuicTuning.TransportParameter>(), QuicTransportParameters.decode(ByteArray(0)))
    }

    @Test
    fun `the extension wrapper is the draft-free identifier and a two-byte length`() {
        // 0x39 is the assigned value. A server that only knows the 0xffa5 the
        // drafts used will ignore this, so the number matters more than most.
        val body = hex(0x09, 0x01, 0x03)
        val extension = QuicTransportParameters.asExtension(body)

        assertArrayEquals(hex(0x00, 0x39, 0x00, 0x03, 0x09, 0x01, 0x03), extension)
        assertEquals(0x0039, QuicTransportParameters.EXTENSION_TYPE)
    }

    @Test
    fun `every tuning preset encodes and decodes back unchanged`() {
        for (tuning in listOf(QuicTuning.NAIVE, QuicTuning.NOWHERE)) {
            val encoded = QuicTransportParameters.encode(tuning.advertisedParameters)
            val decoded = QuicTransportParameters.decode(encoded)
            assertNotNull(decoded)
            assertEquals(tuning.advertisedParameters, decoded)
            // Small enough to sit in a ClientHello without pushing it over an
            // initial datagram, which would need a second flight to complete.
            assertTrue("${encoded.size} bytes", encoded.size < 128)
        }
    }
}
