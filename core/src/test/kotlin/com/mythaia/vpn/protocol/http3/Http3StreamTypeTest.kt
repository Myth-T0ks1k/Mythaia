package com.mythaia.vpn.protocol.http3

import com.mythaia.vpn.protocol.quic.QuicVarInt
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unidirectional stream types, RFC 9114 §6.2 and its registry.
 *
 * The type is a varint, and reading it as a byte is a mistake that only shows
 * up against a peer that greases — which is a peer behaving correctly.
 */
class Http3StreamTypeTest {

    @Test
    fun `the registry values are the ones the RFC assigns`() {
        assertEquals(0x00L, Http3Framer.STREAM_TYPE_CONTROL)
        assertEquals(0x01L, Http3Framer.STREAM_TYPE_PUSH)
        assertEquals(0x02L, Http3Framer.STREAM_TYPE_QPACK_ENCODER)
        assertEquals(0x03L, Http3Framer.STREAM_TYPE_QPACK_DECODER)
    }

    @Test
    fun `a control stream announces itself in one byte`() {
        assertArrayEquals(
            byteArrayOf(0x00),
            Http3Framer.uniStreamType(Http3Framer.STREAM_TYPE_CONTROL)
        )
    }

    @Test
    fun `the declaration reads back with the bytes it used`() {
        val encoded = Http3Framer.uniStreamType(Http3Framer.STREAM_TYPE_QPACK_DECODER)
        assertEquals(QuicVarInt.Decoded(3L, 1), Http3Framer.readUniStreamType(encoded))
    }

    @Test
    fun `a greased type is read at its full width, not as one byte`() {
        // Greased types are 0x1f * N + 0x21, which are large on purpose so that
        // an implementation reading a single byte misidentifies the stream.
        val greased = 0x1f * 4L + 0x21
        val encoded = Http3Framer.uniStreamType(greased)
        val decoded = Http3Framer.readUniStreamType(encoded)

        assertEquals(greased, decoded!!.value)
        assertEquals(encoded.size, decoded.size)
    }

    @Test
    fun `an empty buffer has no type yet`() {
        assertNull(Http3Framer.readUniStreamType(ByteArray(0)))
    }

    @Test
    fun `a type cut off mid-varint waits rather than guessing`() {
        // 0x40 opens a two-byte varint, so one byte is not enough.
        assertNull(Http3Framer.readUniStreamType(byteArrayOf(0x40)))
    }

    @Test
    fun `the opening of a control stream is its type then SETTINGS`() {
        val opening = Http3Framer.uniStreamType(Http3Framer.STREAM_TYPE_CONTROL) +
            Http3Framer.clientSettingsFrame()

        assertEquals(0x00, opening[0].toInt())
        // What follows the type must parse as a SETTINGS frame; a server that
        // reads anything else here closes the connection.
        val rest = opening.copyOfRange(1, opening.size)
        val parsed = Http3Framer.parse(rest)
        assertEquals(
            Http3FrameType.SETTINGS,
            (parsed as Http3Framer.ParseResult.Complete).frame.knownType
        )
    }
}
