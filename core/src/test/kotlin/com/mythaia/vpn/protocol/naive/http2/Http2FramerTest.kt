package com.mythaia.vpn.protocol.naive.http2

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The frame-level details of RFC 9113 §6.1 and §6.2 the session relies on. */
class Http2FramerTest {

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `DATA padding is stripped only when the flag says so`() {
        val padded = Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, hex("02 61 62 00 00"))
        assertArrayEquals(hex("61 62"), Http2Framer.dataPayload(padded))

        val plain = Http2Frame(Http2FrameType.DATA, 0, 1, hex("02 61 62 00 00"))
        assertArrayEquals(hex("02 61 62 00 00"), Http2Framer.dataPayload(plain))

        // All padding is allowed; padding past the payload is not.
        val empty = Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, hex("02 00 00"))
        assertEquals(0, Http2Framer.dataPayload(empty)!!.size)
        assertNull(Http2Framer.dataPayload(Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, hex("03 00 00"))))
        assertNull(Http2Framer.dataPayload(Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, ByteArray(0))))
    }

    @Test
    fun `HEADERS loses its padding and priority block before HPACK sees it`() {
        val flags = Http2FrameFlags.END_HEADERS or Http2FrameFlags.PADDED or Http2FrameFlags.PRIORITY
        val frame = Http2Frame(Http2FrameType.HEADERS, flags, 1, hex("01 80 00 00 03 ff 88 00"))
        assertArrayEquals(hex("88"), Http2Framer.headerBlockFragment(frame))

        val priorityOnly = Http2Frame(Http2FrameType.HEADERS, Http2FrameFlags.PRIORITY, 1, hex("00 00 00 00 10 88"))
        assertArrayEquals(hex("88"), Http2Framer.headerBlockFragment(priorityOnly))

        // A priority block that does not fit.
        assertNull(Http2Framer.headerBlockFragment(Http2Frame(Http2FrameType.HEADERS, Http2FrameFlags.PRIORITY, 1, hex("00 00"))))
    }

    @Test
    fun `CONTINUATION is a frame type of its own`() {
        val buffer = Http2Buffer()
        buffer.append(Http2Framer.serialize(Http2Frame(Http2FrameType.CONTINUATION, Http2FrameFlags.END_HEADERS, 3, hex("88"))))
        val frame = Http2Framer.deserialize(buffer)!!
        assertEquals(Http2FrameType.CONTINUATION, frame.type)
        assertEquals(3, frame.streamID)
        assertArrayEquals(hex("88"), frame.payload)
    }
}
