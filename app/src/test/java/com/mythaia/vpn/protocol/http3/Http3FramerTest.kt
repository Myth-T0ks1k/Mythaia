package com.mythaia.vpn.protocol.http3

/**
 * Frame-layer tests written against RFC 9114 rather than against the encoder.
 *
 * Every expected byte string below is spelled out as literals worked out from
 * the specification's own field layouts and registered codepoints — the frame
 * type registry in §11.2.1, the frame definitions in §7.2, the error codes in
 * §8.1, and QUIC's varint rules from RFC 9000 §16 for the lengths. A codec
 * checked by encoding and then decoding its own output only proves it is
 * self-consistent, which is exactly the property a wrong codec also has.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Http3FramerTest {

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    /**
     * Asserts that no proper prefix of a complete frame parses, and that none
     * of them throws either. This is the property the QUIC stream reader leans
     * on: a read can end on any byte boundary, including inside a varint.
     */
    private fun assertEveryTruncationIsIncomplete(frame: ByteArray) {
        for (length in 0 until frame.size) {
            val partial = frame.copyOfRange(0, length)
            assertEquals(
                "a $length-byte prefix of a ${frame.size}-byte frame must not parse",
                Http3Framer.ParseResult.Incomplete,
                Http3Framer.parse(partial)
            )
        }
    }

    // MARK: registered codepoints

    @Test
    fun `frame type codes are the ones RFC 9114 registers`() {
        assertEquals(0x00L, Http3FrameType.DATA.code)
        assertEquals(0x01L, Http3FrameType.HEADERS.code)
        assertEquals(0x03L, Http3FrameType.CANCEL_PUSH.code)
        assertEquals(0x04L, Http3FrameType.SETTINGS.code)
        assertEquals(0x05L, Http3FrameType.PUSH_PROMISE.code)
        assertEquals(0x07L, Http3FrameType.GOAWAY.code)
        assertEquals(0x0DL, Http3FrameType.MAX_PUSH_ID.code)
    }

    @Test
    fun `the codepoints HTTP2 burned have no name here`() {
        // RFC 9114 §11.2.1 reserves 0x02, 0x06, 0x08 and 0x09 because HTTP/2
        // used them; receiving one is H3_FRAME_UNEXPECTED, so a lookup that
        // resolved them to a usable type would be actively wrong.
        for (reserved in listOf(0x02L, 0x06L, 0x08L, 0x09L)) {
            assertNull("0x${reserved.toString(16)} must not name a frame type", Http3FrameType.from(reserved))
        }
    }

    @Test
    fun `settings identifiers are the ones their RFCs register`() {
        assertEquals(0x01L, Http3SettingsId.QPACK_MAX_TABLE_CAPACITY.code)
        assertEquals(0x06L, Http3SettingsId.MAX_FIELD_SECTION_SIZE.code)
        assertEquals(0x07L, Http3SettingsId.QPACK_BLOCKED_STREAMS.code)
        assertEquals(0x08L, Http3SettingsId.ENABLE_CONNECT_PROTOCOL.code)
        assertEquals(0x33L, Http3SettingsId.H3_DATAGRAM.code)
    }

    @Test
    fun `error codes are the RFC 9114 section 8_1 table`() {
        assertEquals(0x0100L, Http3ErrorCode.NO_ERROR.code)
        assertEquals(0x0101L, Http3ErrorCode.GENERAL_PROTOCOL_ERROR.code)
        assertEquals(0x0102L, Http3ErrorCode.INTERNAL_ERROR.code)
        assertEquals(0x0103L, Http3ErrorCode.STREAM_CREATION_ERROR.code)
        assertEquals(0x0104L, Http3ErrorCode.CLOSED_CRITICAL_STREAM.code)
        assertEquals(0x0105L, Http3ErrorCode.FRAME_UNEXPECTED.code)
        assertEquals(0x0106L, Http3ErrorCode.FRAME_ERROR.code)
        assertEquals(0x0107L, Http3ErrorCode.EXCESSIVE_LOAD.code)
        assertEquals(0x0108L, Http3ErrorCode.ID_ERROR.code)
        assertEquals(0x0109L, Http3ErrorCode.SETTINGS_ERROR.code)
        assertEquals(0x010AL, Http3ErrorCode.MISSING_SETTINGS.code)
        assertEquals(0x010BL, Http3ErrorCode.REQUEST_REJECTED.code)
        assertEquals(0x010CL, Http3ErrorCode.REQUEST_CANCELLED.code)
        assertEquals(0x010DL, Http3ErrorCode.REQUEST_INCOMPLETE.code)
        assertEquals(0x010EL, Http3ErrorCode.MESSAGE_ERROR.code)
        assertEquals(0x010FL, Http3ErrorCode.CONNECT_ERROR.code)
        assertEquals(0x0110L, Http3ErrorCode.VERSION_FALLBACK.code)

        // The registered range is contiguous, so a gap or a typo above would
        // still be caught even if the same mistake were made twice.
        assertEquals(17, Http3ErrorCode.entries.size)
        Http3ErrorCode.entries.forEachIndexed { index, code ->
            assertEquals(0x0100L + index, code.code)
        }
    }

    // MARK: DATA

    @Test
    fun `a DATA frame is type 0x00 then a length then the body`() {
        // RFC 9114 §7.2.1. "hello" is 5 bytes, so the length is the one-byte
        // varint 0x05, and the ASCII follows unchanged.
        val expected = bytes(0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F)
        val frame = Http3Framer.dataFrame("hello".toByteArray(Charsets.US_ASCII))
        assertArrayEquals(expected, frame)

        val parsed = Http3Framer.parse(expected)
        assertEquals(
            Http3Framer.ParseResult.Complete(
                Http3Framer.Frame(0x00L, "hello".toByteArray(Charsets.US_ASCII)),
                7
            ),
            parsed
        )
        assertEquals(
            Http3FrameType.DATA,
            (parsed as Http3Framer.ParseResult.Complete).frame.knownType
        )
    }

    @Test
    fun `an empty DATA frame is two bytes and its only prefix is incomplete`() {
        val expected = bytes(0x00, 0x00)
        assertArrayEquals(expected, Http3Framer.dataFrame(ByteArray(0)))
        assertEquals(
            Http3Framer.ParseResult.Complete(Http3Framer.Frame(0x00L, ByteArray(0)), 2),
            Http3Framer.parse(expected)
        )
        assertEveryTruncationIsIncomplete(expected)
    }

    // MARK: HEADERS

    @Test
    fun `a HEADERS frame is type 0x01 wrapped around an opaque field section`() {
        // The payload is the encoded field section from RFC 9204 Appendix B.1:
        // a 2-byte prefix of zeroes, then a literal field line with a static
        // name reference to :path, then the 11-byte value "/index.html".
        // Fifteen bytes in total, so the frame's length varint is 0x0F.
        val headerBlock = bytes(
            0x00, 0x00, 0x51, 0x0B,
            0x2F, 0x69, 0x6E, 0x64, 0x65, 0x78, 0x2E, 0x68, 0x74, 0x6D, 0x6C
        )
        assertEquals(15, headerBlock.size)

        val expected = bytes(
            0x01, 0x0F,
            0x00, 0x00, 0x51, 0x0B,
            0x2F, 0x69, 0x6E, 0x64, 0x65, 0x78, 0x2E, 0x68, 0x74, 0x6D, 0x6C
        )
        assertArrayEquals(expected, Http3Framer.headersFrame(headerBlock))

        val parsed = Http3Framer.parse(expected)
        assertEquals(
            Http3Framer.ParseResult.Complete(Http3Framer.Frame(0x01L, headerBlock), 17),
            parsed
        )
        assertEveryTruncationIsIncomplete(expected)
    }

    // MARK: SETTINGS

    @Test
    fun `the client SETTINGS frame is byte-for-byte what the settings say it should be`() {
        // Payload, per RFC 9114 §7.2.4, is identifier/value varint pairs:
        //   0x01 0x00                -> QPACK_MAX_TABLE_CAPACITY = 0
        //   0x07 0x00                -> QPACK_BLOCKED_STREAMS = 0
        //   0x06 0x80 0x04 0x00 0x00 -> MAX_FIELD_SECTION_SIZE = 262144, which
        //                               is above 16383 so RFC 9000 §16 puts it
        //                               in the four-byte form 0x80 | 0x00040000
        //   0x08 0x01                -> ENABLE_CONNECT_PROTOCOL = 1
        //   0x33 0x01                -> H3_DATAGRAM = 1
        // Thirteen payload bytes, behind type 0x04 and length 0x0D.
        val expected = bytes(
            0x04, 0x0D,
            0x01, 0x00,
            0x07, 0x00,
            0x06, 0x80, 0x04, 0x00, 0x00,
            0x08, 0x01,
            0x33, 0x01
        )
        assertArrayEquals(expected, Http3Framer.clientSettingsFrame())
        assertEquals(262_144L, Http3Framer.FIELD_SECTION_SIZE_LIMIT)
        assertEveryTruncationIsIncomplete(expected)
    }

    @Test
    fun `a SETTINGS payload reads back as the pairs the wire bytes describe`() {
        val wire = bytes(
            0x04, 0x0D,
            0x01, 0x00,
            0x07, 0x00,
            0x06, 0x80, 0x04, 0x00, 0x00,
            0x08, 0x01,
            0x33, 0x01
        )
        val parsed = Http3Framer.parse(wire) as Http3Framer.ParseResult.Complete
        val frame = parsed.frame
        assertEquals(Http3FrameType.SETTINGS, frame.knownType)
        assertEquals(15, parsed.bytesConsumed)

        assertEquals(
            listOf(1L to 0L, 7L to 0L, 6L to 262_144L, 8L to 1L, 0x33L to 1L),
            Http3Framer.parseSettings(frame.payload)
        )
    }

    @Test
    fun `a settings pair that runs off the end of its payload is refused`() {
        // An identifier with no value, and a value varint that claims two bytes
        // but supplies one. Both are H3_SETTINGS_ERROR, not short reads: the
        // frame length already said where the payload ends.
        assertNull(Http3Framer.parseSettings(bytes(0x01)))
        assertNull(Http3Framer.parseSettings(bytes(0x01, 0x00, 0x06, 0x40)))
        assertEquals(emptyList<Pair<Long, Long>>(), Http3Framer.parseSettings(ByteArray(0)))
    }

    @Test
    fun `a repeated settings identifier is reported rather than collapsed`() {
        // RFC 9114 §7.2.4.1 makes a duplicate identifier a connection error, so
        // the parser has to hand both occurrences over for the caller to notice.
        assertEquals(
            listOf(0x06L to 0L, 0x06L to 1L),
            Http3Framer.parseSettings(bytes(0x06, 0x00, 0x06, 0x01))
        )
    }

    // MARK: multi-byte varints

    @Test
    fun `a length past 63 moves into the two-byte varint form`() {
        // 64 is the first value RFC 9000 §16 cannot fit in one byte: the
        // two-byte form is 0x40 in the top bits and 64 in the remaining
        // fourteen, which is 0x40 0x40.
        val payload = ByteArray(64) { 0xAB.toByte() }
        val frame = Http3Framer.dataFrame(payload)

        assertArrayEquals(bytes(0x00, 0x40, 0x40), frame.copyOfRange(0, 3))
        assertEquals(3 + 64, frame.size)

        assertEquals(
            Http3Framer.ParseResult.Complete(Http3Framer.Frame(0x00L, payload), 67),
            Http3Framer.parse(frame)
        )
        assertEveryTruncationIsIncomplete(frame)
    }

    @Test
    fun `a length past 16383 moves into the four-byte varint form`() {
        // 16384 is 0x00004000, so the four-byte form is 0x80 0x00 0x40 0x00.
        val payload = ByteArray(16_384) { it.toByte() }
        val frame = Http3Framer.dataFrame(payload)

        assertArrayEquals(bytes(0x00, 0x80, 0x00, 0x40, 0x00), frame.copyOfRange(0, 5))
        assertEquals(5 + 16_384, frame.size)

        // Spot-checking the boundary rather than all 16389 prefixes: one byte
        // short is still incomplete, the exact size is the whole frame.
        assertEquals(
            Http3Framer.ParseResult.Incomplete,
            Http3Framer.parse(frame.copyOfRange(0, frame.size - 1))
        )
        assertEquals(
            Http3Framer.ParseResult.Complete(Http3Framer.Frame(0x00L, payload), frame.size),
            Http3Framer.parse(frame)
        )
    }

    @Test
    fun `a frame type past 63 also takes a multi-byte varint`() {
        // RFC 9114 §7.2.8 reserves types of the form 0x1f * N + 0x21. N = 1
        // gives 64, the first type that needs two bytes, encoded 0x40 0x40.
        val greased = 0x1FL * 1 + 0x21L
        assertEquals(64L, greased)

        val frame = Http3Framer.frame(greased, bytes(0xFF))
        assertArrayEquals(bytes(0x40, 0x40, 0x01, 0xFF), frame)

        val parsed = Http3Framer.parse(frame)
        assertEquals(
            Http3Framer.ParseResult.Complete(Http3Framer.Frame(64L, bytes(0xFF)), 4),
            parsed
        )
        // Nothing names a greased type, and that is the point: it must survive
        // the parser intact so the caller can ignore it deliberately.
        assertNull((parsed as Http3Framer.ParseResult.Complete).frame.knownType)
        assertEveryTruncationIsIncomplete(frame)
    }

    @Test
    fun `a length written in a longer form than needed is still accepted`() {
        // RFC 9000 §16 permits a non-minimal encoding, so a peer may send the
        // length 5 as the two-byte 0x40 0x05. Refusing it would be an interop
        // bug that only shows up against that one peer.
        val wire = bytes(0x00, 0x40, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F)
        assertEquals(
            Http3Framer.ParseResult.Complete(
                Http3Framer.Frame(0x00L, "hello".toByteArray(Charsets.US_ASCII)),
                8
            ),
            Http3Framer.parse(wire)
        )
    }

    // MARK: partial buffers and offsets

    @Test
    fun `a header split inside its type varint waits for more`() {
        // The two-byte type 0x40 0x40 with only its first byte present. There
        // is no length to read yet, and guessing one would desynchronise the
        // whole stream.
        assertEquals(Http3Framer.ParseResult.Incomplete, Http3Framer.parse(bytes(0x40)))
        assertEquals(Http3Framer.ParseResult.Incomplete, Http3Framer.parse(bytes(0x40, 0x40)))
        assertEquals(Http3Framer.ParseResult.Incomplete, Http3Framer.parse(ByteArray(0)))
    }

    @Test
    fun `an exhausted buffer is incomplete rather than an error`() {
        val frame = Http3Framer.dataFrame(bytes(0x01, 0x02))
        assertEquals(Http3Framer.ParseResult.Incomplete, Http3Framer.parse(frame, frame.size))
    }

    @Test
    fun `frames arriving back to back are walked with bytesConsumed`() {
        val first = Http3Framer.headersFrame(bytes(0x00, 0x00, 0xD1))
        val second = Http3Framer.dataFrame("hi".toByteArray(Charsets.US_ASCII))
        val stream = first + second

        val a = Http3Framer.parse(stream, 0) as Http3Framer.ParseResult.Complete
        assertEquals(first.size, a.bytesConsumed)
        assertEquals(Http3FrameType.HEADERS, a.frame.knownType)

        val b = Http3Framer.parse(stream, a.bytesConsumed) as Http3Framer.ParseResult.Complete
        assertEquals(second.size, b.bytesConsumed)
        assertEquals(Http3FrameType.DATA, b.frame.knownType)
        assertArrayEquals("hi".toByteArray(Charsets.US_ASCII), b.frame.payload)

        assertEquals(
            Http3Framer.ParseResult.Incomplete,
            Http3Framer.parse(stream, a.bytesConsumed + b.bytesConsumed)
        )
    }

    @Test
    fun `a frame that arrives one byte at a time parses exactly once, at the end`() {
        val frame = Http3Framer.clientSettingsFrame()
        var completions = 0
        for (available in 0..frame.size) {
            when (val result = Http3Framer.parse(frame.copyOfRange(0, available))) {
                is Http3Framer.ParseResult.Complete -> {
                    completions++
                    assertEquals(frame.size, available)
                    assertEquals(frame.size, result.bytesConsumed)
                }
                is Http3Framer.ParseResult.Incomplete -> Unit
                is Http3Framer.ParseResult.Malformed ->
                    throw AssertionError("a truncated frame is not malformed: ${result.reason}")
            }
        }
        assertEquals(1, completions)
    }

    @Test
    fun `a truncated frame at a non-zero offset is still incomplete`() {
        val prefix = Http3Framer.dataFrame(bytes(0xAA))
        val frame = Http3Framer.clientSettingsFrame()
        val stream = prefix + frame

        for (length in prefix.size until stream.size) {
            assertEquals(
                "offset ${prefix.size} into a $length-byte buffer",
                Http3Framer.ParseResult.Incomplete,
                Http3Framer.parse(stream.copyOfRange(0, length), prefix.size)
            )
        }
        assertTrue(Http3Framer.parse(stream, prefix.size) is Http3Framer.ParseResult.Complete)
    }

    // MARK: bad input

    @Test
    fun `a length no buffer could ever hold is malformed, not incomplete`() {
        // Type 0x00 then the largest varint, 2^62-1 in the eight-byte form.
        // Reporting this as incomplete would leave a reader buffering the
        // connection until the heap ran out.
        val wire = bytes(0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)
        val result = Http3Framer.parse(wire)
        assertTrue("expected Malformed, got $result", result is Http3Framer.ParseResult.Malformed)
    }

    @Test
    fun `a negative offset is a caller's bug, not wire data`() {
        try {
            Http3Framer.parse(Http3Framer.dataFrame(ByteArray(0)), -1)
            throw AssertionError("expected a refusal for a negative offset")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    // MARK: payload ownership

    @Test
    fun `a parsed payload does not alias the buffer it came from`() {
        // The Swift reference hands back a zero-copy slice, which makes the
        // frame change under the caller as soon as the receive buffer is
        // reused. Copying here is what lets a parsed frame outlive the read.
        val buffer = Http3Framer.dataFrame(bytes(0x11, 0x22, 0x33))
        val parsed = Http3Framer.parse(buffer) as Http3Framer.ParseResult.Complete

        buffer[2] = 0x99.toByte()
        assertArrayEquals(bytes(0x11, 0x22, 0x33), parsed.frame.payload)
    }

    @Test
    fun `frames compare by their bytes so tests cannot pass on identity alone`() {
        val a = Http3Framer.Frame(0x00L, bytes(0x01, 0x02))
        val b = Http3Framer.Frame(0x00L, bytes(0x01, 0x02))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertTrue(a != Http3Framer.Frame(0x01L, bytes(0x01, 0x02)))
        assertTrue(a != Http3Framer.Frame(0x00L, bytes(0x01, 0x03)))
    }
}
