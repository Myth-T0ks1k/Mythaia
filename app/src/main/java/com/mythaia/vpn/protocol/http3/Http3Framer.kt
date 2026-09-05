package com.mythaia.vpn.protocol.http3

/**
 * The HTTP/3 frame layer: what a peer writes onto a QUIC stream once the
 * connection is up.
 *
 * A frame is a varint type, a varint length, then exactly that many payload
 * bytes (RFC 9114 §7.1). There is no fixed-size header to peek at, so how much
 * buffer a frame needs is only knowable after reading its first few bytes, and
 * a QUIC stream read can end anywhere — including halfway through the length
 * varint. That is what shapes [Http3Framer.parse]: it reports
 * [Http3Framer.ParseResult.Incomplete] without consuming anything, so a caller
 * can append the next read to the same buffer and simply try again.
 *
 * Types, settings identifiers and error codes are carried as raw [Long] values
 * next to their enums rather than only as enums. HTTP/3 reserves whole families
 * of codepoints for extensions and for greasing, so an endpoint has to be able
 * to hold onto a value it has no name for instead of rejecting it.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */

import com.mythaia.vpn.protocol.quic.QuicVarInt

/**
 * The frame types this client names (RFC 9114 §11.2.1).
 *
 * The gaps are deliberate. 0x02, 0x06, 0x08 and 0x09 are permanently reserved
 * because HTTP/2 spent them on frames HTTP/3 does not need, and receiving one
 * is a connection error rather than an unknown type to skip over; giving them
 * names here would invite treating them as ordinary.
 */
enum class Http3FrameType(val code: Long) {
    DATA(0x00),
    HEADERS(0x01),
    CANCEL_PUSH(0x03),
    SETTINGS(0x04),
    PUSH_PROMISE(0x05),
    GOAWAY(0x07),
    MAX_PUSH_ID(0x0D);

    companion object {
        /**
         * The type with this code, or null when there is no name for it.
         *
         * Null is the normal case for extension and greased types, which an
         * endpoint is required to ignore rather than fail on, so callers should
         * treat it as "skip this frame" and not as an error.
         */
        fun from(code: Long): Http3FrameType? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Settings identifiers understood by this client (RFC 9114 §7.2.4.1 and the
 * extensions below).
 *
 * A SETTINGS frame carries identifier/value pairs, and an identifier a peer
 * does not recognise must be ignored — which is how the extension settings got
 * here without a new HTTP version.
 */
enum class Http3SettingsId(val code: Long) {
    QPACK_MAX_TABLE_CAPACITY(0x01),
    MAX_FIELD_SECTION_SIZE(0x06),
    QPACK_BLOCKED_STREAMS(0x07),

    /** RFC 9220: extended CONNECT, which is what brings the `:protocol` pseudo-header. */
    ENABLE_CONNECT_PROTOCOL(0x08),

    /** RFC 9297: HTTP Datagrams, the carrier CONNECT-UDP rides on. */
    H3_DATAGRAM(0x33);

    companion object {
        /** The identifier with this code, or null for one that must be ignored. */
        fun from(code: Long): Http3SettingsId? = entries.firstOrNull { it.code == code }
    }
}

/**
 * Application error codes (RFC 9114 §8.1).
 *
 * These do not travel in frames. They are what an endpoint puts in a QUIC
 * CONNECTION_CLOSE, RESET_STREAM or STOP_SENDING to say why HTTP/3, rather than
 * QUIC, gave up.
 */
enum class Http3ErrorCode(val code: Long) {
    NO_ERROR(0x0100),
    GENERAL_PROTOCOL_ERROR(0x0101),
    INTERNAL_ERROR(0x0102),
    STREAM_CREATION_ERROR(0x0103),
    CLOSED_CRITICAL_STREAM(0x0104),
    FRAME_UNEXPECTED(0x0105),
    FRAME_ERROR(0x0106),
    EXCESSIVE_LOAD(0x0107),
    ID_ERROR(0x0108),
    SETTINGS_ERROR(0x0109),
    MISSING_SETTINGS(0x010A),
    REQUEST_REJECTED(0x010B),
    REQUEST_CANCELLED(0x010C),
    REQUEST_INCOMPLETE(0x010D),
    MESSAGE_ERROR(0x010E),
    CONNECT_ERROR(0x010F),
    VERSION_FALLBACK(0x0110);

    companion object {
        /** The code a peer sent, or null when it is outside the registered set. */
        fun from(code: Long): Http3ErrorCode? = entries.firstOrNull { it.code == code }
    }
}

/** Builds and reads HTTP/3 frames. */
object Http3Framer {

    /**
     * A 256 KiB ceiling on the decompressed size of a field section.
     *
     * The point is to bound what a server can make this client hold in memory
     * for one response's headers; QPACK decompression can expand a small field
     * section into something much larger, so the limit is stated on the
     * decompressed side.
     */
    const val FIELD_SECTION_SIZE_LIMIT = 262_144L

    /**
     * The settings a client announces, in the order it announces them.
     *
     * Both QPACK settings are zero because this client runs QPACK with no
     * dynamic table: nothing is inserted, so nothing can block on an insertion
     * that has not arrived, and the encoder side stays stateless. The other two
     * are what make tunnelling possible at all — extended CONNECT for
     * CONNECT-UDP's handshake and HTTP Datagrams for its payloads.
     */
    val CLIENT_SETTINGS: List<Pair<Long, Long>> = listOf(
        Http3SettingsId.QPACK_MAX_TABLE_CAPACITY.code to 0L,
        Http3SettingsId.QPACK_BLOCKED_STREAMS.code to 0L,
        Http3SettingsId.MAX_FIELD_SECTION_SIZE.code to FIELD_SECTION_SIZE_LIMIT,
        Http3SettingsId.ENABLE_CONNECT_PROTOCOL.code to 1L,
        Http3SettingsId.H3_DATAGRAM.code to 1L
    )

    /**
     * One frame off the wire.
     *
     * [type] stays a raw code rather than an [Http3FrameType] so that a frame
     * this client has no name for still round-trips intact; [knownType] is the
     * lookup for the cases that do have one.
     */
    class Frame(val type: Long, val payload: ByteArray) {

        /** The named type, or null for an extension or greased frame to ignore. */
        val knownType: Http3FrameType? get() = Http3FrameType.from(type)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Frame) return false
            return type == other.type && payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int = 31 * type.hashCode() + payload.contentHashCode()

        override fun toString(): String =
            "Frame(type=0x${type.toString(16)}, payload=${payload.size} bytes)"
    }

    /** What [parse] found at the offset it was given. */
    sealed interface ParseResult {

        /** A whole frame, and how many bytes of the buffer it occupied. */
        data class Complete(val frame: Frame, val bytesConsumed: Int) : ParseResult

        /**
         * The buffer stops short of a whole frame.
         *
         * Nothing was consumed, so the right response is to read more from the
         * stream, append it, and call [parse] again at the same offset.
         */
        data object Incomplete : ParseResult

        /**
         * The frame can never be completed, so waiting for more bytes would
         * block the stream forever. Worth a connection error, not a retry.
         */
        data class Malformed(val reason: String) : ParseResult
    }

    /**
     * Wraps [payload] in a frame of the given type.
     *
     * Both the type and the length are varints, so the header is between two
     * and sixteen bytes wide depending on the numbers involved.
     */
    /**
     * The first bytes of a unidirectional stream say what it is (RFC 9114 §6.2).
     *
     * A varint, not a byte: the registry allows large values, and greasing
     * deliberately uses them. Reading it as a byte works right up until a peer
     * greases and the stream is misidentified.
     */
    const val STREAM_TYPE_CONTROL = 0x00L
    const val STREAM_TYPE_PUSH = 0x01L
    const val STREAM_TYPE_QPACK_ENCODER = 0x02L
    const val STREAM_TYPE_QPACK_DECODER = 0x03L

    /** The opening bytes that declare a unidirectional stream's type. */
    fun uniStreamType(type: Long): ByteArray = QuicVarInt.encode(type)

    /** Reads that declaration, or null when the buffer is still short of it. */
    fun readUniStreamType(bytes: ByteArray): QuicVarInt.Decoded? = QuicVarInt.decode(bytes)

    fun frame(type: Long, payload: ByteArray): ByteArray {
        val out = ByteArray(
            QuicVarInt.sizeOf(type) + QuicVarInt.sizeOf(payload.size.toLong()) + payload.size
        )
        var at = QuicVarInt.write(out, 0, type)
        at += QuicVarInt.write(out, at, payload.size.toLong())
        payload.copyInto(out, at)
        return out
    }

    fun frame(type: Http3FrameType, payload: ByteArray): ByteArray = frame(type.code, payload)

    /** A DATA frame: request or response body bytes (RFC 9114 §7.2.1). */
    fun dataFrame(payload: ByteArray): ByteArray = frame(Http3FrameType.DATA, payload)

    /**
     * A HEADERS frame carrying an already-encoded QPACK field section
     * (RFC 9114 §7.2.2).
     *
     * The framer never looks inside [headerBlock]; header encoding is QPACK's
     * job and keeping the two apart is what lets this be tested against fixed
     * bytes.
     */
    fun headersFrame(headerBlock: ByteArray): ByteArray =
        frame(Http3FrameType.HEADERS, headerBlock)

    /**
     * A SETTINGS frame whose payload is the given identifier/value pairs, each
     * a varint (RFC 9114 §7.2.4).
     *
     * Order is preserved because it is observable on the wire, and a peer that
     * fingerprints clients will notice a different one.
     */
    fun settingsFrame(settings: List<Pair<Long, Long>>): ByteArray {
        var size = 0
        for ((id, value) in settings) {
            size += QuicVarInt.sizeOf(id) + QuicVarInt.sizeOf(value)
        }
        val payload = ByteArray(size)
        var at = 0
        for ((id, value) in settings) {
            at += QuicVarInt.write(payload, at, id)
            at += QuicVarInt.write(payload, at, value)
        }
        return frame(Http3FrameType.SETTINGS, payload)
    }

    /** The SETTINGS frame this client sends first on its control stream. */
    fun clientSettingsFrame(): ByteArray = settingsFrame(CLIENT_SETTINGS)

    /**
     * Reads a SETTINGS payload back into identifier/value pairs.
     *
     * Null means the payload ended mid-varint. That is a malformed frame rather
     * than a short read — the frame's length was already known before its
     * payload was handed over — and RFC 9114 §7.2.4.1 makes it
     * [Http3ErrorCode.SETTINGS_ERROR].
     *
     * Duplicates are returned as they arrived instead of being collapsed into a
     * map, because the same identifier appearing twice is itself a
     * SETTINGS_ERROR and a map would hide it.
     */
    fun parseSettings(payload: ByteArray): List<Pair<Long, Long>>? {
        val out = ArrayList<Pair<Long, Long>>()
        var at = 0
        while (at < payload.size) {
            val id = QuicVarInt.decode(payload, at) ?: return null
            at += id.size
            val value = QuicVarInt.decode(payload, at) ?: return null
            at += value.size
            out.add(id.value to value.value)
        }
        return out
    }

    /**
     * Reads one frame starting at [offset].
     *
     * The buffer is left untouched unless a whole frame is present, which is
     * the property the caller depends on: frames arrive split across QUIC
     * stream reads, and a parser that consumed a partial header would have
     * nowhere to put it back.
     */
    fun parse(bytes: ByteArray, offset: Int = 0): ParseResult {
        require(offset >= 0) { "offset cannot be negative: $offset" }

        val type = QuicVarInt.decode(bytes, offset) ?: return ParseResult.Incomplete
        val length = QuicVarInt.decode(bytes, offset + type.size) ?: return ParseResult.Incomplete

        val headerSize = type.size + length.size
        // A varint length reaches 2^62-1, far past any array the JVM can hold.
        // Such a frame will never become complete, so calling it incomplete
        // would leave the caller buffering the stream until it ran out of heap.
        if (length.value > Int.MAX_VALUE - headerSize) {
            return ParseResult.Malformed("frame length ${length.value} exceeds what can be buffered")
        }

        // The length varint decoded, so this start is within the buffer and the
        // subtraction below cannot go negative or wrap.
        val payloadStart = offset + headerSize
        val payloadLength = length.value.toInt()
        if (payloadLength > bytes.size - payloadStart) return ParseResult.Incomplete

        return ParseResult.Complete(
            Frame(type.value, bytes.copyOfRange(payloadStart, payloadStart + payloadLength)),
            headerSize + payloadLength
        )
    }
}
