package com.mythaia.vpn.protocol.hysteria

import com.mythaia.vpn.protocol.quic.QuicVarInt
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom

/**
 * The Hysteria 2 wire format.
 *
 * Hysteria runs everything inside one QUIC connection to the server. The client
 * first authenticates over HTTP/3 — a `POST /auth` whose interesting parts are
 * three request headers and a private success status — and afterwards a proxied
 * TCP flow is a QUIC stream carrying one framed request, while proxied UDP is
 * carried in QUIC datagrams that name their own destination. Because a datagram
 * cannot be split by the transport the way a stream can, Hysteria does its own
 * fragmentation: every datagram header carries a packet id and a fragment
 * index so the far side can put a large UDP packet back together.
 *
 * Everything in this file is a pure function of bytes. Opening the QUIC
 * connection, encoding the QPACK header block and driving the streams live
 * elsewhere; keeping the framing separate is what lets it be checked against
 * the protocol specification instead of against itself.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object HysteriaProtocol {

    // Frame types and QUIC application error codes.

    /** The varint that prefixes every proxied TCP request. */
    const val TCP_REQUEST_FRAME_TYPE = 0x401L

    /** Closing cleanly. */
    const val CLOSE_ERR_CODE_OK = 0x100L

    /** Closing because the peer broke the framing rules. */
    const val CLOSE_ERR_CODE_PROTOCOL_ERROR = 0x101L

    /** The only accepting value of a TCP response's status byte. */
    const val TCP_RESPONSE_STATUS_OK: Byte = 0

    // The authentication exchange.

    /**
     * The status the server answers `/auth` with when it accepts the password.
     *
     * It is deliberately outside the registered range so that a probe pointed
     * at the same endpoint sees an ordinary HTTP/3 server answering 404 rather
     * than anything that identifies Hysteria.
     */
    const val AUTH_SUCCESS_STATUS = 233

    /** The `:authority` the auth request claims; it is never resolved. */
    const val AUTH_AUTHORITY = "hysteria"

    /** The `:path` of the auth request. */
    const val AUTH_PATH = "/auth"

    /** HTTP/3 pseudo-header names are lowercase, so these match verbatim. */
    const val HEADER_STATUS = ":status"
    const val HEADER_AUTH = "hysteria-auth"
    const val HEADER_CC_RX = "hysteria-cc-rx"
    const val HEADER_PADDING = "hysteria-padding"
    const val HEADER_UDP = "hysteria-udp"
    const val HEADER_CONTENT_LENGTH = "content-length"

    /** The `hysteria-cc-rx` value meaning "run your own bandwidth detection". */
    const val CC_RX_AUTO = "auto"

    // Padding.

    /** Length of the padding on the auth request and its response. */
    val AUTH_PADDING_RANGE = 256..2047

    /** Length of the padding on a TCP request. */
    val TCP_REQUEST_PADDING_RANGE = 64..511

    // Parsing limits. These exist so a hostile server cannot make the client
    // allocate on the strength of a length field alone.

    const val MAX_ADDRESS_LENGTH = 2048
    const val MAX_RESPONSE_MESSAGE_LENGTH = 2048
    const val MAX_PADDING_LENGTH = 4096

    // Addresses.

    /**
     * A destination the way Hysteria writes it: `host:port`, UTF-8, with an
     * IPv6 literal in brackets per RFC 3986 §3.2.2 so that the colons inside
     * the address cannot be mistaken for the port separator.
     */
    fun formatAddress(host: String, port: Int): String =
        if (host.contains(':')) "[$host]:$port" else "$host:$port"

    // TCP framing.

    /**
     * A proxy request: the frame type, the destination, and cover-traffic
     * padding, each length-prefixed with a QUIC varint.
     *
     * [padding] is a parameter rather than an internal draw so that the bytes
     * are reproducible under test; the server never looks at it, so its only
     * job in production is to vary the size of the first write.
     */
    fun encodeTcpRequest(
        address: String,
        padding: ByteArray = randomPadding(TCP_REQUEST_PADDING_RANGE)
    ): ByteArray {
        val addr = address.toByteArray(Charsets.UTF_8)
        val out = ByteArray(
            QuicVarInt.sizeOf(TCP_REQUEST_FRAME_TYPE) +
                QuicVarInt.sizeOf(addr.size.toLong()) + addr.size +
                QuicVarInt.sizeOf(padding.size.toLong()) + padding.size
        )

        var at = QuicVarInt.write(out, 0, TCP_REQUEST_FRAME_TYPE)
        at += QuicVarInt.write(out, at, addr.size.toLong())
        addr.copyInto(out, at)
        at += addr.size
        at += QuicVarInt.write(out, at, padding.size.toLong())
        padding.copyInto(out, at)
        return out
    }

    /**
     * The server's answer to a proxy request.
     *
     * [consumed] is how much of the buffer the response occupied, so a caller
     * reading a stream knows where the proxied payload begins.
     */
    data class TcpResponse(val status: Byte, val message: String, val consumed: Int) {
        val isOk: Boolean get() = status == TCP_RESPONSE_STATUS_OK
    }

    /**
     * Parses a TCP response, or null when [bytes] does not yet hold a whole one.
     *
     * Null also comes back when a length field exceeds its limit, which a
     * caller cannot tell apart from "wait for more"; the limits are far above
     * anything a real server sends, so in practice both mean the same thing —
     * this connection is not going to produce a usable response.
     */
    fun parseTcpResponse(bytes: ByteArray): TcpResponse? {
        if (bytes.isEmpty()) return null
        val status = bytes[0]
        var at = 1

        val messageLength = QuicVarInt.decode(bytes, at) ?: return null
        if (messageLength.value > MAX_RESPONSE_MESSAGE_LENGTH) return null
        at += messageLength.size
        if (at + messageLength.value > bytes.size) return null
        // Lenient on purpose: this is a human-readable diagnostic, and losing a
        // character to U+FFFD beats discarding the reason the server refused.
        val message = String(bytes, at, messageLength.value.toInt(), Charsets.UTF_8)
        at += messageLength.value.toInt()

        val paddingLength = QuicVarInt.decode(bytes, at) ?: return null
        if (paddingLength.value > MAX_PADDING_LENGTH) return null
        at += paddingLength.size
        if (at + paddingLength.value > bytes.size) return null
        at += paddingLength.value.toInt()

        return TcpResponse(status, message, at)
    }

    // UDP datagram framing.

    /** sessionId(4) ‖ packetId(2) ‖ fragId(1) ‖ fragCount(1), all big-endian. */
    const val UDP_HEADER_FIXED_SIZE = 4 + 2 + 1 + 1

    /** A fragment index is one byte, so no packet can be cut into more. */
    const val MAX_FRAGMENTS = 255

    /**
     * One Hysteria UDP datagram.
     *
     * The wire fields are unsigned, and are carried here in the next Kotlin
     * type up so that a session id near 2^32 does not arrive as a negative
     * number that then compares wrong.
     *
     * Neither the address nor the payload carries a trailing length: the
     * address is varint-prefixed and the payload simply runs to the end of the
     * datagram, which is knowable because QUIC delivers datagrams whole.
     */
    data class UdpMessage(
        val sessionId: Long,
        val packetId: Int,
        val fragId: Int,
        val fragCount: Int,
        /** UTF-8 `host:port`, as produced by [formatAddress]. */
        val address: String,
        val payload: ByteArray
    ) {
        init {
            require(sessionId in 0..0xFFFFFFFFL) { "session id out of range: $sessionId" }
            require(packetId in 0..0xFFFF) { "packet id out of range: $packetId" }
            require(fragId in 0..0xFF) { "fragment id out of range: $fragId" }
            require(fragCount in 0..0xFF) { "fragment count out of range: $fragCount" }
        }

        fun encode(): ByteArray {
            val addr = address.toByteArray(Charsets.UTF_8)
            val out = ByteArray(
                UDP_HEADER_FIXED_SIZE +
                    QuicVarInt.sizeOf(addr.size.toLong()) + addr.size +
                    payload.size
            )

            out[0] = (sessionId ushr 24).toByte()
            out[1] = (sessionId ushr 16).toByte()
            out[2] = (sessionId ushr 8).toByte()
            out[3] = sessionId.toByte()
            out[4] = (packetId ushr 8).toByte()
            out[5] = packetId.toByte()
            out[6] = fragId.toByte()
            out[7] = fragCount.toByte()

            var at = UDP_HEADER_FIXED_SIZE
            at += QuicVarInt.write(out, at, addr.size.toLong())
            addr.copyInto(out, at)
            at += addr.size
            payload.copyInto(out, at)
            return out
        }

        // A data class compares an array by identity, which would make two
        // messages holding the same bytes unequal. Everything that handles
        // these cares about the content.
        override fun equals(other: Any?): Boolean =
            this === other || (other is UdpMessage &&
                sessionId == other.sessionId &&
                packetId == other.packetId &&
                fragId == other.fragId &&
                fragCount == other.fragCount &&
                address == other.address &&
                payload.contentEquals(other.payload))

        override fun hashCode(): Int {
            var result = sessionId.hashCode()
            result = 31 * result + packetId
            result = 31 * result + fragId
            result = 31 * result + fragCount
            result = 31 * result + address.hashCode()
            result = 31 * result + payload.contentHashCode()
            return result
        }
    }

    /**
     * Parses a datagram, or null when it is not a well-formed one.
     *
     * A datagram whose payload would be empty is rejected rather than
     * delivered: the reassembly table is keyed by packet id, and a stream of
     * zero-byte fragments is otherwise a free way to occupy every slot in it.
     * Nothing legitimate sends one, because [fragmentUdp] never produces an
     * empty chunk.
     */
    fun decodeUdpMessage(datagram: ByteArray): UdpMessage? {
        if (datagram.size < UDP_HEADER_FIXED_SIZE) return null

        val sessionId = ((datagram[0].toLong() and 0xFF) shl 24) or
            ((datagram[1].toLong() and 0xFF) shl 16) or
            ((datagram[2].toLong() and 0xFF) shl 8) or
            (datagram[3].toLong() and 0xFF)
        val packetId = ((datagram[4].toInt() and 0xFF) shl 8) or (datagram[5].toInt() and 0xFF)
        val fragId = datagram[6].toInt() and 0xFF
        val fragCount = datagram[7].toInt() and 0xFF

        val addressLength = QuicVarInt.decode(datagram, UDP_HEADER_FIXED_SIZE) ?: return null
        if (addressLength.value <= 0 || addressLength.value > MAX_ADDRESS_LENGTH) return null

        var at = UDP_HEADER_FIXED_SIZE + addressLength.size
        // Strictly less than: the address must be followed by payload.
        if (at + addressLength.value >= datagram.size) return null
        val end = at + addressLength.value.toInt()
        val address = decodeUtf8OrNull(datagram, at, end) ?: return null

        return UdpMessage(
            sessionId = sessionId,
            packetId = packetId,
            fragId = fragId,
            fragCount = fragCount,
            address = address,
            payload = datagram.copyOfRange(end, datagram.size)
        )
    }

    /** How many bytes a datagram spends before its payload. */
    fun udpHeaderSize(address: String): Int {
        val addressLength = address.toByteArray(Charsets.UTF_8).size
        return UDP_HEADER_FIXED_SIZE + QuicVarInt.sizeOf(addressLength.toLong()) + addressLength
    }

    /**
     * Cuts a UDP payload into datagrams that each fit [maxDatagramSize].
     *
     * A payload that already fits becomes a single message marked
     * `fragCount = 1`, which the far side forwards without touching the
     * reassembly table at all.
     *
     * Returns an empty list when the payload would need more than
     * [MAX_FRAGMENTS] pieces, since the fragment count has nowhere to go; the
     * caller has to fail the write rather than send a truncated packet.
     */
    fun fragmentUdp(
        sessionId: Long,
        packetId: Int,
        address: String,
        payload: ByteArray,
        maxDatagramSize: Int
    ): List<UdpMessage> {
        val maxPayload = (maxDatagramSize - udpHeaderSize(address)).coerceAtLeast(1)
        if (payload.size <= maxPayload) {
            return listOf(
                UdpMessage(sessionId, packetId, fragId = 0, fragCount = 1, address = address, payload = payload)
            )
        }

        val chunks = (payload.size + maxPayload - 1) / maxPayload
        if (chunks > MAX_FRAGMENTS) return emptyList()

        return (0 until chunks).map { index ->
            val start = index * maxPayload
            val end = minOf(start + maxPayload, payload.size)
            UdpMessage(
                sessionId = sessionId,
                packetId = packetId,
                fragId = index,
                fragCount = chunks,
                address = address,
                payload = payload.copyOfRange(start, end)
            )
        }
    }

    // Authentication.

    /**
     * The Hysteria-specific headers of the `POST /auth` request.
     *
     * `content-length: 0` is there because the request carries no body; the
     * password travels as a header, which is what lets the whole exchange look
     * like an ordinary HTTP/3 request to anything watching.
     */
    fun authRequestHeaders(
        password: String,
        clientRxBytesPerSec: Long,
        padding: String = randomPaddingString()
    ): List<Pair<String, String>> = listOf(
        HEADER_AUTH to password,
        HEADER_CC_RX to clientRxBytesPerSec.toString(),
        HEADER_PADDING to padding,
        HEADER_CONTENT_LENGTH to "0"
    )

    /**
     * What the server said in reply.
     *
     * [serverRxBytesPerSec] is null when the server answered `auto`, meaning it
     * will measure its own downlink; that is a different instruction from a
     * declared rate of zero, so the two cannot share a value.
     */
    data class AuthResponse(
        val status: Int,
        val udpSupported: Boolean,
        val serverRxBytesPerSec: Long?
    ) {
        val isAccepted: Boolean get() = status == AUTH_SUCCESS_STATUS
    }

    /**
     * Reads the auth response headers, or null when there is no usable
     * `:status` — a reply that cannot be graded is a failure, not a refusal.
     *
     * A non-accepting status still comes back as an [AuthResponse] so the
     * caller can report which one it was.
     */
    fun parseAuthResponse(headers: List<Pair<String, String>>): AuthResponse? {
        val status = headers.firstOrNull { it.first == HEADER_STATUS }
            ?.second?.toIntOrNull() ?: return null

        val udpSupported = headers.firstOrNull { it.first == HEADER_UDP }
            ?.second?.lowercase() == "true"

        val ccRx = headers.firstOrNull { it.first == HEADER_CC_RX }?.second.orEmpty()
        val serverRxBytesPerSec = if (ccRx.lowercase() == CC_RX_AUTO) null else ccRx.toLongOrNull() ?: 0L

        return AuthResponse(status, udpSupported, serverRxBytesPerSec)
    }

    // Padding.

    /**
     * The alphabet Hysteria's padding is drawn from. Restricting it to
     * printable ASCII is what lets the same generator fill both a binary frame
     * and an HTTP header value.
     */
    private val PADDING_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            .toByteArray(Charsets.US_ASCII)

    private val random = SecureRandom()

    /**
     * `length` bytes of `[A-Za-z0-9]` cover traffic.
     *
     * Folding random bytes into a 62-letter alphabet with a remainder is
     * slightly biased toward the first characters. That is fine here and
     * nowhere else in this file: nothing reads these bytes back, and the only
     * property that matters is that the size of the enclosing write varies.
     */
    fun randomPadding(length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        val out = ByteArray(length)
        random.nextBytes(out)
        for (i in out.indices) {
            out[i] = PADDING_ALPHABET[(out[i].toInt() and 0xFF) % PADDING_ALPHABET.size]
        }
        return out
    }

    /** Padding of a length drawn from [range]. */
    fun randomPadding(range: IntRange): ByteArray = randomPadding(range.random())

    /** The same bytes as a string, for the `hysteria-padding` header. */
    fun randomPaddingString(range: IntRange = AUTH_PADDING_RANGE): String =
        String(randomPadding(range), Charsets.US_ASCII)

    /**
     * Decodes a slice as UTF-8, refusing malformed input.
     *
     * The platform's constructor would substitute U+FFFD, which for an address
     * means quietly proxying to a destination nobody named.
     */
    private fun decodeUtf8OrNull(bytes: ByteArray, from: Int, to: Int): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, from, to - from))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }
}

/**
 * Puts fragmented Hysteria UDP datagrams back together.
 *
 * Fragments of one packet share a packet id and arrive in no particular order,
 * so each id gets a slot holding the pieces seen so far. A slot is only
 * released when it completes, which means an incomplete one — a fragment lost
 * in the network — would sit there forever; the two bounds below are what stop
 * that from becoming an unbounded leak that a peer could drive deliberately.
 *
 * This is per-flow state and is not synchronised: one instance belongs to one
 * UDP session, which is where the ordering that makes it safe comes from.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class HysteriaDefragmenter(
    private val maxSlots: Int = MAX_SLOTS,
    private val slotTtlNanos: Long = SLOT_TTL_NANOS,
    /** Injectable so the expiry rule can be exercised without waiting. */
    private val clock: () -> Long = System::nanoTime
) {

    private class Slot(val fragmentCount: Int, val createdAt: Long) {
        val fragments = arrayOfNulls<ByteArray>(fragmentCount)
        var received = 0
    }

    private val slots = HashMap<Int, Slot>()

    /** How many packets are part-assembled; bounded by [maxSlots]. */
    val slotCount: Int get() = slots.size

    /**
     * Feeds one datagram in, returning the whole payload once the packet it
     * belongs to is complete and null while pieces are still missing.
     *
     * An unfragmented message passes straight through, so a session that never
     * fragments never touches the table.
     */
    fun accept(message: HysteriaProtocol.UdpMessage): ByteArray? {
        if (message.fragCount <= 1) return message.payload
        // An index past the end names a fragment that cannot exist, so the
        // sender is either broken or probing; either way there is nothing to
        // reassemble and no slot worth opening.
        if (message.fragId >= message.fragCount) return null

        val now = clock()
        val existing = slots[message.packetId]
        val expired = existing != null && now - existing.createdAt > slotTtlNanos

        val slot: Slot
        if (existing != null && !expired && existing.fragmentCount == message.fragCount) {
            slot = existing
        } else {
            // Only a genuinely new packet can push the table over its bound;
            // replacing a slot whose fragment count disagrees reuses the key.
            if ((existing == null || expired) && slots.size >= maxSlots) evictOne(now)
            slot = Slot(message.fragCount, now)
            slots[message.packetId] = slot
        }

        // First writer wins, so a retransmitted fragment cannot inflate the
        // count and complete a packet that is still missing a piece.
        if (slot.fragments[message.fragId] == null) {
            slot.fragments[message.fragId] = message.payload
            slot.received++
        }
        if (slot.received < slot.fragmentCount) return null

        slots.remove(message.packetId)
        val parts = slot.fragments.map { it ?: return null }
        val out = ByteArray(parts.sumOf { it.size })
        var at = 0
        for (part in parts) {
            part.copyInto(out, at)
            at += part.size
        }
        return out
    }

    /** Drops every part-assembled packet, for a session that is going away. */
    fun clear() = slots.clear()

    /** Expired slots go first, and among equals the oldest does. */
    private fun evictOne(now: Long) {
        val victim = slots.entries.minWithOrNull(
            compareByDescending<Map.Entry<Int, Slot>> { now - it.value.createdAt > slotTtlNanos }
                .thenBy { it.value.createdAt }
        ) ?: return
        slots.remove(victim.key)
    }

    companion object {
        /** How long an incomplete packet is worth holding on to. */
        const val SLOT_TTL_NANOS = 10L * 1_000_000_000L

        /** How many packets may be part-assembled at once. */
        const val MAX_SLOTS = 32
    }
}
