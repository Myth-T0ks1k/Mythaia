package com.mythaia.vpn.protocol.sudoku

import com.mythaia.vpn.protocol.anytls.AnyTlsProtocol
import com.mythaia.vpn.protocol.quic.QuicCrypto
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The Sudoku wire format.
 *
 * Sudoku hides a tunnel inside a stream of 4x4 Sudoku puzzles. Both ends derive
 * the same shuffled deck of all 288 complete 4x4 grids from the shared key, and
 * every plaintext byte becomes one grid together with a four-cell clue set that
 * has exactly one solution — so a byte goes out as four "hint" bytes plus
 * whatever padding the sender chose to sprinkle between them. The peer looks the
 * four hints up and gets the byte back. Which octets a hint may occupy is chosen
 * by a *layout*: `ascii` keeps everything printable, `entropy` spreads over the
 * octet space, and a custom eight-character pattern places the bits anywhere.
 *
 * Above that obfuscation sits an ordinary record layer — a two-byte length and a
 * twelve-byte header that doubles as the AEAD nonce and its own associated data
 * — and above that a small handshake called KIP that carries an X25519 exchange
 * and then a one-byte request type: connect TCP, open a multiplexer, or start
 * UDP-over-TCP.
 *
 * Everything in this file is a pure function of bytes or of the key. Opening the
 * connection, the HTTP camouflage transports, the stream multiplexer and the
 * connection pool are transport plumbing and live elsewhere; keeping the codec
 * separate is what lets it be checked against a second transcription of the
 * reference rather than against itself.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object SudokuProtocol {

    // Layouts.

    /** Hints confined to printable octets. */
    const val LAYOUT_ASCII = "ascii"

    /** Hints spread across the octet space. */
    const val LAYOUT_ENTROPY = "entropy"

    /** A custom layout pattern is eight characters: two `x`, two `p`, four `v`. */
    const val CUSTOM_PATTERN_LENGTH = 8

    // Obfuscation.

    /**
     * The scale the padding rate is expressed against: a threshold of
     * [PROBABILITY_ONE] pads at every opportunity, half of it pads about half
     * the time. It is 2^32 because the draw it is compared against is one
     * 32-bit word from the sender's generator.
     */
    const val PROBABILITY_ONE = 1L shl 32

    /** How much obfuscated input the reference asks the transport for at once. */
    const val OBFS_READ_CHUNK_SIZE = 128 * 1024

    /**
     * The floor on a sized read.
     *
     * Padding makes the ratio of wire bytes to decoded bytes unpredictable, so a
     * read sized purely from what the caller still wants can come up short and
     * cost another round trip; this slack absorbs the usual case.
     */
    const val OBFS_MIN_DECODE_READ_SIZE = 64

    /**
     * How many raw bytes to ask the transport for when [decodedRemaining] more
     * decoded bytes are wanted.
     *
     * A pure downlink spends four wire bytes per decoded byte before padding and
     * a packed one spends four per three, which is where the two multipliers
     * come from. Anything large enough that the estimate would exceed [maxRaw]
     * simply reads a full chunk.
     */
    fun wireReadSize(
        decodedRemaining: Int,
        pureDownlink: Boolean,
        maxRaw: Int = OBFS_READ_CHUNK_SIZE
    ): Int {
        if (maxRaw <= OBFS_MIN_DECODE_READ_SIZE || decodedRemaining <= 0) return maxRaw
        val multiplier = if (pureDownlink) 5 else 2
        if (decodedRemaining > (maxRaw - OBFS_MIN_DECODE_READ_SIZE) / multiplier) return maxRaw
        return minOf(maxRaw, decodedRemaining * multiplier + OBFS_MIN_DECODE_READ_SIZE)
    }

    // The record layer.

    /** Every record is prefixed with its body length as a 16-bit big-endian word. */
    const val RECORD_LENGTH_PREFIX_SIZE = 2

    /** epoch(4) ‖ sequence(8), big-endian. */
    const val RECORD_HEADER_SIZE = 12

    /** A body is at least a bare header, and its length field caps it at 65535. */
    const val RECORD_MAX_BODY_SIZE = 65535

    /** What is left for plaintext once the header and the AEAD tag are paid for. */
    const val RECORD_MAX_PLAINTEXT_SIZE =
        RECORD_MAX_BODY_SIZE - RECORD_HEADER_SIZE - QuicCrypto.TAG_LENGTH

    /**
     * How many bytes one epoch key is used for before the sender moves on.
     *
     * The threshold is multiplied by the number of bumps already made, so a
     * long-lived connection rekeys on a widening schedule rather than every
     * 32 MiB forever.
     */
    const val RECORD_EPOCH_REKEY_BYTES = 32L shl 20

    /**
     * How far ahead of the last accepted record an epoch may jump.
     *
     * The peer only ever advances by one, so a larger step means either loss the
     * record layer cannot repair or an injected record; both end the connection.
     */
    const val RECORD_MAX_EPOCH_JUMP = 8L

    /** The label the per-epoch record key is derived under. */
    const val RECORD_KEY_LABEL = "sudoku-record:"

    /**
     * A record header, which is also the record's AEAD nonce and its own
     * associated data.
     *
     * Using the header for all three jobs is what makes the epoch and sequence
     * unforgeable without a separate signature: changing either changes the
     * nonce, and the tag then stops verifying.
     */
    fun recordHeader(epoch: Long, sequence: Long): ByteArray {
        require(epoch in 0..0xFFFFFFFFL) { "record epoch out of range: $epoch" }
        val out = ByteArray(RECORD_HEADER_SIZE)
        out[0] = (epoch ushr 24).toByte()
        out[1] = (epoch ushr 16).toByte()
        out[2] = (epoch ushr 8).toByte()
        out[3] = epoch.toByte()
        for (i in 0 until 8) out[4 + i] = (sequence ushr (56 - 8 * i)).toByte()
        return out
    }

    /** The epoch a record header names, as an unsigned 32-bit value. */
    fun recordEpoch(header: ByteArray, offset: Int = 0): Long =
        ((header[offset].toLong() and 0xFF) shl 24) or
            ((header[offset + 1].toLong() and 0xFF) shl 16) or
            ((header[offset + 2].toLong() and 0xFF) shl 8) or
            (header[offset + 3].toLong() and 0xFF)

    /**
     * The sequence number a record header names.
     *
     * It starts from a random draw and only ever has to match what the peer
     * expects next, so the raw 64 bits are kept as they are; nothing compares
     * two of them for order.
     */
    fun recordSequence(header: ByteArray, offset: Int = 0): Long {
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (header[offset + 4 + i].toLong() and 0xFF)
        return value
    }

    /** Reads the two-byte body length, refusing one that cannot hold a header. */
    fun parseRecordLength(bytes: ByteArray, offset: Int = 0): Int {
        if (offset + RECORD_LENGTH_PREFIX_SIZE > bytes.size) {
            throw SudokuError.ProtocolViolation("truncated record length")
        }
        val length = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        if (length < RECORD_HEADER_SIZE) {
            throw SudokuError.ProtocolViolation("bad record length: $length")
        }
        return length
    }

    /**
     * One whole record: length prefix, header, sealed body.
     *
     * [sequence] is the caller's to advance, because the sender's counter has to
     * survive across records and this function deliberately holds no state.
     */
    fun sealRecord(
        method: SudokuAeadMethod,
        base: ByteArray,
        epoch: Long,
        sequence: Long,
        plaintext: ByteArray
    ): ByteArray {
        require(plaintext.size <= RECORD_MAX_PLAINTEXT_SIZE) {
            "record plaintext of ${plaintext.size} exceeds $RECORD_MAX_PLAINTEXT_SIZE"
        }
        if (method == SudokuAeadMethod.NONE) return plaintext

        val header = recordHeader(epoch, sequence)
        val key = recordEpochKey(base, method, epoch)
        val sealed = QuicCrypto.seal(aeadOf(method), aeadKey(method, key), header, plaintext, header)
        val bodyLength = header.size + sealed.size

        val out = ByteArray(RECORD_LENGTH_PREFIX_SIZE + bodyLength)
        out[0] = (bodyLength ushr 8).toByte()
        out[1] = bodyLength.toByte()
        header.copyInto(out, RECORD_LENGTH_PREFIX_SIZE)
        sealed.copyInto(out, RECORD_LENGTH_PREFIX_SIZE + header.size)
        return out
    }

    /**
     * Opens a record body — header and ciphertext, without the length prefix.
     *
     * The epoch comes out of the body itself rather than from the caller, since
     * the key is derived per epoch and a record may legitimately arrive in a
     * newer one than the last.
     */
    fun openRecord(method: SudokuAeadMethod, base: ByteArray, body: ByteArray): ByteArray {
        if (method == SudokuAeadMethod.NONE) return body
        if (body.size < RECORD_HEADER_SIZE + QuicCrypto.TAG_LENGTH) {
            throw SudokuError.ProtocolViolation("short record body: ${body.size}")
        }
        val header = body.copyOf(RECORD_HEADER_SIZE)
        val key = recordEpochKey(base, method, recordEpoch(header))
        return QuicCrypto.open(
            aeadOf(method),
            aeadKey(method, key),
            header,
            body.copyOfRange(RECORD_HEADER_SIZE, body.size),
            header
        ) ?: throw SudokuError.ProtocolViolation("${method.id} open failed")
    }

    /**
     * Checks a record's epoch and sequence against the last accepted pair.
     *
     * Skipped for the first record of a connection, whose numbers are the peer's
     * random starting point and so cannot be predicted.
     */
    fun validateRecordOrder(lastEpoch: Long, lastSequence: Long, epoch: Long, sequence: Long) {
        if (epoch < lastEpoch) throw SudokuError.ProtocolViolation("replayed record epoch")
        if (epoch == lastEpoch && sequence != lastSequence) {
            throw SudokuError.ProtocolViolation("out of order record")
        }
        if (epoch > lastEpoch && epoch - lastEpoch > RECORD_MAX_EPOCH_JUMP) {
            throw SudokuError.ProtocolViolation("record epoch jump")
        }
    }

    private fun aeadOf(method: SudokuAeadMethod): QuicCrypto.Aead = when (method) {
        SudokuAeadMethod.AES_128_GCM -> QuicCrypto.Aead.AES_128_GCM
        else -> QuicCrypto.Aead.CHACHA20_POLY1305
    }

    // The derivation output is 32 bytes, which is longer than AES-128 wants, so
    // the tail is dropped rather than folded in — the reference takes the same
    // prefix, and a different fold would simply not decrypt.
    private fun aeadKey(method: SudokuAeadMethod, key: ByteArray): ByteArray =
        key.copyOf(aeadOf(method).keyLength)

    // Key schedule.

    /** HKDF-Expand labels for the keys a connection starts out with. */
    const val LABEL_PSK_C2S = "sudoku-psk-c2s"
    const val LABEL_PSK_S2C = "sudoku-psk-s2c"

    /** ...and for the ones it moves to once X25519 has run. */
    const val LABEL_SESSION_C2S = "sudoku-session-c2s"
    const val LABEL_SESSION_S2C = "sudoku-session-s2c"

    /** How long every derived base secret is. */
    const val BASE_KEY_SIZE = 32

    /** The two directions' base secrets. */
    class DirectionKeys(val clientToServer: ByteArray, val serverToClient: ByteArray)

    /**
     * The keys a connection opens with, from the pre-shared key alone.
     *
     * SHA-256 of the key is used directly as the HKDF pseudorandom key rather
     * than being run through HKDF-Extract first. That is what the reference
     * does, and therefore what the server expects.
     */
    fun pskBases(psk: String): DirectionKeys {
        val digest = sha256(psk.toByteArray(Charsets.UTF_8))
        return DirectionKeys(
            hkdfExpand(digest, LABEL_PSK_C2S, BASE_KEY_SIZE),
            hkdfExpand(digest, LABEL_PSK_S2C, BASE_KEY_SIZE)
        )
    }

    /**
     * The keys both sides move to after the handshake.
     *
     * The pre-shared key is the salt and the X25519 output followed by the
     * client's nonce is the input keying material, so someone who learns one
     * session's shared secret still cannot derive another's, and someone who
     * knows only the pre-shared key cannot derive any.
     */
    fun sessionBases(psk: String, shared: ByteArray, nonce: ByteArray): DirectionKeys {
        val salt = sha256(psk.toByteArray(Charsets.UTF_8))
        val prk = hmacSha256(salt, shared, nonce)
        return DirectionKeys(
            hkdfExpand(prk, LABEL_SESSION_C2S, BASE_KEY_SIZE),
            hkdfExpand(prk, LABEL_SESSION_S2C, BASE_KEY_SIZE)
        )
    }

    /**
     * The key one epoch's records are sealed under.
     *
     * The AEAD's own name is bound into the derivation so that the same base
     * secret cannot produce the same key under two different ciphers.
     */
    fun recordEpochKey(base: ByteArray, method: SudokuAeadMethod, epoch: Long): ByteArray {
        require(epoch in 0..0xFFFFFFFFL) { "record epoch out of range: $epoch" }
        // `none` never seals anything, so the name it would contribute does not
        // matter; the reference spells everything that is not AES this way.
        val name = if (method == SudokuAeadMethod.AES_128_GCM) {
            SudokuAeadMethod.AES_128_GCM.id
        } else {
            SudokuAeadMethod.CHACHA20_POLY1305.id
        }
        val epochBytes = byteArrayOf(
            (epoch ushr 24).toByte(), (epoch ushr 16).toByte(), (epoch ushr 8).toByte(), epoch.toByte()
        )
        return hmacSha256(
            base,
            RECORD_KEY_LABEL.toByteArray(Charsets.UTF_8),
            name.toByteArray(Charsets.UTF_8),
            epochBytes
        )
    }

    /** HKDF-Expand over HMAC-SHA-256, RFC 5869 §2.3. */
    fun hkdfExpand(prk: ByteArray, info: String, length: Int): ByteArray {
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val out = ByteArray(length)
        var produced = 0
        var block = ByteArray(0)
        var counter = 1
        while (produced < length) {
            block = hmacSha256(prk, block, infoBytes, byteArrayOf(counter.toByte()))
            val take = minOf(block.size, length - produced)
            block.copyInto(out, produced, 0, take)
            produced += take
            counter++
        }
        return out
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** HMAC-SHA-256 over the concatenation of [parts], without joining them first. */
    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (part in parts) if (part.isNotEmpty()) mac.update(part)
        return mac.doFinal()
    }

    // The KIP handshake.

    /** `kip`, then the message type, then a 16-bit big-endian payload length. */
    val KIP_MAGIC = byteArrayOf(0x6B, 0x69, 0x70)
    const val KIP_HEADER_SIZE = 6

    const val KIP_CLIENT_HELLO: Byte = 0x01
    const val KIP_SERVER_HELLO: Byte = 0x02

    /** Request types, sent once the session keys are in place. */
    const val KIP_CONNECT_TCP: Byte = 0x10
    const val KIP_OPEN_MUX: Byte = 0x11
    const val KIP_OPEN_UDP_OVER_TCP: Byte = 0x12

    /** The feature bits this client claims. */
    const val KIP_FEATURE_FLAGS = 0x1F

    const val KIP_NONCE_SIZE = 16
    const val KIP_PUBLIC_KEY_SIZE = 32

    /** timestamp(8) ‖ key fingerprint(8) ‖ nonce(16) ‖ public key(32) ‖ flags(4). */
    const val KIP_CLIENT_HELLO_SIZE = 8 + 8 + KIP_NONCE_SIZE + KIP_PUBLIC_KEY_SIZE + 4

    /** The same with a table fingerprint appended. */
    const val KIP_CLIENT_HELLO_WITH_HINT_SIZE = KIP_CLIENT_HELLO_SIZE + 4

    /** nonce echo(16) ‖ public key(32) ‖ server flags(4). */
    const val KIP_SERVER_HELLO_SIZE = KIP_NONCE_SIZE + KIP_PUBLIC_KEY_SIZE + 4

    /** A parsed KIP message and how many bytes of the buffer it took. */
    class KipMessage(val type: Byte, val payload: ByteArray, val consumed: Int)

    fun encodeKip(type: Byte, payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFF) { "KIP payload of ${payload.size} does not fit a 16-bit length" }
        val out = ByteArray(KIP_HEADER_SIZE + payload.size)
        KIP_MAGIC.copyInto(out)
        out[3] = type
        out[4] = (payload.size ushr 8).toByte()
        out[5] = payload.size.toByte()
        payload.copyInto(out, KIP_HEADER_SIZE)
        return out
    }

    /**
     * Parses a KIP message out of [bytes].
     *
     * A buffer that is too short throws rather than returning null, because the
     * only caller that parses from a buffer — the early-data handshake — has
     * already read everything the server is going to send, so "not yet" and
     * "malformed" are the same answer there.
     */
    fun parseKip(bytes: ByteArray, offset: Int = 0): KipMessage {
        if (bytes.size - offset < KIP_HEADER_SIZE) {
            throw SudokuError.ProtocolViolation("short KIP frame")
        }
        if (bytes[offset] != KIP_MAGIC[0] ||
            bytes[offset + 1] != KIP_MAGIC[1] ||
            bytes[offset + 2] != KIP_MAGIC[2]
        ) {
            throw SudokuError.ProtocolViolation("bad KIP magic")
        }
        val length = ((bytes[offset + 4].toInt() and 0xFF) shl 8) or (bytes[offset + 5].toInt() and 0xFF)
        val end = offset + KIP_HEADER_SIZE + length
        if (end > bytes.size) {
            throw SudokuError.ProtocolViolation(
                "truncated KIP frame ${bytes.size - offset}/${KIP_HEADER_SIZE + length}"
            )
        }
        return KipMessage(
            type = bytes[offset + 3],
            payload = bytes.copyOfRange(offset + KIP_HEADER_SIZE, end),
            consumed = KIP_HEADER_SIZE + length
        )
    }

    /**
     * The client hello payload.
     *
     * [keyFingerprintSource] is the raw private key when the configured key was
     * hex and the key's own UTF-8 bytes otherwise; only the first eight bytes of
     * its digest travel, which is enough for the server to pick the right
     * account without carrying the key itself.
     *
     * [tableHint] is sent only when more than one custom layout is configured —
     * with a single one both sides already agree, and four constant bytes on
     * every hello would be a fingerprint of their own.
     */
    fun encodeClientHello(
        unixSeconds: Long,
        keyFingerprintSource: ByteArray,
        nonce: ByteArray,
        clientPublicKey: ByteArray,
        tableHint: Long? = null
    ): ByteArray {
        require(nonce.size == KIP_NONCE_SIZE) { "a KIP nonce is $KIP_NONCE_SIZE bytes, got ${nonce.size}" }
        require(clientPublicKey.size == KIP_PUBLIC_KEY_SIZE) {
            "an X25519 public key is $KIP_PUBLIC_KEY_SIZE bytes, got ${clientPublicKey.size}"
        }
        require(tableHint == null || tableHint in 0..0xFFFFFFFFL) { "table hint out of range: $tableHint" }

        val out = ByteArray(
            if (tableHint == null) KIP_CLIENT_HELLO_SIZE else KIP_CLIENT_HELLO_WITH_HINT_SIZE
        )
        for (i in 0 until 8) out[i] = (unixSeconds ushr (56 - 8 * i)).toByte()
        sha256(keyFingerprintSource).copyInto(out, 8, 0, 8)
        nonce.copyInto(out, 16)
        clientPublicKey.copyInto(out, 32)
        var at = 32 + KIP_PUBLIC_KEY_SIZE
        at = writeUInt32(out, at, KIP_FEATURE_FLAGS.toLong())
        if (tableHint != null) writeUInt32(out, at, tableHint)
        return out
    }

    /**
     * Checks a server hello and returns the server's X25519 public key.
     *
     * The echoed nonce is what ties the reply to this hello; without the check a
     * recorded server hello could be replayed to make the client derive keys for
     * a session the server never opened.
     */
    fun parseServerHello(payload: ByteArray, expectedNonce: ByteArray): ByteArray {
        if (payload.size != KIP_SERVER_HELLO_SIZE) {
            throw SudokuError.ProtocolViolation("bad KIP server hello")
        }
        if (!payload.copyOf(KIP_NONCE_SIZE).contentEquals(expectedNonce)) {
            throw SudokuError.ProtocolViolation("KIP nonce mismatch")
        }
        return payload.copyOfRange(KIP_NONCE_SIZE, KIP_NONCE_SIZE + KIP_PUBLIC_KEY_SIZE)
    }

    // Destination addresses.

    /** Address type bytes, the same three SOCKS5 uses (RFC 1928 §5). */
    const val ADDRESS_IPV4: Byte = 0x01
    const val ADDRESS_DOMAIN: Byte = 0x03
    const val ADDRESS_IPV6: Byte = 0x04

    /** A domain's length is one byte, so no longer name can be expressed. */
    const val MAX_DOMAIN_LENGTH = 255

    /**
     * A destination in SOCKS5 address form, which is what a connect request and
     * every UDP-over-TCP frame carry.
     *
     * An over-long name is refused rather than truncated: a truncated name
     * resolves to some other host, which is worse than a failed connection.
     */
    fun encodeAddress(host: String, port: Int): ByteArray {
        require(port in 0..0xFFFF) { "port out of range: $port" }
        if (host.toByteArray(Charsets.UTF_8).size > MAX_DOMAIN_LENGTH) {
            throw SudokuError.InvalidConfiguration("domain too long")
        }
        // Byte-identical to what Sudoku wants, so it is shared rather than
        // written out a second time here.
        return AnyTlsProtocol.encodeAddress(host, port)
    }

    // UDP over TCP.

    /** addressLength(2) ‖ payloadLength(2), big-endian. */
    const val UOT_HEADER_SIZE = 4

    /** Neither field may name more than this, which is well past any datagram. */
    const val UOT_MAX_ADDRESS_SIZE = 64 * 1024
    const val UOT_MAX_PAYLOAD_SIZE = 64 * 1024

    /** One datagram, framed for the UDP-over-TCP stream. */
    fun encodeUdpOverTcp(host: String, port: Int, payload: ByteArray): ByteArray {
        val address = encodeAddress(host, port)
        if (payload.size > 0xFFFF) {
            throw SudokuError.ProtocolViolation("UoT payload too large: ${payload.size}")
        }
        val out = ByteArray(UOT_HEADER_SIZE + address.size + payload.size)
        out[0] = (address.size ushr 8).toByte()
        out[1] = address.size.toByte()
        out[2] = (payload.size ushr 8).toByte()
        out[3] = payload.size.toByte()
        address.copyInto(out, UOT_HEADER_SIZE)
        payload.copyInto(out, UOT_HEADER_SIZE + address.size)
        return out
    }

    /** The two lengths that open a UDP-over-TCP frame. */
    class UdpOverTcpHeader(val addressLength: Int, val payloadLength: Int)

    /**
     * Reads that header.
     *
     * A zero-length address is refused: the receiver skips exactly
     * [UdpOverTcpHeader.addressLength] bytes before the payload, and accepting
     * zero would let a peer desynchronise the stream one frame at a time.
     */
    fun parseUdpOverTcpHeader(bytes: ByteArray, offset: Int = 0): UdpOverTcpHeader {
        if (bytes.size - offset < UOT_HEADER_SIZE) {
            throw SudokuError.ProtocolViolation("truncated UoT header")
        }
        val addressLength = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
        val payloadLength = ((bytes[offset + 2].toInt() and 0xFF) shl 8) or (bytes[offset + 3].toInt() and 0xFF)
        if (addressLength <= 0 || addressLength > UOT_MAX_ADDRESS_SIZE) {
            throw SudokuError.ProtocolViolation("bad UoT address length: $addressLength")
        }
        if (payloadLength > UOT_MAX_PAYLOAD_SIZE) {
            throw SudokuError.ProtocolViolation("bad UoT payload length: $payloadLength")
        }
        return UdpOverTcpHeader(addressLength, payloadLength)
    }

    // The stream multiplexer's framing.

    /** type(1) ‖ streamId(4) ‖ length(4), big-endian. */
    const val MUX_HEADER_SIZE = 9

    /** Opens a stream; the payload is the destination address. */
    const val MUX_OPEN: Byte = 0x01

    /** Carries payload, or — on stream 0 with an empty payload — a keepalive. */
    const val MUX_DATA: Byte = 0x02

    /** The sender is done writing. */
    const val MUX_CLOSE: Byte = 0x03

    /** The stream failed; the payload is a UTF-8 reason. */
    const val MUX_RESET: Byte = 0x04

    /** The largest payload one mux frame may carry. */
    const val MUX_MAX_PAYLOAD_SIZE = 256 * 1024

    /** How long a connection may go unwritten before a keepalive is due. */
    const val MUX_KEEPALIVE_INTERVAL_SECONDS = 15L

    fun encodeMuxFrame(type: Byte, streamId: Long, payload: ByteArray): ByteArray {
        require(streamId in 0..0xFFFFFFFFL) { "stream id out of range: $streamId" }
        if (payload.size > MUX_MAX_PAYLOAD_SIZE) {
            throw SudokuError.ProtocolViolation("mux frame too large: ${payload.size}")
        }
        val out = ByteArray(MUX_HEADER_SIZE + payload.size)
        out[0] = type
        writeUInt32(out, 1, streamId)
        writeUInt32(out, 5, payload.size.toLong())
        payload.copyInto(out, MUX_HEADER_SIZE)
        return out
    }

    /** A mux frame header. [length] is how much payload follows it. */
    class MuxHeader(val type: Byte, val streamId: Long, val length: Int)

    fun parseMuxHeader(bytes: ByteArray, offset: Int = 0): MuxHeader {
        if (bytes.size - offset < MUX_HEADER_SIZE) {
            throw SudokuError.ProtocolViolation("truncated mux header")
        }
        val type = bytes[offset]
        if (type != MUX_OPEN && type != MUX_DATA && type != MUX_CLOSE && type != MUX_RESET) {
            throw SudokuError.ProtocolViolation("bad mux frame")
        }
        val streamId = readUInt32(bytes, offset + 1)
        val length = readUInt32(bytes, offset + 5)
        if (length > MUX_MAX_PAYLOAD_SIZE) {
            throw SudokuError.ProtocolViolation("mux frame too large: $length")
        }
        return MuxHeader(type, streamId, length.toInt())
    }

    // HTTP camouflage.

    /** Prefixed to the key before hashing, so this token cannot be reused elsewhere. */
    const val HTTP_MASK_AUTH_PREFIX = "sudoku-httpmask-auth-v1:"

    /** The header a streaming response uses to announce end-of-stream. */
    const val HTTP_MASK_STREAM_EOF_HEADER = "x-sudoku-stream-eof"

    /** How much of the HMAC travels with the timestamp. */
    const val HTTP_MASK_AUTH_TAG_SIZE = 16

    /**
     * The bearer token a masked request carries.
     *
     * The timestamp is sent in the clear and covered by the MAC, which is what
     * lets the server bound how old a token it will accept without keeping
     * per-client state. It is a parameter rather than read from the clock here
     * so that the token is reproducible.
     */
    fun httpMaskAuthToken(
        key: String,
        mode: String,
        method: String,
        path: String,
        unixSeconds: Long
    ): String {
        val authKey = sha256((HTTP_MASK_AUTH_PREFIX + key).toByteArray(Charsets.UTF_8))
        val timestamp = ByteArray(8)
        for (i in 0 until 8) timestamp[i] = (unixSeconds ushr (56 - 8 * i)).toByte()
        val zero = byteArrayOf(0)
        val mac = hmacSha256(
            authKey,
            mode.toByteArray(Charsets.UTF_8), zero,
            method.toByteArray(Charsets.UTF_8), zero,
            path.toByteArray(Charsets.UTF_8), zero,
            timestamp
        )
        val payload = timestamp + mac.copyOf(HTTP_MASK_AUTH_TAG_SIZE)
        // The token travels in a query string as well as in a header, so the
        // URL-safe alphabet is used and the padding dropped.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(payload)
    }

    /** Puts a request path under the configured root, if there is one. */
    fun applyPathRoot(root: String, path: String): String {
        val clean = SudokuHttpMaskConfiguration.normalizePathRoot(root)
        if (clean.isEmpty()) return path
        return "/$clean" + if (path.startsWith("/")) path else "/$path"
    }

    /** Appends the bearer token as a query parameter. */
    fun appendAuth(path: String, token: String): String =
        path + (if (path.contains("?")) "&" else "?") + "auth=$token"

    // Shared byte helpers.

    /**
     * The four hints of one puzzle, sorted and packed into a lookup key.
     *
     * Sorting is what makes the order the sender chose irrelevant to the
     * receiver: every permutation of the same four octets packs to the same key.
     * Five comparisons is the smallest sorting network for four elements.
     */
    fun packHints(a: Byte, b: Byte, c: Byte, d: Byte): Int {
        var h0 = a.toInt() and 0xFF
        var h1 = b.toInt() and 0xFF
        var h2 = c.toInt() and 0xFF
        var h3 = d.toInt() and 0xFF
        if (h0 > h1) { val t = h0; h0 = h1; h1 = t }
        if (h2 > h3) { val t = h2; h2 = h3; h3 = t }
        if (h0 > h2) { val t = h0; h0 = h2; h2 = t }
        if (h1 > h3) { val t = h1; h1 = h3; h3 = t }
        if (h1 > h2) { val t = h1; h1 = h2; h2 = t }
        return (h0 shl 24) or (h1 shl 16) or (h2 shl 8) or h3
    }

    private fun writeUInt32(out: ByteArray, at: Int, value: Long): Int {
        out[at] = (value ushr 24).toByte()
        out[at + 1] = (value ushr 16).toByte()
        out[at + 2] = (value ushr 8).toByte()
        out[at + 3] = value.toByte()
        return at + 4
    }

    private fun readUInt32(bytes: ByteArray, at: Int): Long =
        ((bytes[at].toLong() and 0xFF) shl 24) or
            ((bytes[at + 1].toLong() and 0xFF) shl 16) or
            ((bytes[at + 2].toLong() and 0xFF) shl 8) or
            (bytes[at + 3].toLong() and 0xFF)
}

/** What can go wrong in Sudoku's codec. */
sealed class SudokuError(message: String) : IOException(message) {
    /** The configuration cannot produce a working connection. */
    class InvalidConfiguration(detail: String) : SudokuError(detail)

    /** The peer sent something the wire format does not allow. */
    class ProtocolViolation(detail: String) : SudokuError(detail)

    /** An HTTP-mask tunnel request or response failed. */
    class HttpMaskFailed(detail: String) : SudokuError(detail)

    /** A multiplexed Sudoku stream or session is closed. */
    class StreamClosed(detail: String) : SudokuError(detail)
}

/**
 * The xorshift64* generator that drives the obfuscation.
 *
 * It decides which of a byte's several puzzles to send, in which order the four
 * hints go out, and where padding lands. None of that has to be unpredictable to
 * the peer — the peer never reproduces the stream, it only decodes it — so the
 * generator is seeded once per connection from the system entropy source and
 * then runs on its own. Being reproducible from a seed is what makes the encoder
 * testable at all.
 */
class SudokuXorshift64Star(seed: Long) {

    private var state: Long = if (seed == 0L) INITIAL_STATE else seed

    /**
     * The unused half of the last 64-bit draw, or [NO_CACHE].
     *
     * A 32-bit request consumes a whole step and keeps the low word for the next
     * one, so a stream of them advances the state half as often. Handing out the
     * words in the other order would desynchronise the padding pattern from what
     * the reference produces for the same seed.
     */
    private var cached: Long = NO_CACHE

    private fun generate(): Long {
        var x = state
        x = x xor (x ushr 12)
        x = x xor (x shl 25)
        x = x xor (x ushr 27)
        state = x
        return x * MULTIPLIER
    }

    /** A full 64-bit draw, discarding any cached half-word. */
    fun nextUInt64(): Long {
        cached = NO_CACHE
        return generate()
    }

    /** The next 32-bit draw, as a value in `0..0xFFFFFFFF`. */
    fun nextUInt32(): Long {
        val hit = cached
        if (hit != NO_CACHE) {
            cached = NO_CACHE
            return hit
        }
        val value = generate()
        cached = value and 0xFFFFFFFFL
        return (value ushr 32) and 0xFFFFFFFFL
    }

    /**
     * A value in `0 until n`, by multiply-and-shift rather than by remainder.
     *
     * The tiny bias this leaves is deliberate: it costs one multiply instead of
     * a rejection loop, and the choice it makes is cover traffic, not a key.
     */
    fun intn(n: Int): Int {
        if (n <= 1) return 0
        return ((nextUInt32() * n) ushr 32).toInt()
    }

    /**
     * Draws this connection's padding rate, somewhere in `[min, max]` percent,
     * scaled to [SudokuProtocol.PROBABILITY_ONE].
     *
     * Picking once per connection rather than per byte is what makes the rate
     * itself unobservable: an eavesdropper sees one ratio and cannot tell
     * whether it was configured or drawn.
     */
    fun pickPaddingThreshold(min: Int, max: Int): Long {
        val low = min.coerceIn(0, 100)
        val high = max.coerceAtLeast(low).coerceAtMost(100)
        val minThreshold = low * SudokuProtocol.PROBABILITY_ONE / 100
        val maxThreshold = high * SudokuProtocol.PROBABILITY_ONE / 100
        if (maxThreshold <= minThreshold) return minThreshold
        // The product is below 2^64, so the wrapped Long holds its exact bits
        // and a logical shift reads the high word back unsigned.
        return minThreshold + ((nextUInt32() * (maxThreshold - minThreshold)) ushr 32)
    }

    private companion object {
        /** Any non-zero state will do; this is the reference's choice. */
        const val INITIAL_STATE = -0x61c8864680b583ebL

        const val MULTIPLIER = 0x2545f4914f6cdd1dL

        /** Out of the `0..0xFFFFFFFF` range a real cached word occupies. */
        const val NO_CACHE = -1L
    }
}

/**
 * Go's `math/rand` lagged Fibonacci source, transcribed.
 *
 * This is not a design choice so much as a compatibility one: the server shuffles
 * its deck of grids with Go's default source seeded from the key, and a client
 * that shuffles differently derives a different deck and decodes nothing. So the
 * generator has to be bit-for-bit Go's, cooked seed table included.
 */
class SudokuGoSource(seed: Long) {

    private var tap = 0
    private var feed = LENGTH - TAP
    private val lag = LongArray(LENGTH)

    init {
        var s = seed % INT32_MAX
        if (s < 0) s += INT32_MAX
        if (s == 0L) s = 89482311L
        var x = s.toInt()
        for (i in -20 until LENGTH) {
            x = seedrand(x)
            if (i < 0) continue
            var u = x.toLong() shl 40
            x = seedrand(x)
            u = u xor (x.toLong() shl 20)
            x = seedrand(x)
            u = u xor x.toLong()
            lag[i] = u xor SUDOKU_GO_COOKED[i]
        }
    }

    /** Lehmer's generator, in the Schrage form Go uses to stay inside 32 bits. */
    private fun seedrand(value: Int): Int {
        val hi = value / Q
        val lo = value % Q
        val x = A * lo - R * hi
        return if (x < 0) x + INT32_MAX.toInt() else x
    }

    fun nextUInt64(): Long {
        tap--
        if (tap < 0) tap += LENGTH
        feed--
        if (feed < 0) feed += LENGTH
        val x = lag[feed] + lag[tap]
        lag[feed] = x
        return x
    }

    /**
     * A value in `0 until n`, with the rejection loop Go uses so that the result
     * is exactly uniform.
     *
     * The bias here would be visible in the shuffled deck, and the deck is shared
     * state with the server, so this one cannot take [SudokuXorshift64Star]'s
     * shortcut.
     */
    fun int31n(n: Int): Int {
        require(n > 0) { "int31n needs a positive bound, got $n" }
        val bound = n.toLong() and 0xFFFFFFFFL
        var x = nextUInt64() and 0x7FFFFFFFFFFFFFFFL
        var product = ((x ushr 31) and 0xFFFFFFFFL) * bound
        var low = product and 0xFFFFFFFFL
        if (low < bound) {
            val threshold = ((-n).toLong() and 0xFFFFFFFFL) % bound
            while (low < threshold) {
                x = nextUInt64() and 0x7FFFFFFFFFFFFFFFL
                product = ((x ushr 31) and 0xFFFFFFFFL) * bound
                low = product and 0xFFFFFFFFL
            }
        }
        return (product ushr 32).toInt()
    }

    private companion object {
        const val LENGTH = 607
        const val TAP = 273
        const val INT32_MAX = 2147483647L
        const val A = 48271
        const val Q = 44488
        const val R = 3399
    }
}

/**
 * Everything about 4x4 Sudoku that does not depend on the key.
 *
 * There are exactly 288 complete 4x4 grids and exactly 1820 ways to choose four
 * of the sixteen cells, and both ends enumerate them in the same order — the
 * deck the key shuffles is this list, so the order is part of the wire format.
 */
object SudokuStaticTables {

    /** All 288 complete grids, row-major, values 1..4. */
    val grids: Array<ByteArray> = buildGrids()

    /** All 1820 ascending four-cell position sets. */
    val hintPositions: Array<ByteArray> = buildPositions()

    private fun buildGrids(): Array<ByteArray> {
        val out = ArrayList<ByteArray>(288)
        fill(ByteArray(16), 0, out)
        return out.toTypedArray()
    }

    private fun fill(current: ByteArray, index: Int, out: MutableList<ByteArray>) {
        if (index == 16) {
            out.add(current.copyOf())
            return
        }
        for (number in 1..4) {
            if (!isValid(current, index, number.toByte())) continue
            current[index] = number.toByte()
            fill(current, index + 1, out)
            current[index] = 0
        }
    }

    private fun isValid(grid: ByteArray, index: Int, number: Byte): Boolean {
        val row = index / 4
        val column = index % 4
        for (i in 0 until 4) {
            if (grid[row * 4 + i] == number || grid[i * 4 + column] == number) return false
        }
        val boxRow = (row / 2) * 2
        val boxColumn = (column / 2) * 2
        for (r in 0 until 2) {
            for (c in 0 until 2) {
                if (grid[(boxRow + r) * 4 + (boxColumn + c)] == number) return false
            }
        }
        return true
    }

    private fun buildPositions(): Array<ByteArray> {
        val out = ArrayList<ByteArray>(1820)
        for (a in 0 until 13) {
            for (b in a + 1 until 14) {
                for (c in b + 1 until 15) {
                    for (d in c + 1 until 16) {
                        out.add(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte()))
                    }
                }
            }
        }
        return out.toTypedArray()
    }
}

/**
 * Where a hint's three fields live inside its wire byte.
 *
 * A hint carries a cell value (two bits) and a cell position (four bits); the
 * layout says which bits of the octet those go in and which octets are therefore
 * *not* hints and so may be used as padding. That choice is what makes one
 * Sudoku stream look like text and another like compressed data.
 */
class SudokuLayout private constructor(
    val name: String,

    /**
     * The padding byte that also means "discard any partial group".
     *
     * Only the packed downlink acts on it — a pure stream has nothing partial to
     * discard — where it lets the server flush a six-bit remainder rather than
     * hold the connection open for two more bits.
     */
    val padMarker: Byte,

    /** The octets a sender may insert between hints. */
    val paddingPool: ByteArray,

    /** `[value 0..3][position 0..15]` to the octet that expresses it. */
    val encodeHint: Array<ByteArray>,

    /** Which of the 256 octets are hints rather than padding. */
    val hintTable: BooleanArray,

    /** For a hint octet, its six-bit group: `value shl 4` or `position`. */
    val decodeGroup: ByteArray,

    /** Which octets carry a group the packed downlink may use. */
    val groupValid: BooleanArray
) {
    companion object {

        /**
         * Hints in `0x40..0x7F`, padding in `0x20..0x3F`: printable ASCII
         * throughout, so the stream survives anything that expects text.
         *
         * `0x7F` is delete rather than printable, so the one hint that would land
         * there is moved to newline; nothing else maps to `0x0A`, which is why
         * the two can share a decoded group.
         */
        fun ascii(): SudokuLayout {
            val padding = ByteArray(32) { (0x20 + it).toByte() }
            val encodeHint = Array(4) { value ->
                ByteArray(16) { position ->
                    val b = 0x40 or (value shl 4) or position
                    (if (b == 0x7F) 0x0A else b).toByte()
                }
            }
            val hint = BooleanArray(256)
            val groupValid = BooleanArray(256)
            val decode = ByteArray(256)
            for (i in 0 until 256) {
                if ((i and 0x40) != 0x40) continue
                hint[i] = true
                groupValid[i] = true
                decode[i] = (i and 0x3F).toByte()
            }
            hint[0x0A] = true
            groupValid[0x0A] = true
            decode[0x0A] = 0x3F
            return SudokuLayout(
                SudokuProtocol.LAYOUT_ASCII, 0x3F, padding, encodeHint, hint, decode, groupValid
            )
        }

        /**
         * Hints wherever bits 4 and 7 are clear, padding interleaved from the two
         * bands around them.
         *
         * The result spans the octet space rather than clustering, which is what
         * a censor looking for structure in a byte histogram would want not to
         * find.
         */
        fun entropy(): SudokuLayout {
            val padding = ByteArray(16)
            for (i in 0 until 8) {
                padding[i * 2] = (0x80 + i).toByte()
                padding[i * 2 + 1] = (0x10 + i).toByte()
            }
            val encodeHint = Array(4) { value ->
                ByteArray(16) { position -> ((value shl 5) or position).toByte() }
            }
            val hint = BooleanArray(256)
            val groupValid = BooleanArray(256)
            val decode = ByteArray(256)
            for (i in 0 until 256) {
                if ((i and 0x90) != 0) continue
                hint[i] = true
                groupValid[i] = true
                decode[i] = (((i shr 1) and 0x30) or (i and 0x0F)).toByte()
            }
            return SudokuLayout(
                SudokuProtocol.LAYOUT_ENTROPY, 0x80.toByte(), padding, encodeHint, hint, decode, groupValid
            )
        }

        /**
         * A layout described by an eight-character pattern, one character per
         * bit from the most significant down: two `x` marks that every hint sets
         * and no padding byte sets, two `p` for the cell value, four `v` for the
         * cell position.
         *
         * Padding candidates are the same shapes with one `x` bit cleared, kept
         * only when at least five bits are set — a sparse padding byte would
         * stand out against hints that always carry both marks.
         */
        fun custom(pattern: String): SudokuLayout {
            val cleaned = pattern.lowercase().filter { it != ' ' }
            if (cleaned.length != SudokuProtocol.CUSTOM_PATTERN_LENGTH) reject()

            val xBits = ArrayList<Int>(2)
            val pBits = ArrayList<Int>(2)
            val vBits = ArrayList<Int>(4)
            cleaned.forEachIndexed { index, character ->
                val bit = 7 - index
                when (character) {
                    'x' -> if (xBits.size < 2) xBits.add(bit) else reject()
                    'p' -> if (pBits.size < 2) pBits.add(bit) else reject()
                    'v' -> if (vBits.size < 4) vBits.add(bit) else reject()
                    else -> reject()
                }
            }
            if (xBits.size != 2 || pBits.size != 2 || vBits.size != 4) reject()
            val xMask = (1 shl xBits[0]) or (1 shl xBits[1])

            val encodeHint = Array(4) { value ->
                ByteArray(16) { position -> (xMask or fieldBits(value, position, pBits, vBits)).toByte() }
            }

            val padding = sortedSetOf<Int>()
            for (value in 0 until 4) {
                for (position in 0 until 16) {
                    for (dropped in 0 until 2) {
                        val candidate = (xMask and (1 shl xBits[dropped]).inv()) or
                            fieldBits(value, position, pBits, vBits)
                        if (Integer.bitCount(candidate and 0xFF) >= 5) padding.add(candidate)
                    }
                }
            }
            if (padding.isEmpty()) reject()

            val hint = BooleanArray(256)
            val groupValid = BooleanArray(256)
            val decode = ByteArray(256)
            for (wire in 0 until 256) {
                if ((wire and xMask) != xMask) continue
                var value = 0
                if ((wire and (1 shl pBits[0])) != 0) value = value or 0x02
                if ((wire and (1 shl pBits[1])) != 0) value = value or 0x01
                var position = 0
                for (group in 0 until 4) {
                    if ((wire and (1 shl vBits[group])) != 0) position = position or (1 shl (3 - group))
                }
                hint[wire] = true
                groupValid[wire] = true
                decode[wire] = ((value shl 4) or position).toByte()
            }

            val pool = ByteArray(padding.size)
            padding.forEachIndexed { index, byte -> pool[index] = byte.toByte() }
            return SudokuLayout(
                "custom($cleaned)", pool[0], pool, encodeHint, hint, decode, groupValid
            )
        }

        private fun reject(): Nothing =
            throw SudokuError.InvalidConfiguration("invalid custom Sudoku table")

        /** The value and position bits of one hint, without the `x` marks. */
        private fun fieldBits(value: Int, position: Int, pBits: List<Int>, vBits: List<Int>): Int {
            var out = 0
            if ((value and 2) != 0) out = out or (1 shl pBits[0])
            if ((value and 1) != 0) out = out or (1 shl pBits[1])
            for (group in 0 until 4) {
                if (((position shr (3 - group)) and 1) != 0) out = out or (1 shl vBits[group])
            }
            return out
        }
    }
}

/**
 * One direction's codebook: the key-shuffled deck, and the puzzles each byte may
 * be sent as.
 *
 * Building it is where the key does its work. The deck of 288 grids is shuffled
 * with Go's generator seeded from the first eight bytes of the key's digest, and
 * byte *n* is assigned grid *n* of the shuffled deck. Every four-cell clue set of
 * that grid which no *other* grid also satisfies becomes a legal encoding of the
 * byte — a byte typically has dozens, which is why the same plaintext never looks
 * the same twice on the wire.
 *
 * The table is immutable once built and safe to share; building it costs a few
 * milliseconds, so callers should keep one per key rather than one per
 * connection.
 */
class SudokuTable internal constructor(
    key: String,
    token: String,
    customPattern: String,

    /** The fingerprint of the key, mode and patterns this table was built from. */
    val hint: Long
) {
    val layout: SudokuLayout = when {
        token == SudokuProtocol.LAYOUT_ASCII -> SudokuLayout.ascii()
        customPattern.isNotEmpty() -> SudokuLayout.custom(customPattern)
        else -> SudokuLayout.entropy()
    }

    /** For each byte, the four-hint puzzles that decode back to it. */
    private val encodeTable: Array<Array<ByteArray>>

    // The reverse direction is a sorted key array searched with binary search
    // rather than a hash map: the lookup runs once per four wire bytes, and
    // boxing an Int key on every one of them would be the decoder's largest
    // single source of garbage.
    private val decodeKeys: IntArray
    private val decodeValues: ByteArray

    init {
        val statics = SudokuStaticTables
        val positions = statics.hintPositions
        val shuffled = Array(statics.grids.size) { statics.grids[it] }

        val digest = SudokuProtocol.sha256(key.toByteArray(Charsets.UTF_8))
        var seed = 0L
        for (i in 0 until 8) seed = (seed shl 8) or (digest[i].toLong() and 0xFF)
        val random = SudokuGoSource(seed)
        for (i in shuffled.size - 1 downTo 1) {
            val j = random.int31n(i + 1)
            val swap = shuffled[i]
            shuffled[i] = shuffled[j]
            shuffled[j] = swap
        }

        // How many grids satisfy each clue set, saturating at two because only
        // "exactly one" matters. The reference rescans all 288 grids for every
        // one of the 256 x 1820 candidates; counting first computes the same
        // answers from the same grids, and turns minutes into milliseconds.
        val counts = Array(positions.size) { ByteArray(256) }
        for (p in positions.indices) {
            val cells = positions[p]
            val row = counts[p]
            for (grid in statics.grids) {
                val slot = clueSlot(
                    grid[cells[0].toInt()], grid[cells[1].toInt()],
                    grid[cells[2].toInt()], grid[cells[3].toInt()]
                )
                if (row[slot] < 2) row[slot]++
            }
        }

        val encode = arrayOfNulls<Array<ByteArray>>(256)
        // Insertion order matters only in that a later entry would win, as it
        // does in the reference's dictionary; in practice no two bytes ever
        // produce the same sorted quadruple, since a unique clue set names
        // exactly one grid and every byte holds a different one.
        val decode = LinkedHashMap<Int, Byte>(1 shl 15)
        for (value in 0 until 256) {
            val target = shuffled[value]
            val puzzles = ArrayList<ByteArray>(64)
            for (p in positions.indices) {
                val cells = positions[p]
                val v0 = target[cells[0].toInt()]
                val v1 = target[cells[1].toInt()]
                val v2 = target[cells[2].toInt()]
                val v3 = target[cells[3].toInt()]
                if (counts[p][clueSlot(v0, v1, v2, v3)].toInt() != 1) continue
                val hints = byteArrayOf(
                    layout.encodeHint[v0 - 1][cells[0].toInt()],
                    layout.encodeHint[v1 - 1][cells[1].toInt()],
                    layout.encodeHint[v2 - 1][cells[2].toInt()],
                    layout.encodeHint[v3 - 1][cells[3].toInt()]
                )
                puzzles.add(hints)
                decode[SudokuProtocol.packHints(hints[0], hints[1], hints[2], hints[3])] = value.toByte()
            }
            encode[value] = puzzles.toTypedArray()
        }

        @Suppress("UNCHECKED_CAST")
        encodeTable = encode as Array<Array<ByteArray>>
        decodeKeys = decode.keys.toIntArray().also { it.sort() }
        decodeValues = ByteArray(decodeKeys.size) { decode[decodeKeys[it]]!! }
    }

    /** How many distinct puzzles [value] may be sent as. */
    fun puzzleCount(value: Int): Int = encodeTable[value and 0xFF].size

    /**
     * Encodes [data], drawing puzzles, hint order and padding from [rng].
     *
     * [paddingThreshold] is compared against a fresh 32-bit draw at each of the
     * five slots per byte, so zero means no padding at all,
     * [SudokuProtocol.PROBABILITY_ONE] or more means one padding byte in every
     * slot — both of which the reference special-cases, since at those two
     * extremes the draw would be wasted and the generator would fall out of step.
     */
    fun encode(data: ByteArray, rng: SudokuXorshift64Star, paddingThreshold: Long): ByteArray {
        require(paddingThreshold >= 0) { "padding threshold out of range: $paddingThreshold" }
        val pool = layout.paddingPool
        val out = ByteArrayOutputStream(maxOf(64, data.size * 6 + 8))

        if (paddingThreshold == 0L) {
            for (byte in data) writePuzzle(out, byte, rng)
            return out.toByteArray()
        }

        if (paddingThreshold >= SudokuProtocol.PROBABILITY_ONE) {
            for (byte in data) {
                out.write(pool[rng.intn(pool.size)].toInt())
                writePuzzle(out, byte, rng) { out.write(pool[rng.intn(pool.size)].toInt()) }
            }
            out.write(pool[rng.intn(pool.size)].toInt())
            return out.toByteArray()
        }

        for (byte in data) {
            if (rng.nextUInt32() < paddingThreshold) out.write(pool[rng.intn(pool.size)].toInt())
            writePuzzle(out, byte, rng) {
                if (rng.nextUInt32() < paddingThreshold) out.write(pool[rng.intn(pool.size)].toInt())
            }
        }
        if (rng.nextUInt32() < paddingThreshold) out.write(pool[rng.intn(pool.size)].toInt())
        return out.toByteArray()
    }

    /**
     * Writes one byte's four hints, calling [beforeEachHint] in the slot ahead of
     * each. The hints go out in a random order because their positions are
     * recoverable from the octets themselves.
     */
    private inline fun writePuzzle(
        out: ByteArrayOutputStream,
        byte: Byte,
        rng: SudokuXorshift64Star,
        beforeEachHint: () -> Unit = {}
    ) {
        val puzzles = encodeTable[byte.toInt() and 0xFF]
        val puzzle = puzzles[rng.intn(puzzles.size)]
        val permutation = SUDOKU_PERMUTATIONS[rng.intn(SUDOKU_PERMUTATIONS.size)]
        for (index in permutation) {
            beforeEachHint()
            out.write(puzzle[index].toInt())
        }
    }

    /** The byte four hints stand for, or -1 when they name no grid. */
    fun decodePackedHints(packed: Int): Int {
        val at = java.util.Arrays.binarySearch(decodeKeys, packed)
        return if (at < 0) -1 else decodeValues[at].toInt() and 0xFF
    }

    private companion object {
        /** Four cell values, 1..4 each, packed into one index. */
        fun clueSlot(a: Byte, b: Byte, c: Byte, d: Byte): Int =
            ((a - 1) shl 6) or ((b - 1) shl 4) or ((c - 1) shl 2) or (d - 1)
    }
}

/**
 * The two codebooks a connection uses, and the fingerprint that names them.
 *
 * The directions are separate because a mode may ask for a different layout each
 * way; when both sides come out the same the uplink table is shared rather than
 * built twice, which halves the setup cost of the common configurations.
 */
class SudokuTablePair(
    key: String,
    asciiMode: SudokuAsciiMode,
    customUplink: String = "",
    customDownlink: String = ""
) {
    /**
     * A fingerprint of everything the tables were derived from.
     *
     * It is a property of the pair rather than of a table, and it travels in the
     * client hello when several custom layouts are configured, so the server can
     * tell which one this client picked without the pattern itself going on the
     * wire.
     */
    val hint: Long

    val uplink: SudokuTable
    val downlink: SudokuTable

    init {
        // A custom pattern only ever replaces the entropy layout; the ASCII one
        // is fixed, so a pattern given for an ASCII direction is dropped rather
        // than applied, and must be dropped from the fingerprint too.
        val uplinkPattern = if (asciiMode.uplinkToken == SudokuProtocol.LAYOUT_ENTROPY) customUplink else ""
        val downlinkPattern = if (asciiMode.downlinkToken == SudokuProtocol.LAYOUT_ENTROPY) customDownlink else ""

        hint = tableHintFingerprint(key, asciiMode.id, uplinkPattern, downlinkPattern)
        uplink = SudokuTable(key, asciiMode.uplinkToken, uplinkPattern, hint)
        downlink = if (asciiMode.uplinkToken == asciiMode.downlinkToken && uplinkPattern == downlinkPattern) {
            uplink
        } else {
            SudokuTable(key, asciiMode.downlinkToken, downlinkPattern, hint)
        }
    }

    companion object {
        /** Domain separator for the fingerprint. */
        const val HINT_LABEL = "sudoku-table-hint"

        /**
         * The first four bytes of a digest over the label and the four inputs,
         * each preceded by a zero byte.
         *
         * The separators matter: without them a key ending in the mode's first
         * characters would fingerprint the same as a shorter key and a longer
         * mode, and two configurations that are not interchangeable would claim
         * to be.
         */
        fun tableHintFingerprint(
            key: String,
            mode: String,
            uplinkPattern: String,
            downlinkPattern: String
        ): Long {
            val out = ByteArrayOutputStream()
            out.write(HINT_LABEL.toByteArray(Charsets.UTF_8))
            for (part in listOf(key, mode, uplinkPattern.trim().lowercase(), downlinkPattern.trim().lowercase())) {
                out.write(0)
                out.write(part.toByteArray(Charsets.UTF_8))
            }
            val digest = SudokuProtocol.sha256(out.toByteArray())
            return ((digest[0].toLong() and 0xFF) shl 24) or
                ((digest[1].toLong() and 0xFF) shl 16) or
                ((digest[2].toLong() and 0xFF) shl 8) or
                (digest[3].toLong() and 0xFF)
        }
    }
}

/**
 * Decoded bytes a caller did not have room for.
 *
 * A decoder is handed a chunk of wire bytes and an output limit, and one chunk
 * can produce more than the limit allows. Dropping the surplus would corrupt the
 * stream and refusing the chunk would mean decoding it twice, so it is held here
 * until the next call.
 */
private class SudokuPendingBytes {
    private var storage = ByteArray(0)
    private var start = 0
    private var end = 0

    val available: Int get() = end - start

    fun append(value: Byte) {
        if (end == storage.size) {
            if (start > 0) {
                storage.copyInto(storage, 0, start, end)
                end -= start
                start = 0
            }
            if (end == storage.size) storage = storage.copyOf(maxOf(64, storage.size * 2))
        }
        storage[end++] = value
    }

    /** Moves up to [limit] bytes out, returning how many went. */
    fun drainInto(out: ByteArrayOutputStream, limit: Int): Int {
        val count = minOf(limit, available)
        if (count <= 0) return 0
        out.write(storage, start, count)
        start += count
        if (start == end) {
            start = 0
            end = 0
        }
        return count
    }
}

/**
 * Decodes a stream of whole puzzles back into bytes.
 *
 * This is the "pure" downlink, and the exact inverse of [SudokuTable.encode]:
 * non-hint octets are padding and are dropped, and every four hints are a byte.
 * The decoder keeps its partial group across calls, so a puzzle split over two
 * reads — or delivered a byte at a time — decodes the same as one that arrived
 * whole.
 */
class SudokuPureDecoder(private val table: SudokuTable) {

    private val hints = ByteArray(4)
    private var hintCount = 0
    private val pending = SudokuPendingBytes()

    /** Decoded bytes held back from an earlier call by its limit. */
    val pendingCount: Int get() = pending.available

    /**
     * Decodes [data], returning at most [limit] bytes and holding any surplus for
     * the next call.
     */
    fun decode(data: ByteArray, limit: Int = Int.MAX_VALUE): ByteArray {
        if (limit <= 0) return EMPTY_BYTES
        if (data.isEmpty() && pending.available == 0) return EMPTY_BYTES

        val out = ByteArrayOutputStream(maxOf(32, minOf(limit, data.size)))
        var written = pending.drainInto(out, limit)
        val hintTable = table.layout.hintTable

        for (byte in data) {
            if (!hintTable[byte.toInt() and 0xFF]) continue
            hints[hintCount++] = byte
            if (hintCount < 4) continue
            hintCount = 0
            val value = table.decodePackedHints(SudokuProtocol.packHints(hints[0], hints[1], hints[2], hints[3]))
            if (value < 0) throw SudokuError.ProtocolViolation("Sudoku decode failed")
            if (written < limit) {
                out.write(value)
                written++
            } else {
                pending.append(value.toByte())
            }
        }
        return out.toByteArray()
    }
}

/**
 * Decodes the packed downlink, where a hint octet stands for six bits of
 * plaintext rather than a quarter of a puzzle.
 *
 * It is the cheaper of the two downlink forms — four octets carry three bytes
 * instead of one — at the cost of no longer looking like the uplink. The bit
 * buffer, like the pure decoder's partial group, survives across calls, and
 * [SudokuLayout.padMarker] clears it so the sender can end a message that does
 * not fall on a byte boundary.
 */
class SudokuPackedDecoder(private val table: SudokuTable) {

    private var bitBuffer = 0L
    private var bitCount = 0
    private val pending = SudokuPendingBytes()

    /** Decoded bytes held back from an earlier call by its limit. */
    val pendingCount: Int get() = pending.available

    fun decode(data: ByteArray, limit: Int = Int.MAX_VALUE): ByteArray {
        if (limit <= 0) return EMPTY_BYTES
        if (data.isEmpty() && pending.available == 0) return EMPTY_BYTES

        val out = ByteArrayOutputStream(maxOf(32, minOf(limit, data.size)))
        var written = pending.drainInto(out, limit)
        val layout = table.layout

        for (byte in data) {
            val index = byte.toInt() and 0xFF
            if (!layout.hintTable[index]) {
                if (byte == layout.padMarker) {
                    bitBuffer = 0
                    bitCount = 0
                }
                continue
            }
            if (!layout.groupValid[index]) throw SudokuError.ProtocolViolation("Sudoku decode failed")
            bitBuffer = (bitBuffer shl 6) or (layout.decodeGroup[index].toLong() and 0xFF)
            bitCount += 6
            while (bitCount >= 8) {
                bitCount -= 8
                val value = ((bitBuffer ushr bitCount) and 0xFF).toInt()
                bitBuffer = if (bitCount == 0) 0L else bitBuffer and ((1L shl bitCount) - 1)
                if (written < limit) {
                    out.write(value)
                    written++
                } else {
                    pending.append(value.toByte())
                }
            }
        }
        return out.toByteArray()
    }
}

/**
 * Turns a configured Ed25519 private key into the public key the tunnel actually
 * shares.
 *
 * A Sudoku key may be given either as the 32-byte public key or as the 64-byte
 * expanded private key an operator gets from the server. Both spellings have to
 * end up at the same pre-shared string, or the two ends derive different record
 * keys — so the 64-byte form is reduced to its scalar and multiplied by the
 * Ed25519 base point here.
 *
 * The arithmetic goes through [BigInteger] rather than packed limbs. This runs
 * once when a connection is configured, never on the data path, and a
 * transcription of hand-rolled 51-bit field arithmetic would be far easier to get
 * subtly wrong than it is to make fast.
 */
object SudokuKeyRecovery {

    /** The order of the Ed25519 prime-order subgroup, little-endian. */
    val GROUP_ORDER = byteArrayOf(
        0xed.toByte(), 0xd3.toByte(), 0xf5.toByte(), 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6.toByte(), 0x9c.toByte(), 0xf7.toByte(), 0xa2.toByte(),
        0xde.toByte(), 0xf9.toByte(), 0xde.toByte(), 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
    )

    /**
     * The public key hex for [keyHex], or null when it is not a key at all.
     *
     * A 32-byte value is already a public key and comes back normalised; a
     * 64-byte one is an expanded private key whose two halves are added mod the
     * group order before the base multiplication. Anything else is a passphrase
     * rather than a key, and the caller uses it verbatim.
     */
    fun recoverPublicKeyHex(keyHex: String): String? {
        val raw = decodeHex(keyHex) ?: return null
        if (raw.size != 32 && raw.size != 64) return null
        if (raw.size == 32) return encodeHex(raw)
        val scalar = scalarAdd(raw.copyOf(32), raw.copyOfRange(32, 64))
        return encodeHex(scalarBaseMultiply(scalar))
    }

    /**
     * Adds two little-endian scalars, reducing once if the sum reached the group
     * order.
     *
     * One conditional subtraction is enough because both inputs are already
     * reduced, so their sum is below twice the order.
     */
    fun scalarAdd(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == 32 && b.size == 32) { "scalars are 32 bytes" }
        val out = ByteArray(32)
        var carry = 0
        for (i in 0 until 32) {
            val sum = (a[i].toInt() and 0xFF) + (b[i].toInt() and 0xFF) + carry
            out[i] = sum.toByte()
            carry = sum shr 8
        }
        if (carry != 0 || isAtLeastGroupOrder(out)) subtractGroupOrder(out)
        return out
    }

    /**
     * The compressed Ed25519 point [scalar] times the base point.
     *
     * The scalar is taken as given rather than clamped: it has already been
     * reduced mod the group order, and clamping it here would move it.
     */
    fun scalarBaseMultiply(scalar: ByteArray): ByteArray {
        require(scalar.size == 32) { "an Ed25519 scalar is 32 bytes, got ${scalar.size}" }
        var result = IDENTITY
        for (bit in 255 downTo 0) {
            result = add(result, result)
            if (((scalar[bit ushr 3].toInt() ushr (bit and 7)) and 1) != 0) result = add(result, BASE)
        }
        val inverse = result.z.modInverse(P)
        val x = result.x.multiply(inverse).mod(P)
        val y = result.y.multiply(inverse).mod(P)

        val out = ByteArray(32)
        val encoded = y.toByteArray()
        // BigInteger is big-endian and may carry a leading sign byte; the wire
        // form is 32 little-endian bytes with the x parity in the top bit.
        for (i in encoded.indices) {
            val target = encoded.size - 1 - i
            if (target < 32) out[target] = encoded[i]
        }
        out[31] = if (x.testBit(0)) {
            (out[31].toInt() or 0x80).toByte()
        } else {
            (out[31].toInt() and 0x7F).toByte()
        }
        return out
    }

    private fun isAtLeastGroupOrder(scalar: ByteArray): Boolean {
        for (i in 31 downTo 0) {
            val a = scalar[i].toInt() and 0xFF
            val b = GROUP_ORDER[i].toInt() and 0xFF
            if (a > b) return true
            if (a < b) return false
        }
        return true
    }

    private fun subtractGroupOrder(scalar: ByteArray) {
        var borrow = 0
        for (i in 0 until 32) {
            val subtrahend = (GROUP_ORDER[i].toInt() and 0xFF) + borrow
            val current = scalar[i].toInt() and 0xFF
            scalar[i] = (current - subtrahend).toByte()
            borrow = if (current < subtrahend) 1 else 0
        }
    }

    /** A point in extended twisted-Edwards coordinates, where `t = xy/z`. */
    private class Point(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    /**
     * The unified addition formula for `a = -1` twisted Edwards curves.
     *
     * It is complete on this curve — no case distinction, and correct when both
     * operands are the same point — so the ladder can use it for doubling too.
     */
    private fun add(p: Point, q: Point): Point {
        val a = p.y.subtract(p.x).multiply(q.y.subtract(q.x)).mod(P)
        val b = p.y.add(p.x).multiply(q.y.add(q.x)).mod(P)
        val c = D2.multiply(p.t).multiply(q.t).mod(P)
        val d = p.z.multiply(q.z).shiftLeft(1).mod(P)
        val e = b.subtract(a).mod(P)
        val f = d.subtract(c).mod(P)
        val g = d.add(c).mod(P)
        val h = b.add(a).mod(P)
        return Point(
            e.multiply(f).mod(P),
            g.multiply(h).mod(P),
            f.multiply(g).mod(P),
            e.multiply(h).mod(P)
        )
    }

    private fun decodeHex(text: String): ByteArray? {
        if (text.length % 2 != 0 || text.isEmpty()) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val high = Character.digit(text[i * 2], 16)
            val low = Character.digit(text[i * 2 + 1], 16)
            if (high < 0 || low < 0) return null
            out[i] = ((high shl 4) or low).toByte()
        }
        return out
    }

    private fun encodeHex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val value = byte.toInt() and 0xFF
            out.append(HEX_DIGITS[value ushr 4]).append(HEX_DIGITS[value and 0x0F])
        }
        return out.toString()
    }

    private const val HEX_DIGITS = "0123456789abcdef"

    /** 2^255 - 19. */
    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

    /** Twice the curve constant d, which is what the addition formula wants. */
    private val D2 = BigInteger(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555"
    ).shiftLeft(1).mod(P)

    private val IDENTITY = Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    private val BASE = run {
        val x = BigInteger(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202"
        )
        val y = BigInteger(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960"
        )
        Point(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }
}

private val EMPTY_BYTES = ByteArray(0)

/**
 * Every ordering of four hints.
 *
 * The sender picks one per byte so that the puzzle's cells do not arrive in a
 * fixed order; the receiver does not need to know which was chosen, because
 * [packHints] sorts them back.
 */
private val SUDOKU_PERMUTATIONS = arrayOf(
    intArrayOf(0, 1, 2, 3), intArrayOf(0, 1, 3, 2), intArrayOf(0, 2, 1, 3), intArrayOf(0, 2, 3, 1),
    intArrayOf(0, 3, 1, 2), intArrayOf(0, 3, 2, 1), intArrayOf(1, 0, 2, 3), intArrayOf(1, 0, 3, 2),
    intArrayOf(1, 2, 0, 3), intArrayOf(1, 2, 3, 0), intArrayOf(1, 3, 0, 2), intArrayOf(1, 3, 2, 0),
    intArrayOf(2, 0, 1, 3), intArrayOf(2, 0, 3, 1), intArrayOf(2, 1, 0, 3), intArrayOf(2, 1, 3, 0),
    intArrayOf(2, 3, 0, 1), intArrayOf(2, 3, 1, 0), intArrayOf(3, 0, 1, 2), intArrayOf(3, 0, 2, 1),
    intArrayOf(3, 1, 0, 2), intArrayOf(3, 1, 2, 0), intArrayOf(3, 2, 0, 1), intArrayOf(3, 2, 1, 0)
)

/**
 * Go's `rngCooked` table, the 607 constants its lagged Fibonacci source mixes
 * into its state at seed time.
 *
 * These are data, not a design: they exist here only because the server's shuffle
 * comes out of Go's generator and the client has to reproduce it exactly.
 */
private val SUDOKU_GO_COOKED = longArrayOf(
    -4181792142133755926L, -4576982950128230565L, 1395769623340756751L, 5333664234075297259L,
    -6347679516498800754L, 9033628115061424579L, 7143218595135194537L, 4812947590706362721L,
    7937252194349799378L, 5307299880338848416L, 8209348851763925077L, -7107630437535961764L,
    4593015457530856296L, 8140875735541888011L, -5903942795589686782L, -603556388664454774L,
    -7496297993371156308L, 113108499721038619L, 4569519971459345583L, -4160538177779461077L,
    -6835753265595711384L, -6507240692498089696L, 6559392774825876886L, 7650093201692370310L,
    7684323884043752161L, -8965504200858744418L, -2629915517445760644L, 271327514973697897L,
    -6433985589514657524L, 1065192797246149621L, 3344507881999356393L, -4763574095074709175L,
    7465081662728599889L, 1014950805555097187L, -4773931307508785033L, -5742262670416273165L,
    2418672789110888383L, 5796562887576294778L, 4484266064449540171L, 3738982361971787048L,
    -4699774852342421385L, 10530508058128498L, -589538253572429690L, -6598062107225984180L,
    8660405965245884302L, 10162832508971942L, -2682657355892958417L, 7031802312784620857L,
    6240911277345944669L, 831864355460801054L, -1218937899312622917L, 2116287251661052151L,
    2202309800992166967L, 9161020366945053561L, 4069299552407763864L, 4936383537992622449L,
    457351505131524928L, -8881176990926596454L, -6375600354038175299L, -7155351920868399290L,
    4368649989588021065L, 887231587095185257L, -3659780529968199312L, -2407146836602825512L,
    5616972787034086048L, -751562733459939242L, 1686575021641186857L, -5177887698780513806L,
    -4979215821652996885L, -1375154703071198421L, 5632136521049761902L, -8390088894796940536L,
    -193645528485698615L, -5979788902190688516L, -4907000935050298721L, -285522056888777828L,
    -2776431630044341707L, 1679342092332374735L, 6050638460742422078L, -2229851317345194226L,
    -1582494184340482199L, 5881353426285907985L, 812786550756860885L, 4541845584483343330L,
    -6497901820577766722L, 4980675660146853729L, -4012602956251539747L, -329088717864244987L,
    -2896929232104691526L, 1495812843684243920L, -2153620458055647789L, 7370257291860230865L,
    -2466442761497833547L, 4706794511633873654L, -1398851569026877145L, 8549875090542453214L,
    -9189721207376179652L, -7894453601103453165L, 7297902601803624459L, 1011190183918857495L,
    -6985347000036920864L, 5147159997473910359L, -8326859945294252826L, 2659470849286379941L,
    6097729358393448602L, -7491646050550022124L, -5117116194870963097L, -896216826133240300L,
    -745860416168701406L, 5803876044675762232L, -787954255994554146L, -3234519180203704564L,
    -4507534739750823898L, -1657200065590290694L, 505808562678895611L, -4153273856159712438L,
    -8381261370078904295L, 572156825025677802L, 1791881013492340891L, 3393267094866038768L,
    -5444650186382539299L, 2352769483186201278L, -7930912453007408350L, -325464993179687389L,
    -3441562999710612272L, -6489413242825283295L, 5092019688680754699L, -227247482082248967L,
    4234737173186232084L, 5027558287275472836L, 4635198586344772304L, -536033143587636457L,
    5907508150730407386L, -8438615781380831356L, 972392927514829904L, -3801314342046600696L,
    -4064951393885491917L, -174840358296132583L, 2407211146698877100L, -1640089820333676239L,
    3940796514530962282L, -5882197405809569433L, 3095313889586102949L, -1818050141166537098L,
    5832080132947175283L, 7890064875145919662L, 8184139210799583195L, -8073512175445549678L,
    -7758774793014564506L, -4581724029666783935L, 3516491885471466898L, -8267083515063118116L,
    6657089965014657519L, 5220884358887979358L, 1796677326474620641L, 5340761970648932916L,
    1147977171614181568L, 5066037465548252321L, 2574765911837859848L, 1085848279845204775L,
    -5873264506986385449L, 6116438694366558490L, 2107701075971293812L, -7420077970933506541L,
    2469478054175558874L, -1855128755834809824L, -5431463669011098282L, -9038325065738319171L,
    -6966276280341336160L, 7217693971077460129L, -8314322083775271549L, 7196649268545224266L,
    -3585711691453906209L, -5267827091426810625L, 8057528650917418961L, -5084103596553648165L,
    -2601445448341207749L, -7850010900052094367L, 6527366231383600011L, 3507654575162700890L,
    9202058512774729859L, 1954818376891585542L, -2582991129724600103L, 8299563319178235687L,
    -5321504681635821435L, 7046310742295574065L, -2376176645520785576L, -7650733936335907755L,
    8850422670118399721L, 3631909142291992901L, 5158881091950831288L, -6340413719511654215L,
    4763258931815816403L, 6280052734341785344L, -4979582628649810958L, 2043464728020827976L,
    -2678071570832690343L, 4562580375758598164L, 5495451168795427352L, -7485059175264624713L,
    553004618757816492L, 6895160632757959823L, -989748114590090637L, 7139506338801360852L,
    -672480814466784139L, 5535668688139305547L, 2430933853350256242L, -3821430778991574732L,
    -1063731997747047009L, -3065878205254005442L, 7632066283658143750L, 6308328381617103346L,
    3681878764086140361L, 3289686137190109749L, 6587997200611086848L, 244714774258135476L,
    -5143583659437639708L, 8090302575944624335L, 2945117363431356361L, -8359047641006034763L,
    3009039260312620700L, -793344576772241777L, 401084700045993341L, -1968749590416080887L,
    4707864159563588614L, -3583123505891281857L, -3240864324164777915L, -5908273794572565703L,
    -3719524458082857382L, -5281400669679581926L, 8118566580304798074L, 3839261274019871296L,
    7062410411742090847L, -8481991033874568140L, 6027994129690250817L, -6725542042704711878L,
    -2971981702428546974L, -7854441788951256975L, 8809096399316380241L, 6492004350391900708L,
    2462145737463489636L, -8818543617934476634L, -5070345602623085213L, -8961586321599299868L,
    -3758656652254704451L, -8630661632476012791L, 6764129236657751224L, -709716318315418359L,
    -3403028373052861600L, -8838073512170985897L, -3999237033416576341L, -2920240395515973663L,
    -2073249475545404416L, 368107899140673753L, -6108185202296464250L, -6307735683270494757L,
    4782583894627718279L, 6718292300699989587L, 8387085186914375220L, 3387513132024756289L,
    4654329375432538231L, -292704475491394206L, -3848998599978456535L, 7623042350483453954L,
    7725442901813263321L, 9186225467561587250L, -5132344747257272453L, -6865740430362196008L,
    2530936820058611833L, 1636551876240043639L, -3658707362519810009L, 1452244145334316253L,
    -7161729655835084979L, -7943791770359481772L, 9108481583171221009L, -3200093350120725999L,
    5007630032676973346L, 2153168792952589781L, 6720334534964750538L, -3181825545719981703L,
    3433922409283786309L, 2285479922797300912L, 3110614940896576130L, -2856812446131932915L,
    -3804580617188639299L, 7163298419643543757L, 4891138053923696990L, 580618510277907015L,
    1684034065251686769L, 4429514767357295841L, -8893025458299325803L, -8103734041042601133L,
    7177515271653460134L, 4589042248470800257L, -1530083407795771245L, 143607045258444228L,
    246994305896273627L, -8356954712051676521L, 6473547110565816071L, 3092379936208876896L,
    2058427839513754051L, -4089587328327907870L, 8785882556301281247L, -3074039370013608197L,
    -637529855400303673L, 6137678347805511274L, -7152924852417805802L, 5708223427705576541L,
    -3223714144396531304L, 4358391411789012426L, 325123008708389849L, 6837621693887290924L,
    4843721905315627004L, -3212720814705499393L, -3825019837890901156L, 4602025990114250980L,
    1044646352569048800L, 9106614159853161675L, -8394115921626182539L, -4304087667751778808L,
    2681532557646850893L, 3681559472488511871L, -3915372517896561773L, -2889241648411946534L,
    -6564663803938238204L, -8060058171802589521L, 581945337509520675L, 3648778920718647903L,
    -4799698790548231394L, -7602572252857820065L, 220828013409515943L, -1072987336855386047L,
    4287360518296753003L, -4633371852008891965L, 5513660857261085186L, -2258542936462001533L,
    -8744380348503999773L, 8746140185685648781L, 228500091334420247L, 1356187007457302238L,
    3019253992034194581L, 3152601605678500003L, -8793219284148773595L, 5559581553696971176L,
    4916432985369275664L, -8559797105120221417L, -5802598197927043732L, 2868348622579915573L,
    -7224052902810357288L, -5894682518218493085L, 2587672709781371173L, -7706116723325376475L,
    3092343956317362483L, -5561119517847711700L, 972445599196498113L, -1558506600978816441L,
    1708913533482282562L, -2305554874185907314L, -6005743014309462908L, -6653329009633068701L,
    -483583197311151195L, 2488075924621352812L, -4529369641467339140L, -4663743555056261452L,
    2997203966153298104L, 1282559373026354493L, 240113143146674385L, 8665713329246516443L,
    628141331766346752L, -4651421219668005332L, -7750560848702540400L, 7596648026010355826L,
    -3132152619100351065L, 7834161864828164065L, 7103445518877254909L, 4390861237357459201L,
    -4780718172614204074L, -319889632007444440L, 622261699494173647L, -3186110786557562560L,
    -8718967088789066690L, -1948156510637662747L, -8212195255998774408L, -7028621931231314745L,
    2623071828615234808L, -4066058308780939700L, -5484966924888173764L, -6683604512778046238L,
    -6756087640505506466L, 5256026990536851868L, 7841086888628396109L, 6640857538655893162L,
    -8021284697816458310L, -7109857044414059830L, -1689021141511844405L, -4298087301956291063L,
    -4077748265377282003L, -998231156719803476L, 2719520354384050532L, 9132346697815513771L,
    4332154495710163773L, -2085582442760428892L, 6994721091344268833L, -2556143461985726874L,
    -8567931991128098309L, 59934747298466858L, -3098398008776739403L, -265597256199410390L,
    2332206071942466437L, -7522315324568406181L, 3154897383618636503L, -7585605855467168281L,
    -6762850759087199275L, 197309393502684135L, -8579694182469508493L, 2543179307861934850L,
    4350769010207485119L, -4468719947444108136L, -7207776534213261296L, -1224312577878317200L,
    4287946071480840813L, 8362686366770308971L, 6486469209321732151L, -5605644191012979782L,
    -1669018511020473564L, 4450022655153542367L, -7618176296641240059L, -3896357471549267421L,
    -4596796223304447488L, -6531150016257070659L, -8982326463137525940L, -4125325062227681798L,
    -1306489741394045544L, -8338554946557245229L, 5329160409530630596L, 7790979528857726136L,
    4955070238059373407L, -4304834761432101506L, -6215295852904371179L, 3007769226071157901L,
    -6753025801236972788L, 8928702772696731736L, 7856187920214445904L, -4748497451462800923L,
    7900176660600710914L, -7082800908938549136L, -6797926979589575837L, -6737316883512927978L,
    4186670094382025798L, 1883939007446035042L, -414705992779907823L, 3734134241178479257L,
    4065968871360089196L, 6953124200385847784L, -7917685222115876751L, -7585632937840318161L,
    -5567246375906782599L, -5256612402221608788L, 3106378204088556331L, -2894472214076325998L,
    4565385105440252958L, 1979884289539493806L, -6891578849933910383L, 3783206694208922581L,
    8464961209802336085L, 2843963751609577687L, 3030678195484896323L, -4429654462759003204L,
    4459239494808162889L, 402587895800087237L, 8057891408711167515L, 4541888170938985079L,
    1042662272908816815L, -3666068979732206850L, 2647678726283249984L, 2144477441549833761L,
    -3417019821499388721L, -2105601033380872185L, 5916597177708541638L, -8760774321402454447L,
    8833658097025758785L, 5970273481425315300L, 563813119381731307L, -6455022486202078793L,
    1598828206250873866L, -4016978389451217698L, -2988328551145513985L, -6071154634840136312L,
    8469693267274066490L, 125672920241807416L, -3912292412830714870L, -2559617104544284221L,
    -486523741806024092L, -4735332261862713930L, 5923302823487327109L, -9082480245771672572L,
    -1808429243461201518L, 7990420780896957397L, 4317817392807076702L, 3625184369705367340L,
    -6482649271566653105L, -3480272027152017464L, -3225473396345736649L, -368878695502291645L,
    -3981164001421868007L, -8522033136963788610L, 7609280429197514109L, 3020985755112334161L,
    -2572049329799262942L, 2635195723621160615L, 5144520864246028816L, -8188285521126945980L,
    1567242097116389047L, 8172389260191636581L, -2885551685425483535L, -7060359469858316883L,
    -6480181133964513127L, -7317004403633452381L, 6011544915663598137L, 5932255307352610768L,
    2241128460406315459L, -8327867140638080220L, 3094483003111372717L, 4583857460292963101L,
    9079887171656594975L, -384082854924064405L, -3460631649611717935L, 4225072055348026230L,
    -7385151438465742745L, 3801620336801580414L, -399845416774701952L, -7446754431269675473L,
    7899055018877642622L, 5421679761463003041L, 5521102963086275121L, -4975092593295409910L,
    8735487530905098534L, -7462844945281082830L, -2080886987197029914L, -1000715163927557685L,
    -4253840471931071485L, -5828896094657903328L, 6424174453260338141L, 359248545074932887L,
    -5949720754023045210L, -2426265837057637212L, 3030918217665093212L, -9077771202237461772L,
    -3186796180789149575L, 740416251634527158L, -2142944401404840226L, 6951781370868335478L,
    399922722363687927L, -8928469722407522623L, -1378421100515597285L, -8343051178220066766L,
    -3030716356046100229L, -8811767350470065420L, 9026808440365124461L, 6440783557497587732L,
    4615674634722404292L, 539897290441580544L, 2096238225866883852L, 8751955639408182687L,
    -7316147128802486205L, 7381039757301768559L, 6157238513393239656L, -1473377804940618233L,
    8629571604380892756L, 5280433031239081479L, 7101611890139813254L, 2479018537985767835L,
    7169176924412769570L, -1281305539061572506L, -7865612307799218120L, 2278447439451174845L,
    3625338785743880657L, 6477479539006708521L, 8976185375579272206L, -3712000482142939688L,
    1326024180520890843L, 7537449876596048829L, 5464680203499696154L, 3189671183162196045L,
    6346751753565857109L, -8982212049534145501L, -6127578587196093755L, -245039190118465649L,
    -6320577374581628592L, 7208698530190629697L, 7276901792339343736L, -7490986807540332668L,
    4133292154170828382L, 2918308698224194548L, -7703910638917631350L, -3929437324238184044L,
    -4300543082831323144L, -6344160503358350167L, 5896236396443472108L, -758328221503023383L,
    -1894351639983151068L, -307900319840287220L, -6278469401177312761L, -2171292963361310674L,
    8382142935188824023L, 9103922860780351547L, 4152330101494654406L
)
