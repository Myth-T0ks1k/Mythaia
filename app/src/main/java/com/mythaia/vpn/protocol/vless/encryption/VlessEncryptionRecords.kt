package com.mythaia.vpn.protocol.vless.encryption

import org.bouncycastle.crypto.digests.Blake3Digest
import org.bouncycastle.crypto.params.Blake3Parameters
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The fixed wire numbers of the post-quantum VLESS record layer.
 *
 * Records are dressed as TLS 1.3 `application_data`: a five-byte header
 * (`0x17 0x0303 length`) then a sealed body. Nothing here is TLS — the disguise
 * is only so the framing looks ordinary to a middlebox — but the lengths are
 * pinned to TLS's so a record never stands out by size.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object VlessWire {
    /** TLS 1.3 record header byte 0 (`application_data`). */
    const val RECORD_TYPE: Byte = 23

    /** TLS 1.3 legacy record version `0x0303`. */
    const val VERSION_MAJOR: Byte = 3
    const val VERSION_MINOR: Byte = 3

    /** 1 type + 2 version + 2 length. */
    const val HEADER_LENGTH = 5

    /** Largest plaintext sealed into one record before it is split. */
    const val MAX_CHUNK_PLAINTEXT = 8192

    /** AES-GCM tag length. */
    const val AEAD_TAG_LENGTH = 16

    /** Largest valid TLS 1.3 record payload (16384 + 256, RFC 8446 §5.2). */
    const val MAX_RECORD_PAYLOAD = 16640

    /** A record payload must hold at least the AEAD tag plus a byte. */
    const val MIN_RECORD_PAYLOAD = 17

    /** A sealed 2-byte length frame: 2 plaintext + 16 tag. */
    const val SEALED_LENGTH_FRAME = 18

    /** ML-KEM ciphertext + X25519 public key + AEAD tag. */
    const val PFS_SERVER_HELLO_LENGTH = 1088 + 32 + 16

    /** Encrypted resumption ticket reply: 16 plaintext + 16 tag. */
    const val ENCRYPTED_TICKET_LENGTH = 32

    /** ML-KEM encapsulation key + X25519 public key, unsealed. */
    const val PFS_CLIENT_HELLO_PAYLOAD_LENGTH = 1184 + 32

    /** The 12-byte AEAD nonce. */
    const val NONCE_LENGTH = 12

    /** The 16-byte CTR IV / handshake IV / server random. */
    const val IV_LENGTH = 16

    /** ML-KEM-768 and X25519 shared secrets are both 32 bytes. */
    const val SHARED_SECRET_LENGTH = 32

    /** ML-KEM-768 ciphertext. */
    const val MLKEM_CIPHERTEXT_LENGTH = 1088
}

/**
 * BLAKE3 in the two shapes this protocol needs: a plain 256-bit hash of a relay
 * public key, and the keyed-derivation that turns a shared secret plus a context
 * into a record or CTR key.
 *
 * The derivation is BLAKE3's `derive_key` with the context supplied as raw bytes
 * rather than a string — the handshake IV, the server random, or a sealed record
 * all serve as context, and none of them is text. That is exactly what
 * [Blake3Parameters.context] takes, so no re-encoding is invented on the way in.
 * BouncyCastle is used rather than the app's native BLAKE3 so this stays a pure
 * JVM path that a unit test can pin against the published BLAKE3 vectors.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object Blake3Kdf {

    private const val KEY_LENGTH = 32

    /** Plain BLAKE3-256 of [input]. */
    fun hash(input: ByteArray): ByteArray {
        val digest = Blake3Digest(KEY_LENGTH)
        digest.update(input, 0, input.size)
        val out = ByteArray(KEY_LENGTH)
        digest.doFinal(out, 0)
        return out
    }

    /**
     * BLAKE3 `derive_key`: [context] is hashed to a context key, which then keys
     * a hash of [keyMaterial]. Returns 32 bytes.
     */
    fun deriveKey(context: ByteArray, keyMaterial: ByteArray): ByteArray {
        val digest = Blake3Digest(KEY_LENGTH)
        digest.init(Blake3Parameters.context(context))
        digest.update(keyMaterial, 0, keyMaterial.size)
        val out = ByteArray(KEY_LENGTH)
        digest.doFinal(out, 0)
        return out
    }
}

/**
 * The raw AES-256-GCM seal and open, with the key and nonce handed in.
 *
 * Split out from [VlessRecordAead] so the AEAD can be pinned against a published
 * GCM known-answer vector on its own, before the BLAKE3 key schedule and the
 * counting nonce are layered on top of it.
 *
 * Only AES-256-GCM is implemented: the reference's ChaCha20-Poly1305 branch is
 * gated on a `useAES` flag it always leaves true, every device this ships to
 * (arm64-v8a) has hardware AES, and the JVM/Android ChaCha20-Poly1305 cipher
 * would not be available below API 28.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object VlessAeadCipher {

    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128

    /** Returns `ciphertext || tag`. [aad] may be null. */
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray?, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    /**
     * Opens `ciphertext || tag`, returning the plaintext or throwing on a failed
     * tag (a [javax.crypto.AEADBadTagException]).
     */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray?, sealed: ByteArray): ByteArray {
        if (sealed.size < VlessWire.AEAD_TAG_LENGTH) {
            throw VlessEncryptionError.ProtocolViolation("framing: sealed buffer shorter than tag")
        }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(sealed)
    }
}

/**
 * One direction's AES-256-GCM stream, keyed by BLAKE3 from a context and secret,
 * with a 12-byte big-endian counter for a nonce.
 *
 * The counter is advanced *before* each use, so nonce zero is never spent — it
 * is reserved as the "no record yet" state, and the all-ones value is reserved
 * for the server's PFS hello, which is opened with an explicit max nonce so it
 * can never collide with the client's forward-counting records on the same key.
 * Advancing and snapshotting the counter is one locked step, so even a stray
 * concurrent call cannot hand the same nonce to two seals.
 *
 * When the counter would wrap past all-ones the key is rolled with a fresh
 * BLAKE3 derivation over the last record; in practice a 96-bit counter never
 * reaches that, but both ends implement it, so it is carried for parity.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class VlessRecordAead(context: ByteArray, key: ByteArray) {

    private val derivedKey: ByteArray = Blake3Kdf.deriveKey(context, key)
    private val nonce = ByteArray(VlessWire.NONCE_LENGTH)
    private val lock = Any()

    /** True when the *last-used* nonce is all-ones, so the next seal/open must rekey. */
    val nonceIsAtMax: Boolean
        get() = synchronized(lock) { nonce.all { it == 0xFF.toByte() } }

    fun seal(plaintext: ByteArray, aad: ByteArray?): ByteArray {
        val n = advanceAndSnapshot()
        return VlessAeadCipher.seal(derivedKey, n, aad, plaintext)
    }

    /** Opens with the next counting nonce (mirrors [seal]'s advance-before-use). */
    fun open(sealed: ByteArray, aad: ByteArray?): ByteArray {
        val n = advanceAndSnapshot()
        return VlessAeadCipher.open(derivedKey, n, aad, sealed)
    }

    /** Opens with an explicit nonce; used for the all-ones server PFS hello. */
    fun open(sealed: ByteArray, nonce: ByteArray, aad: ByteArray?): ByteArray {
        return VlessAeadCipher.open(derivedKey, nonce, aad, sealed)
    }

    private fun advanceAndSnapshot(): ByteArray = synchronized(lock) {
        for (i in nonce.indices.reversed()) {
            nonce[i]++
            if (nonce[i].toInt() != 0) break
        }
        nonce.copyOf()
    }
}

/** The five-byte record header codec. */
internal object VlessRecordHeader {

    fun encode(payloadLength: Int): ByteArray = byteArrayOf(
        VlessWire.RECORD_TYPE,
        VlessWire.VERSION_MAJOR,
        VlessWire.VERSION_MINOR,
        ((payloadLength ushr 8) and 0xFF).toByte(),
        (payloadLength and 0xFF).toByte()
    )

    /**
     * Returns the payload length, or throws [VlessEncryptionError.ProtocolViolation]
     * on a header that is the wrong length, has the wrong prefix, or claims a
     * payload out of the TLS bounds. A 0-RTT rejection surfaces here: the server
     * replaces the record with noise, and noise fails one of these checks.
     */
    fun decode(header: ByteArray): Int {
        if (header.size != VlessWire.HEADER_LENGTH) {
            throw VlessEncryptionError.ProtocolViolation("framing: header is not 5 bytes")
        }
        val length = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        if (header[0] != VlessWire.RECORD_TYPE ||
            header[1] != VlessWire.VERSION_MAJOR ||
            header[2] != VlessWire.VERSION_MINOR
        ) {
            throw VlessEncryptionError.ProtocolViolation("framing: unexpected record prefix")
        }
        if (length < VlessWire.MIN_RECORD_PAYLOAD || length > VlessWire.MAX_RECORD_PAYLOAD) {
            throw VlessEncryptionError.ProtocolViolation("framing: record length $length out of range")
        }
        return length
    }
}

/** Two-byte big-endian length helpers, used for the sealed length frames. */
internal object VlessLengthPrefix {

    fun encode(value: Int): ByteArray = byteArrayOf(
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte()
    )

    fun decode(bytes: ByteArray): Int =
        ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
}

/**
 * AES-256-CTR keystream keyed by BLAKE3 from a public key or shared secret, used
 * to mask the relay block and (in random mode) the record headers.
 *
 * The counter is stateful across calls, exactly as the reference's is: each
 * [process] continues the keystream where the last left off, so masking the
 * pieces of a relay block in sequence produces the same bytes the server
 * reproduces in one pass. The instance therefore belongs to a single direction
 * of a single connection; its calls are serialised.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class VlessEncryptionCtr(key: ByteArray, iv: ByteArray) {

    private val cipher: Cipher

    init {
        if (iv.size != VlessWire.IV_LENGTH) {
            throw VlessEncryptionError.ProtocolViolation(
                "framing: VLESS CTR IV must be ${VlessWire.IV_LENGTH} bytes, got ${iv.size}"
            )
        }
        val derivedKey = Blake3Kdf.deriveKey(CTR_CONTEXT, key)
        cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(derivedKey, "AES"), IvParameterSpec(iv))
    }

    /** Transforms [data] and advances the keystream; returns a new array. */
    @Synchronized
    fun process(data: ByteArray): ByteArray {
        if (data.isEmpty()) return data
        return cipher.update(data)
    }

    /** Transforms `bytes[range]` in place, advancing the keystream. */
    @Synchronized
    fun processInPlace(bytes: ByteArray, fromInclusive: Int, toExclusive: Int) {
        val length = toExclusive - fromInclusive
        if (length <= 0) return
        val out = cipher.update(bytes, fromInclusive, length)
        System.arraycopy(out, 0, bytes, fromInclusive, length)
    }

    companion object {
        /** The domain-separation context that keys every VLESS CTR stream. */
        private val CTR_CONTEXT = "VLESS".toByteArray(Charsets.US_ASCII)
    }
}
