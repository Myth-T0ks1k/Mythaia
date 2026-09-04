package com.mythaia.vpn.protocol.wireguard

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.io.IOException
import java.security.SecureRandom

/** How a WireGuard operation failed. */
class WireGuardError(message: String) : IOException(message)

/**
 * The primitives WireGuard's Noise_IKpsk2 handshake is built from.
 *
 * BLAKE2s rather than SHA-256, ChaCha20-Poly1305 rather than AES-GCM, and
 * X25519 — the protocol fixes all three, so none of this is negotiable and
 * there is nothing to choose at runtime.
 *
 * BouncyCastle throughout: `javax.crypto` has no BLAKE2s at any API level, and
 * ChaCha20-Poly1305 only from API 28 with a different parameter shape.
 */
object WireGuardCrypto {

    const val KEY_SIZE = 32
    const val HASH_SIZE = 32
    const val MAC_SIZE = 16
    const val TAG_SIZE = 16

    private val random = SecureRandom()

    // MARK: - BLAKE2s

    /** BLAKE2s-256 of the concatenation of [parts]. */
    fun hash(vararg parts: ByteArray): ByteArray {
        val digest = Blake2sDigest(null, HASH_SIZE, null, null)
        for (part in parts) digest.update(part, 0, part.size)
        val out = ByteArray(HASH_SIZE)
        digest.doFinal(out, 0)
        return out
    }

    /** BLAKE2s keyed to [key], truncated to [length] — WireGuard's MAC. */
    fun mac(key: ByteArray, data: ByteArray, length: Int = MAC_SIZE): ByteArray {
        val digest = Blake2sDigest(key, length, null, null)
        digest.update(data, 0, data.size)
        val out = ByteArray(length)
        digest.doFinal(out, 0)
        return out
    }

    /** HMAC-BLAKE2s, which is what the HKDF below is built on. */
    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val hmac = HMac(Blake2sDigest(null, HASH_SIZE, null, null))
        hmac.init(KeyParameter(key))
        hmac.update(data, 0, data.size)
        val out = ByteArray(hmac.macSize)
        hmac.doFinal(out, 0)
        return out
    }

    /**
     * HKDF over HMAC-BLAKE2s, returning [count] keys of 32 bytes.
     *
     * Written out rather than taken from a library because the protocol needs
     * the intermediate outputs one at a time (τ₁, τ₂, τ₃), and because the
     * chaining key it produces is fed straight back in as the next salt.
     */
    fun kdf(chainingKey: ByteArray, input: ByteArray, count: Int): List<ByteArray> {
        require(count in 1..3) { "WireGuard KDF is only ever asked for 1..3 keys" }

        val prk = hmac(chainingKey, input)
        val out = ArrayList<ByteArray>(count)

        var previous = hmac(prk, byteArrayOf(0x01))
        out.add(previous)
        for (i in 2..count) {
            previous = hmac(prk, previous + byteArrayOf(i.toByte()))
            out.add(previous)
        }
        return out
    }

    // MARK: - X25519

    /** A private key with the clamping RFC 7748 requires, and its public key. */
    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val privateKey = X25519PrivateKeyParameters(random)
        return privateKey.encoded to privateKey.generatePublicKey().encoded
    }

    fun publicKey(privateKey: ByteArray): ByteArray =
        X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().encoded

    /**
     * The X25519 shared secret.
     *
     * An all-zero result means a low-order public key, which the peer must not
     * be able to force: accepting it would fix the secret to a value it also
     * knows.
     */
    fun sharedSecret(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        if (privateKey.size != KEY_SIZE || peerPublicKey.size != KEY_SIZE) {
            throw WireGuardError("X25519 keys must be 32 bytes")
        }
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privateKey, 0))
        val out = ByteArray(agreement.agreementSize)
        try {
            agreement.calculateAgreement(X25519PublicKeyParameters(peerPublicKey, 0), out, 0)
        } catch (e: Exception) {
            throw WireGuardError("X25519 agreement failed: ${e.message ?: e}")
        }
        if (out.all { it == 0.toByte() }) {
            throw WireGuardError("X25519 produced the all-zero point")
        }
        return out
    }

    // MARK: - AEAD

    /**
     * ChaCha20-Poly1305 with WireGuard's nonce: four zero bytes then the
     * counter, little-endian.
     */
    fun nonce(counter: Long): ByteArray {
        val out = ByteArray(12)
        var value = counter
        for (i in 4 until 12) {
            out[i] = (value and 0xFF).toByte()
            value = value ushr 8
        }
        return out
    }

    fun seal(key: ByteArray, counter: Long, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), TAG_SIZE * 8, nonce(counter), aad))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var written = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        written += cipher.doFinal(out, written)
        return if (written == out.size) out else out.copyOf(written)
    }

    /** Null when the tag does not verify — a wrong key, or a tampered message. */
    fun open(key: ByteArray, counter: Long, ciphertext: ByteArray, aad: ByteArray): ByteArray? = try {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(key), TAG_SIZE * 8, nonce(counter), aad))
        val out = ByteArray(cipher.getOutputSize(ciphertext.size))
        var written = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
        written += cipher.doFinal(out, written)
        if (written == out.size) out else out.copyOf(written)
    } catch (_: Exception) {
        null
    }

    // MARK: - Timestamp

    /**
     * TAI64N, which is what WireGuard puts in the initiation message.
     *
     * The responder keeps the greatest timestamp it has seen from each peer and
     * rejects anything not greater, which is what stops an initiation being
     * replayed.
     */
    fun tai64n(millis: Long = System.currentTimeMillis()): ByteArray {
        val seconds = millis / 1000
        val nanos = (millis % 1000) * 1_000_000

        val out = ByteArray(12)
        // 2^62 plus the Unix second count, big-endian.
        var value = 0x400000000000000AL + seconds
        for (i in 7 downTo 0) {
            out[i] = (value and 0xFF).toByte()
            value = value ushr 8
        }
        var n = nanos
        for (i in 11 downTo 8) {
            out[i] = (n and 0xFF).toByte()
            n = n ushr 8
        }
        return out
    }

    /** Fills [count] bytes from a cryptographic source. */
    fun randomBytes(count: Int): ByteArray = ByteArray(count).also { random.nextBytes(it) }

    /** Base64 as WireGuard configs write keys. Null when it is not a 32-byte key. */
    fun decodeKey(text: String): ByteArray? {
        val bytes = runCatching {
            java.util.Base64.getDecoder().decode(text.trim())
        }.getOrNull() ?: return null
        return bytes.takeIf { it.size == KEY_SIZE }
    }

    fun encodeKey(key: ByteArray): String = java.util.Base64.getEncoder().encodeToString(key)
}
