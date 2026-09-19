package com.mythaia.vpn.protocol.quic

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * QUIC packet protection: the three AEADs RFC 9001 allows, and the nonce each
 * packet is sealed under.
 *
 * A QUIC packet is not protected the way a TLS record is. There is no explicit
 * nonce on the wire — the packet number is the nonce, exclusive-ORed into a
 * per-direction IV — and the associated data is the packet header itself, so
 * anything a middlebox rewrites in the header breaks authentication rather than
 * being silently accepted. Both of those are in [nonce] and in what callers
 * pass as `aad`.
 *
 * On this platform the live tunnel does not go through here: ngtcp2 is built
 * against mbedTLS and seals and opens packets in native code, which is what
 * `NativeBridge.nativeQuicInstallKeys` hands the traffic secrets to. This is
 * the same computation written independently, so that packet protection can be
 * checked against published test vectors on a desktop JVM — where the arm64
 * library cannot be loaded, and where the alternative is to say only that the
 * native code compiles.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object QuicCrypto {

    /**
     * Every AEAD QUIC may use has a 16-byte tag (RFC 9001 §5.3), so a sealed
     * payload is always sixteen bytes longer than what went in and a shorter
     * one cannot be authentic.
     */
    const val TAG_LENGTH = 16

    /**
     * The nonce length, which RFC 9001 §5.1 fixes at the larger of 8 and the
     * AEAD's minimum. That is 12 for all three suites, so there is one length
     * rather than one per algorithm.
     */
    const val NONCE_LENGTH = 12

    /**
     * The AEADs a QUIC connection can end up using, one per TLS 1.3 cipher
     * suite that RFC 9001 §5.3 permits.
     *
     * AES-128-CCM is deliberately absent: TLS_AES_128_CCM_SHA256 is optional
     * for TLS 1.3, no server this client talks to offers it, and an
     * implementation nothing exercises is worse than none.
     */
    enum class Aead(val keyLength: Int) {
        AES_128_GCM(16),
        AES_256_GCM(32),
        CHACHA20_POLY1305(32)
    }

    /**
     * The nonce for one packet, per RFC 9001 §5.3.
     *
     * The packet number is written big-endian, left-padded with zeroes to the
     * width of [iv], and exclusive-ORed with it. Because the padding is on the
     * left and a packet number is at most 62 bits, only the trailing eight
     * bytes of the IV can ever change — which is what makes an eight-byte IV
     * the shortest QUIC allows.
     *
     * [packetNumber] is the full reconstructed number, not the truncated form
     * that appeared in the header; using the truncated one would produce a
     * nonce that only agrees with the peer until the first wrap.
     */
    fun nonce(iv: ByteArray, packetNumber: Long): ByteArray {
        require(iv.size >= 8) { "a QUIC IV is at least 8 bytes, got ${iv.size}" }
        require(packetNumber >= 0) { "packet numbers are 62-bit and non-negative: $packetNumber" }

        val out = iv.copyOf()
        for (i in 0 until 8) {
            val index = out.size - 1 - i
            val byte = ((packetNumber ushr (i * 8)) and 0xFF).toInt()
            out[index] = (out[index].toInt() xor byte).toByte()
        }
        return out
    }

    /**
     * Seals [plaintext], returning ciphertext followed by the 16-byte tag.
     *
     * The tag trails the ciphertext in one array because that is the layout
     * QUIC puts on the wire and the layout ngtcp2 expects back; splitting them
     * would only mean rejoining them at the boundary.
     */
    fun seal(
        aead: Aead,
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray
    ): ByteArray {
        checkKeyAndNonce(aead, key, nonce)
        return when (aead) {
            Aead.CHACHA20_POLY1305 -> chaCha(encrypt = true, key, nonce, plaintext, aad)
            else -> gcm(Cipher.ENCRYPT_MODE, key, nonce, plaintext, aad)
        }
    }

    /**
     * Opens what [seal] produced, or null when it does not authenticate.
     *
     * Null rather than an exception because a packet that fails to open is
     * ordinary: QUIC endpoints receive stray, replayed and injected datagrams,
     * and RFC 9001 §5.2 says an unprotectable packet is discarded rather than
     * treated as an error. A wrong key or nonce length, by contrast, is this
     * side's bug and is refused loudly.
     */
    fun open(
        aead: Aead,
        key: ByteArray,
        nonce: ByteArray,
        sealed: ByteArray,
        aad: ByteArray
    ): ByteArray? {
        checkKeyAndNonce(aead, key, nonce)
        if (sealed.size < TAG_LENGTH) return null
        return try {
            when (aead) {
                Aead.CHACHA20_POLY1305 -> chaCha(encrypt = false, key, nonce, sealed, aad)
                else -> gcm(Cipher.DECRYPT_MODE, key, nonce, sealed, aad)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun checkKeyAndNonce(aead: Aead, key: ByteArray, nonce: ByteArray) {
        require(key.size == aead.keyLength) {
            "$aead takes a ${aead.keyLength}-byte key, got ${key.size}"
        }
        require(nonce.size == NONCE_LENGTH) {
            "a QUIC nonce is $NONCE_LENGTH bytes, got ${nonce.size}"
        }
    }

    /**
     * AES-GCM through the JCA, which appends and verifies the tag itself once
     * the tag length is given in bits.
     */
    private fun gcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LENGTH * 8, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(input)
    }

    /**
     * ChaCha20-Poly1305 through BouncyCastle rather than the JCA.
     *
     * `javax.crypto` only gained the algorithm at API 28, and this module has
     * to work at the project's minimum of 26 — the same reason
     * `WireGuardCrypto` reaches for BouncyCastle.
     */
    private fun chaCha(
        encrypt: Boolean,
        key: ByteArray,
        nonce: ByteArray,
        input: ByteArray,
        aad: ByteArray
    ): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(encrypt, AEADParameters(KeyParameter(key), TAG_LENGTH * 8, nonce, aad))
        val out = ByteArray(cipher.getOutputSize(input.size))
        var written = cipher.processBytes(input, 0, input.size, out, 0)
        written += cipher.doFinal(out, written)
        return if (written == out.size) out else out.copyOf(written)
    }
}
