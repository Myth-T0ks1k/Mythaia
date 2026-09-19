package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.tls.TlsCipherSuite
import com.mythaia.vpn.util.PacketUtil
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * One TLS 1.3 record, sealed or opened (RFC 8446 §5.2).
 *
 * The handshake flight — EncryptedExtensions through Finished — travels under
 * the handshake keys before any record-layer object exists, so it needs a
 * record codec of its own. This is that codec, and nothing more: no sequence
 * state, no stream. The caller owns the sequence number, because on the server
 * the same number space is shared between the flight sent here and the
 * application records that follow on the connection.
 *
 * The layout is the one `TlsClient` reads, so a server built on this and a
 * client built on that agree by construction: the nonce is the IV xor the
 * sequence number, the associated data is the five-byte record header, and the
 * plaintext is the content followed by its inner type and any zero padding.
 */
object TlsHandshakeAead {

    /** Inner content type for a handshake message. */
    const val CONTENT_HANDSHAKE: Byte = 0x16

    /** Inner content type for application data. */
    const val CONTENT_APPLICATION: Byte = 0x17

    /** What a TLS 1.3 record claims to be on the outside, whatever it holds. */
    private const val OUTER_TYPE_APPLICATION: Byte = 0x17

    private const val TAG_LENGTH_BITS = 128

    /**
     * Seals [plaintext] into a complete record, header included.
     *
     * The record header is built first because it is the associated data: it
     * commits to the ciphertext length, which is plaintext + type byte + tag.
     */
    fun seal(
        cipherSuite: Int,
        key: ByteArray,
        iv: ByteArray,
        sequence: Long,
        plaintext: ByteArray,
        innerType: Byte = CONTENT_HANDSHAKE
    ): ByteArray {
        val inner = plaintext + byteArrayOf(innerType)
        val ciphertextLength = inner.size + TAG_LENGTH_BITS / 8
        val header = byteArrayOf(
            OUTER_TYPE_APPLICATION, 0x03, 0x03,
            (ciphertextLength ushr 8).toByte(), ciphertextLength.toByte()
        )

        val cipher = cipherFor(cipherSuite, key, iv, sequence, Cipher.ENCRYPT_MODE)
        cipher.updateAAD(header)
        return header + cipher.doFinal(inner)
    }

    /**
     * Opens one record given its header and body, returning the content with
     * its inner type stripped, or null when the tag does not verify.
     *
     * Null rather than an exception: a record that fails to authenticate is
     * something the peer sent, and on a server that is a client to be dropped,
     * not a fault to propagate.
     */
    fun open(
        cipherSuite: Int,
        key: ByteArray,
        iv: ByteArray,
        sequence: Long,
        header: ByteArray,
        body: ByteArray
    ): Opened? {
        if (body.size < TAG_LENGTH_BITS / 8 + 1) return null
        val decrypted = try {
            val cipher = cipherFor(cipherSuite, key, iv, sequence, Cipher.DECRYPT_MODE)
            cipher.updateAAD(header)
            cipher.doFinal(body)
        } catch (_: Exception) {
            return null
        }

        // Zero padding is trimmed from the end; the first non-zero byte from the
        // right is the inner content type, and everything before it is content.
        var end = decrypted.size - 1
        while (end >= 0 && decrypted[end] == 0.toByte()) end--
        if (end < 0) return null

        return Opened(decrypted[end], decrypted.copyOfRange(0, end))
    }

    /** The inner content type a record carried, and its content. */
    class Opened(val innerType: Byte, val content: ByteArray)

    private fun cipherFor(cipherSuite: Int, key: ByteArray, iv: ByteArray, sequence: Long, mode: Int): Cipher {
        val nonce = PacketUtil.xorNonce(iv, sequence)
        val chacha = cipherSuite == TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256
        val cipher = Cipher.getInstance(if (chacha) "ChaCha20-Poly1305" else "AES/GCM/NoPadding")
        val spec = SecretKeySpec(key, if (chacha) "ChaCha20" else "AES")
        val params = if (chacha) IvParameterSpec(nonce) else GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        cipher.init(mode, spec, params)
        return cipher
    }
}
