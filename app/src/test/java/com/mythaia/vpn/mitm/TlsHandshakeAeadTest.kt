package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.tls.TlsCipherSuite
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The TLS 1.3 record codec that carries the server's handshake flight
 * (RFC 8446 §5.2). The tests build a record the way the RFC says — nonce is the
 * IV xor the sequence number, associated data is the five-byte header, plaintext
 * is content then inner type then zero padding — with a second, independent JCA
 * path, so a bug in the codec cannot hide behind a test that reuses it.
 *
 * A record layer that accepted a tampered record, or that lost the last bytes
 * of a plaintext to padding-trimming, would be a hole in an interception path
 * that is supposed to be transparent, which is why open() is pinned as hard as
 * seal().
 */
class TlsHandshakeAeadTest {

    private val key128 = ByteArray(16) { (it + 1).toByte() }
    private val key256 = ByteArray(32) { (it + 3).toByte() }
    private val iv = ByteArray(12) { (0x40 + it).toByte() }

    /**
     * The RFC 8446 §5.3 nonce, derived here without touching the production
     * helper: the per-record sequence number, left-padded to the IV length and
     * XOR'd into it. Computing it a second way is what makes the round-trip a
     * check rather than a mirror.
     */
    private fun rfcNonce(iv: ByteArray, sequence: Long): ByteArray {
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            nonce[nonce.size - 1 - i] =
                (nonce[nonce.size - 1 - i].toInt() xor ((sequence ushr (8 * i)).toInt() and 0xFF)).toByte()
        }
        return nonce
    }

    private fun aesGcm(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(data)
    }

    private fun recordHeader(ciphertextLength: Int): ByteArray = byteArrayOf(
        0x17, 0x03, 0x03,
        ((ciphertextLength ushr 8) and 0xFF).toByte(), (ciphertextLength and 0xFF).toByte()
    )

    @Test
    fun `seal then open round-trips content and inner type for AES-128 and AES-256`() {
        for ((suite, key) in listOf(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256 to key128,
            TlsCipherSuite.TLS_AES_256_GCM_SHA384 to key256
        )) {
            for (type in listOf(TlsHandshakeAead.CONTENT_HANDSHAKE, TlsHandshakeAead.CONTENT_APPLICATION)) {
                val plaintext = "EncryptedExtensions..Finished".toByteArray()
                val record = TlsHandshakeAead.seal(suite, key, iv, 3L, plaintext, type)
                val header = record.copyOfRange(0, 5)
                val body = record.copyOfRange(5, record.size)
                val opened = TlsHandshakeAead.open(suite, key, iv, 3L, header, body)
                assertNotNull(opened)
                assertEquals(type, opened!!.innerType)
                assertArrayEquals(plaintext, opened.content)
            }
        }
    }

    @Test
    fun `open accepts a record sealed by an independent JCA path`() {
        // Build an AES-128-GCM record entirely by hand from the RFC and confirm
        // the codec opens it: the header is the associated data and commits to
        // the ciphertext length, the nonce is the IV xor the sequence, and the
        // last plaintext byte is the inner content type.
        val sequence = 7L
        val plaintext = "handshake".toByteArray()
        val inner = plaintext + TlsHandshakeAead.CONTENT_HANDSHAKE
        val ciphertextLength = inner.size + 16
        val header = recordHeader(ciphertextLength)
        val nonce = rfcNonce(iv, sequence)
        val body = aesGcm(Cipher.ENCRYPT_MODE, key128, nonce, header, inner)

        val opened = TlsHandshakeAead.open(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence, header, body
        )
        assertNotNull(opened)
        assertEquals(TlsHandshakeAead.CONTENT_HANDSHAKE, opened!!.innerType)
        assertArrayEquals(plaintext, opened.content)
    }

    @Test
    fun `a record sealed by the codec decrypts by hand to content plus inner type`() {
        // The reverse independence check: seal with the codec, then verify its
        // header structure and decrypt its body with a bare JCA cipher. The
        // header must claim exactly plaintext + type + tag bytes.
        val sequence = 2L
        val plaintext = "server-flight".toByteArray()
        val record = TlsHandshakeAead.seal(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence, plaintext, TlsHandshakeAead.CONTENT_HANDSHAKE
        )
        val header = record.copyOfRange(0, 5)
        val body = record.copyOfRange(5, record.size)

        assertEquals(0x17.toByte(), header[0])
        assertEquals(0x03.toByte(), header[1])
        assertEquals(0x03.toByte(), header[2])
        val declared = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        assertEquals(body.size, declared)
        assertEquals(plaintext.size + 1 + 16, declared)

        val decrypted = aesGcm(Cipher.DECRYPT_MODE, key128, rfcNonce(iv, sequence), header, body)
        assertEquals(plaintext.size + 1, decrypted.size)
        assertArrayEquals(plaintext, decrypted.copyOfRange(0, plaintext.size))
        assertEquals(TlsHandshakeAead.CONTENT_HANDSHAKE, decrypted[decrypted.size - 1])
    }

    @Test
    fun `open trims trailing zero padding to find the inner type`() {
        // A TLS 1.3 record may carry zero padding after the content type
        // (§5.4). The opener scans from the end for the first non-zero byte;
        // that byte is the type and the padding is discarded, leaving the
        // content exactly as sealed.
        val sequence = 1L
        val plaintext = "padded".toByteArray()
        val inner = plaintext + TlsHandshakeAead.CONTENT_HANDSHAKE + byteArrayOf(0, 0, 0, 0)
        val header = recordHeader(inner.size + 16)
        val body = aesGcm(Cipher.ENCRYPT_MODE, key128, rfcNonce(iv, sequence), header, inner)

        val opened = TlsHandshakeAead.open(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence, header, body
        )
        assertNotNull(opened)
        assertEquals(TlsHandshakeAead.CONTENT_HANDSHAKE, opened!!.innerType)
        assertArrayEquals(plaintext, opened.content)
    }

    @Test
    fun `a plaintext that ends in a zero byte keeps that byte, since the type follows it`() {
        // Zero-trimming must not eat real content: the inner type sits after
        // the content, so a content that itself ends in 0x00 is preserved.
        val sequence = 4L
        val plaintext = byteArrayOf(1, 2, 0, 0)
        val record = TlsHandshakeAead.seal(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence, plaintext, TlsHandshakeAead.CONTENT_APPLICATION
        )
        val opened = TlsHandshakeAead.open(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence,
            record.copyOfRange(0, 5), record.copyOfRange(5, record.size)
        )
        assertNotNull(opened)
        assertEquals(TlsHandshakeAead.CONTENT_APPLICATION, opened!!.innerType)
        assertArrayEquals(plaintext, opened.content)
    }

    @Test
    fun `a flipped ciphertext byte fails the tag and opens to null`() {
        val record = TlsHandshakeAead.seal(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 0L, "tamper me".toByteArray()
        )
        val header = record.copyOfRange(0, 5)
        val body = record.copyOfRange(5, record.size)
        body[0] = (body[0].toInt() xor 0x01).toByte()
        assertNull(TlsHandshakeAead.open(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 0L, header, body))
    }

    @Test
    fun `opening with the wrong sequence number derives the wrong nonce and fails`() {
        val record = TlsHandshakeAead.seal(
            TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 5L, "seq matters".toByteArray()
        )
        val header = record.copyOfRange(0, 5)
        val body = record.copyOfRange(5, record.size)
        assertNull(TlsHandshakeAead.open(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 6L, header, body))
        // The right sequence still opens it.
        assertNotNull(TlsHandshakeAead.open(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 5L, header, body))
    }

    @Test
    fun `a body too short to hold a tag and a type opens to null`() {
        // Below tag + one type byte there is nothing to authenticate; the
        // opener must reject rather than index off the end.
        assertNull(
            TlsHandshakeAead.open(
                TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 0L, recordHeader(16), ByteArray(16)
            )
        )
    }

    @Test
    fun `a record whose plaintext is all zeros has no type byte and opens to null`() {
        // No non-zero byte means no content type was ever there; the opener
        // returns null rather than inventing one.
        val sequence = 0L
        val inner = byteArrayOf(0, 0, 0)
        val header = recordHeader(inner.size + 16)
        val body = aesGcm(Cipher.ENCRYPT_MODE, key128, rfcNonce(iv, sequence), header, inner)
        assertNull(TlsHandshakeAead.open(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, sequence, header, body))
    }

    @Test
    fun `seal then open round-trips under ChaCha20-Poly1305 where the platform offers it`() {
        val available = try {
            Cipher.getInstance("ChaCha20-Poly1305"); true
        } catch (_: Exception) {
            false
        }
        assumeTrue("ChaCha20-Poly1305 not offered by this JVM", available)

        val plaintext = "chacha flight".toByteArray()
        val record = TlsHandshakeAead.seal(
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, key256, iv, 9L, plaintext
        )
        val opened = TlsHandshakeAead.open(
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256, key256, iv, 9L,
            record.copyOfRange(0, 5), record.copyOfRange(5, record.size)
        )
        assertNotNull(opened)
        assertEquals(TlsHandshakeAead.CONTENT_HANDSHAKE, opened!!.innerType)
        assertArrayEquals(plaintext, opened.content)
    }

    @Test
    fun `the sequence number changes the ciphertext even for identical plaintext`() {
        // If the nonce did not fold in the sequence, two records with the same
        // plaintext would be byte-identical, which is the keystream-reuse bug
        // the xor is there to prevent.
        val plaintext = "same bytes".toByteArray()
        val a = TlsHandshakeAead.seal(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 0L, plaintext)
        val b = TlsHandshakeAead.seal(TlsCipherSuite.TLS_AES_128_GCM_SHA256, key128, iv, 1L, plaintext)
        assertEquals(a.size, b.size)
        assertTrue("records at different sequences must differ", !a.contentEquals(b))
    }
}
