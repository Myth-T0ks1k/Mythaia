package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Packet protection, checked against published numbers rather than against
 * itself.
 *
 * The split follows the specifications. RFC 9001 does not define an AEAD — it
 * borrows all three from TLS 1.3 — so the algorithms are checked against the
 * numbered test cases in McGrew and Viega's GCM specification, the ones NIST
 * adopted, and against RFC 8439 §2.8.2 for ChaCha20-Poly1305. What RFC 9001
 * does define is how QUIC uses them: a 16-byte tag and a nonce built from the
 * packet number (§5.3). Those are checked against the RFC's own text.
 *
 * Named `QuicCryptoUnitTest` rather than `QuicCryptoTest` because the
 * instrumented suite already has a `QuicCryptoTest`, which drives the native
 * ngtcp2 stack through RFC 9001 Appendix A on a device. Two classes with one
 * simple name across two source sets is a needless way to misread a report.
 */
class QuicCryptoUnitTest {

    private fun hex(text: String): ByteArray {
        val clean = text.filterNot { it.isWhitespace() }
        return ByteArray(clean.length / 2) {
            clean.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    // MARK: - RFC 9001 §5.3: what QUIC fixes

    @Test
    fun `the tag is sixteen bytes and the nonce twelve, for every suite`() {
        assertEquals(16, QuicCrypto.TAG_LENGTH)
        assertEquals(12, QuicCrypto.NONCE_LENGTH)
    }

    @Test
    fun `the key lengths are those of the TLS 1_3 suites QUIC allows`() {
        assertEquals(16, QuicCrypto.Aead.AES_128_GCM.keyLength)
        assertEquals(32, QuicCrypto.Aead.AES_256_GCM.keyLength)
        assertEquals(32, QuicCrypto.Aead.CHACHA20_POLY1305.keyLength)
    }

    @Test
    fun `sealing costs exactly the tag`() {
        val plaintext = ByteArray(37) { it.toByte() }
        for (aead in QuicCrypto.Aead.entries) {
            val key = ByteArray(aead.keyLength) { (it + 1).toByte() }
            val nonce = ByteArray(12)
            val sealed = QuicCrypto.seal(aead, key, nonce, plaintext, ByteArray(0))
            assertEquals(aead.name, plaintext.size + 16, sealed.size)
        }
    }

    @Test
    fun `the packet number is left-padded and exclusive-ORed into the IV`() {
        // RFC 9001 §5.3: the reconstructed packet number in network byte order,
        // zero-padded on the left to the width of the IV, XOR the IV.
        assertArrayEquals(
            hex("00000000 0102030405060708"),
            QuicCrypto.nonce(ByteArray(12), 0x0102030405060708L)
        )

        // Packet number zero leaves the IV alone, which is what an XOR with
        // zero has to do — and is why the first packet's nonce is the IV.
        val iv = hex("fa044b2f42a3fd3b46fb255c")
        assertArrayEquals(iv, QuicCrypto.nonce(iv, 0))

        // Only the trailing eight bytes can ever move, because a packet number
        // is at most 62 bits. Here the largest one QUIC can express.
        assertArrayEquals(
            hex("ffffffff c000000000000000"),
            QuicCrypto.nonce(ByteArray(12) { 0xFF.toByte() }, QuicVarInt.MAX)
        )
    }

    @Test
    fun `consecutive packets get nonces that differ only in the low bytes`() {
        val iv = hex("0ac1493ca1905853b0bba03e")
        assertArrayEquals(hex("0ac1493ca1905853b0bba03f"), QuicCrypto.nonce(iv, 1))
        assertArrayEquals(hex("0ac1493ca1905853b0bba03c"), QuicCrypto.nonce(iv, 2))
        assertArrayEquals(hex("0ac1493ca1905853b0bba0be"), QuicCrypto.nonce(iv, 0x80))
        assertArrayEquals(hex("0ac1493ca1905853b0bba13e"), QuicCrypto.nonce(iv, 0x100))
    }

    @Test
    fun `an IV too short to hold a packet number is refused`() {
        for (size in 0..7) {
            try {
                QuicCrypto.nonce(ByteArray(size), 1)
                throw AssertionError("expected a refusal for a $size-byte IV")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun `a negative packet number is a bug rather than a wrap`() {
        try {
            QuicCrypto.nonce(ByteArray(12), -1)
            throw AssertionError("expected a refusal")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }

    // MARK: - AES-128-GCM, against McGrew and Viega's test cases

    @Test
    fun `GCM test case 1 - an empty message is still authenticated`() {
        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.AES_128_GCM,
            key = ByteArray(16),
            nonce = ByteArray(12),
            plaintext = ByteArray(0),
            aad = ByteArray(0)
        )
        assertArrayEquals(hex("58e2fccefa7e3061367f1d57a4e7455a"), sealed)
    }

    @Test
    fun `GCM test case 2 - one block under a zero key`() {
        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.AES_128_GCM,
            key = ByteArray(16),
            nonce = ByteArray(12),
            plaintext = ByteArray(16),
            aad = ByteArray(0)
        )
        assertArrayEquals(
            hex("0388dace60b6a392f328c2b971b2fe78 ab6e47d42cec13bdf53a67b21257bddf"),
            sealed
        )
    }

    @Test
    fun `GCM test case 3 - four blocks, no associated data`() {
        val key = hex("feffe9928665731c6d6a8f9467308308")
        val nonce = hex("cafebabefacedbaddecaf888")
        val plaintext = hex(
            """d9313225f88406e5a55909c5aff5269a
               86a7a9531534f7da2e4c303d8a318a72
               1c3c0c95956809532fcf0e2449a6b525
               b16aedf5aa0de657ba637b391aafd255"""
        )
        val expected = hex(
            """42831ec2217774244b7221b784d0d49c
               e3aa212f2c02a4e035c17e2329aca12e
               21d514b25466931c7d8f6a5aac84aa05
               1ba30b396a0aac973d58e091473f5985
               4d5c2af327cd64a62cf35abd2ba6fab4"""
        )

        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.AES_128_GCM, key, nonce, plaintext, ByteArray(0)
        )
        assertArrayEquals(expected, sealed)
        assertArrayEquals(
            plaintext,
            QuicCrypto.open(QuicCrypto.Aead.AES_128_GCM, key, nonce, expected, ByteArray(0))
        )
    }

    @Test
    fun `GCM test case 4 - associated data changes the tag but not the ciphertext`() {
        val key = hex("feffe9928665731c6d6a8f9467308308")
        val nonce = hex("cafebabefacedbaddecaf888")
        val plaintext = hex(
            """d9313225f88406e5a55909c5aff5269a
               86a7a9531534f7da2e4c303d8a318a72
               1c3c0c95956809532fcf0e2449a6b525
               b16aedf5aa0de657ba637b39"""
        )
        val aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        val expected = hex(
            """42831ec2217774244b7221b784d0d49c
               e3aa212f2c02a4e035c17e2329aca12e
               21d514b25466931c7d8f6a5aac84aa05
               1ba30b396a0aac973d58e091
               5bc94fbc3221a5db94fae95ae7121a47"""
        )

        val sealed = QuicCrypto.seal(QuicCrypto.Aead.AES_128_GCM, key, nonce, plaintext, aad)
        assertArrayEquals(expected, sealed)

        // This is the property QUIC leans on: the header is the associated
        // data, so a rewritten header fails to open rather than decrypting to
        // something plausible.
        val tampered = aad.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertNull(QuicCrypto.open(QuicCrypto.Aead.AES_128_GCM, key, nonce, sealed, tampered))
    }

    // MARK: - AES-256-GCM

    @Test
    fun `GCM test case 13 - an empty message under a 256-bit zero key`() {
        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.AES_256_GCM,
            key = ByteArray(32),
            nonce = ByteArray(12),
            plaintext = ByteArray(0),
            aad = ByteArray(0)
        )
        assertArrayEquals(hex("530f8afbc74536b9a963b4f1c4cb738b"), sealed)
    }

    @Test
    fun `GCM test case 14 - one block under a 256-bit zero key`() {
        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.AES_256_GCM,
            key = ByteArray(32),
            nonce = ByteArray(12),
            plaintext = ByteArray(16),
            aad = ByteArray(0)
        )
        assertArrayEquals(
            hex("cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919"),
            sealed
        )
    }

    // MARK: - ChaCha20-Poly1305, against RFC 8439 §2.8.2

    @Test
    fun `the RFC 8439 AEAD example`() {
        val key = hex(
            """808182838485868788898a8b8c8d8e8f
               909192939495969798999a9b9c9d9e9f"""
        )
        val nonce = hex("070000004041424344454647")
        val aad = hex("50515253c0c1c2c3c4c5c6c7")
        val plaintext = (
            "Ladies and Gentlemen of the class of '99: If I could offer you " +
                "only one tip for the future, sunscreen would be it."
            ).toByteArray(Charsets.US_ASCII)
        val expected = hex(
            """d31a8d34648e60db7b86afbc53ef7ec2
               a4aded51296e08fea9e2b5a736ee62d6
               3dbea45e8ca9671282fafb69da92728b
               1a71de0a9e060b2905d6a5b67ecd3b36
               92ddbd7f2d778b8c9803aee328091b58
               fab324e4fad675945585808b4831d7bc
               3ff4def08e4b7a9de576d26586cec64b
               6116
               1ae10b594f09e26a7e902ecbd0600691"""
        )

        // The RFC's own length, which is also a check on the plaintext above.
        assertEquals(114, plaintext.size)

        val sealed = QuicCrypto.seal(
            QuicCrypto.Aead.CHACHA20_POLY1305, key, nonce, plaintext, aad
        )
        assertArrayEquals(expected, sealed)
        assertArrayEquals(
            plaintext,
            QuicCrypto.open(QuicCrypto.Aead.CHACHA20_POLY1305, key, nonce, expected, aad)
        )
    }

    // MARK: - What a receiver does with a packet that will not open

    @Test
    fun `a flipped byte anywhere in the sealed packet fails to open`() {
        val plaintext = "one QUIC packet payload".toByteArray(Charsets.US_ASCII)
        val aad = hex("c300000001088394c8f03e51570800")

        for (aead in QuicCrypto.Aead.entries) {
            val key = ByteArray(aead.keyLength) { (it * 7 + 3).toByte() }
            val nonce = QuicCrypto.nonce(ByteArray(12) { it.toByte() }, 42)
            val sealed = QuicCrypto.seal(aead, key, nonce, plaintext, aad)
            assertArrayEquals(plaintext, QuicCrypto.open(aead, key, nonce, sealed, aad))

            for (index in sealed.indices) {
                val broken = sealed.copyOf()
                broken[index] = (broken[index].toInt() xor 0x01).toByte()
                assertNull("$aead at $index", QuicCrypto.open(aead, key, nonce, broken, aad))
            }
        }
    }

    @Test
    fun `the wrong nonce or the wrong key opens nothing`() {
        val plaintext = "payload".toByteArray(Charsets.US_ASCII)
        for (aead in QuicCrypto.Aead.entries) {
            val key = ByteArray(aead.keyLength) { (it + 9).toByte() }
            val nonce = QuicCrypto.nonce(ByteArray(12), 5)
            val sealed = QuicCrypto.seal(aead, key, nonce, plaintext, ByteArray(0))

            val neighbour = QuicCrypto.nonce(ByteArray(12), 6)
            assertNull(aead.name, QuicCrypto.open(aead, key, neighbour, sealed, ByteArray(0)))

            val otherKey = key.copyOf().also { it[0] = (it[0].toInt() xor 0x80).toByte() }
            assertNull(aead.name, QuicCrypto.open(aead, otherKey, nonce, sealed, ByteArray(0)))

            // Associated data that was not there when it was sealed.
            assertNull(aead.name, QuicCrypto.open(aead, key, nonce, sealed, byteArrayOf(0)))
        }
    }

    @Test
    fun `anything shorter than the tag cannot be authentic`() {
        val key = ByteArray(16)
        val nonce = ByteArray(12)
        for (size in 0 until QuicCrypto.TAG_LENGTH) {
            assertNull(
                "$size bytes",
                QuicCrypto.open(
                    QuicCrypto.Aead.AES_128_GCM, key, nonce, ByteArray(size), ByteArray(0)
                )
            )
        }
        // Exactly the tag is the empty message, which does open.
        val empty = QuicCrypto.seal(
            QuicCrypto.Aead.AES_128_GCM, key, nonce, ByteArray(0), ByteArray(0)
        )
        assertEquals(QuicCrypto.TAG_LENGTH, empty.size)
        assertNotNull(QuicCrypto.open(QuicCrypto.Aead.AES_128_GCM, key, nonce, empty, ByteArray(0)))
    }

    @Test
    fun `a key or nonce of the wrong length is refused rather than padded`() {
        // A size mismatch is this side's bug, not something a network can
        // produce, so it is not folded into the null that means "discard".
        for (aead in QuicCrypto.Aead.entries) {
            try {
                QuicCrypto.seal(aead, ByteArray(aead.keyLength - 1), ByteArray(12), ByteArray(0), ByteArray(0))
                throw AssertionError("expected a refusal for a short $aead key")
            } catch (_: IllegalArgumentException) {
                // expected
            }
            try {
                QuicCrypto.seal(aead, ByteArray(aead.keyLength), ByteArray(8), ByteArray(0), ByteArray(0))
                throw AssertionError("expected a refusal for an 8-byte $aead nonce")
            } catch (_: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun `a packet sealed under one suite does not open under another`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = ByteArray(12) { (it + 1).toByte() }
        val plaintext = "cross-suite".toByteArray(Charsets.US_ASCII)

        val gcm = QuicCrypto.seal(QuicCrypto.Aead.AES_256_GCM, key, nonce, plaintext, ByteArray(0))
        assertNull(
            QuicCrypto.open(QuicCrypto.Aead.CHACHA20_POLY1305, key, nonce, gcm, ByteArray(0))
        )

        val chacha = QuicCrypto.seal(
            QuicCrypto.Aead.CHACHA20_POLY1305, key, nonce, plaintext, ByteArray(0)
        )
        assertNull(QuicCrypto.open(QuicCrypto.Aead.AES_256_GCM, key, nonce, chacha, ByteArray(0)))
    }
}
