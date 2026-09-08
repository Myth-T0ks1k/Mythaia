package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * The record AEAD, pinned from the bottom up.
 *
 * The raw AES-256-GCM is checked against published known-answer vectors (the
 * McGrew/NIST GCM test cases), so the cipher is confirmed against an external
 * source before the BLAKE3 key schedule and the counting nonce sit on top of it.
 * Those upper layers are then pinned independently: the derived key is
 * recomputed with the separately-tested [Blake3Kdf], and the first nonce is
 * asserted to be one — not zero — because a record layer that spent nonce zero,
 * or reused a nonce across records, would be a keystream-reuse hole. The
 * all-ones nonce open is exercised because the server's PFS hello depends on it.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessRecordAeadTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    // MARK: - Raw AES-256-GCM against published vectors

    @Test
    fun `raw GCM matches the all-zero test case`() {
        // GCM Test Case 14 (AES-256): zero key, zero IV, 16 zero plaintext bytes,
        // no AAD -> known ciphertext and tag.
        val out = VlessAeadCipher.seal(ByteArray(32), ByteArray(12), null, ByteArray(16))
        assertArrayEquals(
            hex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
            out
        )
    }

    @Test
    fun `raw GCM matches the empty-plaintext test case`() {
        // NIST CAVP gcmEncryptExtIV256: empty plaintext and AAD -> tag only.
        val key = hex("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4")
        val nonce = hex("516c33929df5a3284ff463d7")
        val out = VlessAeadCipher.seal(key, nonce, null, ByteArray(0))
        assertArrayEquals(hex("bdc1ac884d332457a1d2664f168c76f0"), out)
    }

    @Test
    fun `raw GCM open reverses seal and rejects a flipped byte`() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(12) { (0x40 + it).toByte() }
        val aad = "header".toByteArray()
        val sealed = VlessAeadCipher.seal(key, nonce, aad, "payload".toByteArray())
        assertArrayEquals("payload".toByteArray(), VlessAeadCipher.open(key, nonce, aad, sealed))

        val tampered = sealed.copyOf()
        tampered[0] = (tampered[0].toInt() xor 1).toByte()
        assertThrows(AEADBadTagException::class.java) { VlessAeadCipher.open(key, nonce, aad, tampered) }
    }

    // MARK: - The counting-nonce record AEAD

    private val context = "pfs-public".toByteArray()
    private val unitedKey = ByteArray(96) { it.toByte() }

    @Test
    fun `the first seal uses nonce one, derived-key contexted`() {
        // Independently: the key is BLAKE3(context, unitedKey) and the first
        // nonce is the 12-byte counter advanced once, i.e. 0x00..0x01.
        val expectedKey = Blake3Kdf.deriveKey(context, unitedKey)
        val nonceOne = ByteArray(12).also { it[11] = 1 }
        val aad = VlessRecordHeader.encode(5 + VlessWire.AEAD_TAG_LENGTH)

        val aead = VlessRecordAead(context, unitedKey)
        val sealed = aead.seal("first".toByteArray(), aad)

        assertArrayEquals(VlessAeadCipher.seal(expectedKey, nonceOne, aad, "first".toByteArray()), sealed)
    }

    @Test
    fun `each seal advances the nonce so identical plaintext differs`() {
        val aead = VlessRecordAead(context, unitedKey)
        val aad = VlessRecordHeader.encode(4 + VlessWire.AEAD_TAG_LENGTH)
        val a = aead.seal("same".toByteArray(), aad)
        val b = aead.seal("same".toByteArray(), aad)
        assertFalse("records at different nonces must differ", a.contentEquals(b))

        // The second is exactly nonce two under the same derived key.
        val expectedKey = Blake3Kdf.deriveKey(context, unitedKey)
        val nonceTwo = ByteArray(12).also { it[11] = 2 }
        assertArrayEquals(VlessAeadCipher.seal(expectedKey, nonceTwo, aad, "same".toByteArray()), b)
    }

    @Test
    fun `a matching reader opens a writer's records in order`() {
        val writer = VlessRecordAead(context, unitedKey)
        val reader = VlessRecordAead(context, unitedKey)
        val aad1 = VlessRecordHeader.encode(3 + VlessWire.AEAD_TAG_LENGTH)
        val aad2 = VlessRecordHeader.encode(3 + VlessWire.AEAD_TAG_LENGTH)
        val s1 = writer.seal("one".toByteArray(), aad1)
        val s2 = writer.seal("two".toByteArray(), aad2)
        assertArrayEquals("one".toByteArray(), reader.open(s1, aad1))
        assertArrayEquals("two".toByteArray(), reader.open(s2, aad2))
    }

    @Test
    fun `the header is bound as associated data`() {
        val writer = VlessRecordAead(context, unitedKey)
        val reader = VlessRecordAead(context, unitedKey)
        val header = VlessRecordHeader.encode(7 + VlessWire.AEAD_TAG_LENGTH)
        val sealed = writer.seal("payload!".toByteArray().copyOfRange(0, 7), header)
        // Opening under a different header must fail the tag.
        val wrongHeader = VlessRecordHeader.encode(8 + VlessWire.AEAD_TAG_LENGTH)
        assertThrows(AEADBadTagException::class.java) { reader.open(sealed, wrongHeader) }
    }

    @Test
    fun `open with the explicit all-ones nonce matches a seal at that nonce`() {
        // The server seals its PFS hello at the max nonce; the client opens it
        // with that nonce explicitly rather than by advancing the counter.
        val derivedKey = Blake3Kdf.deriveKey(context, unitedKey)
        val maxNonce = ByteArray(12) { 0xFF.toByte() }
        val sealed = VlessAeadCipher.seal(derivedKey, maxNonce, null, "server-hello".toByteArray())

        val aead = VlessRecordAead(context, unitedKey)
        assertArrayEquals("server-hello".toByteArray(), aead.open(sealed, maxNonce, null))
    }

    @Test
    fun `a too-short sealed buffer is a framing error, not a tag failure`() {
        val aead = VlessRecordAead(context, unitedKey)
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            aead.open(ByteArray(VlessWire.AEAD_TAG_LENGTH - 1), null)
        }
    }
}
