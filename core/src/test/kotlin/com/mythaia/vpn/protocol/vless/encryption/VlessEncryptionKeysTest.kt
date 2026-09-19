package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.vpn.X25519Crypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The hybrid key operations and the relay-block layout.
 *
 * The primitives are checked for the one property the protocol depends on:
 * encapsulate and decapsulate reach the same secret, and a flipped ML-KEM
 * ciphertext reaches a different one (FIPS 203 rejects implicitly, so the tell
 * is a mismatched secret, not an exception). The relay block is checked against
 * a layout rebuilt by hand from injected secrets — the per-relay CTR mask and
 * the chain-hash binding computed with a separate cipher — so the assertion
 * comes from the wire format the server unwinds, not from the builder's own run.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptionKeysTest {

    private val iv = ByteArray(16) { (0xA0 + it).toByte() }

    // MARK: - Hybrid primitives

    @Test
    fun `ML-KEM encapsulate and decapsulate reach the same 32-byte secret`() {
        val pfs = VlessHybridCrypto.generatePfsKeyPair()
        val mlkemPublic = pfs.publicBytes.copyOfRange(0, VlessEncryptionConfig.MLKEM768_KEY_LENGTH)

        val (secret, ciphertext) = VlessHybridCrypto.mlkemEncapsulate(mlkemPublic)
        assertEquals(32, secret.size)
        assertEquals(VlessWire.MLKEM_CIPHERTEXT_LENGTH, ciphertext.size)

        val recovered = VlessHybridCrypto.mlkemDecapsulate(pfs.mlkemPrivate, ciphertext)
        assertArrayEquals(secret, recovered)
    }

    @Test
    fun `a flipped ML-KEM ciphertext decapsulates to a different secret`() {
        val pfs = VlessHybridCrypto.generatePfsKeyPair()
        val mlkemPublic = pfs.publicBytes.copyOfRange(0, VlessEncryptionConfig.MLKEM768_KEY_LENGTH)
        val (secret, ciphertext) = VlessHybridCrypto.mlkemEncapsulate(mlkemPublic)

        ciphertext[0] = (ciphertext[0].toInt() xor 1).toByte()
        val wrong = VlessHybridCrypto.mlkemDecapsulate(pfs.mlkemPrivate, ciphertext)
        // FIPS 203 implicit rejection: no throw, but the secret must not match.
        assertFalse(secret.contentEquals(wrong))
    }

    @Test
    fun `an X25519 relay offer agrees with the relay's private key`() {
        // Stand up a "relay" X25519 keypair; its public key is what the config
        // would carry, and offering to it must land on the same secret the relay
        // computes from the ephemeral public we send.
        val relay = X25519Crypto.generateKeyPair()
        val relayPrivate = relay.copyOfRange(0, 32)
        val relayPublic = relay.copyOfRange(32, 64)

        val offer = VlessHybridCrypto.encapsulateToRelay(NfsPublicKey.X25519(relayPublic))
        val relaySide = VlessHybridCrypto.x25519Agreement(relayPrivate, offer.publicOrCiphertext)
        assertArrayEquals(offer.sharedSecret, relaySide)
    }

    // MARK: - Relay block layout (injected secrets)

    /** A fixed-output encapsulator that hands back the queued secrets in order. */
    private class FakeEncapsulator(secrets: List<ByteArray>, publics: List<ByteArray>) {
        private val queue = secrets.zip(publics).toMutableList()
        val encapsulate: (NfsPublicKey) -> RelaySecret = {
            val (s, p) = queue.removeAt(0)
            RelaySecret(s, p)
        }
    }

    @Test
    fun `a single native X25519 relay is the ephemeral public with the shared secret`() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val secret = ByteArray(32) { (0x11 + it).toByte() }
        val pub = ByteArray(32) { (0x22 + it).toByte() }
        val fake = FakeEncapsulator(listOf(secret), listOf(pub))

        val block = RelayBlockBuilder(
            listOf(key), VlessEncryptionConfig.XorMode.NATIVE, fake.encapsulate
        ).build(iv)

        assertArrayEquals(pub, block.bytes)
        assertArrayEquals(secret, block.nfsKey)
    }

    @Test
    fun `a single native ML-KEM relay is the ciphertext`() {
        val key = ByteArray(1184) { (it % 251).toByte() }
        val secret = ByteArray(32) { (0x33 + it).toByte() }
        val ciphertext = ByteArray(1088) { (it % 97).toByte() }
        val fake = FakeEncapsulator(listOf(secret), listOf(ciphertext))

        val block = RelayBlockBuilder(
            listOf(key), VlessEncryptionConfig.XorMode.NATIVE, fake.encapsulate
        ).build(iv)

        assertArrayEquals(ciphertext, block.bytes)
        assertArrayEquals(secret, block.nfsKey)
    }

    @Test
    fun `xorpub masks the relay block with a CTR keyed on the relay public key`() {
        val key = ByteArray(32) { (it + 5).toByte() }
        val secret = ByteArray(32) { (0x44 + it).toByte() }
        val pub = ByteArray(32) { (0x55 + it).toByte() }
        val fake = FakeEncapsulator(listOf(secret), listOf(pub))

        val block = RelayBlockBuilder(
            listOf(key), VlessEncryptionConfig.XorMode.XORPUB, fake.encapsulate
        ).build(iv)

        // Rebuilt independently: the block is the public masked by a CTR keyed on
        // the raw relay key.
        val expected = VlessEncryptionCtr(key, iv).process(pub)
        assertArrayEquals(expected, block.bytes)
        assertFalse("xorpub must change the bytes", pub.contentEquals(block.bytes))
    }

    @Test
    fun `two native relays are chain-bound by the next key hash`() {
        val key0 = ByteArray(32) { (it + 1).toByte() }
        val key1 = ByteArray(32) { (it + 100).toByte() }
        val secret0 = ByteArray(32) { (0x11 + it).toByte() }
        val secret1 = ByteArray(32) { (0x66 + it).toByte() }
        val pub0 = ByteArray(32) { (0x22 + it).toByte() }
        val pub1 = ByteArray(32) { (0x77 + it).toByte() }
        val fake = FakeEncapsulator(listOf(secret0, secret1), listOf(pub0, pub1))

        val block = RelayBlockBuilder(
            listOf(key0, key1), VlessEncryptionConfig.XorMode.NATIVE, fake.encapsulate
        ).build(iv)

        // Independent reconstruction: pub0, then the next key's hash masked by a
        // CTR keyed on relay 0's secret, then relay 1's public continuing that
        // same keystream.
        val chainCtr = VlessEncryptionCtr(secret0, iv)
        val maskedHash = chainCtr.process(Blake3Kdf.hash(key1))
        val maskedPub1 = chainCtr.process(pub1)
        val expected = pub0 + maskedHash + maskedPub1

        assertArrayEquals(expected, block.bytes)
        assertArrayEquals(secret1, block.nfsKey)
    }

    // MARK: - United key

    @Test
    fun `the united key is mlkem then x25519 then nfs`() {
        val mlkem = ByteArray(32) { 1 }
        val x25519 = ByteArray(32) { 2 }
        val nfs = ByteArray(32) { 3 }
        val united = deriveUnitedKey(mlkem, x25519, nfs)
        assertEquals(96, united.size)
        assertArrayEquals(mlkem, united.copyOfRange(0, 32))
        assertArrayEquals(x25519, united.copyOfRange(32, 64))
        assertArrayEquals(nfs, united.copyOfRange(64, 96))
    }

    @Test
    fun `a generated PFS public is 1184 plus 32 bytes`() {
        val pfs = VlessHybridCrypto.generatePfsKeyPair()
        assertEquals(VlessEncryptionConfig.MLKEM768_KEY_LENGTH + 32, pfs.publicBytes.size)
        assertEquals(32, pfs.x25519Private.size)
        assertTrue(pfs.publicBytes.isNotEmpty())
    }
}
