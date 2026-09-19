package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The AES-256-CTR masking stream used for the relay block and, in random mode,
 * the record headers.
 *
 * CTR is a stream cipher, so it is checked by the properties that define one
 * rather than by a fixed ciphertext: a fresh instance's output is the plaintext
 * XOR a keystream that does not depend on the plaintext, the same key and IV
 * reproduce that keystream, running the cipher over its own output recovers the
 * input, and the keystream continues across calls so masking a block in pieces
 * matches masking it whole. The last property is the one the relay-block builder
 * leans on when it masks a public key and then a chain hash from one instance.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptionCtrTest {

    private val key = ByteArray(32) { (0x30 + it).toByte() }
    private val iv = ByteArray(16) { (0x10 + it).toByte() }

    @Test
    fun `output is plaintext XOR a plaintext-independent keystream`() {
        val plaintext = "the quick brown fox jumps over the lazy dog".toByteArray()
        val masked = VlessEncryptionCtr(key, iv).process(plaintext)
        // The keystream is the cipher run over zeros; XOR must reproduce the mask.
        val keystream = VlessEncryptionCtr(key, iv).process(ByteArray(plaintext.size))
        val xored = ByteArray(plaintext.size) { (plaintext[it].toInt() xor keystream[it].toInt()).toByte() }
        assertArrayEquals(xored, masked)
    }

    @Test
    fun `masking is reversible with a fresh instance`() {
        val plaintext = ByteArray(200) { (it * 7).toByte() }
        val masked = VlessEncryptionCtr(key, iv).process(plaintext)
        val recovered = VlessEncryptionCtr(key, iv).process(masked)
        assertArrayEquals(plaintext, recovered)
        assertFalse("masking must change the bytes", plaintext.contentEquals(masked))
    }

    @Test
    fun `the same key and IV give the same keystream`() {
        val a = VlessEncryptionCtr(key, iv).process(ByteArray(64))
        val b = VlessEncryptionCtr(key, iv).process(ByteArray(64))
        assertArrayEquals(a, b)
    }

    @Test
    fun `a different key or IV gives a different keystream`() {
        val base = VlessEncryptionCtr(key, iv).process(ByteArray(64))
        val otherKey = key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val otherIv = iv.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(base.contentEquals(VlessEncryptionCtr(otherKey, iv).process(ByteArray(64))))
        assertFalse(base.contentEquals(VlessEncryptionCtr(key, otherIv).process(ByteArray(64))))
    }

    @Test
    fun `the keystream continues across calls`() {
        // Masking a head then a tail from one instance equals masking the whole
        // buffer from a fresh one: this is what binds the relay block's pieces.
        val head = ByteArray(32) { it.toByte() }
        val tail = ByteArray(1088) { (it % 251).toByte() }
        val stepwise = VlessEncryptionCtr(key, iv).let { it.process(head) + it.process(tail) }
        val whole = VlessEncryptionCtr(key, iv).process(head + tail)
        assertArrayEquals(whole, stepwise)
    }

    @Test
    fun `processInPlace transforms only the given range and continues the stream`() {
        val whole = VlessEncryptionCtr(key, iv).process(ByteArray(10) { it.toByte() })
        val buffer = ByteArray(10) { it.toByte() }
        val ctr = VlessEncryptionCtr(key, iv)
        ctr.processInPlace(buffer, 0, 4)
        ctr.processInPlace(buffer, 4, 10)
        assertArrayEquals(whole, buffer)
    }

    @Test
    fun `a non-16-byte IV is rejected`() {
        assertThrows(VlessEncryptionError.ProtocolViolation::class.java) {
            VlessEncryptionCtr(key, ByteArray(12))
        }
    }

    @Test
    fun `an empty input yields empty output`() {
        assertEquals(0, VlessEncryptionCtr(key, iv).process(ByteArray(0)).size)
    }
}
