package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * BLAKE3 pinned against the reference implementation's own published test
 * vectors, not against what this port emits.
 *
 * The vectors come from the BLAKE3 repository's `test_vectors.json`: input case
 * `n` is the bytes `i mod 251` for `i` in `0 until n`, the derive-key context is
 * the fixed string the file names, and the expected outputs are the first 32
 * bytes each mode produces. The 1024-byte case matters because it is exactly one
 * BLAKE3 chunk, so it exercises the tree hashing rather than a single chunk. If
 * the record and CTR keys are to match a server's, the hash under them must be
 * the real BLAKE3 — these are the numbers that say so.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class Blake3KdfTest {

    private val deriveContext = "BLAKE3 2019-12-27 16:29:52 test vectors context".toByteArray(Charsets.US_ASCII)

    private fun seq(n: Int): ByteArray = ByteArray(n) { (it % 251).toByte() }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `plain hash matches the published vectors`() {
        assertArrayEquals(
            hex("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
            Blake3Kdf.hash(seq(0))
        )
        assertArrayEquals(
            hex("2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
            Blake3Kdf.hash(seq(1))
        )
        // One full chunk: crosses into the tree-hashing path.
        assertArrayEquals(
            hex("42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
            Blake3Kdf.hash(seq(1024))
        )
    }

    @Test
    fun `derive_key matches the published vectors`() {
        assertArrayEquals(
            hex("2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
            Blake3Kdf.deriveKey(deriveContext, seq(0))
        )
        assertArrayEquals(
            hex("b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
            Blake3Kdf.deriveKey(deriveContext, seq(1))
        )
        assertArrayEquals(
            hex("7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
            Blake3Kdf.deriveKey(deriveContext, seq(1024))
        )
    }

    @Test
    fun `outputs are 32 bytes and deterministic`() {
        val a = Blake3Kdf.deriveKey("VLESS".toByteArray(), seq(48))
        val b = Blake3Kdf.deriveKey("VLESS".toByteArray(), seq(48))
        assertEquals(32, a.size)
        assertArrayEquals(a, b)
        assertEquals(32, Blake3Kdf.hash(seq(48)).size)
    }

    @Test
    fun `context and key material each change the derived key`() {
        val base = Blake3Kdf.deriveKey("VLESS".toByteArray(), seq(32))
        // A different context is what domain-separates the CTR key from the AEAD
        // key even when the input secret is identical.
        assertFalse(base.contentEquals(Blake3Kdf.deriveKey("OTHER".toByteArray(), seq(32))))
        assertFalse(base.contentEquals(Blake3Kdf.deriveKey("VLESS".toByteArray(), seq(33))))
    }
}
