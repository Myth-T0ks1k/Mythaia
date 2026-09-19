package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.data.model.ProxyError
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import java.util.Base64

/**
 * The `encryption`/`decryption` grammar parsed from real strings.
 *
 * The key bytes are anchored independently: the 32-byte X25519 case pins a
 * literal base64url whose decode is the known byte run `0x00..0x1F`, so the
 * parser is checked against a value derived outside it, not against its own
 * output. Everything structural — the scheme guard, the xor/rtt tokens, the
 * padding-vs-key length split, the "at least one key" rule, and the round trip
 * back to the same string — is asserted from the grammar the reference defines,
 * because a parser that silently accepts a malformed spec would dial plaintext
 * where the user asked for post-quantum encryption.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptionConfigTest {

    // 32 bytes 0x00..0x1F, base64url without padding — verified by hand against
    // the byte run below, so it anchors the decoder to an external value.
    private val x25519KeyB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    private val x25519KeyBytes = ByteArray(32) { it.toByte() }

    private fun mlkemKeyBytes(): ByteArray = ByteArray(1184) { (it % 251).toByte() }
    private fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    @Test
    fun `none and empty are absence, not error`() {
        assertNull(VlessEncryptionConfig.parse(""))
        assertNull(VlessEncryptionConfig.parse("none"))
    }

    @Test
    fun `a single X25519 key parses to the exact bytes`() {
        val config = VlessEncryptionConfig.parse("mlkem768x25519plus.native.1rtt.$x25519KeyB64")!!
        assertEquals(VlessEncryptionConfig.XorMode.NATIVE, config.xorMode)
        assertEquals(VlessEncryptionConfig.RttMode.ONE_RTT, config.rttMode)
        assertEquals("", config.padding)
        assertEquals(1, config.publicKeys.size)
        assertArrayEquals(x25519KeyBytes, config.publicKeys[0])
        assertEquals(0u, config.seconds)
    }

    @Test
    fun `0rtt sets seconds to one`() {
        val config = VlessEncryptionConfig.parse("mlkem768x25519plus.xorpub.0rtt.$x25519KeyB64")!!
        assertEquals(VlessEncryptionConfig.XorMode.XORPUB, config.xorMode)
        assertEquals(VlessEncryptionConfig.RttMode.ZERO_RTT, config.rttMode)
        assertEquals(1u, config.seconds)
    }

    @Test
    fun `padding segments are kept and keys are separated by length`() {
        val config = VlessEncryptionConfig.parse(
            "mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.$x25519KeyB64"
        )!!
        assertEquals(VlessEncryptionConfig.XorMode.RANDOM, config.xorMode)
        // The two short segments are padding; the long one is the key.
        assertEquals("100-111-1111.75-0-111", config.padding)
        assertEquals(1, config.publicKeys.size)
        assertArrayEquals(x25519KeyBytes, config.publicKeys[0])
    }

    @Test
    fun `an ML-KEM-768 key parses at its 1184-byte length`() {
        val mlkem = mlkemKeyBytes()
        val config = VlessEncryptionConfig.parse("mlkem768x25519plus.native.1rtt.${b64(mlkem)}")!!
        assertEquals(1, config.publicKeys.size)
        assertEquals(1184, config.publicKeys[0].size)
        assertArrayEquals(mlkem, config.publicKeys[0])
    }

    @Test
    fun `multiple keys parse in chain order`() {
        val mlkem = mlkemKeyBytes()
        val config = VlessEncryptionConfig.parse(
            "mlkem768x25519plus.native.0rtt.${b64(mlkem)}.$x25519KeyB64"
        )!!
        assertEquals(2, config.publicKeys.size)
        assertArrayEquals(mlkem, config.publicKeys[0])
        assertArrayEquals(x25519KeyBytes, config.publicKeys[1])
    }

    @Test
    fun `encoded round-trips the canonical string`() {
        val strings = listOf(
            "mlkem768x25519plus.native.1rtt.$x25519KeyB64",
            "mlkem768x25519plus.xorpub.0rtt.$x25519KeyB64",
            "mlkem768x25519plus.random.1rtt.100-111-1111.75-0-111.$x25519KeyB64"
        )
        for (s in strings) {
            assertEquals(s, VlessEncryptionConfig.parse(s)!!.encoded())
        }
    }

    @Test
    fun `malformed specs throw rather than downgrade`() {
        val bad = listOf(
            "wrongscheme.native.1rtt.$x25519KeyB64",        // wrong scheme
            "mlkem768x25519plus.native.1rtt",               // too few fields
            "mlkem768x25519plus.bogus.1rtt.$x25519KeyB64",  // bad xor mode
            "mlkem768x25519plus.native.2rtt.$x25519KeyB64", // bad rtt mode
            "mlkem768x25519plus.native.1rtt.100-111-1111",  // padding only, no key
            "mlkem768x25519plus.native.1rtt.${b64(ByteArray(33))}" // wrong key length
        )
        for (s in bad) {
            assertThrows(ProxyError.InvalidUrl::class.java) { VlessEncryptionConfig.parse(s) }
        }
    }

    @Test
    fun `equality and hashing are by key bytes, not array identity`() {
        val a = VlessEncryptionConfig.parse("mlkem768x25519plus.native.1rtt.$x25519KeyB64")!!
        val b = VlessEncryptionConfig.parse("mlkem768x25519plus.native.1rtt.$x25519KeyB64")!!
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }
}
