package com.mythaia.vpn.protocol.wireguard

import org.bouncycastle.crypto.digests.Blake2sDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The WireGuard primitives, checked against published vectors rather than
 * against themselves.
 *
 * A round trip through one implementation proves nothing about the wire: both
 * ends share any mistake. So the pieces that have RFC vectors are pinned to
 * them, and the handshake is driven against a responder written separately from
 * the protocol paper's own steps.
 */
class WireGuardCryptoTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    // MARK: - BLAKE2s (RFC 7693)

    @Test
    fun `BLAKE2s-256 matches its RFC 7693 vector`() {
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            hex(WireGuardCrypto.hash("abc".toByteArray()))
        )
        // The empty input, which the construction hash effectively relies on
        // behaving like any other.
        assertEquals(32, WireGuardCrypto.hash(ByteArray(0)).size)
    }

    @Test
    fun `hashing several parts is hashing their concatenation`() {
        // The handshake always hashes a running value followed by one field, so
        // a wrong order or a missing part would be invisible in a round trip.
        val a = "one".toByteArray()
        val b = "two".toByteArray()
        assertArrayEquals(WireGuardCrypto.hash(a + b), WireGuardCrypto.hash(a, b))
        assertNotEquals(hex(WireGuardCrypto.hash(a, b)), hex(WireGuardCrypto.hash(b, a)))
    }

    @Test
    fun `keyed BLAKE2s truncates to the requested length`() {
        val key = ByteArray(32) { it.toByte() }
        val data = "message".toByteArray()

        val full = WireGuardCrypto.mac(key, data, 32)
        val short = WireGuardCrypto.mac(key, data, 16)
        assertEquals(32, full.size)
        assertEquals(16, short.size)

        // Computed independently: BLAKE2s keyed at a shorter digest length is
        // NOT the prefix of the longer one, which is why the length has to be
        // passed to the digest rather than sliced afterwards.
        val independent = Blake2sDigest(key, 16, null, null).run {
            update(data, 0, data.size)
            ByteArray(16).also { doFinal(it, 0) }
        }
        assertArrayEquals(independent, short)
    }

    // MARK: - X25519 (RFC 7748 §6.1)

    @Test
    fun `X25519 matches its RFC 7748 vector`() {
        val alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPrivate = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

        assertArrayEquals(alicePublic, WireGuardCrypto.publicKey(alicePrivate))
        assertArrayEquals(bobPublic, WireGuardCrypto.publicKey(bobPrivate))
        assertEquals(shared, hex(WireGuardCrypto.sharedSecret(alicePrivate, bobPublic)))
        assertEquals(shared, hex(WireGuardCrypto.sharedSecret(bobPrivate, alicePublic)))
    }

    @Test
    fun `a low-order public key is refused rather than agreed with`() {
        // These force an all-zero secret, which the peer also knows. Accepting
        // one would let anyone who can inject a key fix the session keys.
        val privateKey = WireGuardCrypto.generateKeyPair().first
        for (lowOrder in listOf(
            ByteArray(32),                                          // 0
            ByteArray(32).also { it[0] = 1 },                       // 1
            hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
        )) {
            try {
                WireGuardCrypto.sharedSecret(privateKey, lowOrder)
                fail("expected a refusal for ${hex(lowOrder)}")
            } catch (_: WireGuardError) {
                // expected
            }
        }
    }

    @Test
    fun `keys of the wrong size are refused`() {
        try {
            WireGuardCrypto.sharedSecret(ByteArray(31), ByteArray(32))
            fail("expected a refusal")
        } catch (_: WireGuardError) {
        }
    }

    // MARK: - Nonce

    @Test
    fun `the nonce is four zero bytes then a little-endian counter`() {
        assertArrayEquals(ByteArray(12), WireGuardCrypto.nonce(0))

        val one = WireGuardCrypto.nonce(1)
        assertArrayEquals(ByteArray(4), one.copyOfRange(0, 4))
        assertEquals(1.toByte(), one[4])
        assertEquals(0.toByte(), one[11])

        // Little-endian: the low byte comes first, which is the opposite of
        // every length field in the protocol and easy to get backwards.
        val big = WireGuardCrypto.nonce(0x0102030405060708L)
        assertEquals(0x08.toByte(), big[4])
        assertEquals(0x01.toByte(), big[11])
    }

    // MARK: - AEAD

    @Test
    fun `sealing and opening round-trip, and the AAD is authenticated`() {
        val key = ByteArray(32) { it.toByte() }
        val plaintext = "the packet".toByteArray()
        val aad = "the running hash".toByteArray()

        val sealed = WireGuardCrypto.seal(key, 7, plaintext, aad)
        assertEquals(plaintext.size + WireGuardCrypto.TAG_SIZE, sealed.size)
        assertArrayEquals(plaintext, WireGuardCrypto.open(key, 7, sealed, aad))

        // Every input is bound: a different counter, AAD or key all fail.
        assertNull(WireGuardCrypto.open(key, 8, sealed, aad))
        assertNull(WireGuardCrypto.open(key, 7, sealed, "other".toByteArray()))
        assertNull(WireGuardCrypto.open(ByteArray(32), 7, sealed, aad))

        val tampered = sealed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertNull(WireGuardCrypto.open(key, 7, tampered, aad))
    }

    @Test
    fun `an empty plaintext seals to just the tag`() {
        // The handshake response encrypts nothing at all, so this is a real case.
        val key = ByteArray(32) { it.toByte() }
        val sealed = WireGuardCrypto.seal(key, 0, ByteArray(0), "h".toByteArray())
        assertEquals(WireGuardCrypto.TAG_SIZE, sealed.size)
        assertEquals(0, WireGuardCrypto.open(key, 0, sealed, "h".toByteArray())!!.size)
    }

    // MARK: - KDF

    @Test
    fun `the KDF is HKDF over HMAC-BLAKE2s`() {
        val chainingKey = ByteArray(32) { it.toByte() }
        val input = "input".toByteArray()

        // Written out here from RFC 5869 rather than called through the same
        // helper, so the chaining is checked against the construction.
        val prk = WireGuardCrypto.hmac(chainingKey, input)
        val t1 = WireGuardCrypto.hmac(prk, byteArrayOf(0x01))
        val t2 = WireGuardCrypto.hmac(prk, t1 + byteArrayOf(0x02))
        val t3 = WireGuardCrypto.hmac(prk, t2 + byteArrayOf(0x03))

        val one = WireGuardCrypto.kdf(chainingKey, input, 1)
        assertEquals(1, one.size)
        assertArrayEquals(t1, one[0])

        val three = WireGuardCrypto.kdf(chainingKey, input, 3)
        assertArrayEquals(t1, three[0])
        assertArrayEquals(t2, three[1])
        assertArrayEquals(t3, three[2])
        assertTrue(three.all { it.size == 32 })
    }

    // MARK: - TAI64N

    @Test
    fun `the timestamp is TAI64N and increases with time`() {
        val early = WireGuardCrypto.tai64n(1_000_000_000_000L)
        val late = WireGuardCrypto.tai64n(1_000_000_001_000L)
        assertEquals(12, early.size)

        // The responder keeps the greatest timestamp per peer and rejects
        // anything not greater, so the byte order has to make later compare
        // greater lexicographically.
        assertTrue(hex(late) > hex(early))

        // The seconds field is the 2^62 base plus the Unix second count.
        val seconds = 1_000_000_000_000L / 1000
        val expectedHigh = 0x400000000000000AL + seconds
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (early[i].toLong() and 0xFF)
        assertEquals(expectedHigh, value)
    }

    // MARK: - Key encoding

    @Test
    fun `keys round-trip through base64 as configs write them`() {
        val (privateKey, publicKey) = WireGuardCrypto.generateKeyPair()
        assertEquals(32, privateKey.size)
        assertEquals(32, publicKey.size)

        val text = WireGuardCrypto.encodeKey(publicKey)
        assertEquals(44, text.length)                       // 32 bytes base64
        assertArrayEquals(publicKey, WireGuardCrypto.decodeKey(text))
        assertArrayEquals(publicKey, WireGuardCrypto.decodeKey("  $text  "))
    }

    @Test
    fun `anything that is not a 32-byte key is refused`() {
        assertNull(WireGuardCrypto.decodeKey(""))
        assertNull(WireGuardCrypto.decodeKey("not base64!!"))
        // Valid base64 of the wrong length is the case worth catching: it
        // decodes cleanly and would otherwise be used as a key.
        assertNull(WireGuardCrypto.decodeKey(java.util.Base64.getEncoder().encodeToString(ByteArray(16))))
        assertNull(WireGuardCrypto.decodeKey(java.util.Base64.getEncoder().encodeToString(ByteArray(33))))
    }
}
