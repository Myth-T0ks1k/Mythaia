package com.mythaia.vpn.protocol.hysteria

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Salamander against a vector computed from the specification, not from this
 * code: BLAKE2b-256("hunter2" ‖ 00..07), XORed over 0..39.
 *
 * A round trip alone would pass just as happily with the wrong hash, the wrong
 * concatenation order, or the wrong key period — every one of which would look
 * fine locally and fail against a real Hysteria server.
 */
class SalamanderObfuscatorTest {

    private val obfuscator = SalamanderObfuscator("hunter2")

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
    private fun bytes(hex: String) =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test
    fun `the keystream and ciphertext match the specification`() {
        val salt = ByteArray(8) { it.toByte() }
        val payload = ByteArray(40) { it.toByte() }

        // Built by hand so `open` is exercised against bytes this code did not
        // produce: salt, then the expected ciphertext.
        val datagram = salt + bytes(
            "1c05ead77db308d53fd696368937ac1ea332d699072a9d7d49aa42c1a7696c2e3c25caf75d9328f5"
        )
        assertArrayEquals(payload, obfuscator.open(datagram)!!)
    }

    @Test
    fun `a sealed packet opens back to itself`() {
        val payload = ByteArray(1200) { (it * 7).toByte() }
        val sealed = obfuscator.seal(payload)
        assertEquals(SalamanderObfuscator.SALT_LENGTH + payload.size, sealed.size)
        assertArrayEquals(payload, obfuscator.open(sealed)!!)
    }

    @Test
    fun `every datagram gets a fresh salt`() {
        // The same salt twice would reuse the keystream, which for an XOR
        // cipher means the two packets XOR to each other's plaintext.
        val payload = ByteArray(64) { 0x41 }
        val salts = (1..64).map { hex(obfuscator.seal(payload).copyOfRange(0, 8)) }.toSet()
        assertEquals(64, salts.size)
    }

    @Test
    fun `the keystream repeats every 32 bytes and not sooner`() {
        // A zero payload leaves the raw keystream, so its period is visible.
        val sealed = obfuscator.seal(ByteArray(96))
        val stream = sealed.copyOfRange(8, sealed.size)
        assertArrayEquals(stream.copyOfRange(0, 32), stream.copyOfRange(32, 64))
        assertArrayEquals(stream.copyOfRange(0, 32), stream.copyOfRange(64, 96))
    }

    @Test
    fun `a different password gives a different keystream`() {
        val payload = ByteArray(32)
        val salt = ByteArray(8) { 9 }
        val other = SalamanderObfuscator("different")
        assertTrue(
            !obfuscator.open(salt + payload)!!.contentEquals(other.open(salt + payload)!!)
        )
    }

    @Test
    fun `a datagram too short to hold a salt is dropped, not passed through`() {
        // Handing the raw bytes back would deliver un-deobfuscated data to
        // QUIC. The reference returns 0 bytes written, i.e. drops it.
        assertNull(obfuscator.open(ByteArray(8) { 1 }))
        assertNull(obfuscator.open(ByteArray(0)))
        assertNull(obfuscator.open(ByteArray(3)))
    }

    @Test
    fun `a password below the reference minimum is refused`() {
        try {
            SalamanderObfuscator("abc")
            org.junit.Assert.fail("expected a refusal for a 3-byte password")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }
}
