package com.mythaia.vpn.protocol.tls.ech

import com.mythaia.vpn.Tls13Crypto
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The ECH accept confirmation, RFC 8446 §7.1 HKDF-Expand-Label over the
 * draft's construction.
 *
 * The expected value is computed here with a second, independent HKDF built
 * straight from the RFC's byte layout — not by calling the code under test. If
 * both agree on a random input they were derived from the same specification;
 * if the code had a wrong label or a wrong prefix, only one of them would.
 */
class EchAcceptConfirmationTest {

    private val suite = 0x1301 // TLS_AES_128_GCM_SHA256

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
            doFinal(data)
        }

    /** RFC 8446 §7.1, written out from the struct rather than reused. */
    private fun expandLabel(secret: ByteArray, label: String, context: ByteArray, length: Int): ByteArray {
        val full = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = byteArrayOf((length ushr 8).toByte(), length.toByte()) +
            byteArrayOf(full.size.toByte()) + full +
            byteArrayOf(context.size.toByte()) + context
        // Length is 8, well under one hash block, so a single HMAC round.
        return hmac(secret, info + byteArrayOf(1)).copyOf(length)
    }

    /** A ServerHello-shaped buffer with [confirmation] in bytes 30..38. */
    private fun serverHello(confirmation: ByteArray): ByteArray {
        val hello = ByteArray(80) { (it * 7).toByte() }
        confirmation.copyInto(hello, 30)
        return hello
    }

    private fun expectedConfirmation(innerRandom: ByteArray, inner: ByteArray, hello: ByteArray): ByteArray {
        val zeroed = hello.copyOf().also { ByteArray(8).copyInto(it, 30) }
        val hash = MessageDigest.getInstance("SHA-256").digest(inner + zeroed)
        val prk = hmac(ByteArray(0), innerRandom) // HKDF-Extract with an empty salt
        return expandLabel(prk, "ech accept confirmation", hash, 8)
    }

    @Test
    fun `a server that holds the inner random is recognised`() {
        val innerRandom = ByteArray(32) { (it + 1).toByte() }
        val inner = ByteArray(200) { (it * 3).toByte() }
        val hello = serverHello(ByteArray(8))
        val confirmed = serverHello(expectedConfirmation(innerRandom, inner, hello))

        assertTrue(Tls13Crypto.echAcceptConfirmed(suite, innerRandom, inner, confirmed))
    }

    @Test
    fun `a server that ignored ECH is not mistaken for one that accepted`() {
        // An ordinary random in those eight bytes is exactly what a server that
        // never decrypted the inner hello sends. Reading that as acceptance
        // would put the wrong transcript into the key schedule.
        val innerRandom = ByteArray(32) { 0x42 }
        val inner = ByteArray(100)
        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, innerRandom, inner, serverHello(ByteArray(8) { 0x11 })))
    }

    @Test
    fun `a confirmation for a different inner random does not check out`() {
        val inner = ByteArray(150) { it.toByte() }
        val hello = serverHello(ByteArray(8))
        val forOther = serverHello(expectedConfirmation(ByteArray(32) { 1 }, inner, hello))

        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, ByteArray(32) { 2 }, inner, forOther))
    }

    @Test
    fun `a confirmation for a different inner hello does not check out`() {
        val innerRandom = ByteArray(32) { 9 }
        val hello = serverHello(ByteArray(8))
        val forOther = serverHello(expectedConfirmation(innerRandom, ByteArray(50) { 1 }, hello))

        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, innerRandom, ByteArray(50) { 2 }, forOther))
    }

    @Test
    fun `a single flipped bit in the confirmation is refused`() {
        val innerRandom = ByteArray(32) { 5 }
        val inner = ByteArray(64)
        val hello = serverHello(ByteArray(8))
        val good = expectedConfirmation(innerRandom, inner, hello)
        val flipped = good.copyOf().also { it[7] = (it[7].toInt() xor 1).toByte() }

        assertTrue(Tls13Crypto.echAcceptConfirmed(suite, innerRandom, inner, serverHello(good)))
        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, innerRandom, inner, serverHello(flipped)))
    }

    @Test
    fun `a ServerHello too short to hold a random is never accepted`() {
        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, ByteArray(32), ByteArray(10), ByteArray(37)))
        assertFalse(Tls13Crypto.echAcceptConfirmed(suite, ByteArray(32), ByteArray(10), ByteArray(0)))
    }
}
