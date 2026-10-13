package com.mythaia.vpn.protocol.tls

import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.util.PacketUtil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.NoSuchAlgorithmException

/**
 * The checks added after the 2026-10-13 review: a signature scheme the
 * verifier does not know is refused rather than verified as PKCS#1, names
 * are compared as A-labels, an ECH inner hello offers TLS 1.3 only, an IP
 * literal gets no SNI, and a TLS 1.3 ServerHello without an X25519 share is
 * recognised as TLS 1.3 all the same.
 */
class TlsHardeningTest {

    @Test
    fun `an unknown signature scheme is refused, not mapped to PKCS1 SHA-256`() {
        try {
            TlsPeerVerifier.javaSignatureAlgorithm(0x0420)
            throw AssertionError("expected a refusal")
        } catch (_: NoSuchAlgorithmException) {
        }
        assertEquals("SHA256withRSA/PSS", TlsPeerVerifier.javaSignatureAlgorithm(0x0809))
    }

    @Test
    fun `a name with non-ASCII letters matches its A-label in the certificate`() {
        assertTrue(TlsPeerVerifier.matchesDnsName("bücher.example", "xn--bcher-kva.example"))
        assertTrue(TlsPeerVerifier.matchesDnsName("shop.bücher.example", "*.xn--bcher-kva.example"))
        assertFalse(TlsPeerVerifier.matchesDnsName("bücher.example", "bucher.example"))
    }

    @Test
    fun `an ECH inner hello offers only TLS 1_3 and keeps GREASE`() {
        for (fingerprint in listOf(TlsFingerprint.CHROME_133, TlsFingerprint.FIREFOX_148)) {
            val hello = TlsClientHelloBuilder.buildRawClientHello(
                fingerprint = fingerprint,
                random = ByteArray(32) { it.toByte() },
                sessionId = ByteArray(0),
                serverName = "inner.example",
                publicKey = ByteArray(32) { 7 },
                omitPQKeyShares = true,
                innerHello = true
            )
            val versions = PacketUtil.clientHelloExtension(hello, 0x002B)
            assertNotNull("$fingerprint: no supported_versions", versions)
            val offered = (1 until versions!!.size step 2).map {
                ((versions[it].toInt() and 0xFF) shl 8) or (versions[it + 1].toInt() and 0xFF)
            }
            assertTrue("$fingerprint offers $offered", offered.contains(0x0304))
            assertFalse("$fingerprint still offers TLS 1.2: $offered", offered.contains(0x0303))
            assertTrue("$fingerprint lost its GREASE or 1.3: $offered",
                offered.all { it == 0x0304 || (it and 0x0F0F) == 0x0A0A })
            assertEquals(versions.size - 1, versions[0].toInt() and 0xFF)
            assertTrue(PacketUtil.clientHelloOffersTls13(hello))
        }
    }

    @Test
    fun `the outer hello is unchanged and still offers TLS 1_2`() {
        val hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = TlsFingerprint.CHROME_133,
            random = ByteArray(32) { it.toByte() },
            sessionId = ByteArray(32),
            serverName = "public.example",
            publicKey = ByteArray(32) { 7 },
            omitPQKeyShares = true
        )
        val versions = PacketUtil.clientHelloExtension(hello, 0x002B)!!
        val offered = (1 until versions.size step 2).map {
            ((versions[it].toInt() and 0xFF) shl 8) or (versions[it + 1].toInt() and 0xFF)
        }
        assertTrue(offered.contains(0x0303))
        assertTrue(offered.contains(0x0304))
    }

    @Test
    fun `SNI carries the A-label and is left out for an IP literal`() {
        val named = TlsClientHelloBuilder.buildSNIExtension("bücher.example")
        val name = String(named, 4 + 2 + 1 + 2, named.size - 9, Charsets.US_ASCII)
        assertEquals("xn--bcher-kva.example", name)

        assertEquals(0, TlsClientHelloBuilder.buildSNIExtension("203.0.113.5").size)
        assertEquals(0, TlsClientHelloBuilder.buildSNIExtension("2001:db8::1").size)
    }

    @Test
    fun `a TLS 1_3 ServerHello with a P-256 share is TLS 1_3 without a usable share`() {
        val p256Share = ByteArray(65) { 3 }
        val keyShare = ext(0x0033, u16(0x0017) + u16(p256Share.size) + p256Share)
        val supportedVersions = ext(0x002B, byteArrayOf(0x03, 0x04))
        val record = serverHelloRecord(keyShare + supportedVersions)

        assertNull(PacketUtil.parseServerHello(record))
        assertTrue(PacketUtil.serverHelloSelectsTls13(record))

        val tls12 = serverHelloRecord(ext(0xFF01, byteArrayOf(0x00)))
        assertNull(PacketUtil.parseServerHello(tls12))
        assertFalse(PacketUtil.serverHelloSelectsTls13(tls12))
    }

    @Test
    fun `an X25519 share after another extension is still found`() {
        val share = ByteArray(32) { 9 }
        val supportedVersions = ext(0x002B, byteArrayOf(0x03, 0x04))
        val keyShare = ext(0x0033, u16(0x001D) + u16(32) + share)
        val parsed = PacketUtil.parseServerHello(serverHelloRecord(supportedVersions + keyShare))
        assertNotNull(parsed)
        assertTrue(parsed!!.copyOfRange(0, 32).contentEquals(share))
    }

    private fun u16(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())

    private fun ext(type: Int, body: ByteArray) = u16(type) + u16(body.size) + body

    /** One handshake record holding a ServerHello (TLS_AES_128_GCM_SHA256) with [extensions]. */
    private fun serverHelloRecord(extensions: ByteArray): ByteArray {
        val body = byteArrayOf(0x03, 0x03) + ByteArray(32) { 1 } + byteArrayOf(0x00) +
            byteArrayOf(0x13, 0x01) + byteArrayOf(0x00) + u16(extensions.size) + extensions
        val message = byteArrayOf(0x02, 0x00, (body.size ushr 8).toByte(), body.size.toByte()) + body
        return byteArrayOf(0x16, 0x03, 0x03) + u16(message.size) + message
    }
}
