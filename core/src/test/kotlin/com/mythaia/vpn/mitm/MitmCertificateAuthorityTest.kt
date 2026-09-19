package com.mythaia.vpn.mitm

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Base64
import java.util.Calendar
import java.util.Date
import java.util.GregorianCalendar
import java.util.TimeZone

/**
 * The root the user installs and every leaf chains to. The properties pinned
 * here are the ones a client checks before it trusts a chain: that the root is
 * self-signed and marked a CA, that it comes back byte-identical after a save
 * and reload, that a private key which is not the certificate's is rejected,
 * and that the serial is a positive number a client will accept.
 *
 * Each fact is derived from the standard, not from the code: the validity end
 * is an explicit calendar date ten years on, the PEM is decoded independently
 * back to the DER, and the key-mismatch is a certificate paired with a stranger's
 * key.
 */
class MitmCertificateAuthorityTest {

    private fun utcMillis(year: Int, month: Int, day: Int, hour: Int): Long {
        val calendar = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        calendar.clear()
        calendar.set(year, month, day, hour, 0, 0)
        return calendar.timeInMillis
    }

    @Test
    fun `a generated root is self-signed`() {
        val ca = MitmCertificateAuthority.generate()
        // Verifying under its own public key is the definition of self-signed;
        // it throws if the signature does not hold.
        ca.certificate.verify(ca.certificate.publicKey)
        assertEquals(ca.certificate.subjectX500Principal, ca.certificate.issuerX500Principal)
    }

    @Test
    fun `a generated root is a certificate authority that may sign certificates`() {
        val ca = MitmCertificateAuthority.generate()
        // basicConstraints CA:true carries a pathLen; getBasicConstraints is
        // >= 0 for a CA and -1 for an end-entity certificate.
        assertTrue("root must be a CA", ca.certificate.basicConstraints >= 0)
        // keyCertSign is bit 5 and cRLSign is bit 6 of the KeyUsage bit string.
        val usage = ca.certificate.keyUsage
        assertNotNull("a CA must declare its key usage", usage)
        usage!!
        assertTrue("root must be allowed to sign certificates", usage[5])
        assertTrue("root must be allowed to sign CRLs", usage[6])
    }

    @Test
    fun `save then load brings back the same authority byte for byte`() {
        val ca = MitmCertificateAuthority.generate()
        val loaded = MitmCertificateAuthority.load(ca.privateKeyPkcs8, ca.certificateDer)
        assertArrayEquals(ca.certificateDer, loaded.certificateDer)
        assertArrayEquals(ca.privateKeyPkcs8, loaded.privateKeyPkcs8)
        // A reloaded authority must still be usable end to end: it can sign a
        // leaf that verifies under its certificate.
        val leafKeyPair = MitmCertificateAuthority.generateKeyPair(SecureRandom())
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(
            loaded, leafKeyPair.public, "example.com", BigInteger.valueOf(1234), now - 1000, now + 1_000_000
        )
        leaf.verify(loaded.certificate.publicKey)
    }

    @Test
    fun `the PEM decodes independently back to the DER`() {
        val ca = MitmCertificateAuthority.generate()
        val pem = ca.certificatePem()
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(pem.trimEnd().endsWith("-----END CERTIFICATE-----"))
        val base64 = pem.lines().filterNot { it.startsWith("-----") || it.isEmpty() }.joinToString("")
        assertArrayEquals(ca.certificateDer, Base64.getDecoder().decode(base64))
    }

    @Test
    fun `load rejects a private key that does not belong to the certificate`() {
        val ca = MitmCertificateAuthority.generate()
        val stranger = MitmCertificateAuthority.generate()
        try {
            MitmCertificateAuthority.load(stranger.privateKeyPkcs8, ca.certificateDer)
            fail("expected a refusal for a mismatched key")
        } catch (e: MitmCertificateAuthority.Failure) {
            assertTrue(e.message!!.contains("does not belong"))
        }
    }

    @Test
    fun `load rejects a certificate that is not a certificate authority`() {
        val ca = MitmCertificateAuthority.generate()
        val leafKeyPair = MitmCertificateAuthority.generateKeyPair(SecureRandom())
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(
            ca, leafKeyPair.public, "example.com", BigInteger.valueOf(9), now - 1000, now + 1_000_000
        )
        try {
            MitmCertificateAuthority.load(leafKeyPair.private.encoded, leaf.encoded)
            fail("expected a refusal for a non-CA certificate")
        } catch (e: MitmCertificateAuthority.Failure) {
            assertTrue(e.message!!.contains("not a certificate authority"))
        }
    }

    @Test
    fun `load rejects a CA certificate whose self-signature does not verify`() {
        // A stored root that is marked a CA but was signed by some other key must
        // be refused: trusting it would let anyone who could substitute the file
        // install a root the private key does not actually control. The forged
        // certificate names its own public key as issuer yet is signed by an
        // impostor, so it parses and reads as a CA but fails verify(publicKey).
        val subject = MitmCertificateAuthority.generateKeyPair(SecureRandom())
        val impostor = MitmCertificateAuthority.generateKeyPair(SecureRandom())
        val name = X500Name("O=Mythaia,CN=Forged Root")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(
            name, BigInteger.valueOf(7), Date(now - 1000), Date(now + 1_000_000), name, subject.public
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            // Signed by the impostor, not by `subject`, so the signature will not
            // verify under the public key the certificate carries.
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(impostor.private))

        try {
            MitmCertificateAuthority.load(subject.private.encoded, holder.encoded)
            fail("expected a refusal for a certificate that is not self-signed")
        } catch (e: MitmCertificateAuthority.Failure) {
            assertTrue(e.message!!.contains("not self-signed"))
        }
    }

    @Test
    fun `load rejects bytes that are not a certificate`() {
        val ca = MitmCertificateAuthority.generate()
        try {
            MitmCertificateAuthority.load(ca.privateKeyPkcs8, ByteArray(32) { 0x41 })
            fail("expected a refusal for garbage certificate bytes")
        } catch (e: MitmCertificateAuthority.Failure) {
            assertTrue(e.message!!.contains("did not parse"))
        }
    }

    @Test
    fun `the certificate serial is positive and fits in the intended width`() {
        val ca = MitmCertificateAuthority.generate()
        assertEquals(1, ca.certificate.serialNumber.signum())
        // 16 random bytes is at most 128 bits.
        assertTrue(ca.certificate.serialNumber.bitLength() <= 128)
    }

    @Test
    fun `a serial is never zero, even when every random byte is`() {
        // RFC 5280 §4.1.2.2 forbids a zero serial; the one draw in 2^128 that
        // would produce it must become something a client accepts.
        val allZero = object : SecureRandom() {
            override fun nextBytes(bytes: ByteArray) = bytes.fill(0)
        }
        assertEquals(BigInteger.ONE, MitmCertificateAuthority.randomSerial(allZero))

        // And an ordinary draw is a positive number, never negative from a
        // high bit being read as a sign bit.
        assertEquals(1, MitmCertificateAuthority.randomSerial(SecureRandom()).signum())
    }

    @Test
    fun `validity ends exactly ten calendar years after it begins`() {
        // A fixed instant on a second boundary so the certificate's
        // second-precision times compare exactly, and the expected end is a
        // hand-written calendar date, not a re-run of the code's arithmetic.
        val now = utcMillis(2026, Calendar.MARCH, 15, 12)
        val expectedEnd = utcMillis(2036, Calendar.MARCH, 15, 12)
        assertEquals(expectedEnd, MitmCertificateAuthority.validityEnd(now))

        val ca = MitmCertificateAuthority.generate(nowMillis = now)
        assertEquals(now - MitmCertificateAuthority.NOT_BEFORE_SKEW_MILLIS, ca.certificate.notBefore.time)
        assertEquals(expectedEnd, ca.certificate.notAfter.time)
    }

    @Test
    fun `notBefore is set an hour before now to tolerate a fast client clock`() {
        val now = utcMillis(2026, Calendar.JUNE, 1, 0)
        val ca = MitmCertificateAuthority.generate(nowMillis = now)
        assertEquals(60L * 60 * 1000, now - ca.certificate.notBefore.time)
    }
}
