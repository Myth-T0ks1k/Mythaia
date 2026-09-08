package com.mythaia.vpn.mitm

import org.bouncycastle.asn1.ASN1IA5String
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.x509.GeneralName
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.SecureRandom

/**
 * The per-host leaves an intercepted client is shown. A client matches on the
 * subjectAltName and nothing else, so the tests pin exactly what goes in it:
 * an iPAddress for a literal (Chrome and Safari reject an address hiding in a
 * dNSName), a dNSName for a name, an A-label for a unicode name (a dNSName is
 * an IA5String and the client matches the A-label from its SNI). The cache
 * policy is pinned too, on an injected clock, because a leaf handed out on its
 * last hours breaks a client that re-validates mid-connection.
 *
 * SAN contents are read back with the JDK's own decoder and with BouncyCastle's
 * GeneralName, so the leaf is checked against what a client would see, not
 * against the minting code.
 */
class MitmLeafCertificatesTest {

    private val ip4 = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)

    private fun freshAuthority() = MitmCertificateAuthority.generate()
    private fun leafKey() = MitmCertificateAuthority.generateKeyPair(SecureRandom())

    // --- subjectAltName shape ---

    @Test
    fun `the SAN of an IPv4 literal is a four-byte iPAddress`() {
        val name = MitmLeafCertificates.subjectAltName("93.184.216.34")
        assertEquals(GeneralName.iPAddress, name.tagNo)
        assertArrayEquals(ip4, ASN1OctetString.getInstance(name.name).octets)
        assertArrayEquals(ip4, MitmLeafCertificates.ipAddressBytes("93.184.216.34"))
    }

    @Test
    fun `the SAN of a bracketed IPv6 literal is a sixteen-byte iPAddress`() {
        val name = MitmLeafCertificates.subjectAltName("[::1]")
        assertEquals(GeneralName.iPAddress, name.tagNo)
        val octets = ASN1OctetString.getInstance(name.name).octets
        assertEquals(16, octets.size)
        assertEquals(1, octets[15].toInt())
        for (i in 0 until 15) assertEquals("byte $i must be zero", 0, octets[i].toInt())
    }

    @Test
    fun `the SAN of a hostname is a dNSName`() {
        val name = MitmLeafCertificates.subjectAltName("example.com")
        assertEquals(GeneralName.dNSName, name.tagNo)
        assertEquals("example.com", ASN1IA5String.getInstance(name.name).string)
        assertNull(MitmLeafCertificates.ipAddressBytes("example.com"))
    }

    @Test
    fun `a unicode hostname is carried as its IDNA A-label`() {
        // "bücher" punycodes to "xn--bcher-kva"; the client matched the A-label
        // it put in SNI, so a raw U-label in the certificate would never match.
        val name = MitmLeafCertificates.subjectAltName("bücher.example")
        assertEquals(GeneralName.dNSName, name.tagNo)
        assertEquals("xn--bcher-kva.example", ASN1IA5String.getInstance(name.name).string)
        assertEquals("xn--bcher-kva.example", MitmLeafCertificates.idnaAscii("bücher.example"))
    }

    @Test
    fun `an ASCII hostname is passed through IDNA unchanged`() {
        assertEquals("example.com", MitmLeafCertificates.idnaAscii("example.com"))
    }

    // --- dotted-quad detection ---

    @Test
    fun `only a canonical dotted quad is treated as an IPv4 address`() {
        assertTrue(MitmLeafCertificates.isDottedQuad("1.2.3.4"))
        assertTrue(MitmLeafCertificates.isDottedQuad("255.255.255.255"))
        // Three groups is an inet_aton shorthand and also a legal hostname.
        assertFalse(MitmLeafCertificates.isDottedQuad("1.2.3"))
        // An octet above 255 is not an address.
        assertFalse(MitmLeafCertificates.isDottedQuad("256.1.1.1"))
        // Five groups is neither.
        assertFalse(MitmLeafCertificates.isDottedQuad("1.2.3.4.5"))
    }

    @Test
    fun `shorthand, over-range and zone-tagged forms are not addresses`() {
        assertNull(MitmLeafCertificates.ipAddressBytes("1.2.3"))
        assertNull(MitmLeafCertificates.ipAddressBytes("256.1.1.1"))
        // A zone identifier has no place in a certificate; the whole thing is
        // treated as a name.
        assertNull(MitmLeafCertificates.ipAddressBytes("fe80::1%eth0"))
        assertEquals(GeneralName.dNSName, MitmLeafCertificates.subjectAltName("1.2.3").tagNo)
    }

    // --- the chain verifies, and the JDK sees what we intended ---

    @Test
    fun `a minted leaf is an end-entity certificate that verifies under the CA`() {
        val ca = freshAuthority()
        val key = leafKey()
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(ca, key.public, "example.com", BigInteger.valueOf(42), now - 1000, now + 1_000_000)
        // The issuer names the CA's subject exactly; a byte off and chain
        // building fails.
        assertEquals(ca.certificate.subjectX500Principal, leaf.issuerX500Principal)
        // Verifying under the CA's key throws if the signature does not hold.
        leaf.verify(ca.certificate.publicKey)
        // Not a CA: an end-entity certificate has no basicConstraints CA flag.
        assertEquals(-1, leaf.basicConstraints)
    }

    @Test
    fun `a host leaf's SAN decodes to a dNSName the JDK reads back`() {
        val ca = freshAuthority()
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(ca, leafKey().public, "example.com", BigInteger.ONE, now - 1000, now + 1_000_000)
        val entry = leaf.subjectAlternativeNames!!.first()
        assertEquals(2, entry[0]) // 2 == dNSName in the JDK's SAN encoding
        assertEquals("example.com", entry[1])
    }

    @Test
    fun `an IP leaf's SAN decodes to an iPAddress the JDK reads back`() {
        val ca = freshAuthority()
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(ca, leafKey().public, "93.184.216.34", BigInteger.valueOf(2), now - 1000, now + 1_000_000)
        val entry = leaf.subjectAlternativeNames!!.first()
        assertEquals(7, entry[0]) // 7 == iPAddress in the JDK's SAN encoding
    }

    // --- the cache: normalization, refresh, eviction ---

    @Test
    fun `a host is cached case-insensitively`() {
        val cache = MitmLeafCertificates(freshAuthority())
        val lower = cache.leaf("example.com")
        val mixed = cache.leaf("Example.COM")
        assertSame(lower, mixed)
        assertEquals(1, cache.cachedHostCount)
    }

    @Test
    fun `a leaf within the refresh window is re-minted rather than reused`() {
        var now = 1_000_000_000L
        val cache = MitmLeafCertificates(freshAuthority(), clock = { now })
        val first = cache.leaf("example.com")
        assertEquals(now + MitmLeafCertificates.VALIDITY_MILLIS, first.expiresAtMillis)

        // Still comfortably outside the refresh window: the same leaf comes back.
        now += MitmLeafCertificates.VALIDITY_MILLIS - MitmLeafCertificates.REFRESH_THRESHOLD_MILLIS - 1
        assertSame(first, cache.leaf("example.com"))

        // One millisecond on, exactly the refresh threshold of life remains, so
        // the leaf is re-minted with a fresh expiry rather than handed out on
        // its way to expiring.
        now += 1
        val refreshed = cache.leaf("example.com")
        assertNotSame(first, refreshed)
        assertEquals(now + MitmLeafCertificates.VALIDITY_MILLIS, refreshed.expiresAtMillis)
    }

    @Test
    fun `the cache never exceeds MAX_ENTRIES and drops the least recently used host`() {
        var now = 1_000_000L
        val cache = MitmLeafCertificates(freshAuthority(), clock = { now }, leafKeyPair = leafKey())

        val originals = HashMap<String, MitmLeafCertificates.Leaf>()
        for (i in 0 until MitmLeafCertificates.MAX_ENTRIES) {
            now = 1_000_000L + i
            originals["host$i"] = cache.leaf("host$i")
        }
        assertEquals(MitmLeafCertificates.MAX_ENTRIES, cache.cachedHostCount)

        // Touch host0 so host1 becomes the least recently used.
        now = 2_000_000L
        assertSame(originals["host0"], cache.leaf("host0"))

        // One more distinct host tips the cache over the limit.
        now = 2_000_001L
        cache.leaf("host-new")
        assertEquals(MitmLeafCertificates.MAX_ENTRIES, cache.cachedHostCount)

        // host0 was touched most recently, so it survived: same cached instance.
        now = 2_000_002L
        assertSame(originals["host0"], cache.leaf("host0"))

        // host1 was the least recently used, so it was evicted: requesting it
        // now mints a fresh, different leaf.
        now = 2_000_003L
        assertNotSame(originals["host1"], cache.leaf("host1"))
    }

    @Test
    fun `the common name drops the brackets of an IPv6 literal`() {
        val ca = freshAuthority()
        val now = System.currentTimeMillis()
        val leaf = MitmLeafCertificates.mint(ca, leafKey().public, "[::1]", BigInteger.ONE, now - 1000, now + 1_000_000)
        // The CN reads the same as the SAN, without the SNI brackets.
        assertTrue(leaf.subjectX500Principal.name.contains("CN=::1"))
    }
}
