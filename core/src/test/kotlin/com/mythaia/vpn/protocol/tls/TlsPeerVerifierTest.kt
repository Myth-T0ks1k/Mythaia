package com.mythaia.vpn.protocol.tls

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Hostname matching and algorithm mapping, which decide whether a certificate
 * is accepted. Both are pure, and both are places where being slightly wrong
 * means accepting a certificate issued for somebody else.
 */
class TlsPeerVerifierTest {

    private fun matches(host: String, name: String) =
        TlsPeerVerifier.matchesDnsName(host, name)

    @Test
    fun `an exact name matches and a different one does not`() {
        assertTrue(matches("example.com", "example.com"))
        assertTrue(!matches("example.com", "example.org"))
        assertTrue(!matches("example.com", "notexample.com"))
    }

    @Test
    fun `matching ignores case and a trailing root dot`() {
        assertTrue(matches("EXAMPLE.com", "example.COM"))
        assertTrue(matches("example.com.", "example.com"))
        assertTrue(matches("example.com", "example.com."))
    }

    @Test
    fun `a wildcard covers one label and only one`() {
        assertTrue(matches("a.example.com", "*.example.com"))
        assertTrue(matches("www.example.com", "*.example.com"))
        // Two labels deep is a different host and must not match.
        assertTrue(!matches("a.b.example.com", "*.example.com"))
    }

    @Test
    fun `a wildcard does not cover the domain it sits under`() {
        // A certificate for *.example.com is not a certificate for
        // example.com; treating it as one lets a subdomain stand in for the
        // site itself.
        assertTrue(!matches("example.com", "*.example.com"))
    }

    @Test
    fun `a wildcard needs something in the label it replaces`() {
        assertTrue(!matches(".example.com", "*.example.com"))
    }

    @Test
    fun `a wildcard anywhere but the left-most label is not a wildcard`() {
        // Only the left-most label may be a wildcard; the rest is a literal
        // name that will not match anything real.
        assertTrue(!matches("a.b.com", "a.*.com"))
        assertTrue(!matches("www.example.com", "www.*.com"))
    }

    @Test
    fun `an empty pattern matches nothing`() {
        assertTrue(!matches("example.com", ""))
    }

    @Test
    fun `every signature algorithm maps to the name the provider expects`() {
        // Conscrypt spells PSS with the digest in front; the generic
        // "RSASSA-PSS" needs parameters it will not infer, and the mistake
        // surfaces as a verification failure against a perfectly good server.
        assertEquals("SHA256withECDSA", TlsPeerVerifier.javaSignatureAlgorithm(0x0403))
        assertEquals("SHA384withECDSA", TlsPeerVerifier.javaSignatureAlgorithm(0x0503))
        assertEquals("SHA512withECDSA", TlsPeerVerifier.javaSignatureAlgorithm(0x0603))
        assertEquals("SHA256withRSA/PSS", TlsPeerVerifier.javaSignatureAlgorithm(0x0804))
        assertEquals("SHA384withRSA/PSS", TlsPeerVerifier.javaSignatureAlgorithm(0x0805))
        assertEquals("SHA512withRSA/PSS", TlsPeerVerifier.javaSignatureAlgorithm(0x0806))
        assertEquals("SHA256withRSA", TlsPeerVerifier.javaSignatureAlgorithm(0x0401))
        assertEquals("Ed25519", TlsPeerVerifier.javaSignatureAlgorithm(0x0807))
    }

    @Test
    fun `an empty chain is refused rather than treated as trusted`() {
        try {
            TlsPeerVerifier.parseChain(emptyList())
            throw AssertionError("expected a refusal")
        } catch (e: TlsPeerVerifier.Failure) {
            assertTrue(e.message!!.contains("no certificate"))
        }
    }

    @Test
    fun `bytes that are not a certificate are refused`() {
        try {
            TlsPeerVerifier.parseChain(listOf(ByteArray(16) { 0x41 }))
            throw AssertionError("expected a refusal")
        } catch (e: TlsPeerVerifier.Failure) {
            assertTrue(e.message!!.contains("did not parse"))
        }
    }
}
