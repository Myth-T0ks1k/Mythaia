package com.mythaia.vpn.mitm

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The rule store's job is to decide, per host, whether to intercept and with
 * which set — and, above all, to decide "no" until a user configures it.
 *
 * The selection facts are derived here independently of the store: which set a
 * host should match, and which of two overlapping sets is the more specific,
 * are worked out from the suffixes the test itself writes, and the store's
 * answer is checked against the rule set's name. The emptiness guarantee — the
 * one the tunnel hook leans on — is asserted directly: a fresh store, and a
 * store that only has a CA, return null for every host.
 */
class MitmRuleStoreTest {

    private fun ruleSet(name: String, vararg suffixes: String): MitmRuleSet =
        MitmRuleSet(name = name, domainSuffixes = suffixes.toList(), rules = emptyList())

    // MARK: - The inert default

    @Test
    fun `interceptionFor is null on an empty store`() {
        val store = MitmRuleStore()
        assertNull(store.interceptionFor("example.com"))
        assertNull(store.interceptionFor("mail.example.com"))
        assertNull(store.interceptionFor("anything.at.all"))
        assertEquals(0, store.ruleSetCount)
    }

    @Test
    fun `a CA alone does not make any host intercepted`() {
        val store = MitmRuleStore()
        store.generateAuthority()
        // The CA is installed, but with no rule sets nothing is selected.
        assertNull(store.interceptionFor("example.com"))
    }

    // MARK: - Selection

    @Test
    fun `longest matching suffix wins`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("broad", "example.com"))
        store.addRuleSet(ruleSet("specific", "mail.example.com"))

        // mail.example.com matches both suffixes; the 16-char one is more specific.
        assertEquals("specific", store.interceptionFor("mail.example.com")?.name)
        // www.example.com matches only the broad suffix.
        assertEquals("broad", store.interceptionFor("www.example.com")?.name)
        // The apex matches only the broad suffix.
        assertEquals("broad", store.interceptionFor("example.com")?.name)
        // A host under neither suffix is not intercepted.
        assertNull(store.interceptionFor("example.org"))
    }

    @Test
    fun `a suffix matches the host itself and a dotted sub-label but not a partial label`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("s", "example.com"))

        assertNotNull(store.interceptionFor("example.com"))
        assertNotNull(store.interceptionFor("a.b.example.com"))
        // "notexample.com" ends with "example.com" textually but is a different
        // registrable name — a suffix must align on a label boundary.
        assertNull(store.interceptionFor("notexample.com"))
    }

    @Test
    fun `host matching is case-insensitive and tolerates a trailing root dot`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("s", "Example.COM"))

        assertEquals("s", store.interceptionFor("WWW.Example.Com")?.name)
        assertEquals("s", store.interceptionFor("example.com.")?.name)
    }

    @Test
    fun `a leading-dot suffix is treated the same as a bare one`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("s", ".example.com"))
        assertEquals("s", store.interceptionFor("mail.example.com")?.name)
        assertEquals("s", store.interceptionFor("example.com")?.name)
    }

    // MARK: - add / remove / replace

    @Test
    fun `remove drops a set from selection`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("a", "a.com"))
        store.addRuleSet(ruleSet("b", "b.com"))
        assertEquals("a", store.interceptionFor("a.com")?.name)

        assertTrue(store.removeRuleSet("a"))
        assertNull(store.interceptionFor("a.com"))
        // The other set is untouched.
        assertEquals("b", store.interceptionFor("b.com")?.name)
        // Removing what is not there reports so.
        assertFalse(store.removeRuleSet("a"))
    }

    @Test
    fun `addRuleSet replaces a set of the same name`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("set", "old.com"))
        store.addRuleSet(ruleSet("set", "new.com"))

        assertEquals(1, store.ruleSetCount)
        assertNull(store.interceptionFor("old.com"))
        assertEquals("set", store.interceptionFor("new.com")?.name)
    }

    @Test
    fun `replaceRuleSets discards the old collection and installs the new one`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("a", "a.com"))
        store.addRuleSet(ruleSet("b", "b.com"))

        store.replaceRuleSets(listOf(ruleSet("c", "c.com")))

        assertEquals(1, store.ruleSetCount)
        assertNull(store.interceptionFor("a.com"))
        assertNull(store.interceptionFor("b.com"))
        assertEquals("c", store.interceptionFor("c.com")?.name)
    }

    // MARK: - Enabled flag

    @Test
    fun `a disabled set is not selected`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("off", "example.com"), enabled = false)
        assertNull(store.interceptionFor("example.com"))

        assertTrue(store.setEnabled("off", true))
        assertEquals("off", store.interceptionFor("example.com")?.name)

        assertTrue(store.setEnabled("off", false))
        assertNull(store.interceptionFor("example.com"))
    }

    @Test
    fun `a disabled more-specific set yields to an enabled broader one`() {
        val store = MitmRuleStore()
        store.addRuleSet(ruleSet("broad", "example.com"))
        store.addRuleSet(ruleSet("specific", "mail.example.com"), enabled = false)

        // The specific set would win if enabled; disabled, the broad set is chosen.
        assertEquals("broad", store.interceptionFor("mail.example.com")?.name)
    }

    @Test
    fun `setEnabled on an unknown set reports false`() {
        val store = MitmRuleStore()
        assertFalse(store.setEnabled("nope", true))
    }

    // MARK: - Certificate authority

    @Test
    fun `leafCertificates throws until a CA is installed and is stable afterwards`() {
        val store = MitmRuleStore()
        assertNull(store.authority())
        try {
            store.leafCertificates()
            fail("leafCertificates must throw without a CA")
        } catch (_: IllegalStateException) {
            // expected
        }

        store.generateAuthority()
        assertNotNull(store.authority())
        val first = store.leafCertificates()
        // The same cache is handed out again so leaves are reused.
        assertSame(first, store.leafCertificates())
        // And it can actually mint a leaf for the installed CA.
        assertNotNull(first.leaf("example.com").certificate)
    }

    @Test
    fun `install brings back a persisted CA and resets the leaf cache`() {
        val ca = MitmCertificateAuthority.generate()

        val store = MitmRuleStore()
        store.generateAuthority()
        val before = store.leafCertificates()

        store.install(ca.privateKeyPkcs8, ca.certificateDer)

        assertNotNull(store.authority())
        // The installed root is the one whose bytes we handed in.
        assertArrayEquals(ca.certificateDer, store.authority()!!.certificateDer)
        // Installing a new CA throws away the old leaf cache.
        val after = store.leafCertificates()
        assertTrue("a new CA must reset the leaf cache", before !== after)
    }

    @Test
    fun `a generated authority is returned so its bytes can be persisted`() {
        val store = MitmRuleStore()
        val generated = store.generateAuthority()
        // The returned CA is the one now installed, and it round-trips through load.
        assertArrayEquals(generated.certificateDer, store.authority()!!.certificateDer)
        MitmCertificateAuthority.load(generated.privateKeyPkcs8, generated.certificateDer)
    }

    // MARK: - Teardown

    @Test
    fun `clear returns the store to its inert default`() {
        val store = MitmRuleStore()
        store.generateAuthority()
        store.addRuleSet(ruleSet("a", "example.com"))
        assertNotNull(store.interceptionFor("example.com"))

        store.clear()

        assertNull(store.authority())
        assertEquals(0, store.ruleSetCount)
        assertNull(store.interceptionFor("example.com"))
    }
}
