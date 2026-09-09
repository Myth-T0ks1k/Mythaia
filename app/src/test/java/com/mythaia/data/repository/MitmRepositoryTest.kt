package com.mythaia.data.repository

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import com.mythaia.vpn.mitm.MitmRuleStore
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * The repository's job is to be the thing that finally populates the otherwise
 * inert [MitmRuleStore.shared]: it persists the CA and the imported `.amrs`
 * sets, drives the store from them, and can re-prime the store from disk after
 * the process (or a test) has cleared it.
 *
 * These tests run without Robolectric: [FakeContext] hands the repository a
 * [TemporaryFolder] as its `filesDir` and an in-memory [FakeSharedPreferences],
 * so the same disk-and-prefs state a real device keeps survives across two
 * repository instances the way it would across a process restart. The store is
 * the real process-wide singleton, reset around every test so one test's sets
 * never leak into the next.
 */
class MitmRepositoryTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context

    @Before
    fun setUp() {
        MitmRuleStore.shared.clear()
        context = FakeContext(tempFolder.root)
    }

    @After
    fun tearDown() {
        MitmRuleStore.shared.clear()
    }

    // MARK: - Certificate authority

    @Test
    fun `generateCa installs a CA, marks it installed, and persists it`() = runBlocking {
        val repo = MitmRepository(context)
        assertFalse(repo.caInstalled.value)
        assertNull(MitmRuleStore.shared.authority())

        repo.generateCa()

        // The flow flipped, the store now has a CA, and both files are on disk.
        assertTrue(repo.caInstalled.value)
        assertNotNull(MitmRuleStore.shared.authority())
        assertTrue(File(File(tempFolder.root, "mitm"), "ca.key").exists())
        assertTrue(File(File(tempFolder.root, "mitm"), "ca.der").exists())

        // The exported material is present and consistent with the installed CA.
        val der = repo.caCertificateDer()
        assertNotNull(der)
        assertArrayEqualsNonNull(MitmRuleStore.shared.authority()!!.certificateDer, der!!)
        val pem = repo.caCertificatePem()
        assertNotNull(pem)
        assertTrue(pem!!.contains("BEGIN CERTIFICATE"))
    }

    @Test
    fun `clearCa deletes the persisted CA and clears the flag`() = runBlocking {
        val repo = MitmRepository(context)
        repo.generateCa()
        assertTrue(repo.caInstalled.value)

        repo.clearCa()

        assertFalse(repo.caInstalled.value)
        assertFalse(File(File(tempFolder.root, "mitm"), "ca.key").exists())
        assertFalse(File(File(tempFolder.root, "mitm"), "ca.der").exists())
        assertNull(repo.caCertificateDer())
    }

    // MARK: - Importing rule sets

    @Test
    fun `a valid amrs import adds a set the store then selects for a matching host`() = runBlocking {
        val repo = MitmRepository(context)

        assertTrue(repo.importRuleSet("Alpha", ALPHA_AMRS))

        // The flow shows one set, with the count and suffixes the parser found.
        assertEquals(1, repo.ruleSets.value.size)
        val info = repo.ruleSets.value.single()
        assertEquals("Alpha", info.name)
        assertTrue(info.enabled)
        assertEquals(1, info.ruleCount)
        assertEquals(listOf("alpha.example.com"), info.domainSuffixes)

        // The store now selects it, keyed by the stable name we imported under.
        assertEquals("Alpha", MitmRuleStore.shared.interceptionFor("alpha.example.com")?.name)
        assertEquals("Alpha", MitmRuleStore.shared.interceptionFor("www.alpha.example.com")?.name)
        assertNull(MitmRuleStore.shared.interceptionFor("elsewhere.test"))
    }

    @Test
    fun `a malformed amrs import returns false and adds nothing`() = runBlocking {
        val repo = MitmRepository(context)

        assertFalse(repo.importRuleSet("Junk", MALFORMED_AMRS))

        assertTrue(repo.ruleSets.value.isEmpty())
        assertEquals(0, MitmRuleStore.shared.ruleSetCount)
        assertNull(MitmRuleStore.shared.interceptionFor("anything.test"))
        // Nothing was written to disk either.
        assertFalse(File(File(tempFolder.root, "mitm"), "rulesets").exists())
    }

    @Test
    fun `re-importing the same name replaces the set in place`() = runBlocking {
        val repo = MitmRepository(context)
        assertTrue(repo.importRuleSet("Alpha", ALPHA_AMRS))
        assertTrue(repo.importRuleSet("Alpha", ALPHA_REVISED_AMRS))

        assertEquals(1, repo.ruleSets.value.size)
        assertEquals(1, MitmRuleStore.shared.ruleSetCount)
        // The revised suffix now applies; the old one no longer matches.
        assertEquals("Alpha", MitmRuleStore.shared.interceptionFor("revised.example.com")?.name)
        assertNull(MitmRuleStore.shared.interceptionFor("alpha.example.com"))
    }

    // MARK: - Enable / disable / remove

    @Test
    fun `setEnabled reflects in both the flow and the store`() = runBlocking {
        val repo = MitmRepository(context)
        repo.importRuleSet("Alpha", ALPHA_AMRS)
        assertNotNull(MitmRuleStore.shared.interceptionFor("alpha.example.com"))

        repo.setEnabled("Alpha", false)
        assertFalse(repo.ruleSets.value.single().enabled)
        assertNull(MitmRuleStore.shared.interceptionFor("alpha.example.com"))

        repo.setEnabled("Alpha", true)
        assertTrue(repo.ruleSets.value.single().enabled)
        assertNotNull(MitmRuleStore.shared.interceptionFor("alpha.example.com"))
    }

    @Test
    fun `removeRuleSet drops it from the flow and the store`() = runBlocking {
        val repo = MitmRepository(context)
        repo.importRuleSet("Alpha", ALPHA_AMRS)
        repo.importRuleSet("Beta", BETA_AMRS)
        assertEquals(2, repo.ruleSets.value.size)

        repo.removeRuleSet("Alpha")

        assertEquals(listOf("Beta"), repo.ruleSets.value.map { it.name })
        assertEquals(1, MitmRuleStore.shared.ruleSetCount)
        assertNull(MitmRuleStore.shared.interceptionFor("alpha.example.com"))
        assertEquals("Beta", MitmRuleStore.shared.interceptionFor("beta.example.com")?.name)
    }

    // MARK: - Priming the store from disk

    @Test
    fun `loadInto restores the CA and the enabled sets on a fresh store`() = runBlocking {
        // First "process": generate a CA and import two sets, one of them disabled.
        val first = MitmRepository(context)
        first.generateCa()
        first.importRuleSet("Alpha", ALPHA_AMRS)
        first.importRuleSet("Beta", BETA_AMRS)
        first.setEnabled("Beta", false)
        val savedDer = MitmRuleStore.shared.authority()!!.certificateDer

        // The store is process memory; clear it as a restart would.
        MitmRuleStore.shared.clear()
        assertNull(MitmRuleStore.shared.authority())
        assertEquals(0, MitmRuleStore.shared.ruleSetCount)

        // Second "process": a new repository over the same disk primes the store.
        val second = MitmRepository(context)
        second.loadInto()

        // The CA came back, byte for byte.
        assertTrue(second.caInstalled.value)
        assertNotNull(MitmRuleStore.shared.authority())
        assertArrayEqualsNonNull(savedDer, MitmRuleStore.shared.authority()!!.certificateDer)

        // Both sets are known to the repository with their saved flags.
        assertEquals(2, second.ruleSets.value.size)
        assertEquals(true, second.ruleSets.value.first { it.name == "Alpha" }.enabled)
        assertEquals(false, second.ruleSets.value.first { it.name == "Beta" }.enabled)

        // The enabled set is selected; the disabled one is not.
        assertEquals("Alpha", MitmRuleStore.shared.interceptionFor("alpha.example.com")?.name)
        assertNull(MitmRuleStore.shared.interceptionFor("beta.example.com"))
    }

    @Test
    fun `loadInto is idempotent`() = runBlocking {
        val first = MitmRepository(context)
        first.generateCa()
        first.importRuleSet("Alpha", ALPHA_AMRS)

        MitmRuleStore.shared.clear()

        val second = MitmRepository(context)
        second.loadInto()
        second.loadInto()

        // A second prime replaces rather than duplicates.
        assertEquals(1, MitmRuleStore.shared.ruleSetCount)
        assertEquals(1, second.ruleSets.value.size)
        assertNotNull(MitmRuleStore.shared.authority())
        assertEquals("Alpha", MitmRuleStore.shared.interceptionFor("alpha.example.com")?.name)
    }

    @Test
    fun `loadInto on empty disk leaves the store inert`() = runBlocking {
        val repo = MitmRepository(context)
        repo.loadInto()

        assertFalse(repo.caInstalled.value)
        assertTrue(repo.ruleSets.value.isEmpty())
        assertNull(MitmRuleStore.shared.authority())
        assertEquals(0, MitmRuleStore.shared.ruleSetCount)
    }

    // MARK: - helpers

    private fun assertArrayEqualsNonNull(expected: ByteArray, actual: ByteArray) {
        assertEquals(expected.toList(), actual.toList())
    }

    // MARK: - fixtures

    private companion object {
        val ALPHA_AMRS = """
            name = Alpha display
            hostname = alpha.example.com
            0, 1, ^/api/, X-Alpha, one
        """.trimIndent()

        val ALPHA_REVISED_AMRS = """
            name = Alpha display
            hostname = revised.example.com
            0, 1, ^/api/, X-Alpha, two
        """.trimIndent()

        val BETA_AMRS = """
            name = Beta display
            hostname = beta.example.com
            1, 3, .*, Cache-Control, no-store
        """.trimIndent()

        // No hostname header and no parseable rule line: the parser drops both,
        // so the repository has nothing selectable to store.
        val MALFORMED_AMRS = """
            ### not a real rule set
            just some prose that is not a rule
        """.trimIndent()
    }

    // MARK: - Robolectric-free Android fakes

    /**
     * A [ContextWrapper] with a null base that answers only the two calls the
     * repository makes — [getFilesDir] and [getSharedPreferences]. The mockable
     * android.jar (`testOptions.unitTests.isReturnDefaultValues`) makes the
     * wrapper instantiable; the null base is never dereferenced because both
     * calls are overridden.
     */
    private class FakeContext(private val files: File) : ContextWrapper(null) {
        private val prefs = FakeSharedPreferences()
        override fun getFilesDir(): File = files
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }

    /** An in-memory [SharedPreferences] whose edits apply synchronously. */
    private class FakeSharedPreferences : SharedPreferences {
        private val values = HashMap<String, Any?>()

        override fun getAll(): MutableMap<String, *> = HashMap(values)

        override fun getString(key: String?, defValue: String?): String? =
            if (values.containsKey(key)) values[key] as? String else defValue

        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? =
            if (values.containsKey(key)) values[key] as? MutableSet<String> else defValues

        override fun getInt(key: String?, defValue: Int): Int = values[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = values[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = values[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = values[key] as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = values.containsKey(key)
        override fun edit(): SharedPreferences.Editor = FakeEditor(values)
        override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    }

    private class FakeEditor(private val backing: HashMap<String, Any?>) : SharedPreferences.Editor {
        private val pending = HashMap<String, Any?>()
        private val removals = HashSet<String>()
        private var clearAll = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) pending[key] = value
            return this
        }

        override fun putStringSet(key: String?, set: MutableSet<String>?): SharedPreferences.Editor {
            if (key != null) pending[key] = set
            return this
        }

        override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
            if (key != null) pending[key] = value
            return this
        }

        override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
            if (key != null) pending[key] = value
            return this
        }

        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
            if (key != null) pending[key] = value
            return this
        }

        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
            if (key != null) pending[key] = value
            return this
        }

        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) removals.add(key)
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clearAll = true
            return this
        }

        override fun commit(): Boolean {
            flush()
            return true
        }

        override fun apply() = flush()

        private fun flush() {
            if (clearAll) backing.clear()
            for (key in removals) backing.remove(key)
            backing.putAll(pending)
            pending.clear()
            removals.clear()
            clearAll = false
        }
    }
}
