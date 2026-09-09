package com.mythaia.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.mythaia.vpn.mitm.AmrsParser
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmRuleSet
import com.mythaia.vpn.mitm.MitmRuleStore
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

/**
 * The UI-facing summary of one persisted rule set — everything a settings row
 * needs without holding the compiled [MitmRule] list. Carried by [MitmRepository.ruleSets]
 * so stage 2's screen can list, toggle, and remove sets by [name] (the stable
 * identity the store is also keyed by), show the [ruleCount] it parsed to, and
 * render the [domainSuffixes] it gates.
 */
data class MitmRuleSetInfo(
    val name: String,
    val enabled: Boolean,
    val ruleCount: Int,
    val domainSuffixes: List<String>
)

/**
 * Persists the MITM certificate authority and the imported `.amrs` rule sets,
 * and drives [MitmRuleStore.shared] from them.
 *
 * Nothing populated the store before this: [MitmRuleStore.shared] is empty by
 * default, so interception is inert until something primes it. This repository
 * is that something. It owns the on-disk representation of the two pieces of
 * MITM state the tunnel consults —
 *
 *  - the CA, saved as two files in [Context.getFilesDir]: a PKCS#8 private key
 *    ([CA_KEY_FILE]) and a DER certificate ([CA_CERT_FILE]), exactly the pair
 *    [MitmCertificateAuthority.load] round-trips;
 *  - the imported rule sets, each saved as its raw `.amrs` text in the
 *    [RULE_SETS_DIR] subdirectory, with a small JSON index in the shared
 *    `mythaia_settings` preferences recording each set's stable name, its file,
 *    and whether it is enabled.
 *
 * — and reconciles the store to them with [loadInto]. Because the store lives
 * for the life of the process but the UI and the (UI-less) tunnel service can
 * each be the first to touch it, [loadInto] is idempotent: it installs the CA
 * if present and re-adds every persisted set, and calling it a second time
 * simply replaces what is already there. Both the app process init and a tunnel
 * start call it, and neither has to know whether the other ran.
 *
 * All disk IO happens off the calling thread — every public mutator is `suspend`
 * and does its work under [Dispatchers.IO], mirroring how [GeoIpDatabase] keeps
 * blocking file work off the caller — while the in-memory index and the two
 * [StateFlow]s update synchronously so the UI sees an edit the moment it lands.
 * Writes go through a temp-file-plus-atomic-rename so an interrupted write can
 * never leave a half-written key, certificate, or rule set that fails to load
 * on the next start, the same guarantee [AtomicWrite] gives the routing file.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmRepository(private val context: Context) {

    /** The persisted index entry for one rule set; its rules live in [fileName], not here. */
    @Serializable
    private data class StoredRuleSet(
        val name: String,
        val fileName: String,
        val enabled: Boolean
    )

    /** The in-memory view of one persisted set: where its text lives, its flag, and its parsed form. */
    private data class LoadedRuleSet(
        val fileName: String,
        val enabled: Boolean,
        val ruleSet: MitmRuleSet
    )

    /** The process-wide store the tunnel hook and the configuration UI share. */
    private val store: MitmRuleStore = MitmRuleStore.shared

    private val prefs: SharedPreferences =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    /** Guards [entries] and [authority]; the file IO around it is done off the lock. */
    private val lock = Any()

    /** Insertion-ordered so the flow and the store agree on the order sets were imported. */
    private val entries = LinkedHashMap<String, LoadedRuleSet>()

    /** The CA held in memory once generated or loaded, so PEM/DER export needs no re-read. */
    @Volatile
    private var authority: MitmCertificateAuthority? = null

    private val _caInstalled = MutableStateFlow(false)

    /** Whether a CA is persisted and installed; false until [generateCa] or a [loadInto] that finds one. */
    val caInstalled: StateFlow<Boolean> = _caInstalled.asStateFlow()

    private val _ruleSets = MutableStateFlow<List<MitmRuleSetInfo>>(emptyList())

    /** The imported rule sets, in import order; empty until [loadInto] or an [importRuleSet]. */
    val ruleSets: StateFlow<List<MitmRuleSetInfo>> = _ruleSets.asStateFlow()

    // MARK: - Certificate authority

    /**
     * Generates a fresh CA, persists its bytes, then installs it into the store.
     *
     * Persisting before arming the store is deliberate: a write failure must not
     * leave a CA intercepting traffic that no later [loadInto] could reproduce.
     */
    suspend fun generateCa() = withContext(Dispatchers.IO) {
        // Generate first, persist, then arm the live store: if the atomic write
        // throws (e.g. the disk is full) the caller sees a failure and the store
        // was never armed, rather than a CA intercepting traffic that no later
        // loadInto could bring back.
        val ca = MitmCertificateAuthority.generate()
        mitmDir().mkdirs()
        writeBytesAtomic(caKeyFile(), ca.privateKeyPkcs8)
        writeBytesAtomic(caCertFile(), ca.certificateDer)
        store.install(ca.privateKeyPkcs8, ca.certificateDer)
        authority = ca
        _caInstalled.value = true
        logger.info("MITM certificate authority generated and persisted")
    }

    /** The persisted root certificate as DER, for the user to install, or null when none is stored. */
    suspend fun caCertificateDer(): ByteArray? = withContext(Dispatchers.IO) {
        ensureCaLoaded()?.certificateDer
    }

    /** The persisted root certificate as PEM, for export, or null when none is stored. */
    suspend fun caCertificatePem(): String? = withContext(Dispatchers.IO) {
        ensureCaLoaded()?.certificatePem()
    }

    /**
     * Forgets the persisted CA: deletes both files and clears [caInstalled].
     *
     * The rule sets are left untouched — this turns off only the authority half
     * of MITM, so a re-generated CA re-arms the sets already imported.
     */
    suspend fun clearCa() = withContext(Dispatchers.IO) {
        runCatching { caKeyFile().delete() }
        runCatching { caCertFile().delete() }
        // Drop the CA from the live store too, not just from disk: otherwise a
        // running tunnel would keep intercepting with the in-memory authority
        // until the process restarted, contradicting the cleared state.
        store.clearAuthority()
        authority = null
        _caInstalled.value = false
        logger.info("MITM certificate authority cleared")
    }

    // MARK: - Rule sets

    /**
     * Imports the `.amrs` [amrsText] under the stable [name], persisting it and
     * adding it to the store.
     *
     * Returns false and changes nothing when the text does not parse into a
     * usable set — [AmrsParser] drops malformed lines rather than throwing, so
     * "malformed" here means the result has no [MitmRuleSet.domainSuffixes] (it
     * could never be selected for any host) or no [MitmRuleSet.rules] (it would
     * do nothing once selected), or carries more than [MitmRuleSet.MAX_RULE_COUNT]
     * rules. On success the set is keyed by [name] (not the `.amrs` file's own
     * `name` header) so [setEnabled], [removeRuleSet], and the store all address
     * it consistently; re-importing the same [name] replaces it in place, reusing
     * its file.
     */
    suspend fun importRuleSet(name: String, amrsText: String): Boolean = withContext(Dispatchers.IO) {
        val parsed = AmrsParser.parse(amrsText)
        if (parsed.domainSuffixes.isEmpty() || parsed.rules.isEmpty()) {
            logger.warning("MITM rule set '$name' imported nothing usable; ignored")
            return@withContext false
        }
        if (parsed.rules.size > MitmRuleSet.MAX_RULE_COUNT) {
            logger.warning("MITM rule set '$name' exceeds the ${MitmRuleSet.MAX_RULE_COUNT}-rule cap; ignored")
            return@withContext false
        }

        // Key the store by the caller's stable name so removal and toggling line up
        // with the index; the parsed suffixes and rules are what actually apply.
        val ruleSet = parsed.copy(name = name)
        val existing = synchronized(lock) { entries[name] }
        val fileName = existing?.fileName ?: "${UUID.randomUUID()}.amrs"
        val enabled = existing?.enabled ?: true

        ruleSetsDir().mkdirs()
        ruleSetFile(fileName).writeTextAtomic(amrsText)

        synchronized(lock) { entries[name] = LoadedRuleSet(fileName, enabled, ruleSet) }
        store.addRuleSet(ruleSet, enabled)
        persistIndex()
        rebuildFlow()
        logger.info("MITM rule set '$name' imported (${ruleSet.rules.size} rules, enabled=$enabled)")
        true
    }

    /** Toggles whether the set named [name] is eligible for selection, in both the flow and the store. */
    suspend fun setEnabled(name: String, enabled: Boolean) = withContext(Dispatchers.IO) {
        val existing = synchronized(lock) { entries[name] } ?: return@withContext
        if (existing.enabled == enabled) return@withContext
        synchronized(lock) { entries[name] = existing.copy(enabled = enabled) }
        store.setEnabled(name, enabled)
        persistIndex()
        rebuildFlow()
    }

    /** Removes the set named [name] from disk, the index, the flow, and the store. */
    suspend fun removeRuleSet(name: String) = withContext(Dispatchers.IO) {
        val existing = synchronized(lock) { entries.remove(name) } ?: return@withContext
        runCatching { ruleSetFile(existing.fileName).delete() }
        store.removeRuleSet(name)
        persistIndex()
        rebuildFlow()
        logger.info("MITM rule set '$name' removed")
    }

    // MARK: - Priming the store

    /**
     * Reconciles [MitmRuleStore.shared] to what is on disk: installs the CA if
     * both its files are present and re-adds every persisted rule set with its
     * saved enabled flag, then republishes both flows.
     *
     * Idempotent and safe to call more than once — [MitmRuleStore.install] and
     * [MitmRuleStore.addRuleSet] both replace rather than accumulate — so the UI
     * process init and a UI-less tunnel start can each call it to prime the store
     * without coordinating. A CA whose bytes no longer load, or a rule set whose
     * file is missing or no longer parses, is skipped rather than aborting the
     * whole load.
     */
    suspend fun loadInto() = withContext(Dispatchers.IO) {
        val ca = loadCaFromDisk()
        if (ca != null) {
            authority = ca
            runCatching { store.install(ca.privateKeyPkcs8, ca.certificateDer) }
                .onFailure { logger.warning("MITM CA on disk did not install: ${it.message ?: it}") }
            _caInstalled.value = store.authority() != null
        } else {
            _caInstalled.value = false
        }

        val rebuilt = LinkedHashMap<String, LoadedRuleSet>()
        for (stored in loadIndex()) {
            val file = ruleSetFile(stored.fileName)
            if (!file.exists()) {
                logger.warning("MITM rule set '${stored.name}' file is missing; skipped")
                continue
            }
            val text = runCatching { file.readText() }.getOrNull() ?: continue
            val ruleSet = AmrsParser.parse(text).copy(name = stored.name)
            rebuilt[stored.name] = LoadedRuleSet(stored.fileName, stored.enabled, ruleSet)
            store.addRuleSet(ruleSet, stored.enabled)
        }
        synchronized(lock) {
            entries.clear()
            entries.putAll(rebuilt)
        }
        rebuildFlow()
        logger.info("MITM store primed from disk (caInstalled=${_caInstalled.value}, sets=${rebuilt.size})")
    }

    // MARK: - Internals

    /** Returns the in-memory CA, loading it from disk on first need. Null when none is stored. */
    private fun ensureCaLoaded(): MitmCertificateAuthority? {
        authority?.let { return it }
        val loaded = loadCaFromDisk() ?: return null
        authority = loaded
        return loaded
    }

    /** Loads the persisted CA, or null when either file is absent or the bytes do not verify. */
    private fun loadCaFromDisk(): MitmCertificateAuthority? {
        val keyFile = caKeyFile()
        val certFile = caCertFile()
        if (!keyFile.exists() || !certFile.exists()) return null
        return runCatching {
            MitmCertificateAuthority.load(keyFile.readBytes(), certFile.readBytes())
        }.getOrElse {
            logger.warning("MITM CA on disk did not load: ${it.message ?: it}")
            null
        }
    }

    private fun loadIndex(): List<StoredRuleSet> {
        val stored = prefs.getString(RULE_SETS_KEY, null) ?: return emptyList()
        return runCatching {
            json.decodeFromString(ListSerializer(StoredRuleSet.serializer()), stored)
        }.getOrElse {
            logger.error("Failed to decode the MITM rule set index: $it")
            emptyList()
        }
    }

    private fun persistIndex() {
        val stored = synchronized(lock) {
            entries.map { (name, e) -> StoredRuleSet(name = name, fileName = e.fileName, enabled = e.enabled) }
        }
        val encoded = json.encodeToString(ListSerializer(StoredRuleSet.serializer()), stored)
        prefs.edit { putString(RULE_SETS_KEY, encoded) }
    }

    private fun rebuildFlow() {
        _ruleSets.value = synchronized(lock) {
            entries.map { (name, e) ->
                MitmRuleSetInfo(
                    name = name,
                    enabled = e.enabled,
                    ruleCount = e.ruleSet.rules.size,
                    domainSuffixes = e.ruleSet.domainSuffixes
                )
            }
        }
    }

    private fun mitmDir(): File = File(context.filesDir, MITM_DIR)
    private fun caKeyFile(): File = File(mitmDir(), CA_KEY_FILE)
    private fun caCertFile(): File = File(mitmDir(), CA_CERT_FILE)
    private fun ruleSetsDir(): File = File(mitmDir(), RULE_SETS_DIR)
    private fun ruleSetFile(fileName: String): File = File(ruleSetsDir(), fileName)

    /**
     * Writes [bytes] to [file] via a uniquely-named sibling temp file and an
     * atomic rename, so a crash mid-write leaves either the old file or the new
     * one — never a truncated key or certificate. Mirrors [writeTextAtomic],
     * which the raw `.amrs` text reuses.
     */
    private fun writeBytesAtomic(file: File, bytes: ByteArray) {
        val tmp = File(file.parentFile, "${file.name}.${UUID.randomUUID()}.tmp")
        tmp.writeBytes(bytes)
        try {
            Files.move(
                tmp.toPath(),
                file.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    companion object {
        private val logger = MythaiaLogger("MitmRepository")

        /** Subdirectory of [Context.getFilesDir] holding the CA files and the rule set text. */
        private const val MITM_DIR = "mitm"
        private const val CA_KEY_FILE = "ca.key"
        private const val CA_CERT_FILE = "ca.der"
        private const val RULE_SETS_DIR = "rulesets"

        /** Key in the shared `mythaia_settings` preferences for the JSON rule set index. */
        private const val RULE_SETS_KEY = "mitmRuleSets"
    }
}
