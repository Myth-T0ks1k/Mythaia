package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("MitmRuleStore")

/**
 * The process-lifetime registry that decides, for a single sniffed hostname,
 * whether the tunnel should intercept the connection and — if so — with which
 * rule set.
 *
 * This is the one piece of MITM state the tunnel hook consults on every
 * connection, so its whole contract is built around one guarantee: it is
 * **empty by default**. A fresh store holds no certificate authority and no
 * rule sets, and [interceptionFor] returns `null` for every host until
 * something populates it. That is what keeps [com.mythaia.vpn.LwipTcpConnection]
 * behaving byte-for-byte as it does today until a user turns MITM on — the hook
 * is a single `interceptionFor(sni) != null` check that is inert while the store
 * is untouched.
 *
 * The store owns two things:
 *
 *  - the [MitmCertificateAuthority] every intercepted leaf chains to, set lazily
 *    with [install] (from persisted bytes) or [generateAuthority] (a fresh one),
 *    and the single [MitmLeafCertificates] cache built over it, so leaves are
 *    reused across connections rather than re-minted per handshake;
 *  - a set of **enabled** [MitmRuleSet]s, keyed by [MitmRuleSet.name], each
 *    carrying an enabled flag so a set can be kept but switched off without
 *    being forgotten.
 *
 * [interceptionFor] does host-suffix matching only (it does not consult the CA):
 * among the enabled sets whose [MitmRuleSet.domainSuffixes] match the host, the
 * one with the **longest** matching suffix wins — `mail.example.com` beats
 * `example.com` beats no match — so the most specific configuration a user
 * wrote is the one that applies. The tunnel hook pairs this with [authority] so
 * it intercepts only when both a rule set and a CA are present.
 *
 * Every method is safe to call from any thread: reads take a snapshot under the
 * lock, writes mutate under it, and the connection threads that call
 * [interceptionFor] never see a half-applied edit. The shape mirrors the iOS
 * `NowhereSessionRegistry.shared` singleton — one process-wide [shared] instance
 * the app configures, with the primary constructor left open so a test can drive
 * an isolated store.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmRuleStore {

    /** One rule set plus whether it is currently eligible for selection. */
    private class Entry(var ruleSet: MitmRuleSet, var enabled: Boolean)

    private val lock = Any()

    /** The CA every intercepted leaf chains to; null until [install]/[generateAuthority]. */
    private var authority: MitmCertificateAuthority? = null

    /** The single leaf cache over [authority]; rebuilt whenever the CA changes. */
    private var leafCache: MitmLeafCertificates? = null

    /** Insertion-ordered so longest-suffix ties resolve deterministically to the first-added set. */
    private val entries = LinkedHashMap<String, Entry>()

    // MARK: - Certificate authority

    /**
     * Installs the CA from the two byte arrays [MitmCertificateAuthority.load]
     * round-trips — a PKCS#8 private key and a DER certificate — and drops any
     * existing leaf cache so leaves are re-minted under the new root.
     *
     * @throws MitmCertificateAuthority.Failure when the bytes are not a valid,
     *   self-signed CA whose key matches its certificate.
     */
    fun install(caPkcs8: ByteArray, caDer: ByteArray) {
        val loaded = MitmCertificateAuthority.load(caPkcs8, caDer)
        synchronized(lock) {
            authority = loaded
            leafCache = null
        }
        logger.info("MITM certificate authority installed")
    }

    /**
     * Generates a fresh CA, installs it, and returns it so the caller can
     * persist [MitmCertificateAuthority.privateKeyPkcs8] and
     * [MitmCertificateAuthority.certificateDer] for a later [install].
     */
    fun generateAuthority(): MitmCertificateAuthority {
        val generated = MitmCertificateAuthority.generate()
        synchronized(lock) {
            authority = generated
            leafCache = null
        }
        logger.info("MITM certificate authority generated")
        return generated
    }

    /** The installed CA, or null when none has been set. */
    fun authority(): MitmCertificateAuthority? = synchronized(lock) { authority }

    /**
     * Drops the CA (and its leaf cache), leaving the rule sets in place.
     *
     * Removing the CA disarms interception on its own — the tunnel hook requires
     * a CA as well as a matching rule set — so this is what "clear the root
     * certificate" does at runtime: a live tunnel stops intercepting at the next
     * connection without also forgetting the imported rule sets.
     */
    fun clearAuthority() {
        synchronized(lock) {
            authority = null
            leafCache = null
        }
    }

    /**
     * The shared leaf cache over the installed CA, built on first use and reused
     * afterwards so a repeat host reuses its leaf.
     *
     * @throws IllegalStateException when no CA has been installed — callers that
     *   reached here without an [authority] have a logic error, since the hook
     *   gates interception on the CA being present.
     */
    fun leafCertificates(): MitmLeafCertificates = synchronized(lock) {
        val ca = authority ?: throw IllegalStateException("no MITM certificate authority is installed")
        leafCache ?: MitmLeafCertificates(ca).also { leafCache = it }
    }

    // MARK: - Rule sets

    /**
     * Adds [ruleSet], or replaces the one already stored under the same
     * [MitmRuleSet.name]. [enabled] sets whether it is eligible for selection.
     */
    fun addRuleSet(ruleSet: MitmRuleSet, enabled: Boolean = true) {
        synchronized(lock) { entries[ruleSet.name] = Entry(ruleSet, enabled) }
    }

    /** Removes the rule set named [name]; returns whether one was present. */
    fun removeRuleSet(name: String): Boolean =
        synchronized(lock) { entries.remove(name) != null }

    /**
     * Replaces the entire collection with [ruleSets], all enabled, discarding
     * whatever was there. The CA is left untouched.
     */
    fun replaceRuleSets(ruleSets: List<MitmRuleSet>) {
        synchronized(lock) {
            entries.clear()
            for (ruleSet in ruleSets) entries[ruleSet.name] = Entry(ruleSet, enabled = true)
        }
    }

    /**
     * Toggles whether the set named [name] is eligible for selection, keeping
     * its rules. Returns whether such a set exists.
     */
    fun setEnabled(name: String, enabled: Boolean): Boolean = synchronized(lock) {
        val entry = entries[name] ?: return false
        entry.enabled = enabled
        true
    }

    /** How many rule sets are stored (enabled or not); for inspection and tests. */
    val ruleSetCount: Int
        get() = synchronized(lock) { entries.size }

    // MARK: - Selection

    /**
     * The single best rule set to intercept [host] with, or `null` when none
     * applies — which is the default for every host on an empty store.
     *
     * Among the enabled sets that match [host] on any of their
     * [MitmRuleSet.domainSuffixes], the one whose matching suffix is longest
     * wins: a set gating `mail.example.com` is preferred over one gating
     * `example.com` for the host `mail.example.com`, so the most specific
     * configuration applies. A suffix matches when the host equals it or ends
     * with `"." + suffix`, both compared lowercased with a trailing root dot
     * stripped — so `sub.EXAMPLE.com.` matches the suffix `example.com`.
     *
     * Ties on suffix length resolve to the first-added set (the map is
     * insertion-ordered and the comparison is strictly-greater), so the result
     * is deterministic even for two sets carrying the same suffix.
     */
    fun interceptionFor(host: String): MitmRuleSet? {
        val normalizedHost = normalizeHost(host)
        if (normalizedHost.isEmpty()) return null
        return synchronized(lock) {
            var best: MitmRuleSet? = null
            var bestLength = -1
            for (entry in entries.values) {
                if (!entry.enabled) continue
                val length = bestSuffixMatch(normalizedHost, entry.ruleSet.domainSuffixes)
                if (length > bestLength) {
                    bestLength = length
                    best = entry.ruleSet
                }
            }
            best
        }
    }

    // MARK: - Teardown

    /** Forgets the CA, its leaf cache, and every rule set — MITM off. */
    fun clear() {
        synchronized(lock) {
            authority = null
            leafCache = null
            entries.clear()
        }
        logger.info("MITM rule store cleared")
    }

    companion object {
        /** The process-wide store the tunnel hook and the configuration UI share. */
        val shared = MitmRuleStore()

        /**
         * The length of the longest suffix in [suffixes] that matches [host], or
         * -1 when none does. [host] is expected already normalized; each suffix
         * is normalized here.
         */
        private fun bestSuffixMatch(host: String, suffixes: List<String>): Int {
            var best = -1
            for (raw in suffixes) {
                val suffix = normalizeSuffix(raw)
                if (suffix.isEmpty()) continue
                if (host == suffix || host.endsWith(".$suffix")) {
                    if (suffix.length > best) best = suffix.length
                }
            }
            return best
        }

        /** Lowercased, with a single trailing root dot removed. */
        private fun normalizeHost(host: String): String =
            host.lowercase().removeSuffix(".")

        /** Lowercased, with a leading dot (as some configs write suffixes) and a trailing dot removed. */
        private fun normalizeSuffix(suffix: String): String =
            suffix.lowercase().removePrefix(".").removeSuffix(".")
    }
}
