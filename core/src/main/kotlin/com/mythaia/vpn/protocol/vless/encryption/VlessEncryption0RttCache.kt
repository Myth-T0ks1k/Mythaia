package com.mythaia.vpn.protocol.vless.encryption

import java.util.concurrent.ConcurrentHashMap

/**
 * A process-wide store of 0-RTT resumption tickets, keyed by
 * `(host, port, encryption config)` so two servers, or two differing configs on
 * one server, never share a ticket.
 *
 * The key includes the config's full re-serialisation because the PFS key a
 * ticket resumes was agreed under one exact set of relay keys and modes; a
 * ticket applied under any other would resume into a key the server never held.
 * Invalidation is compare-and-drop on the PFS key rather than a plain remove, so
 * a stale first attempt cannot evict a fresher ticket that a concurrent 1-RTT
 * handshake just stored.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryption0RttCache internal constructor(
    /** Clock seam so expiry can be tested without sleeping; epoch milliseconds. */
    private val clockMs: () -> Long = System::currentTimeMillis
) {

    /**
     * A cached ticket and the key it resumes. [ticket] is the 16-byte plaintext
     * body; [pfsKey] is the 64-byte forward-secret half of the united key.
     */
    class Entry(
        val pfsKey: ByteArray,
        val ticket: ByteArray,
        val expireMs: Long
    )

    private val entries = ConcurrentHashMap<String, Entry>()

    /** Returns a live ticket for [key], dropping and returning null if it has expired. */
    fun lookup(key: String): Entry? {
        val entry = entries[key] ?: return null
        if (entry.expireMs <= clockMs()) {
            entries.remove(key, entry)
            return null
        }
        return entry
    }

    /** Stores a fresh ticket; the latest 1-RTT handshake always wins. */
    fun store(key: String, pfsKey: ByteArray, ticket: ByteArray, expireMs: Long) {
        entries[key] = Entry(pfsKey, ticket, expireMs)
    }

    /**
     * Drops the entry for [key] only if its PFS key still matches [pfsKey], so a
     * newer ticket from a concurrent handshake is not stomped by an older
     * attempt's rejection.
     */
    fun invalidate(key: String, pfsKey: ByteArray) {
        val entry = entries[key] ?: return
        if (entry.pfsKey.contentEquals(pfsKey)) {
            entries.remove(key, entry)
        }
    }

    /** Wired to VPN disconnect so a fresh connect never reuses a stale ticket. */
    fun clear() {
        entries.clear()
    }

    companion object {
        /** The shared instance the handshake and the disconnect path both reach. */
        val shared = VlessEncryption0RttCache()

        /** Lowercases the host so case differences do not fragment the cache. */
        fun cacheKey(host: String, port: Int, config: VlessEncryptionConfig): String =
            "${host.lowercase()}:$port|${config.encoded()}"
    }
}
