package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

/**
 * The 0-RTT ticket store, tested against the invariants a resumption relies on
 * rather than its wiring.
 *
 * A ticket must expire on time, so the clock is a seam driven directly rather
 * than slept through. Invalidation must be compare-and-drop on the PFS key: a
 * rejected first attempt has to remove the exact ticket it tried and leave a
 * fresher one a concurrent handshake stored, because dropping the wrong ticket
 * would either replay a dead one or throw away a live one. The cache key must
 * fold in the full config so two configs on one host never collide.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryption0RttCacheTest {

    private val pfsKey = ByteArray(64) { it.toByte() }
    private val ticket = ByteArray(16) { (0x40 + it).toByte() }

    @Test
    fun `store then lookup returns the entry`() {
        val cache = VlessEncryption0RttCache { 1_000L }
        cache.store("k", pfsKey, ticket, expireMs = 5_000L)
        val entry = cache.lookup("k")
        assertNotNull(entry)
        assertArrayEquals(pfsKey, entry!!.pfsKey)
        assertArrayEquals(ticket, entry.ticket)
    }

    @Test
    fun `an expired entry is dropped on lookup`() {
        var now = 1_000L
        val cache = VlessEncryption0RttCache { now }
        cache.store("k", pfsKey, ticket, expireMs = 2_000L)
        now = 2_000L // expireMs <= now means expired
        assertNull(cache.lookup("k"))
        // And it is gone, not merely hidden.
        now = 1_500L
        assertNull(cache.lookup("k"))
    }

    @Test
    fun `invalidate drops only a matching PFS key`() {
        val cache = VlessEncryption0RttCache { 0L }
        cache.store("k", pfsKey, ticket, expireMs = 10_000L)
        // A stale attempt with a different key must not evict the live ticket.
        cache.invalidate("k", ByteArray(64))
        assertNotNull(cache.lookup("k"))
        // The attempt that actually holds this key may evict it.
        cache.invalidate("k", pfsKey)
        assertNull(cache.lookup("k"))
    }

    @Test
    fun `clear removes everything`() {
        val cache = VlessEncryption0RttCache { 0L }
        cache.store("a", pfsKey, ticket, expireMs = 10_000L)
        cache.store("b", pfsKey, ticket, expireMs = 10_000L)
        cache.clear()
        assertNull(cache.lookup("a"))
        assertNull(cache.lookup("b"))
    }

    @Test
    fun `the cache key lowercases the host and folds in the config`() {
        val keyB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { it.toByte() })
        val config = VlessEncryptionConfig.parse("mlkem768x25519plus.native.0rtt.$keyB64")!!
        val key = VlessEncryption0RttCache.cacheKey("Example.COM", 443, config)
        assertEquals("example.com:443|${config.encoded()}", key)
    }
}
