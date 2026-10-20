package com.mythaia.vpn.util

import com.mythaia.vpn.FakeIpPool
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException

private val logger = MythaiaLogger("ProxyDNSCache")

/**
 * Thread-safe DNS cache with TTL-based expiry.
 *
 * Wraps [InetAddress.getAllByName] with caching so repeated lookups for the same
 * host avoid redundant system DNS calls.
 *
 * When an underlying [Network] is set (via [setUnderlyingNetwork]), DNS resolution
 * uses that network, bypassing the VPN tunnel.
 *
 * IP addresses bypass the cache entirely. Results are stored as IP strings so they
 * can be shared by both TCP ([NioSocket]) and UDP callers.
 */
object DnsCache {

    private const val DEFAULT_TTL_MS = 120_000L
    private const val EVICTION_THRESHOLD = 256
    private val ipv4Regex = Regex("""^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$""")
    /** Coarse character-set guard for IPv6 literals (hex, colon, dot for IPv4-mapped, `%scope`). */
    private val ipv6LiteralForm = Regex("""^[0-9A-Fa-f:.]+(?:%[0-9A-Za-z._-]+)?$""")

    private data class CacheEntry(val ips: List<String>, val expiry: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    @Volatile
    private var activeProxyDomain: String? = null

    /**
     * Underlying physical network for DNS resolution. When set, [resolveAndCache]
     * resolves through the physical interface, bypassing the VPN tunnel — this
     * prevents a circular dependency where proxy DNS resolution would route
     * through the (possibly broken) proxy tunnel.
     */
    @Volatile
    private var underlyingNetwork: UnderlyingNetwork? = null

    fun setActiveProxyDomain(domain: String?) {
        activeProxyDomain = domain?.let { stripBrackets(it).lowercase() }
    }

    /**
     * Pass `null` when VPN is stopped to revert to default resolution.
     */
    fun setUnderlyingNetwork(network: UnderlyingNetwork?) {
        underlyingNetwork = network
    }

    /** The physical network lookups go out on, when the tunnel set one. */
    val network: UnderlyingNetwork? get() = underlyingNetwork

    fun resolveAll(host: String): List<String> {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)

        val key = bare.lowercase()
        val now = System.currentTimeMillis()
        val isActive = activeProxyDomain == key

        val entry = cache[key]
        if (entry != null && now < entry.expiry) return entry.ips

        // Active proxy with stale cache: return stale IPs immediately and refresh
        // in the background. Avoids blocking connections on the active proxy when
        // TTL expires; the stale entry stays in place so concurrent lookups
        // benefit and a failed refresh still has a fallback.
        if (entry != null && isActive) {
            refreshAsync(key, bare)
            return entry.ips
        }

        if (cache.size > EVICTION_THRESHOLD) {
            evictExpired(now)
        }

        val ips = resolveAndCache(key, bare)
        if (ips.isNotEmpty()) return ips

        // Resolution failed: fall back to stale IPs if available.
        return entry?.ips ?: emptyList()
    }

    fun resolveHost(host: String): String? = resolveAll(host).firstOrNull()

    fun prewarm(host: String) {
        resolveAll(host)
    }

    fun cachedIPs(host: String): List<String>? {
        val bare = stripBrackets(host)
        if (isIpAddress(bare)) return listOf(bare)
        return cache[bare.lowercase()]?.ips
    }

    fun isIpAddress(host: String): Boolean {
        val bare = stripBrackets(host)

        // Never call InetAddress on arbitrary domains here: that would trigger a
        // real DNS lookup and can recurse back into the VPN tunnel.
        if (ipv4Regex.matches(bare)) return true
        if (!bare.contains(':')) return false
        // IPv6 literals only contain hex digits, colons, dots (for IPv4-mapped
        // forms), and an optional `%scope` suffix. Reject anything else
        // before handing to InetAddress so a colon-bearing hostname (rare,
        // but legal in some intranet stacks) can never escape into a
        // synchronous DNS lookup.
        if (!ipv6LiteralForm.matches(bare)) return false

        return try {
            InetAddress.getByName(bare) is Inet6Address
        } catch (_: Exception) {
            false
        }
    }

    private fun stripBrackets(host: String): String {
        return if (host.startsWith("[") && host.endsWith("]")) {
            host.substring(1, host.length - 1)
        } else {
            host
        }
    }

    private fun evictExpired(now: Long) {
        val iter = cache.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            if (now >= entry.value.expiry && entry.key != activeProxyDomain) {
                iter.remove()
            }
        }
    }

    /**
     * Refreshes [key] in the background, at most one refresh per name at a time.
     *
     * Both guards matter once encrypted DNS is on. A refresh used to be a
     * platform lookup that returned in milliseconds; through an unreachable
     * DoH or DoT resolver it takes the full four-second timeout, and every new
     * proxied connection calls resolveAll. A browser opening one page would
     * otherwise start hundreds of threads inside a single refresh window.
     */
    private fun refreshAsync(key: String, bare: String) {
        if (!refreshing.add(key)) return
        try {
            refreshExecutor.execute {
                try {
                    resolveAndCache(key, bare)
                } finally {
                    refreshing.remove(key)
                }
            }
        } catch (e: RejectedExecutionException) {
            // The pool is saturated; the stale entry the caller already has is
            // a better answer than blocking for a new one.
            refreshing.remove(key)
            logger.debug("[DNS] Refresh for $bare rejected: ${e.message ?: e}")
        }
    }

    /** Names with a refresh already in flight. */
    private val refreshing = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /**
     * A small bounded pool, so a dead resolver costs a handful of parked
     * threads rather than one per connection.
     */
    private val refreshExecutor: java.util.concurrent.ThreadPoolExecutor =
        java.util.concurrent.ThreadPoolExecutor(
            0, 4,
            30L, java.util.concurrent.TimeUnit.SECONDS,
            java.util.concurrent.LinkedBlockingQueue(32)
        ) { runnable ->
            Thread(runnable, "DnsCache-refresh").apply { isDaemon = true }
        }

    private fun resolveAndCache(key: String, bare: String): List<String> {
        val network = underlyingNetwork

        // Encrypted DNS first when the user has configured it, falling back to
        // the platform resolver rather than failing the dial: an unreachable
        // resolver should cost latency, not connectivity.
        val encrypted = rejectFakeIps(resolveEncrypted(bare, network), bare)
        if (encrypted.isNotEmpty()) {
            cache[key] = CacheEntry(encrypted, System.currentTimeMillis() + DEFAULT_TTL_MS)
            return encrypted
        }

        val ips = try {
            // Resolve through the underlying physical network when available,
            // bypassing the VPN tunnel.
            val addresses = if (network != null) {
                network.getAllByName(bare)
            } else {
                InetAddress.getAllByName(bare)
            }
            rejectFakeIps(addresses.mapNotNull { it.hostAddress }.distinct(), bare)
        } catch (e: Exception) {
            logger.warning("[DNS] Resolution failed for $bare")
            emptyList()
        }

        if (ips.isNotEmpty()) {
            cache[key] = CacheEntry(ips, System.currentTimeMillis() + DEFAULT_TTL_MS)
        }

        return ips
    }

    /**
     * Drops any address inside the synthetic fake-IP range from a resolver
     * result. With no underlying network set, the platform fallback resolves
     * through the VPN's own DNS, which answers every A query with a fake IP
     * (198.18.x.x / fc00::x) — caching that would pin a real name (the proxy
     * server's own, say) to a synthetic address for the whole TTL and send
     * every later dial to a dead fake IP. Treating an all-fake result as a
     * failed resolution lets [resolveAll] keep the previous good entry instead.
     */
    private fun rejectFakeIps(ips: List<String>, bare: String): List<String> {
        if (ips.isEmpty()) return ips
        val real = ips.filterNot { FakeIpPool.isFakeIp(it) }
        if (real.size != ips.size) {
            logger.warning("[DNS] Discarded fake-IP answer(s) for $bare")
        }
        return real
    }

    /**
     * The encrypted-DNS answer for [bare], or an empty list when the feature is
     * off or the resolver did not answer.
     *
     * The resolver's own hostname is deliberately excluded: resolving it
     * through itself is the one lookup that cannot work, and it would recurse
     * back into this method. That name goes to the platform resolver on the
     * physical network, which is the bootstrap every encrypted resolver needs.
     */
    private fun resolveEncrypted(bare: String, network: UnderlyingNetwork?): List<String> {
        val upstream = EncryptedDnsPolicy.upstream
        if (upstream is DnsUpstream.System) return emptyList()
        if (upstream.bootstrapHost?.equals(bare, ignoreCase = true) == true) return emptyList()

        return try {
            DnsUpstreamClient.resolve(bare, upstream, network)
        } catch (e: Exception) {
            logger.warning("[DNS] Encrypted resolution failed for $bare: ${e.message ?: e}")
            emptyList()
        }
    }
}
