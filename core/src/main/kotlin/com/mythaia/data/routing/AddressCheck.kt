package com.mythaia.data.routing

import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.DnsUpstream
import com.mythaia.vpn.util.DnsUpstreamClient
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.ConcurrentHashMap

private val logger = MythaiaLogger("Routing")

/**
 * `IPIfNonMatch` for a name no domain rule matched: resolve it and try the
 * profile's address rules on the answer.
 *
 * Only an encrypted resolver is asked — the profile's DoH (remote first,
 * then domestic), else the user's own encrypted DNS. A plain UDP answer
 * from a censored network is the one most likely to be forged, and a forged
 * private address would send the connection direct into the filter's hands.
 * With no encrypted resolver the check is off and names keep their domain
 * verdict, as `AsIs` would.
 *
 * Every failure falls back to "no verdict", which is the default route; and
 * after a few failures in a row the check rests for a while, so a blocked
 * resolver does not hold up every new name by its timeout.
 */
class AddressCheck(private val matcher: RoutingMatcher) {

    sealed class Verdict {
        data class Matched(val action: RoutingMatcher.Action) : Verdict()
        object NoMatch : Verdict()
    }

    private val upstream: DnsUpstream? = pickUpstream(matcher.profile)

    /** Whether names get checked at all. */
    val enabled: Boolean get() = matcher.resolvesNames && upstream != null

    private class Entry(val verdict: Verdict, val until: Long)
    private val verdicts = ConcurrentHashMap<String, Entry>()

    @Volatile private var failures = 0
    @Volatile private var restUntil = 0L

    /** The verdict already known for [domain], without resolving. */
    fun known(domain: String, now: Long = System.currentTimeMillis()): Verdict? {
        val entry = verdicts[key(domain)] ?: return null
        return if (entry.until > now) entry.verdict else null.also { verdicts.remove(key(domain)) }
    }

    /** Whether [domain] would be resolved now: checks on, no verdict yet, not resting. */
    fun wants(domain: String, now: Long = System.currentTimeMillis()): Boolean =
        enabled && now >= restUntil && known(domain, now) == null

    /**
     * Resolves [domain] and returns the address rule its first address
     * matches. Blocking; null when it could not be resolved.
     */
    fun check(domain: String, now: Long = System.currentTimeMillis()): Verdict? {
        known(domain, now)?.let { return it }
        val name = key(domain)
        val fixed = matcher.hostAddress(name)
        val addresses = if (fixed != null) listOf(fixed) else {
            val via = upstream ?: return null
            if (now < restUntil) return null
            DnsUpstreamClient.resolve(name, via, DnsCache.network, DnsUpstreamClient.Family.IPV4, TIMEOUT_MS)
        }
        if (addresses.isEmpty()) {
            if (fixed == null && ++failures >= FAILURES_BEFORE_REST) {
                restUntil = now + REST_MS
                failures = 0
                logger.warning("[Routing] ${upstream?.text} is not answering; names keep their domain route for ${REST_MS / 60_000} min")
            }
            return null
        }
        failures = 0
        val action = addresses.firstNotNullOfOrNull { matcher.matchAddress(it) }
        val verdict = if (action != null) Verdict.Matched(action) else Verdict.NoMatch
        if (verdicts.size >= MAX_VERDICTS) verdicts.clear()
        verdicts[name] = Entry(verdict, now + VERDICT_MS)
        return verdict
    }

    private fun key(domain: String) = domain.trim().trimEnd('.').lowercase()

    companion object {
        private const val TIMEOUT_MS = 2_500
        private const val FAILURES_BEFORE_REST = 3
        private const val REST_MS = 5 * 60 * 1000L
        private const val VERDICT_MS = 10 * 60 * 1000L
        private const val MAX_VERDICTS = 4096

        /** The profile's DoH, remote then domestic, else the user's encrypted DNS; null when none is encrypted. */
        internal fun pickUpstream(profile: RoutingProfile): DnsUpstream? {
            for (dns in listOfNotNull(profile.remoteDns, profile.domesticDns)) {
                if (!dns.type.equals("DoH", ignoreCase = true)) continue
                val url = dns.domain?.trim()?.takeIf { it.startsWith("https://", ignoreCase = true) } ?: continue
                return DnsUpstream.Doh(url)
            }
            return EncryptedDnsPolicy.upstream.takeIf { it is DnsUpstream.Doh || it is DnsUpstream.Dot }
        }
    }
}
