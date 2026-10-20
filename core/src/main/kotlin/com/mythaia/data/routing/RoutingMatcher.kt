package com.mythaia.data.routing

import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.util.concurrent.ConcurrentHashMap

private val logger = MythaiaLogger("Routing")

/**
 * A [RoutingProfile] compiled for lookups, shared by the phone's tunnel and
 * the desktop router.
 *
 * Order of precedence, as Xray applies the rules Happ builds: a domain rule
 * beats an address rule, and within each kind block beats direct beats
 * proxy — Happ's own sample profile lists `geosite:cn` both as direct and as
 * proxy and means direct. A name no domain rule matches is tried against the
 * address rules once it is resolved (`IPIfNonMatch`), and what matches
 * nothing at all takes [defaultAction].
 *
 * `geoip:` codes are read from the profile's geoip file; a two-letter code
 * the file lacks (or every code, when the profile has no geoip file) falls
 * back to the imported MaxMind database through [countryOf], and
 * `geoip:private` to the built-in private ranges. Reading the file the
 * profile names, rather than mapping everything onto the MaxMind database,
 * keeps the lists a country database cannot express — `geoip:telegram`,
 * `geoip:cloudflare` — and keeps what the provider tested in Happ: the same
 * ranges, not another vendor's idea of the country.
 */
class RoutingMatcher private constructor(
    val profile: RoutingProfile,
    private val block: Rules,
    private val direct: Rules,
    private val proxy: Rules,
    /** What the profile could not use: missing categories, unsupported forms. */
    val warnings: List<String>
) {
    enum class Action { DIRECT, PROXY, BLOCK }

    /** What a destination that matches no rule gets. */
    val defaultAction: Action = if (profile.globalProxy) Action.PROXY else Action.DIRECT

    /** Whether a name no domain rule matches should be resolved and checked by address. */
    val resolvesNames: Boolean = profile.resolvesNames && !(block.ips.isEmpty && direct.ips.isEmpty && proxy.ips.isEmpty)

    private val domainCache = ConcurrentHashMap<String, Any>()

    /** The rule [domain] matches by name, or null when none does. */
    fun matchDomain(domain: String): Action? {
        val name = domain.trim().trimEnd('.').lowercase()
        if (name.isEmpty()) return null
        domainCache[name]?.let { return it as? Action }
        val action = when {
            block.domains.matches(name) -> Action.BLOCK
            direct.domains.matches(name) -> Action.DIRECT
            proxy.domains.matches(name) -> Action.PROXY
            else -> null
        }
        if (domainCache.size >= CACHE_SIZE) domainCache.clear()
        domainCache[name] = action ?: NO_MATCH
        return action
    }

    /** The rule [address] (4 or 16 bytes) matches, or null when none does. */
    fun matchAddress(address: ByteArray): Action? = when {
        block.ips.matches(address) -> Action.BLOCK
        direct.ips.matches(address) -> Action.DIRECT
        proxy.ips.matches(address) -> Action.PROXY
        else -> null
    }

    /** [matchAddress] for a literal; null for a name. */
    fun matchAddress(literal: String): Action? = IpRanges.parseAddress(literal)?.let { matchAddress(it) }

    /** The fixed address [domain] has in the profile's hosts, if any. */
    fun hostAddress(domain: String): String? = profile.dnsHosts[domain.trim().trimEnd('.').lowercase()]

    /** Counts for the profile screen: domains and ranges per action. */
    val summary: Summary
        get() = Summary(
            directDomains = direct.domains.size, directRanges = direct.ips.size,
            proxyDomains = proxy.domains.size, proxyRanges = proxy.ips.size,
            blockDomains = block.domains.size, blockRanges = block.ips.size
        )

    data class Summary(
        val directDomains: Int, val directRanges: Int,
        val proxyDomains: Int, val proxyRanges: Int,
        val blockDomains: Int, val blockRanges: Int
    )

    /** The name and address rules of one action. */
    private class Rules(val domains: DomainSet, val ips: IpSet)

    /** Names by suffix, exact name, substring and pattern. */
    class DomainSet internal constructor(
        private val suffixes: Set<String>,
        private val full: Set<String>,
        private val keywords: List<String>,
        private val patterns: List<Regex>
    ) {
        val size: Int get() = suffixes.size + full.size + keywords.size + patterns.size

        /** [name] is lower-case without a trailing dot. */
        fun matches(name: String): Boolean {
            if (name in full) return true
            if (suffixes.isNotEmpty()) {
                var at = 0
                while (true) {
                    if (suffixes.contains(if (at == 0) name else name.substring(at))) return true
                    val dot = name.indexOf('.', at)
                    if (dot < 0) break
                    at = dot + 1
                }
            }
            for (keyword in keywords) if (name.contains(keyword)) return true
            for (pattern in patterns) if (runCatching { pattern.containsMatchIn(name) }.getOrDefault(false)) return true
            return false
        }
    }

    /** Address ranges, countries looked up in the MaxMind database, and inverted lists. */
    class IpSet internal constructor(
        private val ranges: IpRanges,
        private val outside: List<IpRanges>,
        private val countries: Set<String>,
        private val outsideCountries: Set<String>,
        private val countryOf: ((ByteArray) -> String?)?
    ) {
        val isEmpty: Boolean get() = ranges.isEmpty && outside.isEmpty() && countries.isEmpty() && outsideCountries.isEmpty()
        val size: Int get() = ranges.size + outside.size + countries.size + outsideCountries.size

        fun matches(address: ByteArray): Boolean {
            if (ranges.contains(address)) return true
            for (list in outside) if (!list.contains(address)) return true
            if ((countries.isNotEmpty() || outsideCountries.isNotEmpty()) && countryOf != null) {
                val code = countryOf.invoke(address)?.uppercase()
                if (code != null && code in countries) return true
                if (outsideCountries.isNotEmpty() && (code == null || code !in outsideCountries)) return true
            }
            return false
        }
    }

    companion object {
        private const val CACHE_SIZE = 4096
        private val NO_MATCH = Any()
        private const val MAX_PATTERNS = 2000
        private const val MAX_PATTERN_LENGTH = 512

        /**
         * Compiles [profile] with its rule files. Either file may be absent:
         * the rules that need it then match nothing and say so in [warnings].
         *
         * @param countryOf the MaxMind country of an address, for `geoip:`
         *   codes the geoip file does not cover; null when there is none.
         */
        fun compile(
            profile: RoutingProfile,
            geosite: File?,
            geoip: File?,
            countryOf: ((ByteArray) -> String?)? = null
        ): RoutingMatcher {
            val warnings = ArrayList<String>()
            val siteCodes = profile.sites.mapNotNull { siteCode(it) }.toSet()
            val ipCodes = profile.ips.mapNotNull { ipCode(it)?.first }.toSet()

            val sites: Map<String, List<V2rayGeoFile.Domain>> =
                if (siteCodes.isEmpty()) emptyMap()
                else if (geosite == null || !geosite.isFile) {
                    warnings += "no geosite file for ${siteCodes.size} categories"
                    emptyMap()
                } else runCatching { geosite.inputStream().use { V2rayGeoFile.readSites(it, siteCodes) } }
                    .getOrElse {
                        warnings += "geosite file unreadable: ${it.message ?: it}"
                        logger.warning("[Routing] ${geosite.name}: ${it.message ?: it}")
                        emptyMap()
                    }
            val ips: Map<String, V2rayGeoFile.IpList> =
                if (ipCodes.isEmpty() || geoip == null || !geoip.isFile) emptyMap()
                else runCatching { geoip.inputStream().use { V2rayGeoFile.readIps(it, ipCodes) } }
                    .getOrElse {
                        warnings += "geoip file unreadable: ${it.message ?: it}"
                        logger.warning("[Routing] ${geoip.name}: ${it.message ?: it}")
                        emptyMap()
                    }

            fun domains(entries: List<String>): DomainSet {
                val suffixes = HashSet<String>()
                val full = HashSet<String>()
                val keywords = LinkedHashSet<String>()
                val patterns = ArrayList<Regex>()
                fun pattern(text: String) {
                    if (patterns.size >= MAX_PATTERNS || text.length > MAX_PATTERN_LENGTH) return
                    runCatching { Regex(text) }.getOrNull()?.let { patterns += it }
                        ?: warnings.add("bad pattern $text")
                }
                for (entry in entries) {
                    val e = entry.trim()
                    val lower = e.lowercase()
                    when {
                        lower.startsWith(RoutingProfile.GEOSITE) -> {
                            val spec = e.substring(RoutingProfile.GEOSITE.length)
                            val code = spec.substringBefore('@').trim().uppercase()
                            val attribute = spec.substringAfter('@', "").trim().lowercase()
                            val list = sites[code]
                            if (list == null) {
                                if (sites.isNotEmpty() || (geosite != null && geosite.isFile)) warnings += "geosite:${code.lowercase()} is not in the file"
                                continue
                            }
                            for (domain in list) {
                                if (attribute.isNotEmpty()) {
                                    val negated = attribute.startsWith('!')
                                    val has = attribute.removePrefix("!") in domain.attributes
                                    if (has == negated) continue
                                }
                                when (domain.type) {
                                    V2rayGeoFile.DomainType.PLAIN -> keywords += domain.value
                                    V2rayGeoFile.DomainType.REGEX -> pattern(domain.value)
                                    V2rayGeoFile.DomainType.ROOT_DOMAIN -> suffixes += domain.value.trimStart('.')
                                    V2rayGeoFile.DomainType.FULL -> full += domain.value
                                }
                            }
                        }
                        lower.startsWith("domain:") -> lower.substringAfter(':').trim().trimStart('.').trimEnd('.').takeIf { it.isNotEmpty() }?.let { suffixes += it }
                        lower.startsWith("full:") -> lower.substringAfter(':').trim().trimEnd('.').takeIf { it.isNotEmpty() }?.let { full += it }
                        lower.startsWith("keyword:") -> lower.substringAfter(':').trim().takeIf { it.isNotEmpty() }?.let { keywords += it }
                        lower.startsWith("regexp:") -> pattern(e.substringAfter(':'))
                        lower.startsWith("ext:") || lower.startsWith("dotless:") -> warnings += "unsupported rule $e"
                        lower.isNotEmpty() -> keywords += lower
                    }
                }
                return DomainSet(suffixes, full, keywords.toList(), patterns)
            }

            fun addresses(entries: List<String>): IpSet {
                val builder = IpRanges.Builder()
                val outside = ArrayList<IpRanges>()
                val countries = HashSet<String>()
                val outsideCountries = HashSet<String>()
                for (entry in entries) {
                    val parsed = ipCode(entry)
                    if (parsed == null) {
                        val cidr = IpRanges.parseCidr(entry)
                        if (cidr != null) builder.add(cidr.first, cidr.second)
                        else warnings += "unsupported address rule ${entry.trim()}"
                        continue
                    }
                    val (code, inverse) = parsed
                    val list = ips[code]
                    val ranges: IpRanges? = when {
                        list != null -> IpRanges.Builder().apply { list.cidrs.forEach { add(it.ip, it.prefix) } }.build()
                        code == "PRIVATE" -> IpRanges.PRIVATE
                        else -> null
                    }
                    // A list the file itself marks inverted flips once more.
                    val outsideList = inverse != (list?.inverse == true)
                    when {
                        ranges != null && outsideList -> outside += ranges
                        ranges != null -> builder.addAll(ranges)
                        code.length == 2 && code.all { it in 'A'..'Z' } && countryOf != null ->
                            if (inverse) outsideCountries += code else countries += code
                        else -> warnings += "geoip:${code.lowercase()} has no source"
                    }
                }
                return IpSet(builder.build(), outside, countries, outsideCountries, countryOf)
            }

            val matcher = RoutingMatcher(
                profile = profile,
                block = Rules(domains(profile.blockSites), addresses(profile.blockIp)),
                direct = Rules(domains(profile.directSites), addresses(profile.directIp)),
                proxy = Rules(domains(profile.proxySites), addresses(profile.proxyIp)),
                warnings = warnings.distinct()
            )
            if (matcher.warnings.isNotEmpty()) {
                logger.warning("[Routing] ${profile.name}: ${matcher.warnings.take(5).joinToString("; ")}")
            }
            return matcher
        }

        /** The category of a `geosite:` rule, upper-case; null for any other form. */
        private fun siteCode(entry: String): String? {
            val e = entry.trim()
            if (!e.startsWith(RoutingProfile.GEOSITE, ignoreCase = true)) return null
            return e.substring(RoutingProfile.GEOSITE.length).substringBefore('@').trim().uppercase().takeIf { it.isNotEmpty() }
        }

        /** The code of a `geoip:` rule, upper-case, and whether it is inverted (`geoip:!cn`). */
        private fun ipCode(entry: String): Pair<String, Boolean>? {
            val e = entry.trim()
            if (!e.startsWith(RoutingProfile.GEOIP, ignoreCase = true)) return null
            val spec = e.substring(RoutingProfile.GEOIP.length).trim()
            val inverse = spec.startsWith('!')
            val code = spec.removePrefix("!").trim().uppercase()
            return if (code.isEmpty()) null else code to inverse
        }
    }
}
