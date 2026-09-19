package com.mythaia.desktop.engine

import com.mythaia.data.model.DomainRule
import com.mythaia.data.model.DomainRuleType
import com.mythaia.data.rules.CountryBypassExtras
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.model.RouteTarget
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.GeoIpDatabase
import java.net.InetAddress

/**
 * Decides where one connection goes. Rule mode sends everything through the
 * proxy except what a rule, the private ranges or the country bypass send
 * direct; global mode ignores the user's rules but still keeps the private
 * ranges and the country bypass off the proxy, since those are addresses a
 * proxy cannot reach at all.
 */
class Router(
    private val rules: List<RouteRule>,
    private val global: Boolean,
    bypassCountries: List<String>
) {
    private val bypassExtras: List<DomainRule> = bypassCountries.flatMap { CountryBypassExtras.rulesFor(it) }

    private val suffixRules = rules.filter { it.type == DomainRuleType.DOMAIN_SUFFIX }
        .map { it.value.trim().trimStart('.').lowercase() to it.action }
    private val keywordRules = rules.filter { it.type == DomainRuleType.DOMAIN_KEYWORD }
        .map { it.value.trim().lowercase() to it.action }
    private val cidrRules = rules.filter { it.type == DomainRuleType.IP_CIDR || it.type == DomainRuleType.IP_CIDR6 }
        .mapNotNull { r -> Cidr.parse(r.value)?.let { it to r.action } }
    private val geoRules = rules.filter { it.type == DomainRuleType.GEOIP }
        .map { it.value.trim().uppercase() to it.action }

    private val bypassSuffixes = bypassExtras.filter { it.type == DomainRuleType.DOMAIN_SUFFIX }
        .map { it.value.trim().trimStart('.').lowercase() }
    private val bypassCidrs = bypassExtras.filter { it.type == DomainRuleType.IP_CIDR || it.type == DomainRuleType.IP_CIDR6 }
        .mapNotNull { Cidr.parse(it.value) }
    private val bypassGeo = bypassExtras.filter { it.type == DomainRuleType.GEOIP }.map { it.value.uppercase() }

    /** [host] is a domain name or an IP literal, as the client gave it. */
    fun decide(host: String): RouteTarget {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return RouteTarget.BLOCK
        return if (DnsCache.isIpAddress(h)) decideIp(h) else decideDomain(h)
    }

    private fun decideDomain(domain: String): RouteTarget {
        if (domain == "localhost" || domain.endsWith(".localhost") || domain.endsWith(".local") ||
            domain.endsWith(".lan") || domain.endsWith(".home.arpa")) return RouteTarget.DIRECT
        if (bypassSuffixes.any { domain == it || domain.endsWith(".$it") }) return RouteTarget.DIRECT
        if (!global) {
            for ((suffix, action) in suffixRules) {
                if (domain == suffix || domain.endsWith(".$suffix")) return action
            }
            for ((keyword, action) in keywordRules) {
                if (keyword.isNotEmpty() && domain.contains(keyword)) return action
            }
        }
        return RouteTarget.PROXY
    }

    private fun decideIp(ip: String): RouteTarget {
        val address = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return RouteTarget.PROXY
        if (address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress ||
            address.isAnyLocalAddress || address.isMulticastAddress) return RouteTarget.DIRECT
        val bytes = address.address
        // 100.64.0.0/10 (carrier NAT) and fc00::/7 (ULA) are private too.
        if (bytes.size == 4 && (bytes[0].toInt() and 0xFF) == 100 && (bytes[1].toInt() and 0xC0) == 64) return RouteTarget.DIRECT
        if (bytes.size == 16 && (bytes[0].toInt() and 0xFE) == 0xFC) return RouteTarget.DIRECT

        if (bypassCidrs.any { it.contains(bytes) }) return RouteTarget.DIRECT
        if (bypassGeo.isNotEmpty() && GeoIpDatabase.isLoaded) {
            val code = GeoIpDatabase.countryCode(ip)
            if (code != null && code.uppercase() in bypassGeo) return RouteTarget.DIRECT
        }
        if (!global) {
            for ((cidr, action) in cidrRules) if (cidr.contains(bytes)) return action
            if (geoRules.isNotEmpty() && GeoIpDatabase.isLoaded) {
                val code = GeoIpDatabase.countryCode(ip)?.uppercase()
                if (code != null) geoRules.firstOrNull { it.first == code }?.let { return it.second }
            }
        }
        return RouteTarget.PROXY
    }

    /** One network in CIDR notation, v4 or v6. */
    class Cidr private constructor(private val network: ByteArray, private val prefix: Int) {
        fun contains(address: ByteArray): Boolean {
            if (address.size != network.size) return false
            var bits = prefix
            for (i in network.indices) {
                if (bits <= 0) return true
                val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
                if ((address[i].toInt() and mask) != (network[i].toInt() and mask)) return false
                bits -= 8
            }
            return true
        }

        companion object {
            fun parse(text: String): Cidr? {
                val parts = text.trim().split("/")
                val address = runCatching { InetAddress.getByName(parts[0].trim()) }.getOrNull() ?: return null
                if (!DnsCache.isIpAddress(parts[0].trim())) return null
                val bytes = address.address
                val prefix = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: (bytes.size * 8)
                if (prefix < 0 || prefix > bytes.size * 8) return null
                return Cidr(bytes, prefix)
            }
        }
    }
}
