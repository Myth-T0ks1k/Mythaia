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
 * direct; global mode sends everything through the proxy, the home country
 * included, and keeps only the private ranges off it, since those are
 * addresses a proxy cannot reach at all.
 */
class Router(
    private val rules: List<RouteRule>,
    private val global: Boolean,
    bypassCountries: List<String>
) {
    /** The country bypass applies in rule mode only, as on Android. */
    private val bypassExtras: List<DomainRule> =
        if (global) emptyList() else bypassCountries.flatMap { CountryBypassExtras.rulesFor(it) }

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

    companion object {
        /**
         * Whether [host], taken literally, is this machine: loopback,
         * link-local or the unspecified address, or `localhost` and the
         * names under it. The private ranges are deliberately not here —
         * a LAN client may reach the LAN through the proxy, just not the
         * proxy's own host.
         */
        fun isThisHostLiteral(host: String): Boolean {
            val h = host.trim().trimEnd('.').lowercase().removePrefix("[").removeSuffix("]")
            if (h == "localhost" || h.endsWith(".localhost")) return true
            // DnsCache does not count an IPv4-mapped form (::ffff:127.0.0.1) as an
            // address, since Java parses it to an Inet4Address; it is one here. A
            // colon-bearing string is never looked up by InetAddress, only parsed.
            if (!DnsCache.isIpAddress(h) && !mappedV6.matches(h)) return false
            val address = runCatching { InetAddress.getByName(h) }.getOrNull() ?: return false
            return address.isLoopbackAddress || address.isLinkLocalAddress || address.isAnyLocalAddress
        }

        private val mappedV6 = Regex("""[0-9a-f:][0-9a-f:.]*:[0-9a-f:.]*""")
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
                // Literal check first: getByName would resolve a host name.
                if (!DnsCache.isIpAddress(parts[0].trim())) return null
                val address = runCatching { InetAddress.getByName(parts[0].trim()) }.getOrNull() ?: return null
                val bytes = address.address
                val prefix = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: (bytes.size * 8)
                if (prefix < 0 || prefix > bytes.size * 8) return null
                return Cidr(bytes, prefix)
            }
        }
    }
}
