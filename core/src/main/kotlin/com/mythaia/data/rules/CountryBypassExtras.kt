package com.mythaia.data.rules

import com.mythaia.data.model.DomainRule
import com.mythaia.data.model.DomainRuleType

/**
 * Rules added on top of the bundled country lists.
 *
 * The database ships the operators' IPv4 prefixes and the country TLD; this
 * is where the rest lives — an IPv6 allocation the list predates, a
 * `geoip:` catch-all so an address the list does not enumerate still goes
 * direct once a GeoIP database is imported, and a country's home-grown
 * services that sit on ranges nobody would guess.
 */
object CountryBypassExtras {

    fun rulesFor(countryCode: String): List<DomainRule> = when (countryCode.uppercase()) {
        "TM" -> TURKMENISTAN
        else -> emptyList()
    }

    /**
     * Turkmenistan: Turkmentelecom (AS20661) and the Ashgabat city network
     * (AS51495, AS205471), Altyn Asyr (AS59974), Turkmen hemrasi (AS204579)
     * and Tehno Merkez (AS215487). The `Link` messenger answers from
     * 177.93.143.0/24, Turkmentelecom's one block outside the RIPE space.
     */
    private val TURKMENISTAN: List<DomainRule> = listOf(
        DomainRule(DomainRuleType.GEOIP, "TM"),
        DomainRule(DomainRuleType.DOMAIN_SUFFIX, "tm"),
        DomainRule(DomainRuleType.IP_CIDR, "177.93.143.0/24"),
        DomainRule(DomainRuleType.IP_CIDR, "95.85.96.0/19"),
        DomainRule(DomainRuleType.IP_CIDR, "103.220.0.0/22"),
        DomainRule(DomainRuleType.IP_CIDR, "119.235.112.0/20"),
        DomainRule(DomainRuleType.IP_CIDR, "216.250.8.0/21"),
        DomainRule(DomainRuleType.IP_CIDR, "217.174.224.0/20"),
        DomainRule(DomainRuleType.IP_CIDR, "93.171.220.0/22"),
        DomainRule(DomainRuleType.IP_CIDR, "185.69.184.0/22"),
        DomainRule(DomainRuleType.IP_CIDR, "185.246.72.0/22"),
        DomainRule(DomainRuleType.IP_CIDR, "77.83.59.0/24"),
        DomainRule(DomainRuleType.IP_CIDR, "217.65.78.0/24"),
        DomainRule(DomainRuleType.IP_CIDR6, "2a05:2180::/29")
    )
}
