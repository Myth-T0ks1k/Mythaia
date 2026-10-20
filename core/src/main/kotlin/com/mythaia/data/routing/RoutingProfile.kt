package com.mythaia.data.routing

import kotlinx.serialization.Serializable

/**
 * A routing profile as Happ defines one: which sites and addresses go
 * direct, through the proxy, or nowhere, and what everything else does.
 *
 * Sites take Xray's forms — `geosite:category[@attribute]`, `domain:`,
 * `full:`, `keyword:`, `regexp:`, and a bare name, which Xray matches
 * anywhere in the host. Addresses take `geoip:code` (`geoip:!code` for every
 * address outside it), CIDRs and single addresses.
 *
 * See https://www.happ.su/main/dev-docs/routing.
 */
@Serializable
data class RoutingProfile(
    val name: String,
    /** True: what no rule names goes through the proxy. False: it goes direct. */
    val globalProxy: Boolean = true,
    val directSites: List<String> = emptyList(),
    val directIp: List<String> = emptyList(),
    val proxySites: List<String> = emptyList(),
    val proxyIp: List<String> = emptyList(),
    val blockSites: List<String> = emptyList(),
    val blockIp: List<String> = emptyList(),
    /** `AsIs`, `IPIfNonMatch` or `IPOnDemand`, as Xray spells them. */
    val domainStrategy: String = STRATEGY_IP_IF_NON_MATCH,
    /** Names answered with a fixed address. */
    val dnsHosts: Map<String, String> = emptyMap(),
    val fakeDns: Boolean = false,
    val remoteDns: Dns? = null,
    val domesticDns: Dns? = null,
    val geoipUrl: String? = null,
    val geositeUrl: String? = null,
    /**
     * Happ's `LastUpdated`, in Unix seconds: the profile or its files changed
     * then, so files fetched before it are fetched again.
     */
    val lastUpdated: Long? = null,
    /** Rule precedence (`block-direct-proxy`, `block-proxy-direct`, etc.). */
    val routeOrder: String = ORDER_BLOCK_DIRECT_PROXY
) {
    /** One of the profile's resolvers. [type] is `DoH` or `DoU`. */
    @Serializable
    data class Dns(val type: String, val domain: String? = null, val ip: String? = null)

    val sites: List<String> get() = blockSites + directSites + proxySites
    val ips: List<String> get() = blockIp + directIp + proxyIp

    /** Whether some rule names a geosite category, so the profile needs [geositeUrl]'s file. */
    val needsGeosite: Boolean get() = sites.any { it.trim().startsWith(GEOSITE, ignoreCase = true) }

    /** Whether some rule names a geoip list, so the profile wants [geoipUrl]'s file. */
    val needsGeoip: Boolean get() = ips.any { it.trim().startsWith(GEOIP, ignoreCase = true) }

    /** The files this profile reads, by URL; those it names but has no URL for are left out. */
    val geoFileUrls: List<String>
        get() = listOfNotNull(geositeUrl.takeIf { needsGeosite }, geoipUrl.takeIf { needsGeoip })

    /** Whether names nothing matched are resolved and tried against the address rules. */
    val resolvesNames: Boolean
        get() = !domainStrategy.equals(STRATEGY_AS_IS, ignoreCase = true) && ips.isNotEmpty()

    companion object {
        const val STRATEGY_AS_IS = "AsIs"
        const val STRATEGY_IP_IF_NON_MATCH = "IPIfNonMatch"
        const val STRATEGY_IP_ON_DEMAND = "IPOnDemand"
        const val ORDER_BLOCK_DIRECT_PROXY = "block-direct-proxy"
        const val GEOSITE = "geosite:"
        const val GEOIP = "geoip:"
    }
}
