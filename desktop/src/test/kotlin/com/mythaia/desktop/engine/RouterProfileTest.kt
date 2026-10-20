package com.mythaia.desktop.engine

import com.mythaia.data.routing.RoutingProfile
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteTarget
import org.junit.Assert.assertEquals
import org.junit.Test

class RouterProfileTest {

    @Test
    fun `active routing profile routes block, direct, proxy, and default action`() {
        val profile = RoutingProfile(
            name = "Provider Profile",
            globalProxy = false,
            directSites = listOf("domain:direct.example.com"),
            directIp = listOf("192.0.2.0/24"),
            proxySites = listOf("domain:proxy.example.com"),
            proxyIp = listOf("198.51.100.0/24"),
            blockSites = listOf("domain:ads.example.com"),
            blockIp = listOf("203.0.113.0/24"),
            domainStrategy = RoutingProfile.STRATEGY_IP_IF_NON_MATCH
        )
        val settings = DesktopSettings(
            routeMode = "rule",
            bypassTurkmenistan = false,
            activeRoutingProfile = profile
        )
        val router = Router.from(emptyList(), settings)

        assertEquals(RouteTarget.BLOCK, router.decide("sub.ads.example.com"))
        assertEquals(RouteTarget.BLOCK, router.decide("203.0.113.42"))
        assertEquals(RouteTarget.DIRECT, router.decide("api.direct.example.com"))
        assertEquals(RouteTarget.DIRECT, router.decide("192.0.2.15"))
        assertEquals(RouteTarget.PROXY, router.decide("cdn.proxy.example.com"))
        assertEquals(RouteTarget.PROXY, router.decide("198.51.100.9"))
        assertEquals(RouteTarget.DIRECT, router.decide("other.example.com"))
    }

    @Test
    fun `globalProxy true routes unmatched domains and IPs through proxy`() {
        val profile = RoutingProfile(
            name = "AsIs Profile",
            globalProxy = true,
            domainStrategy = RoutingProfile.STRATEGY_AS_IS
        )
        val router = Router.from(
            emptyList(),
            DesktopSettings(routeMode = "rule", bypassTurkmenistan = false, activeRoutingProfile = profile)
        )
        assertEquals(RouteTarget.PROXY, router.decide("other.example.com"))
        assertEquals(RouteTarget.PROXY, router.decide("198.51.100.55"))
    }
}
