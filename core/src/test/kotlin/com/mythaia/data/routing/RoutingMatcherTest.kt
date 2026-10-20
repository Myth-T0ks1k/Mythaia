package com.mythaia.data.routing

import com.mythaia.data.routing.RoutingMatcher.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingMatcherTest {

    private val geosite = GeoFixtures.file(GeoFixtures.sites)
    private val geoip = GeoFixtures.file(GeoFixtures.ips)

    private fun compile(profile: RoutingProfile, country: ((ByteArray) -> String?)? = null) =
        RoutingMatcher.compile(profile, geosite, geoip, country)

    @Test
    fun `geosite categories in every form`() {
        val m = compile(RoutingProfile(name = "t", directSites = listOf("geosite:cn")))
        assertEquals(Action.DIRECT, m.matchDomain("baidu.com"))
        assertEquals(Action.DIRECT, m.matchDomain("map.baidu.com"))
        assertNull(m.matchDomain("notbaidu.com"))
        assertEquals(Action.DIRECT, m.matchDomain("www.qq.com"))
        // Full matches the name only.
        assertNull(m.matchDomain("img.www.qq.com"))
        // Plain is anywhere in the name.
        assertEquals(Action.DIRECT, m.matchDomain("world.taobao.example"))
        assertEquals(Action.DIRECT, m.matchDomain("cn-42.example.org"))
        assertNull(m.matchDomain("cn-x.example.org"))
        assertEquals(Action.DIRECT, m.matchDomain("BAIDU.COM."))
    }

    @Test
    fun `attributes narrow a category`() {
        val ads = compile(RoutingProfile(name = "t", blockSites = listOf("geosite:cn@ads")))
        assertEquals(Action.BLOCK, ads.matchDomain("ads-cn.com"))
        assertNull(ads.matchDomain("baidu.com"))
        val notAds = compile(RoutingProfile(name = "t", directSites = listOf("geosite:cn@!ads")))
        assertNull(notAds.matchDomain("ads-cn.com"))
        assertEquals(Action.DIRECT, notAds.matchDomain("baidu.com"))
    }

    @Test
    fun `Xray's written forms`() {
        val m = compile(
            RoutingProfile(
                name = "t",
                proxySites = listOf("domain:example.com", "full:exact.org", "keyword:tube", "regexp:^api[0-9]\\.", "ext:other.dat:x", "plain.net")
            )
        )
        assertEquals(Action.PROXY, m.matchDomain("a.b.example.com"))
        assertEquals(Action.PROXY, m.matchDomain("example.com"))
        assertNull(m.matchDomain("badexample.com"))
        assertEquals(Action.PROXY, m.matchDomain("exact.org"))
        assertNull(m.matchDomain("www.exact.org"))
        assertEquals(Action.PROXY, m.matchDomain("www.youtube.com"))
        assertEquals(Action.PROXY, m.matchDomain("api7.service.io"))
        // A bare name is a substring rule in Xray.
        assertEquals(Action.PROXY, m.matchDomain("cdn.plain.net.example"))
        assertTrue(m.warnings.any { it.contains("ext:other.dat") })
    }

    @Test
    fun `block beats direct beats proxy, and the default follows GlobalProxy`() {
        val m = compile(
            RoutingProfile(
                name = "China",
                globalProxy = true,
                directSites = listOf("geosite:cn"),
                proxySites = listOf("geosite:cn", "domain:google.com"),
                blockSites = listOf("domain:baidu.com")
            )
        )
        assertEquals(Action.BLOCK, m.matchDomain("baidu.com"))
        assertEquals(Action.DIRECT, m.matchDomain("www.qq.com"))
        assertEquals(Action.PROXY, m.matchDomain("google.com"))
        assertEquals(Action.PROXY, m.defaultAction)
        assertEquals(Action.DIRECT, compile(RoutingProfile(name = "d", globalProxy = false)).defaultAction)
    }

    @Test
    fun `geoip lists, CIDRs and single addresses`() {
        val m = compile(
            RoutingProfile(
                name = "t",
                directIp = listOf("geoip:cn", "geoip:private", "255.255.255.255"),
                proxyIp = listOf("geoip:telegram"),
                blockIp = listOf("203.0.113.0/24")
            )
        )
        assertEquals(Action.DIRECT, m.matchAddress("1.0.2.200"))
        assertEquals(Action.DIRECT, m.matchAddress("240e::1"))
        // The file's own private list, not the built-in one.
        assertEquals(Action.DIRECT, m.matchAddress("192.168.5.5"))
        assertNull(m.matchAddress("172.16.0.1"))
        assertEquals(Action.DIRECT, m.matchAddress("255.255.255.255"))
        assertEquals(Action.PROXY, m.matchAddress("91.108.5.1"))
        assertEquals(Action.PROXY, m.matchAddress("2001:67c:4e8::5"))
        assertEquals(Action.BLOCK, m.matchAddress("203.0.113.9"))
        assertNull(m.matchAddress("8.8.8.8"))
        assertNull(m.matchAddress("example.com"))
    }

    @Test
    fun `inverted lists match what is outside them`() {
        val m = compile(RoutingProfile(name = "t", proxyIp = listOf("geoip:!cn")))
        assertNull(m.matchAddress("1.0.1.1"))
        assertEquals(Action.PROXY, m.matchAddress("8.8.8.8"))
        // A list the file marks inverted is inverted already.
        val fileInverted = compile(RoutingProfile(name = "t", proxyIp = listOf("geoip:notcn")))
        assertNull(fileInverted.matchAddress("1.0.1.1"))
        assertEquals(Action.PROXY, fileInverted.matchAddress("8.8.8.8"))
    }

    @Test
    fun `countries the file lacks fall back to the country database`() {
        val noFile = RoutingMatcher.compile(
            RoutingProfile(name = "t", directIp = listOf("geoip:tm", "geoip:private", "geoip:telegram")),
            geosite = null, geoip = null,
            countryOf = { if (it.size == 4 && (it[0].toInt() and 0xFF) == 95) "TM" else null }
        )
        assertEquals(Action.DIRECT, noFile.matchAddress("95.85.1.1"))
        assertNull(noFile.matchAddress("8.8.8.8"))
        // geoip:private without a file is the built-in list.
        assertEquals(Action.DIRECT, noFile.matchAddress("172.16.0.1"))
        assertEquals(Action.DIRECT, noFile.matchAddress("fd00::1"))
        assertTrue(noFile.warnings.any { it.contains("telegram") })
    }

    @Test
    fun `names are resolved only when a strategy and address rules ask for it`() {
        assertTrue(compile(RoutingProfile(name = "t", directIp = listOf("geoip:ru"))).resolvesNames)
        assertFalse(compile(RoutingProfile(name = "t", directIp = listOf("geoip:ru"), domainStrategy = "AsIs")).resolvesNames)
        assertFalse(compile(RoutingProfile(name = "t", directSites = listOf("domain:ru"))).resolvesNames)
    }

    @Test
    fun `a missing geosite file leaves its rules empty and says so`() {
        val m = RoutingMatcher.compile(RoutingProfile(name = "t", directSites = listOf("geosite:cn", "domain:ok.com")), null, null)
        assertNull(m.matchDomain("baidu.com"))
        assertEquals(Action.DIRECT, m.matchDomain("ok.com"))
        assertTrue(m.warnings.isNotEmpty())
        val missing = compile(RoutingProfile(name = "t", directSites = listOf("geosite:nowhere")))
        assertTrue(missing.warnings.any { it.contains("geosite:nowhere") })
    }

    @Test
    fun `hosts are looked up by name`() {
        val m = compile(RoutingProfile(name = "t", dnsHosts = mapOf("dns.example" to "9.9.9.9")))
        assertEquals("9.9.9.9", m.hostAddress("DNS.example."))
        assertNull(m.hostAddress("other.example"))
    }
}
