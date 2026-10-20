package com.mythaia.data.routing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class HappRoutingTest {

    /** The custom profile from Happ's routing documentation. */
    private val china = """
        {
            "Name": "China",
            "GlobalProxy": "true",
            "RemoteDNSType": "DoH",
            "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
            "RemoteDNSIP": "1.1.1.1",
            "DomesticDNSType": "DoU",
            "DomesticDNSDomain": "",
            "DomesticDNSIP": "8.8.8.8",
            "Geoipurl": "https://example.com/releases/latest/download/geoip.dat",
            "Geositeurl": "https://example.com/releases/latest/download/geosite.dat",
            "LastUpdated": "",
            "DnsHosts": { "cloudflare-dns.com": "1.1.1.1" },
            "DirectSites": ["geosite:cn", "geosite:geolocation-cn"],
            "DirectIp": ["geoip:cn", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"],
            "ProxySites": ["geosite:cn"],
            "ProxyIp": ["geoip:amazon"],
            "BlockSites": ["geosite:ads"],
            "BlockIp": ["geoip:ads"],
            "DomainStrategy": "IPIfNonMatch",
            "FakeDNS": "false"
        }
    """.trimIndent()

    @Test
    fun `reads the documented profile`() {
        val profile = HappRouting.parseJson(china)!!
        assertEquals("China", profile.name)
        assertTrue(profile.globalProxy)
        assertEquals(listOf("geosite:cn", "geosite:geolocation-cn"), profile.directSites)
        assertEquals(7, profile.directIp.size)
        assertEquals(listOf("geoip:amazon"), profile.proxyIp)
        assertEquals(RoutingProfile.STRATEGY_IP_IF_NON_MATCH, profile.domainStrategy)
        assertEquals(mapOf("cloudflare-dns.com" to "1.1.1.1"), profile.dnsHosts)
        assertEquals(RoutingProfile.Dns("DoU", null, "8.8.8.8"), profile.domesticDns)
        assertEquals("https://cloudflare-dns.com/dns-query", profile.remoteDns?.domain)
        assertNull(profile.lastUpdated)
        assertTrue(profile.needsGeosite)
        assertTrue(profile.needsGeoip)
        assertEquals(2, profile.geoFileUrls.size)
    }

    @Test
    fun `the default profile has no name and takes the one it is given`() {
        val profile = HappRouting.parseJson("""{"GlobalProxy":"false","DirectIp":["10.0.0.0/8"]}""", "My provider")!!
        assertEquals("My provider", profile.name)
        assertFalse(profile.globalProxy)
        assertFalse(profile.needsGeoip)
        assertTrue(profile.geoFileUrls.isEmpty())
        assertEquals(HappRouting.DEFAULT_NAME, HappRouting.parseJson("{}")!!.name)
    }

    @Test
    fun `flags as booleans, lists as strings, keys in any case`() {
        val profile = HappRouting.parseJson(
            """{"name":"x","globalproxy":false,"DIRECTSITES":"domain:a.com, full:b.com","LastUpdated":1730000000123,"Geoipurl":"http://plain.example/geoip.dat"}"""
        )!!
        assertFalse(profile.globalProxy)
        assertEquals(listOf("domain:a.com", "full:b.com"), profile.directSites)
        // Milliseconds become seconds.
        assertEquals(1730000000L, profile.lastUpdated)
        // A rule file over plain HTTP could be swapped on the way.
        assertNull(profile.geoipUrl)
    }

    @Test
    fun `links add, add and turn on, and turn off`() {
        val b64 = Base64.getEncoder().encodeToString(china.toByteArray())
        val add = HappRouting.parseLink("happ://routing/add/$b64") as HappRouting.Command.Add
        assertFalse(add.activate)
        assertEquals("China", add.profile.name)
        val onAdd = HappRouting.parseLink("HAPP://routing/onadd/$b64") as HappRouting.Command.Add
        assertTrue(onAdd.activate)
        assertEquals(HappRouting.Command.Off, HappRouting.parseLink("happ://routing/off"))
        assertNull(HappRouting.parseLink("happ://routing/delete/$b64"))
        assertNull(HappRouting.parseLink("happ://routing/add/bm90IGpzb24="))
        assertNull(HappRouting.parseLink("happ://add/https://example.com/sub"))
    }

    @Test
    fun `base64 in either alphabet, unpadded or percent-encoded`() {
        val json = """{"Name":"Ü?>>","DirectSites":["domain:ü.example"]}"""
        val urlSafe = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        assertEquals("Ü?>>", (HappRouting.parseLink("happ://routing/add/$urlSafe") as HappRouting.Command.Add).profile.name)
        val standard = Base64.getEncoder().encodeToString(json.toByteArray())
        val encoded = java.net.URLEncoder.encode(standard, "UTF-8")
        assertEquals("Ü?>>", (HappRouting.parseLink("happ://routing/onadd/$encoded") as HappRouting.Command.Add).profile.name)
    }

    @Test
    fun `a subscription value may be the link or the profile itself`() {
        val b64 = Base64.getEncoder().encodeToString(china.toByteArray())
        assertTrue((HappRouting.parseSubscriptionValue("happ://routing/add/$b64") as HappRouting.Command.Add).activate.not())
        assertTrue((HappRouting.parseSubscriptionValue(b64) as HappRouting.Command.Add).activate)
        assertTrue((HappRouting.parseSubscriptionValue(china) as HappRouting.Command.Add).activate)
        assertNull(HappRouting.parseSubscriptionValue("nonsense"))
    }

    @Test
    fun `a profile survives its own link`() {
        val profile = HappRouting.parseJson(china)!!.copy(lastUpdated = 1_700_000_000L)
        val back = (HappRouting.parseLink(HappRouting.toLink(profile, activate = true)) as HappRouting.Command.Add).profile
        assertEquals(profile, back)
    }
}
