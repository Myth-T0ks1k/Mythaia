package com.mythaia.data.model

import com.mythaia.data.network.ClashProxyParser
import com.mythaia.data.network.SingBoxJsonImporter
import com.mythaia.data.network.XrayJsonImporter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI

/**
 * Hysteria2 port hopping as each format writes it. The URIs with a port list
 * in the authority are the ones the official client's own tests parse
 * (app/cmd/client_test.go, app/internal/url/url_test.go).
 */
class HysteriaPortHoppingTest {

    // MARK: - The port list

    @Test
    fun `port lists in every spelling read as the same normalised union`() {
        assertEquals("7000-10000,20000", PortUnion.parse("7000-10000,20000").toString())
        // sing-box server_ports ranges, mihomo's slash, spaces, a backwards range.
        assertEquals("2080-3000", PortUnion.parse("2080:3000").toString())
        assertEquals("443,8443", PortUnion.parse("443/8443").toString())
        assertEquals("443,8443", PortUnion.parse(" 8443 , 443 ").toString())
        assertEquals("1000-2000", PortUnion.parse("2000-1000").toString())
        // Overlapping and touching ranges merge, as the official Normalize does.
        assertEquals("100-300", PortUnion.parse("100-200,150-250,251-300").toString())
        assertEquals("443,7788-8899,10010", PortUnion.parse(listOf("10010", "7788:8899", "443")).toString())
    }

    @Test
    fun `lists that name no real port are refused`() {
        for (bad in listOf("", "0", "0-10", "70000", "1-2-3", "a-b", "443,", ",443", "44 3", "-5")) {
            assertNull(bad, PortUnion.parse(bad))
        }
    }

    @Test
    fun `ports are counted, indexed and picked from the whole union`() {
        val ports = PortUnion.parse("443,7788-7790,10010")!!
        assertEquals(5, ports.size)
        assertEquals(listOf(443, 7788, 7789, 7790, 10010), (0 until ports.size).map(ports::portAt))
        val seen = HashSet<Int>()
        val random = kotlin.random.Random(7)
        repeat(500) { seen.add(ports.random(random)) }
        assertEquals(setOf(443, 7788, 7789, 7790, 10010), seen)
        assertFalse(PortUnion.parse("443")!!.hops)
        assertTrue(PortUnion.parse("443-444")!!.hops)
    }

    @Test
    fun `hop intervals in seconds, Go durations and ranges`() {
        assertEquals(HopInterval(30), HopInterval.parse("30"))
        assertEquals(HopInterval(30), HopInterval.parse("30s"))
        assertEquals(HopInterval(90), HopInterval.parse("1m30s"))
        assertEquals(HopInterval(60), HopInterval.parse("1m"))
        assertEquals(HopInterval(10, 50), HopInterval.parse("10-50"))
        assertEquals(HopInterval(10, 50), HopInterval.parse("50-10"))
        // Under the official 5 s floor: raised to it rather than refused.
        assertEquals(HopInterval(5), HopInterval.parse("1"))
        assertEquals(HopInterval(5), HopInterval.parse("500ms"))
        assertEquals(HopInterval(5, 8), HopInterval.parse("2-8"))
        assertNull(HopInterval.parse("soon"))
        assertNull(HopInterval.parse(""))
        assertEquals("10-50", HopInterval(10, 50).toString())
    }

    // MARK: - Links

    @Test
    fun `the official authority list is read, its first port is the one shown`() {
        val c = ProxyConfiguration.fromUrl("hysteria2://saul@better.call:7000-10000,20000/")
        assertEquals("better.call", c.serverAddress)
        assertEquals(7000.toUShort(), c.serverPort)
        assertEquals("7000-10000,20000", c.hysteriaPorts)
        assertEquals("saul", c.password)
        assertEquals("better.call:7000-10000,20000", c.displayEndpoint)
        assertEquals(HopInterval.DEFAULT, c.hysteriaHop)

        val both = ProxyConfiguration.fromUrl("hysteria2://gawr:gura@atlantis.moe:443,7788-8899,10010/")
        assertEquals("atlantis.moe", both.serverAddress)
        assertEquals("gawr:gura", both.password)
        assertEquals("443,7788-8899,10010", both.hysteriaPorts)

        val list = ProxyConfiguration.fromUrl("hysteria2://darkness@laplus.org:8888,9999,11111/")
        assertEquals("8888,9999,11111", list.hysteriaPorts)

        val v6 = ProxyConfiguration.fromUrl("hy2://pw@[2001:db8::1]:20000-20010?insecure=1#v6")
        assertEquals("2001:db8::1", v6.serverAddress)
        assertEquals("20000-20010", v6.hysteriaPorts)
        assertEquals(20000.toUShort(), v6.serverPort)
    }

    @Test
    fun `mport, hop-interval and FinalMask's udpHop`() {
        val m = ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?mport=20000-30000&hop-interval=10-50#m")
        assertEquals(443.toUShort(), m.serverPort)
        assertEquals("20000-30000", m.hysteriaPorts)
        assertEquals(HopInterval(10, 50), m.hysteriaHop)

        val fm = """{"quicParams":{"udpHop":{"ports":"20000-50000","interval":"5-10"}}}"""
        val x = ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?fm=${enc(fm)}#x")
        assertEquals("20000-50000", x.hysteriaPorts)
        assertEquals(HopInterval(5, 10), x.hysteriaHop)

        val mask = """{"udp":[{"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","interval":30,"remotePorts":"4000-4010"}}]}"""
        val y = ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?fm=${enc(mask)}#y")
        assertEquals("4000-4010", y.hysteriaPorts)
        assertEquals(HopInterval(30), y.hysteriaHop)

        // A one-port "list" is no hopping; neither is a bad one.
        assertNull(ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?mport=443#n").hysteriaPorts)
        assertNull(ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?mport=oops#n").hysteriaPorts)
        // An interval without a list says nothing.
        assertNull(ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443?hop-interval=10#n").hysteriaHopInterval)
    }

    @Test
    fun `export puts one port in the authority and the list in mport, as v2rayN reads it`() {
        val c = ProxyConfiguration.fromUrl("hysteria2://saul@better.call:7000-10000,20000/?hop-interval=45#Hop")
        val link = c.toUrl()
        // A URI class (v2rayN's System.Uri, java.net.URI) must still read
        // the authority, so it holds one port, with the list beside it.
        val uri = URI(link)
        assertEquals("better.call", uri.host)
        assertEquals(7000, uri.port)
        val query = uri.rawQuery.split('&').associate { it.substringBefore('=') to java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8") }
        assertEquals("7000-10000,20000", query["mport"])
        assertEquals("45", query["hop-interval"])

        val again = ProxyConfiguration.fromUrl(link)
        assertEquals(c.hysteriaPorts, again.hysteriaPorts)
        assertEquals(c.hysteriaHop, again.hysteriaHop)
        assertEquals(c.serverPort, again.serverPort)

        // Without hopping the link is what it always was.
        assertFalse(ProxyConfiguration.fromUrl("hysteria2://pw@hy.example.com:443#n").toUrl().contains("mport"))
    }

    // MARK: - Importers

    @Test
    fun `sing-box server_ports, hop_interval and hop_interval_max`() {
        val json = """
        {"outbounds":[
          {"type":"hysteria2","tag":"hop","server":"hy.example.com","server_ports":["20000:30000","443"],
           "hop_interval":"15s","hop_interval_max":"1m","password":"pw","tls":{"enabled":true}},
          {"type":"hysteria2","tag":"plain","server":"hy.example.com","server_ports":["2080:3000"],"password":"pw",
           "tls":{"enabled":true}}
        ]}"""
        val byName = SingBoxJsonImporter.parse(json).associateBy { it.name }
        val hop = byName.getValue("hop")
        assertEquals("443,20000-30000", hop.hysteriaPorts)
        assertEquals(20000.toUShort(), hop.serverPort)
        assertEquals(HopInterval(15, 60), hop.hysteriaHop)
        val plain = byName.getValue("plain")
        assertEquals("2080-3000", plain.hysteriaPorts)
        assertEquals(2080.toUShort(), plain.serverPort)
        assertNull(plain.hysteriaHopInterval)
        assertEquals(HopInterval.DEFAULT, plain.hysteriaHop)
    }

    @Test
    fun `Clash ports and hop-interval, with or without a port of its own`() {
        // The YAML as the native parser hands it over: numbers stay numbers.
        val document = org.json.JSONObject(
            """
            {"proxies":[
              {"name":"hop","type":"hysteria2","server":"hy.example.com","port":443,"ports":"20000-30000",
               "hop-interval":20,"password":"pw","sni":"hy.example.com"},
              {"name":"mihomo","type":"hysteria2","server":"hy.example.com","ports":"443/8443/9000-9010",
               "password":"pw"}
            ]}"""
        )
        val parsed = ClashProxyParser.parseDocument(document).configurations.associateBy { it.name }
        val hop = parsed.getValue("hop")
        assertEquals(443.toUShort(), hop.serverPort)
        assertEquals("20000-30000", hop.hysteriaPorts)
        assertEquals(HopInterval(20), hop.hysteriaHop)
        val mihomo = parsed.getValue("mihomo")
        assertEquals(443.toUShort(), mihomo.serverPort)
        assertEquals("443,8443,9000-9010", mihomo.hysteriaPorts)
    }

    @Test
    fun `Xray finalmask quicParams udpHop`() {
        val json = """
        {"outbounds":[{"protocol":"hysteria","tag":"xh",
          "settings":{"version":2,"address":"hy.example.com","port":443},
          "streamSettings":{"network":"hysteria","security":"tls",
            "tlsSettings":{"serverName":"hy.example.com"},
            "hysteriaSettings":{"version":2,"auth":"pw"},
            "finalmask":{"quicParams":{"udpHop":{"ports":"20000-50000","interval":"10-20"}}}}}]}"""
        val c = XrayJsonImporter.parse(json).single()
        assertEquals(443.toUShort(), c.serverPort)
        assertEquals("20000-50000", c.hysteriaPorts)
        assertEquals(HopInterval(10, 20), c.hysteriaHop)
    }

    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8")
}
