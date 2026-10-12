package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.TlsFingerprint
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * A JSON subscription as a real panel serves it: an array of whole Xray
 * configs, one per server, each named by its `remarks`, two of them
 * balancers over several servers.
 *
 * The fixture is a trimmed copy of one provider's subscription with the
 * credentials, addresses and host names replaced; the shapes — singular and
 * plural FinalMask fields, the new Hysteria2 outbound, balancer tags,
 * observatory, mux with concurrency — are kept exactly as served.
 */
class XrayJsonSubscriptionTest {

    private val subscription = """
    [
      {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "inbounds": [
          {"tag": "socks", "port": 10808, "listen": "0.0.0.0", "protocol": "socks",
           "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": false},
           "settings": {"auth": "noauth", "udp": true, "allowTransparent": false}}
        ],
        "outbounds": [
          {"protocol": "vless", "tag": "proxy-1",
           "settings": {"vnext": [{"address": "203.0.113.11", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "xhttp", "security": "tls",
             "tlsSettings": {"serverName": "d111111abcdef8.cloudfront.net", "fingerprint": "safari"},
             "xhttpSettings": {"mode": "auto", "path": "/", "host": "d111111abcdef8.cloudfront.net",
               "extra": {"scMaxEachPostBytes": "500000", "scMinPostsIntervalMs": "60", "xPaddingBytes": "100-1000",
                 "xmux": {"maxConnections": 16, "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "300-600", "hKeepAlivePeriod": 15}}},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "maxSplit": "2", "length": "3", "delay": "1"}}]},
             "sockopt": {"tcpKeepAliveIdle": 15, "tcpKeepAliveInterval": 10, "tcpUserTimeout": 20000}}},
          {"protocol": "vless", "tag": "proxy-2",
           "settings": {"vnext": [{"address": "203.0.113.12", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "ws", "security": "tls",
             "tlsSettings": {"serverName": "d222222abcdef8.cloudfront.net", "fingerprint": "safari"},
             "wsSettings": {"path": "/", "host": "d222222abcdef8.cloudfront.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3-3"], "delays": ["1-1"], "maxSplit": "2-2"}}]}},
           "mux": {"enabled": true, "concurrency": 8, "xudpProxyUDP443": "reject"}},
          {"protocol": "vless", "tag": "proxy-3",
           "settings": {"vnext": [{"address": "203.0.113.13", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "xhttp", "security": "tls",
             "tlsSettings": {"serverName": "d333333abcdef8.cloudfront.net", "fingerprint": "safari"},
             "xhttpSettings": {"mode": "auto", "path": "/", "host": "d333333abcdef8.cloudfront.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "maxSplit": "2", "length": "3", "delay": "1"}}]}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "dns": {"servers": ["1.1.1.1"]},
        "observatory": {"subjectSelector": ["proxy-"], "probeUrl": "https://www.gstatic.com/generate_204",
          "probeInterval": "60s", "enableConcurrency": true},
        "routing": {"domainStrategy": "AsIs",
          "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "balancer-main"}],
          "balancers": [{"tag": "balancer-main", "selector": ["proxy-1", "proxy-2", "proxy-3"],
            "strategy": {"type": "leastPing"}, "fallbackTag": "BLOCK"}]},
        "remarks": "Авто-выбор VIP",
        "meta": {"serverDescription": ""}
      },
      {
        "log": {"loglevel": "warning"},
        "policy": {"levels": {"0": {"handshake": 4}}},
        "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
        "outbounds": [
          {"protocol": "hysteria", "tag": "proxy",
           "settings": {"version": 2, "address": "198.51.100.54", "port": 443},
           "streamSettings": {"network": "hysteria", "security": "tls",
             "tlsSettings": {"serverName": "hy.example.net"},
             "hysteriaSettings": {"version": 2, "auth": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
             "finalmask": {
               "udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}],
               "quicParams": {"congestion": "bbr", "bbrProfile": "standard", "keepAlivePeriod": 10, "maxIdleTimeout": 30,
                 "initStreamReceiveWindow": 8388608, "maxStreamReceiveWindow": 8388608,
                 "initConnectionReceiveWindow": 20971520, "maxConnectionReceiveWindow": 20971520,
                 "maxIncomingStreams": 1024}}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]},
        "remarks": "📴SOCIAL & VIDEO"
      },
      {
        "outbounds": [
          {"protocol": "vless", "tag": "proxy",
           "settings": {"vnext": [{"address": "203.0.113.20", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "ws", "security": "tls",
             "tlsSettings": {"serverName": "d444444abcdef8.cloudfront.net", "fingerprint": "safari"},
             "wsSettings": {"path": "/", "host": "d444444abcdef8.cloudfront.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3"], "delays": ["1"], "maxSplit": "2"}}]}},
           "mux": {"enabled": true, "concurrency": 8, "xudpProxyUDP443": "reject"}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "remarks": "🚀Edge - 4G+Wifi "
      },
      {
        "outbounds": [
          {"protocol": "vless", "tag": "proxy",
           "settings": {"vnext": [{"address": "192.0.2.30", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "grpc", "security": "tls",
             "tlsSettings": {"serverName": "la.example.org", "fingerprint": "edge"},
             "grpcSettings": {"idle_timeout": 60, "health_check_timeout": 20, "initial_windows_size": 35538,
               "serviceName": "fr.example.org", "authority": "la.example.org"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3"], "delays": ["1"], "maxSplit": "2"}}]}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "remarks": "🌩️🇳🇱Relay Upgraded"
      }
    ]
    """

    private val expectedNames = listOf(
        "Авто-выбор VIP · 1", "Авто-выбор VIP · 2", "Авто-выбор VIP · 3",
        "📴SOCIAL & VIDEO",
        "🚀Edge - 4G+Wifi",
        "🌩️🇳🇱Relay Upgraded"
    )

    @Test
    fun `servers are named by remarks, balancer members by their place`() {
        val configs = XrayJsonImporter.parse(subscription)
        assertEquals(expectedNames, configs.map { it.name })
    }

    @Test
    fun `FinalMask fragmentation survives in both spellings`() {
        val vless = XrayJsonImporter.parse(subscription).filter { it.outboundProtocol == OutboundProtocol.VLESS }
        assertEquals(5, vless.size)
        for (c in vless) {
            val fragment = c.tls?.fragment
            assertNotNull("${c.name} lost its fragment settings", fragment)
            assertEquals(listOf(3..3), fragment!!.lengthRanges)
            assertEquals(listOf(1..1), fragment.delayRanges)
            assertEquals(2, fragment.maxSplit)
        }
    }

    @Test
    fun `the new Hysteria2 outbound imports with Salamander from FinalMask`() {
        val hy = XrayJsonImporter.parse(subscription).single { it.outboundProtocol == OutboundProtocol.HYSTERIA2 }
        assertEquals("198.51.100.54", hy.serverAddress)
        assertEquals(443, hy.serverPort.toInt())
        assertEquals("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", hy.password)
        assertEquals("salamander", hy.obfuscation)
        assertEquals("obfs-secret", hy.obfuscationPassword)
        assertEquals("hy.example.net", hy.tls?.serverName)
        // No bandwidth was declared, so BBR stays in charge.
        assertEquals(null, hy.hysteriaUpMbps)
    }

    @Test
    fun `transports and fingerprints come through per server`() {
        val configs = XrayJsonImporter.parse(subscription).associateBy { it.name }
        val xhttp = configs.getValue("Авто-выбор VIP · 1")
        assertEquals("xhttp", xhttp.transport)
        assertEquals("d111111abcdef8.cloudfront.net", xhttp.xhttp?.host)
        assertEquals(TlsFingerprint.SAFARI_26, xhttp.tls?.fingerprint)

        val ws = configs.getValue("Авто-выбор VIP · 2")
        assertEquals("ws", ws.transport)
        assertEquals("d222222abcdef8.cloudfront.net", ws.websocket?.host)
        // mux enabled stays the default; only enabled:false turns it off.
        assertTrue(ws.muxEnabled)

        val grpc = configs.getValue("🌩️🇳🇱Relay Upgraded")
        assertEquals("grpc", grpc.transport)
        assertEquals("fr.example.org", grpc.grpc?.serviceName)
        assertEquals("la.example.org", grpc.grpc?.authority)
        assertEquals(TlsFingerprint.EDGE_85, grpc.tls?.fingerprint)
    }

    @Test
    fun `a subscription body gives the same servers, plain or base64`() {
        val plain = SubscriptionFetcher.parse(subscription.toByteArray()).configurations
        assertEquals(expectedNames, plain.map { it.name })
        val encoded = Base64.getEncoder().encode(subscription.toByteArray())
        assertEquals(expectedNames, SubscriptionFetcher.parse(encoded).configurations.map { it.name })
    }

    @Test
    fun `a single full config with remarks is named by them`() {
        val single = JSONArray(subscription).getJSONObject(2).toString()
        assertEquals(listOf("🚀Edge - 4G+Wifi"), XrayJsonImporter.parse(single).map { it.name })
    }

    // MARK: - The real file, when it is on this machine

    private val realFile = File("C:/gtmp/subs/sub.json")
    private val realLinks = File("C:/gtmp/subs/sub64.txt")

    @Test
    fun `the real JSON subscription imports every server without an error`() {
        assumeTrue("real subscription sample not present", realFile.isFile)
        val text = realFile.readText()

        // Counted independently of the importer: every vless/hysteria outbound.
        val root = JSONArray(text)
        var expected = 0
        for (i in 0 until root.length()) {
            val outbounds = root.getJSONObject(i).getJSONArray("outbounds")
            for (j in 0 until outbounds.length()) {
                if (outbounds.getJSONObject(j).optString("protocol") in setOf("vless", "hysteria")) expected++
            }
        }

        val configs = XrayJsonImporter.parse(text)
        assertEquals(expected, configs.size)
        assertTrue(configs.none { it.name == "proxy" || it.name.startsWith("proxy-") })
        assertEquals(configs.size, configs.map { it.name }.toSet().size)
        assertTrue(configs.filter { it.outboundProtocol == OutboundProtocol.VLESS }.all { it.tls?.fragment != null })
        val hy = configs.single { it.outboundProtocol == OutboundProtocol.HYSTERIA2 }
        assertEquals("salamander", hy.obfuscation)

        assertEquals(configs.map { it.name }, SubscriptionFetcher.parse(realFile.readBytes()).configurations.map { it.name })
    }

    @Test
    fun `the real JSON and the same provider's links agree server by server`() {
        assumeTrue("real subscription samples not present", realFile.isFile && realLinks.isFile)
        val fromJson = XrayJsonImporter.parse(realFile.readText())
        val fromLinks = SubscriptionFetcher.parse(realLinks.readBytes()).configurations

        for (link in fromLinks) {
            val json = fromJson.firstOrNull { it.name == link.name.trim() } ?: continue
            assertEquals(link.name, link.outboundProtocol, json.outboundProtocol)
            assertEquals(link.name, link.serverAddress, json.serverAddress)
            assertEquals(link.name, link.serverPort, json.serverPort)
            assertEquals(link.name, link.transport, json.transport)
            assertEquals(link.name, link.tls?.fragment?.lengthRanges, json.tls?.fragment?.lengthRanges)
            assertEquals(link.name, link.tls?.fragment?.maxSplit, json.tls?.fragment?.maxSplit)
            assertEquals(link.name, link.obfuscation, json.obfuscation)
            assertEquals(link.name, link.obfuscationPassword, json.obfuscationPassword)
        }
    }
}
