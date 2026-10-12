package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig
import com.mythaia.vpn.protocol.wireguard.WireGuardCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Xray JSON the way panels and v2rayNG hand it out. */
class XrayJsonImporterTest {

    private val fullConfig = """
    {
      // exported by a panel
      "log": {"loglevel": "warning"},
      "inbounds": [{"port": 10808, "protocol": "socks"}],
      "outbounds": [
        {
          "tag": "proxy",
          "protocol": "vless",
          "settings": {"vnext": [{"address": "1.2.3.4", "port": 443,
            "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
          "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {"serverName": "www.microsoft.com", "fingerprint": "chrome",
              "publicKey": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", "shortId": "6ba85179e30d4fc2", "spiderX": "/"},
            "sockopt": {"dialerProxy": "fragment"}
          },
          "mux": {"enabled": false},
        },
        {
          "tag": "fragment",
          "protocol": "freedom",
          "settings": {"fragment": {"packets": "tlshello", "length": "10-20", "interval": "10-20"}}
        },
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"}
      ]
    }
    """

    @Test
    fun `a full config with comments and trailing commas imports its proxy outbound`() {
        val configs = XrayJsonImporter.parse(fullConfig)
        assertEquals(1, configs.size)
        val c = configs[0]
        assertEquals(OutboundProtocol.VLESS, c.outboundProtocol)
        assertEquals("proxy", c.name)
        assertEquals("1.2.3.4", c.serverAddress)
        assertEquals(443, c.serverPort.toInt())
        assertEquals("xtls-rprx-vision", c.flow)
        assertEquals("reality", c.security)
        assertEquals("www.microsoft.com", c.reality?.serverName)
        assertEquals(TlsFingerprint.CHROME_133, c.reality?.fingerprint)
        assertEquals(8, c.reality?.shortId?.size)
        assertEquals(false, c.muxEnabled)
        assertNull(c.chain)
    }

    @Test
    fun `fragment through a freedom dialerProxy lands on a tls server`() {
        val json = """
        {"outbounds":[
          {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"safari","alpn":["h2","http/1.1"],"allowInsecure":true},
             "wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"sockopt":{"dialerProxy":"frag"}}},
          {"tag":"frag","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"3","interval":"1"}}}
        ]}"""
        val c = XrayJsonImporter.parse(json).single()
        assertEquals("ws", c.transport)
        assertEquals("/ws", c.websocket?.path)
        assertEquals("cdn.example.com", c.websocket?.host)
        assertEquals("cdn.example.com", c.tls?.serverName)
        assertEquals(TlsFingerprint.SAFARI_26, c.tls?.fingerprint)
        assertEquals(listOf("h2", "http/1.1"), c.tls?.alpn)
        assertEquals(true, c.tls?.allowInsecure)
        val fragment = c.tls?.fragment
        assertNotNull(fragment)
        assertEquals(3..3, fragment!!.lengthRange)
        assertEquals(1..1, fragment.intervalRange)
    }

    @Test
    fun `dialerProxy to another proxy becomes a chain and the hop is not listed twice`() {
        val json = """
        {"outbounds":[
          {"tag":"exit","protocol":"trojan","settings":{"servers":[{"address":"exit.example.com","port":443,"password":"pw"}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"exit.example.com"},"sockopt":{"dialerProxy":"entry"}}},
          {"tag":"entry","protocol":"shadowsocks","settings":{"servers":[{"address":"entry.example.com","port":8388,"method":"aes-256-gcm","password":"secret"}]}}
        ]}"""
        val configs = XrayJsonImporter.parse(json)
        assertEquals(1, configs.size)
        val exit = configs[0]
        assertEquals(OutboundProtocol.TROJAN, exit.outboundProtocol)
        assertEquals("pw", exit.trojanPassword)
        val chain = exit.chain
        assertNotNull(chain)
        assertEquals(1, chain!!.size)
        assertEquals(OutboundProtocol.SHADOWSOCKS, chain[0].outboundProtocol)
        assertEquals("aes-256-gcm", chain[0].ssMethod)
        assertEquals("secret", chain[0].ssPassword)
    }

    @Test
    fun `vmess outbound over grpc and a bare array both import`() {
        val json = """
        [{"protocol":"vmess","tag":"vm","settings":{"vnext":[{"address":"5.6.7.8","port":2053,"users":[{"id":"11111111-2222-3333-4444-555555555555","alterId":0,"security":"aes-128-gcm"}]}]},
          "streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"g.example.com"},"grpcSettings":{"serviceName":"svc","multiMode":true}}},
         {"protocol":"socks","tag":"sk","settings":{"servers":[{"address":"9.9.9.9","port":1080,"users":[{"user":"u","pass":"p"}]}]}}]"""
        val configs = XrayJsonImporter.parse(json)
        assertEquals(2, configs.size)
        val vm = configs.first { it.outboundProtocol == OutboundProtocol.VMESS }
        assertEquals("vm", vm.name)
        assertEquals("aes-128-gcm", vm.vmessSecurity)
        assertEquals("g.example.com", vm.tls?.serverName)
        val sk = configs.first { it.outboundProtocol == OutboundProtocol.SOCKS5 }
        assertEquals("u", sk.socks5Username)
        assertEquals("p", sk.socks5Password)
        assertEquals(1080, sk.serverPort.toInt())
    }

    @Test
    fun `pinned certificates and a verify name map to pcs and vcn`() {
        val pin = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val json = """
        {"outbounds":[
          {"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"front.example.com",
             "pinnedPeerCertSha256":"$pin","verifyPeerCertByName":"real.example.com"}}},
          {"tag":"b","protocol":"vmess","settings":{"vnext":[{"address":"1.2.3.5","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"front.example.com",
             "pinnedPeerCertSha256":["$pin"]},"wsSettings":{"path":"/w"}}}
        ]}"""
        val (vless, vmess) = XrayJsonImporter.parse(json)
        assertEquals(listOf(pin), vless.tls?.pinnedCertSha256)
        assertEquals("real.example.com", vless.tls?.verifyName)
        assertEquals(listOf(pin), vmess.tls?.pinnedCertSha256)
    }

    @Test
    fun `a Hysteria2 outbound with servers, a password and bandwidth`() {
        val json = """
        {"protocol":"hysteria","tag":"hy","settings":{"version":2,"servers":[{"address":"hy.example.com","port":8443}],"password":"pw"},
         "streamSettings":{"network":"hysteria","security":"tls",
           "tlsSettings":{"serverName":"sni.example.com","alpn":["h3"],"allowInsecure":true,"fingerprint":"firefox"},
           "hysteriaSettings":{"version":2,"up":"50 mbps","down":200}}}"""
        val c = XrayJsonImporter.parse(json).single()
        assertEquals(OutboundProtocol.HYSTERIA2, c.outboundProtocol)
        assertEquals("hy", c.name)
        assertEquals("hy.example.com", c.serverAddress)
        assertEquals(8443, c.serverPort.toInt())
        assertEquals("pw", c.password)
        assertEquals("sni.example.com", c.tls?.serverName)
        assertEquals(listOf("h3"), c.tls?.alpn)
        assertEquals(true, c.tls?.allowInsecure)
        assertEquals(50, c.hysteriaUpMbps)
        assertEquals(200, c.hysteriaDownMbps)
        assertNull(c.obfuscation)
    }

    @Test
    fun `Hysteria v1 is refused rather than dialled as v2`() {
        val json = """{"protocol":"hysteria","settings":{"version":1,"address":"1.2.3.4","port":443},
            "streamSettings":{"hysteriaSettings":{"version":1,"auth":"x"}}}"""
        try {
            XrayJsonImporter.parse(json)
            fail("expected a refusal")
        } catch (e: ProxyError.InvalidUrl) {
            assertTrue(e.message!!.contains("version 1"))
        }
    }

    @Test
    fun `bandwidth reads Hysteria units and bare numbers as Mbps`() {
        assertEquals(100, XrayJsonImporter.bandwidthMbps("100 mbps"))
        assertEquals(100, XrayJsonImporter.bandwidthMbps("100Mbps"))
        assertEquals(1000, XrayJsonImporter.bandwidthMbps("1 gbps"))
        assertEquals(1, XrayJsonImporter.bandwidthMbps("500 kbps"))
        assertEquals(30, XrayJsonImporter.bandwidthMbps(30))
        assertEquals(30, XrayJsonImporter.bandwidthMbps("30"))
        assertNull(XrayJsonImporter.bandwidthMbps(0))
        assertNull(XrayJsonImporter.bandwidthMbps("fast"))
        assertNull(XrayJsonImporter.bandwidthMbps(null))
    }

    @Test
    fun `a WireGuard outbound becomes its INI, Reserved included`() {
        val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
        val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })
        val json = """
        {"outbounds":[{"protocol":"wireguard","tag":"warp",
          "settings":{"secretKey":"$privateKey","address":["172.16.0.2","2606:4700:110:8a36::2/128"],
            "peers":[{"publicKey":"$peerKey","endpoint":"engage.cloudflareclient.com:2408","keepAlive":25,
              "allowedIPs":["0.0.0.0/0","::/0"]}],
            "mtu":1280,"reserved":[78,135,76]}}]}"""
        val c = XrayJsonImporter.parse(json).single()
        assertEquals(OutboundProtocol.WIREGUARD, c.outboundProtocol)
        assertEquals("warp", c.name)
        assertEquals("engage.cloudflareclient.com", c.serverAddress)
        assertEquals(2408, c.serverPort.toInt())

        val ini = WireGuardConfig.parse(c.wireGuardConfig!!)
        assertArrayEquals(ByteArray(32) { it.toByte() }, ini.privateKey)
        assertArrayEquals(ByteArray(32) { (it * 7).toByte() }, ini.peer.publicKey)
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36::2/128"), ini.addresses)
        assertEquals(1280, ini.mtu)
        assertEquals(25, ini.peer.persistentKeepalive)
        assertArrayEquals(byteArrayOf(78, 135.toByte(), 76), ini.reserved)
    }

    @Test
    fun `an HTTPS proxy imports and a server name it cannot carry is refused`() {
        val ok = """{"protocol":"http","tag":"h","settings":{"servers":[{"address":"proxy.example.com","port":443,
            "users":[{"user":"u","pass":"p"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"proxy.example.com"}}}"""
        val c = XrayJsonImporter.parse(ok).single()
        assertEquals("proxy.example.com", c.serverAddress)
        assertEquals("u", c.naiveUsername)

        try {
            XrayJsonImporter.parse(ok.replace("\"serverName\":\"proxy.example.com\"", "\"serverName\":\"other.example.com\""))
            fail("expected a refusal")
        } catch (e: ProxyError.InvalidUrl) {
            assertTrue(e.message!!.contains("other.example.com"))
        }
    }

    @Test
    fun `a config with no proxy outbound is refused with a reason`() {
        try {
            XrayJsonImporter.parse("""{"outbounds":[{"protocol":"freedom"}]}""")
            fail("expected a refusal")
        } catch (e: ProxyError.InvalidUrl) {
            assertTrue(e.message!!.contains("No proxy outbound"))
        }
        assertTrue(XrayJsonImporter.looksLikeJson(fullConfig))
        assertTrue(!XrayJsonImporter.looksLikeJson("vless://x@y:1"))
    }
}
