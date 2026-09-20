package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsFingerprint
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
