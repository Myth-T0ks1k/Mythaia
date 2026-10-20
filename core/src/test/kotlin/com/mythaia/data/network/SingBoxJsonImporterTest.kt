package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig
import com.mythaia.vpn.protocol.wireguard.WireGuardCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** sing-box JSON the way Hiddify and sing-box subscriptions hand it out. */
class SingBoxJsonImporterTest {

    private val uuid = "11111111-2222-3333-4444-555555555555"
    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    /** A Hiddify-style generated config: tun + mixed inbounds, selector/urltest, every proxy kind, endpoints. */
    private val config = """
    {
      "log": {"level": "warn", "timestamp": true},
      "dns": {
        "servers": [
          {"tag": "dns-remote", "address": "udp://1.1.1.1", "address_resolver": "dns-direct"},
          {"tag": "dns-direct", "address": "8.8.8.8", "detour": "direct"}
        ],
        "rules": [{"domain_suffix": [".ir"], "server": "dns-direct"}],
        "final": "dns-remote"
      },
      "inbounds": [
        {"type": "tun", "tag": "tun-in", "mtu": 9000, "address": ["172.19.0.1/28"], "auto_route": true,
         "strict_route": true, "stack": "mixed"},
        {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 12334}
      ],
      "outbounds": [
        {"type": "selector", "tag": "select",
         "outbounds": ["auto", "🇩🇪 vless-reality", "vless-ws", "vmess-grpc"], "default": "auto"},
        {"type": "urltest", "tag": "auto", "outbounds": ["🇩🇪 vless-reality", "vless-ws"],
         "url": "https://www.gstatic.com/generate_204", "interval": "10m0s", "tolerance": 1},
        {"type": "vless", "tag": "🇩🇪 vless-reality", "server": "203.0.113.1", "server_port": 443,
         "uuid": "$uuid", "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
         "tls": {"enabled": true, "server_name": "www.microsoft.com",
           "utls": {"enabled": true, "fingerprint": "chrome"},
           "reality": {"enabled": true, "public_key": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", "short_id": "6ba85179e30d4fc2"}}},
        {"type": "vless", "tag": "vless-ws", "server": "cdn.example.com", "server_port": 443, "uuid": "$uuid",
         "tls": {"enabled": true, "server_name": "cdn.example.com", "insecure": false, "alpn": ["http/1.1"],
           "utls": {"enabled": true, "fingerprint": "firefox"}},
         "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"},
           "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"},
         "tls_fragment": {"enabled": true, "size": "10-30", "sleep": "2-8"}},
        {"type": "vmess", "tag": "vmess-grpc", "server": "203.0.113.3", "server_port": 2053, "uuid": "$uuid",
         "security": "aes-128-gcm", "alter_id": 0,
         "tls": {"enabled": true, "server_name": "g.example.com"},
         "transport": {"type": "grpc", "service_name": "svc"}},
        {"type": "trojan", "tag": "trojan-hu", "server": "203.0.113.4", "server_port": 443, "password": "trojan-pw",
         "tls": {"enabled": true, "server_name": "t.example.com"},
         "transport": {"type": "httpupgrade", "host": "t.example.com", "path": "/up"}},
        {"type": "shadowsocks", "tag": "ss-2022", "server": "203.0.113.5", "server_port": 8388,
         "method": "2022-blake3-aes-128-gcm", "password": "AAECAwQFBgcICQoLDA0ODw=="},
        {"type": "hysteria2", "tag": "hy2", "server": "203.0.113.6", "server_port": 443,
         "up_mbps": 50, "down_mbps": 100, "password": "hy-pw",
         "obfs": {"type": "salamander", "password": "obfs-pw"},
         "tls": {"enabled": true, "server_name": "hy.example.com", "insecure": true, "alpn": ["h3"]}},
        {"type": "tuic", "tag": "tuic", "server": "203.0.113.7", "server_port": 443, "uuid": "$uuid",
         "password": "tuic-pw", "congestion_control": "bbr", "udp_relay_mode": "native",
         "tls": {"enabled": true, "server_name": "tuic.example.com", "alpn": ["h3"]}},
        {"type": "anytls", "tag": "anytls", "server": "203.0.113.8", "server_port": 443, "password": "any-pw",
         "tls": {"enabled": true, "server_name": "any.example.com", "utls": {"enabled": true, "fingerprint": "safari"}}},
        {"type": "socks", "tag": "socks", "server": "203.0.113.9", "server_port": 1080, "version": "5",
         "username": "u", "password": "p"},
        {"type": "http", "tag": "https-proxy", "server": "proxy.example.com", "server_port": 443,
         "username": "hu", "password": "hp", "tls": {"enabled": true, "server_name": "proxy.example.com"}},
        {"type": "http", "tag": "plain-http", "server": "203.0.113.10", "server_port": 8080},
        {"type": "wireguard", "tag": "warp-legacy", "server": "engage.cloudflareclient.com", "server_port": 2408,
         "local_address": ["172.16.0.2/32", "2606:4700:110:8a36::2/128"],
         "private_key": "$privateKey", "peer_public_key": "$peerKey", "reserved": [1, 2, 3], "mtu": 1280},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"}
      ],
      "endpoints": [
        {"type": "wireguard", "tag": "warp-endpoint", "system": false, "mtu": 1408,
         "address": ["172.16.0.2/32"], "private_key": "$privateKey",
         "peers": [{"address": "162.159.192.1", "port": 2408, "public_key": "$peerKey",
           "allowed_ips": ["0.0.0.0/0", "::/0"], "reserved": "AQID", "persistent_keepalive_interval": 30}]}
      ],
      "route": {
        "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"ip_is_private": true, "outbound": "direct"}],
        "final": "select", "auto_detect_interface": true
      }
    }
    """

    private val expectedNames = listOf(
        "🇩🇪 vless-reality", "vless-ws", "vmess-grpc", "trojan-hu", "ss-2022", "hy2", "tuic",
        "anytls", "socks", "https-proxy", "warp-legacy", "warp-endpoint"
    )

    private val byName by lazy { SingBoxJsonImporter.parse(config).associateBy { it.name } }

    @Test
    fun `sing-box is told apart from Xray by its outbounds, not by route rules`() {
        assertTrue(SingBoxJsonImporter.looksLikeSingBox(config))
        assertFalse(SingBoxJsonImporter.looksLikeSingBox(
            """{"outbounds":[{"protocol":"vless","tag":"x"}],"routing":{"rules":[{"type":"field"}]}}"""
        ))
        assertFalse(SingBoxJsonImporter.looksLikeSingBox("vless://x@y:1"))
        assertTrue(XrayJsonImporter.looksLikeJson(config))
    }

    @Test
    fun `every proxy imports under its tag and the routing outbounds are skipped`() {
        assertEquals(expectedNames, SingBoxJsonImporter.parse(config).map { it.name })
    }

    @Test
    fun `the subscription path and the Xray entry point both read sing-box`() {
        assertEquals(expectedNames, SubscriptionFetcher.parse(config.toByteArray()).configurations.map { it.name })
        assertEquals(expectedNames, XrayJsonImporter.parse(config).map { it.name })
    }

    @Test
    fun `vless with Reality and Vision`() {
        val c = byName.getValue("🇩🇪 vless-reality")
        assertEquals(OutboundProtocol.VLESS, c.outboundProtocol)
        assertEquals("203.0.113.1", c.serverAddress)
        assertEquals("xtls-rprx-vision", c.flow)
        assertEquals("reality", c.security)
        assertEquals("www.microsoft.com", c.reality?.serverName)
        assertEquals(32, c.reality?.publicKey?.size)
        assertEquals(8, c.reality?.shortId?.size)
        assertEquals(TlsFingerprint.CHROME_133, c.reality?.fingerprint)
    }

    @Test
    fun `vless over WebSocket with early data, uTLS and Hiddify's fragment`() {
        val c = byName.getValue("vless-ws")
        assertEquals("ws", c.transport)
        assertEquals("/ws", c.websocket?.path)
        assertEquals("cdn.example.com", c.websocket?.host)
        assertEquals(2048, c.websocket?.maxEarlyData)
        assertEquals("tls", c.security)
        assertEquals(listOf("http/1.1"), c.tls?.alpn)
        assertEquals(TlsFingerprint.FIREFOX_148, c.tls?.fingerprint)
        val fragment = c.tls?.fragment
        assertNotNull(fragment)
        assertEquals(10..30, fragment!!.lengthRange)
        assertEquals(2..8, fragment.intervalRange)
    }

    @Test
    fun `vmess over gRPC and trojan over HTTPUpgrade`() {
        val vm = byName.getValue("vmess-grpc")
        assertEquals(OutboundProtocol.VMESS, vm.outboundProtocol)
        assertEquals("aes-128-gcm", vm.vmessSecurity)
        assertEquals("grpc", vm.transport)
        assertEquals("svc", vm.grpc?.serviceName)
        assertEquals("g.example.com", vm.tls?.serverName)
        assertEquals(2053, vm.serverPort.toInt())

        val tj = byName.getValue("trojan-hu")
        assertEquals(OutboundProtocol.TROJAN, tj.outboundProtocol)
        assertEquals("trojan-pw", tj.trojanPassword)
        assertEquals("httpupgrade", tj.transport)
        assertEquals("t.example.com", tj.httpUpgrade?.host)
        assertEquals("/up", tj.httpUpgrade?.path)
    }

    @Test
    fun `shadowsocks, socks and an HTTPS proxy`() {
        val ss = byName.getValue("ss-2022")
        assertEquals("2022-blake3-aes-128-gcm", ss.ssMethod)
        assertEquals("AAECAwQFBgcICQoLDA0ODw==", ss.ssPassword)

        val socks = byName.getValue("socks")
        assertEquals(OutboundProtocol.SOCKS5, socks.outboundProtocol)
        assertEquals("u", socks.socks5Username)
        assertEquals("p", socks.socks5Password)

        val https = byName.getValue("https-proxy")
        assertEquals(OutboundProtocol.NAIVE_HTTP11, https.outboundProtocol)
        assertEquals("hu", https.naiveUsername)
        assertEquals("hp", https.naivePassword)
    }

    @Test
    fun `hysteria2, tuic and anytls`() {
        val hy = byName.getValue("hy2")
        assertEquals(OutboundProtocol.HYSTERIA2, hy.outboundProtocol)
        assertEquals("hy-pw", hy.password)
        assertEquals("salamander", hy.obfuscation)
        assertEquals("obfs-pw", hy.obfuscationPassword)
        assertEquals(50, hy.hysteriaUpMbps)
        assertEquals(100, hy.hysteriaDownMbps)
        assertEquals("hy.example.com", hy.tls?.serverName)
        assertEquals(true, hy.tls?.allowInsecure)
        assertEquals(listOf("h3"), hy.tls?.alpn)

        val tuic = byName.getValue("tuic")
        assertEquals(OutboundProtocol.TUIC, tuic.outboundProtocol)
        assertEquals(uuid, tuic.uuid.toString())
        assertEquals("tuic-pw", tuic.password)
        assertEquals("tuic.example.com", tuic.tls?.serverName)

        val any = byName.getValue("anytls")
        assertEquals(OutboundProtocol.ANYTLS, any.outboundProtocol)
        assertEquals("any-pw", any.password)
        assertEquals(TlsFingerprint.SAFARI_26, any.tls?.fingerprint)
    }

    @Test
    fun `WireGuard as a legacy outbound and as an endpoint, Reserved in both`() {
        val legacy = byName.getValue("warp-legacy")
        assertEquals(OutboundProtocol.WIREGUARD, legacy.outboundProtocol)
        assertEquals("engage.cloudflareclient.com", legacy.serverAddress)
        val legacyIni = WireGuardConfig.parse(legacy.wireGuardConfig!!)
        assertArrayEquals(byteArrayOf(1, 2, 3), legacyIni.reserved)
        assertEquals(1280, legacyIni.mtu)
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36::2/128"), legacyIni.addresses)
        assertArrayEquals(ByteArray(32) { (it * 7).toByte() }, legacyIni.peer.publicKey)

        val endpoint = byName.getValue("warp-endpoint")
        assertEquals("162.159.192.1", endpoint.serverAddress)
        assertEquals(2408, endpoint.serverPort.toInt())
        val endpointIni = WireGuardConfig.parse(endpoint.wireGuardConfig!!)
        assertArrayEquals(byteArrayOf(1, 2, 3), endpointIni.reserved)
        assertEquals(30, endpointIni.peer.persistentKeepalive)
        assertEquals(1408, endpointIni.mtu)
        assertArrayEquals(ByteArray(32) { it.toByte() }, endpointIni.privateKey)
    }

    @Test
    fun `a detour to another proxy becomes a chain and the hop is not listed`() {
        val json = """
        {"outbounds":[
          {"type":"trojan","tag":"exit","server":"exit.example.com","server_port":443,"password":"pw",
           "tls":{"enabled":true,"server_name":"exit.example.com"},"detour":"entry"},
          {"type":"shadowsocks","tag":"entry","server":"entry.example.com","server_port":8388,
           "method":"aes-256-gcm","password":"secret"},
          {"type":"direct","tag":"direct"}
        ]}"""
        val exit = SingBoxJsonImporter.parse(json).single()
        assertEquals("exit", exit.name)
        val chain = exit.chain
        assertNotNull(chain)
        assertEquals(OutboundProtocol.SHADOWSOCKS, chain!!.single().outboundProtocol)
        assertEquals("secret", chain.single().ssPassword)
    }

    @Test
    fun `an ECH config in sing-box's PEM form becomes the link's ech`() {
        val body = "AEX+DQBBpQAgACB/RU1sdmFsdWVmb3J0ZXN0aW5nb25seWFiY2RlZgAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
        val json = """
        {"outbounds":[{"type":"vless","tag":"ech","server":"203.0.113.1","server_port":443,"uuid":"$uuid",
          "tls":{"enabled":true,"server_name":"secret.example.com",
            "ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","$body","-----END ECH CONFIGS-----"]}}}]}"""
        assertEquals(body, SingBoxJsonImporter.parse(json).single().tls?.echConfig)
    }

    @Test
    fun `a single bare outbound object imports`() {
        val json = """{"type":"trojan","server":"t.example.com","server_port":443,"password":"pw",
            "tls":{"enabled":true}}"""
        assertTrue(SingBoxJsonImporter.looksLikeSingBox(json))
        val c = SingBoxJsonImporter.parse(json).single()
        // No tag: the endpoint is the name.
        assertEquals("t.example.com:443", c.name)
        assertNull(c.chain)
    }

    @Test
    fun `http and quic transports import and unsupported ones are refused with a reason`() {
        val ok = """
        {"outbounds":[
          {"type":"vless","tag":"h2","server":"a.example.com","server_port":443,"uuid":"$uuid",
           "tls":{"enabled":true},"transport":{"type":"http","host":["h1.example.com","h2.example.com"],"path":"/api","method":"POST","headers":{"X-Custom":["v1","v2"]}}},
          {"type":"trojan","tag":"q","server":"q.example.com","server_port":443,"password":"pw",
           "tls":{"enabled":true},"transport":{"type":"quic"}},
          {"type":"direct","tag":"direct"}
        ]}"""
        val (h2, quic) = SingBoxJsonImporter.parse(ok)
        assertEquals("http", h2.transport)
        assertEquals(listOf("h1.example.com", "h2.example.com"), h2.httpTransport?.hosts)
        assertEquals("/api", h2.httpTransport?.path)
        assertEquals("POST", h2.httpTransport?.method)
        assertEquals("v1, v2", h2.httpTransport?.headers?.get("X-Custom"))
        assertEquals("quic", quic.transport)

        val bad = """
        {"outbounds":[
          {"type":"vless","tag":"kcp","server":"a.example.com","server_port":443,"uuid":"$uuid",
           "transport":{"type":"kcp"}},
          {"type":"shadowtls","tag":"stls","server":"b.example.com","server_port":443},
          {"type":"direct","tag":"direct"}
        ]}"""
        try {
            SingBoxJsonImporter.parse(bad)
            fail("expected a refusal")
        } catch (e: ProxyError.InvalidUrl) {
            assertTrue(e.message!!, e.message!!.contains("kcp"))
            assertTrue(e.message!!, e.message!!.contains("shadowtls"))
        }
    }
}
