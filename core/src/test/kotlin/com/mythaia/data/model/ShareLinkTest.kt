package com.mythaia.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The `hysteria2://`, `hy2://` and `anytls://` share links, which a
 * subscription may carry alongside the schemes this client already dialled.
 */
class ShareLinkTest {

    // MARK: - Hysteria2

    @Test
    fun `parses a full hysteria2 link`() {
        val config = ProxyConfiguration.fromUrl(
            "hysteria2://s3cr3t@example.com:8443" +
                "?sni=cdn.example.com&upmbps=100&downmbps=200" +
                "&obfs=salamander&obfs-password=shhh#Tokyo%20Edge"
        )

        assertEquals(OutboundProtocol.HYSTERIA2, config.outboundProtocol)
        assertEquals("example.com", config.serverAddress)
        assertEquals(8443.toUShort(), config.serverPort)
        assertEquals("s3cr3t", config.password)
        assertEquals("Tokyo Edge", config.name)
        assertEquals(100, config.hysteriaUpMbps)
        assertEquals(200, config.hysteriaDownMbps)
        assertEquals("salamander", config.obfuscation)
        assertEquals("shhh", config.obfuscationPassword)
        assertEquals("tls", config.security)
        assertEquals("cdn.example.com", config.tls?.serverName)
    }

    @Test
    fun `hy2 is the same scheme under another name`() {
        val long = ProxyConfiguration.fromUrl("hysteria2://p@example.com:443#N")
        val short = ProxyConfiguration.fromUrl("hy2://p@example.com:443#N")

        // Not contentEquals: it compares `uuid`, which is a fresh random
        // placeholder for every password-authenticated protocol, so two parses
        // of one link never match. Compare what the link actually carries.
        assertEquals(long.outboundProtocol, short.outboundProtocol)
        assertEquals(long.serverAddress, short.serverAddress)
        assertEquals(long.serverPort, short.serverPort)
        assertEquals(long.password, short.password)
        assertEquals(long.name, short.name)
        assertEquals(long.tls, short.tls)
    }

    @Test
    fun `absent bandwidth stays absent`() {
        // The pair is what selects Brutal congestion control over BBR, so a
        // default here would silently change how the connection behaves.
        val config = ProxyConfiguration.fromUrl("hysteria2://p@example.com:443#N")
        assertNull(config.hysteriaUpMbps)
        assertNull(config.hysteriaDownMbps)
        assertNull(config.obfuscation)
        assertNull(config.obfuscationPassword)
        // With no sni, the server address is the name presented.
        assertEquals("example.com", config.tls?.serverName)
        // The fragment is the display name when the link carries one.
        assertEquals("N", config.name)
        // ...and the host stands in for it when it does not.
        assertEquals("example.com", ProxyConfiguration.fromUrl("hy2://p@example.com:443").name)
    }

    @Test
    fun `a password containing an at sign survives`() {
        // The host is after the LAST @, not the first.
        val config = ProxyConfiguration.fromUrl("hysteria2://us%40er%3Apass@example.com:443#N")
        assertEquals("us@er:pass", config.password)
        assertEquals("example.com", config.serverAddress)
    }

    @Test
    fun `an obfs of none means no obfuscation`() {
        // Some panels write it out; stored verbatim it was refused at every
        // dial as an obfuscation type this build does not speak.
        assertNull(ProxyConfiguration.fromUrl("hysteria2://p@example.com:443?obfs=none#N").obfuscation)
        assertNull(ProxyConfiguration.fromUrl("hysteria2://p@example.com:443?obfs=NONE#N").obfuscation)
        assertEquals("salamander", ProxyConfiguration.fromUrl("hysteria2://p@example.com:443?obfs=salamander#N").obfuscation)
    }

    // MARK: - VMess

    private fun vmessLink(vararg fields: Pair<String, Any>): String {
        val json = org.json.JSONObject()
        for ((key, value) in fields) json.put(key, value)
        return "vmess://" + java.util.Base64.getEncoder().encodeToString(json.toString().toByteArray(Charsets.UTF_8))
    }

    @Test
    fun `vmess over multi-mode grpc round-trips through its URL`() {
        val original = ProxyConfiguration.fromUrl(vmessLink(
            "v" to "2", "ps" to "Grpc", "add" to "example.com", "port" to "2053",
            "id" to "b1a2c3d4-0000-4000-8000-000000000001", "aid" to "0",
            "net" to "grpc", "type" to "multi", "path" to "svc", "tls" to "tls", "sni" to "g.example.com"
        ))
        assertEquals("grpc", original.transport)
        assertEquals(true, original.grpc?.multiMode)
        assertEquals("svc", original.grpc?.serviceName)

        // The exporter writes the mode into `type`, where v2rayN keeps it;
        // the parser must not read that as header obfuscation.
        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())
        assertEquals(original.uuid, reparsed.uuid)
        assertEquals("grpc", reparsed.transport)
        assertEquals(true, reparsed.grpc?.multiMode)
        assertEquals(original.grpc?.serviceName, reparsed.grpc?.serviceName)
        assertEquals(original.tls?.serverName, reparsed.tls?.serverName)
        assertEquals("Grpc", reparsed.name)
    }

    @Test
    fun `vmess http header obfuscation is still refused`() {
        for (net in listOf("tcp", "grpc")) {
            try {
                ProxyConfiguration.fromUrl(vmessLink(
                    "add" to "example.com", "port" to "443",
                    "id" to "b1a2c3d4-0000-4000-8000-000000000001", "net" to net, "type" to "http"
                ))
                fail("expected InvalidUrl for net=$net")
            } catch (_: ProxyError.InvalidUrl) {
                // expected
            }
        }
    }

    // MARK: - VLESS

    @Test
    fun `vless transports without a dialer are refused at import`() {
        val base = "vless://b1a2c3d4-0000-4000-8000-000000000001@example.com:443"
        for (query in listOf("type=kcp", "type=quic", "type=h2", "type=tcp&headerType=http")) {
            try {
                ProxyConfiguration.fromUrl("$base?$query#N")
                fail("expected InvalidUrl for $query")
            } catch (_: ProxyError.InvalidUrl) {
                // expected
            }
        }
        assertEquals("xhttp", ProxyConfiguration.fromUrl("$base?type=splithttp&security=tls#N").transport)
        assertEquals("tcp", ProxyConfiguration.fromUrl("$base?type=raw&headerType=none#N").transport)
        assertEquals("ws", ProxyConfiguration.fromUrl("$base?type=ws&path=%2Fws#N").transport)
    }

    // MARK: - Naive and SOCKS5

    @Test
    fun `an HTTPS proxy keeps HTTP 1-1 through its URL`() {
        val original = ProxyConfiguration.fromUrl("https://u:p@example.com:8443#Proxy", OutboundProtocol.NAIVE_HTTP11)
        assertEquals(OutboundProtocol.NAIVE_HTTP11, original.outboundProtocol)

        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())
        assertEquals(OutboundProtocol.NAIVE_HTTP11, reparsed.outboundProtocol)
        assertEquals(NaiveProtocol.HTTP11, reparsed.naiveProtocol)
        assertEquals("u", reparsed.naiveUsername)
        assertEquals("p", reparsed.naivePassword)
        assertEquals(8443.toUShort(), reparsed.serverPort)
        assertEquals("Proxy", reparsed.name)

        // Without the marker the scheme means HTTP/2, and an explicit choice wins over the marker.
        val http2 = ProxyConfiguration.fromUrl("https://u:p@example.com:8443#P")
        assertEquals(OutboundProtocol.NAIVE_HTTP2, ProxyConfiguration.fromUrl(http2.toUrl()).outboundProtocol)
        assertEquals(
            OutboundProtocol.NAIVE_HTTP2,
            ProxyConfiguration.fromUrl(original.toUrl(), OutboundProtocol.NAIVE_HTTP2).outboundProtocol
        )
    }

    @Test
    fun `a naive link carries allow insecure, its name and its pin both ways`() {
        val link = "https://u:p@1.2.3.4:443?sni=proxy.example&insecure=1&pcs=PIN&vcn=cert.example#N"
            .replace("PIN", "abababababababababababababababababababababababababababababababab")
        val config = ProxyConfiguration.fromUrl(link)
        val tls = config.tls!!
        assertEquals("proxy.example", tls.serverName)
        assertTrue(tls.allowInsecure)
        assertEquals(listOf("abababababababababababababababababababababababababababababababab"), tls.pinnedCertSha256)
        assertEquals("cert.example", tls.verifyName)

        val again = ProxyConfiguration.fromUrl(config.toUrl()).tls!!
        assertEquals(tls.serverName, again.serverName)
        assertTrue(again.allowInsecure)
        assertEquals(tls.pinnedCertSha256, again.pinnedCertSha256)
        assertEquals(tls.verifyName, again.verifyName)

        // A plain link keeps no TLS settings of its own, as before.
        assertNull(ProxyConfiguration.fromUrl("https://u:p@example.com:443#P").tls)
    }

    @Test
    fun `a nowhere link carries allow insecure and its pin both ways`() {
        val config = ProxyConfiguration.fromUrl(
            "nowhere://key@example.com:443?up=udp&down=udp&insecure=1&pcs=abababababababababababababababababababababababababababababababab#W"
        )
        assertTrue(config.tls!!.allowInsecure)
        assertEquals(listOf("abababababababababababababababababababababababababababababababab"), config.tls!!.pinnedCertSha256)
        val again = ProxyConfiguration.fromUrl(config.toUrl())
        assertTrue(again.tls!!.allowInsecure)
        assertEquals(config.tls!!.pinnedCertSha256, again.tls!!.pinnedCertSha256)
    }

    @Test
    fun `a server is marked insecure only when its certificate really goes unchecked`() {
        fun parse(link: String) = ProxyConfiguration.fromUrl(link)
        val id = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
        assertTrue(parse("vless://$id@example.com:443?security=tls&allowInsecure=1#V").skipsCertificateCheck)
        assertTrue(parse("trojan://pw@example.com:443?allowInsecure=1#T").skipsCertificateCheck)
        assertTrue(parse("hysteria2://pw@example.com:443?insecure=1#H").skipsCertificateCheck)
        assertTrue(parse("https://u:p@example.com:443?insecure=1#N").skipsCertificateCheck)
        // A pin is checked whatever the flag says.
        assertTrue(!parse("hysteria2://pw@example.com:443?insecure=1&pcs=abababababababababababababababababababababababababababababababab#H").skipsCertificateCheck)
        // No TLS in use, nothing to skip.
        assertTrue(!parse("vless://$id@example.com:443?security=none&allowInsecure=1#V").skipsCertificateCheck)
        assertTrue(!parse("vless://$id@example.com:443?security=tls#V").skipsCertificateCheck)
    }

    @Test
    fun `a naive link without a port takes 443 and a query is not part of the port`() {
        val config = ProxyConfiguration.fromUrl("https://u:p@example.com?x=1#P")
        assertEquals(443.toUShort(), config.serverPort)
        assertEquals("example.com", config.serverAddress)
        assertEquals(8443.toUShort(), ProxyConfiguration.fromUrl("https://u:p@example.com:8443?x=1").serverPort)
    }

    @Test
    fun `a socks5 link with a query still parses its port`() {
        val config = ProxyConfiguration.fromUrl("socks5://u:p@example.com:1080?udp=1#S")
        assertEquals(1080.toUShort(), config.serverPort)
        assertEquals("u", config.socks5Username)
        assertEquals("p", config.socks5Password)
        assertEquals("S", config.name)
        assertEquals(1080.toUShort(), ProxyConfiguration.fromUrl("socks5://example.com:1080?udp=1").serverPort)
    }

    // MARK: - AnyTLS

    @Test
    fun `parses an anytls link`() {
        val config = ProxyConfiguration.fromUrl(
            "anytls://pw@example.com:8443?sni=front.example&alpn=h2,http%2F1.1&fp=firefox_148&insecure=1#Node"
        )
        assertEquals(OutboundProtocol.ANYTLS, config.outboundProtocol)
        assertEquals("pw", config.password)
        assertEquals("front.example", config.tls?.serverName)
        assertEquals(listOf("h2", "http/1.1"), config.tls?.alpn)
        assertEquals(TlsFingerprint.FIREFOX_148, config.tls?.fingerprint)
        assertEquals(true, config.tls?.allowInsecure)
        assertEquals("Node", config.name)
    }

    // MARK: - Round trip

    @Test
    fun `hysteria2 round-trips through its URL`() {
        val original = ProxyConfiguration.fromUrl(
            "hysteria2://s3cr3t@example.com:8443?sni=cdn.example.com&upmbps=100&downmbps=200" +
                "&obfs=salamander&obfs-password=shhh#Tokyo"
        )
        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())

        assertEquals(original.serverAddress, reparsed.serverAddress)
        assertEquals(original.serverPort, reparsed.serverPort)
        assertEquals(original.password, reparsed.password)
        assertEquals(original.name, reparsed.name)
        assertEquals(original.hysteriaUpMbps, reparsed.hysteriaUpMbps)
        assertEquals(original.hysteriaDownMbps, reparsed.hysteriaDownMbps)
        assertEquals(original.obfuscation, reparsed.obfuscation)
        assertEquals(original.obfuscationPassword, reparsed.obfuscationPassword)
        assertEquals(original.tls?.serverName, reparsed.tls?.serverName)
    }

    @Test
    fun `hy2 exports as the canonical scheme`() {
        val config = ProxyConfiguration.fromUrl("hy2://p@example.com:443#N")
        assertTrue(config.toUrl().startsWith("hysteria2://"))
    }

    @Test
    fun `anytls round-trips through its URL`() {
        val original = ProxyConfiguration.fromUrl(
            "anytls://pw@example.com:8443?sni=front.example&fp=firefox_148&insecure=1#Node"
        )
        val reparsed = ProxyConfiguration.fromUrl(original.toUrl())

        assertEquals(original.password, reparsed.password)
        assertEquals(original.tls?.serverName, reparsed.tls?.serverName)
        assertEquals(original.tls?.fingerprint, reparsed.tls?.fingerprint)
        assertEquals(original.tls?.allowInsecure, reparsed.tls?.allowInsecure)
        assertEquals(original.name, reparsed.name)
    }

    // MARK: - Recognition

    @Test
    fun `canParseUrl recognises the new schemes`() {
        for (url in listOf(
            "hysteria2://p@h:443", "hy2://p@h:443", "anytls://p@h:443"
        )) {
            assertTrue(url, ProxyConfiguration.canParseUrl(url))
        }
    }

    @Test
    fun `a link with no userinfo is rejected, not half-parsed`() {
        for (url in listOf("hysteria2://example.com:443", "anytls://example.com:443")) {
            try {
                ProxyConfiguration.fromUrl(url)
                fail("expected InvalidUrl for $url")
            } catch (_: ProxyError.InvalidUrl) {
                // expected
            }
        }
    }

    @Test
    fun `every protocol a link can name is dialable`() {
        // Hysteria2 was the last one waiting on the QUIC stack. The property
        // stays because a subscription may carry something a future build adds,
        // and failing at the dial with the protocol named beats a silent
        // timeout — but nothing in this build is in that state.
        for (protocol in OutboundProtocol.entries) {
            assertTrue(protocol.name, protocol.isImplemented)
        }
    }
}
