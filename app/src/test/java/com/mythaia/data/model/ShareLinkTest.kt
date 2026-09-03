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
    fun `these protocols are not dialable yet and say so`() {
        // Parsing them keeps a subscription intact; the factory is what refuses.
        assertTrue(OutboundProtocol.VLESS.isImplemented)
        assertTrue(OutboundProtocol.TROJAN.isImplemented)
        assertEquals(false, OutboundProtocol.HYSTERIA2.isImplemented)
        assertEquals(false, OutboundProtocol.ANYTLS.isImplemented)
    }
}
