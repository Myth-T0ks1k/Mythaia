package com.mythaia.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URLEncoder

/**
 * Links the way a live panel writes them: string-valued xhttp `extra`,
 * FinalMask in `fm=`, and uTLS family names in `fp=`. Credentials are
 * placeholders; the shapes are verbatim.
 */
class PanelLinkTest {

    private fun q(s: String) = URLEncoder.encode(s, "UTF-8")

    private val extra = """{"scMaxEachPostBytes":"500000","scMinPostsIntervalMs":"60","xPaddingBytes":"100-1000","xmux":{"maxConnections":16,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000"}}"""
    private val fm = """{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3"],"delays":["1"],"maxSplit":"2"}}]}"""

    @Test
    fun `xhttp extra with string values is applied`() {
        val url = "vless://11111111-2222-3333-4444-555555555555@203.0.113.20:443?encryption=none&security=tls&type=xhttp&headerType=none&path=%2F&host=d555555abcdef8.cloudfront.net&mode=auto&extra=${q(extra)}&fm=${q(fm)}&sni=d555555abcdef8.cloudfront.net&fp=safari#Gold"
        val config = ProxyConfiguration.fromUrl(url)
        val xhttp = config.xhttp
        assertNotNull(xhttp)
        xhttp!!
        assertEquals(500_000, xhttp.scMaxEachPostBytes)
        assertEquals(60, xhttp.scMinPostsIntervalMs)
        assertEquals(100, xhttp.xPaddingBytesFrom)
        assertEquals(1000, xhttp.xPaddingBytesTo)
        assertEquals("d555555abcdef8.cloudfront.net", xhttp.host)
    }

    @Test
    fun `fm on a tls link becomes the server's fragment settings`() {
        val url = "vless://11111111-2222-3333-4444-555555555555@203.0.113.51:443?encryption=none&security=tls&type=ws&headerType=none&path=%2F&host=d666666abcdef8.cloudfront.net&fm=${q(fm)}&sni=d666666abcdef8.cloudfront.net&fp=safari#Edge"
        val config = ProxyConfiguration.fromUrl(url)
        val fragment = config.tls?.fragment
        assertNotNull(fragment)
        fragment!!
        assertEquals(listOf(3..3), fragment.lengthRanges)
        assertEquals(listOf(1..1), fragment.delayRanges)
        assertEquals(2, fragment.maxSplit)
        assertEquals(TlsFingerprint.SAFARI_26, config.tls?.fingerprint)
    }

    @Test
    fun `fp family names map to the newest profile of the family`() {
        assertEquals(TlsFingerprint.EDGE_85, TlsFingerprint.fromRaw("edge"))
        assertEquals(TlsFingerprint.CHROME_133, TlsFingerprint.fromRaw("chrome"))
        assertEquals(TlsFingerprint.FIREFOX_148, TlsFingerprint.fromRaw("firefox"))
        assertEquals(TlsFingerprint.RANDOM, TlsFingerprint.fromRaw("randomized"))
        assertEquals(TlsFingerprint.CHROME_120, TlsFingerprint.fromRaw("chrome_120"))
    }

    @Test
    fun `fm salamander fills hysteria2 obfuscation when obfs params are absent`() {
        val udp = """{"udp":[{"type":"salamander","settings":{"password":"pw123"}}],"quicParams":{"congestion":"bbr"}}"""
        val url = "hysteria2://secret@198.51.100.54:443?fm=${q(udp)}&sni=grid.example.net#Social"
        val config = ProxyConfiguration.fromUrl(url)
        assertEquals("salamander", config.obfuscation)
        assertEquals("pw123", config.obfuscationPassword)
    }

    @Test
    fun `fragment survives the share link round trip`() {
        val url = "vless://11111111-2222-3333-4444-555555555555@198.51.100.12:443?encryption=none&security=tls&type=grpc&serviceName=grpc.example.net&authority=front.example.net&mode=gun&fm=${q(fm)}&sni=front.example.net&fp=edge#Relay"
        val config = ProxyConfiguration.fromUrl(url)
        val again = ProxyConfiguration.fromUrl(config.toUrl())
        val fragment = again.tls?.fragment
        assertNotNull(fragment)
        assertEquals(3..3, fragment!!.lengthRange)
        assertEquals(2, fragment.maxSplit)
        assertTrue(config.toUrl().contains("fragment="))
    }

    @Test
    fun `security none link carries no fragment even with fm`() {
        val url = "vless://11111111-2222-3333-4444-555555555555@192.0.2.86:80?encryption=none&security=none&type=xhttp&host=cdn.example.com&mode=stream-up&fm=${q(fm)}#Premium"
        val config = ProxyConfiguration.fromUrl(url)
        assertNull(config.tls)
        assertEquals(XHttpMode.fromRaw("stream-up"), config.xhttp?.mode)
    }
}
