package com.mythaia.data.model

import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig
import com.mythaia.vpn.protocol.wireguard.WireGuardCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.URLEncoder

/** `wireguard://` and `wg://` share links, as v2rayNG and Hiddify write them. */
class WireGuardLinkTest {

    private val privateBytes = ByteArray(32) { (it + 1).toByte() }
    // Chosen so the base64 has '+', '/' and '=' in it, which is what a link mangles.
    private val peerBytes = ByteArray(32) { (it * 37 + 251).toByte() }
    private val pskBytes = ByteArray(32) { (it * 5).toByte() }

    private val privateKey = WireGuardCrypto.encodeKey(privateBytes)
    private val peerKey = WireGuardCrypto.encodeKey(peerBytes)
    private val psk = WireGuardCrypto.encodeKey(pskBytes)

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    private fun ini(config: ProxyConfiguration): WireGuardConfig {
        assertEquals(OutboundProtocol.WIREGUARD, config.outboundProtocol)
        return WireGuardConfig.parse(config.wireGuardConfig!!)
    }

    @Test
    fun `a v2rayNG wireguard link becomes the INI it stands for`() {
        val link = "wireguard://${enc(privateKey)}@162.159.192.1:2408" +
            "?publickey=${enc(peerKey)}&address=${enc("172.16.0.2/32,2606:4700:110:8a36::2/128")}" +
            "&mtu=1280&reserved=1,2,3&presharedkey=${enc(psk)}#WARP%20DE"
        assertTrue(ProxyConfiguration.canParseUrl(link))

        val config = ProxyConfiguration.fromUrl(link)
        assertEquals("WARP DE", config.name)
        assertEquals("162.159.192.1", config.serverAddress)
        assertEquals(2408, config.serverPort.toInt())

        val parsed = ini(config)
        assertArrayEquals(privateBytes, parsed.privateKey)
        assertArrayEquals(peerBytes, parsed.peer.publicKey)
        assertArrayEquals(pskBytes, parsed.peer.presharedKey)
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36::2/128"), parsed.addresses)
        assertEquals(1280, parsed.mtu)
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.reserved)
        assertEquals(listOf("0.0.0.0/0", "::/0"), parsed.peer.allowedIps)
    }

    @Test
    fun `a Hiddify wg link with keys in the query parses the same`() {
        val link = "wg://engage.cloudflareclient.com:2408?pk=${enc(privateKey)}" +
            "&local_address=172.16.0.2/32,2606:4700:110:8a36::2/128&peer_pk=${enc(peerKey)}" +
            "&pre_shared_key=${enc(psk)}&reserved=AQID&mtu=1330&workers=2#Hiddify%20WARP"
        assertTrue(ProxyConfiguration.canParseUrl(link))

        val config = ProxyConfiguration.fromUrl(link)
        assertEquals("Hiddify WARP", config.name)
        assertEquals("engage.cloudflareclient.com", config.serverAddress)

        val parsed = ini(config)
        assertArrayEquals(privateBytes, parsed.privateKey)
        assertArrayEquals(peerBytes, parsed.peer.publicKey)
        assertArrayEquals(pskBytes, parsed.peer.presharedKey)
        assertEquals(1330, parsed.mtu)
        assertArrayEquals(byteArrayOf(1, 2, 3), parsed.reserved)
        assertEquals(2, parsed.addresses.size)
    }

    @Test
    fun `spellings cross schemes and keys survive the shapes links put them in`() {
        // wg:// with the key as userinfo, v2rayNG's publickey, a URL-safe key
        // with its padding stripped, and an upper-case parameter name.
        val urlSafePeer = peerKey.replace('+', '-').replace('/', '_').trimEnd('=')
        val link = "wg://${enc(privateKey)}@10.0.0.1:51820?PublicKey=$urlSafePeer&address=10.9.0.2"
        val parsed = ini(ProxyConfiguration.fromUrl(link))
        assertArrayEquals(peerBytes, parsed.peer.publicKey)
        // A bare address gets the host prefix the INI wants.
        assertEquals(listOf("10.9.0.2/32"), parsed.addresses)
        assertNull(parsed.reserved)

        // Hex keys, as Xray also accepts them.
        val hexPrivate = privateBytes.joinToString("") { "%02x".format(it) }
        val hex = ini(ProxyConfiguration.fromUrl("wireguard://$hexPrivate@10.0.0.1:51820?peer_pk=${enc(peerKey)}"))
        assertArrayEquals(privateBytes, hex.privateKey)
    }

    @Test
    fun `an IPv6 endpoint stays bracketed and the default name is WireGuard`() {
        val link = "wireguard://${enc(privateKey)}@[2606:4700:d0::a29f:c001]:2408?publickey=${enc(peerKey)}&address=172.16.0.2/32"
        val config = ProxyConfiguration.fromUrl(link)
        assertEquals("2606:4700:d0::a29f:c001", config.serverAddress)
        assertEquals("WireGuard", config.name)
        assertEquals("2606:4700:d0::a29f:c001", ini(config).peer.endpointHost)
    }

    @Test
    fun `a link missing a key is refused with a reason`() {
        for (link in listOf(
            "wireguard://${enc(privateKey)}@1.2.3.4:51820?address=10.0.0.2/32",
            "wg://1.2.3.4:51820?peer_pk=${enc(peerKey)}",
            "wireguard://${enc(privateKey)}@1.2.3.4:51820?publickey=${enc(peerKey)}&reserved=1,2"
        )) {
            try {
                ProxyConfiguration.fromUrl(link)
                fail("expected a refusal for $link")
            } catch (e: ProxyError.InvalidUrl) {
                assertTrue(e.message!!.isNotEmpty())
            }
        }
    }

    @Test
    fun `a subscription list keeps its WireGuard lines`() {
        val body = listOf(
            "wireguard://${enc(privateKey)}@1.2.3.4:51820?publickey=${enc(peerKey)}&address=10.0.0.2/32#one",
            "wg://5.6.7.8:2408?pk=${enc(privateKey)}&peer_pk=${enc(peerKey)}&local_address=10.0.0.3/32#two"
        ).joinToString("\n")
        val result = SubscriptionFetcher.parse(body.toByteArray())
        assertEquals(listOf("one", "two"), result.configurations.map { it.name })
        assertTrue(result.configurations.all { it.outboundProtocol == OutboundProtocol.WIREGUARD })
    }
}
