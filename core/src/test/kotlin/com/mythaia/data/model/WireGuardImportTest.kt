package com.mythaia.data.model

import com.mythaia.vpn.protocol.wireguard.WireGuardCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Importing a `wg-quick` INI as a profile, since WireGuard has no share link. */
class WireGuardImportTest {

    private val privateKey = WireGuardCrypto.encodeKey(ByteArray(32) { it.toByte() })
    private val peerKey = WireGuardCrypto.encodeKey(ByteArray(32) { (it * 7).toByte() })

    private fun ini(extra: String = "") = """
        [Interface]
        PrivateKey = $privateKey
        Address = 10.7.0.2/32
        DNS = 1.1.1.1
        $extra

        [Peer]
        PublicKey = $peerKey
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
    """.trimIndent()

    @Test
    fun `a wg-quick config is recognised and a share link is not`() {
        assertTrue(ProxyConfiguration.looksLikeWireGuardConfig(ini()))
        assertFalse(ProxyConfiguration.looksLikeWireGuardConfig("vless://x@a.b:443#n"))
        assertFalse(ProxyConfiguration.looksLikeWireGuardConfig("https://example.com/sub"))
        // An INI missing its peer is not something that could be dialled.
        assertFalse(
            ProxyConfiguration.looksLikeWireGuardConfig("[Interface]\nPrivateKey = $privateKey")
        )
    }

    @Test
    fun `importing keeps the text and pulls the endpoint out of it`() {
        val config = ProxyConfiguration.fromWireGuardConfig(ini())

        assertEquals(OutboundProtocol.WIREGUARD, config.outboundProtocol)
        assertEquals("vpn.example.com", config.serverAddress)
        assertEquals(51820.toUShort(), config.serverPort)
        // Verbatim, so a key this build does not know still survives a save.
        assertEquals(ini(), config.wireGuardConfig)
    }

    @Test
    fun `an AmneziaWG config is labelled as one`() {
        val plain = ProxyConfiguration.fromWireGuardConfig(ini())
        val amnezia = ProxyConfiguration.fromWireGuardConfig(
            ini("Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nH1 = 1234567\nH4 = 4433221")
        )

        assertEquals("WireGuard", plain.name)
        assertEquals("AmneziaWG", amnezia.name)
    }

    @Test
    fun `a given name wins over the derived one`() {
        assertEquals("Home", ProxyConfiguration.fromWireGuardConfig(ini(), "Home").name)
    }

    @Test
    fun `a config that cannot be parsed is refused with a reason`() {
        try {
            ProxyConfiguration.fromWireGuardConfig("[Interface]\nPrivateKey = nonsense\n\n[Peer]\n")
            fail("expected a refusal")
        } catch (e: Exception) {
            assertTrue(e is ProxyError.InvalidUrl)
            assertNotNull(e.message)
        }
    }

    @Test
    fun `WireGuard exports the config it was given`() {
        // There is no scheme to serialise to, so a round trip hands back the
        // INI rather than an empty or malformed link.
        val config = ProxyConfiguration.fromWireGuardConfig(ini())
        assertEquals(ini(), config.toUrl())
    }
}
