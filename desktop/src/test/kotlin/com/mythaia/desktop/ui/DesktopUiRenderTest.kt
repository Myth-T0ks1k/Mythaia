package com.mythaia.desktop.ui

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.use
import com.mythaia.data.country.CountryGrouping
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.WireGuardForm
import com.mythaia.desktop.AppState
import com.mythaia.desktop.S
import com.mythaia.desktop.store.DesktopStore
import com.mythaia.vpn.protocol.wireguard.WireGuardConfig
import com.mythaia.vpn.protocol.wireguard.WireGuardCrypto
import com.mythaia.vpn.util.MythaiaLogger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Locale
import java.util.UUID

class DesktopUiRenderTest {

    private fun sampleServer(
        name: String,
        host: String = "example.com",
        protocol: OutboundProtocol = OutboundProtocol.VLESS
    ): ProxyConfiguration = ProxyConfiguration(
        name = name,
        serverAddress = host,
        serverPort = 443u,
        uuid = UUID.randomUUID(),
        encryption = "none",
        outboundProtocol = protocol,
        security = "tls"
    )

    private fun sampleWireGuardConfig(amnezia: Boolean = false): ProxyConfiguration {
        val (priv, _) = WireGuardCrypto.generateKeyPair()
        val (_, peerPub) = WireGuardCrypto.generateKeyPair()
        val extra = if (amnezia) {
            """
            Jc = 4
            Jmin = 40
            Jmax = 70
            S1 = 15
            S2 = 30
            H1 = 1234567
            H2 = 7654321
            H3 = 1122334
            H4 = 4433221
            """.trimIndent()
        } else ""
        val conf = """
            [Interface]
            PrivateKey = ${WireGuardCrypto.encodeKey(priv)}
            Address = 10.66.66.2/32, fd42:42:42::2/128
            DNS = 1.1.1.1, 1.0.0.1
            MTU = 1380
            $extra

            [Peer]
            PublicKey = ${WireGuardCrypto.encodeKey(peerPub)}
            Endpoint = wg.example.com:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
        """.trimIndent()
        val parsed = WireGuardConfig.parse(conf)
        return ProxyConfiguration(
            name = if (amnezia) "AWG Frankfurt" else "WG Amsterdam",
            serverAddress = parsed.peer.endpointHost,
            serverPort = parsed.peer.endpointPort.toUShort(),
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.WIREGUARD,
            wireGuardConfig = conf
        )
    }

    @Test
    fun `renders HomeScreen, ProxiesScreen with country sections, SettingsScreen, LogsScreen and ServerEditor`() {
        val state = AppState(DesktopStore(), nativeAvailable = true)
        try {
            val de1 = sampleServer("🇩🇪 Frankfurt 01", "de1.example.com", OutboundProtocol.VLESS)
            val de2 = sampleServer("Германия 02", "de2.example.com", OutboundProtocol.HYSTERIA2)
            val nl1 = sampleServer("[NL] Amsterdam", "nl1.example.com", OutboundProtocol.TROJAN)
            val jp1 = sampleServer("🇯🇵 Tokyo", "jp1.example.com", OutboundProtocol.SHADOWSOCKS)
            val other = sampleServer("Custom Relay", "relay.example.com", OutboundProtocol.SOCKS5)

            listOf(de1, de2, nl1, jp1, other).forEach { state.saveConfiguration(it) }
            state.saveChain(ProxyChain(name = "DE to NL", proxyIds = listOf(de1.id, nl1.id)))
            MythaiaLogger("UiTest").info("Desktop country grouping render test")

            assertEquals("DE", state.countryOf(de1))
            assertEquals("DE", state.countryOf(de2))
            assertEquals("NL", state.countryOf(nl1))
            assertEquals("JP", state.countryOf(jp1))
            assertNull(state.countryOf(other))

            state.useAutoIn(AppState.DEFAULT_GROUP, "NL")
            assertEquals("NL", state.settings.value.autoCountries[AppState.DEFAULT_GROUP])
            assertEquals(nl1.id, state.effectiveConfig(AppState.DEFAULT_GROUP)?.id)

            state.toggleCountryCollapsed(AppState.DEFAULT_GROUP, "JP")
            assertTrue(state.countrySectionKey(AppState.DEFAULT_GROUP, "JP") in state.settings.value.collapsedCountries)

            for (lang in listOf("en", "ru")) {
                S.apply(lang)
                val locale = Locale.forLanguageTag(S.lang.code)
                val sections = CountryGrouping.sections(state.groupConfigs(AppState.DEFAULT_GROUP), { state.countryOf(it) }, locale)
                assertEquals(4, sections.size)
                assertNull(sections.last().code)

                for (dark in listOf(false, true)) {
                    state.setGroupByCountry(true)
                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            App(state)
                        }
                    }.use { scene ->
                        val image = scene.render()
                        assertEquals(1120, image.width)
                        assertEquals(740, image.height)
                    }

                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            HomeScreen(state, onOpenProxies = {})
                        }
                    }.use { scene ->
                        assertNotNull(scene.render())
                    }

                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            ProxiesScreen(state)
                        }
                    }.use { scene ->
                        assertNotNull(scene.render())
                    }

                    state.setGroupByCountry(false)
                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            ProxiesScreen(state)
                        }
                    }.use { scene ->
                        assertNotNull(scene.render())
                    }

                    state.updateSettings { it.copy(tunnelMode = if (dark) "tun" else "proxy") }
                    state.serviceInstalled.value = dark
                    state.serviceAvailable.value = dark
                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            SettingsScreen(state)
                        }
                    }.use { scene ->
                        assertNotNull(scene.render())
                    }

                    ImageComposeScene(width = 1120, height = 740) {
                        MythaiaTheme(dark = dark) {
                            LogsScreen(state)
                        }
                    }.use { scene ->
                        assertNotNull(scene.render())
                    }
                }
            }

            state.toggleCountryCollapsed(AppState.DEFAULT_GROUP, "JP")
            assertFalse(state.countrySectionKey(AppState.DEFAULT_GROUP, "JP") in state.settings.value.collapsedCountries)
            state.useAuto(AppState.DEFAULT_GROUP)
            assertNull(state.settings.value.autoCountries[AppState.DEFAULT_GROUP])
        } finally {
            state.shutdown()
        }
    }

    @Test
    fun `renders ProtocolPicker and ServerEditor for VLESS, WireGuard and AmneziaWG`() {
        val vless = sampleServer("VLESS Berlin", "de.example.com")
        val wg = sampleWireGuardConfig(amnezia = false)
        val awg = sampleWireGuardConfig(amnezia = true)

        ImageComposeScene(width = 560, height = 720) {
            MythaiaTheme(dark = false) {
                NewServerFlow(onSave = {}, onDismiss = {})
            }
        }.use { scene ->
            assertNotNull(scene.render())
        }

        for ((proto, amnezia) in listOf(
            OutboundProtocol.VLESS to false,
            OutboundProtocol.WIREGUARD to false,
            OutboundProtocol.WIREGUARD to true
        )) {
            ImageComposeScene(width = 560, height = 720) {
                MythaiaTheme(dark = false) {
                    ServerEditor(configuration = null, onSave = {}, onDismiss = {}, initialProtocol = proto, amnezia = amnezia)
                }
            }.use { scene ->
                assertNotNull(scene.render())
            }
        }

        for (existing in listOf(vless, wg, awg)) {
            ImageComposeScene(width = 560, height = 720) {
                MythaiaTheme(dark = true) {
                    ServerEditor(configuration = existing, onSave = {}, onDismiss = {})
                }
            }.use { scene ->
                assertNotNull(scene.render())
            }
        }
    }

    @Test
    fun `WireGuardForm keypair generation, validation and config round-trip match editor contract`() {
        val privKey = WireGuardForm.generatePrivateKey()
        val pubKey = WireGuardForm.publicKeyOf(privKey)
        assertNotNull(pubKey)
        assertNull(WireGuardForm.publicKeyOf("not-a-valid-key"))

        val peerPub = WireGuardForm.publicKeyOf(WireGuardForm.generatePrivateKey())!!
        val psk = WireGuardForm.generatePrivateKey()
        val form = WireGuardForm(
            privateKey = privKey,
            addresses = "10.8.0.2/32, fd00::2/128",
            dns = "1.1.1.1, 1.0.0.1",
            mtu = "1380",
            reserved = "12, 34, 56",
            publicKey = peerPub,
            presharedKey = psk,
            endpoint = "[2001:db8::1]:51820",
            allowedIps = "0.0.0.0/0, ::/0",
            keepalive = "25",
            jc = "4",
            jmin = "40",
            jmax = "70",
            s1 = "15",
            s2 = "30",
            h1 = "1234567",
            h2 = "7654321",
            h3 = "1122334",
            h4 = "4433221"
        )
        assertTrue(form.isAmnezia)
        val text = form.toIni()
        assertTrue(text.contains("Endpoint = [2001:db8::1]:51820"))
        val roundTrip = WireGuardForm.fromIni(text)
        assertEquals(privKey, roundTrip.privateKey)
        assertEquals(peerPub, roundTrip.publicKey)
        assertEquals(psk, roundTrip.presharedKey)
        assertEquals("12, 34, 56", roundTrip.reserved)
        assertEquals("[2001:db8::1]:51820", roundTrip.endpoint)
        assertTrue(roundTrip.isAmnezia)
        assertEquals("4", roundTrip.jc)
        assertEquals("4433221", roundTrip.h4)

        val proxyConfig = ProxyConfiguration.fromWireGuardConfig(text, "AWG Test")
        assertEquals(OutboundProtocol.WIREGUARD, proxyConfig.outboundProtocol)
        assertEquals("2001:db8::1", proxyConfig.serverAddress)
        assertEquals(51820.toUShort(), proxyConfig.serverPort)
    }
}
