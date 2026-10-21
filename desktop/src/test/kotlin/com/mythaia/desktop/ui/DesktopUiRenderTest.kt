package com.mythaia.desktop.ui

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.use
import com.mythaia.data.country.CountryGrouping
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.AppState
import com.mythaia.desktop.S
import com.mythaia.desktop.store.DesktopStore
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

            // Verify country grouping state actions on AppState.
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

            ImageComposeScene(width = 560, height = 720) {
                MythaiaTheme(dark = false) {
                    NewServerFlow(onSave = {}, onDismiss = {})
                }
            }.use { scene ->
                assertNotNull(scene.render())
            }

            ImageComposeScene(width = 560, height = 720) {
                MythaiaTheme(dark = true) {
                    ServerEditor(configuration = de1, onSave = {}, onDismiss = {})
                }
            }.use { scene ->
                assertNotNull(scene.render())
            }
        } finally {
            state.shutdown()
        }
    }
}
