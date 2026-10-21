package com.mythaia.desktop.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.routing.HappRouting
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.AppState
import com.mythaia.desktop.DeepLinks
import com.mythaia.desktop.S
import com.mythaia.desktop.store.DesktopStore
import com.mythaia.desktop.tr
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Base64
import java.util.UUID

/**
 * Desktop UI and [AppState] tests for Happ provider keys, routing profiles,
 * deep-link import confirmation, and headless Compose scene rendering.
 *
 * Uses [AppPaths.overrideDataDir] pointing to a temporary directory so the
 * user's real `%APPDATA%\Mythaia` and Windows system proxy are never touched.
 */
class DesktopHappKeysUiTest {

    private lateinit var tempDir: File
    private var state: AppState? = null

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("mythaia-desktop-happ-test-").toFile()
        AppPaths.overrideDataDir = tempDir
        S.apply("en")
    }

    @After
    fun tearDown() {
        runCatching { state?.shutdown() }
        state = null
        AppPaths.overrideDataDir = null
        runCatching { tempDir.deleteRecursively() }
    }

    private fun newState(): AppState {
        val store = DesktopStore()
        val s = AppState(store, nativeAvailable = false)
        s.updateSettings { it.copy(setSystemProxy = false, tunnelMode = "proxy", autoConnect = false) }
        state = s
        return s
    }

    private fun sampleRoutingLink(
        name: String = "Happ Split",
        activate: Boolean = true,
        geositeUrl: String = "",
        geoipUrl: String = ""
    ): String {
        val json = """
            {
              "Name": "$name",
              "GlobalProxy": "true",
              "UseChunkFiles": "${if (geositeUrl.isNotEmpty() || geoipUrl.isNotEmpty()) "true" else "false"}",
              "GeositeUrl": "$geositeUrl",
              "GeoipUrl": "$geoipUrl",
              "RouteOrder": "block-direct-proxy",
              "DirectSites": ["direct.example.com", "domain:local.example.org"],
              "DirectIp": ["203.0.113.0/24"],
              "ProxySites": ["proxy.example.com"],
              "ProxyIp": ["198.51.100.0/24"],
              "BlockSites": ["ads.example.com"],
              "BlockIp": ["192.0.2.0/24"]
            }
        """.trimIndent()
        val b64 = Base64.getEncoder().encodeToString(json.toByteArray(Charsets.UTF_8))
        val verb = if (activate) "onadd" else "add"
        return "happ://routing/$verb/$b64"
    }

    @Test
    fun `DeepLinks recognizes all schemes and unwraps wrapper URLs while preserving fronting`() {
        val schemesToCheck = listOf(
            "mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fx",
            "happ://routing/onadd/eyJOYW1lIjoiVGVzdCJ9",
            "happ://routing/off",
            "happ://add/https://sub.example.com/feed",
            "vless://11111111-1111-1111-1111-111111111111@203.0.113.1:443#VL",
            "vmess://auto:11111111-1111-1111-1111-111111111111@203.0.113.2:443#VM",
            "trojan://pass@203.0.113.3:443#TR",
            "ss://YWVzLTEyOC1nY206cGFzcw==@203.0.113.4:8388#SS",
            "socks5://user:pass@203.0.113.5:1080#S5",
            "socks://user:pass@203.0.113.5:1080#S",
            "hysteria2://pass@203.0.113.6:443#HY2",
            "hy2://pass@203.0.113.6:443#HY2",
            "anytls://pass@203.0.113.7:443#AT",
            "tuic://11111111-1111-1111-1111-111111111111:pass@203.0.113.8:443#TU",
            "wireguard://privkey@203.0.113.9:51820?publickey=pubkey&address=10.0.0.2/32#WG",
            "wg://privkey@203.0.113.9:51820?publickey=pubkey&address=10.0.0.2/32#WG",
            "sudoku://key@203.0.113.10:443#SU",
            "nowhere://203.0.113.11:443?sni=example.com#NW"
        )
        for (link in schemesToCheck) {
            assertTrue("Expected DeepLinks.isLink($link) to be true", DeepLinks.isLink(link))
        }

        // mythaia://import with fronting and name preserves all parameters in fragment form
        val frontedAppLink = "mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub%2Ftoken" +
            "&front=203.0.113.10,203.0.113.11:8443&sni=cdn.example.org&name=Work%20Sub"
        val extracted = DeepLinks.extract(frontedAppLink)
        assertEquals(
            "https://panel.example.com/sub/token#front=203.0.113.10,203.0.113.11:8443&sni=cdn.example.org&name=Work%20Sub",
            extracted
        )

        // happ://add/ unwraps to the underlying subscription URL
        assertEquals(
            "https://sub.example.com/feed",
            DeepLinks.extract("happ://add/https://sub.example.com/feed")
        )

        // happ://routing/ stays intact
        val routingLink = sampleRoutingLink()
        assertEquals(routingLink, DeepLinks.extract(routingLink))
        assertEquals("happ://routing/off", DeepLinks.extract("happ://routing/off"))
    }

    @Test
    fun `requestImport holds happ routing links for confirmation with rule summary before applying`() {
        val app = newState()
        val link = sampleRoutingLink(name = "Corp Split", activate = true)
        assertTrue(HappRouting.isLink(link))

        app.requestImport(link)
        val pending = app.pendingImport.value
        assertNotNull("Expected pendingImport to be populated", pending)
        assertEquals(1, pending!!.names.size)
        val desc = pending.names.single()
        assertTrue("Expected profile name in confirmation: $desc", desc.contains("Corp Split"))
        assertTrue("Expected rule summary in confirmation: $desc", desc.contains("direct.example.com"))
        assertTrue("Expected proxy site in confirmation: $desc", desc.contains("proxy.example.com"))

        // Profile must NOT be applied before confirmation
        assertNull(app.routingProfiles.value.active)
        assertTrue(app.routingProfiles.value.entries.isEmpty())

        // Dismissing leaves routing untouched
        app.dismissImport()
        assertNull(app.pendingImport.value)
        assertTrue(app.routingProfiles.value.entries.isEmpty())

        // Re-request and confirm
        app.requestImport(link)
        assertNotNull(app.pendingImport.value)
        app.addTextNow(app.pendingImport.value!!.text)
        app.dismissImport()

        assertEquals("Corp Split", app.routingProfiles.value.active)
        assertEquals("Corp Split", app.settings.value.activeRoutingProfile?.name)

        // Now requestImport for happ://routing/off
        app.requestImport("happ://routing/off")
        val offPending = app.pendingImport.value
        assertNotNull(offPending)
        assertEquals(listOf(tr("routing_profile_off")), offPending!!.names)
        // Still active until confirmed
        assertEquals("Corp Split", app.routingProfiles.value.active)

        app.addTextNow(offPending.text)
        app.dismissImport()
        assertNull(app.routingProfiles.value.active)
        assertNull(app.settings.value.activeRoutingProfile)
    }

    @Test
    fun `inactive routing profile import does not fetch geo files until selected`() {
        val app = newState()
        val inactiveWithGeo = sampleRoutingLink(
            name = "Deferred Geo",
            activate = false,
            geositeUrl = "https://203.0.113.10:1/unreachable-geosite.dat"
        )
        assertTrue(app.importRoutingLink(inactiveWithGeo))
        val entry = app.routingProfiles.value.find("Deferred Geo")
        assertNotNull(entry)
        assertNull(app.routingProfiles.value.active)
        assertNull(app.routingProfiles.value.pending)
        // Because activate=false, ensureGeoFiles must not fetch or record an error
        Thread.sleep(150)
        val after = app.routingProfiles.value.find("Deferred Geo")!!
        assertNull(after.filesAt)
        assertNull(after.filesTriedAt)
        assertNull(after.filesError)
    }

    @Test
    fun `AppState imports vmess base64 JSON, vless XHTTP, WireGuard INI, and chat messages with routing links`() {
        val app = newState()

        val vmessJson = """
            {
              "v": "2",
              "ps": "VMess-XHTTP-Node",
              "add": "203.0.113.20",
              "port": "443",
              "id": "11111111-2222-3333-4444-555555555555",
              "aid": "0",
              "scy": "chacha20-poly1305",
              "net": "xhttp",
              "type": "none",
              "mode": "packet-up",
              "host": "cdn.example.com",
              "path": "/xhttp",
              "tls": "tls",
              "sni": "sni.example.com",
              "alpn": "h2,http/1.1",
              "fp": "chrome"
            }
        """.trimIndent()
        val vmessB64Link = "vmess://" + Base64.getEncoder().encodeToString(vmessJson.toByteArray(Charsets.UTF_8))
        val pubKey = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
        val vlessXhttpLink = "vless://11111111-2222-3333-4444-555555555555@203.0.113.21:8443" +
            "?type=xhttp&security=reality&path=%2Fsplit&host=edge.example.com&mode=stream-one" +
            "&sni=reality.example.com&pbk=$pubKey&sid=01ab&fp=firefox#VLESS-Reality-Node"

        // Deep-link preview describes both links
        app.requestImport("$vmessB64Link\n$vlessXhttpLink")
        val pending = app.pendingImport.value
        assertNotNull(pending)
        assertEquals(
            listOf("VMess-XHTTP-Node · 203.0.113.20", "VLESS-Reality-Node · 203.0.113.21"),
            pending!!.names
        )
        app.dismissImport()

        // Import chat text containing both proxy links and a Happ routing link
        val routingLink = sampleRoutingLink(name = "ChatProfile", activate = true)
        val chatMessage = "Here are your keys:\n$vmessB64Link\n$vlessXhttpLink\nAnd routing: $routingLink"
        app.addTextNow(chatMessage)

        val configs = app.configurations.value
        assertEquals(2, configs.size)
        val first = configs.first { it.name == "VMess-XHTTP-Node" }
        assertEquals(OutboundProtocol.VMESS, first.outboundProtocol)
        assertEquals("chacha20-poly1305", first.vmessSecurity)
        assertEquals("xhttp", first.transport)
        assertEquals(com.mythaia.data.model.XHttpMode.PACKET_UP, first.xhttp?.mode)
        assertEquals("/xhttp", first.xhttp?.path)
        assertEquals("cdn.example.com", first.xhttp?.host)
        assertEquals("tls", first.security)

        val second = configs.first { it.name == "VLESS-Reality-Node" }
        assertEquals(OutboundProtocol.VLESS, second.outboundProtocol)
        assertEquals("xhttp", second.transport)
        assertEquals(com.mythaia.data.model.XHttpMode.STREAM_ONE, second.xhttp?.mode)
        assertNotNull(second.reality)
        assertEquals("reality.example.com", second.reality?.serverName)
        assertEquals("01ab", second.reality?.shortId?.joinToString("") { "%02x".format(it) })

        assertEquals("ChatProfile", app.routingProfiles.value.active)

        // Also test WireGuard INI import via requestImport and addTextNow
        val wgIni = """
            [Interface]
            PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
            Address = 10.66.66.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
            Endpoint = 203.0.113.99:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        app.requestImport(wgIni)
        assertEquals(listOf("WireGuard · 203.0.113.99"), app.pendingImport.value?.names)
        app.dismissImport()
        app.addTextNow(wgIni)
        assertEquals(3, app.configurations.value.size)
        assertTrue(app.configurations.value.any { it.outboundProtocol == OutboundProtocol.WIREGUARD && it.serverAddress == "203.0.113.99" })
    }

    @Test
    fun `Compose Desktop scenes render App, HomeScreen, ProxiesScreen, and SettingsScreen with Happ keys and routing`() {
        val app = newState()
        app.importRoutingLink(sampleRoutingLink(name = "Desktop UI Profile", activate = true))

        val subId = UUID.randomUUID()
        val store = DesktopStore()
        val sub = Subscription(
            id = subId,
            name = "Provider Managed Sub",
            url = "https://panel.example.com/sub",
            hideSettings = true,
            pinned = true,
            announce = "Maintenance on Sunday",
            supportUrl = "https://support.example.com",
            webPageUrl = "https://account.example.com",
            expire = (System.currentTimeMillis() / 1000L) + 86_400L,
            subInfo = Subscription.SubInfo(
                text = "Plan active",
                color = "green",
                buttonText = "Dashboard",
                buttonLink = "https://account.example.com"
            )
        )
        store.saveSubscriptions(listOf(sub))
        val server = ProxyConfiguration(
            name = "Frankfurt #1",
            serverAddress = "203.0.113.50",
            serverPort = 443u,
            uuid = UUID.fromString("11111111-2222-3333-4444-555555555555"),
            encryption = "none",
            outboundProtocol = OutboundProtocol.VLESS,
            subscriptionId = subId,
            description = "10 Gbps · Gaming & Streaming"
        )
        store.saveConfigurations(listOf(server))
        app.shutdown()

        val hydrated = AppState(store, nativeAvailable = false)
        state = hydrated
        hydrated.updateSettings {
            it.copy(
                setSystemProxy = false,
                activeGroupId = subId.toString(),
                excludedRoutes = listOf("203.0.113.0/24"),
                managedSettings = mapOf("source" to "Provider Managed Sub", "ping-type" to "tcp")
            )
        }

        // Render full App with pendingImport confirmation dialog active
        hydrated.requestImport(sampleRoutingLink(name = "Incoming Link Profile", activate = true))
        val appScene = ImageComposeScene(width = 1040, height = 720)
        try {
            appScene.setContent {
                App(hydrated)
            }
            appScene.render(nanoTime = 1_000_000L)
            appScene.render(nanoTime = 20_000_000L)
        } finally {
            appScene.close()
        }
        hydrated.dismissImport()

        // Render HomeScreen (shows active routing profile pill and provider server)
        val homeScene = ImageComposeScene(width = 1040, height = 720)
        try {
            homeScene.setContent {
                MaterialTheme {
                    HomeScreen(hydrated, onOpenProxies = {})
                }
            }
            homeScene.render(nanoTime = 1_000_000L)
        } finally {
            homeScene.close()
        }

        // Render ProxiesScreen (shows pinned subscription, ProviderNotices, server description, hidden endpoint "—")
        val proxiesScene = ImageComposeScene(width = 1040, height = 720)
        try {
            proxiesScene.setContent {
                MaterialTheme {
                    ProxiesScreen(hydrated)
                }
            }
            proxiesScene.render(nanoTime = 1_000_000L)
        } finally {
            proxiesScene.close()
        }

        // Render SettingsScreen (shows managedSettings banner, excludedRoutes, routingProfiles dropdown & rule summary)
        val settingsScene = ImageComposeScene(width = 1040, height = 720)
        try {
            settingsScene.setContent {
                MaterialTheme {
                    SettingsScreen(hydrated)
                }
            }
            settingsScene.render(nanoTime = 1_000_000L)
        } finally {
            settingsScene.close()
        }
    }
}
