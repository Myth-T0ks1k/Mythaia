package com.mythaia.data.network

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/** The provider keys Happ sells behind a Provider ID: app settings, routing, messages, descriptions. */
class HappProviderKeysTest {

    private fun read(headers: Map<String, String> = emptyMap(), body: String = "", secure: Boolean = true) =
        SubscriptionMetadata.read({ headers[it] }, SubscriptionMetadata.bodyFields(body), secure)

    private fun apply(current: Subscription, panel: SubscriptionFetcher.PanelInfo, allowed: Boolean = true) =
        SubscriptionMetadata.applyTo(current, SubscriptionFetcher.Result(emptyList(), null, null, null, null, null, panel), settingsAllowed = allowed)

    private val base = Subscription(name = "Provider", url = "https://panel.example.com/sub/TOKEN")

    @Test
    fun `settings come only over verified TLS`() {
        val body = "#hide-settings: 1\n#fragmentation-enable: 0\n#routing: happ://routing/off\n#routing-enable: 0\n"
        assertTrue(read(body = body, secure = false).settings.isEmpty())
        assertNull(read(body = body, secure = false).routing)
        assertNull(read(body = body, secure = false).routingEnable)
        val secure = read(body = body)
        assertEquals("1", secure.settings["hide-settings"])
        assertEquals("happ://routing/off", secure.routing)
        assertEquals(false, secure.routingEnable)
    }

    @Test
    fun `the subscription's own settings land on it and lapse when withdrawn`() {
        val panel = read(
            headers = mapOf("change-user-agent" to "Happ/3.0"),
            body = """
                #subscription-autoconnect: true
                #subscription-autoconnect-type: lowestdelay
                #subscription-ping-onopen-enabled: 1
                #subscriptions-sort-type: alphabet
                #subscriptions-collapse: 0
                #hide-settings: true
                #subscription-pin: 1
            """.trimIndent()
        )
        val sub = apply(base.copy(collapsed = true), panel)
        assertEquals("Happ/3.0", sub.userAgent)
        assertEquals(RemoteSettings.AUTO_LOWEST_DELAY, sub.autoConnect)
        assertTrue(sub.pingOnOpen)
        assertEquals(RemoteSettings.SORT_ALPHABET, sub.serverSort)
        assertFalse(sub.collapsible)
        assertFalse(sub.collapsed)
        assertTrue(sub.hideSettings)
        assertTrue(sub.pinned)
        assertTrue(sub.managedSettings)

        // The panel stops sending them: the restrictions lift, the pin stays.
        val later = apply(sub, read())
        assertNull(later.userAgent)
        assertNull(later.autoConnect)
        assertFalse(later.hideSettings)
        assertTrue(later.collapsible)
        assertTrue(later.pinned)
    }

    @Test
    fun `a pin applies when it changes, so the user can unpin`() {
        val pinned = apply(base, read(body = "#subscription-pin: true"))
        assertTrue(pinned.pinned)
        val unpinnedByUser = pinned.copy(pinned = false)
        assertFalse(apply(unpinnedByUser, read(body = "#subscription-pin: true")).pinned)
        assertFalse(apply(unpinnedByUser, read(body = "#subscription-pin: false")).pinned)
        assertTrue(apply(apply(unpinnedByUser, read(body = "#subscription-pin: false")), read(body = "#subscription-pin: 1")).pinned)
    }

    @Test
    fun `with the user's switch off nothing is taken`() {
        val sub = apply(base, read(body = "#hide-settings: 1\n#change-user-agent: X\n#subscription-pin: 1"), allowed = false)
        assertFalse(sub.hideSettings)
        assertNull(sub.userAgent)
        assertFalse(sub.pinned)
    }

    @Test
    fun `a User-Agent that could write headers is refused`() {
        assertNull(RemoteSettings.userAgent(mapOf("change-user-agent" to "A\r\nX-Evil: 1")))
        assertNull(RemoteSettings.userAgent(mapOf("change-user-agent" to "Ünicode")))
        assertEquals("clash-verge/v2", RemoteSettings.userAgent(mapOf("change-user-agent" to " clash-verge/v2 ")))
    }

    @Test
    fun `app keys are acted on only when they change`() {
        val settings = mapOf("ping-type" to "tcp", "hide-settings" to "1", "fragmentation-enable" to "1")
        assertEquals(mapOf("ping-type" to "tcp", "fragmentation-enable" to "1"), RemoteSettings.changedAppKeys(emptyMap(), settings))
        assertEquals(mapOf("fragmentation-enable" to "1"), RemoteSettings.changedAppKeys(mapOf("ping-type" to "tcp", "fragmentation-enable" to "0"), settings))
    }

    @Test
    fun `values map onto Mythaia's settings`() {
        assertEquals(LatencyKind.HTTP, RemoteSettings.latencyKind("proxy-head"))
        assertEquals(LatencyKind.TCP, RemoteSettings.latencyKind("icmp"))
        assertNull(RemoteSettings.latencyKind("smoke"))
        assertEquals("https://www.gstatic.com/generate_204", RemoteSettings.checkUrl("https://www.gstatic.com/generate_204"))
        assertNull(RemoteSettings.checkUrl("ftp://x"))

        val fragment = RemoteSettings.fragment(
            FragmentSettings(),
            mapOf("fragmentation-enable" to "true", "fragmentation-packets" to "1-3", "fragmentation-length" to "50-100", "fragmentation-interval" to "5")
        )!!
        assertTrue(fragment.isEnabled)
        assertEquals(50..100, fragment.lengthRange)
        assertEquals(5..5, fragment.intervalRange)
        assertFalse(RemoteSettings.fragment(FragmentSettings(), mapOf("fragmentation-enable" to "0"))!!.isEnabled)
        assertNull(RemoteSettings.fragment(FragmentSettings(), emptyMap()))

        assertEquals(
            listOf("10.0.0.0/8", "192.168.1.0/24", "8.8.8.8/32"),
            RemoteSettings.excludeRoutes(listOf("10.0.0.0/8"), mapOf("exclude-routes" to "192.168.1.0/24, 8.8.8.8 bogus"))
        )
        assertEquals(listOf("172.16.0.0/12"), RemoteSettings.excludeRoutes(listOf("10.0.0.0/8"), mapOf("exclude-routes-set" to "172.16.0.0/12")))
        assertNull(RemoteSettings.excludeRoutes(emptyList(), emptyMap()))

        assertEquals(listOf("com.google.chrome", "org.telegram.messenger"), RemoteSettings.packages("com.google.chrome, org.telegram.messenger,not a package"))
        assertEquals("bypass", RemoteSettings.perAppMode("BYPASS"))
    }

    @Test
    fun `routing arrives in a header, a body line, or a line of its own`() {
        assertEquals("happ://routing/off", read(headers = mapOf("routing" to "happ://routing/off")).routing)
        assertEquals("happ://routing/off", read(body = "#routing: happ://routing/off").routing)
        assertEquals("happ://routing/off", LinkExtractor.unwrap("happ://routing/off"))
        assertEquals(listOf("happ://routing/onadd/e30="), LinkExtractor.extract("turn this on: happ://routing/onadd/e30= thanks"))
    }

    @Test
    fun `a message is raised once per text`() {
        val sub = base.copy(announce = "Maintenance tonight", subInfo = Subscription.SubInfo("Renew soon", buttonText = "Pay", buttonLink = "https://pay.example"))
        val (first, marked) = ProviderMessages.due(sub)
        assertEquals(listOf(ProviderMessages.Kind.ANNOUNCE, ProviderMessages.Kind.INFO), first.map { it.kind })
        assertEquals("https://pay.example", first[1].link)
        assertTrue(ProviderMessages.due(marked).first.isEmpty())
        val changed = marked.copy(announce = "Maintenance moved to Friday")
        assertEquals(listOf("Maintenance moved to Friday"), ProviderMessages.due(changed).first.map { it.text })
        // What the user saw on import is not raised later.
        assertTrue(ProviderMessages.due(ProviderMessages.markSeen(sub)).first.isEmpty())
    }

    @Test
    fun `the expiry warning is raised when due, once, and again once expired`() {
        val day = 24 * 60 * 60 * 1000L
        val now = 1_000_000_000_000L
        val sub = base.copy(expire = now + 2 * day, expireNotice = true)
        assertTrue(ProviderMessages.due(sub.copy(expire = now + 5 * day), now).first.isEmpty())
        val (soon, marked) = ProviderMessages.due(sub, now)
        assertEquals(Subscription.ExpiryWarning.Soon(2), soon.single().expiry)
        assertTrue(ProviderMessages.due(marked, now + day).first.isEmpty())
        assertEquals(Subscription.ExpiryWarning.Expired, ProviderMessages.due(marked, now + 3 * day).first.single().expiry)
        // Renewed and running out again: a new date, a new warning.
        assertEquals(1, ProviderMessages.due(marked.copy(expire = now + 32 * day), now + 30 * day).first.size)
        assertTrue(ProviderMessages.due(sub.copy(expireNotice = false), now).first.isEmpty())
    }

    @Test
    fun `serverDescription sits under the name`() {
        val description = Base64.getEncoder().encodeToString("Happ the best".toByteArray())
        val vless = ProxyConfiguration.fromUrl(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=tcp#Frankfurt?serverDescription=$description"
        )
        assertEquals("Frankfurt", vless.name)
        assertEquals("Happ the best", vless.description)

        val encoded = ProxyConfiguration.fromUrl(
            "trojan://secret@example.com:443?security=tls#%F0%9F%87%A9%F0%9F%87%AA%20Berlin%3FserverDescription%3D" +
                java.net.URLEncoder.encode(Base64.getEncoder().encodeToString("Ein sehr langer Text, viel zu lang".toByteArray()), "UTF-8")
        )
        assertEquals("🇩🇪 Berlin", encoded.name)
        assertEquals(30, encoded.description!!.length)

        val plain = ProxyConfiguration.fromUrl("vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls#Plain")
        assertNull(plain.description)
        assertEquals("Plain", plain.name)
    }
}
