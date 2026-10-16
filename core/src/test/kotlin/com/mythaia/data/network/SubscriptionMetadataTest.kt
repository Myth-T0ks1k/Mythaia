package com.mythaia.data.network

import com.mythaia.data.model.Subscription
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class SubscriptionMetadataTest {

    private fun read(
        headers: Map<String, String> = emptyMap(),
        body: String = "",
        secure: Boolean = true
    ): SubscriptionFetcher.PanelInfo =
        SubscriptionMetadata.read({ headers[it] }, SubscriptionMetadata.bodyFields(body), secure)

    private fun result(panel: SubscriptionFetcher.PanelInfo, name: String? = null) =
        SubscriptionFetcher.Result(emptyList(), name, null, null, null, null, panel)

    private val base = Subscription(name = "Panel", url = "https://panel.example.com:8443/sub/TOKEN?fmt=raw")

    @Test
    fun `body lines are read as Happ writes them`() {
        val fields = SubscriptionMetadata.bodyFields(
            """
            #profile-title: My VPN
            # Announce :  base64:${Base64.getEncoder().encodeToString("Привет".toByteArray())}
            #profile-title: second one loses
            #not a field
            vless://id@example.com:443#node
            """.trimIndent()
        )
        assertEquals("My VPN", fields["profile-title"])
        assertEquals("Привет", SubscriptionMetadata.decode(fields["announce"]))
        assertEquals(setOf("profile-title", "announce"), fields.keys)
    }

    @Test
    fun `a header wins over the same key in the body`() {
        val panel = read(
            headers = mapOf("profile-title" to "From header"),
            body = "#profile-title: From body\n#support-url: https://t.me/help\n"
        )
        assertEquals("From header", panel.title)
        assertEquals("https://t.me/help", panel.supportUrl)
    }

    @Test
    fun `flags are on for true or 1 only`() {
        assertEquals(true, read(body = "#subscription-auto-update-open-enable: 1").updateOnOpen)
        assertEquals(true, read(body = "#subscription-auto-update-open-enable: TRUE").updateOnOpen)
        assertEquals(false, read(body = "#subscription-auto-update-open-enable: yes please").updateOnOpen)
        assertNull(read().updateOnOpen)
        assertEquals(false, read(body = "#subscription-auto-update-enable: 0").autoUpdate)
        assertEquals(true, read(body = "#notification-subs-expire: 1").expireNotice)
    }

    @Test
    fun `keys that move the subscription need verified TLS and https`() {
        val body = """
            #new-url: https://new.example.com/sub/T
            #new-domain: other.example.com
            #fallback-url: https://backup.example.com/sub/T
            #fronting-target: 104.16.1.1, cdn.example.net:443, bad host!
            #fronting-sni: www.example.org
            """.trimIndent()
        val secure = read(body = body)
        assertEquals("https://new.example.com/sub/T", secure.newUrl)
        assertEquals("other.example.com", secure.newDomain)
        assertEquals("https://backup.example.com/sub/T", secure.fallbackUrl)
        assertEquals(listOf("104.16.1.1", "cdn.example.net:443"), secure.frontTargets)
        assertEquals("www.example.org", secure.frontSni)

        val plain = read(body = body, secure = false)
        assertNull(plain.newUrl)
        assertNull(plain.newDomain)
        assertNull(plain.fallbackUrl)
        assertNull(plain.frontTargets)
        assertNull(plain.frontSni)

        assertNull(read(body = "#new-url: http://new.example.com/sub").newUrl)
        assertNull(read(body = "#fallback-url: javascript:alert(1)").fallbackUrl)
    }

    @Test
    fun `sub-info and the expiry notice`() {
        val panel = read(
            body = """
                #sub-info-text: Pay by Friday
                #sub-info-color: GREEN
                #sub-info-button-text: Pay
                #sub-info-button-link: https://pay.example.com
                #sub-expire: 1
                #sub-expire-button-link: https://pay.example.com/renew
                """.trimIndent()
        )
        assertEquals(Subscription.SubInfo("Pay by Friday", "green", "Pay", "https://pay.example.com"), panel.subInfo)
        assertEquals(true, panel.expireNotice)
        assertEquals("https://pay.example.com/renew", panel.expireButtonLink)
        assertEquals("blue", read(body = "#sub-info-text: x\n#sub-info-color: purple").subInfo?.color)
    }

    @Test
    fun `new-url moves the subscription and keeps its fronting`() {
        val fronted = base.copy(frontSni = "www.example.org", frontTargets = listOf("104.16.1.1"))
        val moved = SubscriptionMetadata.applyTo(fronted, result(read(body = "#new-url: https://new.example.com/s/T")))
        assertEquals("https://new.example.com/s/T", moved.url)
        assertEquals("www.example.org", moved.frontSni)
        assertEquals(listOf("104.16.1.1"), moved.frontTargets)
    }

    @Test
    fun `new-url in Happ's fronted form brings its own fronting`() {
        val moved = SubscriptionMetadata.applyTo(
            base,
            result(read(body = "#new-url: https://cdn.example.net/s/T#Main?resolve-address=104.16.2.2&host=panel2.example.com"))
        )
        assertEquals("https://panel2.example.com/s/T", moved.url)
        assertEquals("cdn.example.net", moved.frontSni)
        assertEquals(listOf("104.16.2.2"), moved.frontTargets)
    }

    @Test
    fun `new-domain keeps the path, the query and the port`() {
        val moved = SubscriptionMetadata.applyTo(base, result(read(body = "#new-domain: Mirror.Example.com")))
        assertEquals("https://mirror.example.com:8443/sub/TOKEN?fmt=raw", moved.url)
        val withPort = SubscriptionMetadata.applyTo(base, result(read(body = "#new-domain: mirror.example.com:443")))
        assertEquals("https://mirror.example.com:443/sub/TOKEN?fmt=raw", withPort.url)
    }

    @Test
    fun `fronting keys set, change and stop the fronting`() {
        val on = SubscriptionMetadata.applyTo(
            base, result(read(body = "#fronting-target: 104.16.1.1\n#fronting-sni: www.example.org"))
        )
        assertEquals(listOf("104.16.1.1"), on.frontTargets)
        assertEquals("www.example.org", on.frontSni)
        assertEquals(base.url, on.url)

        // An SNI alone dials the panel's own address, as in a link.
        val sniOnly = SubscriptionMetadata.applyTo(base, result(read(body = "#fronting-sni: www.example.org")))
        assertEquals(listOf("panel.example.com:8443"), sniOnly.frontTargets)

        val off = SubscriptionMetadata.applyTo(on, result(read(body = "#fronting-target: off")))
        assertTrue(off.frontTargets.isEmpty())
        assertNull(off.frontSni)

        // Saying nothing leaves the fronting as it was.
        assertEquals(on.frontTargets, SubscriptionMetadata.applyTo(on, result(read())).frontTargets)
    }

    @Test
    fun `Happ's resolve-address and host front the URL's own host, once`() {
        val subscription = Subscription(name = "P", url = "https://cdn.example.net/sub/T")
        val panel = read(body = "#resolve-address: 104.16.3.3\n#host: panel.example.com")
        val once = SubscriptionMetadata.applyTo(subscription, result(panel))
        assertEquals("https://panel.example.com/sub/T", once.url)
        assertEquals("cdn.example.net", once.frontSni)
        assertEquals(listOf("104.16.3.3"), once.frontTargets)
        // The next refresh says the same and changes nothing.
        assertEquals(once.copy(lastUpdate = 0), SubscriptionMetadata.applyTo(once, result(panel)).copy(lastUpdate = 0))
    }

    @Test
    fun `messages are withdrawn when the panel stops sending them, the rest is kept`() {
        val first = SubscriptionMetadata.applyTo(
            base.copy(lastFailure = 5, lastFailureMessage = "HTTP 502"),
            result(read(body = "#announce: Maintenance\n#sub-info-text: Hi\n#support-url: https://t.me/x\n#profile-update-interval: 6"))
        )
        assertEquals("Maintenance", first.announce)
        assertEquals("Hi", first.subInfo?.text)
        assertNull(first.lastFailure)
        assertNull(first.lastFailureMessage)
        assertFalse(first.isFailing)

        val second = SubscriptionMetadata.applyTo(first, result(read()))
        assertNull(second.announce)
        assertNull(second.subInfo)
        assertEquals("https://t.me/x", second.supportUrl)
        assertEquals(6, second.updateIntervalHours)
    }

    @Test
    fun `a customised name is kept`() {
        val renamed = base.copy(name = "Mine", isNameCustomized = true)
        assertEquals("Mine", SubscriptionMetadata.applyTo(renamed, result(read(), name = "Panel name")).name)
        assertEquals("Panel name", SubscriptionMetadata.applyTo(base, result(read(), name = "Panel name")).name)
    }

    @Test
    fun `replaceHost keeps user info and handles IPv6`() {
        assertEquals("https://u:p@b.example/x", SubscriptionMetadata.replaceHost("https://u:p@a.example/x", "b.example"))
        assertEquals("https://[2001:db8::1]:8443/x?y=1", SubscriptionMetadata.replaceHost("https://a.example:8443/x?y=1", "[2001:db8::1]"))
        assertEquals("https://b.example:9000", SubscriptionMetadata.replaceHost("https://[2001:db8::1]:8443", "b.example:9000"))
    }

    @Test
    fun `the expiry warning comes three days ahead`() {
        val day = 24 * 60 * 60 * 1000L
        val now = 1_000_000_000_000L
        val sub = Subscription(name = "P", url = "https://p.example", expireNotice = true)
        assertNull(sub.copy(expire = now + 4 * day).expiryWarning(now))
        assertEquals(Subscription.ExpiryWarning.Soon(3), sub.copy(expire = now + 3 * day).expiryWarning(now))
        // Whole days, as the usage card counts them.
        assertEquals(Subscription.ExpiryWarning.Soon(2), sub.copy(expire = now + 2 * day + day / 4).expiryWarning(now))
        assertEquals(Subscription.ExpiryWarning.Soon(1), sub.copy(expire = now + 1).expiryWarning(now))
        assertEquals(Subscription.ExpiryWarning.Expired, sub.copy(expire = now).expiryWarning(now))
        // Only when the panel asked for it.
        assertNull(sub.copy(expire = now, expireNotice = false).expiryWarning(now))
    }
}
