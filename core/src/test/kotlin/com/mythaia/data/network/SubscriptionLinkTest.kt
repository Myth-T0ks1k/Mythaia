package com.mythaia.data.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionLinkTest {

    @Test
    fun `fronting in the fragment is read and taken off the URL`() {
        val link = SubscriptionLink.parse(
            "https://panel.example.com/sub/AbC+123?lang=ru#front=104.16.1.1,cdn.example.net:443&sni=www.example.org"
        )!!
        assertEquals("https://panel.example.com/sub/AbC+123?lang=ru", link.url)
        assertEquals(listOf("104.16.1.1", "cdn.example.net:443"), link.frontTargets)
        assertEquals("www.example.org", link.frontSni)
        assertTrue(link.isFronted)
    }

    @Test
    fun `a URL without fronting comes back exactly as given`() {
        for (url in listOf(
            "https://sub.example.com/abc?token=1",
            "https://sub.example.com/abc#My%20VPN"
        )) {
            val link = SubscriptionLink.parse(url)!!
            assertEquals(url, link.url)
            assertFalse(link.isFronted)
            assertNull(link.frontSni)
        }
        assertNull(SubscriptionLink.parse("vless://id@example.com:443"))
        assertNull(SubscriptionLink.parse("not a link"))
    }

    @Test
    fun `a name alone in the fragment names the group and leaves the URL clean`() {
        val link = SubscriptionLink.parse("https://sub.example.com/abc?x=1#name=Home%20VPN")!!
        assertEquals("https://sub.example.com/abc?x=1", link.url)
        assertEquals("Home VPN", link.name)
        assertFalse(link.isFronted)
        val app = SubscriptionLink.parse("mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fabc&name=Bulk")!!
        assertEquals("https://sub.example.com/abc", SubscriptionLink.parse(app.toFragmentLink())!!.url)
        assertEquals("Bulk", SubscriptionLink.parse(app.toFragmentLink())!!.name)
    }

    @Test
    fun `an SNI alone fronts the panel's own address`() {
        val link = SubscriptionLink.parse("https://panel.example.com:8443/sub/x#sni=allowed.example.org")!!
        assertEquals(listOf("panel.example.com:8443"), link.frontTargets)
        assertEquals("allowed.example.org", link.frontSni)
    }

    @Test
    fun `the app link carries the encoded URL and the fronting`() {
        val link = SubscriptionLink.parse(
            "mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub%2FAbC%2B1%3Fa%3D1%26b%3D2" +
                "&front=104.16.1.1&front=203.0.113.10:443&sni=www.example.org&name=Family%20VPN"
        )!!
        assertEquals("https://panel.example.com/sub/AbC+1?a=1&b=2", link.url)
        assertEquals(listOf("104.16.1.1", "203.0.113.10:443"), link.frontTargets)
        assertEquals("www.example.org", link.frontSni)
        assertEquals("Family VPN", link.name)
    }

    @Test
    fun `a hand-written app link keeps the panel's own query`() {
        val link = SubscriptionLink.parse(
            "mythaia://import?url=https://panel.example.com/sub?token=1&lang=ru&front=104.16.1.1&front-sni=www.example.org"
        )!!
        assertEquals("https://panel.example.com/sub?token=1&lang=ru", link.url)
        assertEquals(listOf("104.16.1.1"), link.frontTargets)
        assertEquals("www.example.org", link.frontSni)
    }

    @Test
    fun `a Hiddify-style name after the hash is the group name`() {
        val link = SubscriptionLink.parse("mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fx&front=1.2.3.4#Work")!!
        assertEquals("https://sub.example.com/x", link.url)
        assertEquals("Work", link.name)
        assertEquals(listOf("1.2.3.4"), link.frontTargets)
    }

    @Test
    fun `both forms survive a round trip`() {
        val original = SubscriptionLink(
            url = "https://panel.example.com/sub/AbC+1?a=1&b=2",
            frontSni = "www.example.org",
            frontTargets = listOf("104.16.1.1", "[2606:4700::1]:443"),
            name = "Семья & друзья"
        )
        assertEquals(original, SubscriptionLink.parse(original.toAppLink()))
        assertEquals(original, SubscriptionLink.parse(original.toFragmentLink()))
        assertTrue(original.toAppLink().startsWith("mythaia://import?url=https%3A%2F%2Fpanel.example.com"))
    }

    @Test
    fun `no fronting means the plain URL in both forms`() {
        val plain = SubscriptionLink("https://sub.example.com/x")
        assertEquals("https://sub.example.com/x", plain.toFragmentLink())
        assertEquals("mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fx", plain.toAppLink())
    }

    @Test
    fun `the extractor turns an app link into the fragment form`() {
        val text = "Подписка: mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub&front=104.16.1.1&sni=www.example.org — открой в Mythaia"
        assertEquals(
            listOf("https://panel.example.com/sub#front=104.16.1.1&sni=www.example.org"),
            LinkExtractor.extract(text)
        )
        assertEquals(
            listOf("https://panel.example.com/sub#front=104.16.1.1&sni=www.example.org"),
            LinkExtractor.extract("https://panel.example.com/sub#front=104.16.1.1&sni=www.example.org")
        )
    }
}
