package com.mythaia.vpn.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the Encrypted DNS settings field is allowed to contain. */
class DnsUpstreamTest {

    @Test
    fun `a DoH host without a path gets the well-known one`() {
        // Someone typing just a hostname means the standard endpoint, not a
        // server rooted at /.
        assertEquals(
            DnsUpstream.Doh("https://dns.google/dns-query"),
            DnsUpstream.from("doh", "dns.google")
        )
        assertEquals(
            DnsUpstream.Doh("https://dns.google/dns-query"),
            DnsUpstream.from("doh", "https://dns.google/")
        )
    }

    @Test
    fun `an explicit DoH path is kept`() {
        assertEquals(
            DnsUpstream.Doh("https://doh.example/resolve"),
            DnsUpstream.from("doh", "https://doh.example/resolve")
        )
    }

    @Test
    fun `DoT takes host, host with port, and bracketed IPv6`() {
        assertEquals(DnsUpstream.Dot("dns.google", 853), DnsUpstream.from("dot", "dns.google"))
        assertEquals(DnsUpstream.Dot("dns.google", 5353), DnsUpstream.from("dot", "dns.google:5353"))
        assertEquals(DnsUpstream.Dot("dns.google", 853), DnsUpstream.from("dot", "tls://dns.google"))

        // A bare IPv6 literal has colons of its own, so it is only read as
        // host:port when bracketed.
        assertEquals(DnsUpstream.Dot("2001:4860:4860::8888", 853),
            DnsUpstream.from("dot", "2001:4860:4860::8888"))
        assertEquals(DnsUpstream.Dot("2001:4860:4860::8888", 853),
            DnsUpstream.from("dot", "[2001:4860:4860::8888]"))
        assertEquals(DnsUpstream.Dot("2001:4860:4860::8888", 5353),
            DnsUpstream.from("dot", "[2001:4860:4860::8888]:5353"))
    }

    @Test
    fun `unusable settings fall back rather than throwing`() {
        assertNull(DnsUpstream.from("doh", ""))
        assertNull(DnsUpstream.from("dot", "   "))
        assertNull(DnsUpstream.from("dot", "host:notaport"))
        assertNull(DnsUpstream.from("dot", "host:0"))
        assertNull(DnsUpstream.from("dot", "host:70000"))
        assertNull(DnsUpstream.from("dot", "[unclosed"))
        // An unknown protocol is not an error either — the caller reads null as
        // "use the system resolver".
        assertNull(DnsUpstream.from("doq", "dns.google"))
    }

    @Test
    fun `bootstrapHost names only what still needs resolving`() {
        // A literal address needs no bootstrap.
        assertNull(DnsUpstream.Plain("1.1.1.1").bootstrapHost)
        assertNull(DnsUpstream.Dot("1.1.1.1").bootstrapHost)
        assertNull(DnsUpstream.System.bootstrapHost)

        // A name does, and DnsCache excludes it so the lookup cannot recurse.
        assertEquals("dns.google", DnsUpstream.Dot("dns.google").bootstrapHost)
        assertEquals("dns.google", DnsUpstream.Doh("https://dns.google/dns-query").bootstrapHost)
    }

    @Test
    fun `text is stable enough to log`() {
        assertTrue(DnsUpstream.Plain("1.1.1.1", 53).text.contains("1.1.1.1"))
        assertTrue(DnsUpstream.Dot("dns.google", 853).text.startsWith("tls://"))
        assertEquals("https://dns.google/dns-query",
            DnsUpstream.Doh("https://dns.google/dns-query").text)
    }
}
