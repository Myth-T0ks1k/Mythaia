package com.mythaia.vpn.mitm

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The HTTP/1.1 MITM bridge loop, driven by two in-memory [MitmByteLeg] doubles —
 * a client leg scripted with the requests a client would send, and an upstream
 * leg scripted with the responses a server would send. The bridge's effect is
 * read back off what each leg *received*, re-parsed with a fresh [Http1Codec], so
 * every assertion is against independently-derived values (a status, a header, a
 * body the test itself wrote) and never against the bridge's own serialized bytes.
 *
 * The byte-identical passthrough cases hand the bridge messages already in the
 * codec's canonical wire form (Host first, a single trailing Content-Length, no
 * Transfer-Encoding), so a correct round-trip is an exact byte match.
 */
class MitmHttp1BridgeTest {

    private val latin1 = StandardCharsets.ISO_8859_1

    // MARK: - Request-phase reject

    @Test
    fun `a request-phase reject answers the client and never writes upstream`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(
                HttpPhase.REQUEST,
                "https://example\\.com/blocked",
                MitmOperation.Rewrite(MitmRewriteAction.Reject200Text("blocked by mythaia"))
            )
        )
        val client = FakeByteLeg(
            bytes(
                "GET /blocked HTTP/1.1",
                "Host: example.com",
                "",
                ""
            )
        )
        val upstream = FakeByteLeg(ByteArray(0))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        // Upstream was never dialed into: a reject short-circuits before forwarding.
        assertEquals(0, upstream.sent().size)

        val answered = Http1Codec().readResponse(
            FakeByteLeg(client.sent()), requestMethod = "GET", requestUrl = "https://example.com/blocked"
        )!!
        assertEquals(200, answered.message.status)
        assertEquals("blocked by mythaia", String(answered.message.body, latin1))
        assertEquals("text/plain; charset=utf-8", answered.message.header("Content-Type"))
        assertNotNull("a synthesized response carries a Date stamp", answered.message.header("Date"))
    }

    // MARK: - Request header-add

    @Test
    fun `a header-add rule forwards a modified request upstream`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.REQUEST, "example\\.com", MitmOperation.HeaderAdd("X-Mythaia-Tag", "present"))
        )
        val client = FakeByteLeg(
            bytes(
                "GET /page HTTP/1.1",
                "Host: example.com",
                "Accept: text/html",
                "",
                ""
            )
        )
        val upstream = FakeByteLeg(simpleResponse(body = "ok"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        val forwarded = Http1Codec().readRequest(FakeByteLeg(upstream.sent()))!!
        assertEquals("GET", forwarded.message.method)
        assertEquals("https://example.com/page", forwarded.message.url)
        assertEquals("present", forwarded.message.header("X-Mythaia-Tag"))
        // The original headers survive the edit.
        assertEquals("text/html", forwarded.message.header("Accept"))

        // The client still received the upstream response.
        val seen = Http1Codec().readResponse(
            FakeByteLeg(client.sent()), requestMethod = "GET", requestUrl = "https://example.com/page"
        )!!
        assertEquals(200, seen.message.status)
        assertEquals("ok", String(seen.message.body, latin1))
    }

    // MARK: - Response body-replace

    @Test
    fun `a response body-replace rewrites the upstream response before the client sees it`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.RESPONSE, "example\\.com", MitmOperation.BodyReplace("foo", "bar"))
        )
        val client = FakeByteLeg(
            bytes("GET /page HTTP/1.1", "Host: example.com", "", "")
        )
        val upstream = FakeByteLeg(simpleResponse(body = "foo baz foo"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        val seen = Http1Codec().readResponse(
            FakeByteLeg(client.sent()), requestMethod = "GET", requestUrl = "https://example.com/page"
        )!!
        // Independently-derived expected body: every "foo" becomes "bar".
        assertEquals("bar baz bar", String(seen.message.body, latin1))

        // The request still reached upstream unmodified in shape.
        val forwarded = Http1Codec().readRequest(FakeByteLeg(upstream.sent()))!!
        assertEquals("https://example.com/page", forwarded.message.url)
    }

    // MARK: - Byte-identical passthrough

    @Test
    fun `an unmatched exchange passes through byte-identical`() = runBlocking {
        // A rule set whose gate cannot match this host: nothing fires either phase.
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.REQUEST, "https://other\\.example/", MitmOperation.HeaderAdd("X-No", "op"))
        )

        // Both messages are already in the codec's canonical wire form.
        val requestWire = bytes(
            "GET /page HTTP/1.1",
            "Host: example.com",
            "Accept: text/html",
            "",
            ""
        )
        val responseWire = bytes(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain",
            "Content-Length: 5",
            "",
            ""
        ) + "hello".toByteArray(latin1)

        val client = FakeByteLeg(requestWire)
        val upstream = FakeByteLeg(responseWire)

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        assertArrayEquals("request forwarded byte-for-byte", requestWire, upstream.sent())
        assertArrayEquals("response returned byte-for-byte", responseWire, client.sent())
    }

    // MARK: - Keep-alive

    @Test
    fun `keep-alive carries a second request on the same legs`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.REQUEST, "example\\.com", MitmOperation.HeaderAdd("X-Seq", "tag"))
        )
        // Two pipelined requests on the one client leg.
        val client = FakeByteLeg(
            bytes("GET /one HTTP/1.1", "Host: example.com", "", "") +
                bytes("GET /two HTTP/1.1", "Host: example.com", "", "")
        )
        // Two responses on the one upstream leg, definite-length so the connection
        // stays alive between them.
        val upstream = FakeByteLeg(simpleResponse(body = "one") + simpleResponse(body = "two"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        // Both requests reached upstream, in order, each carrying the added header.
        val upstreamCodec = Http1Codec()
        val upstreamLeg = FakeByteLeg(upstream.sent())
        val req1 = upstreamCodec.readRequest(upstreamLeg)!!
        val req2 = upstreamCodec.readRequest(upstreamLeg)!!
        assertEquals("https://example.com/one", req1.message.url)
        assertEquals("https://example.com/two", req2.message.url)
        assertEquals("tag", req2.message.header("X-Seq"))
        assertNull("exactly two requests were forwarded", upstreamCodec.readRequest(upstreamLeg))

        // Both responses came back to the client, in order.
        val clientCodec = Http1Codec()
        val clientLeg = FakeByteLeg(client.sent())
        val resp1 = clientCodec.readResponse(clientLeg, "GET", "https://example.com/one")!!
        val resp2 = clientCodec.readResponse(clientLeg, "GET", "https://example.com/two")!!
        assertEquals("one", String(resp1.message.body, latin1))
        assertEquals("two", String(resp2.message.body, latin1))
    }

    @Test
    fun `a Connection close request ends the loop after one exchange`() = runBlocking {
        val client = FakeByteLeg(
            bytes("GET /page HTTP/1.1", "Host: example.com", "Connection: close", "", "") +
                bytes("GET /again HTTP/1.1", "Host: example.com", "", "")
        )
        val upstream = FakeByteLeg(simpleResponse(body = "x") + simpleResponse(body = "y"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSetOf()).run()

        // The second request must NOT have been forwarded: close ended the loop.
        val upstreamLeg = FakeByteLeg(upstream.sent())
        val only = Http1Codec().readRequest(upstreamLeg)!!
        assertEquals("https://example.com/page", only.message.url)
        assertNull("the close request forbids a second exchange", Http1Codec().readRequest(upstreamLeg))
    }

    // MARK: - Helpers

    private fun ruleSetOf(vararg rules: MitmRule): MitmRuleSet =
        MitmRuleSet(name = "test", domainSuffixes = listOf("example.com"), rules = rules.toList())

    /** Joins [lines] with CRLF (trailing CRLF after the last), as Latin-1 wire bytes. */
    private fun bytes(vararg lines: String): ByteArray =
        lines.joinToString("\r\n").toByteArray(latin1)

    /** A canonical, definite-length 200 response whose body is [body]. */
    private fun simpleResponse(body: String): ByteArray =
        bytes(
            "HTTP/1.1 200 OK",
            "Content-Type: text/plain",
            "Content-Length: ${body.toByteArray(latin1).size}",
            "",
            ""
        ) + body.toByteArray(latin1)

    /**
     * An in-memory [MitmByteLeg] that replays [chunks] across [receive] calls,
     * honours [prependToReceiveBuffer] (the codec pushes back bytes it overread
     * into a pipelined next message), records everything [send] writes, and
     * reports end-of-stream once drained or closed.
     */
    private class FakeByteLeg(private val chunks: List<ByteArray>) : MitmByteLeg {
        constructor(all: ByteArray) : this(listOf(all))

        private var index = 0
        private var prepended: ByteArray = ByteArray(0)
        private var closed = false
        private val sent = ByteArrayOutputStream()

        override val negotiatedAlpn: String? = null

        override suspend fun receive(): ByteArray? {
            if (closed) return null
            if (prepended.isNotEmpty()) {
                val buffered = prepended
                prepended = ByteArray(0)
                return buffered
            }
            return if (index < chunks.size) chunks[index++] else null
        }

        override suspend fun send(data: ByteArray) {
            sent.write(data)
        }

        override fun prependToReceiveBuffer(data: ByteArray) {
            if (data.isEmpty()) return
            prepended = if (prepended.isEmpty()) data.copyOf() else prepended + data
        }

        override fun close() {
            closed = true
        }

        fun sent(): ByteArray = sent.toByteArray()
    }
}
