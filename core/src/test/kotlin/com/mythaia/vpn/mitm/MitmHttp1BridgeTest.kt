package com.mythaia.vpn.mitm

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    // MARK: - Over-cap bodies pass through unrewritten, keep-alive intact

    @Test
    fun `a 5 MiB Content-Length response passes through intact and keep-alive carries the next request`() = runBlocking {
        // A body rule that WOULD fire: the small response proves it, the big one
        // proves an over-cap body is passed through untouched instead.
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.RESPONSE, "example\\.com", MitmOperation.BodyReplace("a", "b"))
        )
        val big = ByteArray(5 * 1024 * 1024) { 'a'.code.toByte() }
        val bigResponse = bytes(
            "HTTP/1.1 200 OK",
            "Content-Type: application/octet-stream",
            "Content-Length: ${big.size}",
            "",
            ""
        ) + big
        val client = FakeByteLeg(
            bytes("GET /big HTTP/1.1", "Host: example.com", "", "") +
                bytes("GET /small HTTP/1.1", "Host: example.com", "", "")
        )
        val upstream = FakeByteLeg(bigResponse + simpleResponse(body = "aaa"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        val received = client.sent()
        assertArrayEquals("the big response went out byte-for-byte", bigResponse, received.copyOfRange(0, bigResponse.size))
        val second = Http1Codec().readResponse(
            FakeByteLeg(received.copyOfRange(bigResponse.size, received.size)), "GET", "https://example.com/small"
        )!!
        assertEquals("the next exchange still ran, rules and all", "bbb", String(second.message.body, latin1))

        val upstreamCodec = Http1Codec()
        val upstreamLeg = FakeByteLeg(upstream.sent())
        assertEquals("https://example.com/big", upstreamCodec.readRequest(upstreamLeg)!!.message.url)
        assertEquals("https://example.com/small", upstreamCodec.readRequest(upstreamLeg)!!.message.url)
    }

    @Test
    fun `a chunked response past the cap passes through with its content intact and keep-alive still works`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.RESPONSE, "example\\.com", MitmOperation.BodyReplace("x", "y"))
        )
        val head = bytes("HTTP/1.1 200 OK", "Content-Type: text/plain", "Transfer-Encoding: chunked", "", "")
        val chunk = ByteArray(1024 * 1024) { 'x'.code.toByte() }
        val wire = ByteArrayOutputStream()
        wire.write(head)
        repeat(5) {
            wire.write(bytes("100000", ""))
            wire.write(chunk)
            wire.write(bytes("", ""))
        }
        wire.write(bytes("0", "", ""))
        val client = FakeByteLeg(
            bytes("GET /big HTTP/1.1", "Host: example.com", "", "") +
                bytes("GET /small HTTP/1.1", "Host: example.com", "", "")
        )
        val upstream = FakeByteLeg(wire.toByteArray() + simpleResponse(body = "xxx"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        val received = client.sent()
        assertArrayEquals("the head goes out verbatim", head, received.copyOfRange(0, head.size))
        val (content, end) = dechunk(received, head.size)
        assertEquals(5 * 1024 * 1024, content.size)
        assertTrue("the content is untouched by the body rule", content.all { it == 'x'.code.toByte() })

        val second = Http1Codec().readResponse(
            FakeByteLeg(received.copyOfRange(end, received.size)), "GET", "https://example.com/small"
        )!!
        assertEquals("yyy", String(second.message.body, latin1))
    }

    @Test
    fun `an over-cap request body is streamed upstream behind the rewritten head`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.REQUEST, "example\\.com", MitmOperation.HeaderAdd("X-Tag", "added"))
        )
        val big = ByteArray(Http1Codec.MAX_BUFFERED_BODY_BYTES + 1) { 'u'.code.toByte() }
        val client = FakeByteLeg(
            bytes("PUT /upload HTTP/1.1", "Host: example.com", "Content-Length: ${big.size}", "", "") + big +
                bytes("GET /after HTTP/1.1", "Host: example.com", "", "")
        )
        val upstream = FakeByteLeg(simpleResponse(body = "stored") + simpleResponse(body = "after"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSet).run()

        val sent = upstream.sent()
        val headEnd = indexOfBlankLine(sent) + 4
        val head = String(sent.copyOfRange(0, headEnd), latin1)
        assertTrue(head, head.startsWith("PUT /upload HTTP/1.1\r\n"))
        assertTrue("the head rule applied to the streamed request", head.contains("\r\nX-Tag: added\r\n"))
        assertTrue("the original length frames the streamed body", head.contains("\r\nContent-Length: ${big.size}\r\n"))
        assertArrayEquals(big, sent.copyOfRange(headEnd, headEnd + big.size))
        // Keep-alive: the following request reached upstream too.
        val after = Http1Codec().readRequest(FakeByteLeg(sent.copyOfRange(headEnd + big.size, sent.size)))!!
        assertEquals("https://example.com/after", after.message.url)
    }

    // MARK: - A transparent rewrite is dialed to its new origin

    @Test
    fun `a transparent rewrite onto another host is dialed there rather than sent to the SNI host`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(
                HttpPhase.REQUEST,
                "https://example\\.com/moved",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://other.example:8443/landed"))
            )
        )
        val client = FakeByteLeg(
            bytes("GET /moved HTTP/1.1", "Host: example.com", "", "") +
                bytes("GET /stays HTTP/1.1", "Host: example.com", "", "")
        )
        val home = FakeByteLeg(simpleResponse(body = "from example.com"))
        val other = FakeByteLeg(simpleResponse(body = "from other.example"))
        val dials = ArrayList<String>()

        MitmHttp1Bridge.forTls(
            client, home, ruleSet,
            originHost = "example.com", originPort = 443,
            dialUpstream = { host, port, alpn -> dials.add("$host:$port:${alpn.joinToString()}"); other }
        ).run()

        assertEquals("exactly one extra dial, to the rewritten origin", listOf("other.example:8443:http/1.1"), dials)
        val toOther = Http1Codec().readRequest(FakeByteLeg(other.sent()))!!
        assertEquals("https://other.example:8443/landed", toOther.message.url)
        assertEquals("other.example:8443", toOther.message.header("Host"))
        val toHome = Http1Codec().readRequest(FakeByteLeg(home.sent()))!!
        assertEquals("the unrewritten request still goes to the SNI host", "https://example.com/stays", toHome.message.url)

        // The client saw both responses, in request order.
        val clientCodec = Http1Codec()
        val clientLeg = FakeByteLeg(client.sent())
        val first = clientCodec.readResponse(clientLeg, "GET", "https://other.example:8443/landed")!!
        val second = clientCodec.readResponse(clientLeg, "GET", "https://example.com/stays")!!
        assertEquals("from other.example", String(first.message.body, latin1))
        assertEquals("from example.com", String(second.message.body, latin1))
        assertTrue("the rewritten-origin leg is closed with the connection", other.isClosed)
    }

    // MARK: - Expect: 100-continue

    @Test
    fun `an Expect 100-continue request gets an interim 100 before its body is read and the Expect is not forwarded`() = runBlocking {
        val body = "upload"
        val head = bytes("POST /up HTTP/1.1", "Host: example.com", "Expect: 100-continue", "Content-Length: ${body.length}", "", "")
        // A client that behaves like a real one: it sends the body only once it has
        // seen the 100. If the bridge pulls the body first, this leg reports EOF and
        // the request never reaches upstream.
        val client = ContinueGatedLeg(head, body.toByteArray(latin1))
        val upstream = FakeByteLeg(simpleResponse(body = "ok"))

        MitmHttp1Bridge.forTls(client, upstream, ruleSetOf()).run()

        val clientText = String(client.sent(), latin1)
        assertTrue(clientText, clientText.startsWith("HTTP/1.1 100 Continue\r\n\r\n"))
        val forwarded = Http1Codec().readRequest(FakeByteLeg(upstream.sent()))!!
        assertEquals("upload", String(forwarded.message.body, latin1))
        assertNull("the expectation was answered here; the origin must not wait on it", forwarded.message.header("Expect"))

        // After the interim 100 the final response follows.
        val clientCodec = Http1Codec()
        val clientLeg = FakeByteLeg(client.sent())
        assertEquals(100, clientCodec.readResponse(clientLeg, "POST", "https://example.com/up")!!.message.status)
        val finalResponse = clientCodec.readResponse(clientLeg, "POST", "https://example.com/up")!!
        assertEquals("ok", String(finalResponse.message.body, latin1))
    }

    // MARK: - Helpers

    private fun ruleSetOf(vararg rules: MitmRule): MitmRuleSet =
        MitmRuleSet(name = "test", domainSuffixes = listOf("example.com"), rules = rules.toList())

    private fun indexOfBlankLine(data: ByteArray): Int {
        for (i in 0..data.size - 4) {
            if (data[i] == '\r'.code.toByte() && data[i + 1] == '\n'.code.toByte() &&
                data[i + 2] == '\r'.code.toByte() && data[i + 3] == '\n'.code.toByte()
            ) return i
        }
        throw AssertionError("no blank line in the data")
    }

    /**
     * A hand-rolled chunked decoder (RFC 9112 §7.1), independent of the codec,
     * returning the content and the offset just past the terminating blank line.
     */
    private fun dechunk(data: ByteArray, start: Int): Pair<ByteArray, Int> {
        val content = ByteArrayOutputStream()
        var pos = start
        fun readLine(): String {
            var i = pos
            while (!(data[i] == '\r'.code.toByte() && data[i + 1] == '\n'.code.toByte())) i++
            val line = String(data, pos, i - pos, latin1)
            pos = i + 2
            return line
        }
        while (true) {
            val size = readLine().substringBefore(';').trim().toInt(16)
            if (size == 0) break
            content.write(data, pos, size)
            pos += size
            check(readLine().isEmpty()) { "chunk data must end with CRLF" }
        }
        while (readLine().isNotEmpty()) { /* trailers */ }
        return content.toByteArray() to pos
    }

    /**
     * A client leg that yields its request [head], then its [body] only once a
     * `100 Continue` has been written to it — and EOF instead if it has not.
     */
    private class ContinueGatedLeg(private val head: ByteArray, private val body: ByteArray) : MitmByteLeg {
        private var stage = 0
        private var prepended: ByteArray = ByteArray(0)
        private val out = ByteArrayOutputStream()

        override val negotiatedAlpn: String? = null

        override suspend fun receive(): ByteArray? {
            if (prepended.isNotEmpty()) {
                val buffered = prepended
                prepended = ByteArray(0)
                return buffered
            }
            return when (stage++) {
                0 -> head
                1 -> if (String(out.toByteArray(), StandardCharsets.ISO_8859_1).startsWith("HTTP/1.1 100 Continue\r\n\r\n")) body else null
                else -> null
            }
        }

        override suspend fun send(data: ByteArray) { out.write(data) }
        override fun prependToReceiveBuffer(data: ByteArray) {
            if (data.isNotEmpty()) prepended = if (prepended.isEmpty()) data.copyOf() else prepended + data
        }
        override fun close() {}
        fun sent(): ByteArray = out.toByteArray()
    }

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

        val isClosed: Boolean get() = closed

        fun sent(): ByteArray = sent.toByteArray()
    }
}
