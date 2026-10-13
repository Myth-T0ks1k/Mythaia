package com.mythaia.vpn.mitm

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPOutputStream

/**
 * The framing codec of the HTTP/1.1 MITM bridge. Every expected value here is
 * derived independently of the codec — a URL assembled from the parts the RFC
 * says make it, a body hand-concatenated from the chunks before they were
 * framed, a gzip stream produced by java.util.zip rather than by the codec's own
 * encoder — so a test passes only when the codec agrees with the spec, not when
 * it agrees with itself.
 *
 * The codec is driven through an in-memory [MitmByteLeg] double, [FakeByteLeg],
 * which can split the wire bytes across several [receive] calls to exercise the
 * reader's re-buffering across chunk boundaries.
 */
class Http1CodecTest {

    private val codec = Http1Codec()

    // MARK: - Request parsing

    @Test
    fun `an origin-form GET plus Host reconstructs an absolute https URL`() = runBlocking {
        val wire = crlf(
            "GET /search?q=mythaia HTTP/1.1",
            "Host: example.com",
            "Accept: text/html",
            "",
            ""
        )
        val parsed = codec.readRequest(FakeByteLeg(wire))!!

        assertEquals("GET", parsed.message.method)
        // https + Host authority + origin-form target, assembled by hand.
        assertEquals("https://example.com/search?q=mythaia", parsed.message.url)
        assertEquals(0, parsed.message.body.size)
        assertEquals("text/html", parsed.message.header("Accept"))
    }

    @Test
    fun `a POST Content-Length body is read as exactly that many bytes`() = runBlocking {
        val body = "hello world" // 11 bytes
        val wire = crlf(
            "POST /submit HTTP/1.1",
            "Host: example.com",
            "Content-Type: text/plain",
            "Content-Length: ${body.length}",
            "",
            ""
        ) + body.toByteArray(StandardCharsets.ISO_8859_1)

        // Split the wire mid-body to prove the reader stitches receives together.
        val parsed = codec.readRequest(FakeByteLeg(splitAt(wire, wire.size - 5)))!!

        assertEquals("POST", parsed.message.method)
        assertEquals("https://example.com/submit", parsed.message.url)
        assertArrayEquals(body.toByteArray(StandardCharsets.ISO_8859_1), parsed.message.body)
        assertFalse(parsed.bodyWasDecoded)
    }

    // MARK: - Chunked response parsing

    @Test
    fun `a chunked response dechunks to the concatenated chunk data`() = runBlocking {
        // Two chunks, sizes in hex: 5 = "Hello", 7 = ", world".
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Transfer-Encoding: chunked",
            "",
            "5", "Hello",
            "7", ", world",
            "0",
            "",
            ""
        )
        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!

        // Expected body is the chunk payloads concatenated by hand, no framing.
        assertArrayEquals("Hello, world".toByteArray(StandardCharsets.ISO_8859_1), parsed.message.body)
        assertEquals(200, parsed.message.status)
    }

    @Test
    fun `a chunked body with a trailer is dechunked and the trailer consumed`() = runBlocking {
        // 4 = "Wiki", 5 = "pedia", then a 0-chunk, a trailer field, and the blank line.
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Transfer-Encoding: chunked",
            "",
            "4", "Wiki",
            "5", "pedia",
            "0",
            "Expires: Wed, 21 Oct 2026 07:28:00 GMT",
            "",
            ""
        )
        val leg = FakeByteLeg(wire)
        val parsed = codec.readResponse(leg, requestMethod = "GET", requestUrl = "https://x/")!!

        assertArrayEquals("Wikipedia".toByteArray(StandardCharsets.ISO_8859_1), parsed.message.body)
        // The trailer and final blank line were consumed, so nothing is pushed back.
        assertNull(leg.receive())
    }

    // MARK: - Serialisation

    @Test
    fun `serialize of a parsed Content-Length request round-trips through parse`() = runBlocking {
        val body = "name=mythaia"
        val wire = crlf(
            "POST /submit?x=1 HTTP/1.1",
            "Host: example.com",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: ${body.length}",
            "",
            ""
        ) + body.toByteArray(StandardCharsets.ISO_8859_1)

        val first = codec.readRequest(FakeByteLeg(wire))!!
        val out = codec.serialize(first.message, first)
        val second = codec.readRequest(FakeByteLeg(out))!!

        assertEquals(first.message.method, second.message.method)
        assertEquals(first.message.url, second.message.url)
        assertArrayEquals(first.message.body, second.message.body)
        assertEquals("application/x-www-form-urlencoded", second.message.header("Content-Type"))
        assertEquals(body.length.toString(), second.message.header("Content-Length"))
    }

    @Test
    fun `serialize reframes a chunked response as Content-Length and drops Transfer-Encoding`() = runBlocking {
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Transfer-Encoding: chunked",
            "Content-Type: text/plain",
            "",
            "5", "Hello",
            "7", ", world",
            "0",
            "",
            ""
        )
        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!
        val out = codec.serialize(parsed.message, parsed)
        val text = String(out, StandardCharsets.ISO_8859_1)

        assertTrue("fresh Content-Length expected", text.contains("Content-Length: 12\r\n"))
        assertFalse("Transfer-Encoding must be dropped", text.lowercase().contains("transfer-encoding"))

        val reparsed = codec.readResponse(FakeByteLeg(out), requestMethod = "GET", requestUrl = "https://x/")!!
        assertArrayEquals("Hello, world".toByteArray(StandardCharsets.ISO_8859_1), reparsed.message.body)
    }

    // MARK: - Content coding

    @Test
    fun `a gzipped body decodes to the known plaintext`() = runBlocking {
        val plaintext = "Hello, Mythaia! This body travelled compressed."
        // Compress independently with java.util.zip, not with the codec.
        val gzipped = gzip(plaintext.toByteArray(StandardCharsets.UTF_8))

        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Content-Encoding: gzip",
            "Content-Type: text/plain",
            "Content-Length: ${gzipped.size}",
            "",
            ""
        ) + gzipped

        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!

        assertTrue(parsed.bodyWasDecoded)
        assertEquals(plaintext, String(parsed.message.body, StandardCharsets.UTF_8))
        // The raw (still-compressed) bytes are preserved for verbatim forwarding.
        assertArrayEquals(gzipped, parsed.rawBody)
    }

    @Test
    fun `an unmodified gzipped response is forwarded verbatim keeping its encoding`() = runBlocking {
        val plaintext = "keep me compressed"
        val gzipped = gzip(plaintext.toByteArray(StandardCharsets.UTF_8))
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Content-Encoding: gzip",
            "Content-Length: ${gzipped.size}",
            "",
            ""
        ) + gzipped

        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!
        // Body untouched by any rule: serialize forwards the original compressed bytes.
        val out = codec.serialize(parsed.message, parsed)

        val reparsed = codec.readResponse(FakeByteLeg(out), requestMethod = "GET", requestUrl = "https://x/")!!
        assertEquals("gzip", reparsed.message.header("Content-Encoding"))
        assertArrayEquals(gzipped, reparsed.rawBody)
        assertEquals(plaintext, String(reparsed.message.body, StandardCharsets.UTF_8))
    }

    @Test
    fun `a modified body is forwarded decompressed with Content-Encoding dropped`() = runBlocking {
        val gzipped = gzip("original".toByteArray(StandardCharsets.UTF_8))
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Content-Encoding: gzip",
            "Content-Length: ${gzipped.size}",
            "",
            ""
        ) + gzipped

        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!
        val edited = parsed.message.copy(body = "edited by a rule".toByteArray(StandardCharsets.UTF_8))
        val out = codec.serialize(edited, parsed)

        val reparsed = codec.readResponse(FakeByteLeg(out), requestMethod = "GET", requestUrl = "https://x/")!!
        assertNull("encoding must be dropped once the body is edited", reparsed.message.header("Content-Encoding"))
        assertFalse(reparsed.bodyWasDecoded)
        assertEquals("edited by a rule", String(reparsed.message.body, StandardCharsets.UTF_8))
    }

    @Test
    fun `the 4 MiB cap refuses an over-large decompressed stream`() = runBlocking {
        // 5 MiB of one repeated byte: gzips tiny, inflates past the 4 MiB cap.
        val huge = ByteArray(5 * 1024 * 1024) { 'A'.code.toByte() }
        val gzipped = gzip(huge)
        assertTrue("compressed payload should be small", gzipped.size < Http1Codec.MAX_BUFFERED_BODY_BYTES)

        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Content-Encoding: gzip",
            "Content-Length: ${gzipped.size}",
            "",
            ""
        ) + gzipped

        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")!!

        // The bomb is refused: the body is NOT decoded, and the compressed bytes
        // pass through untouched rather than being inflated into memory.
        assertFalse(parsed.bodyWasDecoded)
        assertArrayEquals(gzipped, parsed.message.body)
    }

    // MARK: - HEAD responses and layered transfer-codings

    @Test
    fun `a HEAD response keeps its declared Content-Length instead of reframing to zero`() = runBlocking {
        // A HEAD response has no body but its Content-Length states what the GET
        // would have returned; re-deriving a Content-Length from the empty body
        // would tell the client the resource is 0 bytes.
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Content-Type: application/pdf",
            "Content-Length: 1048576",
            "",
            ""
        )
        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "HEAD", requestUrl = "https://x/big")!!
        assertEquals(0, parsed.message.body.size)

        val out = codec.serialize(parsed.message, parsed, requestMethod = "HEAD")
        val text = String(out, StandardCharsets.ISO_8859_1)
        assertTrue("the declared length must survive", text.contains("Content-Length: 1048576"))
        assertFalse("a spurious zero length must not be emitted", text.contains("Content-Length: 0"))
        // No body bytes follow the head.
        assertTrue(text.endsWith("\r\n\r\n"))
    }

    @Test
    fun `a Transfer-Encoding layering a content-coding on chunked is refused`() = runBlocking {
        // "gzip, chunked" would leave the body gzip-compressed after de-chunking;
        // the codec fails closed rather than drop the coding and mislabel the body.
        val wire = crlf(
            "HTTP/1.1 200 OK",
            "Transfer-Encoding: gzip, chunked",
            "",
            ""
        )
        try {
            codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/")
            throw AssertionError("expected a refusal for a layered Transfer-Encoding")
        } catch (_: Http1ProtocolException) {
            // expected
        }
    }

    // MARK: - Over-cap bodies are deferred and relayed, not refused

    @Test
    fun `a Content-Length body past the cap is deferred and relayed byte-for-byte with the next message intact`() = runBlocking {
        val body = ByteArray(Http1Codec.MAX_BUFFERED_BODY_BYTES + 1) { (it % 251).toByte() }
        val head = crlf(
            "HTTP/1.1 200 OK",
            "Content-Type: application/octet-stream",
            "Content-Length: ${body.size}",
            "",
            ""
        )
        val next = crlf("HTTP/1.1 204 No Content", "", "")
        // Split inside the body so the relay has both an overread prefix and leg pulls to forward.
        val leg = FakeByteLeg(splitAt(head + body + next, head.size + 1000))

        val parsed = codec.readResponse(leg, requestMethod = "GET", requestUrl = "https://x/big")!!
        val relay = parsed.deferredBody
        assertNotNull("a body past the cap is deferred, not refused", relay)
        requireNotNull(relay)
        assertEquals("nothing of the body is buffered", 0, parsed.message.body.size)
        assertArrayEquals("the head is kept exactly as received", head, relay.rawHead)
        assertEquals(Http1Codec.RelayFraming.ContentLength(body.size.toLong()), relay.framing)

        val sink = FakeByteLeg(ByteArray(0))
        relay.relayTo(sink)
        assertArrayEquals(body, sink.sent.toByteArray())

        // The pipelined next response was pushed back onto the leg and reads as usual.
        val following = codec.readResponse(leg, requestMethod = "GET", requestUrl = "https://x/next")!!
        assertEquals(204, following.message.status)
        assertNull(following.deferredBody)
    }

    @Test
    fun `a chunked body that grows past the cap is relayed re-chunked with content, extensions and trailers kept`() = runBlocking {
        // Five 1 MiB chunks: the fifth would carry the buffered total past 4 MiB.
        val chunk = ByteArray(1024 * 1024) { 'c'.code.toByte() }
        val wire = ByteArrayOutputStream()
        wire.write(crlf("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", ""))
        repeat(5) {
            wire.write(crlf("100000;ext=1", ""))
            wire.write(chunk)
            wire.write(crlf("", ""))
        }
        wire.write(crlf("0", "X-Trailer: t", "", ""))
        wire.write(crlf("HTTP/1.1 204 No Content", "", ""))
        val leg = FakeByteLeg(wire.toByteArray())

        val parsed = codec.readResponse(leg, requestMethod = "GET", requestUrl = "https://x/big")!!
        val relay = parsed.deferredBody!!
        assertEquals(Http1Codec.RelayFraming.Chunked, relay.framing)

        val sink = FakeByteLeg(ByteArray(0))
        relay.relayTo(sink)
        // De-chunked by hand (not by the codec): the content is the five chunks' data,
        // whatever chunk boundaries the relay chose, and the trailer travelled on.
        val (content, trailers, end) = dechunk(sink.sent.toByteArray(), 0)
        assertEquals(5 * 1024 * 1024, content.size)
        assertTrue(content.all { it == 'c'.code.toByte() })
        assertEquals(listOf("X-Trailer: t"), trailers)
        assertEquals("nothing follows the terminating blank line", sink.sent.size(), end)

        val following = codec.readResponse(leg, requestMethod = "GET", requestUrl = "https://x/next")!!
        assertEquals(204, following.message.status)
    }

    @Test
    fun `a single chunk larger than the cap is relayed as the very bytes it arrived in`() = runBlocking {
        val chunk = ByteArray(Http1Codec.MAX_BUFFERED_BODY_BYTES + 1) { 'h'.code.toByte() }
        val chunkedBody = crlf(java.lang.Integer.toHexString(chunk.size), "") + chunk + crlf("", "0", "", "")
        val wire = crlf("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", "") + chunkedBody

        val parsed = codec.readResponse(FakeByteLeg(wire), requestMethod = "GET", requestUrl = "https://x/big")!!
        val relay = parsed.deferredBody!!

        val sink = FakeByteLeg(ByteArray(0))
        relay.relayTo(sink)
        // Nothing was buffered before the cap tripped, so the relayed stream is the
        // original chunked stream byte-for-byte.
        assertArrayEquals(chunkedBody, sink.sent.toByteArray())
    }

    @Test
    fun `relayContentTo strips the chunk framing and hands over only the content`() = runBlocking {
        val chunk = ByteArray(1024 * 1024) { 'k'.code.toByte() }
        val wire = ByteArrayOutputStream()
        wire.write(crlf("HTTP/1.1 200 OK", "Transfer-Encoding: chunked", "", ""))
        repeat(5) {
            wire.write(crlf("100000", ""))
            wire.write(chunk)
            wire.write(crlf("", ""))
        }
        wire.write(crlf("0", "X-Trailer: dropped", "", ""))

        val relay = codec.readResponse(FakeByteLeg(wire.toByteArray()), "GET", "https://x/big")!!.deferredBody!!
        val sink = FakeByteLeg(ByteArray(0))
        relay.relayContentTo(sink)
        val content = sink.sent.toByteArray()
        assertEquals(5 * 1024 * 1024, content.size)
        assertTrue(content.all { it == 'k'.code.toByte() })
    }

    @Test
    fun `a close-delimited body past the cap is relayed to EOF`() = runBlocking {
        val body = ByteArray(Http1Codec.MAX_BUFFERED_BODY_BYTES + 7) { (it % 13).toByte() }
        val wire = crlf("HTTP/1.1 200 OK", "Content-Type: application/octet-stream", "", "") + body
        val parsed = codec.readResponse(FakeByteLeg(splitAt(wire, wire.size / 2)), "GET", "https://x/old")!!
        val relay = parsed.deferredBody!!
        assertEquals(Http1Codec.RelayFraming.UntilClose, relay.framing)

        val sink = FakeByteLeg(ByteArray(0))
        relay.relayTo(sink)
        assertArrayEquals(body, sink.sent.toByteArray())
    }

    // MARK: - Request framing and targets

    @Test
    fun `an empty-body POST is framed with Content-Length 0 but a plain GET stays unframed`() {
        val post = String(codec.serialize(HttpMessage.request("POST", "https://example.com/submit")), StandardCharsets.ISO_8859_1)
        assertTrue("a strict origin answers an unframed empty POST with 411", post.contains("\r\nContent-Length: 0\r\n"))

        val get = String(codec.serialize(HttpMessage.request("GET", "https://example.com/")), StandardCharsets.ISO_8859_1)
        assertFalse("a GET with Content-Length: 0 makes some servers balk", get.lowercase().contains("content-length"))

        // A DELETE that itself declared a zero length keeps a length.
        val delete = String(
            codec.serialize(
                HttpMessage.request("DELETE", "https://example.com/x", listOf(HttpHeader("Content-Length", "0")))
            ),
            StandardCharsets.ISO_8859_1
        )
        assertTrue(delete.contains("\r\nContent-Length: 0\r\n"))
    }

    @Test
    fun `a request with no reconstructible URL keeps the client's own request-target`() = runBlocking {
        // Asterisk-form names no resource, so no URL — but "*" is what the origin must see.
        val options = codec.readRequest(FakeByteLeg(crlf("OPTIONS * HTTP/1.1", "Host: example.com", "", "")))!!
        assertNull(options.message.url)
        assertEquals("*", options.requestTarget)
        val optionsOut = String(codec.serialize(options.message, options), StandardCharsets.ISO_8859_1)
        assertTrue(optionsOut, optionsOut.startsWith("OPTIONS * HTTP/1.1\r\n"))

        // Origin-form with no Host: no authority to build a URL from, same path onward.
        val noHost = codec.readRequest(FakeByteLeg(crlf("GET /no-host?x=1 HTTP/1.1", "", "")))!!
        assertNull(noHost.message.url)
        val noHostOut = String(codec.serialize(noHost.message, noHost), StandardCharsets.ISO_8859_1)
        assertTrue(noHostOut, noHostOut.startsWith("GET /no-host?x=1 HTTP/1.1\r\n"))
    }

    @Test
    fun `the expect-continue hook fires between head and body only for a request that frames a body`() = runBlocking {
        val body = "payload"
        val wire = crlf(
            "POST /up HTTP/1.1",
            "Host: example.com",
            "Expect: 100-continue",
            "Content-Length: ${body.length}",
            "",
            ""
        ) + body.toByteArray(StandardCharsets.ISO_8859_1)
        var fired = 0
        val parsed = codec.readRequest(FakeByteLeg(wire)) { fired++ }!!
        assertEquals(1, fired)
        assertEquals(body, String(parsed.message.body, StandardCharsets.ISO_8859_1))

        // No body framing: there is nothing to wait for, so no interim 100.
        var firedWithoutBody = 0
        codec.readRequest(FakeByteLeg(crlf("GET /x HTTP/1.1", "Host: example.com", "Expect: 100-continue", "", ""))) {
            firedWithoutBody++
        }
        assertEquals(0, firedWithoutBody)
    }

    // MARK: - Diagnostics never leak a query or a header value

    @Test
    fun `a framing error does not quote the request line's query or a header value`() = runBlocking {
        // Four tokens on the request line: malformed, and the query must stay out of the message.
        val badLine = crlf("GET /login?token=SECRET-QUERY extra HTTP/1.1", "Host: example.com", "", "")
        try {
            codec.readRequest(FakeByteLeg(badLine))
            throw AssertionError("expected a refusal for a malformed request line")
        } catch (e: Http1ProtocolException) {
            assertFalse(e.message, e.message!!.contains("SECRET-QUERY"))
        }

        // A header line with no colon: whatever it carries is not echoed.
        val badHeader = crlf("GET / HTTP/1.1", "Host: example.com", "Cookie session=SECRET-COOKIE", "", "")
        try {
            codec.readRequest(FakeByteLeg(badHeader))
            throw AssertionError("expected a refusal for a header line without a colon")
        } catch (e: Http1ProtocolException) {
            assertFalse(e.message, e.message!!.contains("SECRET-COOKIE"))
        }

        // A long malformed line is cut short rather than dumped whole.
        val longLine = crlf("GET " + "/".repeat(500) + " HTTP/1.1 junk", "", "")
        try {
            codec.readRequest(FakeByteLeg(longLine))
            throw AssertionError("expected a refusal for a malformed request line")
        } catch (e: Http1ProtocolException) {
            assertTrue(e.message, e.message!!.length < 200)
        }
    }

    // MARK: - Test helpers

    /** Joins [lines] with CRLF, including a trailing CRLF after the last line. */
    private fun crlf(vararg lines: String): ByteArray =
        lines.joinToString("\r\n").toByteArray(StandardCharsets.ISO_8859_1)

    /** De-chunked content, trailer lines, and the offset just past the terminating blank line. */
    private data class Dechunked(val content: ByteArray, val trailers: List<String>, val end: Int)

    /**
     * A hand-rolled chunked decoder (RFC 9112 §7.1), independent of the codec:
     * size lines are hex before any `;`, each chunk's data is followed by CRLF,
     * a `0` chunk ends the data, and trailer lines run to a blank line.
     */
    private fun dechunk(data: ByteArray, start: Int): Dechunked {
        val content = ByteArrayOutputStream()
        val trailers = ArrayList<String>()
        var pos = start
        fun readLine(): String {
            var i = pos
            while (!(data[i] == '\r'.code.toByte() && data[i + 1] == '\n'.code.toByte())) i++
            val line = String(data, pos, i - pos, StandardCharsets.ISO_8859_1)
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
        while (true) {
            val trailer = readLine()
            if (trailer.isEmpty()) break
            trailers.add(trailer)
        }
        return Dechunked(content.toByteArray(), trailers, pos)
    }

    private fun splitAt(data: ByteArray, index: Int): List<ByteArray> =
        listOf(data.copyOfRange(0, index), data.copyOfRange(index, data.size))

    private fun gzip(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        GZIPOutputStream(out).use { it.write(data) }
        return out.toByteArray()
    }

    /**
     * An in-memory [MitmByteLeg] that replays a fixed list of chunks, honours
     * [prependToReceiveBuffer], and records whatever is sent.
     */
    private class FakeByteLeg(private val chunks: List<ByteArray>) : MitmByteLeg {
        constructor(all: ByteArray) : this(listOf(all))

        private var index = 0
        private var prepended: ByteArray = ByteArray(0)
        val sent = ByteArrayOutputStream()

        override val negotiatedAlpn: String? = null

        override suspend fun receive(): ByteArray? {
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

        override fun close() {}
    }
}
