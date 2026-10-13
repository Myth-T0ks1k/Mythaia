package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.naive.http2.HpackDecoder
import com.mythaia.vpn.protocol.naive.http2.Http2Buffer
import com.mythaia.vpn.protocol.naive.http2.Http2Frame
import com.mythaia.vpn.protocol.naive.http2.Http2FrameFlags
import com.mythaia.vpn.protocol.naive.http2.Http2FrameType
import com.mythaia.vpn.protocol.naive.http2.Http2Framer
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The h2→h1 MITM bridge, driven end to end over an in-memory client [MitmByteLeg]
 * scripted with hand-built HTTP/2 frames, and a fake `dialUpstream` that returns a
 * canned HTTP/1.1 response leg.
 *
 * The inbound request header blocks are assembled from RFC 7541 static-table bytes
 * by hand (indexed fields `0x82`/`0x87`, literal-without-indexing `:path`/`:authority`),
 * never by any encoder in the tree; every response the bridge writes is read back
 * through the app's own [Http2Framer]/[HpackDecoder] on a *different* code path than
 * the one that wrote it, and the forwarded request is re-parsed with a fresh
 * [Http1Codec]. So no assertion is a tautology over the bridge's own output; each
 * checks an independently-derived value (a status, a header, a body the test wrote).
 */
class MitmHttp2BridgeTest {

    private val latin1 = StandardCharsets.ISO_8859_1
    private val ascii = StandardCharsets.US_ASCII

    // MARK: - Request-phase reject

    @Test
    fun `a request-phase reject answers the stream and never dials upstream`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(
                HttpPhase.REQUEST,
                "https://h/blocked",
                MitmOperation.Rewrite(MitmRewriteAction.Reject200Text("blocked"))
            )
        )
        val client = DuplexLeg()
        var dialCalled = false
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSet),
            dialUpstream = { _, _, _ -> dialCalled = true; ReplayLeg(ByteArray(0)) }
        )
        val job = launch { bridge.run() }
        try {
            client.feed(CLIENT_PREFACE + clientSettings() + headersFrame(1, getRequest("/blocked", "h")))

            val frames = collect(client)
            val (headers, body) = decodedResponse(frames, streamID = 1)!!
            assertEquals("200", statusOf(headers))
            assertEquals("text/plain; charset=utf-8", valueOf(headers, "content-type"))
            assertEquals("blocked", String(body, latin1))
            assertFalse("a reject must not dial upstream", dialCalled)
        } finally {
            job.cancel()
        }
    }

    // MARK: - Forward + response streamed back on the right stream

    @Test
    fun `a forward rule dials upstream and streams the rewritten response back on the request's stream`() = runBlocking {
        // A request-phase header-add: the edited request must reach upstream.
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.REQUEST, "h/page", MitmOperation.HeaderAdd("X-Mythaia", "present"))
        )
        val client = DuplexLeg()
        var seenAlpn: List<String>? = null
        val upstream = ReplayLeg(cannedResponse(body = "ok"))
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSet),
            dialUpstream = { _, _, alpn -> seenAlpn = alpn; upstream }
        )
        val job = launch { bridge.run() }
        try {
            client.feed(CLIENT_PREFACE + clientSettings() + headersFrame(3, getRequest("/page", "h")))

            val frames = collect(client)
            // The response came back on stream 3 (the request's own id), not any other.
            val (headers, body) = decodedResponse(frames, streamID = 3)!!
            assertEquals("200", statusOf(headers))
            assertEquals("ok", String(body, latin1))
            assertNull("no response leaked onto a different stream", decodedResponse(frames, streamID = 1))

            // The origin was dialed for http/1.1 and got the rewritten request.
            assertEquals(listOf("http/1.1"), seenAlpn)
            val forwarded = Http1Codec().readRequest(ReplayLeg(upstream.sent()))!!
            assertEquals("GET", forwarded.message.method)
            assertEquals("https://h/page", forwarded.message.url)
            assertEquals("present", forwarded.message.header("X-Mythaia"))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Concurrency: a slow stream does not head-of-line block a fast one

    @Test
    fun `two concurrent streams do not block each other`() = runBlocking {
        val client = DuplexLeg()
        val slowGate = CompletableDeferred<Unit>()
        // Each dial returns a fresh leg that decides, from the request it is handed,
        // whether to answer at once ("/fast") or wait on the gate ("/slow").
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSetOf()),
            dialUpstream = { _, _, _ -> GatedUpstreamLeg(slowGate) }
        )
        val job = launch { bridge.run() }
        try {
            client.feed(
                CLIENT_PREFACE + clientSettings() +
                    headersFrame(1, getRequest("/fast", "h")) +
                    headersFrame(3, getRequest("/slow", "h"))
            )

            // With the slow origin still gated, the fast stream has already answered
            // and the slow one has not — proving no head-of-line blocking.
            val before = collect(client)
            val fast = decodedResponse(before, streamID = 1)
            assertNotNull("the fast stream answers while the slow origin is blocked", fast)
            assertEquals("fast", String(fast!!.second, latin1))
            assertNull("the slow stream has not answered yet", decodedResponse(before, streamID = 3))

            // Release the slow origin; its response now comes back on its own stream.
            slowGate.complete(Unit)
            val after = collect(client)
            val slow = decodedResponse(after, streamID = 3)
            assertNotNull("the slow stream answers once its origin responds", slow)
            assertEquals("slow", String(slow!!.second, latin1))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Client RST_STREAM cancels the stream's upstream dial

    @Test
    fun `a client RST_STREAM cancels that stream's in-flight upstream dial`() = runBlocking {
        val client = DuplexLeg()
        val dialStarted = CompletableDeferred<Unit>()
        val dialCancelled = CompletableDeferred<Unit>()
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSetOf()),
            dialUpstream = { _, _, _ ->
                dialStarted.complete(Unit)
                try {
                    awaitCancellation() // a dial that never completes on its own
                } catch (e: CancellationException) {
                    dialCancelled.complete(Unit)
                    throw e
                }
            }
        )
        val job = launch { bridge.run() }
        try {
            client.feed(CLIENT_PREFACE + clientSettings() + headersFrame(1, getRequest("/page", "h")))
            // The exchange has reached the upstream dial and is parked there.
            withTimeout(2000) { dialStarted.await() }

            // Client aborts the stream: the dial must be cancelled, not run to completion.
            client.feed(Http2Framer.serialize(Http2Framer.rstStreamFrame(1, Http2Framer.ErrorCode.CANCEL)))
            withTimeout(2000) { dialCancelled.await() }
        } finally {
            job.cancel()
        }
    }

    // MARK: - A transparent rewrite is dialed to its new origin

    @Test
    fun `a transparent rewrite onto another origin dials that origin for the stream`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(
                HttpPhase.REQUEST,
                "https://h/moved",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://other.example/landed"))
            )
        )
        val client = DuplexLeg()
        val dials = ArrayList<String>()
        val upstream = ReplayLeg(cannedResponse(body = "landed"))
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSet),
            dialUpstream = { host, port, _ -> dials.add("$host:$port"); upstream }
        )
        val job = launch { bridge.run() }
        try {
            client.feed(CLIENT_PREFACE + clientSettings() + headersFrame(1, getRequest("/moved", "h")))

            val frames = collect(client)
            val (headers, body) = decodedResponse(frames, streamID = 1)!!
            assertEquals("200", statusOf(headers))
            assertEquals("landed", String(body, latin1))

            assertEquals("the stream dialed the rewritten origin, not the SNI host", listOf("other.example:443"), dials)
            val forwarded = Http1Codec().readRequest(ReplayLeg(upstream.sent()))!!
            assertEquals("https://other.example/landed", forwarded.message.url)
            assertEquals("other.example", forwarded.message.header("Host"))
        } finally {
            job.cancel()
        }
    }

    // MARK: - An over-cap response streams through as DATA

    @Test
    fun `a response past the cap streams through as DATA de-chunked and unrewritten`() = runBlocking {
        val ruleSet = ruleSetOf(
            MitmRule(HttpPhase.RESPONSE, "h/big", MitmOperation.BodyReplace("x", "y"))
        )
        // Five 1 MiB chunks: past the 4 MiB cap, so never buffered or offered to the rule.
        val chunk = ByteArray(1024 * 1024) { 'x'.code.toByte() }
        val wire = ByteArrayOutputStream()
        wire.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray(latin1))
        repeat(5) {
            wire.write("100000\r\n".toByteArray(latin1))
            wire.write(chunk)
            wire.write("\r\n".toByteArray(latin1))
        }
        wire.write("0\r\n\r\n".toByteArray(latin1))
        val client = DuplexLeg()
        val bridge = MitmHttp2Bridge(
            client, "h", 443, MitmRewriter(ruleSet),
            dialUpstream = { _, _, _ -> ReplayLeg(wire.toByteArray()) }
        )
        val job = launch { bridge.run() }
        try {
            // The client opens its windows wide so 5 MiB can flow without WINDOW_UPDATEs.
            client.feed(CLIENT_PREFACE + wideWindowSettings() + headersFrame(1, getRequest("/big", "h")))

            val frames = collect(client, idleMs = 1500)
            val (headers, body) = decodedResponse(frames, streamID = 1)!!
            assertEquals("200", statusOf(headers))
            assertEquals("text/plain", valueOf(headers, "content-type"))
            assertNull("a chunked body has no length to declare", valueOf(headers, "content-length"))
            assertEquals(5 * 1024 * 1024, body.size)
            assertTrue("the content passes through untouched by the body rule", body.all { it == 'x'.code.toByte() })
            val data = frames.filter { it.type == Http2FrameType.DATA && it.streamID == 1 }
            assertTrue("the stream is closed after the body", data.last().hasFlag(Http2FrameFlags.END_STREAM))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Helpers

    private fun ruleSetOf(vararg rules: MitmRule): MitmRuleSet =
        MitmRuleSet(name = "test", domainSuffixes = listOf("h"), rules = rules.toList())

    private val CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(ascii)

    private fun clientSettings(): ByteArray =
        Http2Framer.serialize(Http2Framer.settingsFrame(listOf(0x3 to 100)))

    /** Client SETTINGS with the largest INITIAL_WINDOW_SIZE, plus a connection WINDOW_UPDATE to match. */
    private fun wideWindowSettings(): ByteArray =
        Http2Framer.serialize(Http2Framer.settingsFrame(listOf(0x3 to 100, 0x4 to 0x7FFFFFFF))) +
            Http2Framer.serialize(Http2Framer.windowUpdateFrame(0, 0x7FFFFFFF - 65_535))

    /** A GET request HEADERS frame (END_STREAM) for [path] on [authority]. */
    private fun headersFrame(streamID: Int, block: ByteArray): ByteArray =
        Http2Framer.serialize(Http2Framer.headersFrame(streamID, block, endStream = true))

    /**
     * A GET request header block by hand: `:method GET` (static idx 2, indexed),
     * `:scheme https` (static idx 7, indexed), `:path` (literal without indexing,
     * name idx 4), `:authority` (literal without indexing, name idx 1).
     */
    private fun getRequest(path: String, authority: String): ByteArray =
        byteArrayOf(0x82.toByte(), 0x87.toByte(), 0x04) + hpackString(path) +
            byteArrayOf(0x01) + hpackString(authority)

    /** RFC 7541 §5.2 raw (non-Huffman) string literal; length < 128. */
    private fun hpackString(value: String): ByteArray {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size < 128)
        return byteArrayOf(bytes.size.toByte()) + bytes
    }

    /** A canonical, definite-length HTTP/1.1 200 response for the fake origin. */
    private fun cannedResponse(body: String): ByteArray =
        ("HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain\r\n" +
            "Content-Length: ${body.toByteArray(latin1).size}\r\n\r\n").toByteArray(latin1) +
            body.toByteArray(latin1)

    /** Decoded response header fields + concatenated DATA body for [streamID], or null. */
    private fun decodedResponse(frames: List<Http2Frame>, streamID: Int): Pair<List<Pair<String, String>>, ByteArray>? {
        val head = frames.firstOrNull { it.type == Http2FrameType.HEADERS && it.streamID == streamID } ?: return null
        // The server never indexes outbound, so a fresh decoder reads each block.
        val decoded = HpackDecoder().decode(head.payload) ?: return null
        val body = ByteArrayOutputStream()
        frames.filter { it.type == Http2FrameType.DATA && it.streamID == streamID }.forEach { body.write(it.payload) }
        return decoded to body.toByteArray()
    }

    private fun statusOf(headers: List<Pair<String, String>>): String? =
        headers.firstOrNull { it.first == ":status" }?.second

    private fun valueOf(headers: List<Pair<String, String>>, name: String): String? =
        headers.firstOrNull { it.first == name }?.second

    /** Drains all currently-produced outbound bytes and parses them into frames. */
    private suspend fun collect(leg: DuplexLeg, idleMs: Long = 400): List<Http2Frame> {
        val all = ByteArrayOutputStream()
        while (true) {
            val chunk = leg.nextOut(idleMs) ?: break
            all.write(chunk)
        }
        val buffer = Http2Buffer().apply { append(all.toByteArray()) }
        val frames = mutableListOf<Http2Frame>()
        while (true) {
            val frame = Http2Framer.deserialize(buffer) ?: break
            frames.add(frame)
        }
        return frames
    }

    // MARK: - Fakes

    /** In-memory duplex client leg: [feed] the client's bytes, read the server's via [nextOut]. */
    private class DuplexLeg : MitmByteLeg {
        private val inbound = Channel<ByteArray>(Channel.UNLIMITED)
        private val outbound = Channel<ByteArray>(Channel.UNLIMITED)

        override val negotiatedAlpn: String = "h2"

        fun feed(data: ByteArray) { inbound.trySend(data) }

        override suspend fun receive(): ByteArray? = inbound.receiveCatching().getOrNull()
        override suspend fun send(data: ByteArray) { outbound.trySend(data) }
        override fun prependToReceiveBuffer(data: ByteArray) { /* unused by the h2 server */ }
        override fun close() {
            inbound.close()
            outbound.close()
        }

        suspend fun nextOut(idleMs: Long): ByteArray? =
            withTimeoutOrNull(idleMs) { outbound.receiveCatching().getOrNull() }
    }

    /**
     * An upstream h1 leg that replays [initial] once (the canned response, or bytes
     * to re-parse), records everything sent, and honours prepend/close.
     */
    private class ReplayLeg(initial: ByteArray) : MitmByteLeg {
        override val negotiatedAlpn: String? = "http/1.1"
        private var pending: ByteArray? = if (initial.isEmpty()) null else initial
        private var prepended: ByteArray = ByteArray(0)
        private val out = ByteArrayOutputStream()
        var closed = false
            private set

        override suspend fun receive(): ByteArray? {
            if (prepended.isNotEmpty()) {
                val b = prepended; prepended = ByteArray(0); return b
            }
            val next = pending ?: return null
            pending = null
            return next
        }

        override suspend fun send(data: ByteArray) { out.write(data) }
        override fun prependToReceiveBuffer(data: ByteArray) {
            if (data.isNotEmpty()) prepended = if (prepended.isEmpty()) data.copyOf() else prepended + data
        }
        override fun close() { closed = true }
        fun sent(): ByteArray = out.toByteArray()
    }

    /**
     * An upstream h1 leg that answers immediately for a `/fast` request and waits on
     * [slowGate] for a `/slow` one, deciding from the request it was handed (captured
     * on [send] before [receive] is ever called). Its body echoes fast/slow so the
     * two streams' responses are distinguishable.
     */
    private class GatedUpstreamLeg(private val slowGate: CompletableDeferred<Unit>) : MitmByteLeg {
        override val negotiatedAlpn: String? = "http/1.1"
        private val sent = ByteArrayOutputStream()
        private var delivered = false

        override suspend fun receive(): ByteArray? {
            if (delivered) return null
            val request = String(sent.toByteArray(), StandardCharsets.ISO_8859_1)
            val body = if (request.contains("/slow")) {
                slowGate.await()
                "slow"
            } else {
                "fast"
            }
            delivered = true
            val head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n"
            return (head + body).toByteArray(StandardCharsets.ISO_8859_1)
        }

        override suspend fun send(data: ByteArray) { sent.write(data) }
        override fun prependToReceiveBuffer(data: ByteArray) { /* one message per leg; no overread */ }
        override fun close() { }
    }
}
