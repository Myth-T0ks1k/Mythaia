package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.naive.http2.HpackDecoder
import com.mythaia.vpn.protocol.naive.http2.Http2Buffer
import com.mythaia.vpn.protocol.naive.http2.Http2Frame
import com.mythaia.vpn.protocol.naive.http2.Http2FrameFlags
import com.mythaia.vpn.protocol.naive.http2.Http2FrameType
import com.mythaia.vpn.protocol.naive.http2.Http2Framer
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets

/**
 * The h2 MITM server leg, driven over an in-memory [MitmByteLeg] whose inbound
 * side is scripted with hand-built HTTP/2 frames and whose outbound side is
 * re-parsed with the app's own [Http2Framer]/[HpackDecoder].
 *
 * Every request header block fed in is assembled from RFC 7541 static-table bytes
 * (indexed header fields `0x82`/`0x87`/`0x84`, a literal-with-indexing `:authority`)
 * derived by hand, not by any encoder in the tree; every response is read back by a
 * *different* code path (the stateful [HpackDecoder]) than the server used to write
 * it, and control frames are asserted against their RFC-derived wire bytes. So no
 * assertion is a tautology over the server's own output.
 */
class MitmHttp2ServerTest {

    private val ascii = StandardCharsets.US_ASCII

    // MARK: - Preface + SETTINGS

    @Test
    fun `client preface and SETTINGS are accepted and a SETTINGS ACK is sent`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            leg.feed(CLIENT_PREFACE + clientSettings())
            val frames = collect(leg)

            // The server proactively sends its own SETTINGS (not an ACK) ...
            assertTrue(
                "server preface SETTINGS present",
                frames.any { it.type == Http2FrameType.SETTINGS && !it.hasFlag(Http2FrameFlags.ACK) && it.payload.isNotEmpty() }
            )
            // ... a connection-level WINDOW_UPDATE that raises its receive window ...
            assertTrue(
                "connection preface WINDOW_UPDATE present",
                frames.any { it.type == Http2FrameType.WINDOW_UPDATE && it.streamID == 0 }
            )
            // ... and, in answer to the client's SETTINGS, a SETTINGS ACK.
            val ack = frames.first { it.type == Http2FrameType.SETTINGS && it.hasFlag(Http2FrameFlags.ACK) }
            assertTrue("SETTINGS ACK carries no payload", ack.payload.isEmpty())
            // RFC 7540 §6.5.3 wire form of a SETTINGS ACK: length 0, type 4, flags 1, stream 0.
            assertArrayEquals(
                byteArrayOf(0, 0, 0, 0x04, 0x01, 0, 0, 0, 0),
                Http2Framer.serialize(ack)
            )
        } finally {
            job.cancel()
        }
    }

    // MARK: - GET request → HttpMessage

    @Test
    fun `a GET HEADERS frame yields the right request HttpMessage`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            // RFC 7541 static-table encoding of :method GET / :scheme https / :path /
            // plus a literal-with-indexing :authority "h".
            val block = byteArrayOf(0x82.toByte(), 0x87.toByte(), 0x84.toByte(), 0x41) + hpackString("h")
            leg.feed(CLIENT_PREFACE + clientSettings() + headersFrame(1, block, endStream = true))

            val stream = withTimeout(2000) { server.acceptRequest() }
            assertNotNull(stream)
            requireNotNull(stream)
            assertEquals("GET", stream.request.method)
            assertEquals("https://h/", stream.request.url)
            assertEquals("HTTP/2", stream.request.version)
            assertEquals("h", stream.request.header("Host"))
            assertEquals(0, stream.request.body.size)
        } finally {
            job.cancel()
        }
    }

    // MARK: - POST with body → method + url + body

    @Test
    fun `a POST HEADERS+DATA assembles method, url and body`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            // :method POST (idx 3), :scheme https (idx 7), :path literal name idx 4, :authority literal.
            val block = byteArrayOf(0x83.toByte(), 0x87.toByte(), 0x04) + hpackString("/submit") +
                byteArrayOf(0x41) + hpackString("h")
            leg.feed(
                CLIENT_PREFACE + clientSettings() +
                    headersFrame(1, block, endStream = false) +
                    Http2Framer.serialize(Http2Framer.dataFrame(1, "hello".toByteArray(ascii), endStream = true))
            )

            val stream = withTimeout(2000) { server.acceptRequest() }
            requireNotNull(stream)
            assertEquals("POST", stream.request.method)
            assertEquals("https://h/submit", stream.request.url)
            assertEquals("hello", String(stream.request.body, ascii))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Response encoding

    @Test
    fun `a response HttpMessage encodes to HEADERS+DATA an independent HPACK decode reads back`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            val block = byteArrayOf(0x82.toByte(), 0x87.toByte(), 0x84.toByte(), 0x41) + hpackString("h")
            leg.feed(CLIENT_PREFACE + clientSettings() + headersFrame(1, block, endStream = true))

            val stream = withTimeout(2000) { server.acceptRequest() }
            requireNotNull(stream)
            stream.sendResponse(
                HttpMessage.response(
                    status = 200,
                    url = stream.request.url,
                    headers = listOf(HttpHeader("Content-Type", "text/plain")),
                    body = "hi".toByteArray(ascii),
                    version = "HTTP/2"
                )
            )

            val frames = collect(leg)
            val responseHeaders = frames.first { it.type == Http2FrameType.HEADERS && it.streamID == 1 }
            assertTrue("HEADERS carries END_HEADERS", responseHeaders.hasFlag(Http2FrameFlags.END_HEADERS))

            // A fresh (independent) HPACK decoder reads the block back to the same fields.
            val decoded = HpackDecoder().decode(responseHeaders.payload)
            assertNotNull(decoded)
            requireNotNull(decoded)
            assertEquals("200", decoded.first { it.first == ":status" }.second)
            assertEquals("text/plain", decoded.first { it.first == "content-type" }.second)

            val data = frames.first { it.type == Http2FrameType.DATA && it.streamID == 1 }
            assertArrayEquals("hi".toByteArray(ascii), data.payload)
            assertTrue("last DATA carries END_STREAM", data.hasFlag(Http2FrameFlags.END_STREAM))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Flow control

    @Test
    fun `WINDOW_UPDATE is emitted crediting the on-wire length of consumed DATA`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            val block = byteArrayOf(0x83.toByte(), 0x87.toByte(), 0x84.toByte(), 0x41) + hpackString("h")
            val body = "0123456789".toByteArray(ascii) // 10 bytes on the wire, no padding
            leg.feed(
                CLIENT_PREFACE + clientSettings() +
                    headersFrame(1, block, endStream = false) +
                    Http2Framer.serialize(Http2Framer.dataFrame(1, body, endStream = true))
            )
            // Ensure the DATA is consumed (the request is delivered only after END_STREAM).
            withTimeout(2000) { server.acceptRequest() }

            val frames = collect(leg)
            val streamCredits = frames.filter { it.type == Http2FrameType.WINDOW_UPDATE && it.streamID == 1 }
                .mapNotNull { Http2Framer.parseWindowUpdate(it.payload) }
            val connCredits = frames.filter { it.type == Http2FrameType.WINDOW_UPDATE && it.streamID == 0 }
                .mapNotNull { Http2Framer.parseWindowUpdate(it.payload) }

            assertTrue("stream WINDOW_UPDATE credits the 10 consumed bytes", streamCredits.contains(body.size))
            assertTrue("connection WINDOW_UPDATE credits the 10 consumed bytes", connCredits.contains(body.size))
        } finally {
            job.cancel()
        }
    }

    // MARK: - Refusals

    @Test
    fun `an oversized frame is refused with GOAWAY FRAME_SIZE_ERROR`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            // A 9-byte frame header declaring a 2 MiB payload — above the 1 MiB accept cap.
            val oversizedHeader = byteArrayOf(0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
            leg.feed(CLIENT_PREFACE + clientSettings() + oversizedHeader)

            val frames = collect(leg)
            val goaway = frames.first { it.type == Http2FrameType.GOAWAY }
            assertEquals(
                Http2Framer.ErrorCode.FRAME_SIZE_ERROR,
                Http2Framer.parseGoaway(goaway.payload)?.errorCode
            )
            // The connection is torn down: the request queue is closed.
            assertNull(withTimeout(2000) { server.acceptRequest() })
        } finally {
            job.cancel()
        }
    }

    @Test
    fun `a HEADERS frame on stream 0 is refused with GOAWAY PROTOCOL_ERROR`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            val block = byteArrayOf(0x82.toByte(), 0x87.toByte(), 0x84.toByte(), 0x41) + hpackString("h")
            leg.feed(CLIENT_PREFACE + clientSettings() + headersFrame(0, block, endStream = true))

            val frames = collect(leg)
            val goaway = frames.first { it.type == Http2FrameType.GOAWAY }
            assertEquals(
                Http2Framer.ErrorCode.PROTOCOL_ERROR,
                Http2Framer.parseGoaway(goaway.payload)?.errorCode
            )
        } finally {
            job.cancel()
        }
    }

    @Test
    fun `the request queue closes on a clean client EOF`() = runBlocking {
        val leg = DuplexLeg()
        val server = MitmHttp2Server(leg, "h")
        val job = launch { server.run() }
        try {
            leg.feed(CLIENT_PREFACE + clientSettings())
            leg.feedEof()
            assertNull(withTimeout(2000) { server.acceptRequest() })
        } finally {
            job.cancel()
        }
    }

    // MARK: - Helpers

    private val CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(ascii)

    /** A minimal client SETTINGS frame (advertising a stream-concurrency cap). */
    private fun clientSettings(): ByteArray =
        Http2Framer.serialize(Http2Framer.settingsFrame(listOf(0x3 to 100)))

    private fun headersFrame(streamID: Int, block: ByteArray, endStream: Boolean): ByteArray =
        Http2Framer.serialize(Http2Framer.headersFrame(streamID, block, endStream))

    /** RFC 7541 §5.2 raw (non-Huffman) string literal; length < 128. */
    private fun hpackString(value: String): ByteArray {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size < 128)
        return byteArrayOf(bytes.size.toByte()) + bytes
    }

    /** Drains all currently-produced outbound bytes and parses them into frames. */
    private suspend fun collect(leg: DuplexLeg, idleMs: Long = 300): List<Http2Frame> {
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

    /**
     * An in-memory duplex [MitmByteLeg]: the test [feed]s the bytes a client would
     * send and reads back, via [nextOut], the bytes the server wrote. Both sides are
     * unbounded channels so neither the read loop nor a response sender ever blocks.
     */
    private class DuplexLeg : MitmByteLeg {
        private val inbound = Channel<ByteArray>(Channel.UNLIMITED)
        private val outbound = Channel<ByteArray>(Channel.UNLIMITED)

        override val negotiatedAlpn: String = "h2"

        fun feed(data: ByteArray) { inbound.trySend(data) }
        fun feedEof() { inbound.close() }

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
}
