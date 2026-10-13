package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.protocol.grpc.GrpcError
import com.mythaia.vpn.protocol.grpc.GrpcMuxStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A pooled [Http2Session] against a scripted server: what the shared
 * connection does with the frames real servers send. The wire is a pair of
 * channels and the test plays the server.
 */
class Http2SessionTest {

    /** Both directions as channels; the test is the server. */
    private class FakeWire : Http2Wire {
        private val toServer = Channel<ByteArray>(Channel.UNLIMITED)
        private val toClient = Channel<ByteArray>(Channel.UNLIMITED)

        @Volatile
        var cancelled = false

        private val parsed = Http2Buffer()
        private var prefaceSkipped = false
        private val frames = mutableListOf<Http2Frame>()

        override suspend fun send(data: ByteArray) {
            toServer.send(data)
        }

        override suspend fun receive(): ByteArray? = toClient.receiveCatching().getOrNull()

        override fun cancel() {
            cancelled = true
            toClient.close()
        }

        fun serverSends(frame: Http2Frame) {
            toClient.trySend(Http2Framer.serialize(frame))
        }

        /** Every frame the client has sent so far, the connection preface skipped. */
        @Synchronized
        fun sentFrames(): List<Http2Frame> {
            while (true) {
                parsed.append(toServer.tryReceive().getOrNull() ?: break)
            }
            if (!prefaceSkipped && parsed.available >= PREFACE_SIZE) {
                parsed.skip(PREFACE_SIZE)
                prefaceSkipped = true
            }
            if (prefaceSkipped) {
                while (true) frames.add(Http2Framer.deserialize(parsed) ?: break)
            }
            return frames.toList()
        }

        suspend fun awaitFrame(timeoutMs: Long = 3_000, match: (Http2Frame) -> Boolean): Http2Frame? {
            val deadline = System.nanoTime() + timeoutMs * 1_000_000
            while (System.nanoTime() < deadline) {
                sentFrames().firstOrNull(match)?.let { return it }
                delay(10)
            }
            return null
        }

        /** Every frame before this PING has been routed once its ACK is back. */
        suspend fun awaitRouted() {
            val opaque = ByteArray(8) { (it * 17 + 3).toByte() }
            serverSends(Http2Framer.pingFrame(opaque))
            assertNotNull(
                "PING was not answered",
                awaitFrame { it.type == Http2FrameType.PING && it.hasFlag(Http2FrameFlags.ACK) && it.payload.contentEquals(opaque) }
            )
        }

        private companion object {
            const val PREFACE_SIZE = 24
        }
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val sessions = mutableListOf<Http2Session>()

    @After
    fun tearDown() {
        sessions.forEach { it.close() }
    }

    private fun readySession(
        wire: FakeWire = FakeWire(),
        keepaliveIdleMs: Long = Http2Session.KEEPALIVE_IDLE_MS,
        keepaliveTimeoutMs: Long = Http2Session.KEEPALIVE_TIMEOUT_MS
    ): Pair<Http2Session, FakeWire> {
        // The handshake waits for the server's SETTINGS.
        wire.serverSends(Http2Framer.settingsFrame(emptyList()))
        val session = Http2Session(null, scope, null, null, { wire }, keepaliveIdleMs, keepaliveTimeoutMs)
        sessions.add(session)
        return session to wire
    }

    private val requestHeaders = HpackEncoder.encodeHeaderBlock(
        listOf(":method" to "POST", ":scheme" to "https", ":path" to "/", ":authority" to "example.com")
    )

    /** A request stream, opened as gRPC and XHTTP open theirs: without waiting for the response. */
    private suspend fun openRequest(session: Http2Session): Http2Stream {
        val stream = session.acquireStream("test")
        stream.openRequest(requestHeaders, endStream = false, awaitResponse = false)
        return stream
    }

    private suspend fun awaitUntil(timeoutMs: Long = 3_000, condition: () -> Boolean) {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (!condition()) {
            assertTrue("timed out", System.nanoTime() < deadline)
            delay(10)
        }
    }

    private fun hex(s: String): ByteArray =
        s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun goawayFrame(lastStreamID: Int, errorCode: Int): Http2Frame {
        val payload = ByteArray(8)
        for (i in 0 until 4) {
            payload[i] = (lastStreamID shr (24 - 8 * i)).toByte()
            payload[4 + i] = (errorCode shr (24 - 8 * i)).toByte()
        }
        return Http2Frame(Http2FrameType.GOAWAY, 0, 0, payload)
    }

    /** `x-foo: bar` as a literal with incremental indexing: it lands in the dynamic table at 62. */
    private val insertXFoo = hex("40 05 782d666f6f 03 626172")

    // MARK: - HPACK state is per connection

    @Test
    fun `a header block for a stream already closed here still feeds the HPACK table`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session) // 1
        val gone = openRequest(session) // 3
        // Closed on our side; the server's reply for it was already on its way.
        gone.close()

        wire.serverSends(Http2Framer.headersFrame(3, insertXFoo))
        wire.serverSends(Http2Framer.headersFrame(1, hex("88"))) // :status 200
        // The trailers refer to the entry the dropped stream's block inserted.
        wire.serverSends(Http2Framer.headersFrame(1, hex("be"), endStream = true))

        assertNull(stream.receiveData())
        assertEquals(listOf("x-foo" to "bar"), stream.trailers)
    }

    @Test
    fun `a header block that does not decode is a connection error`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        // Index 100: nothing there. The table's state is unknowable after this.
        wire.serverSends(Http2Framer.headersFrame(1, hex("e4")))
        val error = runCatching { stream.receiveData() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.ProtocolError)
        awaitUntil { session.isClosed }
    }

    // MARK: - Padding, priority, CONTINUATION

    @Test
    fun `padded and prioritised HEADERS decode without the padding and priority bytes`() = runBlocking {
        val (session, wire) = readySession()
        val stream = session.acquireStream("test")
        val opened = scope.async { stream.openRequest(requestHeaders, awaitResponse = true) }
        assertNotNull(wire.awaitFrame { it.type == Http2FrameType.HEADERS && it.streamID == 1 })

        // Pad length 3, a 5-byte priority block, `:status 200`, three bytes of padding.
        val payload = hex("03") + hex("00 00 00 00 10") + hex("88") + hex("00 00 00")
        val flags = Http2FrameFlags.END_HEADERS or Http2FrameFlags.PADDED or Http2FrameFlags.PRIORITY
        wire.serverSends(Http2Frame(Http2FrameType.HEADERS, flags, 1, payload))

        withTimeout(3_000) { opened.await() }
        assertTrue(stream.isConnected)
    }

    @Test
    fun `padded DATA reaches the application without its padding`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        val payload = hex("04") + "hello".toByteArray() + ByteArray(4)
        wire.serverSends(Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, payload))
        assertEquals("hello", String(stream.receiveData()!!))
    }

    @Test
    fun `padding longer than the frame is a connection error`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(Http2Frame(Http2FrameType.DATA, Http2FrameFlags.PADDED, 1, hex("09 61")))
        val error = runCatching { stream.receiveData() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.ProtocolError)
        awaitUntil { session.isClosed }
    }

    @Test
    fun `a header block split over CONTINUATION is decoded once, whole`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        // `:status 200`, then `grpc-status: 7` as a literal with incremental
        // indexing, cut in the middle of the name: a gRPC Trailers-Only reply.
        val block = hex("88") + hex("40 0b 677270632d737461747573 01 37")
        wire.serverSends(Http2Frame(Http2FrameType.HEADERS, Http2FrameFlags.END_STREAM, 1, block.copyOfRange(0, 5)))
        wire.serverSends(Http2Frame(Http2FrameType.CONTINUATION, Http2FrameFlags.END_HEADERS, 1, block.copyOfRange(5, block.size)))

        assertNull(stream.receiveData())
        assertEquals(listOf(":status" to "200", "grpc-status" to "7"), stream.trailers)
        // ...which the gRPC reader reports as the failure it is, not a clean end.
        val error = runCatching { GrpcMuxStream(stream).receive() }.exceptionOrNull()
        assertTrue("$error", error is GrpcError.CallFailed)
        assertEquals(7, (error as GrpcError.CallFailed).status)
    }

    @Test
    fun `another frame inside a header block is a connection error`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(Http2Frame(Http2FrameType.HEADERS, 0, 1, hex("88")))
        wire.serverSends(Http2Framer.dataFrame(1, "x".toByteArray()))
        val error = runCatching { stream.receiveData() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.ProtocolError)
        awaitUntil { session.isClosed }
    }

    // MARK: - The end of a stream is reported for what it was

    @Test
    fun `a stream reset mid-download fails the reader instead of ending it cleanly`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(Http2Framer.dataFrame(1, "part".toByteArray()))
        wire.serverSends(Http2Framer.rstStreamFrame(1, Http2Framer.ErrorCode.CANCEL))
        // Whatever arrived before the reset may still be read; the end is the error.
        val error = runCatching { while (stream.receiveData() != null) { } }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.StreamReset)
        assertFalse(session.isClosed)
    }

    @Test
    fun `GOAWAY fails the streams the server never took with a retryable error`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(goawayFrame(lastStreamID = 0, errorCode = Http2Framer.ErrorCode.NO_ERROR))
        val error = runCatching { while (stream.receiveData() != null) { } }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.Goaway)
        awaitUntil { session.isClosed }
    }

    @Test
    fun `a refused request fails its reader`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(Http2Framer.headersFrame(1, hex("8d"), endStream = true)) // :status 404
        val error = runCatching { stream.receiveData() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.TunnelFailed)
    }

    @Test
    fun `END_STREAM is still a clean end with the data before it`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        wire.serverSends(Http2Framer.dataFrame(1, "all".toByteArray()))
        wire.serverSends(Http2Framer.dataFrame(1, ByteArray(0), endStream = true))
        assertEquals("all", String(stream.receiveData()!!))
        assertNull(stream.receiveData())
    }

    // MARK: - Connection window

    @Test
    fun `data nobody reads is still credited to the connection window`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        val chunk = ByteArray(1 shl 20)
        val half = Http2FlowControl.NAIVE_SESSION_MAX_RECV_WINDOW / 2

        // 32 MB buffered on a stream the application then closes unread...
        repeat(32) { wire.serverSends(Http2Framer.dataFrame(1, chunk)) }
        wire.awaitRouted()
        stream.close()
        // ...and 32 MB for a stream that is not there at all.
        repeat(32) { wire.serverSends(Http2Framer.dataFrame(7, chunk)) }

        // Together they are half the window, which is when it is replenished.
        val update = wire.awaitFrame {
            it.type == Http2FrameType.WINDOW_UPDATE && it.streamID == 0 &&
                Http2Framer.parseWindowUpdate(it.payload) == half
        }
        assertNotNull("no WINDOW_UPDATE for the discarded data", update)
    }

    // MARK: - Lifecycle

    @Test
    fun `close during the dial cancels the connection it was waiting for`() = runBlocking {
        val wire = FakeWire().also { it.serverSends(Http2Framer.settingsFrame(emptyList())) }
        val dialStarted = CompletableDeferred<Unit>()
        val dialGate = CompletableDeferred<Unit>()
        val session = Http2Session(null, scope, null, null, {
            dialStarted.complete(Unit)
            dialGate.await()
            wire
        })
        val acquiring = scope.async { session.acquireStream("test") }
        dialStarted.await()
        session.close()
        dialGate.complete(Unit)

        val error = runCatching { acquiring.await() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.ConnectionFailed)
        awaitUntil { wire.cancelled }
        assertTrue(session.isClosed)
        assertFalse(session.hasCapacity)
    }

    @Test
    fun `a silent server is pinged and then given up on`() = runBlocking {
        val (session, wire) = readySession(keepaliveIdleMs = 200, keepaliveTimeoutMs = 200)
        val stream = openRequest(session)
        assertNotNull(
            "no keepalive PING",
            wire.awaitFrame { it.type == Http2FrameType.PING && !it.hasFlag(Http2FrameFlags.ACK) }
        )
        awaitUntil { session.isClosed }
        val error = runCatching { stream.receiveData() }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.ConnectionFailed)
    }

    @Test
    fun `a server that answers the keepalive keeps the connection`() = runBlocking {
        val (session, wire) = readySession(keepaliveIdleMs = 100, keepaliveTimeoutMs = 200)
        openRequest(session)
        val deadline = System.nanoTime() + 800_000_000L
        var answered = 0
        while (System.nanoTime() < deadline) {
            val pings = wire.sentFrames().filter { it.type == Http2FrameType.PING && !it.hasFlag(Http2FrameFlags.ACK) }
            while (answered < pings.size) {
                wire.serverSends(Http2Framer.pingAckFrame(pings[answered].payload))
                answered++
            }
            delay(10)
        }
        assertTrue("no keepalive PING in 800 ms", answered >= 1)
        assertFalse(session.isClosed)
    }

    @Test
    fun `the end of the stream id space closes the connection to new streams`() = runBlocking {
        val (session, _) = readySession()
        openRequest(session)
        session.nextStreamID = 0x7FFFFFFF
        val last = openRequest(session)
        assertEquals(0x7FFFFFFF, last.streamID)

        assertFalse(session.hasCapacity)
        assertNull(session.tryReserveStream("x"))
        val error = runCatching { session.acquireStream("x") }.exceptionOrNull()
        assertTrue("$error", error is Http2Error.Goaway)
    }

    @Test
    fun `two senders on one stream do not interleave their frames`() = runBlocking {
        val (session, wire) = readySession()
        val stream = openRequest(session)
        val a = ByteArray(20_000) { 'a'.code.toByte() }
        val b = ByteArray(20_000) { 'b'.code.toByte() }
        listOf(a, b).map { payload -> scope.async { stream.sendData(payload) } }.awaitAll()

        val sent = wire.sentFrames().filter { it.type == Http2FrameType.DATA && it.streamID == 1 }
        assertEquals(4, sent.size)
        val order = sent.map { it.payload[0].toInt().toChar() }
        assertTrue("$order", order == listOf('a', 'a', 'b', 'b') || order == listOf('b', 'b', 'a', 'a'))
        assertArrayEquals(a, sent.filter { it.payload[0] == a[0] }.fold(ByteArray(0)) { acc, f -> acc + f.payload })
    }
}
