package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.protocol.naive.NaiveConfiguration
import com.mythaia.vpn.protocol.naive.NaivePaddingNegotiator
import com.mythaia.vpn.protocol.naive.NaiveTlsTransport
import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream

private val logger = MythaiaLogger("HTTP2Session")

/**
 * The byte stream an [Http2Session] runs over: a TLS (or Reality) connection to
 * the server, already through its handshake.
 */
interface Http2Wire {
    suspend fun send(data: ByteArray)
    suspend fun receive(): ByteArray?
    fun cancel()
}

/**
 * One TLS connection with multiple concurrent streams: NaiveProxy's CONNECT
 * tunnels, or ordinary requests ([Http2Stream.openRequest]) such as gRPC's. Owns
 * the persistent read loop that routes frames to per-stream [Http2Stream]
 * instances, the 128 MB connection receive window, and serializes writes through
 * a [Mutex]. The first caller to [ensureReady] performs the handshake; concurrent
 * callers wait for it.
 *
 * [dial] opens the connection when given; otherwise the session dials the
 * NaiveProxy server of [configuration] itself.
 */
class Http2Session(
    private val configuration: NaiveConfiguration?,
    private val scope: CoroutineScope,
    private val tunnel: ProxyConnection? = null,
    var onClose: (() -> Unit)? = null,
    private val dial: (suspend () -> Http2Wire)? = null,
    /** Pooled sessions only: silence from the server, with streams open, that earns a PING. */
    private val keepaliveIdleMs: Long = KEEPALIVE_IDLE_MS,
    /** How long after that PING the connection is given up on when nothing at all arrives. */
    private val keepaliveTimeoutMs: Long = KEEPALIVE_TIMEOUT_MS
) {
    companion object {
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        private val CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
        private const val MAX_RECEIVE_BUFFER_SIZE = 2_097_152
        private const val MAX_CONCURRENT_STREAMS = 100

        /** Our SETTINGS_HEADER_TABLE_SIZE: the most the server's HPACK encoder may ask us to keep. */
        private const val HEADER_TABLE_SIZE = 65536

        /** Our SETTINGS_MAX_HEADER_LIST_SIZE, and the most of one header block we buffer across CONTINUATION. */
        private const val MAX_HEADER_BLOCK_SIZE = 262144

        /** RFC 9113 §5.1.1: the last stream id a client can use. */
        private const val MAX_STREAM_ID = 0x7FFFFFFF

        const val KEEPALIVE_IDLE_MS = 30_000L
        const val KEEPALIVE_TIMEOUT_MS = 15_000L

        /** Why a stream fails when its session was closed under it; [Http2StreamPool] retries on it. */
        internal const val CLOSED_MESSAGE = "Session closed"
    }

    enum class State { IDLE, CONNECTING, READY, CLOSED }

    @Volatile
    private var state = State.IDLE

    @Volatile
    private var goawayReceived = false
    private var goawayLastStreamID = Int.MAX_VALUE

    /** Every odd id up to [MAX_STREAM_ID] used: like a GOAWAY, no new streams here (§5.1.1). */
    @Volatile
    private var streamIdsExhausted = false

    private var transport: Http2Wire? = null
    private val receiveBuffer = Http2Buffer()

    /** The server's SETTINGS_MAX_CONCURRENT_STREAMS, when lower than ours. */
    @Volatile
    private var streamLimit = MAX_CONCURRENT_STREAMS

    /** When the last stream ended or the last frame arrived; see [idleNanos]. */
    @Volatile
    private var lastActivityNanos = System.nanoTime()

    /** When the last frame arrived, whatever it was: the keepalive's measure of the server's silence. */
    @Volatile
    private var lastFrameNanos = System.nanoTime()

    private var keepaliveJob: Job? = null

    /**
     * A header block whose HEADERS frame lacked END_HEADERS, collecting its
     * CONTINUATION frames; RFC 9113 §6.10 lets nothing else arrive meanwhile.
     */
    private var pendingHeaderBlock: ByteArrayOutputStream? = null
    private var pendingHeadersStreamID = 0
    private var pendingHeadersFlags = 0

    /** How long the session has carried no stream at all; 0 while one is open. */
    val idleNanos: Long
        get() = if (synchronized(streamsLock) { streams.isNotEmpty() || reserved > 0 }) 0L
        else System.nanoTime() - lastActivityNanos

    /** Not dialled yet, or still in its handshake: a caller may join and wait. */
    val isStarting: Boolean get() = state == State.IDLE || state == State.CONNECTING

    private val streams = mutableMapOf<Int, Http2Stream>()

    /** Internal so a test can walk it to the end of the id space. */
    internal var nextStreamID = 1
    private val streamsLock = Any()

    /** Streams handed out but not opened yet: they hold a slot, not yet an id. */
    private var reserved = 0

    private var connectionSendWindow = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
    private var connectionRecvConsumed = 0
    private val flowLock = Any()
    private var connectionWindowAwaiter: CompletableDeferred<Unit>? = null

    /** The server's SETTINGS_INITIAL_WINDOW_SIZE, used as the initial send window for new streams. */
    var serverInitialWindowSize = Http2FlowControl.DEFAULT_INITIAL_WINDOW_SIZE
        private set

    val hpackDecoder = HpackDecoder(HEADER_TABLE_SIZE)

    private val writeMutex = Mutex()

    /** One dial at a time: concurrent first callers wait here for the handshake. */
    private val readyMutex = Mutex()

    val hasCapacity: Boolean
        get() = state == State.READY && !goawayReceived && !streamIdsExhausted &&
            synchronized(streamsLock) { streams.size + reserved < streamLimit }

    val isClosed: Boolean get() = state == State.CLOSED

    suspend fun acquireStream(destination: String): Http2Stream {
        ensureReady()

        if (state != State.READY) throw Http2Error.NotReady()
        if (goawayReceived || streamIdsExhausted) throw Http2Error.Goaway()

        return synchronized(streamsLock) {
            reserved += 1
            lastActivityNanos = System.nanoTime()
            Http2Stream(this, destination)
        }
    }

    /**
     * Atomically checks capacity and reserves a stream slot. Returns null if the
     * session is at capacity, going-away, or closed. Used by [Http2SessionPool] so
     * concurrent acquisitions cannot exceed [MAX_CONCURRENT_STREAMS]. Mirrors iOS
     * `HTTP2Session.tryReserveStream()`.
     */
    fun tryReserveStream(destination: String): Http2Stream? {
        if (state != State.READY || goawayReceived || streamIdsExhausted) return null
        return synchronized(streamsLock) {
            if (streams.size + reserved >= streamLimit) return@synchronized null
            reserved += 1
            lastActivityNanos = System.nanoTime()
            Http2Stream(this, destination)
        }
    }

    /** A stream handed out and closed without ever opening gives its slot back. */
    fun releaseReservation() {
        synchronized(streamsLock) { if (reserved > 0) reserved -= 1 }
        lastActivityNanos = System.nanoTime()
    }

    /**
     * Gives [stream] the next id and writes its HEADERS ([headers] builds the
     * frame for that id) in one step under the write lock, so ids reach the
     * server in increasing order however the streams' openers interleave
     * (RFC 9113 §5.1.1: an id lower than one already used is a connection
     * error, which took every stream on the connection down with it).
     */
    private suspend fun openStream(stream: Http2Stream, headers: (Int) -> Http2Frame) {
        writeMutex.withLock {
            val t = transport
            if (t == null || state == State.CLOSED) throw Http2Error.ConnectionFailed("Transport closed")
            val id = synchronized(streamsLock) {
                // The id space is finite (§5.1.1); past its end the counter
                // wrapped to a negative id on the wire. Treated like a GOAWAY:
                // no new streams here, the pool dials another connection. The
                // reservation stays with the caller, which releases it on the
                // way out.
                if (nextStreamID !in 1..MAX_STREAM_ID) {
                    streamIdsExhausted = true
                    null
                } else {
                    val id = nextStreamID
                    nextStreamID += 2
                    // The last usable id just went out: [hasCapacity] turns
                    // false now, so the pool stops picking this connection.
                    if (nextStreamID !in 1..MAX_STREAM_ID) streamIdsExhausted = true
                    if (reserved > 0) reserved -= 1
                    streams[id] = stream
                    id
                }
            } ?: throw Http2Error.Goaway()
            stream.assignId(id)
            t.send(Http2Framer.serialize(headers(id)))
        }
    }

    fun removeStream(streamID: Int) {
        synchronized(streamsLock) { streams.remove(streamID) }
        lastActivityNanos = System.nanoTime()
        if ((goawayReceived || streamIdsExhausted) && synchronized(streamsLock) { streams.isEmpty() }) {
            close()
        }
    }

    /**
     * Acks [bytes] consumed from [streamID]'s data channel by the application.
     * Updates per-stream and connection-level recv counters and emits WINDOW_UPDATE
     * when half the window has been drained. Mirrors iOS
     * `HTTP2Stream.acknowledgeConsumedData(count:)`. Called by [Http2Stream.receiveData].
     */
    fun acknowledgeConsumedData(streamID: Int, bytes: Int) {
        if (bytes <= 0) return
        creditConnection(bytes)
        val stream = synchronized(streamsLock) { streams[streamID] }
        stream?.flowControl?.consumeRecv(bytes)?.let { streamInc ->
            scope.launch { sendWindowUpdate(streamID, streamInc) }
        }
    }

    /**
     * The connection half of [acknowledgeConsumedData]: [bytes] of DATA the
     * server sent are done with, whether the application read them or they
     * went to a stream that was already gone. RFC 9113 §6.9: every DATA byte
     * counts against the connection window, so every one has to be credited
     * back, or the shared connection's window runs out after 128 MB of
     * discarded data and the server stops sending to everyone on it.
     */
    fun creditConnection(bytes: Int) {
        if (bytes <= 0) return
        val connInc: Int?
        synchronized(flowLock) {
            connectionRecvConsumed += bytes
            connInc = if (connectionRecvConsumed >= Http2FlowControl.NAIVE_SESSION_MAX_RECV_WINDOW / 2) {
                val v = connectionRecvConsumed
                connectionRecvConsumed = 0
                v
            } else null
        }
        if (connInc != null) {
            scope.launch { sendWindowUpdate(0, connInc) }
        }
    }

    /**
     * Sends RST_STREAM with the given error code. Used when a stream is closed
     * by the client before the server closes it, so the server can reclaim the
     * stream slot. Mirrors iOS `HTTP2Stream.close()` sending CANCEL.
     */
    fun sendReset(streamID: Int, errorCode: Int) {
        scope.launch { sendFrameRaw(Http2Framer.rstStreamFrame(streamID, errorCode)) }
    }

    private suspend fun ensureReady() {
        if (state == State.READY) return
        if (state == State.CLOSED) throw Http2Error.ConnectionFailed(CLOSED_MESSAGE)

        // A mutex rather than a flag: callers on several threads used to be able
        // to see "not connecting" at once and both dial.
        readyMutex.withLock {
            if (state == State.READY) return
            if (state == State.CLOSED) throw Http2Error.ConnectionFailed(CLOSED_MESSAGE)
            try {
                state = State.CONNECTING

                val t: Http2Wire = dial?.invoke() ?: run {
                    val naive = configuration
                        ?: throw Http2Error.ConnectionFailed("No dialer and no NaiveProxy configuration")
                    NaiveTlsTransport(
                        host = naive.proxyHost,
                        port = naive.proxyPort,
                        sni = naive.effectiveSNI,
                        alpn = listOf("h2"),
                        tunnel = tunnel,
                        tls = naive.tls
                    ).also {
                        transport = it
                        it.connect()
                    }
                }
                // close() while the dial was in flight (the pool's closeAll) had
                // no transport to cancel, and going on from here made a READY
                // session with a read loop that nobody could reach any more.
                if (!adoptTransport(t)) throw Http2Error.ConnectionFailed(CLOSED_MESSAGE)

                sendConnectionPreface(t)
                processHandshake(t)

                synchronized(streamsLock) {
                    if (state == State.CLOSED) throw Http2Error.ConnectionFailed(CLOSED_MESSAGE)
                    state = State.READY
                }
                lastActivityNanos = System.nanoTime()
                lastFrameNanos = lastActivityNanos

                scope.launch { readLoop() }
                if (dial != null) keepaliveJob = scope.launch { keepaliveLoop() }
            } catch (e: Exception) {
                closeWithError(e)
                throw e
            }
        }
    }

    /** Stores [t] as the transport unless the session closed meanwhile, in which case it cancels it. */
    private fun adoptTransport(t: Http2Wire): Boolean {
        synchronized(streamsLock) {
            if (state != State.CLOSED) {
                transport = t
                return true
            }
        }
        t.cancel()
        return false
    }

    /**
     * Pooled connections only: a PING once streams are open and the server has
     * sent nothing for [keepaliveIdleMs]; no frame at all within
     * [keepaliveTimeoutMs] after it fails the connection and every stream on
     * it, so the applications reconnect on a fresh one. Without it a stream on
     * a connection the network had dropped silently hung until the
     * application gave up on its own.
     */
    private suspend fun keepaliveLoop() {
        while (state != State.CLOSED) {
            val silentMs = (System.nanoTime() - lastFrameNanos) / 1_000_000
            val busy = synchronized(streamsLock) { streams.isNotEmpty() }
            if (!busy || silentMs < keepaliveIdleMs) {
                delay(if (busy) keepaliveIdleMs - silentMs else keepaliveIdleMs)
                continue
            }
            val before = lastFrameNanos
            sendFrameRaw(Http2Framer.pingFrame())
            delay(keepaliveTimeoutMs)
            if (lastFrameNanos == before && state != State.CLOSED) {
                closeWithError(Http2Error.ConnectionFailed("no reply to keepalive PING within $keepaliveTimeoutMs ms"))
            }
        }
    }

    private suspend fun sendConnectionPreface(t: Http2Wire) {
        val buf = ByteArrayOutputStream()
        buf.write(CONNECTION_PREFACE)

        val settings = Http2Framer.settingsFrame(listOf(
            0x1 to 65536,
            0x2 to 0,
            0x3 to MAX_CONCURRENT_STREAMS,
            0x4 to Http2FlowControl.NAIVE_INITIAL_WINDOW_SIZE,
            0x5 to 16384,
            0x6 to 262144,
        ))
        buf.write(Http2Framer.serialize(settings))

        val windowUpdate = Http2Framer.windowUpdateFrame(
            streamID = 0,
            increment = Http2FlowControl.CONNECTION_WINDOW_UPDATE_INCREMENT
        )
        buf.write(Http2Framer.serialize(windowUpdate))

        t.send(buf.toByteArray())
    }

    /** Processes frames until server SETTINGS is received and ACK'd; CONNECT is per-stream. */
    private suspend fun processHandshake(t: Http2Wire) {
        while (true) {
            val frame = Http2Framer.deserialize(receiveBuffer)
            if (frame == null) {
                readFromTransport(t)
                continue
            }

            when (frame.type) {
                Http2FrameType.SETTINGS -> {
                    if (frame.hasFlag(Http2FrameFlags.ACK)) continue
                    handleServerSettings(frame)
                    sendFrameRaw(Http2Framer.settingsAckFrame())
                    return
                }

                Http2FrameType.WINDOW_UPDATE -> {
                    Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                        if (frame.streamID == 0) connectionSendWindow += inc
                    }
                }

                Http2FrameType.PING -> {
                    if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                        sendFrameRaw(Http2Framer.pingAckFrame(frame.payload))
                    }
                }

                Http2FrameType.GOAWAY -> {
                    val parsed = Http2Framer.parseGoaway(frame.payload)
                    logger.warning("GOAWAY during handshake: ${parsed?.lastStreamID}, ${parsed?.errorCode}")
                    throw Http2Error.Goaway()
                }

                else -> {}
            }
        }
    }

    private suspend fun readLoop() {
        val t = transport ?: return
        try {
            while (state != State.CLOSED) {
                val frame = Http2Framer.deserialize(receiveBuffer)
                if (frame == null) {
                    readFromTransport(t)
                    continue
                }
                routeFrame(frame)
            }
        } catch (e: Exception) {
            if (state != State.CLOSED) {
                logger.error("Read loop error: ${e.message}")
                closeWithError(e)
            }
        }
    }

    /** Routes one frame; throws on a connection error, which [readLoop] turns into [closeWithError]. */
    private fun routeFrame(frame: Http2Frame) {
        lastActivityNanos = System.nanoTime()
        lastFrameNanos = lastActivityNanos

        // RFC 9113 §6.10: an unfinished header block may be followed by nothing
        // but its own CONTINUATION frames.
        if (pendingHeaderBlock != null &&
            (frame.type != Http2FrameType.CONTINUATION || frame.streamID != pendingHeadersStreamID)
        ) {
            throw Http2Error.ProtocolError(
                "${frame.type} on stream ${frame.streamID} inside the header block of stream $pendingHeadersStreamID"
            )
        }

        when (frame.type) {
            Http2FrameType.DATA -> {
                if (frame.streamID == 0) return
                val data = Http2Framer.dataPayload(frame)
                    ?: throw Http2Error.ProtocolError("DATA on stream ${frame.streamID}: padding longer than the frame")
                val stream = synchronized(streamsLock) { streams[frame.streamID] }
                if (stream == null) {
                    // Closed on our side already (our RST and this frame crossed),
                    // but the server spent connection window on it: credit it.
                    creditConnection(frame.payload.size)
                    return
                }

                // §6.1: padding counts against both windows but never reaches
                // the application, so it is acknowledged here and now.
                val padding = frame.payload.size - data.size
                if (padding > 0) acknowledgeConsumedData(frame.streamID, padding)

                // WINDOW_UPDATE deferred to consume time; see [acknowledgeConsumedData]
                // (mirrors iOS HTTP2Stream.acknowledgeConsumedData semantics).
                if (data.isNotEmpty()) {
                    stream.deliverData(data)
                }

                if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                    // END_STREAM is a clean half-close from the server, not a reset.
                    stream.deliverEndStream()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
                }
            }

            Http2FrameType.HEADERS -> {
                if (frame.streamID == 0) throw Http2Error.ProtocolError("HEADERS on stream 0")
                val fragment = Http2Framer.headerBlockFragment(frame)
                    ?: throw Http2Error.ProtocolError("HEADERS on stream ${frame.streamID}: padding or priority longer than the frame")
                if (frame.hasFlag(Http2FrameFlags.END_HEADERS)) {
                    deliverHeaderBlock(frame.streamID, frame.flags, fragment)
                } else {
                    pendingHeadersStreamID = frame.streamID
                    pendingHeadersFlags = frame.flags
                    pendingHeaderBlock = ByteArrayOutputStream(fragment.size * 2).also { it.write(fragment) }
                }
            }

            Http2FrameType.CONTINUATION -> {
                val block = pendingHeaderBlock
                    ?: throw Http2Error.ProtocolError("CONTINUATION on stream ${frame.streamID} without HEADERS")
                if (block.size() + frame.payload.size > MAX_HEADER_BLOCK_SIZE) {
                    throw Http2Error.ProtocolError("header block on stream ${frame.streamID} over $MAX_HEADER_BLOCK_SIZE bytes")
                }
                block.write(frame.payload)
                if (frame.hasFlag(Http2FrameFlags.END_HEADERS)) {
                    pendingHeaderBlock = null
                    deliverHeaderBlock(pendingHeadersStreamID, pendingHeadersFlags, block.toByteArray())
                }
            }

            Http2FrameType.RST_STREAM -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] }
                if (stream != null) {
                    stream.deliverReset()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
                }
            }

            Http2FrameType.SETTINGS -> {
                if (frame.hasFlag(Http2FrameFlags.ACK)) return
                handleServerSettings(frame)
                scope.launch { sendFrameRaw(Http2Framer.settingsAckFrame()) }
            }

            Http2FrameType.PING -> {
                if (!frame.hasFlag(Http2FrameFlags.ACK)) {
                    scope.launch { sendFrameRaw(Http2Framer.pingAckFrame(frame.payload)) }
                }
            }

            Http2FrameType.WINDOW_UPDATE -> {
                Http2Framer.parseWindowUpdate(frame.payload)?.let { inc ->
                    if (frame.streamID == 0) {
                        synchronized(flowLock) {
                            connectionSendWindow += inc
                            // Wake any sender suspended on connection-level flow control.
                            connectionWindowAwaiter?.complete(Unit)
                            connectionWindowAwaiter = null
                        }
                    } else {
                        synchronized(streamsLock) { streams[frame.streamID] }
                            ?.deliverWindowUpdate(inc)
                    }
                }
            }

            Http2FrameType.GOAWAY -> {
                val parsed = Http2Framer.parseGoaway(frame.payload)
                goawayReceived = true
                if (parsed != null) {
                    goawayLastStreamID = parsed.lastStreamID
                    logger.warning("GOAWAY: lastStreamID=${parsed.lastStreamID}, errorCode=${parsed.errorCode}")

                    val affected = synchronized(streamsLock) {
                        streams.filter { it.key > parsed.lastStreamID }
                    }
                    for ((sid, stream) in affected) {
                        stream.deliverGoaway()
                        synchronized(streamsLock) { streams.remove(sid) }
                    }
                }

                if (synchronized(streamsLock) { streams.isEmpty() }) {
                    close()
                }
            }
        }
    }

    /**
     * Decodes a complete header block and hands it to its stream. Decoded
     * whether or not the stream still exists: HPACK's dynamic table is shared
     * by every stream on the connection (RFC 7541 §2.2), and skipping the
     * block of a stream we had already reset (its response was in flight)
     * dropped the table insertions it carried, after which every later header
     * block on the connection decoded to garbage. A block that does not
     * decode leaves the table in an unknown state, so it is a connection
     * error (RFC 9113 §4.3, COMPRESSION_ERROR), not a stream's problem.
     */
    private fun deliverHeaderBlock(streamID: Int, flags: Int, block: ByteArray) {
        val headers = hpackDecoder.decode(block)
            ?: throw Http2Error.ProtocolError("COMPRESSION_ERROR: header block on stream $streamID does not decode")
        val stream = synchronized(streamsLock) { streams[streamID] } ?: return
        stream.deliverHeaders(headers)
        // Trailers (gRPC's grpc-status) end the stream on a HEADERS frame.
        if (flags and Http2FrameFlags.END_STREAM != 0) {
            stream.deliverEndStream()
            synchronized(streamsLock) { streams.remove(streamID) }
        }
    }

    suspend fun sendConnectRequest(stream: Http2Stream, destination: String) {
        val extraHeaders = mutableListOf<Pair<String, String>>()

        configuration?.basicAuth?.let { auth ->
            extraHeaders.add("proxy-authorization" to "Basic $auth")
        }
        extraHeaders.add("user-agent" to USER_AGENT)
        extraHeaders.addAll(NaivePaddingNegotiator.requestHeaders())

        val headerBlock = HpackEncoder.encodeConnectRequest(
            authority = destination,
            extraHeaders = extraHeaders
        )
        openStream(stream) { id -> Http2Framer.headersFrame(streamID = id, headerBlock = headerBlock, endStream = false) }
    }

    /**
     * Opens [stream] as an ordinary request with [headerBlock] (HPACK); the
     * body, if any, follows through [sendData]. [endStream] for a request with
     * no body, such as a GET.
     */
    suspend fun sendRequestHeaders(stream: Http2Stream, headerBlock: ByteArray, endStream: Boolean) {
        openStream(stream) { id -> Http2Framer.headersFrame(streamID = id, headerBlock = headerBlock, endStream = endStream) }
    }

    suspend fun sendData(stream: Http2Stream, data: ByteArray, endStream: Boolean = false) {
        val streamID = stream.streamID
        val streamFlowControl = stream.flowControl
        val maxPayload = Http2Framer.MAX_DATA_PAYLOAD
        var currentOffset = 0

        if (data.isEmpty()) {
            if (endStream) {
                writeMutex.withLock {
                    transport?.send(Http2Framer.serialize(Http2Framer.dataFrame(streamID, ByteArray(0), endStream = true)))
                        ?: throw Http2Error.ConnectionFailed("Transport closed")
                }
            }
            return
        }

        while (currentOffset < data.size) {
            // Checked per chunk: a stream reset or closed in the middle of a
            // long write used to keep sending DATA on it to the end.
            if (!stream.isConnected) throw Http2Error.StreamReset(streamID)
            val remaining = data.size - currentOffset
            // Taken under the lock: with many streams sending at once, an
            // unlocked read-then-subtract let two of them spend the same window.
            val chunkSize = synchronized(flowLock) {
                val allowed = minOf(remaining, maxPayload, connectionSendWindow, streamFlowControl.sendWindow)
                if (allowed > 0) connectionSendWindow -= allowed
                allowed
            }
            if (chunkSize <= 0) {
                // Flow-control blocked. Suspend until a WINDOW_UPDATE arrives
                // for the exhausted scope (connection or stream). Mirrors iOS
                // HTTP2Session.swift:451-455 / HTTP2Connection.swift:427-433
                // — iOS schedules a 50ms retry; we use awaiters for precision.
                if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Session closed")
                if (connectionSendWindow <= 0) {
                    val awaiter = synchronized(flowLock) {
                        if (connectionSendWindow > 0) null
                        else (connectionWindowAwaiter ?: CompletableDeferred<Unit>().also {
                            connectionWindowAwaiter = it
                        })
                    }
                    awaiter?.await()
                } else {
                    streamFlowControl.awaitWindow()
                }
                continue
            }

            streamFlowControl.consumeSend(chunkSize)

            val chunk = data.copyOfRange(currentOffset, currentOffset + chunkSize)
            val last = currentOffset + chunkSize >= data.size
            val frame = Http2Framer.dataFrame(streamID = streamID, payload = chunk, endStream = endStream && last)

            writeMutex.withLock {
                transport?.send(Http2Framer.serialize(frame))
                    ?: throw Http2Error.ConnectionFailed("Transport closed")
            }

            currentOffset += chunkSize
        }
    }

    private fun handleServerSettings(frame: Http2Frame) {
        val settings = Http2Framer.parseSettings(frame.payload)
        for ((id, value) in settings) {
            when (id) {
                0x3 -> { // SETTINGS_MAX_CONCURRENT_STREAMS
                    streamLimit = minOf(MAX_CONCURRENT_STREAMS, value.coerceAtLeast(1))
                }
                0x4 -> { // SETTINGS_INITIAL_WINDOW_SIZE
                    val delta = value - serverInitialWindowSize
                    serverInitialWindowSize = value
                    // RFC 7540 §6.9.2: shift every existing stream's send window by delta.
                    // A snapshot: streams open and close on other threads, and
                    // iterating the live map threw ConcurrentModificationException
                    // out of the read loop, taking the connection down.
                    val open = synchronized(streamsLock) { streams.values.toList() }
                    for (stream in open) {
                        stream.adjustSendWindow(delta)
                    }
                }
            }
        }
    }

    private suspend fun sendWindowUpdate(streamID: Int, increment: Int) {
        try {
            sendFrameRaw(Http2Framer.windowUpdateFrame(streamID = streamID, increment = increment))
        } catch (e: Exception) {
            logger.warning("Failed to send WINDOW_UPDATE: ${e.message}")
        }
    }

    private suspend fun sendFrameRaw(frame: Http2Frame) {
        writeMutex.withLock {
            try {
                transport?.send(Http2Framer.serialize(frame))
            } catch (e: Exception) {
                logger.warning("Failed to send frame: ${e.message}")
            }
        }
    }

    private suspend fun readFromTransport(t: Http2Wire) {
        val data = t.receive()
        if (data == null || data.isEmpty()) {
            throw Http2Error.ConnectionFailed("Connection closed")
        }
        receiveBuffer.append(data)
        if (receiveBuffer.available > MAX_RECEIVE_BUFFER_SIZE) {
            receiveBuffer.clear()
            throw Http2Error.ConnectionFailed("Receive buffer exceeded $MAX_RECEIVE_BUFFER_SIZE bytes")
        }
    }

    private fun closeWithError(error: Exception) {
        // The transition is taken under the lock [adoptTransport] and the
        // READY step use, so a close during the dial is never lost.
        val allStreams = synchronized(streamsLock) {
            if (state == State.CLOSED) return
            state = State.CLOSED
            val snapshot = streams.values.toList()
            streams.clear()
            snapshot
        }
        keepaliveJob?.cancel()
        keepaliveJob = null
        for (stream in allStreams) {
            stream.deliverError(error)
        }

        synchronized(flowLock) {
            connectionWindowAwaiter?.completeExceptionally(error)
            connectionWindowAwaiter = null
        }

        transport?.cancel()
        transport = null
        onClose?.invoke()
    }

    fun close() {
        closeWithError(Http2Error.ConnectionFailed(CLOSED_MESSAGE))
        hpackDecoder.reset()
    }
}
