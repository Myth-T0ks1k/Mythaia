package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.protocol.naive.NaiveConfiguration
import com.mythaia.vpn.protocol.naive.NaivePaddingNegotiator
import com.mythaia.vpn.protocol.naive.NaiveTlsTransport
import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
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
    private val dial: (suspend () -> Http2Wire)? = null
) {
    companion object {
        private const val USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"
        private val CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
        private const val MAX_RECEIVE_BUFFER_SIZE = 2_097_152
        private const val MAX_CONCURRENT_STREAMS = 100
    }

    enum class State { IDLE, CONNECTING, READY, CLOSED }

    @Volatile
    private var state = State.IDLE

    @Volatile
    private var goawayReceived = false
    private var goawayLastStreamID = Int.MAX_VALUE

    private var transport: Http2Wire? = null
    private val receiveBuffer = Http2Buffer()

    /** The server's SETTINGS_MAX_CONCURRENT_STREAMS, when lower than ours. */
    @Volatile
    private var streamLimit = MAX_CONCURRENT_STREAMS

    /** When the last stream ended or the last frame arrived; see [idleNanos]. */
    @Volatile
    private var lastActivityNanos = System.nanoTime()

    /** How long the session has carried no stream at all; 0 while one is open. */
    val idleNanos: Long
        get() = if (synchronized(streamsLock) { streams.isNotEmpty() || reserved > 0 }) 0L
        else System.nanoTime() - lastActivityNanos

    /** Not dialled yet, or still in its handshake: a caller may join and wait. */
    val isStarting: Boolean get() = state == State.IDLE || state == State.CONNECTING

    private val streams = mutableMapOf<Int, Http2Stream>()
    private var nextStreamID = 1
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

    val hpackDecoder = HpackDecoder()

    private val writeMutex = Mutex()

    /** One dial at a time: concurrent first callers wait here for the handshake. */
    private val readyMutex = Mutex()

    val hasCapacity: Boolean
        get() = state == State.READY && !goawayReceived &&
            synchronized(streamsLock) { streams.size + reserved < streamLimit }

    val isClosed: Boolean get() = state == State.CLOSED

    suspend fun acquireStream(destination: String): Http2Stream {
        ensureReady()

        if (state != State.READY) throw Http2Error.NotReady()
        if (goawayReceived) throw Http2Error.Goaway()

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
        if (state != State.READY || goawayReceived) return null
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
                val id = nextStreamID
                nextStreamID += 2
                if (reserved > 0) reserved -= 1
                streams[id] = stream
                id
            }
            stream.assignId(id)
            t.send(Http2Framer.serialize(headers(id)))
        }
    }

    fun removeStream(streamID: Int) {
        synchronized(streamsLock) { streams.remove(streamID) }
        lastActivityNanos = System.nanoTime()
        if (goawayReceived && synchronized(streamsLock) { streams.isEmpty() }) {
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
        val stream = synchronized(streamsLock) { streams[streamID] }
        stream?.flowControl?.consumeRecv(bytes)?.let { streamInc ->
            scope.launch { sendWindowUpdate(streamID, streamInc) }
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
        if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Session closed")

        // A mutex rather than a flag: callers on several threads used to be able
        // to see "not connecting" at once and both dial.
        readyMutex.withLock {
            if (state == State.READY) return
            if (state == State.CLOSED) throw Http2Error.ConnectionFailed("Session closed")
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
                        tunnel = tunnel
                    ).also {
                        transport = it
                        it.connect()
                    }
                }
                transport = t

                sendConnectionPreface(t)
                processHandshake(t)

                state = State.READY
                lastActivityNanos = System.nanoTime()

                scope.launch { readLoop() }
            } catch (e: Exception) {
                state = State.CLOSED
                transport?.cancel()
                transport = null
                onClose?.invoke()
                throw e
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

    private fun routeFrame(frame: Http2Frame) {
        lastActivityNanos = System.nanoTime()
        when (frame.type) {
            Http2FrameType.DATA -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] } ?: return

                // WINDOW_UPDATE deferred to consume time; see [acknowledgeConsumedData]
                // (mirrors iOS HTTP2Stream.acknowledgeConsumedData semantics).
                if (frame.payload.isNotEmpty()) {
                    stream.deliverData(frame.payload)
                }

                if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                    // END_STREAM is a clean half-close from the server, not a reset.
                    stream.deliverEndStream()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
                }
            }

            Http2FrameType.HEADERS -> {
                if (frame.streamID == 0) return
                val stream = synchronized(streamsLock) { streams[frame.streamID] } ?: return
                val headers = hpackDecoder.decode(frame.payload)
                if (headers != null) {
                    stream.deliverHeaders(headers)
                } else {
                    stream.deliverError(Http2Error.ProtocolError("Failed to decode headers"))
                }
                // Trailers (gRPC's grpc-status) end the stream on a HEADERS frame.
                if (frame.hasFlag(Http2FrameFlags.END_STREAM)) {
                    stream.deliverEndStream()
                    synchronized(streamsLock) { streams.remove(frame.streamID) }
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

    suspend fun sendData(
        streamID: Int,
        data: ByteArray,
        streamFlowControl: Http2StreamFlowControl,
        endStream: Boolean = false
    ) {
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
                    for (stream in streams.values) {
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
        if (state == State.CLOSED) return
        state = State.CLOSED

        val allStreams = synchronized(streamsLock) {
            val snapshot = streams.values.toList()
            streams.clear()
            snapshot
        }
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
        if (state == State.CLOSED) return
        state = State.CLOSED

        val allStreams = synchronized(streamsLock) {
            val snapshot = streams.values.toList()
            streams.clear()
            snapshot
        }
        for (stream in allStreams) {
            stream.deliverError(Http2Error.ConnectionFailed("Session closed"))
        }

        synchronized(flowLock) {
            connectionWindowAwaiter?.completeExceptionally(
                Http2Error.ConnectionFailed("Session closed")
            )
            connectionWindowAwaiter = null
        }

        transport?.cancel()
        transport = null
        hpackDecoder.reset()
        onClose?.invoke()
    }
}
