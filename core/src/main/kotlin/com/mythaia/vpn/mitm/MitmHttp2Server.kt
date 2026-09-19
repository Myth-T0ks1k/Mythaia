package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.naive.http2.HpackDecoder
import com.mythaia.vpn.protocol.naive.http2.HpackEncoder
import com.mythaia.vpn.protocol.naive.http2.Http2Buffer
import com.mythaia.vpn.protocol.naive.http2.Http2FrameFlags
import com.mythaia.vpn.protocol.naive.http2.Http2FrameType
import com.mythaia.vpn.protocol.naive.http2.Http2Framer
import com.mythaia.vpn.protocol.naive.http2.Http2StreamFlowControl
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The **server** half of an intercepted HTTP/2 connection: it terminates the
 * client's h2 connection (the client believes it is talking to the origin),
 * demultiplexes its frames into a per-stream request [HttpMessage], and encodes a
 * response [HttpMessage] back onto the right stream. It is the h2 analogue of the
 * request/response reader in [Http1Codec], and the piece stage 2's h2 bridge sits
 * on top of.
 *
 * # What it does, and the one place it simplifies
 *
 * After [run] sends the server connection preface (a SETTINGS frame advertising
 * `ENABLE_PUSH=0`, a stream-concurrency cap, a large receive window and a header
 * list cap, followed by a connection-level WINDOW_UPDATE) and validates the 24-byte
 * client preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), it runs a single read loop:
 *
 *  - **HEADERS (+CONTINUATION)** are reassembled and HPACK-decoded through one
 *    stateful inbound [HpackDecoder]; the pseudo-header section (`:method`,
 *    `:path`, `:scheme`, `:authority`) becomes the request line — method, an
 *    absolute `scheme://authority/path` URL, and a synthesised `Host` — and the
 *    regular fields become [HttpHeader]s in wire order.
 *  - **DATA** is buffered into that stream's body, honouring flow control: the
 *    on-wire length of every DATA frame is immediately credited back with a
 *    per-stream and a connection WINDOW_UPDATE, so the client's window never
 *    stalls the upload.
 *  - once a stream half-closes (`END_STREAM` on its HEADERS or a DATA frame, or a
 *    trailer HEADERS block) the fully-assembled request is handed to the caller
 *    through [acceptRequest].
 *
 * The deliberate simplification is that a request is delivered **only once its
 * whole body is buffered**, not incrementally: [HttpMessage] carries the complete
 * decompressed body a rule reads, so the server buffers up to
 * [MAX_BUFFERED_BODY_BYTES] and refuses (RST_STREAM) a larger upload rather than
 * streaming a partial message. Trailer fields are dropped. Both are noted as
 * deferrals for a later streaming stage.
 *
 * The caller sends a response with [Http2ServerStream.sendResponse]: `:status`
 * plus the response headers are HPACK-encoded (literal-without-indexing only, so
 * the outbound table is always empty and can never desync — see [HpackEncoder]),
 * then the body is framed as DATA respecting the peer's per-stream and connection
 * send windows, with `END_STREAM` on the last frame. SETTINGS, WINDOW_UPDATE,
 * PING and RST_STREAM from the client are handled while a response is in flight,
 * because the read loop keeps running independently of the response senders.
 *
 * # The two HPACK tables
 *
 * Header compression is stateful per direction. The inbound decoder ([HpackDecoder])
 * owns the client→server dynamic table and must see every request header block in
 * order; a decode failure is treated as a fatal `COMPRESSION_ERROR` (a desync would
 * corrupt every later header). The outbound encoder never indexes, so the
 * server→client dynamic table stays empty and trivially in step.
 *
 * # Concurrency
 *
 * [run] owns the read loop and is the only mutator of per-stream request state; it
 * is launched once by the caller. Response senders run on the caller's coroutines;
 * frame writes are serialised through a [Mutex], the shared connection send window
 * through a monitor, and the per-stream response send window through the reused
 * [Http2StreamFlowControl]. Stream bookkeeping touched by both sides is guarded by
 * [streamsLock].
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmHttp2Server(
    private val client: MitmByteLeg,
    private val host: String,
    private val logger: MythaiaLogger = MythaiaLogger("MitmHttp2Server")
) {

    // MARK: - Public surface

    /**
     * Drives the connection: sends the server preface, validates the client
     * preface, then reads and demultiplexes frames until the client closes or a
     * fatal protocol violation forces a GOAWAY. Closes the leg and the request
     * queue on return. Launch this once (e.g. `launch { server.run() }`) and drive
     * requests with [acceptRequest] concurrently.
     */
    suspend fun run() {
        sendServerPreface()
        readLoop()
    }

    /**
     * Suspends for the next fully-assembled request stream, or returns `null` once
     * the connection has ended (client EOF, fatal violation, or [close]). Each
     * returned [Http2ServerStream] is answered exactly once with
     * [Http2ServerStream.sendResponse].
     */
    suspend fun acceptRequest(): Http2ServerStream? =
        requestChannel.receiveCatching().getOrNull()

    /** Tears the connection down; a running [run] loop unwinds and closes the leg. */
    fun close() {
        closed = true
        requestChannel.close()
        runCatching { client.close() }
    }

    // MARK: - Connection state (read loop only, except where noted)

    private val buffer = Http2Buffer()
    private val inboundHpack = HpackDecoder()
    private val writeMutex = Mutex()

    @Volatile private var closed = false
    private var goawaySent = false
    private var highestStreamID = 0

    /** Header block being reassembled across HEADERS + CONTINUATION, if any. */
    private var pending: PendingHeaders? = null

    private val streamsLock = Any()
    /** Streams whose request body is still arriving (headers seen, no END_STREAM). */
    private val assembling = HashMap<Int, RequestAssembly>()
    /** Streams delivered to the caller and awaiting/producing a response. */
    private val responders = HashMap<Int, Http2ServerStream>()
    /** WINDOW_UPDATE credit that arrived before a stream's responder existed. */
    private val pendingStreamCredit = HashMap<Int, Int>()

    private val requestChannel = Channel<Http2ServerStream>(Channel.UNLIMITED)

    // MARK: - Flow control (send side)

    private val flowLock = Any()
    private var connectionSendWindow = DEFAULT_INITIAL_WINDOW
    private var connectionWindowAwaiter: CompletableDeferred<Unit>? = null
    /** The client's advertised SETTINGS_INITIAL_WINDOW_SIZE; seeds each response stream. */
    private var clientInitialWindowSize = DEFAULT_INITIAL_WINDOW

    // MARK: - Preface

    private suspend fun sendServerPreface() {
        val settings = Http2Framer.settingsFrame(
            listOf(
                0x2 to 0,                              // SETTINGS_ENABLE_PUSH = 0
                0x3 to MAX_CONCURRENT_STREAMS,         // SETTINGS_MAX_CONCURRENT_STREAMS
                0x4 to RECEIVE_WINDOW,                 // SETTINGS_INITIAL_WINDOW_SIZE
                0x5 to MAX_FRAME_PAYLOAD,              // SETTINGS_MAX_FRAME_SIZE
                0x6 to MAX_HEADER_LIST_SIZE,           // SETTINGS_MAX_HEADER_LIST_SIZE
            )
        )
        val connectionCredit = Http2Framer.windowUpdateFrame(
            streamID = 0,
            increment = RECEIVE_WINDOW - DEFAULT_INITIAL_WINDOW
        )
        writeMutex.withLock {
            client.send(Http2Framer.serialize(settings))
            client.send(Http2Framer.serialize(connectionCredit))
        }
    }

    /**
     * Reads and validates the 24-byte client connection preface, pushing any bytes
     * that followed it (the client's SETTINGS and beyond) into the frame buffer.
     */
    private suspend fun validateClientPreface() {
        val acc = ByteArrayOutputStream()
        while (acc.size() < CLIENT_PREFACE.size) {
            val chunk = client.receive()
                ?: throw Http2ServerException("client closed before sending the connection preface", PROTOCOL_ERROR)
            if (chunk.isNotEmpty()) acc.write(chunk)
        }
        val bytes = acc.toByteArray()
        val head = bytes.copyOfRange(0, CLIENT_PREFACE.size)
        if (!head.contentEquals(CLIENT_PREFACE)) {
            throw Http2ServerException("invalid client connection preface", PROTOCOL_ERROR)
        }
        if (bytes.size > CLIENT_PREFACE.size) {
            buffer.append(bytes.copyOfRange(CLIENT_PREFACE.size, bytes.size))
        }
    }

    // MARK: - Read loop

    private suspend fun readLoop() {
        try {
            validateClientPreface()
            while (!closed) {
                val frame = nextFrame()
                if (frame == null) {
                    val chunk = client.receive() ?: break // clean client EOF
                    if (chunk.isNotEmpty()) {
                        buffer.append(chunk)
                        if (buffer.available > MAX_RECEIVE_BUFFER) {
                            throw Http2ServerException("receive buffer exceeded cap", INTERNAL_ERROR)
                        }
                    }
                    continue
                }
                handleFrame(frame)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Http2ServerException) {
            logger.warning("[h2] $host: ${e.message}; sending GOAWAY(${e.errorCode})")
            sendGoaway(e.errorCode)
        } catch (e: Exception) {
            logger.warning("[h2] $host: read loop ended on ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            shutdown()
        }
    }

    /**
     * Parses one complete frame, consuming its bytes, or returns `null` when the
     * buffer does not yet hold a full frame. Throws when a frame's declared length
     * exceeds the receive cap — checked from the 9-byte header alone, before the
     * payload is buffered, so a hostile length can't force an unbounded allocation.
     *
     * The raw type byte is read directly (rather than through
     * [Http2Framer.deserialize]) because the naive client's [Http2FrameType] enum
     * omits CONTINUATION / PRIORITY / PUSH_PROMISE, which the server must
     * demultiplex distinctly; all buffering and every control-frame parser is still
     * the reused [Http2Framer] machinery.
     */
    private fun nextFrame(): RawFrame? {
        if (buffer.available < Http2Framer.HEADER_SIZE) return null
        val header = buffer.peekHeader()
        val length = ((header[0].toInt() and 0xFF) shl 16) or
            ((header[1].toInt() and 0xFF) shl 8) or
            (header[2].toInt() and 0xFF)
        if (length > MAX_RECEIVED_FRAME_PAYLOAD) {
            throw Http2ServerException("frame length $length exceeds cap $MAX_RECEIVED_FRAME_PAYLOAD", FRAME_SIZE_ERROR)
        }
        if (buffer.available < Http2Framer.HEADER_SIZE + length) return null
        val typeCode = header[3].toInt() and 0xFF
        val flags = header[4].toInt() and 0xFF
        val streamID = (((header[5].toInt() and 0xFF) shl 24) or
            ((header[6].toInt() and 0xFF) shl 16) or
            ((header[7].toInt() and 0xFF) shl 8) or
            (header[8].toInt() and 0xFF)) and 0x7FFFFFFF
        buffer.skip(Http2Framer.HEADER_SIZE)
        val payload = buffer.read(length)
        return RawFrame(typeCode, flags, streamID, payload)
    }

    private suspend fun handleFrame(frame: RawFrame) {
        // A HEADERS block being continued must not be interleaved with any other
        // frame; RFC 7540 §6.2 makes that a connection error.
        if (pending != null && frame.typeCode != FRAME_TYPE_CONTINUATION) {
            throw Http2ServerException("frame type ${frame.typeCode} interleaved with a pending HEADERS block", PROTOCOL_ERROR)
        }
        when (frame.typeCode) {
            Http2FrameType.DATA.value -> handleData(frame)
            Http2FrameType.HEADERS.value -> handleHeaders(frame)
            FRAME_TYPE_PRIORITY -> { /* stream prioritisation is advisory; ignored */ }
            Http2FrameType.RST_STREAM.value -> handleRstStream(frame)
            Http2FrameType.SETTINGS.value -> handleSettings(frame)
            FRAME_TYPE_PUSH_PROMISE -> throw Http2ServerException("client sent PUSH_PROMISE", PROTOCOL_ERROR)
            Http2FrameType.PING.value -> handlePing(frame)
            Http2FrameType.GOAWAY.value ->
                logger.info("[h2] $host: client GOAWAY; finishing in-flight streams")
            Http2FrameType.WINDOW_UPDATE.value -> handleWindowUpdate(frame)
            FRAME_TYPE_CONTINUATION -> handleContinuation(frame)
            else -> { /* unknown frame type — ignore per RFC 7540 §4.1 */ }
        }
    }

    // MARK: - SETTINGS / PING / WINDOW_UPDATE / RST_STREAM

    private suspend fun handleSettings(frame: RawFrame) {
        if (frame.streamID != 0) throw Http2ServerException("SETTINGS on non-zero stream", PROTOCOL_ERROR)
        if (frame.flags and Http2FrameFlags.ACK != 0) {
            if (frame.payload.isNotEmpty()) throw Http2ServerException("SETTINGS ACK with payload", FRAME_SIZE_ERROR)
            return
        }
        if (frame.payload.size % 6 != 0) throw Http2ServerException("SETTINGS payload not a multiple of 6", FRAME_SIZE_ERROR)
        for ((id, value) in Http2Framer.parseSettings(frame.payload)) {
            when (id) {
                0x2 -> if (value != 0 && value != 1) {
                    throw Http2ServerException("SETTINGS_ENABLE_PUSH must be 0 or 1", PROTOCOL_ERROR)
                }
                0x4 -> { // SETTINGS_INITIAL_WINDOW_SIZE
                    if (value < 0) throw Http2ServerException("SETTINGS_INITIAL_WINDOW_SIZE over 2^31-1", FLOW_CONTROL_ERROR)
                    applyClientInitialWindow(value)
                }
                // 0x1 (HEADER_TABLE_SIZE): our encoder never indexes, so nothing to size.
                // 0x5 (MAX_FRAME_SIZE): we cap our own DATA at 16 KiB, always <= any legal value.
                // 0x6 (MAX_HEADER_LIST_SIZE): advisory for our encoder; responses stay small.
            }
        }
        writeMutex.withLock { client.send(Http2Framer.serialize(Http2Framer.settingsAckFrame())) }
    }

    private fun applyClientInitialWindow(newValue: Int) {
        val delta = newValue - clientInitialWindowSize
        clientInitialWindowSize = newValue
        if (delta == 0) return
        // RFC 7540 §6.9.2: shift every open response stream's send window by delta.
        val open = synchronized(streamsLock) { responders.values.toList() }
        for (stream in open) stream.flowControl.adjustSendWindow(delta)
    }

    private suspend fun handlePing(frame: RawFrame) {
        if (frame.streamID != 0) throw Http2ServerException("PING on non-zero stream", PROTOCOL_ERROR)
        if (frame.payload.size != 8) throw Http2ServerException("PING payload not 8 bytes", FRAME_SIZE_ERROR)
        if (frame.flags and Http2FrameFlags.ACK == 0) {
            writeMutex.withLock { client.send(Http2Framer.serialize(Http2Framer.pingAckFrame(frame.payload))) }
        }
    }

    private suspend fun handleWindowUpdate(frame: RawFrame) {
        if (frame.payload.size != 4) throw Http2ServerException("WINDOW_UPDATE payload not 4 bytes", FRAME_SIZE_ERROR)
        val increment = Http2Framer.parseWindowUpdate(frame.payload) ?: return
        if (increment == 0) {
            if (frame.streamID == 0) throw Http2ServerException("WINDOW_UPDATE increment 0 on connection", PROTOCOL_ERROR)
            resetStream(frame.streamID, PROTOCOL_ERROR)
            return
        }
        if (frame.streamID == 0) {
            synchronized(flowLock) {
                if (connectionSendWindow.toLong() + increment > MAX_WINDOW) {
                    throw Http2ServerException("connection send window overflow", FLOW_CONTROL_ERROR)
                }
                connectionSendWindow += increment
                connectionWindowAwaiter?.complete(Unit)
                connectionWindowAwaiter = null
            }
            return
        }
        val stream = synchronized(streamsLock) { responders[frame.streamID] }
        if (stream != null) {
            stream.flowControl.applyWindowUpdate(increment)
        } else {
            // Credit for a stream whose responder does not exist yet (client
            // pre-crediting the response) — stash it and apply at delivery. Bounded:
            // a client that sends WINDOW_UPDATEs for a flood of stream ids it never
            // opens would otherwise grow this map without limit (a memory DoS), so a
            // new id past the tracked-stream cap ends the connection.
            synchronized(streamsLock) {
                if (frame.streamID !in pendingStreamCredit &&
                    pendingStreamCredit.size >= MAX_TRACKED_STREAMS
                ) {
                    throw Http2ServerException(
                        "too many WINDOW_UPDATEs for streams with no responder", PROTOCOL_ERROR
                    )
                }
                pendingStreamCredit[frame.streamID] =
                    ((pendingStreamCredit[frame.streamID] ?: 0).toLong() + increment)
                        .coerceAtMost(MAX_WINDOW).toInt()
            }
        }
    }

    private fun handleRstStream(frame: RawFrame) {
        if (frame.streamID == 0) throw Http2ServerException("RST_STREAM on stream 0", PROTOCOL_ERROR)
        if (frame.payload.size != 4) throw Http2ServerException("RST_STREAM payload not 4 bytes", FRAME_SIZE_ERROR)
        synchronized(streamsLock) {
            assembling.remove(frame.streamID)
            pendingStreamCredit.remove(frame.streamID)
            responders.remove(frame.streamID)
        }?.let { stream ->
            stream.markAborted()
            stream.flowControl.cancelAwaiters(Http2ServerException("stream reset by client", CANCEL))
        }
    }

    // MARK: - HEADERS / CONTINUATION

    private suspend fun handleHeaders(frame: RawFrame) {
        if (frame.streamID == 0) throw Http2ServerException("HEADERS on stream 0", PROTOCOL_ERROR)
        if (frame.streamID % 2 == 0) throw Http2ServerException("client HEADERS on even stream ${frame.streamID}", PROTOCOL_ERROR)
        val block = stripHeadersPadding(frame.payload, frame.flags)
            ?: throw Http2ServerException("HEADERS with invalid padding", PROTOCOL_ERROR)
        if (block.size > MAX_HEADER_BLOCK_BYTES) throw Http2ServerException("HEADERS block over cap", PROTOCOL_ERROR)
        val endStream = frame.flags and Http2FrameFlags.END_STREAM != 0
        if (frame.flags and Http2FrameFlags.END_HEADERS != 0) {
            finalizeHeaders(frame.streamID, block, endStream)
        } else {
            pending = PendingHeaders(frame.streamID, ByteArrayOutputStream().apply { write(block) }, endStream)
        }
    }

    private suspend fun handleContinuation(frame: RawFrame) {
        val p = pending ?: throw Http2ServerException("stray CONTINUATION", PROTOCOL_ERROR)
        if (p.streamID != frame.streamID) throw Http2ServerException("CONTINUATION stream id mismatch", PROTOCOL_ERROR)
        p.count++
        if (p.count > MAX_CONTINUATION_FRAMES) throw Http2ServerException("too many CONTINUATION frames", PROTOCOL_ERROR)
        if (p.fragments.size() + frame.payload.size > MAX_HEADER_BLOCK_BYTES) {
            throw Http2ServerException("header block over cap", PROTOCOL_ERROR)
        }
        p.fragments.write(frame.payload)
        if (frame.flags and Http2FrameFlags.END_HEADERS != 0) {
            pending = null
            finalizeHeaders(p.streamID, p.fragments.toByteArray(), p.endStream)
        }
    }

    private suspend fun finalizeHeaders(streamID: Int, block: ByteArray, endStream: Boolean) {
        val decoded = inboundHpack.decode(block)
            ?: throw Http2ServerException("HPACK decode failed (table desync)", COMPRESSION_ERROR)

        val method = decoded.firstOrNull { it.first == ":method" }?.second
        if (method == null) {
            // No :method — a trailer HEADERS on an open stream, or a malformed request.
            val assembly = synchronized(streamsLock) { assembling[streamID] }
            if (assembly != null) {
                finalizeTrailers(assembly, decoded, endStream)
            } else {
                if (streamID > highestStreamID) highestStreamID = streamID
                logger.warning("[h2] $host stream $streamID: request HEADERS missing :method; RST")
                resetStream(streamID, PROTOCOL_ERROR)
            }
            return
        }

        if (streamID <= highestStreamID) throw Http2ServerException("non-increasing stream id $streamID", PROTOCOL_ERROR)
        highestStreamID = streamID

        validateRequestHeaders(decoded)?.let { reason ->
            logger.warning("[h2] $host stream $streamID: $reason; RST")
            resetStream(streamID, PROTOCOL_ERROR)
            return
        }

        val upperMethod = method.uppercase()
        if (!HttpHeader.isValidName(upperMethod)) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }
        if (upperMethod == "CONNECT") {
            logger.warning("[h2] $host stream $streamID: CONNECT cannot be bridged; RST HTTP_1_1_REQUIRED")
            resetStream(streamID, HTTP_1_1_REQUIRED)
            return
        }

        val path = decoded.first { it.first == ":path" }.second
        val scheme = decoded.first { it.first == ":scheme" }.second
        val authority = decoded.firstOrNull { it.first == ":authority" }?.second ?: host
        // Require origin-form (":path" beginning with "/"). This rejects the rare
        // asterisk-form ("OPTIONS *") and any authority/absolute form, which the
        // "scheme://authority$path" URL below would otherwise mangle into a bad
        // Host (e.g. "https://h*") forwarded to the origin.
        if (path.isEmpty() || !path.startsWith("/") || path.any { it.code <= 0x20 || it.code == 0x7F }) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }
        if (!isWireSafeHeaderValue(authority) || !isWireSafeHeaderValue(scheme)) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }

        val contentLength = parseContentLength(decoded)
        if (contentLength == INVALID_CONTENT_LENGTH) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }

        val tracked = synchronized(streamsLock) { assembling.size + responders.size }
        if (tracked >= MAX_TRACKED_STREAMS) {
            logger.warning("[h2] $host stream $streamID: tracked-stream cap reached; REFUSED_STREAM")
            resetStream(streamID, REFUSED_STREAM)
            return
        }

        val regular = decoded
            .filter { !it.first.startsWith(":") && !HttpHeader.nameEquals(it.first, "host") }
            .map { HttpHeader(it.first, it.second) }
        val assembly = RequestAssembly(streamID, upperMethod, scheme, authority, path, regular, contentLength)

        if (endStream) {
            if (contentLength != null && contentLength != 0L) {
                // Declared a body but ended with none (RFC 7540 §8.1.2.6).
                resetStream(streamID, PROTOCOL_ERROR); return
            }
            deliverRequest(assembly, ByteArray(0))
        } else {
            synchronized(streamsLock) { assembling[streamID] = assembly }
        }
    }

    private suspend fun finalizeTrailers(assembly: RequestAssembly, decoded: List<Pair<String, String>>, endStream: Boolean) {
        val streamID = assembly.streamID
        // A trailer section must close the stream and carry no pseudo-headers (RFC 7540 §8.1).
        if (!endStream) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }
        if (decoded.any { it.first.startsWith(":") }) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }
        val remaining = assembly.contentLengthRemaining
        if (remaining != null && remaining != 0L) {
            resetStream(streamID, PROTOCOL_ERROR); return
        }
        synchronized(streamsLock) { assembling.remove(streamID) }
        // Deferral: trailer fields are dropped, not merged into the request.
        deliverRequest(assembly, assembly.body.toByteArray())
    }

    // MARK: - DATA

    private suspend fun handleData(frame: RawFrame) {
        if (frame.streamID == 0) throw Http2ServerException("DATA on stream 0", PROTOCOL_ERROR)
        val onWire = frame.payload.size
        val body = stripDataPadding(frame.payload, frame.flags)
            ?: throw Http2ServerException("DATA with invalid padding", PROTOCOL_ERROR)
        val endStream = frame.flags and Http2FrameFlags.END_STREAM != 0

        val assembly = synchronized(streamsLock) { assembling[frame.streamID] }
        if (assembly == null) {
            // Not an open upload: keep the connection window from leaking, then
            // decide whether this is a protocol error or a harmless late frame.
            creditConnectionWindow(onWire)
            if (frame.streamID > highestStreamID) {
                throw Http2ServerException("DATA on idle stream ${frame.streamID}", PROTOCOL_ERROR)
            }
            if (synchronized(streamsLock) { responders.containsKey(frame.streamID) }) {
                // The client already half-closed this stream with END_STREAM.
                resetStream(frame.streamID, STREAM_CLOSED)
            }
            return
        }

        creditStreamAndConnection(frame.streamID, onWire)

        val remaining = assembly.contentLengthRemaining
        if (remaining != null) {
            if (body.size > remaining) {
                logger.warning("[h2] $host stream ${frame.streamID}: body exceeds Content-Length; RST")
                dropAssembling(frame.streamID); resetStream(frame.streamID, PROTOCOL_ERROR); return
            }
            assembly.contentLengthRemaining = remaining - body.size
            if (endStream && assembly.contentLengthRemaining != 0L) {
                logger.warning("[h2] $host stream ${frame.streamID}: body shorter than Content-Length; RST")
                dropAssembling(frame.streamID); resetStream(frame.streamID, PROTOCOL_ERROR); return
            }
        }
        if (assembly.body.size() + body.size > MAX_BUFFERED_BODY_BYTES) {
            logger.warning("[h2] $host stream ${frame.streamID}: request body over $MAX_BUFFERED_BODY_BYTES cap; refusing")
            dropAssembling(frame.streamID); resetStream(frame.streamID, INTERNAL_ERROR); return
        }
        assembly.body.write(body)
        if (endStream) {
            dropAssembling(frame.streamID)
            deliverRequest(assembly, assembly.body.toByteArray())
        }
    }

    private fun dropAssembling(streamID: Int) {
        synchronized(streamsLock) { assembling.remove(streamID) }
    }

    // MARK: - Flow control crediting (receive side)

    /**
     * Replenishes the client's per-stream and connection windows for the on-wire
     * length of a consumed DATA frame. Credited immediately per frame rather than
     * batched at a threshold: it keeps a client from stalling mid-upload and gives
     * a single deterministic point where a WINDOW_UPDATE follows a DATA frame.
     */
    private suspend fun creditStreamAndConnection(streamID: Int, onWire: Int) {
        if (onWire <= 0) return
        writeMutex.withLock {
            client.send(Http2Framer.serialize(Http2Framer.windowUpdateFrame(streamID, onWire)))
            client.send(Http2Framer.serialize(Http2Framer.windowUpdateFrame(0, onWire)))
        }
    }

    private suspend fun creditConnectionWindow(onWire: Int) {
        if (onWire <= 0) return
        writeMutex.withLock {
            client.send(Http2Framer.serialize(Http2Framer.windowUpdateFrame(0, onWire)))
        }
    }

    // MARK: - Request delivery

    private fun deliverRequest(assembly: RequestAssembly, body: ByteArray) {
        val url = "${assembly.scheme}://${assembly.authority}${assembly.path}"
        val headers = ArrayList<HttpHeader>(assembly.regularHeaders.size + 1)
        headers.add(HttpHeader("Host", assembly.authority))
        headers.addAll(assembly.regularHeaders)
        val message = HttpMessage.request(
            method = assembly.method,
            url = url,
            headers = headers,
            body = body,
            version = "HTTP/2"
        )
        val flow = Http2StreamFlowControl(clientInitialWindowSize)
        val stream = Http2ServerStream(assembly.streamID, message, flow)
        synchronized(streamsLock) {
            pendingStreamCredit.remove(assembly.streamID)?.let { credit ->
                if (credit > 0) flow.applyWindowUpdate(credit)
            }
            responders[assembly.streamID] = stream
        }
        if (requestChannel.trySend(stream).isFailure) {
            logger.warning("[h2] $host stream ${assembly.streamID}: request queue closed; dropping request")
        }
    }

    // MARK: - Response encoding (used by Http2ServerStream)

    /**
     * Builds the HPACK block for a response: `:status` first, then every non-forbidden
     * header lowercased. Connection-specific fields illegal in HTTP/2 (RFC 7540
     * §8.1.2.2) are dropped so the emitted block can never make the client treat the
     * message as malformed; the caller keeps `Content-Length` correct.
     */
    private fun buildResponseHeaderBlock(status: Int, headers: List<HttpHeader>): ByteArray {
        val fields = ArrayList<Pair<String, String>>(headers.size + 1)
        fields.add(":status" to status.toString())
        for (header in headers) {
            if (header.name.startsWith(":")) continue
            val lower = header.name.lowercase()
            if (lower in FORBIDDEN_H2_RESPONSE_HEADERS) continue
            if (lower == "te" && !header.value.trim().equals("trailers", ignoreCase = true)) continue
            fields.add(lower to header.value)
        }
        return HpackEncoder.encodeHeaderBlock(fields)
    }

    /**
     * Frames a header block as HEADERS (+CONTINUATION when it overflows one frame).
     * The single-frame path reuses [Http2Framer.headersFrame] (END_HEADERS set); the
     * rare multi-frame path uses [serializeFrame] because the naive builder can't
     * express a non-final HEADERS and has no CONTINUATION builder.
     */
    private fun emitHeaders(streamID: Int, block: ByteArray, endStream: Boolean): ByteArray {
        if (block.size <= MAX_FRAME_PAYLOAD) {
            return Http2Framer.serialize(Http2Framer.headersFrame(streamID, block, endStream))
        }
        val out = ByteArrayOutputStream()
        var firstFlags = 0
        if (endStream) firstFlags = firstFlags or Http2FrameFlags.END_STREAM
        out.write(serializeFrame(Http2FrameType.HEADERS.value, firstFlags, streamID, block.copyOfRange(0, MAX_FRAME_PAYLOAD)))
        var offset = MAX_FRAME_PAYLOAD
        while (offset < block.size) {
            val end = minOf(block.size, offset + MAX_FRAME_PAYLOAD)
            val isLast = end == block.size
            out.write(serializeFrame(FRAME_TYPE_CONTINUATION, if (isLast) Http2FrameFlags.END_HEADERS else 0, streamID, block.copyOfRange(offset, end)))
            offset = end
        }
        return out.toByteArray()
    }

    private suspend fun sendResponseBody(streamID: Int, flow: Http2StreamFlowControl, body: ByteArray) {
        var offset = 0
        while (offset < body.size) {
            flow.awaitWindow()
            awaitConnectionWindow()
            val grant = synchronized(flowLock) {
                val g = minOf(body.size - offset, MAX_FRAME_PAYLOAD, flow.sendWindow, connectionSendWindow)
                if (g > 0) connectionSendWindow -= g
                g
            }
            if (grant <= 0) continue
            if (!flow.consumeSend(grant)) {
                // The stream window shrank under us (a SETTINGS delta); refund and retry.
                synchronized(flowLock) { connectionSendWindow += grant }
                continue
            }
            val end = offset + grant
            val isLast = end >= body.size
            val chunk = body.copyOfRange(offset, end)
            offset = end
            writeMutex.withLock {
                client.send(Http2Framer.serialize(Http2Framer.dataFrame(streamID, chunk, endStream = isLast)))
            }
        }
    }

    private suspend fun awaitConnectionWindow() {
        val awaiter = synchronized(flowLock) {
            if (connectionSendWindow > 0) return
            connectionWindowAwaiter ?: CompletableDeferred<Unit>().also { connectionWindowAwaiter = it }
        }
        awaiter.await()
    }

    private fun finishResponder(streamID: Int) {
        synchronized(streamsLock) { responders.remove(streamID) }
    }

    // MARK: - RST / GOAWAY / teardown

    private suspend fun resetStream(streamID: Int, errorCode: Int) {
        val stream = synchronized(streamsLock) {
            assembling.remove(streamID)
            pendingStreamCredit.remove(streamID)
            responders.remove(streamID)
        }
        stream?.markAborted()
        stream?.flowControl?.cancelAwaiters(Http2ServerException("stream reset", errorCode))
        runCatching {
            writeMutex.withLock {
                client.send(Http2Framer.serialize(Http2Framer.rstStreamFrame(streamID, errorCode)))
            }
        }
    }

    private suspend fun sendGoaway(errorCode: Int) {
        if (goawaySent) return
        goawaySent = true
        val payload = ByteArray(8)
        val last = highestStreamID and 0x7FFFFFFF
        payload[0] = ((last ushr 24) and 0xFF).toByte()
        payload[1] = ((last ushr 16) and 0xFF).toByte()
        payload[2] = ((last ushr 8) and 0xFF).toByte()
        payload[3] = (last and 0xFF).toByte()
        payload[4] = ((errorCode ushr 24) and 0xFF).toByte()
        payload[5] = ((errorCode ushr 16) and 0xFF).toByte()
        payload[6] = ((errorCode ushr 8) and 0xFF).toByte()
        payload[7] = (errorCode and 0xFF).toByte()
        runCatching {
            writeMutex.withLock {
                client.send(serializeFrame(Http2FrameType.GOAWAY.value, 0, 0, payload))
            }
        }
    }

    private fun shutdown() {
        closed = true
        requestChannel.close()
        synchronized(flowLock) {
            connectionWindowAwaiter?.completeExceptionally(Http2ServerException("connection closed", NO_ERROR))
            connectionWindowAwaiter = null
        }
        val open = synchronized(streamsLock) {
            val snapshot = responders.values.toList()
            responders.clear()
            assembling.clear()
            pendingStreamCredit.clear()
            snapshot
        }
        for (stream in open) {
            stream.markAborted()
            stream.flowControl.cancelAwaiters(Http2ServerException("connection closed", NO_ERROR))
        }
        runCatching { client.close() }
    }

    /** Serialises one raw frame (9-byte header + payload) for CONTINUATION and GOAWAY. */
    private fun serializeFrame(typeCode: Int, flags: Int, streamID: Int, payload: ByteArray): ByteArray {
        val out = ByteArray(Http2Framer.HEADER_SIZE + payload.size)
        val length = payload.size
        out[0] = ((length ushr 16) and 0xFF).toByte()
        out[1] = ((length ushr 8) and 0xFF).toByte()
        out[2] = (length and 0xFF).toByte()
        out[3] = typeCode.toByte()
        out[4] = flags.toByte()
        val sid = streamID and 0x7FFFFFFF
        out[5] = ((sid ushr 24) and 0xFF).toByte()
        out[6] = ((sid ushr 16) and 0xFF).toByte()
        out[7] = ((sid ushr 8) and 0xFF).toByte()
        out[8] = (sid and 0xFF).toByte()
        System.arraycopy(payload, 0, out, Http2Framer.HEADER_SIZE, length)
        return out
    }

    // MARK: - Padding / validation helpers

    /** Strips a PADDED prefix and a PRIORITY prefix from a HEADERS payload; null if invalid. */
    private fun stripHeadersPadding(payload: ByteArray, flags: Int): ByteArray? {
        var start = 0
        var end = payload.size
        if (flags and FLAG_PADDED != 0) {
            if (payload.isEmpty()) return null
            val padLength = payload[0].toInt() and 0xFF
            start = 1
            end -= padLength
            if (end < start) return null
        }
        if (flags and FLAG_PRIORITY != 0) {
            if (end - start < 5) return null
            start += 5
        }
        return payload.copyOfRange(start, end)
    }

    /** Strips a PADDED prefix from a DATA payload; null if invalid. */
    private fun stripDataPadding(payload: ByteArray, flags: Int): ByteArray? {
        if (flags and FLAG_PADDED == 0) return payload
        if (payload.isEmpty()) return null
        val padLength = payload[0].toInt() and 0xFF
        val end = payload.size - padLength
        if (end < 1) return null
        return payload.copyOfRange(1, end)
    }

    /** Returns a rejection reason, or null when the request's header set is valid. */
    private fun validateRequestHeaders(decoded: List<Pair<String, String>>): String? {
        var seenRegular = false
        var methods = 0
        var paths = 0
        var schemes = 0
        var authorities = 0
        for ((name, value) in decoded) {
            if (name.isEmpty()) return "empty header name"
            if (name.startsWith(":")) {
                if (seenRegular) return "pseudo-header after a regular header"
                when (name) {
                    ":method" -> methods++
                    ":path" -> paths++
                    ":scheme" -> schemes++
                    ":authority" -> authorities++
                    else -> return "unknown request pseudo-header $name"
                }
            } else {
                seenRegular = true
                if (name.any { it in 'A'..'Z' }) return "uppercase header name $name"
                if (name in FORBIDDEN_H2_REQUEST_HEADERS) return "connection-specific header $name"
                if (name == "te" && value.trim() != "trailers") return "te header with a value other than trailers"
                // An h2 header value is length-prefixed, so it can carry the CR/LF/NUL
                // that an HTTP/1.1 line cannot. As the h2->h1 intermediary we MUST
                // reject those (RFC 7540 §10.3) or the value smuggles a second
                // request/header past the origin's line-based parser.
                if (!isWireSafeHeaderValue(value)) return "header value with a forbidden control character"
            }
        }
        if (methods != 1 || paths != 1 || schemes != 1) return "missing or duplicate required pseudo-header"
        if (authorities > 1) return "duplicate :authority"
        return null
    }

    /**
     * The declared `Content-Length`: null when none is present, [INVALID_CONTENT_LENGTH]
     * when it is unparseable, negative, or inconsistent across duplicates, else the value.
     */
    private fun parseContentLength(decoded: List<Pair<String, String>>): Long? {
        val values = decoded.filter { HttpHeader.nameEquals(it.first, "content-length") }
        if (values.isEmpty()) return null
        val parsed = values.map { it.second.trim().toLongOrNull() }
        if (parsed.any { it == null || it < 0 }) return INVALID_CONTENT_LENGTH
        val distinct = parsed.map { it!! }.distinct()
        if (distinct.size != 1) return INVALID_CONTENT_LENGTH
        return distinct.first()
    }

    private fun isWireSafeHeaderValue(value: String): Boolean =
        value.none { it == '\r' || it == '\n' || it == '\u0000' }

    // MARK: - Types

    private class RawFrame(
        val typeCode: Int,
        val flags: Int,
        val streamID: Int,
        val payload: ByteArray
    )

    private class PendingHeaders(
        val streamID: Int,
        val fragments: ByteArrayOutputStream,
        val endStream: Boolean
    ) {
        var count = 0
    }

    private class RequestAssembly(
        val streamID: Int,
        val method: String,
        val scheme: String,
        val authority: String,
        val path: String,
        val regularHeaders: List<HttpHeader>,
        var contentLengthRemaining: Long?,
        val body: ByteArrayOutputStream = ByteArrayOutputStream()
    )

    /**
     * One terminated request stream handed to the caller: the fully-assembled
     * [request] and the one-shot way to answer it. The response is encoded and
     * paced by the enclosing server, so a caller only supplies an [HttpMessage].
     */
    inner class Http2ServerStream internal constructor(
        val streamID: Int,
        val request: HttpMessage,
        internal val flowControl: Http2StreamFlowControl
    ) {
        private val responded = AtomicBoolean(false)
        @Volatile private var aborted = false
        private val abortLatch = CompletableDeferred<Unit>()

        internal fun markAborted() {
            aborted = true
            abortLatch.complete(Unit)
        }

        /**
         * Suspends until the client resets this stream (RST_STREAM) or the
         * connection is torn down (both reach [markAborted]). The stage-2 h2 bridge
         * races each stream's upstream exchange against this, so a client cancel
         * promptly abandons the in-flight origin dial and fetch rather than finishing
         * work whose response would only be discarded. Idempotent: the latch fires
         * once and stays completed.
         */
        suspend fun awaitAborted() {
            abortLatch.await()
        }

        /**
         * Encodes and sends [response] on this stream: `:status` and headers as one
         * HEADERS block, then the body as flow-controlled DATA with END_STREAM on
         * the final frame (or on the HEADERS when the body is empty). May be called
         * at most once; a no-op if the stream was already reset.
         */
        suspend fun sendResponse(response: HttpMessage) {
            check(responded.compareAndSet(false, true)) { "response already sent on stream $streamID" }
            if (aborted) return
            val status = response.status ?: 200
            val block = buildResponseHeaderBlock(status, response.headers)
            require(block.size <= MAX_HEADER_BLOCK_BYTES) { "response header block over cap" }
            val body = response.body
            writeMutex.withLock {
                if (aborted) return
                client.send(emitHeaders(streamID, block, endStream = body.isEmpty()))
            }
            if (body.isNotEmpty()) sendResponseBody(streamID, flowControl, body)
            finishResponder(streamID)
        }

        /** Aborts this stream toward the client with a RST_STREAM of [errorCode]. */
        suspend fun reset(errorCode: Int = CANCEL) {
            resetStream(streamID, errorCode)
        }
    }

    private class Http2ServerException(message: String, val errorCode: Int) : Exception(message)

    private companion object {
        /** RFC 7540 §3.5 client connection preface. */
        private val CLIENT_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)

        private const val DEFAULT_INITIAL_WINDOW = 65_535
        private const val MAX_WINDOW = 0x7FFFFFFFL

        /** SETTINGS_MAX_FRAME_SIZE minimum (RFC 7540 §6.5.2); we advertise no larger. */
        private const val MAX_FRAME_PAYLOAD = 16_384

        /** Hard cap on an accepted frame payload — above the advertised 16 KiB so a
         *  peer can't force an unbounded allocation, but bounded. */
        private const val MAX_RECEIVED_FRAME_PAYLOAD = 1 * 1024 * 1024

        private const val MAX_HEADER_BLOCK_BYTES = 256 * 1024
        private const val MAX_HEADER_LIST_SIZE = 256 * 1024
        private const val MAX_CONTINUATION_FRAMES = 1024
        private const val MAX_TRACKED_STREAMS = 256
        private const val MAX_CONCURRENT_STREAMS = 128
        private const val MAX_BUFFERED_BODY_BYTES = 4 * 1024 * 1024
        private const val MAX_RECEIVE_BUFFER = 8 * 1024 * 1024
        private const val RECEIVE_WINDOW = 4 * 1024 * 1024

        // Frame type codes the naive Http2FrameType enum omits.
        private const val FRAME_TYPE_PRIORITY = 0x2
        private const val FRAME_TYPE_PUSH_PROMISE = 0x5
        private const val FRAME_TYPE_CONTINUATION = 0x9

        private const val FLAG_PADDED = 0x8
        private const val FLAG_PRIORITY = 0x20

        // RFC 7540 §7 error codes not in the naive Http2Framer.ErrorCode.
        private const val COMPRESSION_ERROR = 0x9
        private const val HTTP_1_1_REQUIRED = 0xd

        // Re-exported for readability at call sites.
        private const val NO_ERROR = Http2Framer.ErrorCode.NO_ERROR
        private const val PROTOCOL_ERROR = Http2Framer.ErrorCode.PROTOCOL_ERROR
        private const val INTERNAL_ERROR = Http2Framer.ErrorCode.INTERNAL_ERROR
        private const val FLOW_CONTROL_ERROR = Http2Framer.ErrorCode.FLOW_CONTROL_ERROR
        private const val FRAME_SIZE_ERROR = Http2Framer.ErrorCode.FRAME_SIZE_ERROR
        private const val STREAM_CLOSED = Http2Framer.ErrorCode.STREAM_CLOSED
        private const val REFUSED_STREAM = Http2Framer.ErrorCode.REFUSED_STREAM
        private const val CANCEL = Http2Framer.ErrorCode.CANCEL

        private const val INVALID_CONTENT_LENGTH = Long.MIN_VALUE

        /** Connection-specific request headers illegal over HTTP/2 (RFC 7540 §8.1.2.2). */
        private val FORBIDDEN_H2_REQUEST_HEADERS =
            setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")

        /** Connection-specific response headers dropped when encoding a response. */
        private val FORBIDDEN_H2_RESPONSE_HEADERS =
            setOf("connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade")
    }
}
