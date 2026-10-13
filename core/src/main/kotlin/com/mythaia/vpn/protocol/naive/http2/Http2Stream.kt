package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.protocol.naive.NaivePaddingNegotiator
import com.mythaia.vpn.protocol.naive.NaiveTunnel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val logger = MythaiaLogger("HTTP2Stream")

/**
 * A single HTTP/2 CONNECT tunnel stream multiplexed on an [Http2Session].
 * Lifecycle: IDLE → TUNNEL_PENDING → TUNNEL_OPEN → CLOSED.
 */
class Http2Stream(
    private val session: Http2Session,
    private val destination: String
) : NaiveTunnel {

    /**
     * Given when the stream's HEADERS are written ([Http2Session.openStream]),
     * not when it is handed out: ids must reach the server in increasing order
     * (RFC 9113 §5.1.1), and streams handed out together can open in any order.
     * 0 until then.
     */
    @Volatile
    var streamID: Int = 0
        private set

    internal fun assignId(id: Int) {
        streamID = id
    }

    enum class State { IDLE, TUNNEL_PENDING, TUNNEL_OPEN, CLOSED }

    @Volatile
    private var state = State.IDLE

    val flowControl = Http2StreamFlowControl(session.serverInitialWindowSize)

    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /**
     * One send at a time: two concurrent senders used to interleave their DATA
     * frames chunk by chunk, which is corrupt payload to the other side.
     */
    private val sendMutex = Mutex()

    private val tunnelReady = CompletableDeferred<Unit>()

    override var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    override val isConnected: Boolean get() = state == State.TUNNEL_OPEN

    override suspend fun openTunnel() {
        if (state != State.IDLE) throw Http2Error.ProtocolError("Stream $streamID: invalid state for openTunnel")
        state = State.TUNNEL_PENDING

        try {
            session.sendConnectRequest(this, destination)
            tunnelReady.await()
        } catch (e: Exception) {
            state = State.CLOSED
            release()
            throw e
        }
    }

    /**
     * Opens the stream as an ordinary request rather than a CONNECT tunnel:
     * sends [headerBlock] (HPACK), with [endStream] for a request without a
     * body. Unless [awaitResponse], the body may follow at once, as gRPC
     * clients send their first message without waiting for the response
     * headers; those are checked when they arrive, and a refusal ends the
     * stream (the reader sees its end).
     */
    suspend fun openRequest(headerBlock: ByteArray, endStream: Boolean = false, awaitResponse: Boolean = false) {
        if (state != State.IDLE) throw Http2Error.ProtocolError("Stream $streamID: invalid state for openRequest")
        state = if (awaitResponse) State.TUNNEL_PENDING else State.TUNNEL_OPEN
        try {
            session.sendRequestHeaders(this, headerBlock, endStream)
            if (awaitResponse) tunnelReady.await()
        } catch (e: Exception) {
            state = State.CLOSED
            dataChannel.close()
            release()
            throw e
        }
    }

    /** The trailing headers (gRPC's grpc-status), once the server sent them. */
    @Volatile
    var trailers: List<Pair<String, String>>? = null
        private set

    @Volatile
    private var responseSeen = false

    override suspend fun sendData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        sendMutex.withLock { session.sendData(this, data) }
    }

    /** Sends [data] and ends this side of the stream (an upload's last piece). */
    suspend fun sendLastData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        sendMutex.withLock { session.sendData(this, data, endStream = true) }
    }

    override suspend fun receiveData(): ByteArray? {
        // Drain before reporting the end: END_STREAM closes the channel the
        // moment it arrives, usually while DATA frames ahead of it are still
        // buffered. Returning null on the CLOSED state alone threw that tail
        // away — a fast server's last few hundred kilobytes of every response.
        val result = dataChannel.receiveCatching()
        if (result.isClosed) {
            // A reset, GOAWAY or connection error fails the channel, and the
            // reader must see that: as a plain null it was indistinguishable
            // from the server's END_STREAM, and a download cut off mid-way
            // looked complete. Only END_STREAM and a local close end in null.
            result.exceptionOrNull()?.let { throw it }
            return null
        }
        val data = result.getOrThrow()
        // Defer WINDOW_UPDATE to consume time so back-pressure is preserved
        // through the channel — mirrors iOS HTTP2Stream.acknowledgeConsumedData.
        if (data.isNotEmpty()) {
            session.acknowledgeConsumedData(streamID, data.size)
        }
        return data
    }

    override fun close() {
        if (state == State.CLOSED) return
        val priorState = state
        state = State.CLOSED
        dataChannel.close()
        discardBuffered()
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream closed"))
        // Send RST_STREAM(CANCEL) so the server reclaims the slot when we
        // close while the stream is still open. Mirrors iOS HTTP2Stream.close
        // (HTTP2Stream.swift:160-184).
        if ((priorState == State.TUNNEL_PENDING || priorState == State.TUNNEL_OPEN) && streamID != 0) {
            session.sendReset(streamID, Http2Framer.ErrorCode.CANCEL)
        }
        release()
    }

    /** Gives the stream's place back: its slot if it never opened, its id otherwise. */
    private fun release() {
        if (streamID == 0) session.releaseReservation() else session.removeStream(streamID)
    }

    /**
     * Drops what the application never read and gives the server its
     * connection window back for it (RFC 9113 §6.9): the window is otherwise
     * only credited as the application reads, so bytes left behind by a stream
     * that ended early were lost from the shared connection's window for good.
     */
    private fun discardBuffered() {
        var bytes = 0
        while (true) {
            val chunk = dataChannel.tryReceive().getOrNull() ?: break
            bytes += chunk.size
        }
        if (bytes > 0) session.creditConnection(bytes)
    }

    /**
     * Completes [tunnelReady] on a 200 response, fails it on error status. A
     * second HEADERS block, without `:status`, is the trailers.
     */
    fun deliverHeaders(headers: List<Pair<String, String>>) {
        val statusHeader = headers.firstOrNull { it.first == ":status" }
        if (statusHeader == null) {
            if (responseSeen) {
                trailers = headers
                return
            }
            fail(Http2Error.ProtocolError("Stream $streamID: missing :status"))
            return
        }
        responseSeen = true
        // gRPC's Trailers-Only response (a call refused before any message):
        // `:status 200` and grpc-status in one block, END_STREAM on it. Kept as
        // the trailers too, or the reader took the refusal for a clean end.
        if (headers.any { it.first == "grpc-status" }) trailers = headers

        when (statusHeader.second) {
            "200" -> {
                negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers)
                if (state == State.TUNNEL_PENDING) state = State.TUNNEL_OPEN
                tunnelReady.complete(Unit)
            }
            "407" -> fail(Http2Error.AuthenticationRequired())
            else -> fail(Http2Error.TunnelFailed(statusHeader.second))
        }
    }

    /** A refused request: closes the stream, so a request that did not wait for the answer ends too. */
    private fun fail(error: Http2Error) {
        state = State.CLOSED
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)
        tunnelReady.completeExceptionally(error)
    }

    fun deliverData(data: ByteArray) {
        if (state == State.CLOSED || !dataChannel.trySend(data).isSuccess) {
            // Nobody will read it, but the server spent connection window on
            // it: give that back, or the shared connection runs dry (§6.9).
            session.creditConnection(data.size)
        }
    }

    fun deliverWindowUpdate(increment: Int) {
        flowControl.applyWindowUpdate(increment)
    }

    fun deliverReset() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        val error = Http2Error.StreamReset(streamID)
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)

        if (!wasOpen) {
            tunnelReady.completeExceptionally(error)
        }
    }

    /** Server END_STREAM = clean half-close. Closes data channel without throwing. */
    fun deliverEndStream() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream END_STREAM"))
    }

    /**
     * GOAWAY named a lower last stream id: the server never processed this
     * stream. It ends with [Http2Error.Goaway], never a clean end, so the
     * caller knows to try again on a new connection.
     */
    fun deliverGoaway() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        val error = Http2Error.Goaway()
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)

        if (!wasOpen) {
            tunnelReady.completeExceptionally(error)
        }
    }

    fun deliverError(error: Exception) {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)

        if (!wasOpen) {
            tunnelReady.completeExceptionally(error)
        }
    }

    /** RFC 7540 §6.9.2: adjusts send window when SETTINGS_INITIAL_WINDOW_SIZE changes. */
    fun adjustSendWindow(delta: Int) {
        flowControl.adjustSendWindow(delta)
    }
}
