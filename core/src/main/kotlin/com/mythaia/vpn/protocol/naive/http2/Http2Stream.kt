package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.protocol.naive.NaivePaddingNegotiator
import com.mythaia.vpn.protocol.naive.NaiveTunnel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel

private val logger = MythaiaLogger("HTTP2Stream")

/**
 * A single HTTP/2 CONNECT tunnel stream multiplexed on an [Http2Session].
 * Lifecycle: IDLE → TUNNEL_PENDING → TUNNEL_OPEN → CLOSED.
 */
class Http2Stream(
    val streamID: Int,
    private val session: Http2Session,
    private val destination: String
) : NaiveTunnel {

    enum class State { IDLE, TUNNEL_PENDING, TUNNEL_OPEN, CLOSED }

    @Volatile
    private var state = State.IDLE

    val flowControl = Http2StreamFlowControl(session.serverInitialWindowSize)

    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    private val tunnelReady = CompletableDeferred<Unit>()

    override var negotiatedPaddingType = NaivePaddingNegotiator.PaddingType.NONE
        private set

    override val isConnected: Boolean get() = state == State.TUNNEL_OPEN

    override suspend fun openTunnel() {
        if (state != State.IDLE) throw Http2Error.ProtocolError("Stream $streamID: invalid state for openTunnel")
        state = State.TUNNEL_PENDING

        try {
            session.sendConnectRequest(streamID, destination)
            tunnelReady.await()
        } catch (e: Exception) {
            state = State.CLOSED
            session.removeStream(streamID)
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
            session.sendRequestHeaders(streamID, headerBlock, endStream)
            if (awaitResponse) tunnelReady.await()
        } catch (e: Exception) {
            state = State.CLOSED
            dataChannel.close()
            session.removeStream(streamID)
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
        session.sendData(streamID, data, flowControl)
    }

    /** Sends [data] and ends this side of the stream (an upload's last piece). */
    suspend fun sendLastData(data: ByteArray) {
        if (state != State.TUNNEL_OPEN) throw Http2Error.NotReady()
        session.sendData(streamID, data, flowControl, endStream = true)
    }

    override suspend fun receiveData(): ByteArray? {
        // Drain before reporting the end: END_STREAM closes the channel the
        // moment it arrives, usually while DATA frames ahead of it are still
        // buffered. Returning null on the CLOSED state alone threw that tail
        // away — a fast server's last few hundred kilobytes of every response.
        val data = dataChannel.receiveCatching().getOrNull() ?: return null
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
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream closed"))
        // Send RST_STREAM(CANCEL) so the server reclaims the slot when we
        // close while the stream is still open. Mirrors iOS HTTP2Stream.close
        // (HTTP2Stream.swift:160-184).
        if (priorState == State.TUNNEL_PENDING || priorState == State.TUNNEL_OPEN) {
            session.sendReset(streamID, Http2Framer.ErrorCode.CANCEL)
        }
        session.removeStream(streamID)
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
        dataChannel.close()
        flowControl.cancelAwaiters(error)
        tunnelReady.completeExceptionally(error)
    }

    fun deliverData(data: ByteArray) {
        if (state == State.CLOSED) return
        dataChannel.trySend(data)
    }

    fun deliverWindowUpdate(increment: Int) {
        flowControl.applyWindowUpdate(increment)
    }

    fun deliverReset() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.StreamReset(streamID))

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.StreamReset(streamID))
        }
    }

    /** Server END_STREAM = clean half-close. Closes data channel without throwing. */
    fun deliverEndStream() {
        if (state == State.CLOSED) return
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.ConnectionFailed("Stream END_STREAM"))
    }

    fun deliverGoaway() {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.Goaway())

        if (!wasOpen) {
            tunnelReady.completeExceptionally(Http2Error.Goaway())
        }
    }

    fun deliverError(error: Exception) {
        if (state == State.CLOSED) return
        val wasOpen = state == State.TUNNEL_OPEN
        state = State.CLOSED
        dataChannel.close()
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
