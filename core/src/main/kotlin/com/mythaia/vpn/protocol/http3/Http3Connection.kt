package com.mythaia.vpn.protocol.http3

import com.mythaia.vpn.protocol.quic.QuicConnection
import com.mythaia.vpn.protocol.quic.QuicStream
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Http3")

/**
 * HTTP/3 over a QUIC connection.
 *
 * Almost all of HTTP/3 is bookkeeping around two facts: each request gets its
 * own QUIC stream, and both ends must open a unidirectional control stream and
 * announce their settings on it before anything else counts. Get the second one
 * wrong and a compliant server closes the connection without explaining why.
 *
 * This is a client, and a narrow one — enough to carry a request and read the
 * response, which is what the protocols above it need. There is no push, no
 * dynamic QPACK table, and no server-initiated request handling.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class Http3Connection(
    private val quic: QuicConnection,
    /** What goes in our SETTINGS; see [Http3Framer.PLAIN_CLIENT_SETTINGS]. */
    private val settings: List<Pair<Long, Long>> = Http3Framer.CLIENT_SETTINGS
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val started = AtomicBoolean(false)

    /** Our control stream, which stays open for the life of the connection. */
    private var controlStream: QuicStream? = null

    /** What the server said in its SETTINGS, once it has. */
    @Volatile
    var peerSettings: List<Pair<Long, Long>> = emptyList()
        private set

    val isConnected: Boolean get() = quic.isConnected

    /**
     * Brings HTTP/3 up over an already-connected QUIC connection.
     *
     * The control stream and its SETTINGS go first and are never closed:
     * closing a control stream is a connection error in HTTP/3, not a tidy-up.
     */
    suspend fun start(): Boolean {
        if (started.getAndSet(true)) return controlStream != null
        if (!quic.isConnected) return false

        val control = quic.openUniStream() ?: run {
            logger.warning("[H3] No credit for a control stream")
            return false
        }
        controlStream = control

        // Stream type first, then SETTINGS, in one write so they cannot be
        // separated by a lost packet into something the server reads as a
        // stream of unknown type.
        val opening = Http3Framer.uniStreamType(Http3Framer.STREAM_TYPE_CONTROL) +
            Http3Framer.clientSettingsFrame(settings)
        control.send(opening)

        return true
    }

    /**
     * Sends one request and returns the stream carrying its response.
     *
     * The headers go out immediately; the body, if any, follows on the same
     * stream. The caller reads the response from the returned stream.
     */
    suspend fun request(headers: ByteArray, body: ByteArray? = null, fin: Boolean = false): QuicStream? {
        val stream = quic.openStream() ?: run {
            logger.debug("[H3] No stream credit for a request")
            return null
        }

        stream.send(Http3Framer.headersFrame(headers))
        if (body != null && body.isNotEmpty()) {
            stream.send(Http3Framer.dataFrame(body))
        }
        if (fin) stream.finish()
        return stream
    }

    /**
     * Reads the server's control stream in the background.
     *
     * Its SETTINGS are the only part this client acts on, but the stream has to
     * keep being drained: an unread stream stops the peer sending on it once
     * the flow-control window closes, and a GOAWAY would then never arrive.
     */
    fun observePeerControlStream(stream: QuicStream) {
        scope.launch {
            var buffer = ByteArray(0)
            var typeRead = false

            while (true) {
                val chunk = stream.receive() ?: break
                buffer += chunk

                if (!typeRead) {
                    val type = Http3Framer.readUniStreamType(buffer) ?: continue
                    if (type.value != Http3Framer.STREAM_TYPE_CONTROL) {
                        // QPACK and push streams are not handled; draining is
                        // enough to keep the peer from blocking on them.
                        return@launch
                    }
                    buffer = buffer.copyOfRange(type.size, buffer.size)
                    typeRead = true
                }

                while (true) {
                    when (val result = Http3Framer.parse(buffer)) {
                        is Http3Framer.ParseResult.Complete -> {
                            if (result.frame.knownType == Http3FrameType.SETTINGS) {
                                Http3Framer.parseSettings(result.frame.payload)?.let {
                                    peerSettings = it
                                    logger.debug("[H3] Peer settings: $it")
                                }
                            }
                            buffer = buffer.copyOfRange(result.bytesConsumed, buffer.size)
                        }
                        is Http3Framer.ParseResult.Malformed -> {
                            logger.warning("[H3] Control stream: ${result.reason}")
                            return@launch
                        }
                        Http3Framer.ParseResult.Incomplete -> break
                    }
                    if (buffer.isEmpty()) break
                }
            }
        }
    }

    fun close() {
        controlStream?.cancel()
        controlStream = null
        scope.cancel()
    }
}
