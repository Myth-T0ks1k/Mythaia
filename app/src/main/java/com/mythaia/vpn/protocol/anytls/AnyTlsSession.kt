package com.mythaia.vpn.protocol.anytls

import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

private val logger = MythaiaLogger("AnyTLS")

/**
 * One AnyTLS session: many streams multiplexed over a single TLS connection.
 *
 * The session owns the write side, because the padding scheme is defined in
 * terms of TLS writes — it says how to split the first few of them into records
 * of particular sizes. Every stream therefore hands its bytes here rather than
 * touching the connection, and [writeShaped] decides what actually goes out.
 */
class AnyTlsSession(
    private val tls: TlsRecordConnection,
    /** The scheme in force, which the server may replace mid-session. */
    @Volatile var padding: AnyTlsPaddingScheme,
    private val clientName: String,
    /** Called when the server pushes a new scheme, so the client can adopt it. */
    private val onPaddingScheme: (AnyTlsPaddingScheme) -> Unit
) {

    private val random = SecureRandom()
    private val writeLock = Mutex()
    private val streams = ConcurrentHashMap<Int, AnyTlsStream>()
    private val nextStreamId = AtomicInteger(0)
    private val packetCounter = AtomicInteger(0)
    private val closed = AtomicBoolean(false)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var receiveJob: Job? = null

    /**
     * Whether padding is still being applied.
     *
     * Turned off for good once the counter passes the scheme's stop, so a long
     * session does not keep paying for a check it will never pass again.
     */
    @Volatile
    private var shaping = true

    /**
     * Buffered writes, used only to make the settings frame and the first
     * stream's SYN share one TLS write.
     *
     * The scheme numbers packets, and packet 1 is defined as settings plus the
     * first SYN and its address. Sending them separately would shift every
     * later packet by one and shape the session wrongly.
     */
    @Volatile
    private var buffering = false
    private var buffer = ByteArray(0)

    /** Protocol version the server reported; version-2 features stay off below it. */
    @Volatile
    var peerVersion: Int = 1
        private set

    val isClosed: Boolean get() = closed.get()

    /** How many streams are live, for the pool's idle check. */
    val activeStreams: Int get() = streams.size

    /**
     * Sends the settings frame and starts reading.
     *
     * Settings must be the first thing on a new session — a server that sees a
     * SYN before it refuses the session outright.
     */
    suspend fun start() {
        buffering = true
        writeFrame(AnyTlsProtocol.CMD_SETTINGS, 0,
            AnyTlsProtocol.settings(clientName, padding.md5))

        receiveJob = scope.launch { receiveLoop() }
    }

    /**
     * Opens a stream to [host]:[port].
     *
     * The address goes out as the stream's first data, in SOCKS5 form, and that
     * write is what flushes the buffered settings — which is exactly how the
     * reference client composes packet 1.
     */
    suspend fun openStream(host: String, port: Int): AnyTlsStream {
        if (closed.get()) throw ProxyError.ProtocolError("AnyTLS session is closed")

        val id = nextStreamId.incrementAndGet()
        val stream = AnyTlsStream(id, this)
        streams[id] = stream

        writeFrame(AnyTlsProtocol.CMD_SYN, id)
        buffering = false
        sendStreamData(id, AnyTlsProtocol.encodeAddress(host, port))

        return stream
    }

    /** Sends one stream's payload, split to fit the 16-bit length field. */
    suspend fun sendStreamData(streamId: Int, data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val take = minOf(MAX_FRAME_PAYLOAD, data.size - offset)
            writeFrame(AnyTlsProtocol.CMD_PSH, streamId, data.copyOfRange(offset, offset + take))
            offset += take
        }
    }

    /** Tells the peer a stream is finished and forgets it. */
    suspend fun closeStream(streamId: Int) {
        streams.remove(streamId) ?: return
        if (closed.get()) return
        runCatching { writeFrame(AnyTlsProtocol.CMD_FIN, streamId) }
    }

    fun close() {
        if (!closed.compareAndSet(false, true)) return
        streams.values.forEach { it.onSessionClosed() }
        streams.clear()
        runCatching { tls.cancel() }
        scope.cancel()
        logger.debug("[AnyTLS] Session closed")
    }

    // MARK: - Writing

    private suspend fun writeFrame(command: Byte, streamId: Int, data: ByteArray = ByteArray(0)) {
        writeShaped(AnyTlsProtocol.frame(command, streamId, data))
    }

    /**
     * Writes bytes, split into records the padding scheme asks for.
     *
     * The sizes are TLS plaintext lengths, so each piece is one call into the
     * TLS layer. Where a piece is longer than the payload left, the remainder
     * is filled with a `cmdWaste` frame — padding the peer reads and discards.
     */
    private suspend fun writeShaped(bytes: ByteArray) = writeLock.withLock {
        var payload = bytes

        if (buffering) {
            buffer += payload
            return@withLock
        }
        if (buffer.isNotEmpty()) {
            payload = buffer + payload
            buffer = ByteArray(0)
        }

        if (!shaping) {
            tls.send(payload)
            return@withLock
        }

        val packet = packetCounter.incrementAndGet()
        if (!padding.shapes(packet)) {
            // Past the scheme's stop: nothing is shaped again on this session.
            shaping = false
            tls.send(payload)
            return@withLock
        }

        // The shaping itself is a pure function of the payload and the sizes,
        // so it can be checked against the reference without a socket.
        for (record in AnyTlsProtocol.shapeWrites(payload, padding.recordSizes(packet, random))) {
            tls.send(record)
        }
    }

    // MARK: - Reading

    private suspend fun receiveLoop() {
        val reader = FrameReader(tls)
        try {
            while (!closed.get()) {
                val frame = reader.next() ?: break
                dispatch(frame)
            }
        } catch (e: Exception) {
            if (!closed.get()) logger.debug("[AnyTLS] Session read ended: ${e.message}")
        } finally {
            close()
        }
    }

    private suspend fun dispatch(frame: Frame) {
        when (frame.command) {
            AnyTlsProtocol.CMD_PSH -> streams[frame.streamId]?.onData(frame.data)

            AnyTlsProtocol.CMD_FIN -> {
                streams.remove(frame.streamId)?.onPeerClosed()
            }

            // Padding. Read and drop — the length was already consumed.
            AnyTlsProtocol.CMD_WASTE -> Unit

            AnyTlsProtocol.CMD_SYNACK -> {
                // Empty means the outbound connected; a body is an error text.
                if (frame.data.isNotEmpty()) {
                    val reason = String(frame.data, Charsets.UTF_8)
                    logger.debug("[AnyTLS] Stream ${frame.streamId} refused: $reason")
                    streams.remove(frame.streamId)?.onPeerClosed()
                }
            }

            AnyTlsProtocol.CMD_SERVER_SETTINGS -> {
                val settings = AnyTlsProtocol.parseSettings(frame.data)
                peerVersion = settings["v"]?.toIntOrNull() ?: 1
                logger.debug("[AnyTLS] Server speaks version $peerVersion")
            }

            AnyTlsProtocol.CMD_UPDATE_PADDING_SCHEME -> {
                val next = AnyTlsPaddingScheme.parse(frame.data)
                if (next == null) {
                    logger.warning("[AnyTLS] Server sent a padding scheme that does not parse")
                } else {
                    // Applies to sessions opened from now on, as the protocol
                    // says; changing it mid-session would desynchronise the
                    // packet counter both sides are shaping against.
                    padding = next
                    onPaddingScheme(next)
                    logger.debug("[AnyTLS] Padding scheme updated (${next.md5})")
                }
            }

            AnyTlsProtocol.CMD_HEART_REQUEST -> {
                runCatching { writeFrame(AnyTlsProtocol.CMD_HEART_RESPONSE, frame.streamId) }
            }

            AnyTlsProtocol.CMD_HEART_RESPONSE -> Unit

            AnyTlsProtocol.CMD_ALERT -> {
                // The server explaining why it is about to hang up.
                logger.error("[AnyTLS] Server alert: ${String(frame.data, Charsets.UTF_8)}")
                close()
            }

            else -> logger.debug("[AnyTLS] Ignoring command ${frame.command}")
        }
    }

    private data class Frame(val command: Byte, val streamId: Int, val data: ByteArray)

    /**
     * Turns the TLS byte stream back into frames.
     *
     * TLS hands back whatever arrived, which has nothing to do with frame
     * boundaries, so this keeps a buffer and only yields a frame once its
     * header and whole body are present.
     */
    private class FrameReader(private val tls: TlsRecordConnection) {
        private var buffer = ByteArray(0)

        suspend fun next(): Frame? {
            while (true) {
                if (buffer.size >= AnyTlsProtocol.HEADER_SIZE) {
                    val header = AnyTlsProtocol.readHeader(buffer)
                    val total = AnyTlsProtocol.HEADER_SIZE + header.length
                    if (buffer.size >= total) {
                        val data = buffer.copyOfRange(AnyTlsProtocol.HEADER_SIZE, total)
                        buffer = buffer.copyOfRange(total, buffer.size)
                        return Frame(header.command, header.streamId, data)
                    }
                }
                val chunk = tls.receive() ?: return null
                if (chunk.isEmpty()) continue
                buffer += chunk
            }
        }
    }

    private companion object {
        /** The length field is a uint16, so no frame can carry more than this. */
        const val MAX_FRAME_PAYLOAD = 65535
    }
}
