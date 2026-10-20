package com.mythaia.vpn.protocol.sudoku

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

private val logger = MythaiaLogger("SudokuMux")

/**
 * Multiplexes many TCP flows over one authenticated [SudokuSession].
 *
 * After the KIP handshake rekeys the [SudokuRecordStream], the session sends
 * `KIP_OPEN_MUX` (`0x11` with an empty payload) once. From that point on, the
 * record stream carries 9-byte mux frames:
 * - `0x01` (`MUX_OPEN`): `streamId (4B BE) || length (4B BE) || SOCKS5 address`
 * - `0x02` (`MUX_DATA`): `streamId (4B BE) || length (4B BE) || data` (or `streamId = 0`, empty payload for keepalive)
 * - `0x03` (`MUX_CLOSE`): `streamId (4B BE) || 0`
 * - `0x04` (`MUX_RESET`): `streamId (4B BE) || length (4B BE) || UTF-8 message`
 * - `0x05` / `0x06` (`MUX_CONTROL_PING` / `MUX_CONTROL_PONG`): `streamId = 0`, `length = 0`
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuMuxSession private constructor(
    val session: SudokuSession,
    private val record: SudokuRecordStream,
    private val onClosed: (() -> Unit)? = null
) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private val closed = AtomicBoolean(false)
    private val streamIdLock = Any()
    private var nextStreamId = 0L

    private val streams = ConcurrentHashMap<Long, SudokuMuxStreamConnection>()
    private val lastActivityNanos = AtomicLong(System.nanoTime())

    val isConnected: Boolean
        get() = !closed.get() && session.isConnected

    val activeStreamCount: Int
        get() = streams.size

    private fun startLoops() {
        scope.launch { readLoop() }
        scope.launch { keepaliveLoop() }
    }

    /**
     * Opens a new logical TCP stream to [host]:[port] on this multiplexed session
     * and optionally writes [initialData] as the first `MUX_DATA` frame(s).
     */
    suspend fun dialTcp(
        host: String,
        port: Int,
        initialData: ByteArray?
    ): SudokuMuxStreamConnection {
        if (!isConnected) {
            throw SudokuError.StreamClosed("Sudoku mux session is closed")
        }
        val address = SudokuProtocol.encodeAddress(host, port)
        val streamId = synchronized(streamIdLock) {
            nextStreamId = (nextStreamId + 1) and 0xFFFFFFFFL
            if (nextStreamId == 0L) nextStreamId = 1L
            nextStreamId
        }
        val streamConn = SudokuMuxStreamConnection(
            muxSession = this,
            streamId = streamId,
            outerTlsVersion = session.outerTlsVersion
        )
        streams[streamId] = streamConn
        try {
            sendFrame(SudokuProtocol.MUX_OPEN, streamId, address)
            if (initialData != null && initialData.isNotEmpty()) {
                streamConn.sendRaw(initialData)
            }
            return streamConn
        } catch (e: Exception) {
            streams.remove(streamId)
            streamConn.deliverReset(e.message ?: "Sudoku mux open failed")
            throw e
        }
    }

    internal suspend fun sendFrame(type: Byte, streamId: Long, payload: ByteArray) {
        if (closed.get() || !session.isConnected) {
            throw SudokuError.StreamClosed("Sudoku mux session is closed")
        }
        lastActivityNanos.set(System.nanoTime())
        val frame = SudokuProtocol.encodeMuxFrame(type, streamId, payload)
        try {
            record.send(frame)
        } catch (e: Exception) {
            failAll(e.message ?: "Sudoku mux write failed")
            throw e
        }
    }

    internal fun closeStreamFromClient(streamId: Long, sendCloseFrame: Boolean) {
        streams.remove(streamId)
        if (sendCloseFrame && isConnected) {
            scope.launch {
                runCatching {
                    sendFrame(SudokuProtocol.MUX_CLOSE, streamId, EMPTY_BYTES)
                }
            }
        }
    }

    fun close() {
        failAll("Sudoku mux closed")
    }

    private fun failAll(reason: String) {
        if (!closed.compareAndSet(false, true)) return
        val active = streams.values.toList()
        streams.clear()
        for (stream in active) {
            stream.deliverReset(reason)
        }
        session.close()
        scope.cancel()
        onClosed?.invoke()
    }

    private suspend fun readLoop() {
        try {
            while (!closed.get()) {
                val headerBytes = record.readExact(SudokuProtocol.MUX_HEADER_SIZE) ?: break
                lastActivityNanos.set(System.nanoTime())
                val rawType = headerBytes[0]

                if (rawType == MUX_CONTROL_PING || rawType == MUX_CONTROL_PONG) {
                    val streamId = ((headerBytes[1].toLong() and 0xFF) shl 24) or
                        ((headerBytes[2].toLong() and 0xFF) shl 16) or
                        ((headerBytes[3].toLong() and 0xFF) shl 8) or
                        (headerBytes[4].toLong() and 0xFF)
                    val length = ((headerBytes[5].toLong() and 0xFF) shl 24) or
                        ((headerBytes[6].toLong() and 0xFF) shl 16) or
                        ((headerBytes[7].toLong() and 0xFF) shl 8) or
                        (headerBytes[8].toLong() and 0xFF)
                    if (streamId != 0L || length != 0L) {
                        throw SudokuError.ProtocolViolation("bad mux control frame")
                    }
                    if (rawType == MUX_CONTROL_PING) {
                        lastActivityNanos.set(System.nanoTime())
                        record.send(CONTROL_PONG_FRAME)
                    }
                    continue
                }

                val header = SudokuProtocol.parseMuxHeader(headerBytes)
                val payload = if (header.length == 0) {
                    EMPTY_BYTES
                } else {
                    record.readExact(header.length)
                        ?: throw SudokuError.ProtocolViolation("truncated mux payload")
                }
                lastActivityNanos.set(System.nanoTime())

                when (header.type) {
                    SudokuProtocol.MUX_DATA -> {
                        if (header.streamId != 0L && payload.isNotEmpty()) {
                            streams[header.streamId]?.deliverData(payload)
                        }
                    }
                    SudokuProtocol.MUX_CLOSE -> {
                        streams.remove(header.streamId)?.deliverClose()
                    }
                    SudokuProtocol.MUX_RESET -> {
                        val message = String(payload, Charsets.UTF_8).trim().ifEmpty { "reset" }
                        streams.remove(header.streamId)?.deliverReset(message)
                    }
                    SudokuProtocol.MUX_OPEN -> {
                        // Server-initiatedMUX_OPEN does not occur on client sessions.
                    }
                }
            }
            failAll("Sudoku mux closed")
        } catch (e: Exception) {
            logger.debug("[SudokuMux] Read loop ended: ${e.message}")
            failAll(e.message ?: "Sudoku mux failed")
        }
    }

    private suspend fun keepaliveLoop() {
        val intervalMs = SudokuProtocol.MUX_KEEPALIVE_INTERVAL_SECONDS * 1000L
        val intervalNanos = intervalMs * 1_000_000L
        while (!closed.get()) {
            delay(intervalMs)
            if (closed.get() || !session.isConnected) break
            if (streams.isEmpty()) continue
            val idleNanos = System.nanoTime() - lastActivityNanos.get()
            if (idleNanos < intervalNanos) continue
            try {
                lastActivityNanos.set(System.nanoTime())
                if (session.settings.usesHttpMaskControlFrames) {
                    record.send(CONTROL_PING_FRAME)
                } else {
                    record.send(KEEPALIVE_DATA_FRAME)
                }
            } catch (e: Exception) {
                failAll(e.message ?: "Sudoku mux keepalive failed")
                break
            }
        }
    }

    companion object {
        const val MUX_CONTROL_PING: Byte = 0x05
        const val MUX_CONTROL_PONG: Byte = 0x06
        const val MAX_DATA_WRITE_SIZE: Int = 128 * 1024

        private val EMPTY_BYTES = ByteArray(0)
        private val CONTROL_PING_FRAME = byteArrayOf(MUX_CONTROL_PING, 0, 0, 0, 0, 0, 0, 0, 0)
        private val CONTROL_PONG_FRAME = byteArrayOf(MUX_CONTROL_PONG, 0, 0, 0, 0, 0, 0, 0, 0)
        private val KEEPALIVE_DATA_FRAME = SudokuProtocol.encodeMuxFrame(SudokuProtocol.MUX_DATA, 0L, EMPTY_BYTES)

        /**
         * Opens a [SudokuSession], completes KIP authentication, sends `KIP_OPEN_MUX`,
         * and starts the multiplexed frame reader and keepalive loops.
         */
        suspend fun open(
            settings: SudokuConnectionSettings,
            tunnel: ProxyConnection? = null,
            rawTransportFactory: (suspend () -> Transport)? = null,
            onClosed: (() -> Unit)? = null
        ): SudokuMuxSession {
            val session = SudokuSession(settings, tunnel, rawTransportFactory)
            val record = try {
                session.openMux()
            } catch (e: Exception) {
                session.close()
                throw e
            }
            return SudokuMuxSession(session, record, onClosed).also { it.startLoops() }
        }
    }
}

/**
 * One logical TCP stream riding a [SudokuMuxSession].
 */
class SudokuMuxStreamConnection internal constructor(
    private val muxSession: SudokuMuxSession,
    val streamId: Long,
    override val outerTlsVersion: TlsVersion?
) : ProxyConnection() {

    private sealed class StreamEvent {
        class Data(val bytes: ByteArray) : StreamEvent()
        data object Eof : StreamEvent()
        class Reset(val message: String) : StreamEvent()
    }

    private val closed = AtomicBoolean(false)
    private val remoteClosed = AtomicBoolean(false)
    @Volatile
    private var resetMessage: String? = null

    private val events = Channel<StreamEvent>(Channel.UNLIMITED)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    override val isConnected: Boolean
        get() = !closed.get() && !remoteClosed.get() && muxSession.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        if (data.isEmpty() || closed.get()) return
        resetMessage?.let { throw ProxyError.ProtocolError("Sudoku mux reset: $it") }
        if (remoteClosed.get() || !muxSession.isConnected) {
            throw ProxyError.ProtocolError("Sudoku mux stream is closed")
        }
        var offset = 0
        while (offset < data.size) {
            val count = minOf(SudokuMuxSession.MAX_DATA_WRITE_SIZE, data.size - offset)
            val chunk = data.copyOfRange(offset, offset + count)
            try {
                muxSession.sendFrame(SudokuProtocol.MUX_DATA, streamId, chunk)
            } catch (e: Exception) {
                throw when (e) {
                    is ProxyError -> e
                    else -> ProxyError.ProtocolError(e.message ?: "Sudoku mux write failed")
                }
            }
            offset += count
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        if (data.isEmpty() || closed.get()) return
        scope.launch {
            runCatching { sendRaw(data) }
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        val event = events.receiveCatching().getOrNull() ?: return null
        return when (event) {
            is StreamEvent.Data -> event.bytes
            is StreamEvent.Eof -> null
            is StreamEvent.Reset -> throw ProxyError.ProtocolError("Sudoku mux reset: ${event.message}")
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        val shouldSendClose = !remoteClosed.get()
        events.close()
        muxSession.closeStreamFromClient(streamId, sendCloseFrame = shouldSendClose)
        scope.cancel()
    }

    internal fun deliverData(bytes: ByteArray) {
        if (closed.get() || remoteClosed.get() || bytes.isEmpty()) return
        events.trySend(StreamEvent.Data(bytes))
    }

    internal fun deliverClose() {
        if (!remoteClosed.compareAndSet(false, true)) return
        events.trySend(StreamEvent.Eof)
        events.close()
    }

    internal fun deliverReset(message: String) {
        if (!remoteClosed.compareAndSet(false, true)) return
        resetMessage = message
        events.trySend(StreamEvent.Reset(message))
        events.close()
    }
}

/**
 * Process-wide pool of [SudokuMuxSession] instances keyed by server and Sudoku
 * outbound parameters.
 *
 * When a profile has `mux=on`, concurrent TCP flows to the same Sudoku server
 * reuse a single authenticated `KIP_OPEN_MUX` session rather than performing a
 * new TCP/TLS/HTTP-mask + KIP handshake per flow.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object SudokuMuxPool {

    data class Key(
        val serverHost: String,
        val serverPort: Int,
        val key: String,
        val aeadMethod: SudokuAeadMethod,
        val paddingMin: Int,
        val paddingMax: Int,
        val asciiMode: SudokuAsciiMode,
        val customTables: List<String>,
        val enablePureDownlink: Boolean,
        val httpMaskDisable: Boolean,
        val httpMaskMode: SudokuHttpMaskMode,
        val httpMaskTls: Boolean,
        val httpMaskHost: String,
        val httpMaskPathRoot: String,
        val tlsServerName: String?,
        val tlsAlpn: List<String>?,
        val tlsAllowInsecure: Boolean?,
        val tlsPinnedCertSha256: List<String>?
    )

    private val sessions = ConcurrentHashMap<Key, SudokuMuxSession>()
    private val keyLocks = ConcurrentHashMap<Key, Mutex>()

    fun keyFor(configuration: ProxyConfiguration, sudoku: SudokuConfiguration): Key {
        val tls = configuration.tls
        return Key(
            serverHost = configuration.serverAddress,
            serverPort = configuration.serverPort.toInt(),
            key = sudoku.key,
            aeadMethod = sudoku.aeadMethod,
            paddingMin = sudoku.paddingMin,
            paddingMax = sudoku.paddingMax,
            asciiMode = sudoku.asciiMode,
            customTables = sudoku.customTables,
            enablePureDownlink = sudoku.enablePureDownlink,
            httpMaskDisable = sudoku.httpMask.disable,
            httpMaskMode = sudoku.httpMask.mode,
            httpMaskTls = sudoku.httpMask.tls,
            httpMaskHost = sudoku.httpMask.host,
            httpMaskPathRoot = sudoku.httpMask.pathRoot,
            tlsServerName = tls?.serverName,
            tlsAlpn = tls?.alpn,
            tlsAllowInsecure = tls?.allowInsecure,
            tlsPinnedCertSha256 = tls?.pinnedCertSha256
        )
    }

    suspend fun dialTcp(
        key: Key,
        settings: SudokuConnectionSettings,
        host: String,
        port: Int,
        initialData: ByteArray?,
        rawTransportFactory: (suspend () -> Transport)? = null
    ): SudokuMuxStreamConnection {
        val mutex = keyLocks.computeIfAbsent(key) { Mutex() }
        val muxSession = mutex.withLock {
            val existing = sessions[key]
            if (existing != null && existing.isConnected) {
                existing
            } else {
                sessions.remove(key)
                lateinit var created: SudokuMuxSession
                created = SudokuMuxSession.open(
                    settings = settings,
                    tunnel = null,
                    rawTransportFactory = rawTransportFactory,
                    onClosed = { sessions.remove(key, created) }
                )
                sessions[key] = created
                created
            }
        }
        return try {
            muxSession.dialTcp(host, port, initialData)
        } catch (e: Exception) {
            if (!muxSession.isConnected) {
                sessions.remove(key, muxSession)
            }
            throw e
        }
    }

    fun release(key: Key) {
        sessions.remove(key)?.close()
    }

    fun clearAll() {
        val active = sessions.values.toList()
        sessions.clear()
        for (session in active) {
            session.close()
        }
    }
}
