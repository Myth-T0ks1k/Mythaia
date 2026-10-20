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
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Sudoku")

/**
 * Dials Sudoku over its full set of carriers:
 * - Plain obfuscated TCP (optionally fronted by the `legacy` HTTP decoy header)
 * - TLS carrier (`httpMask.tls = true`)
 * - WebSocket camouflage (`httpMask.mode = ws`)
 * - Split HTTP-mask tunnel (`httpMask.mode` in `stream`, `poll`, or `auto` with
 *   early KIP handshake on `/session?ed=...`)
 * - Native stream multiplexing (`multiplex = on`) pooled via [SudokuMuxPool].
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuClient(
    private val configuration: ProxyConfiguration,
    private val sudoku: SudokuConfiguration,
    private val tunnel: ProxyConnection? = null,
    internal val rawTransportFactory: (suspend () -> Transport)? = null
) {

    /** Opens a proxied TCP flow to [host]:[port]. */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        val settings = resolveSettings()
        if (settings.usesMultiplex) {
            return try {
                if (tunnel != null) {
                    val mux = SudokuMuxSession.open(settings, tunnel, rawTransportFactory)
                    mux.dialTcp(host, port, initialData)
                } else {
                    val key = SudokuMuxPool.keyFor(configuration, sudoku)
                    SudokuMuxPool.dialTcp(key, settings, host, port, initialData, rawTransportFactory)
                }
            } catch (e: Exception) {
                throw asProxyError(e, host, port)
            }
        }

        val session = SudokuSession(settings, tunnel, rawTransportFactory)
        try {
            session.connectTcp(host, port, initialData)
        } catch (e: Exception) {
            session.close()
            throw asProxyError(e, host, port)
        }
        return SudokuStreamConnection(session)
    }

    /** Opens a UDP-over-TCP flow; datagrams to [host]:[port] ride it framed. */
    suspend fun connectUDP(host: String, port: Int): ProxyConnection {
        val settings = resolveSettings()
        val session = SudokuSession(settings, tunnel, rawTransportFactory)
        try {
            session.openUdp()
        } catch (e: Exception) {
            session.close()
            throw asProxyError(e, host, port)
        }
        return SudokuUdpConnection(session, host, port)
    }

    private fun resolveSettings(): SudokuConnectionSettings {
        carrierRefusal(sudoku)?.let { throw ProxyError.ProtocolError(it) }
        return SudokuConnectionSettings.of(
            serverHost = configuration.serverAddress,
            serverPort = configuration.serverPort.toInt(),
            sudoku = sudoku,
            tls = configuration.tls
        )
    }

    private fun asProxyError(e: Exception, host: String, port: Int): ProxyError = when (e) {
        is ProxyError -> e
        else -> {
            logger.debug("[Sudoku] Dial to $host:$port failed: ${e.message}")
            ProxyError.ProtocolError(e.message ?: "Sudoku: dial failed")
        }
    }

    companion object {
        /**
         * Why this build cannot dial the given configuration, or null when it can.
         *
         * All Sudoku carriers (plain TCP, legacy HTTP decoy, TLS, WebSocket mask,
         * split HTTP `stream`/`poll`/`auto` masks, and native multiplexing) are
         * wired, so every valid [SudokuConfiguration] is dialable.
         */
        internal fun carrierRefusal(@Suppress("UNUSED_PARAMETER") sudoku: SudokuConfiguration): String? = null

        /**
         * Returns the pool key when [configuration] uses Sudoku native multiplexing
         * (`mux=on`), or null when each flow dials its own connection.
         */
        fun poolKey(configuration: ProxyConfiguration): Any? {
            val sudoku = runCatching { configuration.toSudokuConfiguration() }.getOrNull() ?: return null
            if (sudoku.multiplex != SudokuMultiplex.ON) return null
            return SudokuMuxPool.keyFor(configuration, sudoku)
        }

        /** Closes any pooled multiplexed session for [configuration]. */
        fun release(configuration: ProxyConfiguration) {
            val sudoku = runCatching { configuration.toSudokuConfiguration() }.getOrNull() ?: return
            if (sudoku.multiplex != SudokuMultiplex.ON) return
            SudokuMuxPool.release(SudokuMuxPool.keyFor(configuration, sudoku))
        }

        /** Closes all pooled multiplexed sessions across all servers. */
        fun clearAllPools() {
            SudokuMuxPool.clearAll()
        }
    }
}

/**
 * A Sudoku TCP flow presented as a proxy connection.
 *
 * The connection is the record stream: bytes sent become record payloads, bytes
 * received are the record stream's plaintext, and the far side finishing surfaces
 * as end of stream. Cancelling tears the whole session down, which is the only
 * owner of the underlying carrier.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuStreamConnection internal constructor(
    private val session: SudokuSession
) : ProxyConnection() {

    private val closed = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    override val isConnected: Boolean
        get() = !closed.get() && session.isConnected

    override val outerTlsVersion: TlsVersion?
        get() = session.outerTlsVersion

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        val record = session.stream ?: throw ProxyError.ProtocolError("Sudoku connection is closed")
        record.send(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        val record = session.stream ?: return
        scope.launch { runCatching { record.send(data) } }
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        val record = session.stream ?: return null
        return record.receive(TCP_RECEIVE_CHUNK)
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        session.close()
        scope.cancel()
    }

    private companion object {
        /** How much decoded plaintext one read asks for; the record layer sizes to fit. */
        const val TCP_RECEIVE_CHUNK = 64 * 1024
    }
}

/**
 * A Sudoku UDP-over-TCP flow presented as a proxy connection.
 *
 * Every datagram is framed with its destination address and length, and every
 * frame read is stripped back to its payload; the address is fixed for this
 * connection but the wire format carries it on each frame, so it is written each
 * time and skipped on the way back. Reads pull exactly one frame at a time, so a
 * frame split across records reassembles before it is handed up.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuUdpConnection internal constructor(
    private val session: SudokuSession,
    private val destinationHost: String,
    private val destinationPort: Int
) : ProxyConnection() {

    private val closed = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    override val isConnected: Boolean
        get() = !closed.get() && session.isConnected

    override val outerTlsVersion: TlsVersion?
        get() = session.outerTlsVersion

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        val record = session.stream ?: throw ProxyError.ProtocolError("Sudoku connection is closed")
        record.send(SudokuProtocol.encodeUdpOverTcp(destinationHost, destinationPort, data))
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        val record = session.stream ?: return
        scope.launch {
            runCatching { record.send(SudokuProtocol.encodeUdpOverTcp(destinationHost, destinationPort, data)) }
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        val record = session.stream ?: return null
        val header = record.readExact(SudokuProtocol.UOT_HEADER_SIZE) ?: return null
        val frame = SudokuProtocol.parseUdpOverTcpHeader(header)
        // The address is validated and then dropped: this connection already
        // knows where its datagrams go, and only the payload belongs to the
        // caller.
        if (frame.addressLength > 0) {
            record.readExact(frame.addressLength) ?: throw SudokuError.ProtocolViolation("truncated UoT address")
        }
        if (frame.payloadLength == 0) return ByteArray(0)
        return record.readExact(frame.payloadLength)
            ?: throw SudokuError.ProtocolViolation("truncated UoT payload")
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        session.close()
        scope.cancel()
    }
}
