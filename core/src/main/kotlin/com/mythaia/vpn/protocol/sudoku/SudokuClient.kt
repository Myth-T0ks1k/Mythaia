package com.mythaia.vpn.protocol.sudoku

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Sudoku")

/**
 * Dials Sudoku over its plain obfuscated TCP carrier.
 *
 * A dial is short: refuse the shapes this build cannot carry, resolve the
 * carrier settings once, and hand a fresh [SudokuSession] the destination. The
 * session owns the socket, the obfuscation and record layers, and the KIP
 * authentication; what is left here is the classification of the destination and
 * of the configuration.
 *
 * Only the carrier that needs nothing beyond a raw socket is wired: the
 * obfuscated stream, optionally fronted by the legacy HTTP decoy, with no
 * multiplexer. The stream/poll/auto HTTP-mask transports frame the obfuscated
 * bytes as real HTTP request/response bodies and need that machinery; the
 * WebSocket mask needs an upgrade handshake; the TLS carrier needs a TLS client
 * around the socket; and native multiplexing needs the mux framing and a shared,
 * pooled connection. Each of those is refused with a message saying so rather
 * than dialled wrongly, mirroring how [com.mythaia.vpn.protocol.nowhere.NowhereClient]
 * refuses the carriers it cannot yet speak.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuClient(
    private val configuration: ProxyConfiguration,
    private val sudoku: SudokuConfiguration,
    private val tunnel: ProxyConnection? = null
) {

    /** Opens a proxied TCP flow to [host]:[port]. */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        val settings = resolveSettings()
        val session = SudokuSession(settings, tunnel)
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
        val session = SudokuSession(settings, tunnel)
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
            sudoku = sudoku
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
         * A single reason is returned, in the order a request meets the layers it
         * cannot cross: the multiplexer first, then the TLS carrier, then the HTTP
         * and WebSocket masks. `auto` and `off` multiplexing both dial the plain
         * carrier — only `on` demands the mux — and the `legacy` mask is carried,
         * because it is only a decoy prefix on an otherwise plain stream.
         */
        internal fun carrierRefusal(sudoku: SudokuConfiguration): String? {
            if (sudoku.multiplex == SudokuMultiplex.ON) {
                return "Sudoku native multiplexing (mux=on) is not wired yet; this build dials " +
                    "one connection per flow (mux=off or mux=auto)"
            }
            val mask = sudoku.httpMask
            if (mask.tls) {
                return "Sudoku over a TLS carrier is not wired yet; this build dials the plain " +
                    "obfuscated TCP carrier only"
            }
            if (!mask.disable && mask.mode != SudokuHttpMaskMode.LEGACY) {
                return "Sudoku HTTP camouflage mode '${mask.mode.id}' is not wired yet; this build " +
                    "dials the plain obfuscated TCP carrier (httpmask disabled or mode=legacy)"
            }
            return null
        }
    }
}

/**
 * A Sudoku TCP flow presented as a proxy connection.
 *
 * The connection is the record stream: bytes sent become record payloads, bytes
 * received are the record stream's plaintext, and the far side finishing surfaces
 * as end of stream. The carrier is plain obfuscated TCP with no outer TLS, so
 * [outerTlsVersion] stays null. Cancelling tears the whole session down, which is
 * the only owner of the socket — there is nothing shared to keep alive.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuStreamConnection internal constructor(
    private val session: SudokuSession
) : ProxyConnection() {

    private val closed = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val isConnected: Boolean
        get() = !closed.get() && session.isConnected

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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val isConnected: Boolean
        get() = !closed.get() && session.isConnected

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
