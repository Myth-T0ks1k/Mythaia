package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.SocketProtector
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("Quic")

/**
 * One QUIC connection: a socket, an event loop, and the streams on top.
 *
 * The three pieces below this each know one thing. ngtcp2 knows the protocol
 * but not where the bytes come from; [QuicTlsHandler] knows the handshake but
 * never sees a packet; this knows the socket and the clock, and carries bytes
 * between them.
 *
 * Two threads: one draining the socket, one running the timer. Everything that
 * touches ngtcp2 is serialised on [engineLock], because a `ngtcp2_conn` is not
 * thread-safe and the reader, the timer and any stream write would otherwise
 * reach it at once.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class QuicConnection(
    private val serverName: String,
    private val serverPort: Int,
    private val alpn: List<String>,
    private val tuning: QuicTuning = QuicTuning.NAIVE,
    fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133
) : NativeBridge.QuicCallback {

    private val tls = QuicTlsHandler(serverName, alpn, tuning, fingerprint)

    /** ngtcp2's handle. Zero before [connect] and after [close]. */
    @Volatile
    private var handle = 0L

    /** Serialises every call into ngtcp2, which is not thread-safe. */
    private val engineLock = Any()

    @Volatile
    private var socket: DatagramSocket? = null

    @Volatile
    private var endpoint: InetSocketAddress? = null

    private val running = AtomicBoolean(false)
    private val handshake = CompletableDeferred<Boolean>()
    private val threads = mutableListOf<Thread>()

    /** Streams by ngtcp2 stream id. */
    private val streams = ConcurrentHashMap<Long, QuicStream>()

    val isConnected: Boolean get() = handle != 0L && tls.phase == QuicTlsHandler.Phase.ESTABLISHED

    /** What the peer advertised, once the handshake has got that far. */
    val peerTransportParameters: List<QuicTuning.TransportParameter>
        get() = tls.peerTransportParameters

    // MARK: - Lifecycle

    /**
     * Brings the connection up, returning when the handshake completes.
     *
     * False means it did not: the reason is in the log, and in
     * [QuicTlsHandler.failure] where TLS was what failed.
     */
    suspend fun connect(timeoutMillis: Long = HANDSHAKE_TIMEOUT_MS): Boolean {
        if (running.getAndSet(true)) return handshake.await()

        val address = if (DnsCache.isIpAddress(serverName)) {
            serverName
        } else {
            DnsCache.resolveHost(serverName)
        } ?: run {
            logger.warning("[QUIC] Could not resolve $serverName")
            return false
        }

        val bound = DatagramSocket()
        if (!SocketProtector.protect(bound)) {
            bound.close()
            logger.warning("[QUIC] Could not protect the socket from the tunnel")
            return false
        }
        bound.soTimeout = SOCKET_POLL_MS
        socket = bound

        val target = InetSocketAddress(InetAddress.getByName(address), serverPort)
        endpoint = target

        handle = NativeBridge.nativeQuicConnCreate(
            address, serverPort, bound.localAddress.hostAddress ?: "0.0.0.0", bound.localPort, this
        )
        if (handle == 0L) {
            bound.close()
            logger.warning("[QUIC] ngtcp2 refused to create the connection")
            return false
        }

        spawn("quic-read", ::runReader)
        spawn("quic-timer", ::runTimer)

        // The first flight goes out as soon as something asks ngtcp2 to write.
        flush()

        return withTimeoutOrNull(timeoutMillis) { handshake.await() } ?: run {
            logger.warning("[QUIC] Handshake to $serverName timed out")
            close()
            false
        }
    }

    fun close() {
        if (!running.getAndSet(false)) return

        streams.values.forEach { it.onPeerClosed() }
        streams.clear()

        synchronized(engineLock) {
            if (handle != 0L) {
                NativeBridge.nativeQuicConnFree(handle)
                handle = 0L
            }
        }

        socket?.close()
        socket = null
        threads.forEach { it.interrupt() }
        threads.clear()

        if (!handshake.isCompleted) handshake.complete(false)
    }

    private fun spawn(name: String, body: () -> Unit) {
        val thread = Thread({
            try {
                body()
            } catch (e: Exception) {
                if (running.get()) logger.warning("[QUIC] $name ended: ${e.message}")
            }
        }, name).apply { isDaemon = true }
        threads.add(thread)
        thread.start()
    }

    // MARK: - Streams

    /**
     * Opens a bidirectional stream.
     *
     * Null when the peer's stream credit is spent — QUIC lets a server bound
     * how many streams may be open, and the answer then is to wait rather than
     * to force one.
     */
    fun openStream(): QuicStream? {
        val id = synchronized(engineLock) {
            if (handle == 0L) return null
            NativeBridge.nativeQuicOpenBidiStream(handle)
        }
        if (id < 0) {
            logger.debug("[QUIC] No stream credit left (ngtcp2 $id)")
            return null
        }
        val stream = QuicStream(id, this)
        streams[id] = stream
        return stream
    }

    /**
     * Offers stream data to ngtcp2 and puts the packet it built on the wire.
     *
     * The packet and the accepted byte count are different numbers, and both
     * come back: sending only the count would leave ngtcp2 waiting to have a
     * packet acknowledged that never left.
     */
    internal fun writeStream(streamId: Long, data: ByteArray, fin: Boolean): Long {
        val accepted = LongArray(1)
        val datagram = synchronized(engineLock) {
            if (handle == 0L) return -1
            NativeBridge.nativeQuicConnWriteStream(handle, streamId, data, fin, accepted)
        }
        datagram?.let { send(it) }
        flush()
        return accepted[0]
    }

    internal fun shutdownStream(streamId: Long) {
        streams.remove(streamId)
        synchronized(engineLock) {
            if (handle != 0L) NativeBridge.nativeQuicShutdownStream(handle, streamId, 0)
        }
        flush()
    }

    /**
     * Reports consumed bytes so the peer reopens the window.
     *
     * Skipping this stalls a transfer partway through with nothing logged: the
     * peer is simply not allowed to send more.
     */
    internal fun extendOffsets(streamId: Long, count: Int) {
        synchronized(engineLock) {
            if (handle != 0L) NativeBridge.nativeQuicExtendOffsets(handle, streamId, count)
        }
    }

    // MARK: - Event loop

    /** Drains everything ngtcp2 wants to send and puts it on the wire. */
    private fun flush() {
        while (true) {
            val datagram = synchronized(engineLock) {
                if (handle == 0L) null else NativeBridge.nativeQuicConnWrite(handle)
            } ?: break
            if (!send(datagram)) return
        }
        // The burst is over, so ngtcp2 can pace the next one. Without this the
        // pacing interval is never consulted and a window leaves as fast as the
        // socket takes it.
        synchronized(engineLock) {
            if (handle != 0L) NativeBridge.nativeQuicConnFlushDone(handle)
        }
    }

    /** Puts one datagram on the wire. False when the socket has gone. */
    private fun send(datagram: ByteArray): Boolean {
        val target = endpoint ?: return false
        val current = socket ?: return false
        return try {
            current.send(DatagramPacket(datagram, datagram.size, target))
            true
        } catch (e: Exception) {
            if (running.get()) logger.warning("[QUIC] Send failed: ${e.message}")
            false
        }
    }

    private fun runReader() {
        val buffer = ByteArray(MAX_DATAGRAM)
        val packet = DatagramPacket(buffer, buffer.size)

        while (running.get()) {
            val current = socket ?: break
            try {
                packet.setData(buffer, 0, buffer.size)
                current.receive(packet)
            } catch (e: java.net.SocketTimeoutException) {
                continue
            } catch (e: Exception) {
                if (running.get()) logger.warning("[QUIC] Socket read failed: ${e.message}")
                break
            }

            val received = buffer.copyOf(packet.length)
            val rv = synchronized(engineLock) {
                if (handle == 0L) return@synchronized 0
                NativeBridge.nativeQuicConnRead(handle, received, received.size)
            }
            if (rv < 0) {
                logger.warning("[QUIC] Connection failed while reading (ngtcp2 $rv)")
                if (!handshake.isCompleted) handshake.complete(false)
                close()
                return
            }
            flush()
        }
    }

    /**
     * Runs ngtcp2's own timer.
     *
     * QUIC does its loss detection and pacing on a deadline the library
     * computes; missing it does not fail loudly, it just stops retransmitting.
     */
    private fun runTimer() {
        while (running.get()) {
            try {
                Thread.sleep(TIMER_TICK_MS)
            } catch (_: InterruptedException) {
                break
            }
            if (!running.get()) break

            val expiry = synchronized(engineLock) {
                if (handle == 0L) -1L else NativeBridge.nativeQuicConnExpiry(handle)
            }
            if (expiry < 0) continue
            if (System.nanoTime() < expiry) continue

            val rv = synchronized(engineLock) {
                if (handle == 0L) 0 else NativeBridge.nativeQuicConnHandleExpiry(handle)
            }
            if (rv < 0) {
                logger.warning("[QUIC] Connection expired (ngtcp2 $rv)")
                close()
                return
            }
            flush()
        }
    }

    // MARK: - Callbacks from ngtcp2

    /**
     * Handshake bytes, or a request for the first flight.
     *
     * Called from inside a native call that already holds [engineLock], so
     * nothing here may take it again.
     */
    override fun onCryptoData(level: Int, data: ByteArray?) {
        val connection = handle
        if (connection == 0L) return

        if (data == null) {
            val hello = tls.buildClientHello() ?: return
            NativeBridge.nativeQuicSubmitCrypto(
                connection, QuicTlsHandler.LEVEL_INITIAL, hello
            )
            return
        }

        if (tls.processCryptoData(connection, data) == QuicTlsHandler.Outcome.FAILED) {
            logger.warning("[QUIC] Handshake failed: ${tls.failure}")
            if (!handshake.isCompleted) handshake.complete(false)
        }
    }

    override fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean) {
        val stream = streams[streamId] ?: return
        if (data.isNotEmpty()) {
            stream.onData(data)
            extendOffsets(streamId, data.size)
        }
        if (fin) stream.onPeerClosed()
    }

    override fun onStreamClose(streamId: Long, errorCode: Long) {
        streams.remove(streamId)?.onPeerClosed()
    }

    override fun onHandshakeComplete() {
        logger.debug("[QUIC] Handshake complete with $serverName")
        if (!handshake.isCompleted) handshake.complete(true)
    }

    companion object {
        /** Everything a QUIC datagram can be, plus room to read a larger one. */
        private const val MAX_DATAGRAM = 1500

        private const val SOCKET_POLL_MS = 1000
        private const val TIMER_TICK_MS = 10L
        private const val HANDSHAKE_TIMEOUT_MS = 10_000L
    }
}
