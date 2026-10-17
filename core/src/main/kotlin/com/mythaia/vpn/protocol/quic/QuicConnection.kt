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
    /** Where the datagrams go: a host name to resolve or an address. */
    private val serverName: String,
    private val serverPort: Int,
    private val alpn: List<String>,
    private val tuning: QuicTuning = QuicTuning.NAIVE,
    fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133,
    /** The name in the TLS handshake and on the certificate; the link's `sni`, else [serverName]. */
    tlsServerName: String = serverName,
    /** The link's `insecure` flag. */
    allowInsecure: Boolean = false,
    /** Certificates trusted by SHA-256 regardless of CA. */
    pinnedCertSha256: List<String>? = null,
    /** The name the certificate must carry when it is not the SNI. */
    verifyName: String? = null,
    /**
     * Hysteria's packet obfuscation, applied to every datagram in both
     * directions; null sends QUIC packets as they are.
     */
    private val obfuscator: com.mythaia.vpn.protocol.hysteria.HysteriaObfuscator? = null
) : NativeBridge.QuicCallback {

    private val tls = QuicTlsHandler(tlsServerName, alpn, tuning, fingerprint, allowInsecure, pinnedCertSha256, verifyName)

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

    /** Where unreliable datagrams go, when anything wants them. */
    @Volatile
    var onDatagramReceived: ((ByteArray) -> Unit)? = null

    /**
     * Datagrams waiting for congestion window or pacing, oldest first; guarded
     * by [engineLock]. quic-go, which the Hysteria and TUIC servers run, queues
     * datagrams the same way: dropping every datagram the pacer was not ready
     * for lost a share of each call's packets on a path with no loss at all,
     * and every packet that Hysteria or TUIC had to split in two, whose second
     * half always met the pacer.
     */
    private val pendingDatagrams = ArrayDeque<PendingDatagram>()

    private class PendingDatagram(val data: ByteArray, val queuedAt: Long)

    /** Streams by ngtcp2 stream id. */
    private val streams = ConcurrentHashMap<Long, QuicStream>()

    val isConnected: Boolean get() = handle != 0L && tls.phase == QuicTlsHandler.Phase.ESTABLISHED

    /**
     * Keying material bound to this session (RFC 5705).
     *
     * TUIC turns its password into a token this way, so a token captured on one
     * connection proves nothing on another. Null before the handshake finishes.
     */
    fun exportKeyingMaterial(label: ByteArray, context: ByteArray, length: Int): ByteArray? =
        tls.exportKeyingMaterial(label, context, length)

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
            address,
            serverPort,
            bound.localAddress.hostAddress ?: "0.0.0.0",
            bound.localPort,
            tuning.toNativeArray(),
            this
        )
        if (handle == 0L) {
            bound.close()
            logger.warning("[QUIC] ngtcp2 refused to create the connection")
            return false
        }

        // The hello advertises what ngtcp2 was created with, connection id included.
        tls.localTransportParameters = NativeBridge.nativeQuicLocalTransportParams(handle)

        spawn("quic-read", ::runReader)
        spawn("quic-timer", ::runTimer)

        // The first flight goes out as soon as something asks ngtcp2 to write.
        flush()

        // A caller cancelled during the handshake (a latency test's timeout,
        // say) leaves by exception rather than through the timeout branch, so
        // the connection is closed here too. Otherwise the socket, both threads
        // and the ngtcp2 handle stay up with nobody holding them, and a
        // handshake that completes afterwards is kept open for good by the
        // keep-alive.
        return try {
            withTimeoutOrNull(timeoutMillis) { handshake.await() } ?: run {
                logger.warning("[QUIC] Handshake to $serverName timed out")
                close()
                false
            }
        } catch (e: Throwable) {
            close()
            throw e
        }
    }

    fun close() {
        if (!running.getAndSet(false)) return

        streams.values.forEach { it.onPeerClosed() }
        streams.clear()

        // Tell the peer, best effort: without a CONNECTION_CLOSE the server
        // keeps the session, its streams and its UDP sessions until its idle
        // timeout, and a client that reconnects straight away holds two.
        val farewell = synchronized(engineLock) {
            if (handle == 0L) null else runCatching { NativeBridge.nativeQuicConnClose(handle) }.getOrNull()
        }
        farewell?.let { send(it) }

        synchronized(engineLock) {
            if (handle != 0L) {
                NativeBridge.nativeQuicConnFree(handle)
                handle = 0L
            }
            pendingDatagrams.clear()
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
            } catch (e: Throwable) {
                // Throwable, not Exception: an OutOfMemoryError raised inside
                // a native callback surfaces here, and a connection whose
                // reader or timer has died is dead — leaving it open merely
                // hides that until the idle timeout.
                if (running.get()) {
                    logger.warning("[QUIC] $name died: $e")
                    close()
                }
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
    /**
     * Opens a unidirectional stream, which only this end may write to.
     *
     * HTTP/3 needs one for its control stream. Null when the peer has granted
     * no credit for them, which is what a plain tunnel profile does.
     */
    fun openUniStream(): QuicStream? {
        val id = synchronized(engineLock) {
            if (handle == 0L) return null
            NativeBridge.nativeQuicOpenUniStream(handle)
        }
        if (id < 0) {
            logger.debug("[QUIC] No unidirectional stream credit (ngtcp2 $id)")
            return null
        }
        val stream = QuicStream(id, this)
        streams[id] = stream
        return stream
    }

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
     *
     * Returns how many bytes went out (0 with [fin] means the FIN did),
     * [WRITE_AGAIN] when nothing fit this time, or a value below it when the
     * stream or the connection is finished and offering again is pointless.
     */
    internal fun writeStream(streamId: Long, data: ByteArray, fin: Boolean): Long {
        val accepted = LongArray(1)
        val datagram = synchronized(engineLock) {
            if (handle == 0L) return WRITE_CLOSED
            NativeBridge.nativeQuicConnWriteStream(handle, streamId, data, fin, accepted)
        }
        datagram?.let { send(it) }
        flush()
        return accepted[0]
    }

    /**
     * A quarter of the stream receive window: how much a stream lets the app
     * consume before it hands that stream's credit back. Large enough that
     * ngtcp2 sends a MAX_STREAM_DATA for each batch (it does so once a quarter
     * of the window is owed), small enough that the peer never waits for the
     * whole window to drain.
     */
    internal val streamCreditThreshold: Long =
        (tuning.initialMaxStreamDataBidiLocal / 4).coerceAtLeast(1)

    /**
     * Connection credit consumed and not yet handed back, across all streams.
     *
     * The connection window is shared, so it is credited from one tally
     * rather than with each stream's batch: per stream, every stream that
     * went quiet partway through a batch held its unreturned bytes back from
     * the connection window, and a browser's dozen idle keep-alive
     * connections could shut the window for every stream on the session.
     */
    private val owedConnectionCredit = java.util.concurrent.atomic.AtomicLong(0)

    /** An eighth of the connection window, so the peer always has most of it. */
    private val connectionCreditThreshold: Long = (tuning.initialMaxData / 8).coerceAtLeast(1)

    /**
     * Sends one unreliable datagram, now or as soon as the congestion window
     * and pacing allow; see [pendingDatagrams].
     *
     * False only when the connection is gone. A datagram that can never fit
     * (larger than the peer accepts) is dropped when its turn comes, and
     * nothing retransmits a datagram, so that is all the failure handling
     * there is.
     */
    fun sendDatagram(data: ByteArray): Boolean {
        synchronized(engineLock) {
            if (handle == 0L) return false
            // Full: the oldest goes. For a call, a fresh packet is worth more.
            if (pendingDatagrams.size >= MAX_PENDING_DATAGRAMS) pendingDatagrams.removeFirst()
            pendingDatagrams.addLast(PendingDatagram(data, System.nanoTime()))
        }
        flush()
        return true
    }

    /**
     * The largest datagram that goes out as one packet right now, or 0 when
     * not yet known. Protocols that split UDP payloads split above this.
     */
    fun maxDatagramPayload(): Int = synchronized(engineLock) {
        if (handle == 0L) 0 else NativeBridge.nativeQuicMaxDatagramPayload(handle)
    }

    /**
     * Hands queued datagrams to ngtcp2 while it has room, sending every packet
     * it builds, including ones that came back without the datagram in them.
     * False when the socket has gone.
     */
    private fun drainDatagrams(): Boolean {
        val status = IntArray(1)
        while (true) {
            val packet = synchronized(engineLock) {
                if (handle == 0L) return true
                // Stale ones go unsent: late audio is useless, and a datagram
                // ngtcp2 can never fit (it then builds nothing and says "not
                // yet") must not hold up the queue for good.
                val now = System.nanoTime()
                while (pendingDatagrams.firstOrNull()?.let { now - it.queuedAt > MAX_DATAGRAM_AGE_NS } == true) {
                    pendingDatagrams.removeFirst()
                }
                val next = pendingDatagrams.firstOrNull() ?: return true
                val built = NativeBridge.nativeQuicWriteDatagram(handle, next.data, status)
                // Sent, or never sendable: either way it leaves the queue.
                if (status[0] != 0) pendingDatagrams.removeFirst()
                built
            }
            if (status[0] < 0) logger.debug("[QUIC] Datagram refused (ngtcp2 ${status[0]})")
            if (packet != null) {
                if (!send(packet)) return false
            } else if (status[0] == 0) {
                // No room yet: the next ACK read or pacing deadline flushes again.
                return true
            }
        }
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
     * peer is simply not allowed to send more. Crediting too early is the
     * opposite failure: the peer fills the heap faster than the app reads.
     *
     * [streamCount] reopens stream [streamId]'s window (a negative id: none),
     * [connectionCount] the connection's. [wake] asks for the MAX_STREAM_DATA
     * / MAX_DATA frames to leave now rather than on the next read or timer; it
     * must be false from inside a native callback, where ngtcp2 may not be
     * asked to write.
     */
    internal fun extendOffsets(streamId: Long, streamCount: Long, connectionCount: Long, wake: Boolean) {
        if (streamCount <= 0 && connectionCount <= 0) return
        synchronized(engineLock) {
            if (handle == 0L) return
            var stream = maxOf(streamCount, 0)
            var connection = maxOf(connectionCount, 0)
            while (stream > 0 || connection > 0) {
                val s = minOf(stream, Int.MAX_VALUE.toLong()).toInt()
                val c = minOf(connection, Int.MAX_VALUE.toLong()).toInt()
                NativeBridge.nativeQuicExtendOffsets(handle, streamId, s, c)
                stream -= s
                connection -= c
            }
        }
        if (wake) flush()
    }

    /** Bytes the app has read, for the connection window; see [owedConnectionCredit]. */
    internal fun creditConnection(count: Long) {
        if (count <= 0 || owedConnectionCredit.addAndGet(count) < connectionCreditThreshold) return
        val flush = owedConnectionCredit.getAndSet(0)
        if (flush > 0) extendOffsets(-1, 0, flush, wake = true)
    }

    // MARK: - Event loop

    /** Drains everything ngtcp2 wants to send and puts it on the wire. */
    private fun flush() {
        if (!drainDatagrams()) return
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

    /** Puts one datagram on the wire, obfuscated when configured. False when the socket has gone. */
    private fun send(datagram: ByteArray): Boolean {
        val target = endpoint ?: return false
        val current = socket ?: return false
        return try {
            val wire = obfuscator?.seal(datagram) ?: listOf(datagram)
            for (piece in wire) current.send(DatagramPacket(piece, piece.size, target))
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

            val raw = buffer.copyOf(packet.length)
            // An obfuscated datagram that does not open is not ours: noise on
            // the port, or a piece the obfuscator is still reassembling.
            val received = if (obfuscator != null) (obfuscator.open(raw) ?: continue) else raw
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
            // Sleep until ngtcp2's deadline, at most a tick. A fixed 10 ms tick
            // held every paced packet for up to 10 ms: the second half of a
            // fragmented call packet arrived that much after the first.
            val deadline = synchronized(engineLock) {
                if (handle == 0L) -1L else NativeBridge.nativeQuicConnExpiry(handle)
            }
            val wait = if (deadline < 0) TIMER_TICK_NANOS
            else (deadline - System.nanoTime()).coerceIn(MIN_TIMER_WAIT_NANOS, TIMER_TICK_NANOS)
            try {
                Thread.sleep(wait / 1_000_000, (wait % 1_000_000).toInt())
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
        val stream = streams[streamId] ?: run {
            // A stream this end never opened (the server's HTTP/3 control
            // stream, say). Nobody reads it, so the credit it consumed is
            // handed straight back; otherwise every byte on it shrinks the
            // connection window for good.
            extendOffsets(streamId, data.size.toLong(), data.size.toLong(), wake = false)
            return
        }
        // The credit comes back when the app reads the bytes, not here: see
        // QuicStream. Crediting on arrival let a fast server fill the heap.
        if (data.isNotEmpty()) stream.onData(data)
        if (fin) stream.onPeerClosed()
    }

    override fun onStreamClose(streamId: Long, errorCode: Long) {
        streams.remove(streamId)?.onTransportClosed()
    }

    override fun onStreamReset(streamId: Long, errorCode: Long) {
        streams.remove(streamId)?.onPeerReset(errorCode)
    }

    /** Handed to whoever registered for datagrams; dropped when nobody has. */
    override fun onDatagram(data: ByteArray) {
        onDatagramReceived?.invoke(data)
    }

    override fun onHandshakeComplete() {
        logger.debug("[QUIC] Handshake complete with $serverName")
        if (!handshake.isCompleted) handshake.complete(true)
    }

    companion object {
        /** [writeStream] took nothing this time; offer the same bytes again. */
        internal const val WRITE_AGAIN = -1L

        /**
         * [writeStream] on a connection that is already gone. Below
         * [WRITE_AGAIN], like every ngtcp2 error, so callers need one test.
         */
        internal const val WRITE_CLOSED = -2L

        /** Everything a QUIC datagram can be, plus room to read a larger one. */
        private const val MAX_DATAGRAM = 1500

        /** quic-go queues 32; fragments of a large payload count one each. */
        private const val MAX_PENDING_DATAGRAMS = 64

        /** How long a datagram may wait for room before it is dropped. */
        private const val MAX_DATAGRAM_AGE_NS = 500_000_000L

        private const val SOCKET_POLL_MS = 1000
        /** The longest the timer sleeps; it wakes sooner when ngtcp2's deadline is nearer. */
        private const val TIMER_TICK_NANOS = 10_000_000L

        /** The shortest, so a deadline already past cannot spin the thread. */
        private const val MIN_TIMER_WAIT_NANOS = 200_000L
        private const val HANDSHAKE_TIMEOUT_MS = 10_000L
    }
}
