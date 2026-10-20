package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.hysteria.HysteriaClient
import com.mythaia.vpn.protocol.tuic.TuicClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * One Hysteria2 / TUIC client or V2Ray QUIC transport session per server,
 * shared by every flow.
 *
 * All three multiplex everything onto one QUIC connection — that is
 * where their speed comes from — so a client per flow was the worst of both
 * worlds: every TCP connection in the tunnel paid a full QUIC handshake,
 * HTTP/3 setup and authentication (most of a second on a filtered network),
 * and the connections were never closed, each holding a socket and, for
 * TUIC, a heartbeat until the server's idle timeout. Clients bring their
 * session back up on their own when it dies; [closeAll] ends them when the
 * tunnel stops or switches server, and [evict] ends one server's after a
 * latency test (see [com.mythaia.vpn.protocol.ProxyClientFactory.release]).
 */
object QuicClientPool {

    private val hysteria = ConcurrentHashMap<String, HysteriaClient>()
    private val tuic = ConcurrentHashMap<String, TuicClient>()
    private val transport = ConcurrentHashMap<String, QuicTransportSession>()

    fun hysteria(configuration: ProxyConfiguration): HysteriaClient =
        hysteria.computeIfAbsent(key(configuration)) { HysteriaClient(configuration) }

    fun tuic(configuration: ProxyConfiguration): TuicClient =
        tuic.computeIfAbsent(key(configuration)) { TuicClient(configuration) }

    suspend fun openTransportStream(configuration: ProxyConfiguration, tls: TlsConfiguration): QuicStream =
        transport.computeIfAbsent(key(configuration)) { QuicTransportSession(configuration, tls) }.openStream()

    /** Ends every pooled session. Safe to call any time; the next dial starts afresh. */
    fun closeAll() {
        val h = hysteria.values.toList()
        val t = tuic.values.toList()
        val q = transport.values.toList()
        hysteria.clear()
        tuic.clear()
        transport.clear()
        h.forEach { runCatching { it.close() } }
        t.forEach { runCatching { it.close() } }
        q.forEach { runCatching { it.close() } }
    }

    /**
     * Ends the session [configuration] reaches, if one is pooled.
     *
     * Nothing else would: the keep-alive (15 s) beats the idle timeout (30 s)
     * and TUIC adds its own heartbeat, so a pooled client never idles out, and
     * each holds a socket and two threads. A latency test across thousands of
     * servers kept one per server and ran out of threads.
     */
    fun evict(configuration: ProxyConfiguration) {
        val k = key(configuration)
        hysteria.remove(k)?.let { runCatching { it.close() } }
        tuic.remove(k)?.let { runCatching { it.close() } }
        transport.remove(k)?.let { runCatching { it.close() } }
    }

    /** Everything that makes two configurations reach the same session. */
    internal fun key(c: ProxyConfiguration): String = listOf(
        c.outboundProtocol, c.transport, c.serverAddress, c.serverPort, c.uuid, c.password, c.trojanPassword,
        c.obfuscation, c.obfuscationPassword, c.hysteriaUpMbps, c.hysteriaDownMbps,
        c.hysteriaPorts, c.hysteriaHopInterval, c.hysteriaHopIntervalMax,
        c.tls?.serverName, c.tls?.allowInsecure, c.tls?.fingerprint, c.tls?.alpn,
        c.tls?.pinnedCertSha256, c.tls?.verifyName
    ).joinToString("|")
}

/**
 * The V2Ray/sing-box `quic` transport: raw bidirectional QUIC streams on a
 * shared connection, with default ALPN `h3` when none is configured.
 */
internal class QuicTransportSession(
    private val configuration: ProxyConfiguration,
    private val tls: TlsConfiguration
) {
    private val lock = Mutex()

    @Volatile
    private var quic: QuicConnection? = null

    @Volatile
    private var closed = false

    private val backoff = QuicRedialBackoff()

    suspend fun openStream(): QuicStream {
        val session = lock.withLock { ensureSessionLocked() }
        session.openStream()?.let { return it }
        // Stream credit exhausted on the old connection; open a fresh one.
        val fresh = lock.withLock {
            if (quic === session) {
                runCatching { quic?.close() }
                quic = null
            }
            ensureSessionLocked()
        }
        return fresh.openStream()
            ?: throw ProxyError.ConnectionFailed("QUIC transport: no stream credit left")
    }

    private suspend fun ensureSessionLocked(): QuicConnection {
        if (closed) throw ProxyError.ConnectionFailed("QUIC transport session closed")
        quic?.takeIf { it.isConnected }?.let { return it }
        backoff.check("QUIC")

        runCatching { quic?.close() }
        quic = null

        val alpn = tls.alpn?.takeIf { it.isNotEmpty() } ?: listOf("h3")
        val connection = QuicConnection(
            serverName = configuration.serverAddress,
            serverPort = configuration.serverPort.toInt(),
            alpn = alpn,
            tuning = QuicTuning.NOWHERE,
            fingerprint = tls.fingerprint,
            tlsServerName = tls.serverName.ifBlank { configuration.serverAddress },
            allowInsecure = tls.allowInsecure,
            pinnedCertSha256 = tls.pinnedCertSha256,
            verifyName = tls.verifyName
        )
        try {
            if (!connection.connect()) {
                throw ProxyError.ConnectionFailed("QUIC transport handshake failed")
            }
            if (closed) throw ProxyError.ConnectionFailed("QUIC transport session closed")
            quic = connection
            if (closed) {
                quic = null
                throw ProxyError.ConnectionFailed("QUIC transport session closed")
            }
        } catch (e: CancellationException) {
            runCatching { connection.close() }
            throw e
        } catch (e: Throwable) {
            runCatching { connection.close() }
            if (!closed) backoff.failed(e)
            throw e
        }
        backoff.succeeded()
        return connection
    }

    fun close() {
        closed = true
        val c = quic
        quic = null
        c?.close()
    }
}

/**
 * A UDP flow carried in QUIC datagrams: [send] hands one payload to the
 * protocol's framing, [receive] returns one payload the dispatcher routed
 * here. Unreliable by design, as UDP is — a full inbox drops the oldest.
 */
internal class QuicUdpFlow(
    private val scope: CoroutineScope,
    private val transmit: suspend (ByteArray) -> Unit,
    private val onClose: () -> Unit
) : ProxyConnection() {

    private val inbox = Channel<ByteArray>(capacity = 256, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    @Volatile
    private var closed = false

    override val isConnected: Boolean get() = !closed

    fun deliver(payload: ByteArray) {
        if (!closed) inbox.trySend(payload)
    }

    override suspend fun sendRaw(data: ByteArray) {
        if (closed) throw ProxyError.ConnectionFailed("UDP flow closed")
        transmit(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        scope.launch { runCatching { sendRaw(data) } }
    }

    override suspend fun receiveRaw(): ByteArray? = inbox.receiveCatching().getOrNull()

    override fun cancel() {
        if (closed) return
        closed = true
        inbox.close()
        onClose()
    }
}

/**
 * Reassembles fragmented UDP messages: both protocols split a payload too
 * large for one datagram into numbered pieces under one packet id. Partial
 * messages are kept for a few seconds and then dropped, as the protocols'
 * own implementations do, so a lost fragment costs one packet and no memory.
 */
internal class UdpReassembler {
    private class Partial(val pieces: Array<ByteArray?>, val started: Long)

    /** Insertion-ordered so the oldest partial can be evicted when the map is full. */
    private val partial = LinkedHashMap<Long, Partial>()

    /** The whole payload once every piece of [packetKey] has arrived, else null. */
    @Synchronized
    fun add(packetKey: Long, fragmentId: Int, fragmentCount: Int, payload: ByteArray): ByteArray? {
        if (fragmentCount <= 1) return payload
        if (fragmentId !in 0 until fragmentCount) return null
        val now = System.currentTimeMillis()

        // Drop stale partials on every insert, not only when the map is large.
        // The key is (session << 16 | packetId) with a 16-bit packet id, so a
        // fragment of packet N and one of packet N+65536 share a key: without a
        // short expiry an orphaned fragment of the first would be glued onto the
        // second and corrupt it.
        partial.entries.removeIf { now - it.value.started > STALE_MS }

        val existing = partial[packetKey]
        val entry = if (existing == null || existing.pieces.size != fragmentCount) {
            // No partial, or one whose fragment count disagrees — a stale key
            // collision. Start fresh rather than index into the wrong-sized
            // array or glue mismatched pieces together.
            Partial(arrayOfNulls(fragmentCount), now).also {
                partial[packetKey] = it
                if (partial.size > MAX_PARTIALS) {
                    val oldest = partial.keys.iterator()
                    if (oldest.hasNext()) { oldest.next(); oldest.remove() }
                }
            }
        } else {
            existing
        }

        entry.pieces[fragmentId] = payload
        if (entry.pieces.any { it == null }) return null
        partial.remove(packetKey)
        val total = entry.pieces.sumOf { it!!.size }
        val out = ByteArray(total)
        var at = 0
        for (piece in entry.pieces) {
            piece!!.copyInto(out, at)
            at += piece.size
        }
        return out
    }

    private companion object {
        /** A UDP packet reassembles in milliseconds on any working path; 2 s is already generous. */
        const val STALE_MS = 2_000L

        /** A ceiling on half-assembled packets, so a flood of lone fragments cannot grow the map without bound. */
        const val MAX_PARTIALS = 1024
    }
}
