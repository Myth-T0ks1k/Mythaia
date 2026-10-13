package com.mythaia.vpn.protocol.naive.http2

import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val logger = MythaiaLogger("H2-POOL")

/**
 * HTTP/2 connections shared by the transports that send ordinary requests over
 * them (gRPC, XHTTP), one pool per server, as Xray's clients share them: the
 * first stream to a server dials it, later ones open on that connection.
 *
 * Dialling per tunnel cost every new connection an app made a TCP and a TLS
 * handshake more than Xray, with a fragmented ClientHello's pauses on top:
 * 0.4 to 1.1 s to the first byte of each new request on a real server, where
 * Xray needed 0.12 s.
 *
 * A connection idle for [IDLE_CLOSE_MS] is closed rather than reused: CDNs and
 * mobile NATs drop idle connections without telling anyone, and a stream on a
 * dead connection only fails when its first reply never comes. [closeAll] when
 * the tunnel stops, switches server or wakes from sleep.
 */
object Http2StreamPool {

    private val sessions = HashMap<String, MutableList<Http2Session>>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var reaper: Job? = null

    private const val IDLE_CLOSE_MS = 60_000L
    private const val REAP_INTERVAL_MS = 15_000L

    /**
     * A new stream, not yet opened, on a pooled connection to the server [key]
     * identifies (everything that shapes the connection); [dial] opens a new
     * connection (TLS or Reality, ALPN h2) when none has room. [label] names
     * the stream in errors and logs.
     */
    suspend fun reserve(key: String, label: String, dial: suspend () -> Http2Wire): Http2Stream {
        var retriedClosed = false
        while (true) {
            val session: Http2Session
            val reservedStream: Http2Stream?
            val join: Boolean
            synchronized(this) {
                val list = sessions.getOrPut(key) { mutableListOf() }
                list.removeAll { it.isClosed }
                val ready = list.firstOrNull { it.hasCapacity }
                val starting = list.firstOrNull { it.isStarting }
                when {
                    // Reserved under the pool lock: the reaper closes idle sessions
                    // under it too, so one it is about to close is never handed out
                    // (that surfaced as "Transport closed" instead of a retry).
                    ready != null -> { session = ready; join = false; reservedStream = ready.tryReserveStream(label) }
                    // Several streams at once (a page's first requests) wait for
                    // the connection being dialled instead of dialling their own.
                    starting != null -> { session = starting; join = true; reservedStream = null }
                    else -> {
                        val fresh = Http2Session(null, scope, null, null, dial)
                        fresh.onClose = { synchronized(this) { sessions[key]?.remove(fresh) } }
                        list.add(fresh)
                        session = fresh
                        join = true
                        reservedStream = null
                    }
                }
                startReaper()
            }
            if (!join) return reservedStream ?: continue
            try {
                return session.acquireStream(label)
            } catch (e: Http2Error.ConnectionFailed) {
                // Closed between the pick and the join (closeAll, or a dial that
                // was cancelled under it): once more, on another connection.
                if (!retriedClosed && e.message?.endsWith(Http2Session.CLOSED_MESSAGE) == true) {
                    retriedClosed = true
                    continue
                }
                throw e
            }
        }
    }

    /** Ends every pooled connection. */
    fun closeAll() {
        val all = synchronized(this) {
            val snapshot = sessions.values.flatten()
            sessions.clear()
            reaper?.cancel()
            reaper = null
            snapshot
        }
        for (session in all) {
            session.onClose = null
            runCatching { session.close() }
        }
    }

    private fun startReaper() {
        if (reaper?.isActive == true) return
        reaper = scope.launch {
            while (true) {
                delay(REAP_INTERVAL_MS)
                val (idle, done) = synchronized(this@Http2StreamPool) {
                    val stale = sessions.values.flatten().filter {
                        !it.isClosed && !it.isStarting && it.idleNanos > IDLE_CLOSE_MS * 1_000_000
                    }
                    for (list in sessions.values) list.removeAll { it in stale || it.isClosed }
                    sessions.entries.removeAll { it.value.isEmpty() }
                    val empty = sessions.isEmpty()
                    if (empty) reaper = null
                    stale to empty
                }
                for (session in idle) {
                    session.onClose = null
                    runCatching { session.close() }
                }
                if (done) {
                    logger.debug("No pooled HTTP/2 connections left")
                    return@launch
                }
            }
        }
    }
}

/** A TLS or Reality connection as the byte stream a pooled session runs over. */
class TlsRecordWire(private val connection: com.mythaia.vpn.protocol.tls.TlsRecordConnection) : Http2Wire {
    override suspend fun send(data: ByteArray) = connection.send(data)
    override suspend fun receive(): ByteArray? = connection.receive()
    override fun cancel() = connection.cancel()
}

/** Any [com.mythaia.vpn.protocol.Transport] as the byte stream a pooled session runs over. */
class TransportWire(private val transport: com.mythaia.vpn.protocol.Transport) : Http2Wire {
    override suspend fun send(data: ByteArray) = transport.send(data)
    override suspend fun receive(): ByteArray? = transport.receive()
    override fun cancel() = transport.forceCancel()
}

/** A plain TCP connection (HTTP/2 without TLS) as the byte stream a pooled session runs over. */
class SocketWire(private val socket: com.mythaia.vpn.util.NioSocket) : Http2Wire {
    override suspend fun send(data: ByteArray) = socket.send(data)
    override suspend fun receive(): ByteArray? = socket.receive()
    override fun cancel() = socket.forceCancel()
}

/** What makes two streams able to share a pooled connection: the same server, reached the same way. */
object Http2PoolKey {
    private val json = kotlinx.serialization.json.Json { encodeDefaults = true }

    /**
     * [tls] is the TLS the connection is dialled with (ALPN as sent). Serialized
     * rather than toString'd, so array fields compare by content and an edited
     * server never reuses the old connection.
     */
    fun of(
        configuration: com.mythaia.data.model.ProxyConfiguration,
        tls: com.mythaia.data.model.TlsConfiguration?,
        vararg extra: String?
    ): String = (
        listOf(
            configuration.serverAddress,
            configuration.serverPort.toString(),
            tls?.let { json.encodeToString(com.mythaia.data.model.TlsConfiguration.serializer(), it) },
            configuration.reality?.let {
                json.encodeToString(com.mythaia.data.model.RealityConfiguration.serializer(), it)
            }
        ) + extra
    ).joinToString("|")
}
