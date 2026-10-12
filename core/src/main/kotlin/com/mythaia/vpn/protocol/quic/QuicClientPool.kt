package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.hysteria.HysteriaClient
import com.mythaia.vpn.protocol.tuic.TuicClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * One Hysteria2 / TUIC client per server, shared by every flow.
 *
 * Both protocols multiplex everything onto one QUIC connection — that is
 * where their speed comes from — so a client per flow was the worst of both
 * worlds: every TCP connection in the tunnel paid a full QUIC handshake,
 * HTTP/3 setup and authentication (most of a second on a filtered network),
 * and the connections were never closed, each holding a socket and, for
 * TUIC, a heartbeat until the server's idle timeout. Clients bring their
 * session back up on their own when it dies; [closeAll] ends them when the
 * tunnel stops or switches server.
 */
object QuicClientPool {

    private val hysteria = ConcurrentHashMap<String, HysteriaClient>()
    private val tuic = ConcurrentHashMap<String, TuicClient>()

    fun hysteria(configuration: ProxyConfiguration): HysteriaClient =
        hysteria.computeIfAbsent(key(configuration)) { HysteriaClient(configuration) }

    fun tuic(configuration: ProxyConfiguration): TuicClient =
        tuic.computeIfAbsent(key(configuration)) { TuicClient(configuration) }

    /** Ends every pooled session. Safe to call any time; the next dial starts afresh. */
    fun closeAll() {
        val h = hysteria.values.toList()
        val t = tuic.values.toList()
        hysteria.clear()
        tuic.clear()
        h.forEach { runCatching { it.close() } }
        t.forEach { runCatching { it.close() } }
    }

    /** Everything that makes two configurations reach the same session. */
    private fun key(c: ProxyConfiguration): String = listOf(
        c.outboundProtocol, c.serverAddress, c.serverPort, c.uuid, c.password, c.trojanPassword,
        c.obfuscation, c.obfuscationPassword, c.hysteriaUpMbps, c.hysteriaDownMbps,
        c.tls?.serverName, c.tls?.allowInsecure, c.tls?.fingerprint, c.tls?.alpn,
        c.tls?.pinnedCertSha256, c.tls?.verifyName
    ).joinToString("|")
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

    private val partial = HashMap<Long, Partial>()

    /** The whole payload once every piece of [packetKey] has arrived, else null. */
    @Synchronized
    fun add(packetKey: Long, fragmentId: Int, fragmentCount: Int, payload: ByteArray): ByteArray? {
        if (fragmentCount <= 1) return payload
        if (fragmentId !in 0 until fragmentCount) return null
        val now = System.currentTimeMillis()
        if (partial.size > 64) partial.entries.removeIf { now - it.value.started > STALE_MS }
        val entry = partial.getOrPut(packetKey) { Partial(arrayOfNulls(fragmentCount), now) }
        if (entry.pieces.size != fragmentCount) {
            partial.remove(packetKey)
            return null
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
        const val STALE_MS = 5_000L
    }
}
