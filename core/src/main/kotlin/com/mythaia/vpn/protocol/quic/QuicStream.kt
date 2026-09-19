package com.mythaia.vpn.protocol.quic

import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One QUIC stream, presented as an ordinary proxy connection.
 *
 * A stream owns no socket — several share the connection underneath — so
 * closing one leaves the rest running, which is the whole reason to multiplex.
 */
class QuicStream(
    private val streamId: Long,
    private val connection: QuicConnection
) : ProxyConnection() {

    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)

    /** Set when no more data will arrive; what is queued is still readable. */
    private val ended = AtomicBoolean(false)

    private val cancelled = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val isConnected: Boolean
        get() = !cancelled.get() && connection.isConnected

    /**
     * Writes to the stream, offering the remainder again until it is taken.
     *
     * ngtcp2 accepts as much as flow control and congestion allow and no more,
     * so a partial accept is normal rather than an error; what is left waits
     * for the peer to open the window.
     */
    override suspend fun sendRaw(data: ByteArray) {
        if (cancelled.get()) return
        var offset = 0
        while (offset < data.size) {
            val remaining = if (offset == 0) data else data.copyOfRange(offset, data.size)
            if (!isConnected) return
            val accepted = connection.writeStream(streamId, remaining, fin = false)
            // Negative means the connection is gone. Zero means ngtcp2 took
            // nothing this time — the window is shut, or the packet had no room
            // for a STREAM frame — which is ordinary backpressure, not failure.
            if (accepted < 0) return
            if (accepted == 0L) {
                delay(WRITE_RETRY_MS)
                continue
            }
            offset += accepted.toInt()
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        if (cancelled.get()) return
        scope.launch { runCatching { sendRaw(data) } }
    }

    /**
     * The next chunk, or null once the stream ended *and* was drained.
     *
     * Not gated on the ended flag: a peer that finishes and closes usually
     * delivers the last data and the FIN together, and refusing to read after
     * the FIN would throw away the tail of every response.
     */
    override suspend fun receiveRaw(): ByteArray? = incoming.receiveCatching().getOrNull()

    override suspend fun startReceiving(
        handler: suspend (ByteArray) -> Unit,
        errorHandler: suspend (Exception?) -> Unit
    ) {
        scope.launch {
            try {
                while (true) {
                    val data = receive() ?: break
                    handler(data)
                }
                errorHandler(null)
            } catch (e: Exception) {
                errorHandler(e)
            }
        }
    }

    /**
     * Ends our side of the stream without abandoning it.
     *
     * A request that has sent its whole body says so with a FIN; the response
     * still comes back afterwards, which is why this is not [cancel].
     */
    suspend fun finish() {
        if (cancelled.get()) return
        connection.writeStream(streamId, ByteArray(0), fin = true)
    }

    override fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        ended.set(true)
        incoming.close()
        connection.shutdownStream(streamId)
        scope.cancel()
    }

    internal fun onData(data: ByteArray) {
        if (ended.get()) return
        incoming.trySend(data)
    }

    internal fun onPeerClosed() {
        if (!ended.compareAndSet(false, true)) return
        incoming.close()
    }

    private companion object {
        const val WRITE_RETRY_MS = 5L
    }
}
