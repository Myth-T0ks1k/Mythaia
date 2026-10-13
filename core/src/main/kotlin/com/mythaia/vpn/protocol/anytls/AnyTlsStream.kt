package com.mythaia.vpn.protocol.anytls

import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * One multiplexed stream, presented as an ordinary proxy connection.
 *
 * Everything a caller sends becomes `cmdPSH` frames on the session; everything
 * the session routes here arrives through a channel. The stream owns no socket
 * of its own, which is the whole point — several of these share one TLS
 * connection, and closing one leaves the rest running.
 */
class AnyTlsStream(
    private val streamId: Int,
    private val session: AnyTlsSession
) : ProxyConnection() {

    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)

    /**
     * Bytes queued in [incoming] and not yet read. The channel itself is
     * unbounded, so this is what bounds it: past [INBOUND_BUDGET] the session's
     * read loop parks in [onData] until the reader drains some. That is the
     * backpressure — the loop stops reading the TLS socket, its TCP window
     * fills, and the server slows down — that the reference gets from its
     * blocking pipe. Without it a slow reader (lwIP's window on a phone) had
     * the whole response accumulate on the heap.
     */
    private val buffered = AtomicInteger(0)
    private val gateLock = Any()

    /** Completed when the reader has drained below budget; null while under it. */
    private var drained: CompletableDeferred<Unit>? = null

    /** Set when no more data will arrive; queued data is still readable. */
    private val ended = AtomicBoolean(false)

    /** Set by [cancel], i.e. by this side giving up. */
    private val cancelled = AtomicBoolean(false)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    override val isConnected: Boolean
        get() = !cancelled.get() && !session.isClosed

    override suspend fun sendRaw(data: ByteArray) {
        if (cancelled.get()) return
        session.sendStreamData(streamId, data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (cancelled.get()) return
        scope.launch { runCatching { session.sendStreamData(streamId, data) } }
    }

    /**
     * The next chunk, or null once the stream has ended *and* been drained.
     *
     * Deliberately not gated on the ended flag: a server that finishes a
     * response and closes usually delivers the last data frame and the FIN in
     * one read, so refusing to read after the FIN would throw away the tail of
     * every response. Closing the channel is what marks the end, and a closed
     * channel still yields what is already in it.
     */
    override suspend fun receiveRaw(): ByteArray? {
        val data = incoming.receiveCatching().getOrNull() ?: return null
        if (buffered.addAndGet(-data.size) <= INBOUND_BUDGET) openGate()
        return data
    }

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
     * Gives up on this stream from our side.
     *
     * The FIN goes out without waiting for it. This is called from the lwIP
     * executor — a single thread driving the whole tunnel — and the write path
     * suspends whenever the socket is not immediately writable, so blocking on
     * it here would stall every other flow until the uplink drained.
     */
    override fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        ended.set(true)
        incoming.close()
        // A session loop parked on this stream must not stay parked for a
        // reader that is gone.
        openGate()
        session.closeStreamAsync(streamId)
        scope.cancel()
    }

    /**
     * Data the session routed to this stream.
     *
     * Suspends the caller — the session's read loop, so every stream on the
     * session — while this stream holds more than [INBOUND_BUDGET] unread
     * bytes. See [buffered].
     */
    internal suspend fun onData(data: ByteArray) {
        if (ended.get()) return
        buffered.addAndGet(data.size)
        incoming.trySend(data)

        while (buffered.get() > INBOUND_BUDGET && !ended.get()) {
            val gate = synchronized(gateLock) {
                drained ?: CompletableDeferred<Unit>().also { drained = it }
            }
            // Re-checked after the gate is published: a drain that landed
            // between the check above and the publish found no gate to open,
            // and waiting on it now would park the whole session for good.
            if (buffered.get() <= INBOUND_BUDGET || ended.get()) {
                openGate()
                return
            }
            gate.await()
        }
    }

    /** Wakes a session loop parked in [onData], if one is. */
    private fun openGate() {
        val gate = synchronized(gateLock) { drained.also { drained = null } }
        gate?.complete(Unit)
    }

    /**
     * The peer sent FIN, or refused the stream.
     *
     * The channel is closed rather than emptied, so a reader still drains what
     * arrived before the end.
     */
    internal fun onPeerClosed() {
        if (!ended.compareAndSet(false, true)) return
        incoming.close()
        openGate()
    }

    /** The whole session went away underneath this stream. */
    internal fun onSessionClosed() = onPeerClosed()

    private companion object {
        /** Unread bytes one stream may hold before the session stops reading for it. */
        const val INBOUND_BUDGET = 1024 * 1024
    }
}
