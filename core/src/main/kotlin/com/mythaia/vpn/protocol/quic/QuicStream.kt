package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** The peer sent RESET_STREAM: the receive side ended abruptly, not cleanly. */
class QuicStreamReset(val errorCode: Long) :
    IOException("QUIC stream reset by peer (error $errorCode)")

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

    /** Set when the peer reset the stream, or the transport closed it under us. */
    private val broken = AtomicBoolean(false)

    @Volatile
    private var resetCause: QuicStreamReset? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)

    /**
     * Receive-side flow control, deferred to consume time.
     *
     * [buffered] is what has been delivered into [incoming] but not yet taken
     * out; [owedCredit] is what has been taken out but not yet credited back
     * to the peer. The peer's window is only reopened as the app reads, so a
     * fast server cannot fill the heap faster than the tunnel drains — the bug
     * that crediting on arrival caused. On a hard close both counts are handed
     * back so the connection-level window does not leak.
     */
    private val buffered = AtomicLong(0)
    private val owedCredit = AtomicLong(0)

    /**
     * Sends serialised onto one coroutine so bytes keep their order: a launch
     * per [sendRawAsync] call raced, and a QUIC stream that reorders its own
     * bytes is a broken stream. [sendRaw] and [finish] go through the same
     * queue, so order holds across the sync and async paths too.
     */
    private val outbound = Channel<SendJob>(Channel.UNLIMITED)

    private class SendJob(
        val data: ByteArray,
        val fin: Boolean,
        val done: CompletableDeferred<Unit>?
    )

    init {
        scope.launch {
            try {
                for (job in outbound) {
                    try {
                        writeOrdered(job.data, job.fin)
                        job.done?.complete(Unit)
                    } catch (e: Throwable) {
                        job.done?.completeExceptionally(e)
                    }
                }
            } finally {
                // The queue closed or the scope was cancelled: nothing more
                // will drain, so no awaiting caller should hang on a job.
                while (true) {
                    val job = outbound.tryReceive().getOrNull() ?: break
                    job.done?.completeExceptionally(ProxyError.ConnectionFailed("QUIC stream $streamId closed"))
                }
            }
        }
    }

    override val isConnected: Boolean
        get() = !cancelled.get() && !broken.get() && connection.isConnected

    /**
     * Writes to the stream, keeping order with every other write on it.
     *
     * The bytes are not written here but handed to the single sender coroutine;
     * this suspends until that coroutine has placed them (so back-pressure and
     * errors still reach the caller).
     */
    override suspend fun sendRaw(data: ByteArray) {
        if (cancelled.get() || broken.get()) return
        val done = CompletableDeferred<Unit>()
        if (outbound.trySend(SendJob(data, fin = false, done = done)).isFailure) return
        done.await()
    }

    override fun sendRawAsync(data: ByteArray) {
        if (cancelled.get() || broken.get()) return
        outbound.trySend(SendJob(data, fin = false, done = null))
    }

    /**
     * Offers the whole payload, the remainder again until it is taken.
     *
     * ngtcp2 accepts as much as flow control and congestion allow and no more,
     * so a partial accept is ordinary rather than an error; what is left waits
     * for the peer to open the window. A result below [QuicConnection.WRITE_AGAIN]
     * is terminal — the stream is gone — and surfaces as an exception on a data
     * write, or is swallowed on a FIN, where there is nothing left to end.
     */
    private suspend fun writeOrdered(data: ByteArray, fin: Boolean) {
        var offset = 0
        while (true) {
            if (cancelled.get() || broken.get()) return
            val remaining = if (offset == 0) data else data.copyOfRange(offset, data.size)
            val accepted = connection.writeStream(streamId, remaining, fin)
            when {
                accepted < QuicConnection.WRITE_AGAIN -> {
                    // Terminal: the stream does not exist, is shut for writing,
                    // or the connection is closing. Retrying would only spin.
                    if (fin) return
                    throw ProxyError.ConnectionFailed("QUIC stream $streamId write failed (ngtcp2 $accepted)")
                }
                accepted == QuicConnection.WRITE_AGAIN -> {
                    // Nothing fit this time — congestion, pacing, a full packet
                    // or a blocked window. A FIN with no data lands here until
                    // ngtcp2 has room for it, which is why finish() must loop.
                    delay(WRITE_RETRY_MS)
                }
                else -> {
                    offset += accepted.toInt()
                    if (offset >= data.size) return
                }
            }
        }
    }

    /**
     * The next chunk, or null once the stream ended *and* was drained.
     *
     * Not gated on the ended flag: a peer that finishes and closes usually
     * delivers the last data and the FIN together, and refusing to read after
     * the FIN would throw away the tail of every response. Reading is what
     * reopens the peer's flow-control window, so each chunk taken out is
     * credited back here.
     */
    override suspend fun receiveRaw(): ByteArray? {
        val result = incoming.receiveCatching()
        val data = result.getOrNull()
        if (data == null) {
            // The channel is closed. A reset closed it with a cause, which the
            // caller must see rather than mistake for a clean end-of-stream.
            resetCause?.let { throw it }
            return null
        }
        buffered.addAndGet(-data.size.toLong())
        creditConsumed(data.size.toLong())
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
     * Ends our side of the stream without abandoning it.
     *
     * A request that has sent its whole body says so with a FIN; the response
     * still comes back afterwards, which is why this is not [cancel]. The FIN
     * rides the ordered queue so it cannot overtake unsent data, and is retried
     * by [writeOrdered] until ngtcp2 has room for it — a FIN dropped on a full
     * congestion window is never resent on its own.
     */
    suspend fun finish() {
        if (cancelled.get() || broken.get()) return
        val done = CompletableDeferred<Unit>()
        if (outbound.trySend(SendJob(ByteArray(0), fin = true, done = done)).isFailure) return
        done.await()
    }

    override fun cancel() {
        if (!cancelled.compareAndSet(false, true)) return
        ended.set(true)
        // Hand back the window for anything buffered but never read, so the
        // connection-level credit does not leak when other streams live on.
        returnOutstandingCredit(wake = false)
        incoming.close()
        outbound.close()
        connection.shutdownStream(streamId)
        scope.cancel()
    }

    internal fun onData(data: ByteArray) {
        if (ended.get() || broken.get()) {
            // Nothing will read it, so give the window straight back.
            returnCredit(data.size.toLong(), wake = false)
            return
        }
        buffered.addAndGet(data.size.toLong())
        if (incoming.trySend(data).isFailure) {
            buffered.addAndGet(-data.size.toLong())
            returnCredit(data.size.toLong(), wake = false)
        }
    }

    /** A clean FIN: no more data, but what is queued stays readable. */
    internal fun onPeerClosed() {
        if (!ended.compareAndSet(false, true)) return
        incoming.close()
    }

    /**
     * The transport closed the stream (both sides shut). Like a FIN, but any
     * bytes still buffered are now lost, so their window is handed back.
     */
    internal fun onTransportClosed() {
        if (!ended.compareAndSet(false, true)) return
        returnOutstandingCredit(wake = false)
        incoming.close()
    }

    /**
     * The peer sent RESET_STREAM. The receive ends in a [QuicStreamReset]
     * rather than a clean null, the stream is marked unusable, and the window
     * for undrained bytes is returned.
     */
    internal fun onPeerReset(errorCode: Long) {
        if (!broken.compareAndSet(false, true)) return
        ended.set(true)
        resetCause = QuicStreamReset(errorCode)
        returnOutstandingCredit(wake = false)
        incoming.close(resetCause)
        outbound.close()
    }

    /**
     * Called from inside a native callback, so it must never ask ngtcp2 to
     * write. Bytes read but not yet credited to the stream have had their
     * connection credit already (see [creditConsumed]); bytes never read
     * have had neither.
     */
    private fun returnOutstandingCredit(wake: Boolean) {
        val read = owedCredit.getAndSet(0)
        val unread = buffered.getAndSet(0)
        connection.extendOffsets(streamId, read + unread, unread, wake)
    }

    /** Bytes that arrived and will never be read: both windows get them back. */
    private fun returnCredit(count: Long, wake: Boolean) {
        if (count > 0) connection.extendOffsets(streamId, count, count, wake)
    }

    /**
     * Credits consumed bytes: to the connection's shared tally at once, and
     * to this stream in batches, since a MAX_STREAM_DATA per chunk would be a
     * frame per read. The stream's peer is told once a quarter of its window
     * has been read, which is also when ngtcp2 decides the frame is worth
     * sending.
     */
    private fun creditConsumed(count: Long) {
        connection.creditConnection(count)
        val owed = owedCredit.addAndGet(count)
        if (owed >= connection.streamCreditThreshold) {
            val flush = owedCredit.getAndSet(0)
            if (flush > 0) connection.extendOffsets(streamId, flush, 0, wake = true)
        }
    }

    private companion object {
        const val WRITE_RETRY_MS = 5L
    }
}
