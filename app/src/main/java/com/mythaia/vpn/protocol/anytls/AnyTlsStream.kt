package com.mythaia.vpn.protocol.anytls

import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean

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
    private val closed = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val isConnected: Boolean
        get() = !closed.get() && !session.isClosed

    override suspend fun sendRaw(data: ByteArray) {
        if (closed.get()) return
        session.sendStreamData(streamId, data)
    }

    override fun sendRawAsync(data: ByteArray) {
        if (closed.get()) return
        scope.launch { runCatching { session.sendStreamData(streamId, data) } }
    }

    override suspend fun receiveRaw(): ByteArray? {
        if (closed.get()) return null
        return runCatching { incoming.receive() }.getOrNull()
    }

    override suspend fun startReceiving(
        handler: suspend (ByteArray) -> Unit,
        errorHandler: suspend (Exception?) -> Unit
    ) {
        scope.launch {
            try {
                while (isConnected) {
                    val data = receive() ?: break
                    handler(data)
                }
                errorHandler(null)
            } catch (e: Exception) {
                errorHandler(e)
            }
        }
    }

    override fun cancel() {
        if (!closed.compareAndSet(false, true)) return
        incoming.close()
        // Tell the peer, but never let a dead session make closing throw.
        runCatching { runBlocking { session.closeStream(streamId) } }
        scope.cancel()
    }

    /** Data the session routed to this stream. */
    internal fun onData(data: ByteArray) {
        if (closed.get()) return
        incoming.trySend(data)
    }

    /** The peer sent FIN, or refused the stream: no more data is coming. */
    internal fun onPeerClosed() {
        if (!closed.compareAndSet(false, true)) return
        incoming.close()
        scope.cancel()
    }

    /** The whole session went away underneath this stream. */
    internal fun onSessionClosed() = onPeerClosed()
}
