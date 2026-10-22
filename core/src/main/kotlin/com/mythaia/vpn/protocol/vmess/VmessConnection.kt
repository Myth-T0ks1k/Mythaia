package com.mythaia.vpn.protocol.vmess

import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val logger = MythaiaLogger("VMess")

/**
 * One VMess stream over [transport].
 *
 * The sealed request header rides the first write, so a connection costs no
 * extra round trip. The reply's header is read once, lazily, on the first
 * receive — the server sends it in front of the first body chunk.
 */
class VmessConnection(
    private val transport: Transport,
    private val session: VmessProtocol.Session,
    requestHeader: ByteArray
) : ProxyConnection() {

    private val chunkStream = session.option and VmessProtocol.OPTION_CHUNK_STREAM != 0
    private val masking = session.option and VmessProtocol.OPTION_CHUNK_MASKING != 0
    private val padding = session.option and VmessProtocol.OPTION_GLOBAL_PADDING != 0
    private val authenticatedLength = session.option and VmessProtocol.OPTION_AUTHENTICATED_LENGTH != 0

    private val writer = VmessChunkStream(
        key = session.requestBodyKey,
        iv = session.requestBodyIv,
        security = session.security,
        masking = masking,
        globalPadding = padding,
        authenticatedLength = authenticatedLength
    )

    private val reader = VmessChunkStream(
        key = session.responseBodyKey,
        iv = session.responseBodyIv,
        security = session.security,
        masking = masking,
        globalPadding = padding,
        authenticatedLength = authenticatedLength,
        lengthKeySource = session.requestBodyKey,
        lengthIvFallback = session.requestBodyIv
    )

    /**
     * Prepended to the first write and cleared once it has gone out.
     *
     * Atomic because sendAsync is called off the coroutine that owns
     * [sendLock]: two writers racing here would either send the header twice or
     * put a body chunk in front of it, and the server would drop the stream
     * either way.
     */
    private val pendingHeader = java.util.concurrent.atomic.AtomicReference(requestHeader)

    private val sendLock = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()

    private var buffer = ByteArray(0)
    private var responseHeaderRead = false
    private var closed = false

    @Volatile
    private var cancelled = false

    override val isConnected: Boolean
        get() = !cancelled && !closed

    override suspend fun sendRaw(data: ByteArray) {
        // The chunk writer advances a counter and a mask stream per chunk, so
        // only one writer may be inside encode at a time.
        sendLock.withLock {
            drainAsyncQueueLocked()
            val header = pendingHeader.getAndSet(null)
            val body = if (chunkStream) writer.encode(data) else data
            try {
                transport.send(if (header != null) header + body else body)
            } finally {
                drainAsyncQueueLocked()
            }
        }
        flushAsyncIfUnlocked()
    }

    override fun sendRawAsync(data: ByteArray) {
        synchronized(asyncQueue) {
            asyncQueue.addLast(data)
        }
        flushAsyncIfUnlocked()
    }

    private fun drainAsyncQueueLocked() {
        while (true) {
            val next = synchronized(asyncQueue) {
                if (asyncQueue.isEmpty()) null else asyncQueue.removeFirst()
            } ?: break
            runCatching {
                val header = pendingHeader.getAndSet(null)
                val body = if (chunkStream) writer.encode(next) else next
                transport.sendAsync(if (header != null) header + body else body)
            }
        }
    }

    private fun flushAsyncIfUnlocked() {
        while (synchronized(asyncQueue) { asyncQueue.isNotEmpty() }) {
            if (!sendLock.tryLock()) return
            try {
                drainAsyncQueueLocked()
            } finally {
                sendLock.unlock()
            }
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            if (!responseHeaderRead) {
                val consumed = VmessProtocol.openResponseHeader(session, buffer)
                if (consumed >= 0) {
                    buffer = buffer.copyOfRange(consumed, buffer.size)
                    responseHeaderRead = true
                } else {
                    if (!fill()) return null
                    continue
                }
            }

            if (!chunkStream) {
                if (buffer.isNotEmpty()) {
                    val out = buffer
                    buffer = ByteArray(0)
                    return out
                }
                if (!fill()) {
                    closed = true
                    return null
                }
                val out = buffer
                buffer = ByteArray(0)
                return out
            }

            when (val decoded = reader.decode(buffer, 0)) {
                is VmessChunkStream.Decoded.Chunk -> {
                    buffer = buffer.copyOfRange(decoded.consumed, buffer.size)
                    // A zero-length payload is not the terminator — that is a
                    // separate case — so only skip it and keep reading.
                    if (decoded.payload.isNotEmpty()) return decoded.payload
                }
                VmessChunkStream.Decoded.EndOfStream -> {
                    closed = true
                    return null
                }
                VmessChunkStream.Decoded.NeedMore -> if (!fill()) return null
            }
        }
    }

    /** Reads more from the transport. False when it is finished. */
    private suspend fun fill(): Boolean {
        if (cancelled) return false
        val more = transport.receive()
        if (more == null || more.isEmpty()) return false
        buffer = buffer + more
        return true
    }

    override fun cancel() {
        if (cancelled) return
        cancelled = true
        synchronized(asyncQueue) { asyncQueue.clear() }
        try {
            transport.forceCancel()
        } catch (e: Exception) {
            logger.debug("VMess cancel: ${e.message ?: e}")
        }
    }
}
