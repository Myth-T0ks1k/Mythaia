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

    private val masking = session.option and VmessProtocol.OPTION_CHUNK_MASKING != 0
    private val padding = session.option and VmessProtocol.OPTION_GLOBAL_PADDING != 0

    private val writer = VmessChunkStream(
        key = session.requestBodyKey,
        iv = session.requestBodyIv,
        security = session.security,
        masking = masking,
        globalPadding = padding
    )

    private val reader = VmessChunkStream(
        key = session.responseBodyKey,
        iv = session.responseBodyIv,
        security = session.security,
        masking = masking,
        globalPadding = padding
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
            val header = pendingHeader.getAndSet(null)
            val body = writer.encode(data)
            transport.send(if (header != null) header + body else body)
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        val header = pendingHeader.getAndSet(null)
        val body = synchronized(writer) { writer.encode(data) }
        transport.sendAsync(if (header != null) header + body else body)
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
        try {
            transport.forceCancel()
        } catch (e: Exception) {
            logger.debug("VMess cancel: ${e.message ?: e}")
        }
    }
}
