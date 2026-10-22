package com.mythaia.vpn.protocol.mux

import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.data.model.ProxyError

private val logger = MythaiaLogger("MuxSession")

/**
 * Individual mux session: send (Keep frame), close (End frame), and demuxer
 * delivery callbacks.
 */
class MuxSession(
    val sessionID: Int,           // UInt16 range
    val network: MuxNetwork,
    val targetHost: String,
    val targetPort: Int,          // UInt16 range
    private val client: MuxClient,
    private val globalID: ByteArray? = null
) {
    @Volatile
    var closed: Boolean = false
        private set

    var dataHandler: ((ByteArray) -> Unit)? = null

    var closeHandler: (() -> Unit)? = null

    // For XUDP, the first send must include a New frame with the data payload
    // and GlobalID — defer the New frame until first data arrives.
    private var firstFrameSent: Boolean = (globalID == null)

    companion object {
        /**
         * Maximum payload size per Mux frame. MuxFrame uses an unsigned 16-bit
         * length field (max 65,535 bytes); capping each frame at 32 KB prevents
         * uint16 length overflow and keeps shared mux connection latency low.
         */
        private const val MAX_FRAME_PAYLOAD_SIZE = 32_768
    }

    /**
     * Sends data through the mux connection as Keep frame(s) with payload.
     * For XUDP, the first call sends a New frame with the data and GlobalID.
     */
    suspend fun send(data: ByteArray) {
        if (closed) throw ProxyError.ConnectionFailed("Mux session closed")

        if (data.isEmpty()) {
            sendSingleChunk(data)
            return
        }

        var offset = 0
        while (offset < data.size) {
            if (closed) throw ProxyError.ConnectionFailed("Mux session closed")
            val chunkSize = minOf(MAX_FRAME_PAYLOAD_SIZE, data.size - offset)
            val chunk = if (offset == 0 && chunkSize == data.size) {
                data
            } else {
                data.copyOfRange(offset, offset + chunkSize)
            }
            sendSingleChunk(chunk)
            offset += chunkSize
        }
    }

    private suspend fun sendSingleChunk(chunk: ByteArray) {
        val isFirst = !firstFrameSent
        val frame = if (isFirst) {
            firstFrameSent = true
            encodeNewFrameWithData(chunk)
        } else {
            encodeKeepFrame(chunk)
        }
        try {
            client.writeFrame(frame)
        } catch (e: Exception) {
            // Reset firstFrameSent on failure so retry sends New frame.
            if (isFirst) firstFrameSent = false
            throw e
        }
    }

    /**
     * Non-suspending send: the closed check and frame encoding happen on the
     * calling thread (lwipExecutor) to prevent races with closeAll(). Used for
     * buffered payloads during initial connection setup.
     */
    fun sendAsync(data: ByteArray) {
        if (closed) return

        if (data.isEmpty()) {
            sendSingleChunkAsync(data)
            return
        }

        var offset = 0
        while (offset < data.size) {
            if (closed) return
            val chunkSize = minOf(MAX_FRAME_PAYLOAD_SIZE, data.size - offset)
            val chunk = if (offset == 0 && chunkSize == data.size) {
                data
            } else {
                data.copyOfRange(offset, offset + chunkSize)
            }
            sendSingleChunkAsync(chunk)
            offset += chunkSize
        }
    }

    private fun sendSingleChunkAsync(chunk: ByteArray) {
        val frame = if (!firstFrameSent) {
            firstFrameSent = true
            encodeNewFrameWithData(chunk)
        } else {
            encodeKeepFrame(chunk)
        }
        client.writeFrameAsync(frame)
    }

    private fun encodeNewFrameWithData(data: ByteArray): ByteArray {
        val metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.NEW,
            option = MuxOption.DATA,
            network = network,
            targetHost = targetHost,
            targetPort = targetPort,
            globalID = globalID
        )
        return encodeMuxFrame(metadata = metadata, payload = data)
    }

    private fun encodeKeepFrame(data: ByteArray): ByteArray {
        var metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.KEEP,
            option = MuxOption.DATA
        )
        // UDP Keep frames carry the address.
        if (network == MuxNetwork.UDP) {
            metadata = metadata.copy(
                network = network,
                targetHost = targetHost,
                targetPort = targetPort
            )
        }
        return encodeMuxFrame(metadata = metadata, payload = data)
    }

    /** Closes this session by sending an End frame. */
    fun close() {
        if (closed) return
        closed = true

        val metadata = MuxFrameMetadata(
            sessionID = sessionID,
            status = MuxSessionStatus.END,
            option = 0
        )
        val frame = encodeMuxFrame(metadata = metadata, payload = null)
        client.writeFrameAsync(frame)
        client.removeSession(sessionID)

        closeHandler?.invoke()
    }

    fun deliverData(data: ByteArray) {
        if (closed) return
        dataHandler?.invoke(data)
    }

    /**
     * Delivers a server-initiated close to this session. The server already
     * sent the End frame, and `MuxClient.handleReceivedData` removed the
     * session from its map before invoking this — there is no peer to ack to.
     * Mirrors iOS MuxSession.swift:117-121.
     */
    fun deliverClose() {
        if (closed) return
        closed = true
        closeHandler?.invoke()
    }
}
