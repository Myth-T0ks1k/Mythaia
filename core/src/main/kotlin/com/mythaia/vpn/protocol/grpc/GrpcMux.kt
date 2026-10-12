package com.mythaia.vpn.protocol.grpc

import com.mythaia.vpn.protocol.naive.http2.HpackEncoder
import com.mythaia.vpn.protocol.naive.http2.Http2StreamPool
import com.mythaia.vpn.protocol.naive.http2.Http2Stream
import com.mythaia.vpn.protocol.naive.http2.Http2Wire
import java.io.ByteArrayOutputStream

/** What both gRPC transports give the protocol above them: one byte stream per tunnel. */
interface GrpcTunnel {
    val isConnected: Boolean
    suspend fun send(data: ByteArray)

    /** The next payload; null at the end of the stream. */
    suspend fun receive(): ByteArray?
    fun cancel()
}

/**
 * gRPC tunnels as streams of the pooled HTTP/2 connections in
 * [Http2StreamPool], as Xray's client (grpc-go) runs them: the first tunnel to
 * a server dials it, every later one opens a stream on that connection.
 */
object GrpcMux {

    /**
     * A tunnel to the server [key] identifies (everything that shapes the
     * connection: address, port, TLS or Reality settings); [dial] opens a new
     * connection (TLS or Reality, ALPN h2) when the pool has none with room.
     */
    suspend fun open(
        key: String,
        grpc: GrpcConfiguration,
        authority: String,
        secure: Boolean,
        dial: suspend () -> Http2Wire
    ): GrpcTunnel {
        val headers = GrpcCodec.requestHeaders(grpc, authority, secure)
        val stream = Http2StreamPool.reserve("grpc|$key", grpc.resolvedPath(), dial)
        try {
            stream.openRequest(headers, endStream = false, awaitResponse = false)
        } catch (e: Exception) {
            stream.close()
            throw e
        }
        return GrpcMuxStream(stream)
    }
}

/** One gRPC tunnel as a stream of a pooled HTTP/2 connection; see [GrpcMux]. */
internal class GrpcMuxStream(private val stream: Http2Stream) : GrpcTunnel {

    private val messages = GrpcCodec.MessageReader()

    override val isConnected: Boolean get() = stream.isConnected

    override suspend fun send(data: ByteArray) {
        stream.sendData(GrpcCodec.wrapMessage(GrpcCodec.encodeHunk(data)))
    }

    override suspend fun receive(): ByteArray? {
        while (true) {
            messages.next()?.let { payload ->
                // An empty Hunk carries nothing; above us an empty read means the end.
                if (payload.isNotEmpty()) return payload
                continue
            }
            val chunk = stream.receiveData()
            if (chunk == null) {
                GrpcCodec.failureIn(stream.trailers)?.let { throw it }
                return null
            }
            messages.add(chunk)
        }
    }

    override fun cancel() = stream.close()
}

/** The gRPC framing both transports share: request headers, `Hunk` messages and their 5-byte prefix. */
internal object GrpcCodec {

    private val DEFAULT_USER_AGENT: String
        get() = com.mythaia.vpn.protocol.ProxyUserAgent.chrome

    /** The same headers [GrpcConnection] sends, as an HPACK block. */
    fun requestHeaders(grpc: GrpcConfiguration, authority: String, secure: Boolean): ByteArray =
        HpackEncoder.encodeHeaderBlock(
            listOf(
                ":authority" to authority,
                ":method" to "POST",
                ":path" to grpc.resolvedPath(),
                ":scheme" to if (secure) "https" else "http",
                "content-type" to "application/grpc",
                "te" to "trailers",
                "grpc-encoding" to "identity",
                "grpc-accept-encoding" to "identity",
                "user-agent" to grpc.userAgent.ifEmpty { DEFAULT_USER_AGENT }
            )
        )

    /** `Hunk { bytes data = 1; }`: tag 0x0A, a varint length, the bytes. */
    fun encodeHunk(data: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(data.size + 6)
        out.write(0x0A)
        var v = data.size.toLong()
        while (v >= 0x80L) {
            out.write(((v and 0x7FL) or 0x80L).toInt())
            v = v ushr 7
        }
        out.write(v.toInt())
        out.write(data)
        return out.toByteArray()
    }

    /** The 5-byte gRPC prefix: not compressed, then the length. */
    fun wrapMessage(message: ByteArray): ByteArray {
        val out = ByteArray(5 + message.size)
        val len = message.size
        out[1] = (len ushr 24).toByte()
        out[2] = (len ushr 16).toByte()
        out[3] = (len ushr 8).toByte()
        out[4] = len.toByte()
        System.arraycopy(message, 0, out, 5, len)
        return out
    }

    /** grpc-status other than 0 in the trailers, as an error; null when the call ended well. */
    fun failureIn(trailers: List<Pair<String, String>>?): GrpcError? {
        val status = trailers?.firstOrNull { it.first == "grpc-status" }?.second?.toIntOrNull() ?: return null
        if (status == 0) return null
        val message = trailers.firstOrNull { it.first == "grpc-message" }?.second
        return GrpcError.CallFailed(status, "status $status", message)
    }

    /** Reassembles gRPC messages from DATA payloads and decodes their `Hunk`s. */
    class MessageReader {
        private var buffer = ByteArray(0)
        private var length = 0

        fun add(chunk: ByteArray) {
            if (length + chunk.size > buffer.size) {
                buffer = buffer.copyOf(maxOf(buffer.size * 2, length + chunk.size, 4096))
            }
            System.arraycopy(chunk, 0, buffer, length, chunk.size)
            length += chunk.size
        }

        /** The next whole message's payload, or null until more bytes arrive. */
        fun next(): ByteArray? {
            if (length < 5) return null
            if (buffer[0].toInt() != 0) throw GrpcError.CompressedMessageUnsupported()
            val size = ((buffer[1].toInt() and 0xFF) shl 24) or ((buffer[2].toInt() and 0xFF) shl 16) or
                ((buffer[3].toInt() and 0xFF) shl 8) or (buffer[4].toInt() and 0xFF)
            if (size < 0 || size > MAX_MESSAGE) throw GrpcError.InvalidResponse("message of $size bytes")
            if (length < 5 + size) return null
            val message = buffer.copyOfRange(5, 5 + size)
            System.arraycopy(buffer, 5 + size, buffer, 0, length - 5 - size)
            length -= 5 + size
            return decodeHunks(message)
        }

        private companion object {
            const val MAX_MESSAGE = 16 * 1024 * 1024
        }
    }

    /** Field 1 of a `Hunk` or `MultiHunk`, concatenated; other fields skipped. */
    fun decodeHunks(message: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(message.size)
        var offset = 0
        fun varint(): Long {
            var value = 0L
            var shift = 0
            while (true) {
                if (offset >= message.size) throw GrpcError.InvalidResponse("truncated varint")
                val b = message[offset++].toInt() and 0xFF
                value = value or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) return value
                shift += 7
                if (shift >= 64) throw GrpcError.InvalidResponse("varint too long")
            }
        }
        while (offset < message.size) {
            val tag = varint()
            when ((tag and 0x07L).toInt()) {
                2 -> {
                    val len = varint().toInt()
                    if (len < 0 || offset + len > message.size) throw GrpcError.InvalidResponse("truncated field")
                    if ((tag ushr 3) == 1L) out.write(message, offset, len)
                    offset += len
                }
                0 -> varint()
                5 -> offset += 4
                1 -> offset += 8
                else -> throw GrpcError.InvalidResponse("unknown wire type")
            }
        }
        return out.toByteArray()
    }
}
