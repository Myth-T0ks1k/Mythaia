package com.mythaia.vpn.protocol.anytls

import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.atomic.AtomicBoolean

private val logger = MythaiaLogger("AnyTLS")

/**
 * UDP over an AnyTLS stream, in sing-box's udp-over-tcp v2 framing.
 *
 * AnyTLS has no datagram mode of its own. Instead a stream is opened to the
 * reserved name `sp.v2.udp-over-tcp.arpa`, which the server recognises and
 * treats as a UDP association rather than a TCP connect.
 *
 * The framing has two forms and this uses the connected one: a single request
 * naming the destination, after which every datagram is just a length and its
 * bytes. The unconnected form repeats an address on each packet — and note it
 * numbers address families differently there (0x00/0x01/0x02) from the request
 * (0x01/0x03/0x04, as SOCKS5 does). Only the request form is used here, so the
 * SOCKS5 numbering is the only one on the wire.
 */
class AnyTlsUdpConnection(
    private val stream: AnyTlsStream,
    private val destinationHost: String,
    private val destinationPort: Int
) : ProxyConnection() {

    private val requestSent = AtomicBoolean(false)
    private var buffer = ByteArray(0)

    override val isConnected: Boolean get() = stream.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        val prefix = if (requestSent.compareAndSet(false, true)) request() else ByteArray(0)
        stream.send(prefix + length(data.size) + data)
    }

    override fun sendRawAsync(data: ByteArray) {
        val prefix = if (requestSent.compareAndSet(false, true)) request() else ByteArray(0)
        stream.sendAsync(prefix + length(data.size) + data)
    }

    /**
     * One datagram.
     *
     * A stream read has nothing to do with datagram boundaries, so this keeps
     * what it has and only returns once a whole length-prefixed packet is in
     * hand.
     */
    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            if (buffer.size >= 2) {
                val size = ((buffer[0].toInt() and 0xFF) shl 8) or (buffer[1].toInt() and 0xFF)
                if (buffer.size >= 2 + size) {
                    val packet = buffer.copyOfRange(2, 2 + size)
                    buffer = buffer.copyOfRange(2 + size, buffer.size)
                    return packet
                }
            }
            val chunk = stream.receive() ?: return null
            if (chunk.isEmpty()) continue
            buffer += chunk
        }
    }

    override suspend fun startReceiving(
        handler: suspend (ByteArray) -> Unit,
        errorHandler: suspend (Exception?) -> Unit
    ) {
        try {
            while (isConnected) {
                val packet = receive() ?: break
                handler(packet)
            }
            errorHandler(null)
        } catch (e: Exception) {
            logger.debug("[AnyTLS-UDP] Receive ended: ${e.message}")
            errorHandler(e)
        }
    }

    override fun cancel() = stream.cancel()

    /** `isConnect = 1`, then the destination in SOCKS5 address form. */
    private fun request(): ByteArray =
        byteArrayOf(1) + AnyTlsProtocol.encodeAddress(destinationHost, destinationPort)

    private fun length(size: Int): ByteArray =
        byteArrayOf((size ushr 8).toByte(), size.toByte())
}
