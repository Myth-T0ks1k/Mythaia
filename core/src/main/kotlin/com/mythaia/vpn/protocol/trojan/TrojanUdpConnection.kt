package com.mythaia.vpn.protocol.trojan

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("Trojan-UDP")

/**
 * Wraps a TLS-backed transport as a Trojan UDP-over-TCP session.
 *
 * Each outgoing datagram is framed as `addr:port + length + CRLF + payload`
 * on top of the Trojan UDP request header (sent once). The inbound side
 * buffers stream bytes from TLS and emits one payload per `receiveRaw` call,
 * silently dropping the per-packet header.
 */
class TrojanUdpConnection(
    private val tlsConnection: Transport,
    private val tlsVersion: TlsVersion?,
    password: String,
    private val dstHost: String,
    private val dstPort: Int
) : ProxyConnection() {

    private val passwordKey: ByteArray = TrojanProtocol.passwordKey(password)

    private var headerSent = false
    private var receiveBuffer: ByteArray = ByteArray(0)
    private val lock = Any()

    override val isConnected: Boolean get() = true
    override val outerTlsVersion: TlsVersion?
        get() = tlsVersion

    override suspend fun sendRaw(data: ByteArray) {
        if (tooLarge(data)) return
        tlsConnection.send(frame(data))
    }

    override fun sendRawAsync(data: ByteArray) {
        if (tooLarge(data)) return
        try {
            tlsConnection.sendAsync(frame(data))
        } catch (e: Exception) {
            logger.error("[Trojan-UDP] Send error: ${e.message}")
        }
    }

    /**
     * A datagram the framing cannot carry is dropped here, as the network
     * would drop an oversized packet — not truncated (the receiver would get
     * garbage) and not fatal (one odd packet must not end the association).
     */
    private fun tooLarge(data: ByteArray): Boolean {
        if (data.size <= TrojanProtocol.MAX_UDP_PAYLOAD_LENGTH) return false
        logger.warning(
            "[Trojan-UDP] Dropping ${data.size}-byte datagram to $dstHost:$dstPort; " +
                "the framing carries at most ${TrojanProtocol.MAX_UDP_PAYLOAD_LENGTH}"
        )
        return true
    }

    override suspend fun receiveRaw(): ByteArray? = deliverNextPacket()

    override fun cancel() {
        synchronized(lock) { receiveBuffer = ByteArray(0) }
        tlsConnection.forceCancel()
    }

    /** Prepends the one-shot request header (first call only) to a framed UDP packet. */
    private fun frame(payload: ByteArray): ByteArray {
        val packet = TrojanProtocol.encodeUDPPacket(dstHost, dstPort, payload)
        synchronized(lock) {
            if (!headerSent) {
                headerSent = true
                val header = TrojanProtocol.buildRequestHeader(
                    passwordKey = passwordKey,
                    command = TrojanProtocol.COMMAND_UDP,
                    host = dstHost,
                    port = dstPort
                )
                return header + packet
            }
        }
        return packet
    }

    private suspend fun deliverNextPacket(): ByteArray? {
        while (true) {
            val parsed = synchronized(lock) {
                val res = TrojanProtocol.tryDecodeUDPPacket(receiveBuffer)
                if (res != null) {
                    receiveBuffer = receiveBuffer.copyOfRange(res.consumed, receiveBuffer.size)
                }
                res
            }
            if (parsed != null) return parsed.payload

            val data = tlsConnection.receive() ?: return null
            if (data.isEmpty()) return null
            synchronized(lock) {
                receiveBuffer = if (receiveBuffer.isEmpty()) data else receiveBuffer + data
            }
        }
    }
}
