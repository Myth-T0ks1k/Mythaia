package com.mythaia.vpn.protocol.trojan

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("Trojan")

/**
 * Wraps a TLS-backed transport with the Trojan TCP request header.
 *
 * The header — `hex(sha224(password)) + CRLF + cmd + addr:port + CRLF` — is
 * prepended to the first `sendRaw` payload and travels inside the same TLS
 * record; an empty first payload writes exactly the header, which is how
 * [TrojanClient] flushes it at connect time for flows where the server speaks
 * first. The receive path is a pass-through because Trojan servers reply
 * without any framing of their own.
 */
class TrojanConnection(
    private val tlsConnection: Transport,
    private val tlsVersion: TlsVersion?,
    password: String,
    destinationHost: String,
    destinationPort: Int
) : ProxyConnection() {

    private var pendingHeader: ByteArray? = TrojanProtocol.buildRequestHeader(
        passwordKey = TrojanProtocol.passwordKey(password),
        command = TrojanProtocol.COMMAND_TCP,
        host = destinationHost,
        port = destinationPort
    )
    private val headerLock = Any()

    override val isConnected: Boolean get() = true
    override val outerTlsVersion: TlsVersion?
        get() = tlsVersion

    override suspend fun sendRaw(data: ByteArray) {
        val payload = consumeHeader()?.let { it + data } ?: data
        tlsConnection.send(payload)
    }

    override fun sendRawAsync(data: ByteArray) {
        val payload = consumeHeader()?.let { it + data } ?: data
        try {
            tlsConnection.sendAsync(payload)
        } catch (e: Exception) {
            logger.error("[Trojan] Send error: ${e.message}")
        }
    }

    override suspend fun receiveRaw(): ByteArray? = tlsConnection.receive()

    override fun cancel() = tlsConnection.forceCancel()

    /** Returns the request header on the first call and `null` thereafter. */
    private fun consumeHeader(): ByteArray? = synchronized(headerLock) {
        val header = pendingHeader
        pendingHeader = null
        header
    }
}
