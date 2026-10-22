package com.mythaia.vpn.protocol.trojan

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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
    private val sendMutex = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()

    override val isConnected: Boolean get() = true
    override val outerTlsVersion: TlsVersion?
        get() = tlsVersion

    override suspend fun sendRaw(data: ByteArray) {
        sendMutex.withLock {
            drainAsyncQueueLocked()
            val payload = consumeHeader()?.let { it + data } ?: data
            try {
                tlsConnection.send(payload)
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
            val payload = consumeHeader()?.let { it + next } ?: next
            try {
                tlsConnection.sendAsync(payload)
            } catch (e: Exception) {
                logger.error("[Trojan] Send error: ${e.message}")
            }
        }
    }

    private fun flushAsyncIfUnlocked() {
        while (synchronized(asyncQueue) { asyncQueue.isNotEmpty() }) {
            if (!sendMutex.tryLock()) return
            try {
                drainAsyncQueueLocked()
            } finally {
                sendMutex.unlock()
            }
        }
    }

    override suspend fun receiveRaw(): ByteArray? = tlsConnection.receive()

    override fun cancel() {
        synchronized(asyncQueue) { asyncQueue.clear() }
        tlsConnection.forceCancel()
    }

    /** Returns the request header on the first call and `null` thereafter. */
    private fun consumeHeader(): ByteArray? = synchronized(headerLock) {
        val header = pendingHeader
        pendingHeader = null
        header
    }
}
