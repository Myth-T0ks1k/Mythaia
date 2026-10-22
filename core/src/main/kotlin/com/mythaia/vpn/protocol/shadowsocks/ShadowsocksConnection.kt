package com.mythaia.vpn.protocol.shadowsocks

import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val logger = MythaiaLogger("Shadowsocks")

/**
 * Shadowsocks TCP connection wrapping a transport with AEAD encryption. The address
 * header is prepended to the first send (encrypted as part of the stream); an
 * empty first send therefore emits a chunk holding just the header, which is how
 * [ShadowsocksClient] flushes it at connect time. Shadowsocks has no response header.
 */
class ShadowsocksConnection(
    private val transport: Transport,
    cipher: ShadowsocksCipher,
    masterKey: ByteArray,
    private var addressHeader: ByteArray?
) : ProxyConnection() {

    private val writer = ShadowsocksAEADWriter(cipher, masterKey)
    private val reader = ShadowsocksAEADReader(cipher, masterKey)
    private val headerLock = Any()
    private val sendMutex = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()

    override val isConnected: Boolean get() = true

    override suspend fun sendRaw(data: ByteArray) {
        sendMutex.withLock {
            drainAsyncQueueLocked()
            val plaintext = consumeHeaderAndBuild(data)
            val encrypted = writer.seal(plaintext)
            try {
                transport.send(encrypted)
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

    private fun consumeHeaderAndBuild(data: ByteArray): ByteArray = synchronized(headerLock) {
        val header = addressHeader
        if (header != null) {
            addressHeader = null
            header + data
        } else {
            data
        }
    }

    private fun drainAsyncQueueLocked() {
        while (true) {
            val next = synchronized(asyncQueue) {
                if (asyncQueue.isEmpty()) null else asyncQueue.removeFirst()
            } ?: break
            try {
                val plaintext = consumeHeaderAndBuild(next)
                val encrypted = writer.seal(plaintext)
                transport.sendAsync(encrypted)
            } catch (e: Exception) {
                logger.error("[SS] Send error: ${e.message}")
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

    override suspend fun receiveRaw(): ByteArray? {
        while (true) {
            val data = transport.receive() ?: return null
            if (data.isEmpty()) return null
            val plaintext = reader.open(data)
            if (plaintext.isNotEmpty()) return plaintext
            // Empty plaintext means the AEAD reader needs more bytes — loop.
        }
    }

    override fun cancel() {
        synchronized(asyncQueue) { asyncQueue.clear() }
        transport.forceCancel()
    }
}
