package com.mythaia.vpn.protocol.vless

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.grpc.GrpcConnection
import com.mythaia.vpn.protocol.httpupgrade.HttpUpgradeConnection
import com.mythaia.vpn.protocol.tls.TlsRecordConnection
import com.mythaia.vpn.protocol.websocket.WebSocketConnection
import com.mythaia.vpn.protocol.xhttp.XHttpConnection
import com.mythaia.vpn.util.NioSocket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Base for VLESS connections; strips the 2-byte response header
 * (`version` + `addonsLength`) from the first stream bytes. Header bytes are
 * buffered across reads so transports that deliver fragmented headers
 * (WebSocket, XHTTP, HTTP/2) work correctly.
 */
abstract class VlessConnection : ProxyConnection() {

    var responseHeaderReceived = false
    private val responseHeaderLock = Any()
    private var pendingResponseHeaderBuffer: ByteArray = ByteArray(0)

    /**
     * Returns payload with any VLESS response header stripped. If the current
     * read contained only header bytes, recursively reads more rather than
     * returning early (otherwise the caller would see EOF).
     */
    suspend fun processResponseHeader(data: ByteArray): ByteArray? {
        var output: ByteArray? = null
        var shouldReceiveMore = false

        synchronized(responseHeaderLock) {
            if (responseHeaderReceived) {
                output = data
            } else {
                val combined = if (pendingResponseHeaderBuffer.isEmpty()) {
                    data
                } else {
                    pendingResponseHeaderBuffer + data
                }

                when {
                    combined.size < 2 -> {
                        pendingResponseHeaderBuffer = combined
                        shouldReceiveMore = true
                    }
                    combined[0] != VlessProtocol.VERSION -> {
                        // No VLESS response header — deliver all buffered bytes as payload.
                        responseHeaderReceived = true
                        output = combined
                        pendingResponseHeaderBuffer = ByteArray(0)
                    }
                    else -> {
                        val addonsLength = combined[1].toInt() and 0xFF
                        val headerLength = 2 + addonsLength
                        if (combined.size < headerLength) {
                            pendingResponseHeaderBuffer = combined
                            shouldReceiveMore = true
                        } else {
                            responseHeaderReceived = true
                            if (combined.size > headerLength) {
                                output = combined.copyOfRange(headerLength, combined.size)
                            } else {
                                shouldReceiveMore = true
                            }
                            pendingResponseHeaderBuffer = ByteArray(0)
                        }
                    }
                }
            }
        }

        return when {
            output != null -> output
            shouldReceiveMore -> receiveRaw()
            else -> data
        }
    }
}

/**
 * Wraps any [ProxyConnection] with VLESS UDP framing: outgoing payloads get a
 * 2-byte big-endian length prefix; the inbound side reassembles length-prefixed
 * packets from the inner connection. The inner connection handles transport
 * concerns (TLS, HTTP upgrade, gRPC, WebSocket) and response-header stripping.
 */
class VlessUdpConnection(private val inner: ProxyConnection) : ProxyConnection() {

    private val udpState = UdpBufferState()
    private val udpLock = Any()

    override val isConnected: Boolean get() = inner.isConnected
    override val outerTlsVersion: TlsVersion? get() = inner.outerTlsVersion

    override suspend fun send(data: ByteArray) {
        super.send(UdpFraming.frame(data))
    }

    override fun sendAsync(data: ByteArray) {
        super.sendAsync(UdpFraming.frame(data))
    }

    override suspend fun sendRaw(data: ByteArray) = inner.sendRaw(data)
    override fun sendRawAsync(data: ByteArray) = inner.sendRawAsync(data)

    override suspend fun receive(): ByteArray? {
        synchronized(udpLock) {
            UdpFraming.extract(udpState)?.let { return it }
        }
        return receiveMore()
    }

    private suspend fun receiveMore(): ByteArray? {
        while (true) {
            val data = inner.receive() ?: return null
            synchronized(udpLock) {
                udpState.append(data)
                UdpFraming.extract(udpState)?.let { return it }
            }
        }
    }

    override suspend fun receiveRaw(): ByteArray? = inner.receiveRaw()

    override fun cancel() {
        synchronized(udpLock) { udpState.clear() }
        inner.cancel()
    }
}

open class VlessDirectConnection(val connection: Transport) : VlessConnection() {

    override val isConnected: Boolean
        get() = (connection as? NioSocket)?.state == NioSocket.State.READY || connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) {
        connection.send(data)
    }

    override fun sendRawAsync(data: ByteArray) {
        connection.sendAsync(data)
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = connection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() {
        connection.forceCancel()
    }
}

open class VlessHttpUpgradeConnection(
    private val huConnection: HttpUpgradeConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = huConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = huConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = huConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = huConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = huConnection.cancel()
}

open class VlessXHttpConnection(
    private val xhttpConnection: XHttpConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = xhttpConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = xhttpConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = xhttpConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = xhttpConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = xhttpConnection.cancel()
}

open class VlessTlsConnection(
    private val tlsConnection: TlsRecordConnection
) : VlessConnection() {

    override val outerTlsVersion: TlsVersion?
        get() = if (tlsConnection.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12

    override val isConnected: Boolean
        get() = (tlsConnection.connection as? NioSocket)?.state == NioSocket.State.READY
            || tlsConnection.connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = tlsConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = tlsConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = tlsConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = tlsConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = tlsConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = tlsConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = tlsConnection.sendRawAsync(data)
}

open class VlessWebSocketConnection(
    private val wsConnection: WebSocketConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = wsConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) = wsConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = wsConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = wsConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = wsConnection.cancel()
}

open class VlessRealityConnection(
    private val realityConnection: TlsRecordConnection
) : VlessConnection() {

    override val outerTlsVersion: TlsVersion? get() = TlsVersion.TLS13

    override val isConnected: Boolean
        get() = (realityConnection.connection as? NioSocket)?.state == NioSocket.State.READY
            || realityConnection.connection !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = realityConnection.send(data)
    override fun sendRawAsync(data: ByteArray) = realityConnection.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = realityConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = realityConnection.cancel()

    override suspend fun receiveDirectRaw(): ByteArray? = realityConnection.receiveRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = realityConnection.sendRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = realityConnection.sendRawAsync(data)
}

open class VlessGrpcConnection(
    private val grpcConnection: com.mythaia.vpn.protocol.grpc.GrpcTunnel
) : VlessConnection() {

    private val sendMutex = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()
    private val asyncScope by lazy {
        CoroutineScope(Dispatchers.IO + SupervisorJob() + com.mythaia.vpn.tunnelCrashGuard)
    }

    override val isConnected: Boolean get() = grpcConnection.isConnected

    override suspend fun sendRaw(data: ByteArray) {
        sendMutex.withLock {
            drainAsyncQueueLocked()
            try {
                grpcConnection.send(data)
            } finally {
                drainAsyncQueueLocked()
            }
        }
    }

    override fun sendRawAsync(data: ByteArray) {
        synchronized(asyncQueue) {
            asyncQueue.addLast(data)
        }
        asyncScope.launch {
            sendMutex.withLock {
                drainAsyncQueueLocked()
            }
        }
    }

    private suspend fun drainAsyncQueueLocked() {
        while (true) {
            val next = synchronized(asyncQueue) {
                if (asyncQueue.isEmpty()) null else asyncQueue.removeFirst()
            } ?: break
            runCatching { grpcConnection.send(next) }
        }
    }

    override suspend fun receiveRaw(): ByteArray? {
        val data = grpcConnection.receive() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() {
        synchronized(asyncQueue) { asyncQueue.clear() }
        runCatching { asyncScope.cancel() }
        grpcConnection.cancel()
    }
}

/**
 * A header-free [ProxyConnection] view of the raw transport, handed to the VLESS
 * post-quantum encryption handshake.
 *
 * The handshake exchanges its own bytes over this connection — the relay block,
 * the PFS server hello, sealed length frames — none of which is VLESS framing.
 * So unlike every other subclass here it does no response-header stripping: it
 * must pass those bytes through untouched, or the handshake would try to read a
 * VLESS response header where a PFS hello sits and corrupt the exchange. The
 * VLESS request/response framing only appears one layer up, on top of the
 * encrypted connection the handshake returns (see [VlessEncryptionConnection]).
 */
class VlessRawTransportConnection(private val transport: Transport) : ProxyConnection() {

    override val isConnected: Boolean
        get() = (transport as? NioSocket)?.state == NioSocket.State.READY || transport !is NioSocket

    override suspend fun sendRaw(data: ByteArray) = transport.send(data)
    override fun sendRawAsync(data: ByteArray) = transport.sendAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = transport.receive() ?: return null
        if (data.isEmpty()) return null
        return data
    }

    override fun cancel() = transport.forceCancel()
}

/**
 * VLESS carried over the post-quantum encryption layer.
 *
 * [encrypted] is what
 * [com.mythaia.vpn.protocol.vless.encryption.VlessEncryptionClient.handshake]
 * returns: it seals every byte written and opens every byte read, standing in
 * for the outer TLS/Reality a plain VLESS dial would use. So the VLESS request
 * header is the first plaintext written through it, and the 2-byte VLESS
 * response header is stripped from the first decrypted bytes — exactly the
 * contract every other VLESS transport subclass honours; only the sealing
 * underneath is new, and it lives entirely inside [encrypted].
 *
 * [outerTlsVersion] delegates to [encrypted], which reports the raw transport's
 * (null) — deliberately, so Vision is rejected up front: Vision needs outer TLS
 * 1.3, and here the encryption has replaced it.
 */
open class VlessEncryptionConnection(
    private val encrypted: ProxyConnection
) : VlessConnection() {

    override val isConnected: Boolean get() = encrypted.isConnected
    override val outerTlsVersion: TlsVersion? get() = encrypted.outerTlsVersion

    override suspend fun sendRaw(data: ByteArray) = encrypted.sendRaw(data)
    override fun sendRawAsync(data: ByteArray) = encrypted.sendRawAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        val data = encrypted.receiveRaw() ?: return null
        if (data.isEmpty()) return null
        return processResponseHeader(data)
    }

    override fun cancel() = encrypted.cancel()

    // Vision cannot run over this connection (outerTlsVersion is null, so it is
    // rejected before wrapping), but the direct methods still delegate to the
    // encryption's own AEAD-peeling path so the wrapper is a faithful, complete
    // pass-through rather than silently falling back to the base sealed path.
    override suspend fun receiveDirectRaw(): ByteArray? = encrypted.receiveDirectRaw()
    override suspend fun sendDirectRaw(data: ByteArray) = encrypted.sendDirectRaw(data)
    override fun sendDirectRawAsync(data: ByteArray) = encrypted.sendDirectRawAsync(data)
}

sealed class RealityError(message: String) : Exception(message) {
    class DecryptionFailed(val rawData: ByteArray? = null) : RealityError("TLS record decryption failed")
    class HandshakeFailed(msg: String) : RealityError("TLS handshake failed: $msg")
    class InvalidResponse(msg: String) : RealityError("Invalid response: $msg")
    class AuthenticationFailed : RealityError("Reality server authentication failed")
}
