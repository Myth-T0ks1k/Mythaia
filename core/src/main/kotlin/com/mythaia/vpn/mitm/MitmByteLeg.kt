package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.ProxyConnectionProtocol
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.tls.TlsRecordConnection

/**
 * One end of a duplex byte stream the HTTP/1.1 bridge reads a message off and
 * writes a message onto, with nothing above raw bytes.
 *
 * The bridge is written against this interface, not against a TLS connection or
 * a tunnel, so the message codec can be driven by an in-memory double in a unit
 * test and by a real socket in production through the same calls. [receive]
 * yields the next chunk of decrypted application bytes (whatever size the
 * transport happened to hand up), or `null` once the peer has closed — that
 * `null` is the end-of-body signal for a connection-delimited response.
 *
 * [prependToReceiveBuffer] exists because a reader that scans for the end of a
 * message head almost always overreads into the body (or into a pipelined next
 * message): the surplus is handed back here so the following [receive] returns
 * it before touching the transport again, rather than being lost.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
interface MitmByteLeg {

    /**
     * The ALPN protocol the transport negotiated (`"h2"`, `"http/1.1"`, …), or
     * `null` when none was negotiated or the leg is cleartext. The bridge reads
     * it once to decide whether to speak HTTP/1.1 or HTTP/2 over this leg.
     */
    val negotiatedAlpn: String?

    /** The next chunk of bytes, or `null` at end of stream (peer closed). */
    suspend fun receive(): ByteArray?

    /** Writes [data] to the peer. */
    suspend fun send(data: ByteArray)

    /**
     * Pushes [data] back so the next [receive] returns it first. Used for the
     * bytes a head scan overread past the blank line. A no-op for empty input.
     */
    fun prependToReceiveBuffer(data: ByteArray)

    /** Closes the leg; further receives report end of stream. */
    fun close()
}

/**
 * A [MitmByteLeg] over the app's [TlsRecordConnection] — the TLS-terminated leg,
 * either the server side facing the client or the client side facing upstream.
 *
 * Every call forwards straight through: [TlsRecordConnection] already buffers,
 * prepends, and exposes the negotiated ALPN, so the adapter adds nothing but the
 * name change.
 */
class TlsRecordByteLeg(private val connection: TlsRecordConnection) : MitmByteLeg {

    override val negotiatedAlpn: String?
        get() = connection.negotiatedAlpn

    override suspend fun receive(): ByteArray? = connection.receive()

    override suspend fun send(data: ByteArray) = connection.send(data)

    override fun prependToReceiveBuffer(data: ByteArray) =
        connection.prependToReceiveBuffer(data)

    override fun close() = connection.cancel()
}

/**
 * A [MitmByteLeg] over a cleartext byte source — a plain [Transport] or a
 * [ProxyConnectionProtocol] reached through the tunnel — for intercepting
 * unencrypted HTTP.
 *
 * A cleartext leg negotiates no ALPN, so [negotiatedAlpn] is always `null` and
 * the bridge speaks HTTP/1.1. Unlike the TLS leg there is no underlying buffer
 * that can take bytes back, so this adapter keeps its own small prepend buffer
 * and drains it ahead of the transport, mirroring the reference's `PlaintextLeg`.
 *
 * Use [forTransport] or [forProxy] to build one; the raw send/receive/close
 * hooks are captured so a single tiny implementation serves both sources.
 */
class PlaintextByteLeg private constructor(
    private val doReceive: suspend () -> ByteArray?,
    private val doSend: suspend (ByteArray) -> Unit,
    private val doClose: () -> Unit
) : MitmByteLeg {

    override val negotiatedAlpn: String? = null

    private val lock = Any()
    private var prepended: ByteArray = ByteArray(0)

    override fun prependToReceiveBuffer(data: ByteArray) {
        if (data.isEmpty()) return
        synchronized(lock) {
            prepended = if (prepended.isEmpty()) data.copyOf() else prepended + data
        }
    }

    override suspend fun receive(): ByteArray? {
        synchronized(lock) {
            if (prepended.isNotEmpty()) {
                val buffered = prepended
                prepended = ByteArray(0)
                return buffered
            }
        }
        return doReceive()
    }

    override suspend fun send(data: ByteArray) = doSend(data)

    override fun close() {
        synchronized(lock) { prepended = ByteArray(0) }
        doClose()
    }

    companion object {
        /** Wraps a raw [Transport] (its `forceCancel` closes the leg). */
        fun forTransport(transport: Transport): PlaintextByteLeg =
            PlaintextByteLeg(
                doReceive = { transport.receive() },
                doSend = { transport.send(it) },
                doClose = { transport.forceCancel() }
            )

        /** Wraps a tunneled [ProxyConnectionProtocol] (its `cancel` closes the leg). */
        fun forProxy(connection: ProxyConnectionProtocol): PlaintextByteLeg =
            PlaintextByteLeg(
                doReceive = { connection.receive() },
                doSend = { connection.send(it) },
                doClose = { connection.cancel() }
            )
    }
}
