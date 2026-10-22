package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The `random` obfuscation leg: it CTR-masks only the five-byte record headers
 * in each direction, leaving the AEAD-sealed payloads alone.
 *
 * The payloads already look like noise, so nothing is gained by masking them;
 * what a passive observer could otherwise pick out is the regular `0x17 0x0303
 * <len>` header cadence that gives the TLS-record disguise away. Masking just
 * the headers erases that cadence at almost no cost. The masker walks each write
 * as a state machine: skip a stretch (an unmasked prelude, or a payload whose
 * length a previous header announced), then XOR the next five header bytes and
 * read the length they carry to size the next skip.
 *
 * The inbound CTR is not known until the server's random arrives, so bytes that
 * need masking before then are stashed and masked once [installInboundCTR] runs
 * — the server random itself is skipped, not masked, so it reaches the record
 * layer that needs it.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class VlessXorConnection(
    private val inner: ProxyConnection,
    outCtr: VlessEncryptionCtr,
    inCtr: VlessEncryptionCtr?,
    outSkip: Int,
    inSkip: Int
) : ProxyConnection() {

    // Outbound masking state, mutated only inside [sendRaw] / [sendRawAsync] under [sendMutex].
    private var outCtr: VlessEncryptionCtr = outCtr
    private var outSkip: Int = outSkip
    private var outHeader = ByteArray(0)

    private val recvLock = Any()
    private var inCtr: VlessEncryptionCtr? = inCtr
    private var inSkip: Int = inSkip
    private var inHeader = ByteArray(0)
    private var pendingPostSkip = ByteArray(0)

    /**
     * Serialises writes. The mask advances a keystream that runs across records,
     * so masking and the inner write must happen together — masking under one
     * lock and sending under another could let a later record reach the wire
     * before an earlier one and desynchronise the server's unmask.
     */
    private val sendMutex = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()

    override val isConnected: Boolean get() = inner.isConnected
    override val outerTlsVersion: TlsVersion? get() = inner.outerTlsVersion

    /** Installs the inbound CTR once the server random is known (0-RTT path). */
    fun installInboundCTR(key: ByteArray, iv: ByteArray) {
        synchronized(recvLock) { inCtr = VlessEncryptionCtr(key, iv) }
    }

    // MARK: - Send

    override suspend fun sendRaw(data: ByteArray) {
        if (data.isEmpty()) return
        sendMutex.withLock {
            drainAsyncQueueLocked()
            val bytes = data.copyOf()
            applyOutboundMask(bytes)
            try {
                inner.sendRaw(bytes)
            } finally {
                drainAsyncQueueLocked()
            }
        }
        flushAsyncIfUnlocked()
    }

    override fun sendRawAsync(data: ByteArray) {
        if (data.isEmpty()) return
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
            runCatching {
                val bytes = next.copyOf()
                applyOutboundMask(bytes)
                inner.sendRawAsync(bytes)
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

    private fun applyOutboundMask(bytes: ByteArray) {
        var offset = 0
        while (offset < bytes.size) {
            if (outSkip > 0) {
                val consume = minOf(outSkip, bytes.size - offset)
                outSkip -= consume
                offset += consume
                continue
            }
            val needed = VlessWire.HEADER_LENGTH - outHeader.size
            val chunk = minOf(needed, bytes.size - offset)
            // Capture the plaintext header before masking it, so its length is
            // read from the real bytes, not the XOR'd ones.
            outHeader += bytes.copyOfRange(offset, offset + chunk)
            outCtr.processInPlace(bytes, offset, offset + chunk)
            offset += chunk
            if (outHeader.size == VlessWire.HEADER_LENGTH) {
                outSkip = decodeHeaderLength(outHeader)
                outHeader = ByteArray(0)
            } else {
                break
            }
        }
    }

    // MARK: - Receive

    override suspend fun receiveRaw(): ByteArray? {
        val stashed = synchronized(recvLock) {
            if (pendingPostSkip.isNotEmpty() && inCtr != null) {
                val data = pendingPostSkip
                pendingPostSkip = ByteArray(0)
                applyInboundMask(data)
            } else {
                null
            }
        }
        if (stashed != null) return stashed

        val received = inner.receiveRaw()
        if (received == null || received.isEmpty()) return received
        return synchronized(recvLock) { applyInboundMask(received) }
    }

    private fun applyInboundMask(data: ByteArray): ByteArray {
        if (data.isEmpty()) return data
        var bytes = data.copyOf()
        var offset = 0
        while (offset < bytes.size) {
            if (inSkip > 0) {
                val consume = minOf(inSkip, bytes.size - offset)
                inSkip -= consume
                offset += consume
                continue
            }
            val ctr = inCtr
            if (ctr == null) {
                // No inbound CTR yet: hold the rest until one is installed, and
                // hand back only what came before it (the unmasked prefix).
                pendingPostSkip += bytes.copyOfRange(offset, bytes.size)
                bytes = bytes.copyOfRange(0, offset)
                break
            }
            val needed = VlessWire.HEADER_LENGTH - inHeader.size
            val chunk = minOf(needed, bytes.size - offset)
            // Unmask the header first, then read its plaintext length.
            ctr.processInPlace(bytes, offset, offset + chunk)
            inHeader += bytes.copyOfRange(offset, offset + chunk)
            offset += chunk
            if (inHeader.size == VlessWire.HEADER_LENGTH) {
                inSkip = decodeHeaderLength(inHeader)
                inHeader = ByteArray(0)
            } else {
                break
            }
        }
        return bytes
    }

    override fun cancel() {
        synchronized(asyncQueue) { asyncQueue.clear() }
        inner.cancel()
    }

    /**
     * The payload length carried in bytes 3-4 of a TLS `application_data`
     * header. Returns 0 on a prefix or length mismatch, which re-enters header
     * mode rather than skipping a bogus span, so a corrupted stream resynchs.
     */
    private fun decodeHeaderLength(header: ByteArray): Int {
        if (header[0] != VlessWire.RECORD_TYPE ||
            header[1] != VlessWire.VERSION_MAJOR ||
            header[2] != VlessWire.VERSION_MINOR
        ) {
            return 0
        }
        val length = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        if (length < VlessWire.MIN_RECORD_PAYLOAD || length > VlessWire.MAX_RECORD_PAYLOAD) return 0
        return length
    }
}
