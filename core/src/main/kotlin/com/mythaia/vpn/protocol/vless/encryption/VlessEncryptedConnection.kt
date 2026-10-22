package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.protocol.ProxyConnection
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The live connection the handshake hands back: application bytes travel as
 * AEAD-sealed records dressed like TLS 1.3 `application_data`, and arrive
 * decrypted.
 *
 * A write is split into ≤8 KiB chunks, each sealed with the five-byte header as
 * associated data so the header cannot be rewritten without breaking the tag,
 * and each record advances the write nonce. A read is the reverse, gated by two
 * one-time steps that only matter at the start: in 0-RTT the read key is unknown
 * until the server's 16-byte random arrives, so it is derived on the first read;
 * and a 1-RTT server sends a run of handshake-tail padding that is drained and
 * discarded before any application record.
 *
 * The 0-RTT gamble is settled on the first record. A server that rejects the
 * replayed ticket answers with noise, which fails to decode as a record header;
 * seen on the first record and only there, that invalidates exactly the ticket
 * that was tried (not a fresher one a concurrent handshake may have stored) and
 * asks the caller to dial again 1-RTT.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class VlessEncryptedConnection(
    private val inner: ProxyConnection,
    writeAead: VlessRecordAead,
    readAead: VlessRecordAead?,
    private val unitedKey: ByteArray,
    preludeBytes: ByteArray?,
    pendingServerPaddingLength: Int,
    carryOverBytes: ByteArray,
    private val xorConnection: VlessXorConnection?,
    private val zeroRttState: ZeroRttState?,
    private val cache: VlessEncryption0RttCache = VlessEncryption0RttCache.shared
) : ProxyConnection() {

    /**
     * The snapshot behind a 0-RTT attempt, so a first-record decode failure
     * invalidates the exact ticket that was tried.
     */
    class ZeroRttState(
        val unitedKey: ByteArray,
        val pfsKey: ByteArray,
        val cacheKey: String
    )

    // Send state, guarded by [sendMutex]: building frames advances the write
    // nonce, so it and the inner write happen under one lock to keep records in
    // nonce order on the wire.
    private var writeAead: VlessRecordAead = writeAead
    private var preludeBytes: ByteArray? = preludeBytes
    private val sendMutex = Mutex()
    private val asyncQueue = java.util.ArrayDeque<ByteArray>()

    // Receive state, guarded by [recvMutex]. Receive is single-consumer, so the
    // whole read runs under the lock rather than in short critical sections.
    private var readAead: VlessRecordAead? = readAead
    private var inboundBuffer: ByteArray = carryOverBytes
    private var pendingServerPaddingLength: Int = pendingServerPaddingLength
    private var firstRecordSeen = false
    private val recvMutex = Mutex()

    override val isConnected: Boolean get() = inner.isConnected
    override val outerTlsVersion: TlsVersion? get() = inner.outerTlsVersion

    // MARK: - Send

    override suspend fun sendRaw(data: ByteArray) {
        if (data.isEmpty()) return
        sendMutex.withLock {
            drainAsyncQueueLocked()
            val frames = buildOutboundFrames(data)
            try {
                inner.sendRaw(frames)
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
                val frames = buildOutboundFrames(next)
                inner.sendRawAsync(frames)
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

    /** Assumes [sendMutex] held. */
    private fun buildOutboundFrames(plaintext: ByteArray): ByteArray {
        val prelude = preludeBytes
        preludeBytes = null
        val chunks = (plaintext.size + VlessWire.MAX_CHUNK_PLAINTEXT - 1) / VlessWire.MAX_CHUNK_PLAINTEXT
        val out = ByteArrayOutputStream(
            (prelude?.size ?: 0) + plaintext.size + chunks * (VlessWire.HEADER_LENGTH + VlessWire.AEAD_TAG_LENGTH)
        )
        if (prelude != null) {
            out.write(prelude)
        }
        var offset = 0
        while (offset < plaintext.size) {
            val chunkSize = minOf(plaintext.size - offset, VlessWire.MAX_CHUNK_PLAINTEXT)
            val chunk = plaintext.copyOfRange(offset, offset + chunkSize)
            // The header encodes chunk + tag and is this record's associated data.
            val header = VlessRecordHeader.encode(chunkSize + VlessWire.AEAD_TAG_LENGTH)
            val willRekey = writeAead.nonceIsAtMax
            val sealed = writeAead.seal(chunk, header)
            out.write(header)
            out.write(sealed)
            if (willRekey) {
                writeAead = VlessRecordAead(header + sealed, unitedKey)
            }
            offset += chunkSize
        }
        return out.toByteArray()
    }

    // MARK: - Receive

    override suspend fun receiveRaw(): ByteArray? = recvMutex.withLock {
        // 0-RTT: the read key is unknown until the server random arrives.
        if (readAead == null) establishReadAead()
        drainServerPadding()
        readOneRecord()
    }

    /** Reads the 16-byte server random, derives the read key, arms the inbound mask. */
    private suspend fun establishReadAead() {
        val needed = VlessWire.IV_LENGTH
        while (inboundBuffer.size < needed) {
            val data = inner.receiveRaw()
            if (data == null || data.isEmpty()) throw VlessEncryptionError.ConnectionClosed()
            inboundBuffer += data
        }
        val serverRandom = inboundBuffer.copyOfRange(0, needed)
        inboundBuffer = inboundBuffer.copyOfRange(needed, inboundBuffer.size)
        readAead = VlessRecordAead(serverRandom, unitedKey)
        xorConnection?.installInboundCTR(unitedKey, serverRandom)
    }

    /** Drains the one-shot 1-RTT handshake-tail padding before any application record. */
    private suspend fun drainServerPadding() {
        if (pendingServerPaddingLength <= 0) return
        val needed = pendingServerPaddingLength
        while (inboundBuffer.size < needed) {
            val data = inner.receiveRaw()
            // EOF mid-padding surfaces as a clean close on the next record read.
            if (data == null || data.isEmpty()) return
            inboundBuffer += data
        }
        val sealedPadding = inboundBuffer.copyOfRange(0, needed)
        inboundBuffer = inboundBuffer.copyOfRange(needed, inboundBuffer.size)
        readAead!!.open(sealedPadding, null)
        pendingServerPaddingLength = 0
    }

    /** Reads and decrypts one record; null is a clean close. */
    private suspend fun readOneRecord(): ByteArray? {
        while (true) {
            if (inboundBuffer.size >= VlessWire.HEADER_LENGTH) {
                val header = inboundBuffer.copyOfRange(0, VlessWire.HEADER_LENGTH)
                val payloadLength = try {
                    VlessRecordHeader.decode(header)
                } catch (e: VlessEncryptionError.ProtocolViolation) {
                    // A 0-RTT rejection is noise where a record header belongs:
                    // seen on the first record, and only there, it invalidates
                    // the tried ticket and asks for a fresh handshake.
                    if (!firstRecordSeen && zeroRttState != null) {
                        cache.invalidate(zeroRttState.cacheKey, zeroRttState.pfsKey)
                        throw VlessEncryptionError.HandshakeFailed("new handshake needed")
                    }
                    throw e
                }
                val recordTotal = VlessWire.HEADER_LENGTH + payloadLength
                if (inboundBuffer.size >= recordTotal) {
                    val sealedPayload = inboundBuffer.copyOfRange(VlessWire.HEADER_LENGTH, recordTotal)
                    inboundBuffer = inboundBuffer.copyOfRange(recordTotal, inboundBuffer.size)
                    val aead = readAead!!
                    val willRekey = aead.nonceIsAtMax
                    // Header bytes are this record's associated data.
                    val plaintext = aead.open(sealedPayload, header)
                    firstRecordSeen = true
                    if (willRekey) {
                        readAead = VlessRecordAead(header + sealedPayload, unitedKey)
                    }
                    return plaintext
                }
            }
            val data = inner.receiveRaw()
            if (data == null || data.isEmpty()) return null
            inboundBuffer += data
        }
    }

    // MARK: - Vision direct copy (bypass the AEAD layer)

    // Peels only this layer, delegating to inner so any random-mode XOR masking
    // and the outer transport stay intact.

    override suspend fun sendDirectRaw(data: ByteArray) = inner.sendRaw(data)

    override fun sendDirectRawAsync(data: ByteArray) = inner.sendRawAsync(data)

    override suspend fun receiveDirectRaw(): ByteArray? {
        // Flush bytes over-read past the last record; inner would not replay them.
        val leftover = recvMutex.withLock {
            if (inboundBuffer.isNotEmpty()) {
                val l = inboundBuffer
                inboundBuffer = ByteArray(0)
                l
            } else {
                null
            }
        }
        return leftover ?: inner.receiveRaw()
    }

    override fun cancel() {
        synchronized(asyncQueue) { asyncQueue.clear() }
        inner.cancel()
    }
}
