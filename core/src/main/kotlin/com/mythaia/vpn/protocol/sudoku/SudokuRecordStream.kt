package com.mythaia.vpn.protocol.sudoku

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom

/**
 * The record layer, riding the obfuscation shell beneath it.
 *
 * Every write is sealed into one or more records — a length prefix, a header that
 * doubles as the AEAD nonce and its own associated data, and the ciphertext — and
 * every read reverses that. The sealing and opening are pure and live in
 * [SudokuProtocol]; what this class owns is the state those functions cannot hold:
 * the sender's epoch and sequence, which climb across records and rekey on a
 * widening byte schedule, and the receiver's expectation of the next pair, which
 * is what makes a replayed or reordered record detectable.
 *
 * The two directions are locked apart. Sends serialise on [sendMutex] because a
 * record's sequence number must not be handed out twice and frames must not
 * interleave on the wire; the single reader serialises on [recvMutex], which also
 * guards the small buffer of plaintext a record produced beyond what its reader
 * asked for. Neither mutex is re-entrant, so the public [receive] and [readExact]
 * take the lock once and drive a private helper that assumes it is held.
 *
 * The `none` method turns all of this off: there is no record framing, and the
 * obfuscated stream carries the payload directly. It exists for the case where
 * something outside Sudoku already provides secrecy.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuRecordStream(
    private val obfs: SudokuObfsTransport,
    private val method: SudokuAeadMethod,
    baseSend: ByteArray,
    baseRecv: ByteArray
) {

    private val sendMutex = Mutex()
    private var baseSend = baseSend
    private var sendEpoch = randomNonZeroUInt32()
    private var sendSequence = randomNonZeroUInt64()
    private var sendBytes = 0L
    private var sendEpochUpdates = 0

    private val recvMutex = Mutex()
    private var baseRecv = baseRecv
    private var recvEpoch = 0L
    private var recvSequence = 0L
    private var recvInitialized = false

    /** Plaintext a record produced past what its reader wanted, held for next time. */
    private var leftover = EMPTY
    private var leftoverOffset = 0

    /**
     * Seals [data] into records and writes them.
     *
     * Payload larger than one record's plaintext budget is split, because the
     * length prefix is a 16-bit field; each piece advances the sequence and, once
     * enough bytes have gone under one epoch key, rolls the epoch forward.
     */
    suspend fun send(data: ByteArray) {
        if (data.isEmpty()) return
        sendMutex.withLock {
            if (method == SudokuAeadMethod.NONE) {
                obfs.send(data)
                return@withLock
            }
            var offset = 0
            while (offset < data.size) {
                val count = minOf(SudokuProtocol.RECORD_MAX_PLAINTEXT_SIZE, data.size - offset)
                val chunk = data.copyOfRange(offset, offset + count)
                val frame = SudokuProtocol.sealRecord(method, baseSend, sendEpoch, sendSequence, chunk)
                // The sequence has to survive across records, so it is advanced
                // here rather than inside the stateless seal.
                sendSequence += 1
                obfs.send(frame)
                offset += count
                bumpEpochIfDue(count)
            }
        }
    }

    /** Up to [max] decoded plaintext bytes, or null at end of stream. */
    suspend fun receive(max: Int): ByteArray? {
        if (max <= 0) return EMPTY
        return recvMutex.withLock { receiveLocked(max) }
    }

    /**
     * Exactly [count] bytes, or null if the stream ends before the first of them.
     *
     * A stream that ends part way through is a truncation, not a clean close, and
     * throws — the handshake and the UDP framing above both rely on that
     * distinction to tell "nothing more is coming" from "the peer cut a frame in
     * half".
     */
    suspend fun readExact(count: Int): ByteArray? {
        if (count <= 0) return EMPTY
        return recvMutex.withLock {
            val out = ByteArray(count)
            var have = 0
            while (have < count) {
                val chunk = receiveLocked(count - have)
                    ?: return@withLock if (have == 0) null
                    else throw SudokuError.ProtocolViolation("truncated read")
                chunk.copyInto(out, have)
                have += chunk.size
            }
            out
        }
    }

    /**
     * Moves both directions onto fresh base secrets.
     *
     * Called once, when the KIP exchange has produced the session keys. The send
     * counters are re-randomised and the receive side is told to expect a new
     * peer starting point, which is why the first record after a rekey skips the
     * order check.
     */
    suspend fun rekey(send: ByteArray, recv: ByteArray) {
        sendMutex.withLock {
            baseSend = send
            sendEpoch = randomNonZeroUInt32()
            sendSequence = randomNonZeroUInt64()
            sendBytes = 0
            sendEpochUpdates = 0
        }
        recvMutex.withLock {
            baseRecv = recv
            recvEpoch = 0
            recvSequence = 0
            recvInitialized = false
            leftover = EMPTY
            leftoverOffset = 0
        }
    }

    fun close() {
        obfs.close()
    }

    // MARK: - Receiving (caller holds recvMutex)

    private suspend fun receiveLocked(max: Int): ByteArray? {
        takeLeftover(max)?.let { return it }
        if (method == SudokuAeadMethod.NONE) return obfs.receive(max)

        while (true) {
            val lengthPrefix = readExactObfs(SudokuProtocol.RECORD_LENGTH_PREFIX_SIZE) ?: return null
            val bodyLength = SudokuProtocol.parseRecordLength(lengthPrefix)
            val body = readExactObfs(bodyLength)
                ?: throw SudokuError.ProtocolViolation("truncated record body")

            val epoch = SudokuProtocol.recordEpoch(body)
            val sequence = SudokuProtocol.recordSequence(body)
            // The first record of a rekeyed stream carries the peer's random
            // starting point and so cannot be predicted; every later one must
            // follow the last.
            if (recvInitialized) {
                SudokuProtocol.validateRecordOrder(recvEpoch, recvSequence, epoch, sequence)
            }
            val plain = SudokuProtocol.openRecord(method, baseRecv, body)
            recvEpoch = epoch
            recvSequence = sequence + 1
            recvInitialized = true

            if (plain.isEmpty()) continue
            if (plain.size <= max) return plain
            // The record produced more than the reader wanted; hand out the head
            // and keep the tail for the next call rather than dropping it.
            leftover = plain
            leftoverOffset = max
            return plain.copyOf(max)
        }
    }

    private fun takeLeftover(max: Int): ByteArray? {
        val available = leftover.size - leftoverOffset
        if (available <= 0) return null
        val take = minOf(max, available)
        val out = leftover.copyOfRange(leftoverOffset, leftoverOffset + take)
        leftoverOffset += take
        if (leftoverOffset >= leftover.size) {
            leftover = EMPTY
            leftoverOffset = 0
        }
        return out
    }

    /**
     * Exactly [count] bytes of the record-layer stream, or null if it ends before
     * the first of them; a partial frame throws.
     */
    private suspend fun readExactObfs(count: Int): ByteArray? {
        val out = ByteArray(count)
        var have = 0
        while (have < count) {
            val chunk = obfs.receive(count - have)
                ?: return if (have == 0) null
                else throw SudokuError.ProtocolViolation("truncated record frame")
            chunk.copyInto(out, have)
            have += chunk.size
        }
        return out
    }

    // MARK: - Sending (caller holds sendMutex)

    private fun bumpEpochIfDue(added: Int) {
        sendBytes += added
        // The threshold widens with each bump, so a long connection rekeys its
        // epoch less and less often rather than every 32 MiB forever.
        val threshold = SudokuProtocol.RECORD_EPOCH_REKEY_BYTES * (sendEpochUpdates + 1)
        if (sendBytes < threshold) return
        sendEpoch = (sendEpoch + 1) and 0xFFFFFFFFL
        sendEpochUpdates += 1
        sendSequence = randomNonZeroUInt64()
    }

    private companion object {
        val EMPTY = ByteArray(0)

        private val random = SecureRandom()

        /**
         * A starting epoch that is neither zero nor the largest 32-bit value.
         *
         * Both ends of the range are avoided the way the reference avoids them,
         * so the value can climb by one without immediately wrapping and cannot
         * begin at a boundary the order check treats specially.
         */
        fun randomNonZeroUInt32(): Long {
            while (true) {
                val bytes = ByteArray(4).also { random.nextBytes(it) }
                var value = 0L
                for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
                if (value != 0L && value != 0xFFFFFFFFL) return value
            }
        }

        /** A starting sequence that is neither all-zero nor all-ones. */
        fun randomNonZeroUInt64(): Long {
            while (true) {
                val bytes = ByteArray(8).also { random.nextBytes(it) }
                var value = 0L
                for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
                if (value != 0L && value != -1L) return value
            }
        }
    }
}
