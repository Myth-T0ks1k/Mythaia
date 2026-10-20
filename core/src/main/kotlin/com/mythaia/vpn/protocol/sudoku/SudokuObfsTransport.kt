package com.mythaia.vpn.protocol.sudoku

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The obfuscation shell: a byte stream in and out, with every write turned into
 * Sudoku puzzles on the way to the wire and every read turned back on the way in.
 *
 * This is where the disguise lives. A plaintext write becomes puzzles plus
 * padding through the uplink codebook and a chosen padding rate; a wire read is
 * fed to the downlink decoder, which drops padding, reassembles four-hint puzzles
 * into bytes, and holds whatever will not fit the caller's limit for next time.
 * The codec itself is pure and lives in [SudokuProtocol]; this class only owns the
 * one generator that drives the sender and the one decoder that drives the
 * receiver, and pumps bytes between them and the raw [Transport] underneath.
 *
 * The generator is stateful and must advance in a single sequence, so every send
 * holds [sendMutex] across the encode. Receiving is single-consumer by
 * construction — the record layer above reads on one coroutine — so the decoder
 * needs no lock of its own.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuObfsTransport(
    private val transport: Transport,
    private val uplink: SudokuTable,
    downlink: SudokuTable,
    private val pureDownlink: Boolean,
    private val rng: SudokuXorshift64Star,
    private val threshold: Long
) {

    private val sendMutex = Mutex()

    /**
     * The downlink decoder, chosen once.
     *
     * The two forms are not interchangeable — a pure stream carries whole puzzles
     * and a packed one carries six-bit groups — and which the server uses is
     * fixed by the configuration, so the decoder is bound here rather than per
     * read. It is captured behind a function so the receiver does not branch on
     * every chunk.
     */
    private val decode: (ByteArray, Int) -> ByteArray = if (pureDownlink) {
        val decoder = SudokuPureDecoder(downlink)
        val fn: (ByteArray, Int) -> ByteArray = { data, limit -> decoder.decode(data, limit) }
        fn
    } else {
        val decoder = SudokuPackedDecoder(downlink)
        val fn: (ByteArray, Int) -> ByteArray = { data, limit -> decoder.decode(data, limit) }
        fn
    }

    /** Encodes [plain] and writes the puzzles to the wire. */
    suspend fun send(plain: ByteArray) {
        if (plain.isEmpty()) return
        sendMutex.withLock {
            val encoded = uplink.encode(plain, rng, threshold)
            transport.send(encoded)
        }
    }

    /**
     * Up to [max] decoded bytes, or null at end of stream.
     *
     * Bytes the decoder held back from an earlier read are handed out before the
     * transport is touched at all, so a caller draining a large record never
     * blocks on a socket it does not need. Only once nothing is pending is a wire
     * chunk read and decoded; a chunk that decodes to nothing but padding is
     * skipped rather than mistaken for end of stream.
     */
    suspend fun receive(max: Int): ByteArray? {
        if (max <= 0) return EMPTY
        val pending = decode(EMPTY, max)
        if (pending.isNotEmpty()) return pending
        while (true) {
            val wire = transport.receive() ?: return null
            if (wire.isEmpty()) continue
            val out = decode(wire, max)
            if (out.isNotEmpty()) return out
        }
    }

    fun close() = transport.forceCancel()

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
