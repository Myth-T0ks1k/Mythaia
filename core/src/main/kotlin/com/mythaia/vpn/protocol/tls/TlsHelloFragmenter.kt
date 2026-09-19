package com.mythaia.vpn.protocol.tls

import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.delay
import java.security.SecureRandom

/**
 * Splits one TLS handshake record into several, each a complete record of its
 * own — the same 3-byte type and version, its own length, a slice of the
 * handshake bytes — and sends them with a pause between. Xray calls this
 * `fragment` with `packets: tlshello`; see
 * [com.mythaia.data.model.FragmentSettings] for why it exists. The record
 * layer on the other side reassembles the message, as every TLS
 * implementation must.
 *
 * Mirrors the iOS `TLSHelloFragmenter`.
 */
object TlsHelloFragmenter {

    private const val HANDSHAKE_CONTENT_TYPE: Byte = 0x16
    private const val HEADER_LENGTH = 5

    /**
     * [record] cut into records whose payloads are [lengths] bytes long, in
     * order, the last taking whatever remains; [lengths] running out falls back
     * to its last value. Anything that is not one well-formed handshake record
     * comes back untouched, as a single piece.
     */
    fun split(record: ByteArray, lengths: List<Int>): List<ByteArray> {
        val last = lengths.lastOrNull() ?: return listOf(record)
        if (record.size <= HEADER_LENGTH || record[0] != HANDSHAKE_CONTENT_TYPE || last <= 0) {
            return listOf(record)
        }
        val declared = ((record[3].toInt() and 0xFF) shl 8) or (record[4].toInt() and 0xFF)
        if (HEADER_LENGTH + declared != record.size) return listOf(record)

        val pieces = ArrayList<ByteArray>()
        var from = HEADER_LENGTH
        var index = 0
        while (from < record.size) {
            val length = maxOf(1, if (index < lengths.size) lengths[index] else last)
            val to = minOf(from + length, record.size)
            val payloadLength = to - from
            val piece = ByteArray(HEADER_LENGTH + payloadLength)
            piece[0] = record[0]
            piece[1] = record[1]
            piece[2] = record[2]
            piece[3] = ((payloadLength shr 8) and 0xFF).toByte()
            piece[4] = (payloadLength and 0xFF).toByte()
            record.copyInto(piece, HEADER_LENGTH, from, to)
            pieces.add(piece)
            from = to
            index++
        }
        return pieces
    }

    /** The same, with each length drawn from [lengthRange]. */
    fun split(record: ByteArray, lengthRange: IntRange, random: SecureRandom): List<ByteArray> =
        split(record, listOf(lengthRange), 0, random)

    /**
     * FinalMask's shape: the n-th piece is drawn from the n-th of
     * [lengthRanges], the last range serving every piece after it, and with
     * [maxSplit] > 0 the piece that would be the last allowed takes whatever
     * remains. `lengths ["3"], maxSplit 2` is therefore "3 bytes, then the
     * rest" — the classic split — and not a hello cut into 3-byte slivers.
     */
    fun split(record: ByteArray, lengthRanges: List<IntRange>, maxSplit: Int, random: SecureRandom): List<ByteArray> {
        if (lengthRanges.isEmpty()) return listOf(record)
        val payloadCount = maxOf(0, record.size - HEADER_LENGTH)
        val lengths = ArrayList<Int>()
        var covered = 0
        var index = 0
        while (covered < payloadCount) {
            if (maxSplit > 0 && lengths.size == maxSplit - 1) {
                lengths.add(payloadCount - covered)
                break
            }
            val range = lengthRanges[minOf(index, lengthRanges.size - 1)]
            val length = maxOf(1, nextInRange(random, range))
            lengths.add(length)
            covered += length
            index++
        }
        return split(record, if (lengths.isEmpty()) listOf(lengthRanges.last().last) else lengths)
    }

    /**
     * Sends [record] in pieces over [transport], each [lengthRange] bytes of
     * hello, pausing between them by [intervalRange] milliseconds. A hello
     * shorter than the shortest piece goes out as it is.
     */
    suspend fun send(
        record: ByteArray,
        transport: Transport,
        lengthRange: IntRange,
        intervalRange: IntRange,
        random: SecureRandom = SecureRandom()
    ) {
        val pieces = split(record, lengthRange, random)
        for ((index, piece) in pieces.withIndex()) {
            transport.send(piece)
            if (index == pieces.size - 1) break
            val pause = nextInRange(random, intervalRange)
            if (pause > 0) delay(pause.toLong())
        }
    }

    /**
     * A value drawn uniformly from [range]. [SecureRandom.nextInt] rejects a
     * non-positive bound, so a single-value range short-circuits.
     */
    fun nextInRange(random: SecureRandom, range: IntRange): Int {
        val span = range.last - range.first
        if (span <= 0) return range.first
        return range.first + random.nextInt(span + 1)
    }
}
