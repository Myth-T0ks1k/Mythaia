package com.mythaia.vpn.protocol.quic

/**
 * QUIC's variable-length integer encoding (RFC 9000 §16).
 *
 * The two high bits of the first byte pick a 1, 2, 4 or 8-byte form and the
 * rest of the bits are the value, so small numbers cost one byte. It is used
 * for nearly every length and identifier in QUIC and HTTP/3, which is why it
 * lives on its own rather than inside whichever layer needed it first.
 *
 * Values are carried as [Long] because Kotlin has no unsigned 64-bit type in
 * common use; the encoding tops out at 2^62 - 1, comfortably inside a positive
 * Long, so a negative value here is a caller's mistake rather than a wrap.
 */
object QuicVarInt {

    /** The largest value the encoding can express: 2^62 - 1. */
    const val MAX = 4_611_686_018_427_387_903L

    /** How many bytes [value] will take. */
    fun sizeOf(value: Long): Int = when {
        value < 0 -> throw IllegalArgumentException("varint cannot be negative: $value")
        value <= 63 -> 1
        value <= 16_383 -> 2
        value <= 1_073_741_823 -> 4
        value <= MAX -> 8
        else -> throw IllegalArgumentException("varint out of range: $value")
    }

    fun encode(value: Long): ByteArray {
        val out = ByteArray(sizeOf(value))
        write(out, 0, value)
        return out
    }

    /** Writes [value] at [offset] and returns the number of bytes written. */
    fun write(out: ByteArray, offset: Int, value: Long): Int {
        val size = sizeOf(value)
        when (size) {
            1 -> out[offset] = value.toByte()
            2 -> {
                out[offset] = (0x40 or (value ushr 8).toInt()).toByte()
                out[offset + 1] = value.toByte()
            }
            4 -> {
                out[offset] = (0x80 or (value ushr 24).toInt()).toByte()
                out[offset + 1] = (value ushr 16).toByte()
                out[offset + 2] = (value ushr 8).toByte()
                out[offset + 3] = value.toByte()
            }
            else -> {
                out[offset] = (0xC0 or (value ushr 56).toInt()).toByte()
                for (i in 1 until 8) {
                    out[offset + i] = (value ushr ((7 - i) * 8)).toByte()
                }
            }
        }
        return size
    }

    /** A decoded value and how many bytes it occupied. */
    data class Decoded(val value: Long, val size: Int)

    /**
     * Reads a varint at [offset], or null when the buffer stops short of one.
     *
     * Null rather than an exception because every caller here is parsing bytes
     * that arrived over a network: a truncated frame is something to wait for
     * or drop, not something exceptional.
     */
    fun decode(bytes: ByteArray, offset: Int = 0): Decoded? {
        if (offset < 0 || offset >= bytes.size) return null

        val first = bytes[offset].toInt() and 0xFF
        return when (first ushr 6) {
            0 -> Decoded((first and 0x3F).toLong(), 1)

            1 -> {
                if (offset + 2 > bytes.size) return null
                Decoded(
                    ((first and 0x3F).toLong() shl 8) or (bytes[offset + 1].toLong() and 0xFF),
                    2
                )
            }

            2 -> {
                if (offset + 4 > bytes.size) return null
                var value = (first and 0x3F).toLong() shl 24
                value = value or ((bytes[offset + 1].toLong() and 0xFF) shl 16)
                value = value or ((bytes[offset + 2].toLong() and 0xFF) shl 8)
                value = value or (bytes[offset + 3].toLong() and 0xFF)
                Decoded(value, 4)
            }

            else -> {
                if (offset + 8 > bytes.size) return null
                var value = (first and 0x3F).toLong() shl 56
                for (i in 1 until 8) {
                    value = value or ((bytes[offset + i].toLong() and 0xFF) shl ((7 - i) * 8))
                }
                Decoded(value, 8)
            }
        }
    }
}
