package com.mythaia.vpn.protocol.anytls

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * How AnyTLS shapes the sizes of its first few TLS records.
 *
 * A scheme is a small text document: `stop=N` says how many packets to shape,
 * and `<n>=a-b,c,d-e` gives the record sizes packet `n` should be split into.
 * The client starts on a built-in default and replaces it with whatever the
 * server sends in `cmdUpdatePaddingScheme` — which is the point of the design.
 * When a censor learns the default pattern, the server can push a new one and
 * every client changes shape without an update.
 *
 * The scheme is identified by the MD5 of its exact bytes, so the raw text is
 * kept rather than re-serialised: a scheme that round-trips through parsing
 * would hash differently and the server would push a replacement forever.
 */
class AnyTlsPaddingScheme private constructor(
    /** The bytes as received, which is what the digest is taken over. */
    val raw: ByteArray,
    val md5: String,
    private val stop: Int,
    private val sizes: Map<Int, List<Int>>
) {

    /**
     * The record sizes for packet [packet], or empty when the scheme says
     * nothing about it — in which case the caller writes the packet as it is.
     */
    fun recordSizes(packet: Int, random: SecureRandom): List<Int> {
        val spec = sizes[packet] ?: return emptyList()
        return spec.map { value ->
            when {
                value == CHECK -> CHECK
                value >= 0 -> value
                else -> {
                    // A negative non-check value encodes a range as -(min shl 16 or max).
                    val packed = -value
                    val lo = packed ushr 16
                    val hi = packed and 0xFFFF
                    if (hi <= lo) lo else lo + random.nextInt(hi - lo)
                }
            }
        }
    }

    /** Whether packet [packet] should still be shaped at all. */
    fun shapes(packet: Int): Boolean = packet < stop

    companion object {
        /**
         * The check mark, written `c` in a scheme.
         *
         * It means "if the payload is used up, stop here" — so a small request
         * is not followed by padding records that would themselves be a
         * signature.
         */
        const val CHECK = -1

        /**
         * The scheme every client starts on, byte for byte as the reference
         * implementation ships it. Its MD5 is what a server compares against,
         * so a stray newline here would cause a pointless update on every
         * session.
         */
        val DEFAULT_TEXT =
            "stop=8\n" +
                "0=30-30\n" +
                "1=100-400\n" +
                "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n" +
                "3=9-9,500-1000\n" +
                "4=500-1000\n" +
                "5=500-1000\n" +
                "6=500-1000\n" +
                "7=500-1000"

        val DEFAULT: AnyTlsPaddingScheme by lazy {
            parse(DEFAULT_TEXT.toByteArray(Charsets.UTF_8))
                ?: error("the built-in padding scheme does not parse")
        }

        /** Null when the text is not a usable scheme; the caller keeps the old one. */
        fun parse(raw: ByteArray): AnyTlsPaddingScheme? {
            val entries = String(raw, Charsets.UTF_8)
                .split('\n')
                .mapNotNull { line ->
                    val at = line.indexOf('=')
                    if (at <= 0) null else line.substring(0, at).trim() to line.substring(at + 1).trim()
                }
                .toMap()
            if (entries.isEmpty()) return null

            val stop = entries["stop"]?.toIntOrNull() ?: return null

            val sizes = HashMap<Int, List<Int>>()
            for ((key, value) in entries) {
                val packet = key.toIntOrNull() ?: continue
                val spec = value.split(',').mapNotNull { part -> encodePart(part.trim()) }
                if (spec.isNotEmpty()) sizes[packet] = spec
            }

            val digest = MessageDigest.getInstance("MD5").digest(raw)
            val md5 = digest.joinToString("") { "%02x".format(it) }
            return AnyTlsPaddingScheme(raw, md5, stop, sizes)
        }

        /**
         * A part is either `c`, a fixed size, or a range.
         *
         * A range is packed into a negative int rather than kept as a pair so
         * the parsed form stays a flat list of ints; the sizes involved are
         * record lengths, far below 16 bits each.
         */
        private fun encodePart(part: String): Int? {
            if (part == "c") return CHECK
            val dash = part.indexOf('-')
            if (dash <= 0) return null
            var lo = part.substring(0, dash).toIntOrNull() ?: return null
            var hi = part.substring(dash + 1).toIntOrNull() ?: return null
            if (lo > hi) { val t = lo; lo = hi; hi = t }
            if (lo <= 0 || hi <= 0) return null
            if (lo == hi) return lo
            if (lo > 0xFFFF || hi > 0xFFFF) return null
            return -((lo shl 16) or hi)
        }
    }
}
