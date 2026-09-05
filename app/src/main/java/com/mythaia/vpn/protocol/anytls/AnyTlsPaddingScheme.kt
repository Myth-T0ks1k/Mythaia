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
    private val sizes: Map<Int, List<Part>>
) {

    /**
     * One entry in a packet's size list.
     *
     * A sealed type rather than an encoding into an Int. The first version of
     * this packed a range into one negative int, which silently overflowed to a
     * positive number once the minimum reached 32768 — and a positive value
     * reads back as a *fixed* size of about 1.6 GB, which allocates a buffer
     * that size. The reference keeps its bounds as plain 64-bit locals and
     * accepts any positive range, so there is nothing to be clever about here.
     */
    private sealed interface Part {
        data object Check : Part
        data class Fixed(val size: Int) : Part
        data class Range(val lo: Int, val hi: Int) : Part
    }

    /**
     * The record sizes for packet [packet], or empty when the scheme says
     * nothing about it — in which case the caller writes the packet as it is.
     */
    fun recordSizes(packet: Int, random: SecureRandom): List<Int> {
        val spec = sizes[packet] ?: return emptyList()
        return spec.map { part ->
            when (part) {
                is Part.Check -> CHECK
                is Part.Fixed -> part.size
                // Go draws in [lo, hi), matching rand.Int over (hi - lo).
                is Part.Range -> part.lo + random.nextInt(part.hi - part.lo)
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
         * A record size this client will not exceed.
         *
         * The reference accepts any positive range, but a TLS record cannot
         * carry more than 2^14 bytes anyway, so a larger request is clamped
         * rather than dropped — dropping the part would emit fewer records than
         * the server asked for, which changes the very signature the scheme
         * exists to control.
         */
        const val MAX_RECORD = 16384

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

            val sizes = HashMap<Int, List<Part>>()
            for ((key, value) in entries) {
                val packet = key.toIntOrNull() ?: continue
                val spec = value.split(',').mapNotNull { part -> parsePart(part.trim()) }
                if (spec.isNotEmpty()) sizes[packet] = spec
            }

            val digest = MessageDigest.getInstance("MD5").digest(raw)
            val md5 = digest.joinToString("") { "%02x".format(it) }
            return AnyTlsPaddingScheme(raw, md5, stop, sizes)
        }

        /** A part is either `c`, a fixed size, or a range — as the reference reads it. */
        private fun parsePart(part: String): Part? {
            if (part == "c") return Part.Check

            val dash = part.indexOf('-')
            if (dash <= 0) return null
            var lo = part.substring(0, dash).toIntOrNull() ?: return null
            var hi = part.substring(dash + 1).toIntOrNull() ?: return null
            if (lo > hi) { val t = lo; lo = hi; hi = t }

            // The reference's only rejection: both bounds must be positive.
            if (lo <= 0 || hi <= 0) return null

            lo = lo.coerceAtMost(MAX_RECORD)
            hi = hi.coerceAtMost(MAX_RECORD)
            return if (lo == hi) Part.Fixed(lo) else Part.Range(lo, hi)
        }
    }
}
