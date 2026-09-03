package com.mythaia.data.model

import kotlinx.serialization.Serializable

/**
 * Xray's `fragment` with `packets: tlshello`: the TLS ClientHello goes out as
 * several TLS records with a pause between them, so a filter that reads the
 * server name off the first packet does not find it there. Every server
 * reassembles a handshake message across records — the TLS spec requires it —
 * so nothing on the far side has to know.
 *
 * On by default: the product ships to networks where the server name is the
 * first thing a filter looks for, and the cost is a few dozen milliseconds per
 * handshake with the proxy server, once per connection.
 *
 * Mirrors the iOS `FragmentSettings`.
 */
@Serializable
data class FragmentSettings(
    val isEnabled: Boolean = true,

    /**
     * Bytes of ClientHello per record, drawn at random from this range for each
     * record. Xray's popular `100-200`.
     */
    val minLength: Int = DEFAULT_MIN_LENGTH,
    val maxLength: Int = DEFAULT_MAX_LENGTH,

    /**
     * Milliseconds between one record and the next, drawn at random from this
     * range. Xray's popular `10-20`.
     */
    val minInterval: Int = DEFAULT_MIN_INTERVAL,
    val maxInterval: Int = DEFAULT_MAX_INTERVAL
) {

    /**
     * The ranges as the fragmenter draws from them: never empty, never below
     * one byte or zero milliseconds, whichever way round the two ends were
     * typed.
     */
    val lengthRange: IntRange
        get() {
            val low = maxOf(1, minOf(minLength, maxLength))
            return low..maxOf(low, maxOf(minLength, maxLength))
        }

    val intervalRange: IntRange
        get() {
            val low = maxOf(0, minOf(minInterval, maxInterval))
            return low..maxOf(low, maxOf(minInterval, maxInterval))
        }

    /**
     * The `fragment=` query value of a share link, as Happ and Streisand write
     * it: `length,interval,packets`. Emitted with the fixed `tlshello` packets
     * field, which is the only mode this client implements.
     */
    fun toShareLinkValue(): String {
        val length = rangeText(lengthRange)
        val interval = rangeText(intervalRange)
        return "$length,$interval,tlshello"
    }

    private fun rangeText(range: IntRange): String =
        if (range.first == range.last) "${range.first}" else "${range.first}-${range.last}"

    companion object {
        const val DEFAULT_MIN_LENGTH = 100
        const val DEFAULT_MAX_LENGTH = 200
        const val DEFAULT_MIN_INTERVAL = 10
        const val DEFAULT_MAX_INTERVAL = 20

        /**
         * Parses the `fragment=` query of a share link:
         * `length,interval,packets`, each of the first two a number or an `a-b`
         * range — `3,1,tlshello`, `1-10,5-20,tlshello`. Null when it does not
         * parse.
         *
         * `packets` other than `tlshello` (Xray's `1-3`, raw TCP pieces) are
         * taken as `tlshello` too: cutting the hello into records is safe
         * wherever cutting the stream would have been, and it is the hello a
         * filter is after.
         */
        fun fromShareLink(value: String): FragmentSettings? {
            val fields = value.split(",").map { it.trim() }
            if (fields.size != 3) return null
            if (fields[2].isEmpty()) return null

            val length = parseRange(fields[0]) ?: return null
            if (length.first < 1) return null
            val interval = parseRange(fields[1]) ?: return null

            return FragmentSettings(
                isEnabled = true,
                minLength = length.first,
                maxLength = length.last,
                minInterval = interval.first,
                maxInterval = interval.last
            )
        }

        private fun parseRange(text: String): IntRange? {
            val ends = text.split("-")
            if (ends.size != 1 && ends.size != 2) return null
            val low = ends[0].toIntOrNull() ?: return null
            if (low < 0) return null
            if (ends.size == 1) return low..low
            val high = ends[1].toIntOrNull() ?: return null
            if (high < low) return null
            return low..high
        }
    }
}
