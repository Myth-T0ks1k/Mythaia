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
 * Two shapes are carried. The simple one — one length range, one interval
 * range — is what the settings screen edits and what the tunnel-wide default
 * is. The full FinalMask one — a length range and a delay range *per piece*,
 * and a cap on the number of pieces — is what panels send in `fm=`, and it
 * is kept as sent so "3 bytes, then the rest, 1 ms apart" means exactly that.
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
    val maxInterval: Int = DEFAULT_MAX_INTERVAL,

    /**
     * FinalMask's per-piece `lengths`, as `a` or `a-b` texts: the n-th entry
     * sizes the n-th piece, the last entry every piece after it. Empty means
     * "use [minLength]..[maxLength] for every piece".
     */
    val lengthSteps: List<String> = emptyList(),

    /** FinalMask's per-piece `delays`, same shape; the n-th entry is the pause after the n-th piece. */
    val delaySteps: List<String> = emptyList(),

    /** FinalMask's `maxSplit`: at most this many pieces, the last taking the rest. 0 is no cap. */
    val maxSplit: Int = 0
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

    /** One range per piece; the fragmenter repeats the last for the remainder. */
    val lengthRanges: List<IntRange>
        get() {
            val steps = lengthSteps.mapNotNull { parseRange(it) }.map { maxOf(1, it.first)..maxOf(1, it.last) }
            return if (steps.isEmpty()) listOf(lengthRange) else steps
        }

    /** One pause range per piece boundary; the last repeats. */
    val delayRanges: List<IntRange>
        get() {
            val steps = delaySteps.mapNotNull { parseRange(it) }
            return if (steps.isEmpty()) listOf(intervalRange) else steps
        }

    /**
     * The `fragment=` query value of a share link, as Happ and Streisand write
     * it: `length,interval,packets[,maxSplit]`. Emitted with the fixed
     * `tlshello` packets field, which is the only mode this client implements.
     * A per-piece list is written as its first step, which is the piece the
     * filter sees; the rest cannot be said in this form.
     */
    fun toShareLinkValue(): String {
        val length = rangeText(lengthRanges.first())
        val interval = rangeText(delayRanges.first())
        val split = if (maxSplit > 0) ",$maxSplit" else ""
        return "$length,$interval,tlshello$split"
    }

    /** The same settings as a FinalMask `fm=` document, which loses nothing. */
    fun toFinalMaskJson(): String {
        val lengths = org.json.JSONArray().apply { lengthRanges.forEach { put(rangeText(it)) } }
        val delays = org.json.JSONArray().apply { delayRanges.forEach { put(rangeText(it)) } }
        val settings = org.json.JSONObject()
            .put("packets", "tlshello")
            .put("lengths", lengths)
            .put("delays", delays)
        if (maxSplit > 0) settings.put("maxSplit", maxSplit.toString())
        val mask = org.json.JSONObject().put("type", "fragment").put("settings", settings)
        return org.json.JSONObject().put("tcp", org.json.JSONArray().put(mask)).toString()
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
         * `length,interval,packets[,maxSplit]`, each of the first two a number
         * or an `a-b` range — `3,1,tlshello`, `1-10,5-20,tlshello,2`. Null
         * when it does not parse.
         *
         * `packets` other than `tlshello` (Xray's `1-3`, raw TCP pieces) are
         * taken as `tlshello` too: cutting the hello into records is safe
         * wherever cutting the stream would have been, and it is the hello a
         * filter is after.
         */
        fun fromShareLink(value: String): FragmentSettings? {
            val fields = value.split(",").map { it.trim() }
            if (fields.size != 3 && fields.size != 4) return null
            if (fields[2].isEmpty()) return null

            val length = parseRange(fields[0]) ?: return null
            if (length.first < 1) return null
            val interval = parseRange(fields[1]) ?: return null
            val maxSplit = fields.getOrNull(3)?.let { parseRange(it)?.last ?: return null } ?: 0

            return FragmentSettings(
                isEnabled = true,
                minLength = length.first,
                maxLength = length.last,
                minInterval = interval.first,
                maxInterval = interval.last,
                maxSplit = maxSplit
            )
        }

        /**
         * Parses Xray FinalMask, as the `fm=` link parameter carries it:
         * `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello",
         * "lengths":["3"],"delays":["1"],"maxSplit":"2"}}], ...}`.
         *
         * Only the `tcp` fragment mask is read; `udp` (Salamander) and
         * `quicParams` belong to the protocols that use them. Null when there
         * is no fragment mask or it does not parse.
         *
         * Panels write the per-piece lists in two spellings: plural arrays
         * (`"lengths":["3"]`) and a singular value (`"length":"3"`, or a bare
         * number) that means the same one-entry list. Both are read, since
         * one provider's JSON subscription uses each in different entries.
         */
        fun fromFinalMask(json: String): FragmentSettings? {
            val root = runCatching { org.json.JSONObject(json) }.getOrNull() ?: return null
            val tcp = root.optJSONArray("tcp") ?: return null
            for (i in 0 until tcp.length()) {
                val mask = tcp.optJSONObject(i) ?: continue
                if (mask.optString("type") != "fragment") continue
                val settings = mask.optJSONObject("settings") ?: continue
                return fromFinalMaskSettings(settings)
            }
            return null
        }

        private fun fromFinalMaskSettings(settings: org.json.JSONObject): FragmentSettings? {
            val lengths = rangeTexts(settings.opt("lengths") ?: settings.opt("length"))
            val delays = rangeTexts(settings.opt("delays") ?: settings.opt("delay"))
            if (lengths.isEmpty()) return null
            val first = parseRange(lengths.first()) ?: return null
            val firstDelay = delays.firstOrNull()?.let { parseRange(it) } ?: (0..0)
            // Int32Range: "2" or "2-3"; the upper end is the cap that matters.
            val maxSplit = rangeTexts(settings.opt("maxSplit")).firstOrNull()?.let { parseRange(it)?.last } ?: 0
            return FragmentSettings(
                isEnabled = true,
                minLength = maxOf(1, first.first),
                maxLength = maxOf(1, first.last),
                minInterval = firstDelay.first,
                maxInterval = firstDelay.last,
                lengthSteps = lengths,
                delaySteps = delays,
                maxSplit = maxSplit
            )
        }

        /** A JSON array of range texts, or one range text, as a list. */
        private fun rangeTexts(value: Any?): List<String> = when (value) {
            null -> emptyList()
            is org.json.JSONArray -> (0 until value.length()).map { value.opt(it)?.toString() ?: "" }
                .filter { it.isNotBlank() }
            else -> listOf(value.toString()).filter { it.isNotBlank() }
        }

        internal fun parseRange(text: String): IntRange? {
            val ends = text.trim().split("-")
            if (ends.size != 1 && ends.size != 2) return null
            val low = ends[0].trim().toIntOrNull() ?: return null
            if (low < 0) return null
            if (ends.size == 1) return low..low
            val high = ends[1].trim().toIntOrNull() ?: return null
            if (high < low) return null
            return low..high
        }
    }
}
