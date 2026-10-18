package com.mythaia.data.model

/**
 * A set of UDP ports as Hysteria2 port hopping lists them: single ports and
 * inclusive ranges, sorted and merged, e.g. `443,8443,20000-30000`.
 *
 * Every format spells the same thing a little differently, and all of them
 * are read here: the official client and Clash separate entries with `,`
 * (mihomo also with `/`) and write ranges as `a-b`; sing-box's
 * `server_ports` writes them as `a:b`. A range written backwards is turned
 * round, as the official parser does. Port 0 is not a port anyone listens on,
 * so a list that names it is refused rather than dialled.
 *
 * [toString] is the canonical spelling, which is what is stored and exported.
 */
class PortUnion private constructor(val ranges: List<IntRange>) {

    /** How many ports there are in all; a port is picked uniformly from them. */
    val size: Int = ranges.sumOf { it.last - it.first + 1 }

    val first: Int get() = ranges.first().first

    /** More than one port to hop between. */
    val hops: Boolean get() = size > 1

    operator fun contains(port: Int): Boolean = ranges.any { port in it }

    /** The [index]th port in ascending order, `0 until size`. */
    fun portAt(index: Int): Int {
        require(index in 0 until size) { "port index $index outside 0 until $size" }
        var rest = index
        for (range in ranges) {
            val count = range.last - range.first + 1
            if (rest < count) return range.first + rest
            rest -= count
        }
        error("unreachable")
    }

    /** One port at random, every port equally likely, as the official client picks. */
    fun random(random: kotlin.random.Random = kotlin.random.Random): Int = portAt(random.nextInt(size))

    override fun toString(): String =
        ranges.joinToString(",") { if (it.first == it.last) "${it.first}" else "${it.first}-${it.last}" }

    override fun equals(other: Any?): Boolean = other is PortUnion && other.ranges == ranges
    override fun hashCode(): Int = ranges.hashCode()

    companion object {
        /**
         * Reads [text], or null when it is not a port list: empty, a port
         * outside 1..65535, or a piece that is not a number or a range.
         */
        fun parse(text: String?): PortUnion? {
            val raw = text?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val pieces = raw.split(',', '/').map { it.trim() }
            if (pieces.any { it.isEmpty() }) return null
            val ranges = pieces.map { piece ->
                val bounds = piece.split('-', ':')
                when (bounds.size) {
                    1 -> port(bounds[0])?.let { it..it }
                    2 -> {
                        val a = port(bounds[0])
                        val b = port(bounds[1])
                        if (a == null || b == null) null else minOf(a, b)..maxOf(a, b)
                    }
                    else -> null
                } ?: return null
            }
            return PortUnion(normalize(ranges))
        }

        /** [parse] over a list of entries, as sing-box and some JSON writers give them. */
        fun parse(entries: List<String>): PortUnion? =
            entries.takeIf { it.isNotEmpty() }?.joinToString(",")?.let { parse(it) }

        /** Whether a port field holds a list or a range rather than one port. */
        fun isList(text: String): Boolean = text.contains(',') || text.contains('-') || text.contains('/')

        private fun port(text: String): Int? =
            text.trim().takeIf { it.isNotEmpty() && it.all(Char::isDigit) && it.length <= 5 }
                ?.toInt()?.takeIf { it in 1..65535 }

        private fun normalize(ranges: List<IntRange>): List<IntRange> {
            val sorted = ranges.sortedWith(compareBy<IntRange> { it.first }.thenBy { it.last })
            val merged = ArrayList<IntRange>()
            for (range in sorted) {
                val last = merged.lastOrNull()
                if (last != null && range.first <= last.last + 1) {
                    if (range.last > last.last) merged[merged.size - 1] = last.first..range.last
                } else {
                    merged.add(range)
                }
            }
            return merged
        }
    }
}

/**
 * How often Hysteria2 port hopping moves to a new port, in seconds.
 *
 * The official client hops every 30 s unless told otherwise, refuses anything
 * under 5 s, and can pick each interval at random between a minimum and a
 * maximum (`minHopInterval`/`maxHopInterval`; sing-box's `hop_interval_max`).
 * [min] and [max] are kept apart rather than packed together.
 */
data class HopInterval(val min: Int, val max: Int = min) {

    init {
        require(min in MIN_SECONDS..max) { "hop interval $min-$max s" }
    }

    /** The link spelling: `30`, or `10-50` for a random interval. */
    override fun toString(): String = if (min == max) "$min" else "$min-$max"

    companion object {
        const val DEFAULT_SECONDS = 30
        const val MIN_SECONDS = 5

        val DEFAULT = HopInterval(DEFAULT_SECONDS)

        /**
         * One interval in any of the spellings in use: whole seconds (`30`,
         * Clash's `hop-interval`), a Go duration (`30s`, `1m`, sing-box's
         * `hop_interval`), or Xray's range of seconds (`10-50`).
         *
         * An interval under 5 s is raised to 5 s: the official client refuses
         * the whole configuration over it, which would lose the server for a
         * number that only tunes how often it hops. Null when unreadable.
         */
        fun parse(text: String?): HopInterval? {
            val raw = text?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            val dash = raw.indexOf('-', startIndex = 1)
            if (dash > 0) {
                val low = seconds(raw.substring(0, dash)) ?: return null
                val high = seconds(raw.substring(dash + 1)) ?: return null
                return of(minOf(low, high), maxOf(low, high))
            }
            return seconds(raw)?.let { of(it, it) }
        }

        /** [min]..[max] with each end raised to the 5 s floor; null for a zero or negative one. */
        fun of(min: Int?, max: Int? = min): HopInterval? {
            val low = min?.takeIf { it > 0 } ?: return null
            val high = max?.takeIf { it > 0 } ?: low
            val floor = maxOf(low, MIN_SECONDS)
            return HopInterval(floor, maxOf(floor, high))
        }

        /** Whole seconds from `30`, `30s`, `1m30s`, `1.5m` or `500ms` (rounded up). */
        internal fun seconds(text: String): Int? {
            val t = text.trim().lowercase()
            if (t.isEmpty()) return null
            if (t.all(Char::isDigit)) return t.toIntOrNull()
            var total = 0.0
            var rest = t
            val unit = Regex("^([0-9]+(?:\\.[0-9]+)?)(ms|h|m|s)")
            while (rest.isNotEmpty()) {
                val match = unit.find(rest) ?: return null
                val value = match.groupValues[1].toDouble()
                total += when (match.groupValues[2]) {
                    "h" -> value * 3600
                    "m" -> value * 60
                    "s" -> value
                    else -> value / 1000
                }
                rest = rest.substring(match.value.length)
            }
            return kotlin.math.ceil(total).toInt().takeIf { it > 0 }
        }
    }
}
