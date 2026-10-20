package com.mythaia.data.routing

/**
 * A set of address ranges, IPv4 and IPv6, answered by binary search.
 *
 * A country from a geoip file is thousands of CIDRs. Kept as sorted,
 * merged ranges in primitive arrays they cost a few bytes each and a lookup
 * is a dozen comparisons, where a bit trie would allocate a node per bit.
 */
class IpRanges private constructor(
    private val v4Start: LongArray,
    private val v4End: LongArray,
    private val v6StartHi: LongArray,
    private val v6StartLo: LongArray,
    private val v6EndHi: LongArray,
    private val v6EndLo: LongArray
) {
    val isEmpty: Boolean get() = v4Start.isEmpty() && v6StartHi.isEmpty()

    /** How many merged ranges the set holds. */
    val size: Int get() = v4Start.size + v6StartHi.size

    /** [address] is 4 or 16 bytes; an IPv4-mapped IPv6 address counts as its IPv4 one. */
    fun contains(address: ByteArray): Boolean = when (address.size) {
        4 -> containsV4(v4(address, 0))
        16 -> if (isV4Mapped(address)) containsV4(v4(address, 12)) else containsV6(long(address, 0), long(address, 8))
        else -> false
    }

    private fun containsV4(value: Long): Boolean {
        // The last range starting at or below the value.
        var lo = 0
        var hi = v4Start.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (v4Start[mid] <= value) {
                found = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return found >= 0 && value <= v4End[found]
    }

    private fun containsV6(valueHi: Long, valueLo: Long): Boolean {
        var lo = 0
        var hi = v6StartHi.size - 1
        var found = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (compare(v6StartHi[mid], v6StartLo[mid], valueHi, valueLo) <= 0) {
                found = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return found >= 0 && compare(valueHi, valueLo, v6EndHi[found], v6EndLo[found]) <= 0
    }

    class Builder {
        private val v4 = ArrayList<LongArray>()
        private val v6 = ArrayList<LongArray>()

        /** Adds [address]/[prefix]; host bits are ignored. Returns false for a malformed pair. */
        fun add(address: ByteArray, prefix: Int): Boolean {
            when (address.size) {
                4 -> {
                    if (prefix !in 0..32) return false
                    val value = v4(address, 0)
                    val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
                    val start = value and mask
                    v4 += longArrayOf(start, start or (mask.inv() and 0xFFFFFFFFL))
                }
                16 -> {
                    if (prefix !in 0..128) return false
                    if (isV4Mapped(address) && prefix >= 96) return add(address.copyOfRange(12, 16), prefix - 96)
                    val hi = long(address, 0)
                    val lo = long(address, 8)
                    val (maskHi, maskLo) = mask128(prefix)
                    v6 += longArrayOf(hi and maskHi, lo and maskLo, (hi and maskHi) or maskHi.inv(), (lo and maskLo) or maskLo.inv())
                }
                else -> return false
            }
            return true
        }

        fun addAll(other: IpRanges) {
            for (i in other.v4Start.indices) v4 += longArrayOf(other.v4Start[i], other.v4End[i])
            for (i in other.v6StartHi.indices) {
                v6 += longArrayOf(other.v6StartHi[i], other.v6StartLo[i], other.v6EndHi[i], other.v6EndLo[i])
            }
        }

        fun build(): IpRanges {
            v4.sortWith(compareBy<LongArray> { it[0] })
            val starts4 = ArrayList<Long>()
            val ends4 = ArrayList<Long>()
            for (range in v4) {
                if (ends4.isNotEmpty() && range[0] <= ends4.last() + 1) {
                    if (range[1] > ends4.last()) ends4[ends4.size - 1] = range[1]
                } else {
                    starts4 += range[0]
                    ends4 += range[1]
                }
            }

            v6.sortWith { a, b -> compare(a[0], a[1], b[0], b[1]) }
            val merged = ArrayList<LongArray>()
            for (range in v6) {
                val last = merged.lastOrNull()
                if (last != null && adjacentOrOverlapping(last[2], last[3], range[0], range[1])) {
                    if (compare(range[2], range[3], last[2], last[3]) > 0) {
                        last[2] = range[2]
                        last[3] = range[3]
                    }
                } else {
                    merged += range.copyOf()
                }
            }
            return IpRanges(
                starts4.toLongArray(), ends4.toLongArray(),
                LongArray(merged.size) { merged[it][0] }, LongArray(merged.size) { merged[it][1] },
                LongArray(merged.size) { merged[it][2] }, LongArray(merged.size) { merged[it][3] }
            )
        }

        /** Whether a range starting at [startHi]:[startLo] touches one ending at [endHi]:[endLo]. */
        private fun adjacentOrOverlapping(endHi: Long, endLo: Long, startHi: Long, startLo: Long): Boolean {
            if (compare(startHi, startLo, endHi, endLo) <= 0) return true
            // end + 1 == start, carrying into the high half.
            val nextLo = endLo + 1
            val nextHi = if (nextLo == 0L) endHi + 1 else endHi
            return nextHi == startHi && nextLo == startLo && !(endHi == -1L && endLo == -1L)
        }
    }

    companion object {
        val EMPTY: IpRanges = Builder().build()

        /** The ranges `geoip:private` means when no geoip file supplies them. */
        val PRIVATE: IpRanges by lazy {
            val builder = Builder()
            for (cidr in listOf(
                "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
                "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"
            )) {
                parseCidr(cidr)?.let { (address, prefix) -> builder.add(address, prefix) }
            }
            builder.build()
        }

        /**
         * `a.b.c.d`, `a.b.c.d/n`, an IPv6 literal or `v6/n`, as bytes and a
         * prefix (the full width when none is written). Never resolves a name.
         */
        fun parseCidr(text: String): Pair<ByteArray, Int>? {
            val trimmed = text.trim()
            val slash = trimmed.indexOf('/')
            val addressText = if (slash >= 0) trimmed.substring(0, slash) else trimmed
            val address = parseAddress(addressText) ?: return null
            val prefix = if (slash >= 0) trimmed.substring(slash + 1).trim().toIntOrNull() ?: return null else address.size * 8
            if (prefix < 0 || prefix > address.size * 8) return null
            return address to prefix
        }

        /** An IPv4 or IPv6 literal as bytes; null for anything else, a name included. */
        fun parseAddress(text: String): ByteArray? {
            val t = text.trim().removePrefix("[").removeSuffix("]")
            if (t.isEmpty()) return null
            if (':' !in t) {
                val parts = t.split('.')
                if (parts.size != 4) return null
                val out = ByteArray(4)
                for (i in 0 until 4) {
                    val p = parts[i]
                    if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return null
                    val v = p.toInt()
                    if (v > 255) return null
                    out[i] = v.toByte()
                }
                return out
            }
            return parseV6(t)
        }

        private fun parseV6(text: String): ByteArray? {
            if (text.count { it == ':' } < 2 || text.contains(":::")) return null
            // A trailing dotted quad (::ffff:1.2.3.4) is two groups.
            var body = text
            var tail: ByteArray? = null
            val lastColon = text.lastIndexOf(':')
            if ('.' in text.substring(lastColon + 1)) {
                tail = parseAddress(text.substring(lastColon + 1)) ?: return null
                body = text.substring(0, lastColon + 1) + "0:0"
            }
            val halves = body.split("::")
            if (halves.size > 2) return null
            fun groups(part: String): List<Int>? {
                if (part.isEmpty()) return emptyList()
                return part.split(':').map { g ->
                    if (g.isEmpty() || g.length > 4 || !g.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) return null
                    g.toInt(16)
                }
            }
            val head = groups(halves[0]) ?: return null
            val rest = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
            val total = head.size + rest.size
            if (halves.size == 1 && total != 8) return null
            if (halves.size == 2 && total > 7) return null
            val all = head + List(8 - total) { 0 } + rest
            val out = ByteArray(16)
            for (i in 0 until 8) {
                out[i * 2] = (all[i] ushr 8).toByte()
                out[i * 2 + 1] = all[i].toByte()
            }
            tail?.copyInto(out, 12)
            return out
        }

        private fun v4(bytes: ByteArray, at: Int): Long =
            ((bytes[at].toLong() and 0xFF) shl 24) or ((bytes[at + 1].toLong() and 0xFF) shl 16) or
                ((bytes[at + 2].toLong() and 0xFF) shl 8) or (bytes[at + 3].toLong() and 0xFF)

        private fun long(bytes: ByteArray, at: Int): Long {
            var v = 0L
            for (i in 0 until 8) v = (v shl 8) or (bytes[at + i].toLong() and 0xFF)
            return v
        }

        private fun isV4Mapped(address: ByteArray): Boolean {
            for (i in 0 until 10) if (address[i].toInt() != 0) return false
            return address[10].toInt() == -1 && address[11].toInt() == -1
        }

        private fun mask128(prefix: Int): Pair<Long, Long> = when {
            prefix == 0 -> 0L to 0L
            prefix < 64 -> (-1L shl (64 - prefix)) to 0L
            prefix == 64 -> -1L to 0L
            prefix < 128 -> -1L to (-1L shl (128 - prefix))
            else -> -1L to -1L
        }

        /** Unsigned 128-bit comparison. */
        private fun compare(aHi: Long, aLo: Long, bHi: Long, bLo: Long): Int {
            val hi = java.lang.Long.compareUnsigned(aHi, bHi)
            return if (hi != 0) hi else java.lang.Long.compareUnsigned(aLo, bLo)
        }
    }
}
