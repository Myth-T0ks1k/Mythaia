package com.mythaia.vpn.protocol.hysteria

/**
 * How a Hysteria2 node asks for its UDP datagrams to be disguised.
 *
 * This is the configuration, not the transformation: it is what a
 * `hysteria2://` link, a Clash YAML block, or a stored profile can say, and it
 * is what [HysteriaObfuscator.of] turns into something that actually touches
 * bytes. Keeping the two apart matters because the config has to survive a
 * round trip through storage and comparison — hence a plain value type — while
 * the obfuscator owns a random source and, for gecko, live reassembly state.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
sealed interface HysteriaObfuscation {

    /** The shared secret both ends derive the keystream from. */
    val password: String

    /** The tag used on the wire, in links, in Clash YAML, and in stored JSON. */
    val typeTag: String

    /** Plain XOR obfuscation. */
    data class Salamander(override val password: String) : HysteriaObfuscation {
        override val typeTag: String get() = "salamander"
    }

    /**
     * Salamander plus handshake fragmentation.
     *
     * The bounds are the size window each emitted datagram is padded into. They
     * are held exactly as given rather than normalized here, so that a config
     * read back from storage compares equal to the one written; [make] and
     * [GeckoObfuscator] both normalize at the point where the numbers are
     * actually used.
     */
    data class Gecko(
        override val password: String,
        val minPacketSize: Int,
        val maxPacketSize: Int
    ) : HysteriaObfuscation {
        override val typeTag: String get() = "gecko"
    }

    companion object {
        /** Gecko packet-size bounds, in bytes. */
        const val GECKO_MIN_PACKET_SIZE_DEFAULT = 512
        const val GECKO_MAX_PACKET_SIZE_DEFAULT = 1200

        /** Anything outside this is clamped; the upper end is a safe MTU ceiling. */
        val GECKO_PACKET_SIZE_RANGE = 0..2048

        /**
         * Settles gecko's bounds into a usable pair.
         *
         * Absent or non-positive values fall back to the defaults, both ends are
         * clamped into [GECKO_PACKET_SIZE_RANGE], and a maximum below the
         * minimum is raised to meet it rather than rejected — a node with
         * nonsense bounds should still connect, because the bounds only shape
         * padding and getting them wrong costs traffic analysis resistance, not
         * correctness.
         */
        fun normalizedGeckoSizes(min: Int?, max: Int?): Pair<Int, Int> {
            fun clamp(value: Int) = value.coerceIn(GECKO_PACKET_SIZE_RANGE)
            val lo = clamp(if ((min ?: 0) > 0) min!! else GECKO_MIN_PACKET_SIZE_DEFAULT)
            val hi = clamp(if ((max ?: 0) > 0) max!! else GECKO_MAX_PACKET_SIZE_DEFAULT)
            return if (hi >= lo) lo to hi else lo to lo
        }

        /**
         * Builds a config from a wire `type` string.
         *
         * Null for an empty or unrecognized type, which leaves the caller to
         * decide whether that means "no obfuscation" or "a node this build
         * cannot speak to, skip it". Answering that here would force one of the
         * two, and both are wanted in different places.
         */
        fun make(
            type: String?,
            password: String?,
            geckoMinPacketSize: Int? = null,
            geckoMaxPacketSize: Int? = null
        ): HysteriaObfuscation? {
            if (type.isNullOrEmpty()) return null
            val secret = password ?: ""
            return when (type.lowercase()) {
                "salamander" -> Salamander(secret)
                "gecko" -> {
                    val (lo, hi) = normalizedGeckoSizes(geckoMinPacketSize, geckoMaxPacketSize)
                    Gecko(secret, lo, hi)
                }
                else -> null
            }
        }
    }
}
