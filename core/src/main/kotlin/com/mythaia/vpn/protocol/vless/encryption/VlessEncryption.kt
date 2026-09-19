package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.data.model.ProxyError
import java.util.Base64

/**
 * The wire grammar of the VLESS `encryption`/`decryption` parameter for the
 * post-quantum family, parsed once and carried as a value.
 *
 * This is the negotiation behind `mlkem768x25519plus.<xor>.<rtt>[.<pad>...].<key>[.<key>...]`,
 * not TLS and not Vision: the string names a hybrid ML-KEM-768 + X25519 key
 * exchange, an obfuscation mode, whether a 0-RTT ticket may be replayed, and
 * one or more relay public keys. It is kept apart from the handshake so the
 * grammar can be checked against literal strings without a socket, the way a
 * malformed `encryption=` in a share link should fail loudly rather than
 * silently drop to plaintext.
 *
 * A value is either absent (`"none"` or empty, which [parse] returns as null)
 * or complete: there is no partially-valid state, because a client that
 * misreads which relay key to encapsulate to would hand the server bytes it
 * cannot open and call it a network error.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
data class VlessEncryptionConfig(
    val xorMode: XorMode,
    val rttMode: RttMode,
    /**
     * The padding spec exactly as it arrived, so [encoded] round-trips it; an
     * empty string means the default schedule in [VlessEncryptionPadding].
     */
    val padding: String,
    /**
     * Relay public keys in chain order: 32 bytes is an X25519 key, 1184 an
     * ML-KEM-768 encapsulation key. The last one's shared secret keys the
     * record layer; the earlier ones only bind the relay chain.
     */
    val publicKeys: List<ByteArray>
) {

    /** How the client-hello relay block and record headers are obfuscated. */
    enum class XorMode(val wire: UByte, val token: String) {
        /** No obfuscation: the relay block and headers travel in the clear. */
        NATIVE(0u, "native"),

        /** The relay block is CTR-masked with each relay's own public key. */
        XORPUB(1u, "xorpub"),

        /** Relay block masking plus a running CTR mask over every record header. */
        RANDOM(2u, "random");

        companion object {
            fun fromToken(token: String): XorMode? = entries.find { it.token == token }
        }
    }

    /** Whether a resumption ticket may be replayed to skip a round trip. */
    enum class RttMode(val token: String) {
        ONE_RTT("1rtt"),
        ZERO_RTT("0rtt")
    }

    /**
     * The `Account.Seconds` wire value: 1 requests 0-RTT resumption, 0 asks for
     * none. The server still decides the actual ticket lifetime; this only says
     * whether the client will try to cache and replay one at all.
     */
    val seconds: UInt
        get() = if (rttMode == RttMode.ZERO_RTT) 1u else 0u

    /**
     * Re-serialises to the exact grammar [parse] accepts, so a parsed config
     * keys the 0-RTT cache by the same string it was dialled with.
     */
    fun encoded(): String {
        val parts = mutableListOf(SCHEME, xorMode.token, rttMode.token)
        if (padding.isNotEmpty()) parts.add(padding)
        for (key in publicKeys) parts.add(base64UrlEncode(key))
        return parts.joinToString(".")
    }

    // Data class equals/hashCode ignore array identity, so they are written by
    // hand: two configs are the same negotiation only if their keys match byte
    // for byte, which is also what makes the cache key stable.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VlessEncryptionConfig) return false
        return xorMode == other.xorMode &&
            rttMode == other.rttMode &&
            padding == other.padding &&
            publicKeys.size == other.publicKeys.size &&
            publicKeys.indices.all { publicKeys[it].contentEquals(other.publicKeys[it]) }
    }

    override fun hashCode(): Int {
        var result = xorMode.hashCode()
        result = 31 * result + rttMode.hashCode()
        result = 31 * result + padding.hashCode()
        for (key in publicKeys) result = 31 * result + key.contentHashCode()
        return result
    }

    companion object {
        const val SCHEME = "mlkem768x25519plus"

        /** X25519 public keys are 32 bytes on the wire. */
        const val X25519_KEY_LENGTH = 32

        /** ML-KEM-768 encapsulation keys are 1184 bytes on the wire. */
        const val MLKEM768_KEY_LENGTH = 1184

        /**
         * A segment shorter than this is read as a padding spec; longer is a
         * base64url key. A base64 key is never this short (32 raw bytes is 43
         * characters), and a padding triple like `100-111-1111` is never this
         * long — the same threshold the reference uses to tell them apart.
         */
        private const val PADDING_SEGMENT_MAX_LENGTH = 20

        /**
         * Parses [string], returning null for the `"none"`/empty sentinels and
         * throwing [ProxyError.InvalidUrl] for anything else malformed rather
         * than silently downgrading to plaintext.
         */
        fun parse(string: String): VlessEncryptionConfig? {
            if (string.isEmpty() || string == "none") return null

            // Empty subsequences are kept: a trailing or doubled dot is a
            // malformed spec, not something to quietly compact away.
            val segments = string.split(".")
            if (segments.size < 4) {
                throw ProxyError.InvalidUrl("VLESS encryption: too few fields")
            }
            if (segments[0] != SCHEME) {
                throw ProxyError.InvalidUrl("VLESS encryption: unsupported scheme ${segments[0]}")
            }

            val xorMode = XorMode.fromToken(segments[1])
                ?: throw ProxyError.InvalidUrl("VLESS encryption: invalid xorMode ${segments[1]}")

            val rttMode = when (segments[2]) {
                "1rtt" -> RttMode.ONE_RTT
                "0rtt" -> RttMode.ZERO_RTT
                else -> throw ProxyError.InvalidUrl("VLESS encryption: invalid rttMode ${segments[2]}")
            }

            val paddingSegments = mutableListOf<String>()
            val publicKeys = mutableListOf<ByteArray>()
            for (i in 3 until segments.size) {
                val segment = segments[i]
                if (segment.length < PADDING_SEGMENT_MAX_LENGTH) {
                    paddingSegments.add(segment)
                    continue
                }
                val key = base64UrlDecodeOrNull(segment)
                if (key == null ||
                    (key.size != X25519_KEY_LENGTH && key.size != MLKEM768_KEY_LENGTH)
                ) {
                    throw ProxyError.InvalidUrl("VLESS encryption: invalid publicKey")
                }
                publicKeys.add(key)
            }

            if (publicKeys.isEmpty()) {
                throw ProxyError.InvalidUrl("VLESS encryption: no public keys")
            }

            return VlessEncryptionConfig(
                xorMode = xorMode,
                rttMode = rttMode,
                padding = paddingSegments.joinToString("."),
                publicKeys = publicKeys
            )
        }

        /**
         * Base64url without padding, the alphabet share links use. `java.util`
         * rather than `android.util` so the parser runs unchanged in a unit
         * test, where the Android base64 is a stub that returns nothing.
         */
        private fun base64UrlEncode(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        private fun base64UrlDecodeOrNull(value: String): ByteArray? = try {
            Base64.getUrlDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}

/**
 * The client-hello padding schedule: how many decoy bytes to spend and how long
 * to pause between fragments, so the first flight does not always show the same
 * length and timing to an observer.
 *
 * A spec is a dot-joined run of `prob-min-max` triples that alternate between
 * length rules (even positions) and gap rules (odd positions). The first length
 * rule is held to a floor because a first flight that can shrink below the real
 * client-hello prefix would leak that prefix's size; every other rule is free
 * to roll to zero. Parsing and validation live here, apart from the randomised
 * [materialize] roll, so the grammar and its bounds can be tested without
 * drawing any random numbers.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
data class VlessEncryptionPadding(
    /** (probability%, min, max) byte-count rules, applied in order. */
    val lengths: List<Triple<Int, Int, Int>>,
    /** (probability%, min ms, max ms) inter-fragment sleep rules. */
    val gaps: List<Triple<Int, Int, Int>>
) {

    /**
     * Rolls the schedule into concrete choices for one handshake.
     *
     * @return the total decoy byte count, the per-rule byte counts (the first
     *   fragment absorbs the pre-padding prefix), and the gaps in milliseconds.
     */
    fun materialize(random: java.util.Random = java.util.Random()): Materialized {
        val lens = ArrayList<Int>(lengths.size)
        var total = 0
        for ((prob, lo, hi) in lengths) {
            val length = if (prob >= random.nextInt(100)) randomInRange(random, lo, maxOf(lo, hi)) else 0
            lens.add(length)
            total += length
        }
        val gapList = ArrayList<Long>(gaps.size)
        for ((prob, lo, hi) in gaps) {
            val g = if (prob >= random.nextInt(100)) randomInRange(random, lo, maxOf(lo, hi)) else 0
            gapList.add(g.toLong())
        }
        return Materialized(total, lens, gapList)
    }

    /** One rolled schedule: [totalLength] decoy bytes, per-rule [lengths], [gapsMs] pauses. */
    data class Materialized(
        val totalLength: Int,
        val lengths: List<Int>,
        val gapsMs: List<Long>
    )

    companion object {
        /**
         * The floor the first length rule must clear. Below 35 bytes a decoy
         * fragment could not cover the real client-hello prefix it is meant to
         * hide, so the reference rejects the spec rather than under-padding.
         */
        const val FIRST_LENGTH_FLOOR = 35

        /** 18-byte sealed length frame + the 16-bit maximum body. */
        const val MAX_TOTAL_LENGTH = 18 + 65535

        val DEFAULT = VlessEncryptionPadding(
            lengths = listOf(Triple(100, 111, 1111), Triple(50, 0, 3333)),
            gaps = listOf(Triple(75, 0, 111))
        )

        /**
         * Parses a padding spec, returning [DEFAULT] for the empty string and
         * throwing [VlessEncryptionError.Unsupported] for a malformed one.
         */
        fun parse(raw: String): VlessEncryptionPadding {
            if (raw.isEmpty()) return DEFAULT
            val lengths = mutableListOf<Triple<Int, Int, Int>>()
            val gaps = mutableListOf<Triple<Int, Int, Int>>()
            var totalMaxLen = 0
            raw.split(".").forEachIndexed { i, segment ->
                val parts = segment.split("-")
                val prob = parts.getOrNull(0)?.toIntOrNull()
                val lo = parts.getOrNull(1)?.toIntOrNull()
                val hi = parts.getOrNull(2)?.toIntOrNull()
                if (parts.size < 3 || prob == null || lo == null || hi == null) {
                    throw VlessEncryptionError.Unsupported("invalid padding segment \"$segment\"")
                }
                if (i == 0 && (prob < 100 || lo < FIRST_LENGTH_FLOOR || hi < FIRST_LENGTH_FLOOR)) {
                    throw VlessEncryptionError.Unsupported(
                        "first padding length must be at least $FIRST_LENGTH_FLOOR"
                    )
                }
                if (i % 2 == 0) {
                    lengths.add(Triple(prob, lo, hi))
                    totalMaxLen += maxOf(lo, hi)
                } else {
                    gaps.add(Triple(prob, lo, hi))
                }
            }
            if (totalMaxLen > MAX_TOTAL_LENGTH) {
                throw VlessEncryptionError.Unsupported(
                    "total padding length must not exceed $MAX_TOTAL_LENGTH"
                )
            }
            return VlessEncryptionPadding(lengths, gaps)
        }

        /** Inclusive `[lo, hi]`; the reference draws with the high bound inclusive. */
        private fun randomInRange(random: java.util.Random, lo: Int, hi: Int): Int {
            if (hi <= lo) return lo
            return lo + random.nextInt(hi - lo + 1)
        }
    }
}

/**
 * Failures the post-quantum VLESS encryption layer raises once past the link
 * parse: a handshake that did not agree, a record that did not frame, a peer
 * that hung up, or a feature this port does not carry.
 *
 * Kept distinct from [ProxyError] so a caller can tell a live protocol failure
 * from a malformed share link, and distinct per-case so the record reader can
 * decide (for one 0-RTT reject) to invalidate a ticket rather than surface the
 * error.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
sealed class VlessEncryptionError(message: String) : Exception(message) {
    class HandshakeFailed(detail: String) :
        VlessEncryptionError("VLESS encryption handshake failed: $detail")

    class ProtocolViolation(detail: String) :
        VlessEncryptionError("VLESS encryption protocol violation: $detail")

    class ConnectionClosed(detail: String? = null) :
        VlessEncryptionError("VLESS encryption connection closed" + (detail?.let { ": $it" } ?: ""))

    class Unsupported(feature: String) :
        VlessEncryptionError("VLESS encryption unsupported: $feature")
}
