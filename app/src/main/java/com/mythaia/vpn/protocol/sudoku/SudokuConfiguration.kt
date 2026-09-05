package com.mythaia.vpn.protocol.sudoku

/**
 * The settings a Sudoku outbound is described by.
 *
 * Every field here changes what goes on the wire, which is why the values are
 * normalised the moment a configuration is built rather than at each use: the
 * table fingerprint is a hash of the mode and the custom patterns, so a stray
 * space or a different letter case in a subscription link would otherwise
 * derive a different set of tables than the server built and nothing would
 * decode.
 *
 * The reference reads these out of JSON with several legacy spellings. The
 * spellings are preserved as the enums' [SudokuAeadMethod.id] and friends, and
 * the tolerant parsers below accept what the legacy fields carried, but the
 * JSON plumbing itself lives with the rest of this app's configuration layer.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuConfiguration(
    key: String,
    val aeadMethod: SudokuAeadMethod = SudokuAeadMethod.CHACHA20_POLY1305,
    paddingMin: Int = DEFAULT_PADDING_MIN,
    paddingMax: Int = DEFAULT_PADDING_MAX,
    val asciiMode: SudokuAsciiMode = SudokuAsciiMode.PREFER_ENTROPY,
    customTables: List<String> = emptyList(),
    /**
     * Whether the server may send the downlink as whole Sudoku puzzles rather
     * than packed six-bit groups. It costs four wire bytes per byte instead of
     * four per three, and buys a downlink that looks like the uplink.
     */
    val enablePureDownlink: Boolean = true,
    val multiplex: SudokuMultiplex = SudokuMultiplex.OFF,
    val httpMask: SudokuHttpMaskConfiguration = SudokuHttpMaskConfiguration()
) {
    /** The pre-shared key, or an Ed25519 private key in hex. */
    val key: String = key.trim()

    /** Percentage of positions that get a padding byte, at the low end. */
    val paddingMin: Int = paddingMin.coerceIn(0, 100)

    /**
     * The high end of the same range.
     *
     * A maximum below the minimum is raised to it rather than rejected, so a
     * hand-edited configuration degrades to a fixed padding rate instead of
     * failing to connect.
     */
    val paddingMax: Int = paddingMax.coerceIn(this.paddingMin, 100)

    /**
     * Bit patterns for custom wire layouts, in preference order.
     *
     * More than one entry means the client picks one per connection and tells
     * the server which by sending the table fingerprint in its client hello;
     * with a single entry both sides already agree and no fingerprint is sent.
     */
    val customTables: List<String> = normalizeCustomTables(customTables)

    /** Whether a client hello for this configuration carries a table hint. */
    val sendsTableHint: Boolean get() = customTables.size > 1

    companion object {
        const val DEFAULT_PADDING_MIN = 5
        const val DEFAULT_PADDING_MAX = 15

        /**
         * Drops blank and repeated patterns, keeping the order they were given
         * in, and falls back to [legacy] — the older single-table field — only
         * when nothing usable came from the plural one.
         */
        fun normalizeCustomTables(tables: List<String>, legacy: String = ""): List<String> {
            val normalized = tables.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
            if (normalized.isNotEmpty()) return normalized
            val trimmedLegacy = legacy.trim()
            return if (trimmedLegacy.isEmpty()) emptyList() else listOf(trimmedLegacy)
        }
    }
}

/** The AEAD that protects each record. */
enum class SudokuAeadMethod(val id: String, val displayName: String) {
    CHACHA20_POLY1305("chacha20-poly1305", "ChaCha20-Poly1305"),
    AES_128_GCM("aes-128-gcm", "AES-128-GCM"),

    /**
     * No record layer at all: the obfuscated stream carries the payload
     * directly. Only useful when something else already provides secrecy.
     */
    NONE("none", "None");

    companion object {
        fun fromId(value: String): SudokuAeadMethod? =
            entries.firstOrNull { it.id == value.trim().lowercase() }
    }
}

/**
 * Which wire layout each direction uses.
 *
 * The ASCII layout keeps every byte inside the printable range, which survives
 * middleboxes that expect text but is visibly not random; the entropy layout
 * spreads bytes over the whole octet space. The mixed modes exist because the
 * two directions are often inspected differently.
 */
enum class SudokuAsciiMode(val id: String, val displayName: String) {
    PREFER_ENTROPY("prefer_entropy", "Prefer Entropy"),
    PREFER_ASCII("prefer_ascii", "Prefer ASCII"),
    UP_ASCII_DOWN_ENTROPY("up_ascii_down_entropy", "Up ASCII / Down Entropy"),
    UP_ENTROPY_DOWN_ASCII("up_entropy_down_ascii", "Up Entropy / Down ASCII");

    /** The layout token for client-to-server traffic: `ascii` or `entropy`. */
    val uplinkToken: String
        get() = when (this) {
            PREFER_ASCII, UP_ASCII_DOWN_ENTROPY -> SudokuProtocol.LAYOUT_ASCII
            PREFER_ENTROPY, UP_ENTROPY_DOWN_ASCII -> SudokuProtocol.LAYOUT_ENTROPY
        }

    /** The same for server-to-client traffic. */
    val downlinkToken: String
        get() = when (this) {
            PREFER_ASCII, UP_ENTROPY_DOWN_ASCII -> SudokuProtocol.LAYOUT_ASCII
            PREFER_ENTROPY, UP_ASCII_DOWN_ENTROPY -> SudokuProtocol.LAYOUT_ENTROPY
        }

    /** The abbreviation a share link uses for the two symmetric modes. */
    val shortLinkToken: String
        get() = when (this) {
            PREFER_ENTROPY -> "entropy"
            PREFER_ASCII -> "ascii"
            UP_ASCII_DOWN_ENTROPY, UP_ENTROPY_DOWN_ASCII -> id
        }

    companion object {
        /**
         * Parses a mode, accepting the abbreviations share links use and
         * treating an empty value as the default.
         *
         * Returns null for anything else, because an unrecognised mode would
         * otherwise silently become the default and derive tables the server
         * does not share.
         */
        fun fromNormalized(value: String): SudokuAsciiMode? =
            when (val raw = value.trim().lowercase()) {
                "", "entropy", PREFER_ENTROPY.id -> PREFER_ENTROPY
                "ascii", PREFER_ASCII.id -> PREFER_ASCII
                else -> entries.firstOrNull { it.id == raw }
            }
    }
}

/** How the obfuscated stream is dressed up as HTTP, if at all. */
enum class SudokuHttpMaskMode(val id: String, val displayName: String) {
    /** A single long POST whose body is the stream. */
    LEGACY("legacy", "Legacy"),
    STREAM("stream", "Stream"),
    POLL("poll", "Poll"),

    /** Try [STREAM]; fall back to [POLL] when it does not come up. */
    AUTO("auto", "Auto"),
    WS("ws", "WebSocket");

    companion object {
        fun fromId(value: String): SudokuHttpMaskMode? =
            entries.firstOrNull { it.id == value.trim().lowercase() }
    }
}

/** Whether several proxied streams share one Sudoku connection. */
enum class SudokuMultiplex(val id: String) {
    OFF("off"),
    AUTO("auto"),
    ON("on");

    val displayName: String get() = id.uppercase()

    companion object {
        /** Anything unrecognised means off, which is what the reference does. */
        fun fromNormalized(value: String): SudokuMultiplex =
            when (value.trim().lowercase()) {
                AUTO.id -> AUTO
                ON.id -> ON
                else -> OFF
            }
    }
}

/**
 * The HTTP camouflage settings.
 *
 * [host] overrides the `Host` header, and [pathRoot] prefixes every request
 * path so one server can host the tunnel under an innocuous-looking directory.
 */
class SudokuHttpMaskConfiguration(
    val disable: Boolean = false,
    val mode: SudokuHttpMaskMode = SudokuHttpMaskMode.LEGACY,
    val tls: Boolean = false,
    host: String = "",
    pathRoot: String = ""
) {
    val host: String = host.trim()
    val pathRoot: String = normalizePathRoot(pathRoot)

    companion object {
        /**
         * Strips surrounding whitespace and slashes, and rejects anything that
         * is not a single unreserved path segment.
         *
         * A rejected root becomes the empty string rather than an error: the
         * root is decoration, and refusing to connect over a mistyped one
         * would be worse than serving the tunnel from the default paths.
         */
        fun normalizePathRoot(raw: String): String {
            val trimmed = raw.trim().trim('/')
            if (trimmed.isEmpty()) return ""
            val allowed = trimmed.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-' }
            return if (allowed) trimmed else ""
        }
    }
}
