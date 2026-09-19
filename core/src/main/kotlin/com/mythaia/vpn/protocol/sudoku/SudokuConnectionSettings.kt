package com.mythaia.vpn.protocol.sudoku

import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Everything a Sudoku carrier needs to know before it opens a socket, resolved
 * once from the profile so the data path never re-derives it.
 *
 * Several of these fields are not simply what the user typed. [psk] is the
 * *public* key the tunnel actually shares: a Sudoku key may be given as a 32-byte
 * public key, a 64-byte expanded private key, or a passphrase, and both key forms
 * have to reduce to the same string or the two ends derive different record keys —
 * so a hex key is run through [SudokuKeyRecovery] here. [keyFingerprintSource] is
 * the material whose digest goes in the client hello, and it is deliberately *not*
 * the same as [psk]: for a hex key it is the raw private bytes, so the server can
 * recognise the account without the public key alone giving it away.
 *
 * [selectedCustomTable] resolves the per-connection choice among several custom
 * layouts, and [sendsTableHint] records whether the client hello must tell the
 * server which one was picked — with zero or one layout both sides already agree.
 *
 * This is the analog of the reference's `SudokuNativeConfig`; the JSON plumbing
 * that produces a [SudokuConfiguration] lives with the rest of the app's
 * configuration layer, and is fed to [of] alongside the server address.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class SudokuConnectionSettings(
    val serverHost: String,
    val serverPort: Int,
    val psk: String,
    val keyFingerprintSource: ByteArray,
    val aeadMethod: SudokuAeadMethod,
    val paddingMin: Int,
    val paddingMax: Int,
    val asciiMode: SudokuAsciiMode,
    val selectedCustomTable: String,
    val sendsTableHint: Boolean,
    val pureDownlink: Boolean,
    /**
     * The decoy HTTP request written ahead of the obfuscated stream in legacy
     * mask mode, or null when no camouflage prefix is sent. It is a plaintext
     * prefix — it does not ride the obfuscation — so it is stored as bytes ready
     * to hand straight to the raw transport.
     */
    val legacyMaskHeader: ByteArray?
) {

    /**
     * The two codebooks this connection encodes and decodes with.
     *
     * Built lazily and shared through [SudokuTableStore]: constructing a pair
     * shuffles a deck of 288 grids and enumerates every unique clue set, which
     * costs a few milliseconds — far too much to pay per dial when a profile
     * opens many connections, and safe to share because a pair is immutable once
     * built.
     */
    val tablePair: SudokuTablePair
        get() = SudokuTableStore.pairFor(psk, asciiMode, selectedCustomTable)

    companion object {
        /**
         * Resolves the carrier settings for a Sudoku profile.
         *
         * [serverPort] is taken already widened to an [Int] so the caller keeps
         * ownership of the profile's own port type. The custom-layout choice is
         * made here, once, because it must be stable for the life of the
         * connection: the table hint in the hello and the tables the stream uses
         * have to name the same layout.
         */
        fun of(serverHost: String, serverPort: Int, sudoku: SudokuConfiguration): SudokuConnectionSettings {
            // A hex key is either a bare public key or an expanded private key; a
            // passphrase is anything that is not 32 or 64 hex bytes. The private
            // bytes, when present, are what the fingerprint is taken over.
            val rawKey = decodeHex(sudoku.key)
            val privateKeyBytes = rawKey?.takeIf { it.size == 32 || it.size == 64 }
            val psk = SudokuKeyRecovery.recoverPublicKeyHex(sudoku.key) ?: sudoku.key
            val fingerprintSource = privateKeyBytes ?: sudoku.key.toByteArray(Charsets.UTF_8)

            val tables = sudoku.customTables
            val selected = when {
                tables.isEmpty() -> ""
                tables.size == 1 -> tables[0]
                // More than one: the client picks one per connection and tells
                // the server which by the hint in its hello.
                else -> tables[SecureRandom().nextInt(tables.size)]
            }

            val legacyHeader = legacyMaskHeader(serverHost, sudoku.httpMask)

            return SudokuConnectionSettings(
                serverHost = serverHost,
                serverPort = serverPort,
                psk = psk,
                keyFingerprintSource = fingerprintSource,
                aeadMethod = sudoku.aeadMethod,
                paddingMin = sudoku.paddingMin,
                paddingMax = sudoku.paddingMax,
                asciiMode = sudoku.asciiMode,
                selectedCustomTable = selected,
                sendsTableHint = sudoku.sendsTableHint,
                pureDownlink = sudoku.enablePureDownlink,
                legacyMaskHeader = legacyHeader
            )
        }

        /**
         * The decoy request for legacy HTTP-mask mode, or null when no prefix is
         * due.
         *
         * A prefix is sent only when masking is on and set to the legacy mode,
         * which is the one that fronts the obfuscated stream with a single long
         * POST rather than framing it as HTTP. The TLS carrier and the other mask
         * modes are refused before settings are built, so they never reach here.
         */
        private fun legacyMaskHeader(serverHost: String, mask: SudokuHttpMaskConfiguration): ByteArray? {
            if (mask.disable || mask.mode != SudokuHttpMaskMode.LEGACY) return null
            val host = mask.host.ifEmpty { serverHost }
            val path = SudokuProtocol.applyPathRoot(mask.pathRoot, "/api")
            val request = "POST $path HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: keep-alive\r\n" +
                "Content-Type: application/octet-stream\r\n" +
                "Content-Length: 1048576\r\n\r\n"
            return request.toByteArray(Charsets.US_ASCII)
        }

        /** Decodes an even-length hex string, or null when it is not hex at all. */
        private fun decodeHex(text: String): ByteArray? {
            if (text.isEmpty() || text.length % 2 != 0) return null
            val out = ByteArray(text.length / 2)
            for (i in out.indices) {
                val high = Character.digit(text[i * 2], 16)
                val low = Character.digit(text[i * 2 + 1], 16)
                if (high < 0 || low < 0) return null
                out[i] = ((high shl 4) or low).toByte()
            }
            return out
        }
    }
}

/**
 * A small cache of table pairs, keyed by everything that shapes them.
 *
 * A [SudokuTablePair] is expensive to build and immutable once built, so it is
 * kept rather than rebuilt for every connection of the same profile. The cache is
 * bounded: a client that cycled through many keys could otherwise hold a pair for
 * each forever, and dropping the whole map when it grows is safe precisely because
 * a live connection already holds its own reference to the pair it uses.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object SudokuTableStore {

    private const val MAX_ENTRIES = 16

    private val pairs = ConcurrentHashMap<String, SudokuTablePair>()

    fun pairFor(psk: String, asciiMode: SudokuAsciiMode, customTable: String): SudokuTablePair {
        val key = "$psk\u0000${asciiMode.id}\u0000$customTable"
        pairs[key]?.let { return it }
        if (pairs.size >= MAX_ENTRIES) pairs.clear()
        return pairs.getOrPut(key) {
            SudokuTablePair(
                key = psk,
                asciiMode = asciiMode,
                customUplink = customTable,
                customDownlink = customTable
            )
        }
    }
}
