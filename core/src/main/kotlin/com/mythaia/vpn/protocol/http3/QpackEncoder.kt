package com.mythaia.vpn.protocol.http3

import com.mythaia.vpn.protocol.naive.http2.HpackHuffman
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * QPACK field-section coding for HTTP/3 (RFC 9204).
 *
 * HTTP/3 cannot reuse HPACK because QUIC delivers streams out of order, so
 * QPACK splits compression into a static table plus an optional dynamic table
 * that lives on its own unidirectional streams. This client advertises
 * `SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0`, which means the dynamic table is
 * never populated in either direction: every field line we send resolves
 * against the static table or carries its own bytes, and any dynamic reference
 * arriving from a peer is a protocol violation rather than something to look
 * up. That restriction is what keeps this small enough to be a pure function of
 * bytes, and therefore testable against the RFC's own values.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object QpackEncoder {

    /** The largest value a prefixed integer may carry, 2^62 - 1 (RFC 9204 §4.1.1). */
    const val MAX_INTEGER = 4_611_686_018_427_387_903L

    /** Number of entries in the RFC 9204 Appendix A static table, indexed 0..98. */
    const val STATIC_TABLE_SIZE = 99

    // The handful of static entries this client emits by index. Named because a
    // bare 23 in the middle of a header block is unreadable and, worse, silently
    // wrong if the table is ever misremembered.
    private const val INDEX_AUTHORITY = 0
    private const val INDEX_PATH = 1
    private const val INDEX_METHOD_CONNECT = 15
    private const val INDEX_METHOD_GET = 17
    private const val INDEX_METHOD_POST = 20
    private const val INDEX_SCHEME_HTTPS = 23

    /** A decoded prefixed integer together with the number of bytes it occupied. */
    data class PrefixedInteger(val value: Long, val size: Int)

    // MARK: - Encoding

    /**
     * Encodes the field section of a CONNECT request.
     *
     * Classic CONNECT (RFC 9114 §4.4) carries only `:method` and `:authority`;
     * `:scheme` and `:path` are forbidden there. Supplying [protocolPseudo]
     * switches to extended CONNECT (RFC 9220 §3, and RFC 9298 §3 for UDP
     * proxying), where `:protocol`, `:scheme` and `:path` all become mandatory —
     * which is why they are emitted together rather than as separate options.
     */
    fun encodeConnectHeaders(
        authority: String,
        protocolPseudo: String? = null,
        path: String? = null,
        extraHeaders: List<Pair<String, String>> = emptyList()
    ): ByteArray {
        val block = ByteArrayOutputStream()
        writeFieldSectionPrefix(block)

        block.write(indexedFieldLine(INDEX_METHOD_CONNECT))

        if (protocolPseudo != null) {
            block.write(literalFieldLine(":protocol", protocolPseudo))
            block.write(indexedFieldLine(INDEX_SCHEME_HTTPS))
            block.write(literalFieldLineWithNameReference(INDEX_PATH, path ?: "/"))
        }

        block.write(literalFieldLineWithNameReference(INDEX_AUTHORITY, authority))
        writeExtraHeaders(block, extraHeaders)
        return block.toByteArray()
    }

    /** Encodes the field section of a POST request. */
    fun encodePostHeaders(
        authority: String,
        path: String,
        extraHeaders: List<Pair<String, String>> = emptyList()
    ): ByteArray = encodeRequestHeaders("POST", authority, path, extraHeaders)

    /**
     * Encodes the field section of a request with an arbitrary [method].
     *
     * GET and POST have their own static-table entries and cost one byte each;
     * anything else has to be spelled out, because the static table holds only
     * the seven methods listed in Appendix A and a name reference to one of them
     * would carry the wrong value.
     */
    fun encodeRequestHeaders(
        method: String,
        authority: String,
        path: String,
        extraHeaders: List<Pair<String, String>> = emptyList()
    ): ByteArray {
        val block = ByteArrayOutputStream()
        writeFieldSectionPrefix(block)

        when (method.uppercase()) {
            "GET" -> block.write(indexedFieldLine(INDEX_METHOD_GET))
            "POST" -> block.write(indexedFieldLine(INDEX_METHOD_POST))
            else -> block.write(literalFieldLine(":method", method))
        }
        block.write(indexedFieldLine(INDEX_SCHEME_HTTPS))
        block.write(literalFieldLineWithNameReference(INDEX_AUTHORITY, authority))
        block.write(literalFieldLineWithNameReference(INDEX_PATH, path))

        writeExtraHeaders(block, extraHeaders)
        return block.toByteArray()
    }

    /**
     * The field section prefix (RFC 9204 §4.5.1): Required Insert Count 0 and a
     * Delta Base of 0. Both are prefixed integers rather than QUIC varints, and
     * both are zero for as long as the dynamic table stays empty, so the prefix
     * is a constant two zero bytes.
     */
    private fun writeFieldSectionPrefix(out: ByteArrayOutputStream) {
        out.write(0x00)
        out.write(0x00)
    }

    private fun writeExtraHeaders(out: ByteArrayOutputStream, headers: List<Pair<String, String>>) {
        for ((name, value) in headers) out.write(literalFieldLine(name, value))
    }

    /** Indexed field line (RFC 9204 §4.5.2): `1 T index(6+)`, with T=1 for the static table. */
    private fun indexedFieldLine(index: Int): ByteArray =
        encodePrefixedInteger(index.toLong(), prefixBits = 6, prefix = 0xC0)

    /**
     * Literal field line with name reference (RFC 9204 §4.5.4): `01 N T index(4+)`
     * then the value. N=0 because nothing here is a secret a proxy must not
     * re-index, and T=1 selects the static table.
     */
    private fun literalFieldLineWithNameReference(staticIndex: Int, value: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(encodePrefixedInteger(staticIndex.toLong(), prefixBits = 4, prefix = 0x50))
        out.write(encodeStringLiteral(value))
        return out.toByteArray()
    }

    /**
     * Literal field line with literal name (RFC 9204 §4.5.6): `001 N H len(3+)`
     * then the name, then the value.
     *
     * The name is lowercased because RFC 9114 §4.2 makes an uppercase character
     * in a field name malformed, and callers reasonably pass `Content-Type`.
     */
    private fun literalFieldLine(name: String, value: String): ByteArray {
        val out = ByteArrayOutputStream()
        val nameBytes = name.lowercase().toByteArray(Charsets.UTF_8)
        out.write(encodePrefixedInteger(nameBytes.size.toLong(), prefixBits = 3, prefix = 0x20))
        out.write(nameBytes)
        out.write(encodeStringLiteral(value))
        return out.toByteArray()
    }

    /**
     * String literal (RFC 9204 §4.1.2): an H bit above a 7-bit length prefix,
     * then that many bytes.
     *
     * H is always 0 here. QPACK shares HPACK's Huffman code, and [HpackHuffman]
     * already carries that table, but only as a decoder — and duplicating a
     * 257-entry table to save a few bytes on a header block that is sent once
     * per stream is a poor trade. Sending raw is always legal; the decoder below
     * still accepts H=1 from peers.
     */
    private fun encodeStringLiteral(string: String): ByteArray {
        val bytes = string.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        out.write(encodePrefixedInteger(bytes.size.toLong(), prefixBits = 7, prefix = 0x00))
        out.write(bytes)
        return out.toByteArray()
    }

    // MARK: - Prefixed integers

    /**
     * The QPACK prefixed integer of RFC 9204 §4.1.1: [prefixBits] low bits of the
     * first byte hold the value, and once those bits are all ones the remainder
     * spills into 7-bit continuation bytes, little-endian, high bit set on all
     * but the last. [prefix] supplies the pattern bits above the prefix.
     *
     * This is NOT the QUIC variable-length integer of RFC 9000 §16 that
     * [com.mythaia.vpn.protocol.quic.QuicVarInt] implements, even though the two
     * sit bytes apart on the wire: the HTTP/3 HEADERS frame that carries a field
     * section writes its type and length as QUIC varints, and everything from the
     * first byte of the field section prefix onwards — every index, every string
     * length — uses this form instead. They are not interchangeable and they do
     * not even agree on small values: 15293 is `7b bd` as a QUIC varint and
     * `1f 9e 77` as a 5-bit-prefix QPACK integer. Mixing them up yields a block
     * that decodes into plausible nonsense rather than failing outright, so the
     * two encodings are deliberately kept in separate files.
     */
    fun encodePrefixedInteger(value: Long, prefixBits: Int, prefix: Int): ByteArray {
        require(prefixBits in 1..8) { "prefix must be 1 to 8 bits, was $prefixBits" }
        require(value in 0..MAX_INTEGER) { "integer out of QPACK range: $value" }

        val maxPrefix = (1 shl prefixBits) - 1
        val out = ByteArrayOutputStream()

        if (value < maxPrefix) {
            out.write(prefix or value.toInt())
        } else {
            out.write(prefix or maxPrefix)
            var remaining = value - maxPrefix
            while (remaining >= 128) {
                out.write(((remaining and 0x7FL) or 0x80L).toInt())
                remaining = remaining ushr 7
            }
            out.write(remaining.toInt())
        }
        return out.toByteArray()
    }

    /**
     * Reads a prefixed integer at [offset], or null when the buffer stops short
     * or the value cannot be represented.
     *
     * Null rather than an exception because everything reaching here arrived
     * over the network: a truncated or absurd integer is input to reject, not an
     * exceptional condition. Room is checked before each shift so that a hostile
     * run of continuation bytes cannot wrap a [Long] into a small positive value.
     */
    fun decodePrefixedInteger(data: ByteArray, offset: Int, prefixBits: Int): PrefixedInteger? {
        if (prefixBits !in 1..8) return null
        if (offset < 0 || offset >= data.size) return null

        val mask = (1 shl prefixBits) - 1
        val first = data[offset].toInt() and mask
        if (first < mask) return PrefixedInteger(first.toLong(), 1)

        var value = mask.toLong()
        var shift = 0
        var position = offset + 1
        while (position < data.size) {
            val byte = data[position].toInt() and 0xFF
            val addend = (byte and 0x7F).toLong()
            if (shift > 62 || (MAX_INTEGER ushr shift) < addend) return null
            val shifted = addend shl shift
            if (MAX_INTEGER - shifted < value) return null
            value += shifted
            position++
            if (byte and 0x80 == 0) return PrefixedInteger(value, position - offset)
            shift += 7
        }
        return null
    }

    // MARK: - Decoding

    /**
     * Decodes a field section, or null if it is malformed or references the
     * dynamic table.
     *
     * A dynamic reference is refused rather than ignored: we advertised a table
     * capacity of zero, so a peer that sends one has either lost track of the
     * connection state or is trying to desynchronise us, and neither is
     * something to paper over by dropping a field line the caller will then
     * assume was absent.
     */
    fun decodeHeaders(data: ByteArray): List<Pair<String, String>>? {
        if (data.size < 2) return null

        val headers = mutableListOf<Pair<String, String>>()
        var offset = 0

        // Required Insert Count, an 8-bit prefix integer, must be zero for us.
        val requiredInsertCount = decodePrefixedInteger(data, offset, prefixBits = 8) ?: return null
        if (requiredInsertCount.value != 0L) return null
        offset += requiredInsertCount.size

        // Delta Base: a sign bit above a 7-bit prefix. With no dynamic table the
        // base is always zero, so only the field's width matters here.
        if (offset >= data.size) return null
        val deltaBase = decodePrefixedInteger(data, offset, prefixBits = 7) ?: return null
        offset += deltaBase.size

        while (offset < data.size) {
            val first = data[offset].toInt() and 0xFF

            when {
                first and 0x80 != 0 -> {
                    // Indexed field line: 1 T index(6+). T=0 is the dynamic table.
                    if (first and 0x40 == 0) return null
                    val index = decodePrefixedInteger(data, offset, prefixBits = 6) ?: return null
                    offset += index.size
                    headers += staticTableEntry(index.value) ?: return null
                }

                first and 0x40 != 0 -> {
                    // Literal with name reference: 01 N T index(4+) value.
                    if (first and 0x10 == 0) return null
                    val nameIndex = decodePrefixedInteger(data, offset, prefixBits = 4) ?: return null
                    offset += nameIndex.size
                    val name = staticTableEntry(nameIndex.value)?.first ?: return null
                    val value = decodeStringLiteral(data, offset) ?: return null
                    offset += value.size
                    headers += name to value.text
                }

                first and 0x20 != 0 -> {
                    // Literal with literal name: 001 N H nameLen(3+) name value.
                    val nameIsHuffman = first and 0x08 != 0
                    val nameLength = decodePrefixedInteger(data, offset, prefixBits = 3) ?: return null
                    offset += nameLength.size
                    val name = readText(data, offset, nameLength.value, nameIsHuffman) ?: return null
                    offset += nameLength.value.toInt()
                    val value = decodeStringLiteral(data, offset) ?: return null
                    offset += value.size
                    headers += name to value.text
                }

                else -> {
                    // 0001xxxx and 0000xxxx are the post-base forms, which exist
                    // only to reference entries inserted after the base.
                    return null
                }
            }
        }

        return headers
    }

    /** A decoded string literal and the number of bytes it occupied, length prefix included. */
    private data class Text(val text: String, val size: Int)

    private fun decodeStringLiteral(data: ByteArray, offset: Int): Text? {
        if (offset < 0 || offset >= data.size) return null
        val huffman = data[offset].toInt() and 0x80 != 0
        val length = decodePrefixedInteger(data, offset, prefixBits = 7) ?: return null
        val start = offset + length.size
        val text = readText(data, start, length.value, huffman) ?: return null
        return Text(text, length.size + length.value.toInt())
    }

    private fun readText(data: ByteArray, offset: Int, length: Long, huffman: Boolean): String? {
        if (offset < 0 || length < 0 || length > (data.size - offset).toLong()) return null
        val slice = data.copyOfRange(offset, offset + length.toInt())
        // QPACK reuses HPACK's Huffman code verbatim (RFC 9204 §4.1.2 points at
        // RFC 7541 Appendix B), so the HTTP/2 table is the same table.
        val bytes = if (huffman) (HpackHuffman.decode(slice) ?: return null) else slice
        return decodeUtf8(bytes)
    }

    /**
     * Strict UTF-8: ill-formed bytes are rejected instead of turning into
     * replacement characters, because a field name or value that silently
     * mutates is worse than a connection that fails.
     */
    private fun decodeUtf8(bytes: ByteArray): String? = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }

    // MARK: - Static table

    /** The entry at [index], or null if [index] is outside RFC 9204 Appendix A. */
    fun staticTableEntry(index: Int): Pair<String, String>? = STATIC_TABLE.getOrNull(index)

    private fun staticTableEntry(index: Long): Pair<String, String>? =
        if (index in 0 until STATIC_TABLE_SIZE.toLong()) STATIC_TABLE[index.toInt()] else null

    /**
     * RFC 9204 Appendix A, complete and in index order.
     *
     * The whole table is here rather than the subset this client encodes with,
     * because a peer may reference any of it — an origin server commonly indexes
     * `content-type` at 44 or names `user-agent` at 95 — and an entry we cannot
     * resolve is a field line that would go missing from a decoded response.
     * Note that the values are inconsistent about whitespace (52 has a space
     * after the semicolon, 54 does not); they are reproduced exactly, since they
     * are compared as bytes.
     */
    private val STATIC_TABLE: List<Pair<String, String>> = listOf(
        ":authority" to "",                                                     // 0
        ":path" to "/",                                                         // 1
        "age" to "0",                                                           // 2
        "content-disposition" to "",                                            // 3
        "content-length" to "0",                                                // 4
        "cookie" to "",                                                         // 5
        "date" to "",                                                           // 6
        "etag" to "",                                                           // 7
        "if-modified-since" to "",                                              // 8
        "if-none-match" to "",                                                  // 9
        "last-modified" to "",                                                  // 10
        "link" to "",                                                           // 11
        "location" to "",                                                       // 12
        "referer" to "",                                                        // 13
        "set-cookie" to "",                                                     // 14
        ":method" to "CONNECT",                                                 // 15
        ":method" to "DELETE",                                                  // 16
        ":method" to "GET",                                                     // 17
        ":method" to "HEAD",                                                    // 18
        ":method" to "OPTIONS",                                                 // 19
        ":method" to "POST",                                                    // 20
        ":method" to "PUT",                                                     // 21
        ":scheme" to "http",                                                    // 22
        ":scheme" to "https",                                                   // 23
        ":status" to "103",                                                     // 24
        ":status" to "200",                                                     // 25
        ":status" to "304",                                                     // 26
        ":status" to "404",                                                     // 27
        ":status" to "503",                                                     // 28
        "accept" to "*/*",                                                      // 29
        "accept" to "application/dns-message",                                  // 30
        "accept-encoding" to "gzip, deflate, br",                               // 31
        "accept-ranges" to "bytes",                                             // 32
        "access-control-allow-headers" to "cache-control",                      // 33
        "access-control-allow-headers" to "content-type",                       // 34
        "access-control-allow-origin" to "*",                                   // 35
        "cache-control" to "max-age=0",                                         // 36
        "cache-control" to "max-age=2592000",                                   // 37
        "cache-control" to "max-age=604800",                                    // 38
        "cache-control" to "no-cache",                                          // 39
        "cache-control" to "no-store",                                          // 40
        "cache-control" to "public, max-age=31536000",                          // 41
        "content-encoding" to "br",                                             // 42
        "content-encoding" to "gzip",                                           // 43
        "content-type" to "application/dns-message",                            // 44
        "content-type" to "application/javascript",                             // 45
        "content-type" to "application/json",                                   // 46
        "content-type" to "application/x-www-form-urlencoded",                  // 47
        "content-type" to "image/gif",                                          // 48
        "content-type" to "image/jpeg",                                         // 49
        "content-type" to "image/png",                                          // 50
        "content-type" to "text/css",                                           // 51
        "content-type" to "text/html; charset=utf-8",                           // 52
        "content-type" to "text/plain",                                         // 53
        "content-type" to "text/plain;charset=utf-8",                           // 54
        "range" to "bytes=0-",                                                  // 55
        "strict-transport-security" to "max-age=31536000",                      // 56
        "strict-transport-security" to "max-age=31536000; includesubdomains",   // 57
        "strict-transport-security" to
            "max-age=31536000; includesubdomains; preload",                     // 58
        "vary" to "accept-encoding",                                            // 59
        "vary" to "origin",                                                     // 60
        "x-content-type-options" to "nosniff",                                  // 61
        "x-xss-protection" to "1; mode=block",                                  // 62
        ":status" to "100",                                                     // 63
        ":status" to "204",                                                     // 64
        ":status" to "206",                                                     // 65
        ":status" to "302",                                                     // 66
        ":status" to "400",                                                     // 67
        ":status" to "403",                                                     // 68
        ":status" to "421",                                                     // 69
        ":status" to "425",                                                     // 70
        ":status" to "500",                                                     // 71
        "accept-language" to "",                                                // 72
        "access-control-allow-credentials" to "FALSE",                          // 73
        "access-control-allow-credentials" to "TRUE",                           // 74
        "access-control-allow-headers" to "*",                                  // 75
        "access-control-allow-methods" to "get",                                // 76
        "access-control-allow-methods" to "get, post, options",                 // 77
        "access-control-allow-methods" to "options",                            // 78
        "access-control-expose-headers" to "content-length",                    // 79
        "access-control-request-headers" to "content-type",                     // 80
        "access-control-request-method" to "get",                               // 81
        "access-control-request-method" to "post",                              // 82
        "alt-svc" to "clear",                                                   // 83
        "authorization" to "",                                                  // 84
        "content-security-policy" to
            "script-src 'none'; object-src 'none'; base-uri 'none'",            // 85
        "early-data" to "1",                                                    // 86
        "expect-ct" to "",                                                      // 87
        "forwarded" to "",                                                      // 88
        "if-range" to "",                                                       // 89
        "origin" to "",                                                         // 90
        "purpose" to "prefetch",                                                // 91
        "server" to "",                                                         // 92
        "timing-allow-origin" to "*",                                           // 93
        "upgrade-insecure-requests" to "1",                                     // 94
        "user-agent" to "",                                                     // 95
        "x-forwarded-for" to "",                                                // 96
        "x-frame-options" to "deny",                                            // 97
        "x-frame-options" to "sameorigin",                                      // 98
    )
}
