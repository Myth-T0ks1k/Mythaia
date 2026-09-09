package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import org.brotli.dec.BrotliInputStream

/**
 * Thrown when an HTTP/1.1 message cannot be read as well-formed, or carries a
 * framing ambiguity a request smuggler could exploit (two `Content-Length`
 * values, `Content-Length` alongside `Transfer-Encoding`, a chunk size that is
 * not hex, …). The bridge fails the connection closed on this rather than
 * guessing a framing and desynchronising the two legs.
 */
class Http1ProtocolException(message: String) : Exception(message)

/**
 * An HTTP/1.1 message as it came off the wire, bundled with what the codec needs
 * to re-frame it on the way out.
 *
 * [message] is what a rewrite rule reads and edits: its body is already
 * de-chunked and decompressed, its headers are in wire order. The other fields
 * record how the body arrived so [Http1Codec.serialize] can make the one
 * decision the rewriter cannot: an **untouched** compressed body is forwarded
 * byte-for-byte with its original `Content-Encoding` intact (re-compressing it
 * would be wasteful and lossy), while a **modified** body is forwarded
 * decompressed with `Content-Encoding` dropped, because the edited plaintext no
 * longer matches the original coding.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class ParsedHttp1Message internal constructor(
    /** The message a rule sees: head in wire order, body de-chunked and decompressed. */
    val message: HttpMessage,
    /**
     * The body exactly as received after de-chunking but **before**
     * decompression — i.e. still `Content-Encoding`-compressed when the response
     * was. Forwarded verbatim when a rule left the body untouched.
     */
    val rawBody: ByteArray,
    /** The original `Content-Encoding` header value (all values joined), or null. */
    val contentEncoding: String?,
    /** True when `Content-Encoding` named a real (non-identity) coding. */
    val hadContentCoding: Boolean,
    /**
     * True when [rawBody] was actually decompressed into [message]'s body. False
     * when there was no coding, or the coding was unsupported / failed / would
     * exceed the decompressed cap — in which case [message]'s body *is* [rawBody]
     * and the bridge must treat it as passthrough (not offer it to body rules).
     */
    val bodyWasDecoded: Boolean
)

/**
 * Reads an HTTP/1.1 request or response off a [MitmByteLeg] into an
 * [HttpMessage], and serialises an [HttpMessage] back to HTTP/1.1 wire bytes.
 *
 * This is the framing half of the MITM bridge and it is pure of sockets: it
 * talks only to the [MitmByteLeg] abstraction, so a unit test drives it with an
 * in-memory double. What it owns:
 *
 *  - **Request-target reconstruction.** An origin-form target (`/path`) plus the
 *    `Host` header becomes an absolute `https://host/path`; an absolute-form
 *    target is honoured as-is. The absolute URL is what a rule's `url-pattern`
 *    matches against.
 *  - **Body framing, read side.** `Content-Length`, `Transfer-Encoding: chunked`
 *    (trailers consumed and dropped), and — for a response with neither — the
 *    HTTP/1.0 "read until the peer closes" delimiter. A request with neither has
 *    an empty body. Conflicting framing is rejected as smuggling.
 *  - **Body framing, write side.** A fresh `Content-Length` is always emitted and
 *    `Transfer-Encoding` is always dropped, so the downstream leg gets a simple,
 *    unambiguous frame regardless of how the body arrived.
 *  - **Content coding.** `gzip`/`deflate`/`br` bodies are decompressed for the
 *    rewriter (see [ParsedHttp1Message]), under a hard [MAX_BUFFERED_BODY_BYTES]
 *    cap on the decompressed size so a decompression bomb cannot exhaust memory.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class Http1Codec(
    /** The scheme stamped onto a reconstructed request URL; `https` for a TLS MITM. */
    private val scheme: String = "https",
    private val logger: MythaiaLogger = MythaiaLogger("Http1Codec")
) {

    // MARK: - Reading

    /**
     * Reads one HTTP/1.1 request, or `null` at a clean end of stream before any
     * bytes of a request arrived. Any bytes read past the body (a pipelined next
     * request) are pushed back onto [leg] for the following read.
     *
     * @throws Http1ProtocolException on a malformed or smuggling-shaped request.
     */
    suspend fun readRequest(leg: MitmByteLeg): ParsedHttp1Message? {
        val reader = LegReader(leg)
        val lines = reader.readHead() ?: return null

        val startLine = lines[0]
        val tokens = startLine.split(" ")
        if (tokens.size != 3) {
            throw Http1ProtocolException("malformed request line: \"$startLine\"")
        }
        val method = tokens[0]
        val target = tokens[1]
        if (!HttpHeader.isValidName(method)) {
            throw Http1ProtocolException("invalid request method token: \"$method\"")
        }
        // CONNECT is a tunnel-establishment verb, not a message the bridge rewrites;
        // letting it through the origin-form reconstruction would mislabel an
        // authority-form target as a path. Reject it up front.
        if (method.equals("CONNECT", ignoreCase = true)) {
            throw Http1ProtocolException("CONNECT is not a rewritable HTTP/1.1 message")
        }

        val headers = parseHeaders(lines)
        val host = firstHeaderValue(headers, "Host")?.trim()
        val url = reconstructRequestUrl(target, host)

        val framing = requestFraming(headers)
        val rawBody = readBody(reader, framing)
        reader.pushBackRemainder()

        return buildParsed(
            phase = HttpPhase.REQUEST,
            method = method,
            url = url,
            version = WIRE_VERSION,
            status = null,
            headers = headers,
            rawBody = rawBody
        )
    }

    /**
     * Reads one HTTP/1.1 response, or `null` at a clean end of stream before any
     * bytes of a response arrived.
     *
     * [requestMethod] decides the no-body cases the status code alone cannot — a
     * response to `HEAD` has no body however it is framed. [requestUrl] is the
     * originating request's URL, which response-phase rules match against and
     * which is stamped onto the returned message (response heads carry no path).
     *
     * @throws Http1ProtocolException on a malformed or smuggling-shaped response.
     */
    suspend fun readResponse(
        leg: MitmByteLeg,
        requestMethod: String?,
        requestUrl: String?
    ): ParsedHttp1Message? {
        val reader = LegReader(leg)
        val lines = reader.readHead() ?: return null

        val startLine = lines[0]
        val tokens = startLine.split(" ", limit = 3)
        if (tokens.size < 2 || !tokens[0].startsWith("HTTP/")) {
            throw Http1ProtocolException("malformed status line: \"$startLine\"")
        }
        val version = tokens[0]
        val status = tokens[1].toIntOrNull()
            ?: throw Http1ProtocolException("non-numeric status code: \"${tokens[1]}\"")

        val headers = parseHeaders(lines)
        val framing = responseFraming(status, requestMethod, headers)
        val rawBody = readBody(reader, framing)
        // For a connection-delimited body the leg is now at EOF; otherwise push
        // back any pipelined bytes that followed this response.
        reader.pushBackRemainder()

        return buildParsed(
            phase = HttpPhase.RESPONSE,
            method = null,
            url = requestUrl,
            version = version,
            status = status,
            headers = headers,
            rawBody = rawBody
        )
    }

    /** Joins the head lines' bodies into [HttpHeader]s, honouring obs-fold continuations. */
    private fun parseHeaders(lines: List<String>): List<HttpHeader> {
        val headers = ArrayList<HttpHeader>(lines.size)
        // lines[0] is the start line; header lines follow. Obs-fold lines (a
        // leading SP/HTAB) were already merged into their predecessor by the
        // reader, so every line here is "name: value".
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon < 0) {
                throw Http1ProtocolException("header line without a colon: \"$line\"")
            }
            val name = line.substring(0, colon)
            if (!HttpHeader.isValidName(name)) {
                throw Http1ProtocolException("invalid header name: \"$name\"")
            }
            val value = line.substring(colon + 1).trim(' ', '\t')
            headers.add(HttpHeader(name, value))
        }
        return headers
    }

    /**
     * origin-form + `Host` → `scheme://host/path`; absolute-form honoured as-is.
     * Null when no URL can be determined (origin-form with no `Host`, or the
     * asterisk-form `*` that names no resource) — the rewriter treats a null URL
     * as a non-match and fails closed.
     */
    private fun reconstructRequestUrl(target: String, host: String?): String? {
        if (target == "*") return null
        if (target.contains("://")) return target // absolute-form: already whole
        if (host.isNullOrEmpty()) return null
        // origin-form (a path, or anything else) hangs off the authority.
        return "$scheme://$host$target"
    }

    // MARK: - Body framing

    private sealed class Framing {
        object None : Framing()
        data class ContentLength(val length: Int) : Framing()
        object Chunked : Framing()
        object ReadUntilClose : Framing()
    }

    private fun requestFraming(headers: List<HttpHeader>): Framing {
        val (contentLength, transferEncoding) = frameGuards(headers)
        if (transferEncoding != null) {
            if (!transferEncodingIsChunkedOnly(transferEncoding)) {
                throw Http1ProtocolException(
                    "unsupported request Transfer-Encoding (only a lone chunked is handled): \"$transferEncoding\""
                )
            }
            return Framing.Chunked
        }
        if (contentLength != null) {
            val length = contentLength.toInt()
            return if (length == 0) Framing.None else Framing.ContentLength(length)
        }
        return Framing.None
    }

    private fun responseFraming(
        status: Int,
        requestMethod: String?,
        headers: List<HttpHeader>
    ): Framing {
        // A response to HEAD echoes the headers of the GET response, Content-Length
        // included, but carries no body whatever those headers say.
        if (requestMethod?.equals("HEAD", ignoreCase = true) == true) return Framing.None
        if (isNoBodyStatus(status)) return Framing.None

        val (contentLength, transferEncoding) = frameGuards(headers)
        if (transferEncoding != null) {
            if (!transferEncodingIsChunkedOnly(transferEncoding)) {
                // A content-coding layered on chunked (e.g. "gzip, chunked") would
                // leave the body compressed after de-chunking; rather than drop the
                // coding and mislabel it as identity, fail closed on the response.
                throw Http1ProtocolException(
                    "unsupported response Transfer-Encoding (only a lone chunked is handled): \"$transferEncoding\""
                )
            }
            return Framing.Chunked
        }
        if (contentLength != null) {
            val length = contentLength.toInt()
            return if (length == 0) Framing.None else Framing.ContentLength(length)
        }
        // No length and no chunking: the body runs until the peer closes (HTTP/1.0
        // style, or a server that simply omitted the framing).
        return Framing.ReadUntilClose
    }

    /**
     * The anti-smuggling gate over the two framing headers, returning the single
     * clean `Content-Length` and the single `Transfer-Encoding` (either may be
     * null). Rejects the ambiguities a desync attack is built on.
     */
    private fun frameGuards(headers: List<HttpHeader>): Pair<String?, String?> {
        val contentLengths = headerValues(headers, "Content-Length").map { it.trim() }
        val transferEncodings = headerValues(headers, "Transfer-Encoding")

        if (contentLengths.isNotEmpty() && transferEncodings.isNotEmpty()) {
            throw Http1ProtocolException("both Content-Length and Transfer-Encoding present")
        }

        val contentLength: String? = if (contentLengths.isEmpty()) {
            null
        } else {
            // More than one Content-Length field is a desync vector even when the
            // values agree, so reject the duplicate rather than pick one.
            if (contentLengths.size > 1) {
                throw Http1ProtocolException("multiple Content-Length headers: $contentLengths")
            }
            if (!isCleanContentLength(contentLengths[0])) {
                throw Http1ProtocolException("malformed Content-Length: \"${contentLengths[0]}\"")
            }
            // A clean value is all digits; anything past the buffered-body cap (or
            // too large to hold in a Long) is refused, not used to size a buffer.
            if (contentLengths[0].toLongOrNull()?.let { it > MAX_BUFFERED_BODY_BYTES } != false) {
                throw Http1ProtocolException("Content-Length exceeds buffered-body cap: ${contentLengths[0]}")
            }
            contentLengths[0]
        }

        val transferEncoding: String? = if (transferEncodings.isEmpty()) {
            null
        } else {
            if (transferEncodings.size > 1) {
                throw Http1ProtocolException("multiple Transfer-Encoding headers")
            }
            transferEncodings[0]
        }

        return contentLength to transferEncoding
    }

    private suspend fun readBody(reader: LegReader, framing: Framing): ByteArray =
        when (framing) {
            Framing.None -> EMPTY
            is Framing.ContentLength -> reader.readExactly(framing.length)
            Framing.Chunked -> readChunkedBody(reader)
            Framing.ReadUntilClose -> reader.readToEof(MAX_BUFFERED_BODY_BYTES)
        }

    /**
     * Reads a chunked body into its de-chunked bytes. Chunk extensions (after a
     * `;` on the size line) and the trailer section (header fields after the
     * final `0` chunk, up to the blank line) are parsed and dropped — the
     * bridge re-frames with `Content-Length`, so neither travels onward.
     */
    private suspend fun readChunkedBody(reader: LegReader): ByteArray {
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = reader.readLine(MAX_CHUNK_LINE_BYTES)
            val size = parseChunkSize(sizeLine)
                ?: throw Http1ProtocolException("malformed chunk-size line: \"$sizeLine\"")

            if (size == 0) {
                // Trailer section: zero or more header lines, then the blank line.
                while (true) {
                    val trailer = reader.readLine(MAX_CHUNK_LINE_BYTES)
                    if (trailer.isEmpty()) break
                }
                break
            }

            val chunk = reader.readExactly(size)
            out.write(chunk)
            if (out.size() > MAX_BUFFERED_BODY_BYTES) {
                throw Http1ProtocolException(
                    "chunked body exceeded buffered-body cap ($MAX_BUFFERED_BODY_BYTES bytes)"
                )
            }

            val crlf = reader.readExactly(2)
            if (crlf[0] != CR || crlf[1] != LF) {
                throw Http1ProtocolException("missing CRLF after chunk data")
            }
        }
        return out.toByteArray()
    }

    /** Hex chunk size, ignoring any `;`-delimited extension; null if not valid hex. */
    private fun parseChunkSize(line: String): Int? {
        val head = line.substringBefore(';').trim()
        if (head.isEmpty()) return null
        if (head.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) return null
        val size = head.toLongOrNull(16) ?: return null
        if (size < 0 || size > MAX_BUFFERED_BODY_BYTES) return null // a single huge chunk is refused, not allocated
        return size.toInt()
    }

    // MARK: - Content coding

    private fun buildParsed(
        phase: HttpPhase,
        method: String?,
        url: String?,
        version: String,
        status: Int?,
        headers: List<HttpHeader>,
        rawBody: ByteArray
    ): ParsedHttp1Message {
        val contentEncoding = combinedHeaderValue(headers, "Content-Encoding")
        val hadContentCoding = contentEncoding != null &&
            codingTokens(contentEncoding).any { it.isNotEmpty() && it != "identity" }

        var body = rawBody
        var decoded = false
        if (hadContentCoding) {
            val result = decodeBody(rawBody, contentEncoding!!)
            if (result != null) {
                body = result
                decoded = true
            } else {
                // Unsupported coding, a malformed stream, or a body that would blow
                // the cap: forward the compressed bytes verbatim, unseen by rules.
                logger.warning(
                    "Content-Encoding \"$contentEncoding\" not decoded (${rawBody.size} B); forwarding verbatim"
                )
            }
        }

        val message = HttpMessage(phase, method, url, version, status, headers, body)
        return ParsedHttp1Message(message, rawBody, contentEncoding, hadContentCoding, decoded)
    }

    /**
     * Decompresses [data] through the [contentEncoding] chain, decoding in the
     * reverse of the order the codings were applied. Returns null — caller then
     * forwards verbatim — when any coding is unsupported, the chain is absurdly
     * long, a stream is malformed, or the decompressed size would exceed
     * [MAX_BUFFERED_BODY_BYTES] (the decompression-bomb guard).
     */
    internal fun decodeBody(data: ByteArray, contentEncoding: String): ByteArray? {
        val tokens = codingTokens(contentEncoding)
        if (tokens.isEmpty()) return data
        if (tokens.size > MAX_CODEC_CHAIN_LENGTH) return null

        var current = data
        for (token in tokens.asReversed()) {
            current = when (token) {
                "identity" -> current
                "gzip", "x-gzip" -> gunzip(current) ?: return null
                "deflate" -> inflate(current) ?: return null
                "br" -> unbrotli(current) ?: return null
                else -> return null // unknown coding (zstd, compress, …)
            }
        }
        return current
    }

    /** Comma-split, trimmed, lower-cased content-coding tokens. */
    private fun codingTokens(contentEncoding: String): List<String> =
        contentEncoding.split(',')
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }

    private fun gunzip(data: ByteArray): ByteArray? =
        runCatching { GZIPInputStream(ByteArrayInputStream(data)).use { readCapped(it) } }.getOrNull()

    /**
     * `Content-Encoding: deflate` in the wild is usually zlib-wrapped (RFC 1950),
     * though some servers send raw DEFLATE. Try the zlib form first, then raw.
     */
    private fun inflate(data: ByteArray): ByteArray? {
        if (data.isEmpty()) return null
        inflateWith(data, nowrap = false)?.let { return it }
        return inflateWith(data, nowrap = true)
    }

    private fun inflateWith(data: ByteArray, nowrap: Boolean): ByteArray? {
        val inflater = Inflater(nowrap)
        try {
            inflater.setInput(data)
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(READ_BUFFER_BYTES)
            while (!inflater.finished()) {
                val n = inflater.inflate(buffer)
                if (n == 0) {
                    if (inflater.finished() || inflater.needsDictionary()) break
                    if (inflater.needsInput()) return null // truncated stream
                }
                if (n > 0) {
                    if (out.size().toLong() + n > MAX_BUFFERED_BODY_BYTES) return null
                    out.write(buffer, 0, n)
                }
            }
            if (!inflater.finished()) return null
            return out.toByteArray()
        } catch (_: Exception) {
            return null
        } finally {
            inflater.end()
        }
    }

    private fun unbrotli(data: ByteArray): ByteArray? =
        runCatching { BrotliInputStream(ByteArrayInputStream(data)).use { readCapped(it) } }.getOrNull()

    /** Drains [input], returning null the instant the output would pass the cap. */
    private fun readCapped(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(READ_BUFFER_BYTES)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            total += n
            if (total > MAX_BUFFERED_BODY_BYTES) return null
            out.write(buffer, 0, n)
        }
        return out.toByteArray()
    }

    // MARK: - Serialising

    /**
     * Serialises [message] to HTTP/1.1 wire bytes, re-framing the body with a
     * fresh `Content-Length` and dropping `Transfer-Encoding`.
     *
     * [original] is the [ParsedHttp1Message] this message was rewritten from, or
     * null for a wholly synthesized message (a rule's reject/redirect response).
     * It is the key to the compression decision: when the rule left the body
     * byte-for-byte unchanged and the body arrived compressed, the original
     * compressed bytes are forwarded verbatim with `Content-Encoding` intact;
     * when the body was edited, the decompressed bytes go out with
     * `Content-Encoding` dropped.
     */
    fun serialize(
        message: HttpMessage,
        original: ParsedHttp1Message? = null,
        requestMethod: String? = null
    ): ByteArray {
        val hadContentCoding = original?.hadContentCoding == true
        val modified = original == null || !message.body.contentEquals(original.message.body)

        val bodyBytes: ByteArray
        val dropContentEncoding: Boolean
        if (!modified && hadContentCoding) {
            // Untouched and compressed: keep it exactly as it arrived.
            bodyBytes = original!!.rawBody
            dropContentEncoding = false
        } else {
            // Edited (or never decoded, or synthesized): emit the decompressed /
            // given bytes as identity. Drop Content-Encoding only when we had
            // actually decoded — stripping it off still-compressed passthrough
            // bytes would mislabel them.
            bodyBytes = message.body
            dropContentEncoding = original?.bodyWasDecoded == true
        }

        return when (message.phase) {
            HttpPhase.REQUEST -> serializeRequest(message, bodyBytes, dropContentEncoding)
            HttpPhase.RESPONSE -> serializeResponse(message, bodyBytes, dropContentEncoding, requestMethod)
        }
    }

    private fun serializeRequest(
        message: HttpMessage,
        body: ByteArray,
        dropContentEncoding: Boolean
    ): ByteArray {
        val method = message.method ?: "GET"
        val target = requestTarget(message.url)
        val out = ByteArrayOutputStream()
        appendLine(out, "$method $target $WIRE_VERSION")

        // Host first, derived from the URL only when the message carries none.
        if (message.headers.none { it.isNamed("Host") }) {
            authorityFromUrl(message.url)?.let { appendHeader(out, "Host", it) }
        }

        val cookies = ArrayList<String>()
        for (header in message.headers) {
            if (isDroppedFramingHeader(header, dropContentEncoding)) continue
            // HTTP/1.1 forbids split Cookie (RFC 6265 §5.4); coalesce with "; ".
            if (header.isNamed("Cookie")) {
                cookies.add(header.value)
                continue
            }
            if (!appendHeaderIfSafe(out, header)) continue
        }
        if (cookies.isNotEmpty()) {
            // The coalesced value is written directly, bypassing appendHeaderIfSafe
            // (whose no-space rule would reject a legitimate "a=1; b=2"). A Cookie
            // value legitimately carries spaces but never a CR/LF/NUL — those are the
            // request-splitting octets — so screen for exactly those. Defense in depth
            // behind the h2 termination, which already rejects such values upstream.
            val cookie = cookies.joinToString("; ")
            if (cookie.none { it == '\r' || it == '\n' || it.code == 0 }) {
                appendHeader(out, "Cookie", cookie)
            } else {
                logger.warning("dropping a Cookie header carrying a control character")
            }
        }
        // A request with a body carries a fresh Content-Length; a body-less request
        // carries none (a GET with Content-Length: 0 is odd and some servers balk).
        if (body.isNotEmpty()) {
            appendHeader(out, "Content-Length", body.size.toString())
        }

        appendCrlf(out)
        out.write(body)
        return out.toByteArray()
    }

    private fun serializeResponse(
        message: HttpMessage,
        body: ByteArray,
        dropContentEncoding: Boolean,
        requestMethod: String?
    ): ByteArray {
        val status = message.status ?: 0
        // A HEAD response carries no body whatever its headers say, but its
        // Content-Length describes what a GET would have returned, so it must be
        // preserved rather than re-derived from the empty buffered body.
        val isHead = requestMethod?.equals("HEAD", ignoreCase = true) == true
        val out = ByteArrayOutputStream()
        appendLine(out, "$WIRE_VERSION $status ${reasonPhrase(status)}")

        for (header in message.headers) {
            if (isDroppedFramingHeader(header, dropContentEncoding)) continue
            if (!appendHeaderIfSafe(out, header)) continue
        }

        // A no-body status frames itself (the absence of a body is defined by the
        // status); everything else gets an explicit Content-Length so the client
        // does not fall back to reading until close.
        val noBody = isNoBodyStatus(status)
        if (isHead) {
            firstHeaderValue(message.headers, "Content-Length")
                ?.takeIf { isCleanContentLength(it) }
                ?.let { appendHeader(out, "Content-Length", it) }
        } else if (!noBody) {
            appendHeader(out, "Content-Length", body.size.toString())
        }

        appendCrlf(out)
        if (!noBody && !isHead) out.write(body)
        return out.toByteArray()
    }

    /** Content-Length and Transfer-Encoding are always re-framed; Content-Encoding only when decoded. */
    private fun isDroppedFramingHeader(header: HttpHeader, dropContentEncoding: Boolean): Boolean {
        if (header.isNamed("Content-Length") || header.isNamed("Transfer-Encoding")) return true
        if (dropContentEncoding && header.isNamed("Content-Encoding")) return true
        return false
    }

    /**
     * The origin-form request-target for an absolute URL: the path (empty → `/`)
     * and query, fragment stripped. Recovered by string-slicing off the
     * `scheme://authority` prefix rather than re-parsing, so a target the client
     * sent is reproduced exactly and not re-encoded.
     */
    private fun requestTarget(url: String?): String {
        if (url.isNullOrEmpty()) return "/"
        val sep = url.indexOf("://")
        if (sep < 0) return url // already a bare target
        var i = sep + 3
        while (i < url.length && url[i] != '/' && url[i] != '?' && url[i] != '#') i++
        var target = url.substring(i)
        val hash = target.indexOf('#')
        if (hash >= 0) target = target.substring(0, hash)
        return target.ifEmpty { "/" }
    }

    /** `host` or `host:port` from an absolute URL, for a derived `Host` header. */
    private fun authorityFromUrl(url: String?): String? {
        if (url.isNullOrEmpty()) return null
        val sep = url.indexOf("://")
        if (sep < 0) return null
        var i = sep + 3
        while (i < url.length && url[i] != '/' && url[i] != '?' && url[i] != '#') i++
        return url.substring(sep + 3, i).ifEmpty { null }
    }

    // MARK: - Wire helpers

    private fun appendLine(out: ByteArrayOutputStream, line: String) {
        appendLatin1(out, line)
        appendCrlf(out)
    }

    private fun appendHeader(out: ByteArrayOutputStream, name: String, value: String) {
        appendLatin1(out, name)
        out.write(':'.code)
        out.write(' '.code)
        appendLatin1(out, value)
        appendCrlf(out)
    }

    /** Writes a header unless its name or value carries a CR/LF/NUL injection vector. */
    private fun appendHeaderIfSafe(out: ByteArrayOutputStream, header: HttpHeader): Boolean {
        if (!HttpHeader.isValidName(header.name) || !HttpHeader.isValidValue(header.value)) {
            logger.warning("dropping unsafe header from serialized head: \"${header.name}\"")
            return false
        }
        appendHeader(out, header.name, header.value)
        return true
    }

    /**
     * Writes [text] as ISO-8859-1 so a byte that rode in on the wire rides back
     * out unchanged, rather than being re-encoded as multi-byte UTF-8.
     */
    private fun appendLatin1(out: ByteArrayOutputStream, text: String) {
        out.write(text.toByteArray(StandardCharsets.ISO_8859_1))
    }

    private fun appendCrlf(out: ByteArrayOutputStream) {
        out.write(CR.toInt())
        out.write(LF.toInt())
    }

    // MARK: - Header lookups

    private fun firstHeaderValue(headers: List<HttpHeader>, name: String): String? =
        headers.firstOrNull { it.isNamed(name) }?.value

    private fun headerValues(headers: List<HttpHeader>, name: String): List<String> =
        headers.filter { it.isNamed(name) }.map { it.value }

    private fun combinedHeaderValue(headers: List<HttpHeader>, name: String): String? {
        val values = headerValues(headers, name)
        return when (values.size) {
            0 -> null
            1 -> values[0]
            else -> values.joinToString(", ")
        }
    }

    // MARK: - Framing predicates

    /**
     * True only when the transfer-coding is exactly `chunked` with nothing
     * layered on it. A list such as `gzip, chunked` is rejected by the callers
     * rather than de-chunked with the content-coding silently dropped — this
     * codec decodes content-codings only when they ride on `Content-Encoding`,
     * where the decode path and the 4 MiB cap apply.
     */
    private fun transferEncodingIsChunkedOnly(value: String): Boolean {
        val codings = value.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        return codings.size == 1 && codings[0].equals("chunked", ignoreCase = true)
    }

    /** All digits, no leading zero unless the value is exactly "0". */
    private fun isCleanContentLength(value: String): Boolean {
        if (value.isEmpty() || value.any { it !in '0'..'9' }) return false
        if (value.length > 1 && value[0] == '0') return false
        return true
    }

    /** Statuses that carry no message body by definition (RFC 9110 §6.4.1). */
    private fun isNoBodyStatus(status: Int): Boolean = when (status) {
        204, 205, 304 -> true
        else -> status in 100..199 && status != 101
    }

    private fun reasonPhrase(status: Int): String = when (status) {
        100 -> "Continue"
        101 -> "Switching Protocols"
        200 -> "OK"
        201 -> "Created"
        202 -> "Accepted"
        204 -> "No Content"
        206 -> "Partial Content"
        301 -> "Moved Permanently"
        302 -> "Found"
        303 -> "See Other"
        304 -> "Not Modified"
        307 -> "Temporary Redirect"
        308 -> "Permanent Redirect"
        400 -> "Bad Request"
        401 -> "Unauthorized"
        403 -> "Forbidden"
        404 -> "Not Found"
        405 -> "Method Not Allowed"
        408 -> "Request Timeout"
        409 -> "Conflict"
        410 -> "Gone"
        418 -> "I'm a teapot"
        429 -> "Too Many Requests"
        500 -> "Internal Server Error"
        501 -> "Not Implemented"
        502 -> "Bad Gateway"
        503 -> "Service Unavailable"
        504 -> "Gateway Timeout"
        else -> ""
    }

    /**
     * A cursor over a [MitmByteLeg] that reads exactly what the codec asks for —
     * a head, a fixed count, a CRLF-terminated line, or everything to EOF — and
     * remembers how far past the ask it overread so [pushBackRemainder] can hand
     * the surplus back to the leg.
     */
    private class LegReader(private val leg: MitmByteLeg) {
        private var data: ByteArray = EMPTY
        private var off = 0
        private var headScan = 0

        private fun remaining() = data.size - off

        /** Pulls one non-empty chunk; false at EOF. Compacts the consumed prefix first. */
        private suspend fun pull(): Boolean {
            while (true) {
                val more = leg.receive() ?: return false
                if (more.isEmpty()) continue
                if (off > 0) {
                    data = data.copyOfRange(off, data.size)
                    headScan -= off
                    if (headScan < 0) headScan = 0
                    off = 0
                }
                data = if (data.isEmpty()) more else data + more
                return true
            }
        }

        /**
         * Reads up to and past the blank line ending the head, returning the head
         * split into lines (start line first, obs-folds merged, empties dropped),
         * or null at a clean EOF before any bytes arrived.
         */
        suspend fun readHead(): List<String>? {
            while (true) {
                val crlfCrlf = indexOfCrlfCrlf(headScan)
                if (crlfCrlf >= 0) {
                    val headBytes = data.copyOfRange(off, crlfCrlf)
                    off = crlfCrlf + 4
                    headScan = 0
                    return foldHeadLines(String(headBytes, StandardCharsets.ISO_8859_1))
                }
                // Resume the next scan where a CRLFCRLF could still begin.
                headScan = maxOf(off, data.size - 3)
                if (remaining() > MAX_HEAD_BYTES) {
                    throw Http1ProtocolException("head exceeded $MAX_HEAD_BYTES bytes without a blank line")
                }
                if (!pull()) {
                    if (remaining() == 0) return null // clean EOF between messages
                    throw Http1ProtocolException("connection closed mid-head")
                }
            }
        }

        /** Index of the first byte of a CRLFCRLF at or after [from], or -1. */
        private fun indexOfCrlfCrlf(from: Int): Int {
            var i = maxOf(from, off)
            val end = data.size - 3
            while (i <= end) {
                if (data[i] == CR && data[i + 1] == LF && data[i + 2] == CR && data[i + 3] == LF) {
                    return i
                }
                i++
            }
            return -1
        }

        /** Splits the head text on CRLF, merges obs-fold continuations, drops empty lines. */
        private fun foldHeadLines(text: String): List<String> {
            val result = ArrayList<String>()
            for (raw in text.split("\r\n")) {
                if (raw.isEmpty()) continue
                val folded = raw[0] == ' ' || raw[0] == '\t'
                if (folded) {
                    if (result.isEmpty()) {
                        throw Http1ProtocolException("obs-fold continuation with no preceding line")
                    }
                    result[result.size - 1] = result[result.size - 1] + " " + raw.trimStart(' ', '\t')
                } else {
                    result.add(raw)
                }
            }
            if (result.isEmpty()) throw Http1ProtocolException("empty message head")
            return result
        }

        /** Reads exactly [n] bytes, or throws at a premature EOF. */
        suspend fun readExactly(n: Int): ByteArray {
            if (n == 0) return EMPTY
            val out = ByteArray(n)
            var got = 0
            while (got < n) {
                if (remaining() == 0 && !pull()) {
                    throw Http1ProtocolException("connection closed after $got of $n body bytes")
                }
                val take = minOf(n - got, remaining())
                System.arraycopy(data, off, out, got, take)
                off += take
                got += take
            }
            return out
        }

        /** Reads one CRLF-terminated line (CRLF stripped) as Latin-1, bounded by [maxLen]. */
        suspend fun readLine(maxLen: Int): String {
            while (true) {
                val crlf = indexOfCrlf(off)
                if (crlf >= 0) {
                    val line = String(data, off, crlf - off, StandardCharsets.ISO_8859_1)
                    off = crlf + 2
                    return line
                }
                if (remaining() > maxLen) {
                    throw Http1ProtocolException("line exceeded $maxLen bytes without CRLF")
                }
                if (!pull()) throw Http1ProtocolException("connection closed mid-line")
            }
        }

        private fun indexOfCrlf(from: Int): Int {
            var i = maxOf(from, off)
            val end = data.size - 2
            while (i <= end) {
                if (data[i] == CR && data[i + 1] == LF) return i
                i++
            }
            return -1
        }

        /** Reads every remaining byte until EOF, refusing a body past [cap]. */
        suspend fun readToEof(cap: Int): ByteArray {
            val out = ByteArrayOutputStream()
            if (remaining() > 0) {
                out.write(data, off, remaining())
                off = data.size
            }
            while (true) {
                val more = leg.receive() ?: break
                if (more.isEmpty()) continue
                out.write(more)
                if (out.size() > cap) {
                    throw Http1ProtocolException("read-until-close body exceeded $cap bytes")
                }
            }
            return out.toByteArray()
        }

        /** Hands any bytes read past the message (a pipelined next one) back to the leg. */
        fun pushBackRemainder() {
            if (remaining() > 0) {
                leg.prependToReceiveBuffer(data.copyOfRange(off, data.size))
                off = data.size
            }
        }
    }

    companion object {
        /**
         * The hard cap on a buffered body: the request/response the codec holds in
         * memory, and — critically — the decompressed size a `Content-Encoding`
         * body is allowed to reach. A decompression bomb that would inflate past
         * this is refused (the body is forwarded compressed and unseen) rather
         * than allowed to exhaust the process's heap. 4 MiB matches the reference.
         */
        const val MAX_BUFFERED_BODY_BYTES = 4 * 1024 * 1024

        /** The wire version the bridge always emits; it speaks HTTP/1.1 to both legs. */
        private const val WIRE_VERSION = "HTTP/1.1"

        private const val MAX_HEAD_BYTES = 64 * 1024
        private const val MAX_CHUNK_LINE_BYTES = 16 * 1024

        /** A stacked coding chain longer than this is a CPU-amplification vector; refuse it. */
        private const val MAX_CODEC_CHAIN_LENGTH = 4

        private const val READ_BUFFER_BYTES = 64 * 1024

        private const val CR: Byte = 0x0D
        private const val LF: Byte = 0x0A

        private val EMPTY = ByteArray(0)
    }
}
