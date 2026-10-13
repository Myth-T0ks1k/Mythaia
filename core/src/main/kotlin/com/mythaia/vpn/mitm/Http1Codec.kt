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
    val bodyWasDecoded: Boolean,
    /**
     * The request-target exactly as the client wrote it (`/path?q`, `*`, or an
     * absolute-form URL), or null for a response. [Http1Codec.serialize] falls
     * back to it when the message carries no URL — origin-form with no `Host`,
     * or `OPTIONS *` — so the origin still sees the resource that was asked for
     * rather than a made-up `/`.
     */
    val requestTarget: String? = null,
    /**
     * Non-null when the body was too large to buffer: [message]'s body is then
     * empty and the bytes are still on the leg, to be streamed onward with
     * [Http1Codec.BodyRelay.relayTo] (or dropped with [Http1Codec.BodyRelay.discard])
     * before anything else is read off that leg. Rules never see such a body.
     */
    val deferredBody: Http1Codec.BodyRelay? = null
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
 *  - **Over-cap bodies are streamed, not refused.** A body that would exceed
 *    [MAX_BUFFERED_BODY_BYTES] on the wire — a declared `Content-Length` past it,
 *    a chunked stream that grows past it, a close-delimited one that does — is
 *    handed back as a [ParsedHttp1Message.deferredBody]: the head is parsed (so
 *    URL and header rules, and the request-phase reject/redirect decision, still
 *    apply), the body is left on the leg, and the bridge pumps it onward with
 *    [BodyRelay.relayTo] in bounded slices under the message's own framing. The
 *    alternative — failing the connection — made every large download and
 *    upload on an intercepted host unreachable.
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
     * request) are pushed back onto [leg] for the following read — unless the
     * body was deferred (see [ParsedHttp1Message.deferredBody]), in which case
     * the relay does so once it has pumped the body.
     *
     * [expectContinue] is invoked once, after the head is parsed and before the
     * body is read, when the head carries `Expect: 100-continue` and frames a
     * body. A client that sent that header is waiting for an interim `100
     * Continue` before it sends a byte of body, so the bridge uses the hook to
     * write one; without it the client stalls for its expect timeout and only
     * then sends the body.
     *
     * @throws Http1ProtocolException on a malformed or smuggling-shaped request.
     */
    suspend fun readRequest(
        leg: MitmByteLeg,
        expectContinue: (suspend () -> Unit)? = null
    ): ParsedHttp1Message? {
        val reader = LegReader(leg)
        val lines = reader.readHead() ?: return null

        val startLine = lines[0]
        val tokens = startLine.split(" ")
        if (tokens.size != 3) {
            throw Http1ProtocolException("malformed request line: ${describeRequestLine(startLine)}")
        }
        val method = tokens[0]
        val target = tokens[1]
        if (!HttpHeader.isValidName(method)) {
            throw Http1ProtocolException("invalid request method token: ${describeLine(method)}")
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
        if (framing != Framing.None && expectContinue != null && expectsContinue(headers)) {
            expectContinue()
        }
        val body = readBody(reader, framing)
        if (body is BodyRead.Buffered) reader.pushBackRemainder()

        return buildParsed(
            phase = HttpPhase.REQUEST,
            method = method,
            url = url,
            version = WIRE_VERSION,
            status = null,
            headers = headers,
            body = body,
            requestTarget = target
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
            throw Http1ProtocolException("malformed status line: ${describeLine(startLine)}")
        }
        val version = tokens[0]
        val status = tokens[1].toIntOrNull()
            ?: throw Http1ProtocolException("non-numeric status code: ${describeLine(tokens[1])}")

        val headers = parseHeaders(lines)
        val framing = responseFraming(status, requestMethod, headers)
        val body = readBody(reader, framing)
        // For a connection-delimited body the leg is now at EOF; otherwise push
        // back any pipelined bytes that followed this response. A deferred body
        // still owns the leg, and its relay pushes back when it is done.
        if (body is BodyRead.Buffered) reader.pushBackRemainder()

        return buildParsed(
            phase = HttpPhase.RESPONSE,
            method = null,
            url = requestUrl,
            version = version,
            status = status,
            headers = headers,
            body = body,
            requestTarget = null
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
                // The line is not quoted: with no colon there is no name to show
                // without also showing what may be a value (a cookie, a token).
                throw Http1ProtocolException("header line ${i} without a colon (${line.length} chars)")
            }
            val name = line.substring(0, colon)
            if (!HttpHeader.isValidName(name)) {
                throw Http1ProtocolException("invalid header name: ${describeLine(name)}")
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

    /** Whether the request head asks for an interim `100 Continue` before the body (RFC 9110 §10.1.1). */
    private fun expectsContinue(headers: List<HttpHeader>): Boolean =
        headers.asSequence()
            .filter { it.isNamed("Expect") }
            .flatMap { it.value.splitToSequence(',') }
            .any { it.trim().equals("100-continue", ignoreCase = true) }

    // MARK: - Body framing

    private sealed class Framing {
        object None : Framing()
        data class ContentLength(val length: Long) : Framing()
        object Chunked : Framing()
        object ReadUntilClose : Framing()
    }

    private fun requestFraming(headers: List<HttpHeader>): Framing {
        val (contentLength, transferEncoding) = frameGuards(headers)
        if (transferEncoding != null) {
            if (!transferEncodingIsChunkedOnly(transferEncoding)) {
                throw Http1ProtocolException(
                    "unsupported request Transfer-Encoding (only a lone chunked is handled): ${describeLine(transferEncoding)}"
                )
            }
            return Framing.Chunked
        }
        if (contentLength != null) {
            return if (contentLength == 0L) Framing.None else Framing.ContentLength(contentLength)
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
                    "unsupported response Transfer-Encoding (only a lone chunked is handled): ${describeLine(transferEncoding)}"
                )
            }
            return Framing.Chunked
        }
        if (contentLength != null) {
            return if (contentLength == 0L) Framing.None else Framing.ContentLength(contentLength)
        }
        // No length and no chunking: the body runs until the peer closes (HTTP/1.0
        // style, or a server that simply omitted the framing).
        return Framing.ReadUntilClose
    }

    /**
     * The anti-smuggling gate over the two framing headers, returning the single
     * clean `Content-Length` and the single `Transfer-Encoding` (either may be
     * null). Rejects the ambiguities a desync attack is built on. A length past
     * [MAX_BUFFERED_BODY_BYTES] is *not* rejected here: it is a legitimate large
     * transfer, and [readBody] streams it instead of buffering it.
     */
    private fun frameGuards(headers: List<HttpHeader>): Pair<Long?, String?> {
        val contentLengths = headerValues(headers, "Content-Length").map { it.trim() }
        val transferEncodings = headerValues(headers, "Transfer-Encoding")

        if (contentLengths.isNotEmpty() && transferEncodings.isNotEmpty()) {
            throw Http1ProtocolException("both Content-Length and Transfer-Encoding present")
        }

        val contentLength: Long? = if (contentLengths.isEmpty()) {
            null
        } else {
            // More than one Content-Length field is a desync vector even when the
            // values agree, so reject the duplicate rather than pick one.
            if (contentLengths.size > 1) {
                throw Http1ProtocolException("${contentLengths.size} Content-Length headers")
            }
            if (!isCleanContentLength(contentLengths[0])) {
                throw Http1ProtocolException("malformed Content-Length: ${describeLine(contentLengths[0])}")
            }
            // A clean value is all digits; one too large to hold in a Long is not
            // a length any peer means, so it is refused as malformed.
            contentLengths[0].toLongOrNull()
                ?: throw Http1ProtocolException("Content-Length out of range: ${describeLine(contentLengths[0])}")
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

    /** What [readBody] produced: the whole body in memory, or a relay for one too large to hold. */
    private sealed class BodyRead {
        class Buffered(val bytes: ByteArray) : BodyRead()
        class Deferred(val relay: BodyRelay) : BodyRead()
    }

    private suspend fun readBody(reader: LegReader, framing: Framing): BodyRead =
        when (framing) {
            Framing.None -> BodyRead.Buffered(EMPTY)
            is Framing.ContentLength ->
                if (framing.length > MAX_BUFFERED_BODY_BYTES) {
                    // Known up front to be too big: nothing of the body is read here;
                    // the relay streams exactly the declared count from the leg.
                    BodyRead.Deferred(
                        BodyRelay(RelayFraming.ContentLength(framing.length), reader.lastRawHead, reader, EMPTY, null, 0L)
                    )
                } else {
                    BodyRead.Buffered(reader.readExactly(framing.length.toInt()))
                }
            Framing.Chunked -> readChunkedBody(reader)
            Framing.ReadUntilClose -> {
                val read = reader.readToEof(MAX_BUFFERED_BODY_BYTES)
                if (read.complete) {
                    BodyRead.Buffered(read.bytes)
                } else {
                    BodyRead.Deferred(
                        BodyRelay(RelayFraming.UntilClose, reader.lastRawHead, reader, read.bytes, null, 0L)
                    )
                }
            }
        }

    /**
     * Reads a chunked body into its de-chunked bytes. Chunk extensions (after a
     * `;` on the size line) and the trailer section (header fields after the
     * final `0` chunk, up to the blank line) are parsed and dropped — the
     * bridge re-frames with `Content-Length`, so neither travels onward.
     *
     * The moment the *next* chunk would carry the buffered total past
     * [MAX_BUFFERED_BODY_BYTES] — whether by many chunks or by one huge one — the
     * read stops before that chunk's data and the rest is deferred to a
     * [BodyRelay]: what is buffered goes out re-chunked, that chunk's size line
     * (already consumed) is re-emitted ahead of its data, and the remainder of
     * the stream is copied raw, extensions and trailers included.
     */
    private suspend fun readChunkedBody(reader: LegReader): BodyRead {
        val out = ByteArrayOutputStream()
        while (true) {
            val sizeLine = reader.readLine(MAX_CHUNK_LINE_BYTES)
            val size = parseChunkSize(sizeLine)
                ?: throw Http1ProtocolException("malformed chunk-size line: ${describeLine(sizeLine)}")

            if (size == 0L) {
                // Trailer section: zero or more header lines, then the blank line.
                while (true) {
                    val trailer = reader.readLine(MAX_CHUNK_LINE_BYTES)
                    if (trailer.isEmpty()) break
                }
                return BodyRead.Buffered(out.toByteArray())
            }

            if (size > MAX_BUFFERED_BODY_BYTES - out.size()) {
                return BodyRead.Deferred(
                    BodyRelay(RelayFraming.Chunked, reader.lastRawHead, reader, out.toByteArray(), sizeLine, size)
                )
            }

            val chunk = reader.readExactly(size.toInt())
            out.write(chunk)
            reader.expectChunkCrlf()
        }
    }

    /**
     * Hex chunk size, ignoring any `;`-delimited extension; null if not valid
     * hex or too large to hold in a Long (no peer means such a chunk).
     */
    private fun parseChunkSize(line: String): Long? {
        val head = line.substringBefore(';').trim()
        if (head.isEmpty()) return null
        if (head.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) return null
        return head.toLongOrNull(16)
    }

    // MARK: - Over-cap body relay

    /**
     * How a deferred body is framed on the wire, which is also how [BodyRelay]
     * frames it onward and what [serializeHeadForRelay] declares in the head.
     */
    sealed class RelayFraming {
        /** Exactly [length] body bytes follow the head. */
        data class ContentLength(val length: Long) : RelayFraming()

        /** `Transfer-Encoding: chunked`: the relay keeps the body chunked. */
        object Chunked : RelayFraming()

        /** No framing — the body runs until the peer closes (a response only). */
        object UntilClose : RelayFraming()
    }

    /**
     * A body left on the leg because it was too large to buffer, and the one-shot
     * pump that moves it onward.
     *
     * The relay owns the reader (and so the leg) from the end of the head until
     * [relayTo] or [discard] returns: it forwards whatever the head scan had
     * already overread, then streams the rest straight from the leg in slices of
     * at most [MAX_RELAY_SLICE_BYTES], never holding the body. It knows where the
     * message ends — the declared count, the terminating `0` chunk and its
     * trailers, or EOF — so the bytes of a pipelined next message are pushed back
     * onto the leg exactly as a buffered read would, and keep-alive carries on.
     *
     * [rawHead] is the head exactly as received — start line, headers and the
     * blank line — for a caller that forwards it verbatim (the response path).
     */
    inner class BodyRelay internal constructor(
        val framing: RelayFraming,
        val rawHead: ByteArray,
        private val reader: LegReader,
        /** Body bytes already read before the cap tripped (de-chunked for [RelayFraming.Chunked]). */
        private val buffered: ByteArray,
        /** For [RelayFraming.Chunked]: a size line already consumed whose data is still on the leg. */
        private val pendingSizeLine: String?,
        private val pendingSize: Long
    ) {
        private var pumped = false

        /**
         * Streams the body to [sink] under [framing] — HTTP/1.1 wire form, chunk
         * framing included — then hands any overread back to the source leg.
         */
        suspend fun relayTo(sink: MitmByteLeg) = pump(sink, framed = true)

        /**
         * Streams only the body's content to [sink] — chunk sizes, extensions and
         * trailers stripped — for a sink that frames the body itself, such as an
         * HTTP/2 stream carrying it as DATA. Still `Content-Encoding`-coded if it
         * arrived so.
         */
        suspend fun relayContentTo(sink: MitmByteLeg) = pump(sink, framed = false)

        /** Consumes the body without forwarding it (a request answered by a rule), keeping the leg in frame. */
        suspend fun discard() = pump(null, framed = false)

        private suspend fun pump(sink: MitmByteLeg?, framed: Boolean) {
            check(!pumped) { "a deferred body can be relayed only once" }
            pumped = true
            when (framing) {
                is RelayFraming.ContentLength -> {
                    // Nothing was buffered (the length was known from the head), so
                    // the whole count comes off the reader and the leg.
                    reader.copyExactly(framing.length, sink)
                    reader.pushBackRemainder()
                }
                RelayFraming.Chunked -> {
                    if (buffered.isNotEmpty()) sendTo(sink, if (framed) chunkFrame(buffered) else buffered)
                    copyChunkedRemainder(sink, framed)
                    reader.pushBackRemainder()
                }
                RelayFraming.UntilClose -> {
                    sendTo(sink, buffered)
                    reader.copyToEof(sink)
                }
            }
        }

        /**
         * Copies the rest of a chunked stream: each size line is parsed only to
         * know how far the chunk data runs and where the stream ends. When
         * [framed], the size lines (extension and all), the CRLFs and the trailer
         * section are re-emitted as they were; otherwise only the chunk data is.
         */
        private suspend fun copyChunkedRemainder(sink: MitmByteLeg?, framed: Boolean) {
            var line = pendingSizeLine
            var size = pendingSize
            while (true) {
                if (line == null) {
                    line = reader.readLine(MAX_CHUNK_LINE_BYTES)
                    size = parseChunkSize(line)
                        ?: throw Http1ProtocolException("malformed chunk-size line: ${describeLine(line)}")
                }
                if (framed) sendTo(sink, lineBytes(line))
                if (size == 0L) break
                reader.copyExactly(size, sink)
                reader.expectChunkCrlf()
                if (framed) sendTo(sink, CRLF)
                line = null
            }
            while (true) {
                val trailer = reader.readLine(MAX_CHUNK_LINE_BYTES)
                if (framed) sendTo(sink, lineBytes(trailer))
                if (trailer.isEmpty()) break
            }
        }

        private suspend fun sendTo(sink: MitmByteLeg?, data: ByteArray) {
            if (sink != null && data.isNotEmpty()) sink.send(data)
        }

        /** One chunk carrying all of [data]: `hex-size CRLF data CRLF`. */
        private fun chunkFrame(data: ByteArray): ByteArray {
            val out = ByteArrayOutputStream(data.size + 24)
            appendLine(out, java.lang.Long.toHexString(data.size.toLong()))
            out.write(data)
            appendCrlf(out)
            return out.toByteArray()
        }

        private fun lineBytes(line: String): ByteArray {
            val out = ByteArrayOutputStream(line.length + 2)
            appendLine(out, line)
            return out.toByteArray()
        }
    }

    // MARK: - Content coding

    private fun buildParsed(
        phase: HttpPhase,
        method: String?,
        url: String?,
        version: String,
        status: Int?,
        headers: List<HttpHeader>,
        body: BodyRead,
        requestTarget: String?
    ): ParsedHttp1Message {
        val contentEncoding = combinedHeaderValue(headers, "Content-Encoding")
        val hadContentCoding = contentEncoding != null &&
            codingTokens(contentEncoding).any { it.isNotEmpty() && it != "identity" }

        if (body is BodyRead.Deferred) {
            // Too large to hold: the head is all a rule gets to see. The body stays
            // on the leg for the relay, compressed or not, exactly as it arrived.
            val message = HttpMessage(phase, method, url, version, status, headers, EMPTY)
            return ParsedHttp1Message(
                message, EMPTY, contentEncoding, hadContentCoding, bodyWasDecoded = false,
                requestTarget = requestTarget, deferredBody = body.relay
            )
        }

        val rawBody = (body as BodyRead.Buffered).bytes
        var decoded = false
        var decodedBody = rawBody
        if (hadContentCoding) {
            val result = decodeBody(rawBody, contentEncoding!!)
            if (result != null) {
                decodedBody = result
                decoded = true
            } else {
                // Unsupported coding, a malformed stream, or a body that would blow
                // the cap: forward the compressed bytes verbatim, unseen by rules.
                logger.warning(
                    "Content-Encoding ${describeLine(contentEncoding)} not decoded (${rawBody.size} B); forwarding verbatim"
                )
            }
        }

        val message = HttpMessage(phase, method, url, version, status, headers, decodedBody)
        return ParsedHttp1Message(
            message, rawBody, contentEncoding, hadContentCoding, decoded,
            requestTarget = requestTarget, deferredBody = null
        )
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
            HttpPhase.REQUEST -> serializeRequest(message, bodyBytes, dropContentEncoding, original?.requestTarget)
            HttpPhase.RESPONSE -> serializeResponse(message, bodyBytes, dropContentEncoding, requestMethod)
        }
    }

    /**
     * Serialises only the head of [message] for a body that [relay] will stream
     * after it, declaring the relay's own framing — the original `Content-Length`
     * or `Transfer-Encoding: chunked` — in place of the fresh length [serialize]
     * would derive from a (here, empty) buffered body. `Content-Encoding` is kept:
     * the body goes onward exactly as it arrived, so its coding still applies.
     *
     * This is the request path's head for an over-cap upload: the head a rule
     * may have rewritten (URL, `Host`, added headers) goes out re-serialised,
     * and the untouched body follows it. [original] supplies the client's
     * request-target for a message with no URL, as in [serialize].
     */
    fun serializeHeadForRelay(
        message: HttpMessage,
        relay: BodyRelay,
        original: ParsedHttp1Message? = null
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val framing: (ByteArrayOutputStream) -> Unit = { o ->
            when (val f = relay.framing) {
                is RelayFraming.ContentLength -> appendHeader(o, "Content-Length", f.length.toString())
                RelayFraming.Chunked -> appendHeader(o, "Transfer-Encoding", "chunked")
                RelayFraming.UntilClose -> { /* delimited by the close; nothing to declare */ }
            }
        }
        when (message.phase) {
            HttpPhase.REQUEST ->
                writeRequestHead(out, message, dropContentEncoding = false, original?.requestTarget, framing)
            HttpPhase.RESPONSE ->
                writeResponseHead(out, message, dropContentEncoding = false, framing)
        }
        appendCrlf(out)
        return out.toByteArray()
    }

    private fun serializeRequest(
        message: HttpMessage,
        body: ByteArray,
        dropContentEncoding: Boolean,
        originalTarget: String?
    ): ByteArray {
        val out = ByteArrayOutputStream()
        writeRequestHead(out, message, dropContentEncoding, originalTarget) { o ->
            // A request with a body carries a fresh Content-Length. A body-less one
            // carries `Content-Length: 0` only when something expects it: a method
            // that conventionally has a body (a strict origin answers an unframed
            // empty POST/PUT/PATCH with 411), or a request that itself declared a
            // framing header (`Content-Length: 0`, or chunked with no data). A plain
            // GET/HEAD stays unframed — a GET with Content-Length: 0 is odd and some
            // servers balk at it.
            val method = message.method ?: "GET"
            val declaredFraming = message.headers.any {
                it.isNamed("Content-Length") || it.isNamed("Transfer-Encoding")
            }
            if (body.isNotEmpty() || declaredFraming || method.uppercase() in BODY_METHODS) {
                appendHeader(o, "Content-Length", body.size.toString())
            }
        }
        appendCrlf(out)
        out.write(body)
        return out.toByteArray()
    }

    /**
     * Writes the request line and headers (no final blank line): `Host` first,
     * derived from the URL only when the message carries none; split `Cookie`
     * fields coalesced; framing headers dropped and re-declared by [framing].
     */
    private fun writeRequestHead(
        out: ByteArrayOutputStream,
        message: HttpMessage,
        dropContentEncoding: Boolean,
        originalTarget: String?,
        framing: (ByteArrayOutputStream) -> Unit
    ) {
        val method = message.method ?: "GET"
        val target = requestTarget(message.url, originalTarget)
        appendLine(out, "$method $target $WIRE_VERSION")

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
        framing(out)
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
        val noBody = isNoBodyStatus(status)
        val out = ByteArrayOutputStream()
        writeResponseHead(out, message, dropContentEncoding) { o ->
            // A no-body status frames itself (the absence of a body is defined by the
            // status); everything else gets an explicit Content-Length so the client
            // does not fall back to reading until close.
            if (isHead) {
                firstHeaderValue(message.headers, "Content-Length")
                    ?.takeIf { isCleanContentLength(it) }
                    ?.let { appendHeader(o, "Content-Length", it) }
            } else if (!noBody) {
                appendHeader(o, "Content-Length", body.size.toString())
            }
        }
        appendCrlf(out)
        if (!noBody && !isHead) out.write(body)
        return out.toByteArray()
    }

    /** Writes the status line and headers (no final blank line); framing headers dropped and re-declared by [framing]. */
    private fun writeResponseHead(
        out: ByteArrayOutputStream,
        message: HttpMessage,
        dropContentEncoding: Boolean,
        framing: (ByteArrayOutputStream) -> Unit
    ) {
        val status = message.status ?: 0
        appendLine(out, "$WIRE_VERSION $status ${reasonPhrase(status)}")
        for (header in message.headers) {
            if (isDroppedFramingHeader(header, dropContentEncoding)) continue
            if (!appendHeaderIfSafe(out, header)) continue
        }
        framing(out)
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
     * sent is reproduced exactly and not re-encoded. With no URL at all (an
     * origin-form request that carried no `Host`, or `OPTIONS *`) the client's
     * own [originalTarget] is reproduced, so the origin is asked for the resource
     * the client named and not a made-up `/`.
     */
    private fun requestTarget(url: String?, originalTarget: String?): String {
        if (url.isNullOrEmpty()) return originalTarget?.ifEmpty { null } ?: "/"
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
     * the surplus back to the leg. The `copy*` members stream instead of
     * buffering, for a [BodyRelay] pumping a body the codec will never hold.
     */
    internal class LegReader(private val leg: MitmByteLeg) {
        private var data: ByteArray = EMPTY
        private var off = 0
        private var headScan = 0

        /**
         * The head [readHead] last consumed, byte-for-byte and blank line
         * included, so an over-cap message's head can be forwarded verbatim.
         */
        var lastRawHead: ByteArray = EMPTY
            private set

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
                    lastRawHead = data.copyOfRange(off, crlfCrlf + 4)
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

        /** Reads and checks the CRLF that terminates a chunk's data. */
        suspend fun expectChunkCrlf() {
            val crlf = readExactly(2)
            if (crlf[0] != CR || crlf[1] != LF) {
                throw Http1ProtocolException("missing CRLF after chunk data")
            }
        }

        /** What [readToEof] collected, and whether it reached EOF before the cap. */
        class EofRead(val bytes: ByteArray, val complete: Boolean)

        /**
         * Reads until EOF, stopping — with [EofRead.complete] false and what was
         * read so far — as soon as the body passes [cap]; the caller then streams
         * the rest with [copyToEof] rather than holding it.
         */
        suspend fun readToEof(cap: Int): EofRead {
            val out = ByteArrayOutputStream()
            if (remaining() > 0) {
                out.write(data, off, remaining())
                off = data.size
            }
            while (out.size() <= cap) {
                val more = leg.receive() ?: return EofRead(out.toByteArray(), complete = true)
                if (more.isEmpty()) continue
                out.write(more)
            }
            return EofRead(out.toByteArray(), complete = false)
        }

        /**
         * Streams exactly [n] bytes to [sink] — or discards them when [sink] is
         * null — in slices of at most [MAX_RELAY_SLICE_BYTES], so no more than
         * one slice is ever held. The buffered overread goes first, then the leg.
         */
        suspend fun copyExactly(n: Long, sink: MitmByteLeg?) {
            var left = n
            while (left > 0) {
                if (remaining() == 0 && !pull()) {
                    throw Http1ProtocolException("connection closed with $left body bytes still to relay")
                }
                val take = minOf(left, remaining().toLong(), MAX_RELAY_SLICE_BYTES.toLong()).toInt()
                sink?.send(data.copyOfRange(off, off + take))
                off += take
                left -= take
            }
        }

        /** Streams everything up to EOF to [sink] (or discards it), slice by slice. */
        suspend fun copyToEof(sink: MitmByteLeg?) {
            if (remaining() > 0) {
                copyExactly(remaining().toLong(), sink)
            }
            while (true) {
                val more = leg.receive() ?: return
                if (more.isEmpty() || sink == null) continue
                var start = 0
                while (start < more.size) {
                    val end = minOf(more.size, start + MAX_RELAY_SLICE_BYTES)
                    sink.send(if (start == 0 && end == more.size) more else more.copyOfRange(start, end))
                    start = end
                }
            }
        }

        /** Hands any bytes read past the message (a pipelined next one) back to the leg. */
        fun pushBackRemainder() {
            if (remaining() > 0) {
                leg.prependToReceiveBuffer(data.copyOfRange(off, data.size))
                off = data.size
            }
        }
    }

    // MARK: - Diagnostics

    /**
     * A request line as it may appear in an exception message — and so in the
     * warning log: cut at the query (query strings carry tokens and ids), then
     * capped like any other line by [describeLine].
     */
    private fun describeRequestLine(line: String): String = describeLine(line.substringBefore('?'))

    /**
     * A wire line (or token) quoted for an exception message, capped at
     * [MAX_LOGGED_LINE_CHARS] so a hostile or merely long line cannot dump itself
     * — cookies, paths and all — into the log.
     */
    private fun describeLine(line: String): String =
        if (line.length <= MAX_LOGGED_LINE_CHARS) {
            "\"$line\""
        } else {
            "\"${line.take(MAX_LOGGED_LINE_CHARS)}...\" (${line.length} chars)"
        }

    companion object {
        /**
         * The hard cap on a buffered body: the request/response the codec holds in
         * memory, and — critically — the decompressed size a `Content-Encoding`
         * body is allowed to reach. A decompression bomb that would inflate past
         * this is refused (the body is forwarded compressed and unseen) rather
         * than allowed to exhaust the process's heap. 4 MiB matches the reference.
         * A body larger than this *on the wire* is not refused but streamed
         * through unrewritten — see [BodyRelay].
         */
        const val MAX_BUFFERED_BODY_BYTES = 4 * 1024 * 1024

        /** The largest slice a [BodyRelay] holds while pumping an over-cap body. */
        const val MAX_RELAY_SLICE_BYTES = 64 * 1024

        /** The wire version the bridge always emits; it speaks HTTP/1.1 to both legs. */
        private const val WIRE_VERSION = "HTTP/1.1"

        private const val MAX_HEAD_BYTES = 64 * 1024
        private const val MAX_CHUNK_LINE_BYTES = 16 * 1024

        /** A stacked coding chain longer than this is a CPU-amplification vector; refuse it. */
        private const val MAX_CODEC_CHAIN_LENGTH = 4

        private const val READ_BUFFER_BYTES = 64 * 1024

        /** How much of a wire line an exception message may quote; see [describeLine]. */
        private const val MAX_LOGGED_LINE_CHARS = 64

        /**
         * Methods that conventionally carry a body, for which an empty body is
         * still framed with `Content-Length: 0` (RFC 9110 §8.6: a server may
         * reject an unframed body-bearing request with 411).
         */
        private val BODY_METHODS = setOf("POST", "PUT", "PATCH")

        private const val CR: Byte = 0x0D
        private const val LF: Byte = 0x0A
        private val CRLF = byteArrayOf(CR, LF)

        private val EMPTY = ByteArray(0)
    }
}
