package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.naive.http2.Http2Framer
import com.mythaia.vpn.util.MythaiaLogger
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/**
 * The HTTP/2 MITM bridge: it terminates the client's h2 connection through the
 * stage-1 [MitmHttp2Server], and for every request stream that server surfaces it
 * runs the same [MitmRewriter] the HTTP/1.1 bridge does, dials the origin over
 * **HTTP/1.1**, and streams the rewritten response back on the originating stream.
 *
 * # Where the two protocols meet
 *
 * The client speaks h2; the origin is spoken to in h1. [MitmHttp2Server] hands up a
 * fully-assembled request [HttpMessage] per stream and encodes a response
 * [HttpMessage] back onto it; [Http1Codec] serialises a request onto the upstream
 * leg and reads the response off it. The bridge is the seam between them, per
 * stream:
 *
 *  1. Run [MitmRewriter] (request phase) under [MitmRegexGuard]'s per-message
 *     deadline. A [MitmRewriteResult.Respond] (reject / redirect) is encoded
 *     straight back on the stream with [MitmHttp2Server.Http2ServerStream.sendResponse]
 *     and **no upstream dial happens**.
 *  2. A [MitmRewriteResult.Forward] dials one upstream h1 leg for this stream
 *     (`dialUpstream(..., ["http/1.1"])`), serialises the reframed request with
 *     [Http1Codec.serialize], reads the response with [Http1Codec.readResponse],
 *     rewrites it (response phase), and encodes it back on the client stream.
 *
 * One upstream leg per stream is dialed — the simplest correct mapping (no h1
 * keep-alive pool to multiplex an h2 connection over) — and closed when the stream
 * ends.
 *
 * # Concurrency and cancellation
 *
 * Streams are independent and must not head-of-line block one another: a slow
 * origin on one stream cannot stall another. So each stream's exchange is
 * [launch]ed on the bridge's own scope and progresses concurrently; the read loop
 * ([MitmHttp2Server.run]) runs as a sibling. A client RST_STREAM is propagated as
 * coroutine cancellation: a per-stream watcher awaits
 * [MitmHttp2Server.Http2ServerStream.awaitAborted] and cancels that stream's
 * exchange, so an in-flight upstream dial or fetch is abandoned at once instead of
 * running to completion for a response no one will read.
 *
 * # Body handling is Http1Codec's, not re-implemented
 *
 * The request the h2 server buffered is the raw concatenated DATA bytes — still
 * `Content-Encoding`-compressed if the client compressed it — so it is adapted into
 * the same [ParsedHttp1Message] shape the h1 codec produces ([parseBufferedRequest]),
 * which reuses [Http1Codec.decodeBody] (gzip/deflate/br under the 4 MiB cap) and
 * lets [Http1Codec.serialize] make the identical verbatim-vs-decompressed decision
 * on the way to the origin. The upstream response goes through [Http1Codec.readResponse]
 * unchanged, so its `bodyWasDecoded` gate and cap are the h1 ones; the only h2-specific
 * step is re-selecting the body and dropping `Content-Length`/`Content-Encoding` for
 * DATA framing ([encodeResponseForClient]), because h2 frames a body by DATA +
 * END_STREAM rather than by a `Content-Length` the codec would re-derive. The
 * `Accept-Encoding` clamp on the forwarded request is exactly the h1 bridge's.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmHttp2Bridge(
    private val client: MitmByteLeg,
    private val host: String,
    private val port: Int,
    private val rewriter: MitmRewriter,
    private val dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg,
    private val codec: Http1Codec = Http1Codec(scheme = "https"),
    private val regexDeadlineMs: Long = MitmHttp1Bridge.DEFAULT_REGEX_DEADLINE_MS,
    private val logger: MythaiaLogger = MythaiaLogger("MitmHttp2Bridge")
) {

    /**
     * Terminates the h2 connection and drives every request stream concurrently
     * until the client closes or the connection is torn down, then closes the
     * client leg (the enclosed [MitmHttp2Server] owns and closes it). Each stream's
     * upstream leg is closed when that stream ends.
     */
    suspend fun run() {
        val server = MitmHttp2Server(client, host)
        try {
            coroutineScope {
                // The read loop is a sibling of the per-stream handlers, so a slow
                // stream never stops new HEADERS from being demultiplexed.
                launch { server.run() }
                while (true) {
                    val stream = server.acceptRequest() ?: break
                    launch { handleStream(stream) }
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger.warning("[h2] $host: bridge loop ended on ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            server.close()
        }
    }

    /**
     * Runs one stream's exchange, racing it against a client abort so a RST_STREAM
     * cancels the in-flight upstream work. The watcher is torn down as soon as the
     * exchange finishes normally, so a completed stream leaks no suspended coroutine.
     */
    private suspend fun handleStream(stream: MitmHttp2Server.Http2ServerStream) {
        coroutineScope {
            val exchange = launch { runExchange(stream) }
            val abortWatcher = launch {
                stream.awaitAborted()
                exchange.cancel(CancellationException("client reset h2 stream ${stream.streamID}"))
            }
            exchange.join()
            abortWatcher.cancel()
        }
    }

    private suspend fun runExchange(stream: MitmHttp2Server.Http2ServerStream) {
        var upstream: MitmByteLeg? = null
        try {
            val parsedRequest = parseBufferedRequest(stream.request)
            val requestEditable = parsedRequest.bodyWasDecoded || !parsedRequest.hadContentCoding

            when (val result = guardedRewrite(parsedRequest.message, requestEditable)) {
                null -> {
                    // Regex deadline tripped. A catastrophic pattern is per-connection,
                    // but on h2 the smallest safe blast radius is this one stream.
                    logger.warning("[h2] $host stream ${stream.streamID}: request rewrite hit the regex deadline; RST")
                    runCatching { stream.reset(INTERNAL_ERROR) }
                }
                is MitmRewriteResult.Respond -> {
                    // Reject / redirect: answer on the stream, never dial upstream.
                    stream.sendResponse(prepareSynthesizedResponse(result.response))
                }
                is MitmRewriteResult.Forward -> {
                    upstream = forwardAndRespond(stream, result.message, parsedRequest)
                }
            }
        } catch (e: CancellationException) {
            // Client RST_STREAM or connection teardown. The server already RST the
            // stream toward the client on a client-initiated reset, so nothing more
            // needs sending — just let the upstream leg close in the finally.
            throw e
        } catch (e: Http1ProtocolException) {
            logger.warning("[h2] $host stream ${stream.streamID}: upstream framing/smuggling violation; RST: ${e.message}")
            runCatching { stream.reset(INTERNAL_ERROR) }
        } catch (e: Exception) {
            logger.warning("[h2] $host stream ${stream.streamID}: exchange failed (${e.javaClass.simpleName}: ${e.message}); RST")
            runCatching { stream.reset(INTERNAL_ERROR) }
        } finally {
            upstream?.let { leg -> runCatching { leg.close() } }
        }
    }

    /**
     * Dials one upstream h1 leg, forwards the (reframed) request, reads and rewrites
     * the response, and streams it back on [stream]. Returns the dialed leg so
     * [runExchange]'s finally closes it even on an early return.
     */
    private suspend fun forwardAndRespond(
        stream: MitmHttp2Server.Http2ServerStream,
        forwardMessage: HttpMessage,
        parsedRequest: ParsedHttp1Message
    ): MitmByteLeg {
        // Clamp Accept-Encoding to codings we can decode, exactly as the h1 bridge
        // does, so the origin never answers in one (zstd, …) we'd have to pass
        // through opaque and defeat every body rule.
        val forwarded = clampAcceptEncoding(forwardMessage)
        val upstream = dialUpstream(host, port, UPSTREAM_ALPNS)
        // serialize makes the verbatim-vs-decompressed call from parsedRequest: an
        // untouched compressed body rides out with Content-Encoding intact, an
        // edited one goes out decompressed with the coding dropped.
        upstream.send(codec.serialize(forwarded, parsedRequest))

        var parsedResponse = codec.readResponse(upstream, forwarded.method, forwarded.url)
            ?: run {
                logger.warning("[h2] $host stream ${stream.streamID}: upstream closed before responding; RST")
                runCatching { stream.reset(INTERNAL_ERROR) }
                return upstream
            }
        // Interim 1xx (100 Continue, 103 Early Hints): the client stream's response
        // is one-shot, so — unlike the h1 bridge, which relays them — the h2 bridge
        // consumes and drops them and forwards only the final response. (Deferral.)
        while (isInterimStatus(parsedResponse.message.status)) {
            parsedResponse = codec.readResponse(upstream, forwarded.method, forwarded.url)
                ?: run {
                    logger.warning("[h2] $host stream ${stream.streamID}: upstream closed after an interim response; RST")
                    runCatching { stream.reset(INTERNAL_ERROR) }
                    return upstream
                }
        }

        val responseEditable = parsedResponse.bodyWasDecoded || !parsedResponse.hadContentCoding
        val rewritten = rewriteResponse(parsedResponse.message, responseEditable)
            ?: run {
                logger.warning("[h2] $host stream ${stream.streamID}: response rewrite hit the regex deadline; RST")
                runCatching { stream.reset(INTERNAL_ERROR) }
                return upstream
            }
        stream.sendResponse(encodeResponseForClient(parsedResponse, rewritten))
        return upstream
    }

    // MARK: - Rewrite under the regex deadline

    /** Runs the rewrite under the deadline; null means "drop this stream". */
    private fun guardedRewrite(message: HttpMessage, bodyEditable: Boolean): MitmRewriteResult? =
        try {
            MitmRegexGuard.runWithRegexDeadline(regexDeadlineMs) { rewriter.rewrite(message, bodyEditable) }
        } catch (_: RegexDeadlineExceededException) {
            null
        }

    /**
     * Rewrites a response (header + body passes) under the deadline, returning the
     * message to encode, or null to drop. The reject/redirect pass is request-only,
     * so a response never short-circuits — but a future response-phase synthesizer
     * is honoured defensively rather than dropped, mirroring the h1 bridge.
     */
    private fun rewriteResponse(message: HttpMessage, bodyEditable: Boolean): HttpMessage? =
        when (val result = guardedRewrite(message, bodyEditable)) {
            null -> null
            is MitmRewriteResult.Forward -> result.message
            is MitmRewriteResult.Respond -> {
                logger.warning("[h2] $host: response phase produced a synthesized response; forwarding it to the client verbatim")
                result.response
            }
        }

    // MARK: - Request adaptation and forwarding

    /**
     * Adapts the h2 server's buffered request into the [ParsedHttp1Message] the h1
     * codec produces, reusing [Http1Codec.decodeBody] for the (rare) compressed
     * request body so the request-phase body-editability gate and the forward-path
     * compression decision are identical to the h1 bridge's, without re-implementing
     * either. The h2 server already capped the raw body at 4 MiB; `decodeBody`
     * applies the same cap to the decompressed size (returning null → forwarded
     * verbatim) so a request-side decompression bomb is refused too.
     */
    private fun parseBufferedRequest(request: HttpMessage): ParsedHttp1Message {
        val rawBody = request.body
        val codingValues = request.headers.filter { it.isNamed("Content-Encoding") }.map { it.value }
        val contentEncoding = when (codingValues.size) {
            0 -> null
            1 -> codingValues[0]
            else -> codingValues.joinToString(", ")
        }
        val hadContentCoding = contentEncoding != null && contentEncoding
            .split(',')
            .map { it.trim().lowercase() }
            .any { it.isNotEmpty() && it != "identity" }

        var body = rawBody
        var decoded = false
        if (hadContentCoding) {
            codec.decodeBody(rawBody, contentEncoding!!)?.let { body = it; decoded = true }
        }
        return ParsedHttp1Message(
            message = request.copy(body = body),
            rawBody = rawBody,
            contentEncoding = contentEncoding,
            hadContentCoding = hadContentCoding,
            bodyWasDecoded = decoded
        )
    }

    /**
     * Narrows a forwarded request's `Accept-Encoding` to the codings [Http1Codec]
     * can decode, preserving the client's preference order and dropping q-values —
     * byte-for-byte the h1 bridge's clamp. A request that asked for no encoding is
     * left untouched; one whose every coding is undecodable is pinned to `identity`.
     */
    private fun clampAcceptEncoding(request: HttpMessage): HttpMessage {
        if (request.headers.none { it.isNamed("Accept-Encoding") }) return request
        val allowed = request.headers.asSequence()
            .filter { it.isNamed("Accept-Encoding") }
            .flatMap { it.value.splitToSequence(',') }
            .map { it.substringBefore(';').trim().lowercase() }
            .filter { it in DECODABLE_ENCODINGS }
            .distinct()
            .toList()
        val value = if (allowed.isEmpty()) "identity" else allowed.joinToString(", ")
        val headers = request.headers.filterNot { it.isNamed("Accept-Encoding") } +
            HttpHeader("Accept-Encoding", value)
        return request.copy(headers = headers)
    }

    // MARK: - Response encoding for the client stream

    /**
     * Picks the response body and headers to encode back on the h2 stream, applying
     * the identical verbatim-vs-decompressed decision [Http1Codec.serialize] makes,
     * adapted to h2 framing: `Content-Length` is always dropped (h2 frames the body
     * by DATA + END_STREAM, so a stale length — the compressed size against a
     * decompressed body — would make the message malformed), and `Content-Encoding`
     * is dropped only when the body was actually decoded. An untouched compressed
     * body is sent verbatim with its coding intact for the client to decompress.
     */
    private fun encodeResponseForClient(parsed: ParsedHttp1Message, rewritten: HttpMessage): HttpMessage {
        val modified = !rewritten.body.contentEquals(parsed.message.body)
        val body: ByteArray
        val dropContentEncoding: Boolean
        if (!modified && parsed.hadContentCoding) {
            body = parsed.rawBody
            dropContentEncoding = false
        } else {
            body = rewritten.body
            dropContentEncoding = parsed.bodyWasDecoded
        }
        val headers = rewritten.headers.filterNot {
            it.isNamed("Content-Length") || (dropContentEncoding && it.isNamed("Content-Encoding"))
        }
        return rewritten.copy(headers = headers, body = body)
    }

    /**
     * Prepares a rule-synthesized response for the client stream: a `Date` is
     * stamped and any `Content-Length` is dropped (h2 re-derives framing from the
     * DATA it sends). Hop-by-hop headers illegal over h2 are dropped by the server's
     * response encoder, so a synthesized message — which carries none anyway — needs
     * no extra scrubbing here.
     */
    private fun prepareSynthesizedResponse(response: HttpMessage): HttpMessage {
        val headers = ArrayList<HttpHeader>(response.headers.size + 1)
        headers.add(HttpHeader("Date", httpDate()))
        for (header in response.headers) {
            if (header.isNamed("Date") || header.isNamed("Content-Length")) continue
            headers.add(header)
        }
        return response.copy(headers = headers)
    }

    private fun httpDate(): String = IMF_FIXDATE.format(Instant.now())

    /** An interim (`1xx`) status other than `101`. */
    private fun isInterimStatus(status: Int?): Boolean =
        status != null && status in 100..199 && status != 101

    companion object {
        /** The origin is always spoken to in HTTP/1.1; the bridge translates h2⇄h1. */
        private val UPSTREAM_ALPNS = listOf("http/1.1")

        /** Content codings [Http1Codec] can decode, for the Accept-Encoding clamp. */
        private val DECODABLE_ENCODINGS = setOf("gzip", "deflate", "br", "identity", "x-gzip")

        /** RFC 9110 IMF-fixdate, fixed-locale, UTC — matches the h1 bridge's stamp. */
        private val IMF_FIXDATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
                .withZone(ZoneOffset.UTC)

        /** RST_STREAM error code used when the bridge cannot complete a stream. */
        private val INTERNAL_ERROR = Http2Framer.ErrorCode.INTERNAL_ERROR

        /**
         * Builds an h2 bridge for a TLS-terminated interception (origin scheme
         * `https`) from an already-selected rule set. [dialUpstream] is called once
         * per stream to open that stream's HTTP/1.1 origin leg.
         */
        fun forTls(
            client: MitmByteLeg,
            host: String,
            port: Int,
            ruleSet: MitmRuleSet,
            dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg,
            regexDeadlineMs: Long = MitmHttp1Bridge.DEFAULT_REGEX_DEADLINE_MS,
            logger: MythaiaLogger = MythaiaLogger("MitmHttp2Bridge")
        ): MitmHttp2Bridge =
            MitmHttp2Bridge(
                client, host, port, MitmRewriter(ruleSet), dialUpstream,
                Http1Codec(scheme = "https"), regexDeadlineMs, logger
            )
    }
}
