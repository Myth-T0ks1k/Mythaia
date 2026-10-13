package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/**
 * The HTTP/1.1 MITM bridge loop: it ties a **client** byte-leg and an
 * already-dialed **upstream** byte-leg to a [MitmRewriter], reading one message
 * at a time off each and letting rules read and edit it in flight.
 *
 * It composes the stage-1 framing codec and the pure rewrite engine rather than
 * re-implementing either:
 *
 *  - [Http1Codec] parses a request/response off a leg into an [HttpMessage]
 *    (body de-chunked and decompressed) and serialises the edited message back,
 *    re-framing it with a fresh `Content-Length`. An **unmodified** compressed
 *    body is forwarded byte-for-byte with its `Content-Encoding` intact, because
 *    [Http1Codec.serialize] is handed the original [ParsedHttp1Message].
 *  - [MitmRewriter] decides what each message becomes: a request can be
 *    [MitmRewriteResult.Forward]ed (URL/headers/body possibly rewritten) or
 *    answered on the spot with a [MitmRewriteResult.Respond] that never reaches
 *    upstream; a response is always forwarded, header/body-rewritten.
 *  - [MitmRegexGuard] bounds every `rewrite()` call with a per-message deadline,
 *    so a catastrophic-backtracking pattern from an untrusted `.amrs`
 *    subscription drops the connection instead of hanging the bridge thread.
 *
 * One exchange per loop turn: read a request → rewrite → on `Respond` answer the
 * client and leave upstream untouched; on `Forward` serialise to upstream, read
 * the response, rewrite it (response phase, URL = the originating request's), and
 * serialise back to the client. HTTP/1.1 keep-alive carries the loop to the next
 * request on the same legs until a `Connection: close`, a connection-delimited
 * response, or an EOF on either side ends it. A request that matches no rule
 * still round-trips through the codec, which normalises its framing (a
 * desync-hardening the reference also performs); with a body that no rule
 * touched, the original bytes — compression and all — are what travel on.
 *
 * A body too large to buffer (over [Http1Codec.MAX_BUFFERED_BODY_BYTES]) is not
 * a reason to drop the connection: the codec hands it back as a
 * [ParsedHttp1Message.deferredBody] and the bridge streams it through under its
 * original framing, unrewritten — a request's head still goes through the
 * rewriter (so a reject/redirect, a URL or header rule still apply) and is
 * re-serialised ahead of the streamed body; a response's head goes out verbatim.
 *
 * The bridge does **not** dial its first upstream leg: the session layer provides
 * both legs and, for a cleartext (port 80) interception, wraps the raw transport
 * in stage 1's [PlaintextByteLeg] and builds the bridge with [forCleartext] so
 * the very same loop runs over plaintext with an `http` scheme. It *does* dial
 * further legs when given [dialUpstream]: a transparent rewrite that moves a
 * request to another host or port is honoured by dialing that origin (one leg
 * per origin, kept for the connection's lifetime — see [upstreamFor]) rather
 * than sending the rewritten `Host` to the SNI host. The bridge closes every leg
 * when [run] returns.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmHttp1Bridge(
    private val client: MitmByteLeg,
    private val upstream: MitmByteLeg,
    private val rewriter: MitmRewriter,
    private val codec: Http1Codec = Http1Codec(),
    private val regexDeadlineMs: Long = DEFAULT_REGEX_DEADLINE_MS,
    private val logger: MythaiaLogger = MythaiaLogger("MitmHttp1Bridge"),
    /**
     * The origin [upstream] was dialed to (the SNI host and destination port,
     * on the bridge's scheme). Null when unknown, in which case every request
     * goes to [upstream] whatever its URL says, as before per-request dialing.
     */
    private val origin: HttpOrigin? = null,
    /**
     * Opens a further origin leg for a request whose rewritten URL names a
     * different origin than [origin]; null disables per-request dialing.
     */
    private val dialUpstream: (suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg)? = null
) {

    /** Legs dialed for rewritten origins, keyed by [HttpOrigin], closed with the connection. */
    private val rewrittenUpstreams = HashMap<HttpOrigin, MitmByteLeg>()

    /**
     * Runs the bridge until the connection ends, then closes both legs.
     *
     * A framing or smuggling violation from [Http1Codec] fails the connection
     * closed (nothing half-parsed is forwarded); a regex deadline drops it the
     * same way. Both are deliberate: desynchronising the two legs is worse than
     * losing the connection.
     */
    suspend fun run() {
        try {
            // HTTP/2 is a separate effort; the MITM rewrite path speaks only
            // HTTP/1.1. If either leg negotiated h2, tunnel the bytes through
            // untouched rather than mis-parse frames as HTTP/1 messages.
            if (client.negotiatedAlpn == "h2" || upstream.negotiatedAlpn == "h2") {
                logger.info("h2 ALPN negotiated; MITM rewrite is HTTP/1.1-only — splicing the connection through untouched")
                spliceRaw()
                return
            }
            bridgeLoop()
        } catch (e: Http1ProtocolException) {
            logger.warning("HTTP/1 framing/smuggling violation; closing the connection without forwarding: ${e.message}")
        } finally {
            closeBoth()
        }
    }

    private suspend fun bridgeLoop() {
        while (true) {
            // A client that sent Expect: 100-continue is waiting for the interim
            // 100 before it sends a byte of body; the codec calls back between
            // head and body so it is written then, not after its expect timeout.
            val parsedRequest = codec.readRequest(client, expectContinue = { client.send(CONTINUE_100) })
                ?: return // clean client EOF between requests
            val request = parsedRequest.message

            // WebSocket/Upgrade: once an Upgrade request is seen the connection
            // stops being HTTP/1.1 message framing the moment the server agrees,
            // so forward the request unrewritten and splice the rest of the
            // connection raw in both directions. (Deferral: no rewrite and no
            // keep-alive past an Upgrade, whether or not the server accepts it —
            // never a desync.)
            if (isUpgradeRequest(request)) {
                logger.info("Upgrade request seen; forwarding unrewritten and splicing the connection raw from here")
                forwardRequest(upstream, request, parsedRequest)
                spliceRaw()
                return
            }

            val requestResult = guardedRewrite(request, bodyEditable(parsedRequest))
                ?: return // deadline → drop (finally closes)

            when (requestResult) {
                is MitmRewriteResult.Respond -> {
                    // A reject/redirect: we answer the client ourselves and never
                    // touch upstream. The request body was already read — or, if
                    // it was too large to buffer, is drained here — so the client
                    // leg sits at the next request for keep-alive.
                    parsedRequest.deferredBody?.discard()
                    val close = wantsClose(request.headers)
                    client.send(synthesizedResponseBytes(requestResult.response, close))
                    if (close) return
                }

                is MitmRewriteResult.Forward -> {
                    // Clamp Accept-Encoding to codings we can decode, so the
                    // upstream does not answer in one we would have to pass
                    // through unrewritten (zstd, say) — this is what keeps body
                    // rules effective on a compressed response. The Expect is
                    // dropped: the body is already in hand (or being streamed), so
                    // the origin has nothing to wait for and no 100 to send.
                    val forwarded = stripExpectContinue(clampAcceptEncoding(requestResult.message))
                    val exchangeUpstream = upstreamFor(request.url, forwarded.url)
                    forwardRequest(exchangeUpstream, forwarded, parsedRequest)

                    // The response head carries no URL; response-phase rules match
                    // the originating (post-rewrite) request URL, and HEAD decides
                    // a no-body framing the status alone cannot.
                    var parsedResponse = codec.readResponse(exchangeUpstream, forwarded.method, forwarded.url)
                        ?: return // upstream closed before sending a response

                    // Relay interim 1xx responses (100 Continue, 103 Early Hints)
                    // straight through and keep reading, so the two legs stay framed
                    // in step until the final response.
                    while (isInterimStatus(parsedResponse.message.status)) {
                        client.send(codec.serialize(parsedResponse.message, parsedResponse))
                        parsedResponse = codec.readResponse(exchangeUpstream, forwarded.method, forwarded.url)
                            ?: return
                    }

                    val deferred = parsedResponse.deferredBody
                    if (deferred != null) {
                        // Too large to hold and so never offered to a rule: the head
                        // goes to the client exactly as the origin wrote it, then the
                        // body streams behind it under that head's own framing.
                        logger.info("response body over the ${Http1Codec.MAX_BUFFERED_BODY_BYTES}-byte cap; passed through unrewritten")
                        client.send(deferred.rawHead)
                        deferred.relayTo(client)
                    } else {
                        val response = rewriteResponse(parsedResponse.message, bodyEditable(parsedResponse))
                            ?: return // deadline → drop
                        client.send(codec.serialize(response, parsedResponse, forwarded.method))
                    }

                    if (wantsClose(request.headers) ||
                        wantsClose(parsedResponse.message.headers) ||
                        responseDelimitedByClose(parsedResponse)
                    ) {
                        return
                    }
                }
            }
        }
    }

    /**
     * Writes [message] to [to]: the whole re-framed message when its body was
     * buffered, or — for a body too large to buffer — the head serialised from
     * [message]'s (possibly rewritten) headers under the body's original framing,
     * followed by the body streamed straight off the client leg.
     */
    private suspend fun forwardRequest(to: MitmByteLeg, message: HttpMessage, parsed: ParsedHttp1Message) {
        val deferred = parsed.deferredBody
        if (deferred == null) {
            to.send(codec.serialize(message, parsed))
            return
        }
        logger.info("request body over the ${Http1Codec.MAX_BUFFERED_BODY_BYTES}-byte cap; passed through unrewritten")
        to.send(codec.serializeHeadForRelay(message, deferred, parsed))
        deferred.relayTo(to)
    }

    // MARK: - Per-request upstream selection

    /**
     * The leg a request is sent on. That is [upstream] — the leg dialed for the
     * SNI host — unless the rewriter moved the request ([rewrittenUrl] differs
     * from [originalUrl]) onto another origin on the bridge's own scheme, in
     * which case a leg to that origin is dialed on first use and reused for the
     * rest of the connection, so a transparent rewrite to `https://other.example/`
     * actually reaches `other.example` instead of sending its `Host` to the
     * original host. A request the rewriter left alone always goes to
     * [upstream], whatever its `Host` says; so does every request when
     * [dialUpstream] or [origin] is absent. A rewrite onto a different scheme
     * (`http` from a TLS bridge) would need a transport the dialer cannot open,
     * so it is logged and the request goes to [upstream] with only its URL and
     * `Host` rewritten.
     */
    private suspend fun upstreamFor(originalUrl: String?, rewrittenUrl: String?): MitmByteLeg {
        if (rewrittenUrl == originalUrl) return upstream
        val dial = dialUpstream ?: return upstream
        val home = origin ?: return upstream
        val target = HttpOrigin.parse(rewrittenUrl) ?: return upstream
        if (target == home) return upstream
        if (target.scheme != home.scheme) {
            logger.info("rewritten URL moves to scheme '${target.scheme}', which this ${home.scheme} dialer cannot open; keeping the original upstream")
            return upstream
        }
        rewrittenUpstreams[target]?.let { return it }
        logger.info("rewritten URL names ${target.host}:${target.port}; dialing it for this connection")
        val leg = dial(target.host, target.port, UPSTREAM_ALPNS)
        rewrittenUpstreams[target] = leg
        return leg
    }

    // MARK: - Rewrite under the regex deadline

    /** Runs the rewrite under the deadline; null means "drop the connection". */
    private fun guardedRewrite(message: HttpMessage, bodyEditable: Boolean): MitmRewriteResult? =
        try {
            MitmRegexGuard.runWithRegexDeadline(regexDeadlineMs) { rewriter.rewrite(message, bodyEditable) }
        } catch (_: RegexDeadlineExceededException) {
            null
        }

    /**
     * Whether a parsed message's body is plain text the rules may edit. A body
     * whose content-coding could not be decoded (unsupported, malformed, or past
     * the 4 MiB cap) is opaque compressed bytes: offering it to a body-replace
     * rule would run a regex over the compressed stream and corrupt it, so those
     * rules are skipped for it. A deferred (over-cap) body is not in hand at all.
     */
    private fun bodyEditable(parsed: ParsedHttp1Message): Boolean =
        parsed.deferredBody == null && (parsed.bodyWasDecoded || !parsed.hadContentCoding)

    /**
     * Drops an `Expect: 100-continue` from a request about to be forwarded. The
     * bridge has already answered that expectation itself (see [bridgeLoop]) and
     * sends the body without pause, so leaving it in would have the origin emit
     * a 100 the client has already had — or, for an origin that honours the
     * expectation strictly, make it wait on a body that is already on its way.
     */
    private fun stripExpectContinue(request: HttpMessage): HttpMessage {
        val kept = request.headers.filterNot {
            it.isNamed("Expect") && it.value.trim().equals("100-continue", ignoreCase = true)
        }
        return if (kept.size == request.headers.size) request else request.copy(headers = kept)
    }

    /**
     * Narrows a forwarded request's `Accept-Encoding` to the codings [Http1Codec]
     * can decode, preserving the client's own preference order and dropping a
     * q-value. A request that asked for no encoding is left untouched; one whose
     * every coding is undecodable is pinned to `identity`, so the upstream never
     * answers in something we would have to forward opaque. Absent the clamp, a
     * server free to pick e.g. `zstd` would defeat every body rule.
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

    /**
     * Rewrites a response (header + body passes) under the deadline, returning
     * the message to serialise, or null to drop. The rewrite (reject/redirect)
     * pass is request-only, so a response never short-circuits — but a future
     * response-phase synthesizer is honoured defensively rather than dropped.
     */
    private fun rewriteResponse(message: HttpMessage, bodyEditable: Boolean): HttpMessage? =
        when (val result = guardedRewrite(message, bodyEditable)) {
            null -> null
            is MitmRewriteResult.Forward -> result.message
            is MitmRewriteResult.Respond -> {
                logger.warning("response phase produced a synthesized response; forwarding it to the client verbatim")
                result.response
            }
        }

    // MARK: - Synthesized response framing

    /**
     * Serialises a rule-synthesized response for the client: its own framing
     * headers are re-derived (a fresh `Content-Length` via [Http1Codec]), a
     * `Date` is stamped, and hop-by-hop headers are dropped — a synthesized
     * message has no end-to-end connection to speak for. [close] adds
     * `Connection: close` when the exchange will not be kept alive.
     */
    private fun synthesizedResponseBytes(response: HttpMessage, close: Boolean): ByteArray {
        val headers = ArrayList<HttpHeader>(response.headers.size + 2)
        headers.add(HttpHeader("Date", httpDate()))
        for (header in response.headers) {
            if (header.isNamed("Date")) continue // we stamp our own, authoritative one
            if (HOP_BY_HOP.any { header.isNamed(it) }) continue
            headers.add(header)
        }
        if (close) headers.add(HttpHeader("Connection", "close"))
        return codec.serialize(response.copy(headers = headers), original = null)
    }

    private fun httpDate(): String = IMF_FIXDATE.format(Instant.now())

    // MARK: - Connection lifecycle predicates

    /** Any `Connection: close` token (case-insensitive) across the `Connection` headers. */
    private fun wantsClose(headers: List<HttpHeader>): Boolean =
        headers.asSequence()
            .filter { it.isNamed("Connection") }
            .flatMap { it.value.splitToSequence(',') }
            .any { it.trim().equals("close", ignoreCase = true) }

    /**
     * Whether the upstream response was delimited by the connection closing
     * (HTTP/1.0-style: no `Content-Length`, no `Transfer-Encoding`, a
     * body-bearing status). After such a response the upstream leg is at EOF, so
     * the connection cannot be kept alive however the client framed its request.
     * Checked against the headers **as received**, since [Http1Codec] re-frames a
     * fresh `Content-Length` onto the copy sent to the client.
     */
    private fun responseDelimitedByClose(parsed: ParsedHttp1Message): Boolean {
        val status = parsed.message.status ?: return true
        if (isNoBodyStatus(status)) return false
        val hasContentLength = parsed.message.headers.any { it.isNamed("Content-Length") }
        val hasTransferEncoding = parsed.message.headers.any { it.isNamed("Transfer-Encoding") }
        return !hasContentLength && !hasTransferEncoding
    }

    /** Statuses that carry no body by definition (RFC 9110 §6.4.1); mirrors [Http1Codec]. */
    private fun isNoBodyStatus(status: Int): Boolean = when (status) {
        204, 205, 304 -> true
        else -> status in 100..199 && status != 101
    }

    /** An interim (`1xx`) status other than `101` — forwarded and followed by a final response. */
    private fun isInterimStatus(status: Int?): Boolean =
        status != null && status in 100..199 && status != 101

    /** Presence of an `Upgrade` header is enough to treat the connection as leaving HTTP/1.1. */
    private fun isUpgradeRequest(message: HttpMessage): Boolean =
        message.headers.any { it.isNamed("Upgrade") }

    // MARK: - Raw splice (upgrade / h2 passthrough)

    /**
     * Copies bytes both ways between the two legs until either direction reaches
     * EOF, then closes both. Used for an h2 connection and past an Upgrade, where
     * the bytes are no longer HTTP/1.1 messages the bridge can frame.
     */
    private suspend fun spliceRaw() = coroutineScope {
        launch {
            try {
                pump(client, upstream)
            } finally {
                closeBoth()
            }
        }
        launch {
            try {
                pump(upstream, client)
            } finally {
                closeBoth()
            }
        }
    }

    private suspend fun pump(from: MitmByteLeg, to: MitmByteLeg) {
        try {
            while (true) {
                val chunk = from.receive() ?: break
                if (chunk.isNotEmpty()) to.send(chunk)
            }
        } catch (_: Exception) {
            // A leg closed underneath us as the tunnel ended; the finally closes both.
        }
    }

    /** Closes the client leg, the session-dialed upstream, and every origin leg dialed for a rewrite. */
    private fun closeBoth() {
        runCatching { client.close() }
        runCatching { upstream.close() }
        for (leg in rewrittenUpstreams.values) runCatching { leg.close() }
        rewrittenUpstreams.clear()
    }

    companion object {
        /**
         * Per-message rewrite deadline. Legitimate gate/body matching costs
         * microseconds; this is orders of magnitude above that so a scheduling
         * hiccup never false-trips, while still bounding a catastrophic pattern
         * to a second of one connection thread before the connection is dropped.
         */
        const val DEFAULT_REGEX_DEADLINE_MS = 1000L

        /** The interim response written to a client that sent `Expect: 100-continue`. */
        private val CONTINUE_100 = "HTTP/1.1 100 Continue\r\n\r\n".toByteArray(Charsets.ISO_8859_1)

        /** The h1 bridge speaks HTTP/1.1 on every upstream leg, including one dialed for a rewrite. */
        private val UPSTREAM_ALPNS = listOf("http/1.1")

        /**
         * Hop-by-hop headers (RFC 9110 §7.6.1) stripped from a synthesized
         * response. `Content-Length` is intentionally absent: [Http1Codec]
         * re-frames it, so it is re-derived rather than dropped here.
         */
        private val HOP_BY_HOP = listOf(
            "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
            "TE", "Trailer", "Transfer-Encoding", "Upgrade"
        )

        /** Content codings [Http1Codec] can decode, for the Accept-Encoding clamp. */
        private val DECODABLE_ENCODINGS = setOf("gzip", "deflate", "br", "identity", "x-gzip")

        /** RFC 9110 IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), fixed-locale, UTC. */
        private val IMF_FIXDATE =
            DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
                .withZone(ZoneOffset.UTC)

        /**
         * Builds a bridge for a TLS-terminated interception (scheme `https`) from
         * an already-selected rule set. Both legs must already be dialed. With
         * [originHost]/[originPort] (what [upstream] was dialed to) and a
         * [dialUpstream], a request rewritten onto another `https` origin is
         * dialed there instead of being sent to [upstream] — see [upstreamFor].
         */
        fun forTls(
            client: MitmByteLeg,
            upstream: MitmByteLeg,
            ruleSet: MitmRuleSet,
            regexDeadlineMs: Long = DEFAULT_REGEX_DEADLINE_MS,
            logger: MythaiaLogger = MythaiaLogger("MitmHttp1Bridge"),
            originHost: String? = null,
            originPort: Int = 443,
            dialUpstream: (suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg)? = null
        ): MitmHttp1Bridge =
            MitmHttp1Bridge(
                client, upstream, MitmRewriter(ruleSet), Http1Codec(scheme = "https"), regexDeadlineMs, logger,
                origin = originHost?.let { HttpOrigin.of("https", it, originPort) },
                dialUpstream = dialUpstream
            )

        /**
         * Builds a bridge for a cleartext (port 80) interception (scheme `http`)
         * from an already-selected rule set. The legs are stage 1's
         * [PlaintextByteLeg] over the raw transport, so the identical loop runs
         * over plaintext — the only difference is the reconstructed-URL scheme.
         * [originHost]/[originPort]/[dialUpstream] work as in [forTls], for a
         * rewrite onto another `http` origin; the dialer must then open a
         * cleartext leg.
         */
        fun forCleartext(
            client: MitmByteLeg,
            upstream: MitmByteLeg,
            ruleSet: MitmRuleSet,
            regexDeadlineMs: Long = DEFAULT_REGEX_DEADLINE_MS,
            logger: MythaiaLogger = MythaiaLogger("MitmHttp1Bridge"),
            originHost: String? = null,
            originPort: Int = 80,
            dialUpstream: (suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg)? = null
        ): MitmHttp1Bridge =
            MitmHttp1Bridge(
                client, upstream, MitmRewriter(ruleSet), Http1Codec(scheme = "http"), regexDeadlineMs, logger,
                origin = originHost?.let { HttpOrigin.of("http", it, originPort) },
                dialUpstream = dialUpstream
            )
    }
}
