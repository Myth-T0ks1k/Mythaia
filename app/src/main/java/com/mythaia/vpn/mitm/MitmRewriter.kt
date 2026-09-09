package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger
import java.net.URI
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.Charset
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * The outcome of applying a rule set to one message.
 *
 * A request-phase `rewrite` can answer the client itself — a `302` or a
 * synthesized `200` that never reaches upstream — so the result is not always
 * "the same message, edited": it is either the (possibly rewritten) message to
 * [Forward] onward, or a [Respond] the caller sends back to the client in its
 * place. Splitting the two here keeps the caller from having to sniff a status
 * code to tell a rewritten request from a short-circuit.
 */
sealed class MitmRewriteResult {
    /** Forward this message (headers/body/URL possibly rewritten) to the other leg. */
    data class Forward(val message: HttpMessage) : MitmRewriteResult()

    /** Answer the client with this synthesized response; do not dial upstream. */
    data class Respond(val response: HttpMessage) : MitmRewriteResult()
}

/**
 * Applies a [MitmRuleSet]'s rules to an [HttpMessage], the pure core of the MITM
 * rewrite path.
 *
 * This is a total function of `(rule set, message) → result`: no sockets, no
 * framing, no decompression. The caller hands it a message whose body is already
 * decompressed (see [HttpMessage]) and re-frames whatever comes back with a fresh
 * `Content-Length`, because only the framing layer knows how the original body
 * was framed. The 4 MiB buffered-body cap and `Content-Encoding` handling the
 * reference documents are that caller's job, not this transform's.
 *
 * The rule set is assumed to be pre-selected for the message's host (suffix
 * matching, most-specific-wins, is the session layer's job); this only decides
 * which of the set's rules fire for the message's phase and URL. Order within a
 * message is fixed and matches the reference's documented semantics:
 *
 *  1. **Rewrite** (request phase only). Rewrite rules are tried in order; the
 *     first that both matches and resolves wins. A reject/redirect short-circuits
 *     with a [MitmRewriteResult.Respond]; a transparent rewrite changes the URL
 *     and `Host`, then processing continues.
 *  2. **Headers.** Every matching `header-add` / `header-delete` / `header-replace`
 *     of the message's phase applies, in rule order.
 *  3. **Body.** Every matching `body-replace` and `body-json` of the message's
 *     phase composes, in rule order, over the body. A `body-replace` runs over
 *     the decoded text body; a `body-json` patches the body only when its
 *     `Content-Type` is a JSON media type, leaving any other body untouched.
 *
 * The gate for the header and body passes is tested against the message's URL as
 * it arrived — for a request, before any transparent rewrite of step 1. This is a
 * deliberate, documented simplification: it keeps the transform deterministic and
 * order-independent, and matches the reading that a rule's `url-pattern` selects
 * "which requests, as received". A response's URL is the originating request's
 * post-rewrite URL, which the caller sets on the message, so response gating needs
 * no special case.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmRewriter(ruleSet: MitmRuleSet) {

    private val logger = MythaiaLogger("MitmRewriter")

    /** A rule with its gate (and any body/rewrite templates) compiled once, up front. */
    private class CompiledRule(
        val phase: HttpPhase,
        val gate: Regex,
        val operation: MitmOperation,
        val bodySearch: Regex?,
        val bodyReplacement: MitmCaptureTemplate?,
        val rewriteTemplate: MitmCaptureTemplate?
    )

    private val rules: List<CompiledRule> = ruleSet.rules.mapNotNull { compile(it) }

    private fun compile(rule: MitmRule): CompiledRule? {
        // The parser already validated these compile; recompiling defensively here means a
        // directly-constructed rule set (a test, a future in-app editor) can't slip an
        // uncompilable pattern into the hot path — it is dropped with a warning instead.
        val gate = runCatching { Regex(rule.urlPattern) }.getOrNull() ?: run {
            logger.warning("dropping rule: url-pattern did not compile: ${rule.urlPattern}")
            return null
        }
        return when (val op = rule.operation) {
            is MitmOperation.BodyReplace -> {
                val search = runCatching { Regex(op.search) }.getOrNull() ?: run {
                    logger.warning("dropping body-replace rule: search did not compile: ${op.search}")
                    return null
                }
                CompiledRule(rule.phase, gate, op, search, MitmCaptureTemplate(op.replacement), null)
            }
            is MitmOperation.Rewrite -> {
                val template = when (val action = op.action) {
                    is MitmRewriteAction.Transparent -> MitmCaptureTemplate(action.url)
                    is MitmRewriteAction.Redirect302 -> MitmCaptureTemplate(action.url)
                    else -> null
                }
                CompiledRule(rule.phase, gate, op, null, null, template)
            }
            else -> CompiledRule(rule.phase, gate, op, null, null, null)
        }
    }

    /**
     * Applies every matching rule to [message] and returns what to do with it.
     *
     * [bodyEditable] is false when [message]'s body is not text the rules can
     * safely edit — a still-compressed body whose coding could not be decoded
     * (unsupported, malformed, or past the decompression cap). Body-replace
     * rules are then skipped so they cannot run a regex over opaque bytes and
     * corrupt them; header, URL and reject/redirect rules still apply. The
     * default is true, for a body that is already plain text.
     */
    fun rewrite(message: HttpMessage, bodyEditable: Boolean = true): MitmRewriteResult {
        val normalizedUrl = normalizeUrl(message.url)

        var url = message.url
        var headers = message.headers
        var body = message.body

        // 1. Rewrite pass — request phase only; first rule that resolves wins.
        if (message.phase == HttpPhase.REQUEST) {
            for (rule in rules) {
                if (rule.phase != HttpPhase.REQUEST) continue
                val op = rule.operation as? MitmOperation.Rewrite ?: continue
                val match = matchGate(rule.gate, normalizedUrl) ?: continue
                when (val resolved = resolveRewrite(op.action, rule.rewriteTemplate, match, message)) {
                    // Matched but did not resolve (a templated target that expanded to an
                    // invalid URL) — a later rewrite rule may still win.
                    null -> continue
                    is ResolvedRewrite.Transparent -> {
                        url = resolved.url
                        headers = rewriteHost(headers, resolved.authority)
                        break
                    }
                    is ResolvedRewrite.Respond -> return MitmRewriteResult.Respond(resolved.response)
                }
            }
        }

        // 2. Header pass — every matching header rule of this phase, in rule order.
        for (rule in rules) {
            if (rule.phase != message.phase) continue
            val op = rule.operation
            if (op !is MitmOperation.HeaderAdd &&
                op !is MitmOperation.HeaderDelete &&
                op !is MitmOperation.HeaderReplace
            ) {
                continue
            }
            if (matchGate(rule.gate, normalizedUrl) == null) continue
            headers = when (op) {
                is MitmOperation.HeaderAdd -> headers + HttpHeader(op.name, op.value)
                is MitmOperation.HeaderDelete -> headers.filterNot { it.isNamed(op.name) }
                is MitmOperation.HeaderReplace ->
                    headers.map { if (it.isNamed(op.name)) HttpHeader(op.name, op.value) else it }
                else -> headers
            }
        }

        // 3. Body pass — every matching body-replace / body-json of this phase composes, in rule order.
        val bodyOps = rules.filter { rule ->
            rule.phase == message.phase &&
                (rule.operation is MitmOperation.BodyReplace || rule.operation is MitmOperation.BodyJson) &&
                matchGate(rule.gate, normalizedUrl) != null
        }
        if (bodyEditable && bodyOps.isNotEmpty()) {
            // The body's content-type and charset are the ones it arrived with; a header
            // rule that rewrote Content-Type did not transcode or reshape the bytes.
            body = applyBodyOps(bodyOps, message.headers, body)
        }

        return MitmRewriteResult.Forward(message.copy(url = url, headers = headers, body = body))
    }

    // MARK: - Rewrite resolution

    private sealed class ResolvedRewrite {
        data class Transparent(val url: String, val authority: String) : ResolvedRewrite()
        data class Respond(val response: HttpMessage) : ResolvedRewrite()
    }

    private fun resolveRewrite(
        action: MitmRewriteAction,
        template: MitmCaptureTemplate?,
        match: MatchResult,
        message: HttpMessage
    ): ResolvedRewrite? {
        return when (action) {
            is MitmRewriteAction.Transparent -> {
                val expanded = expandTarget(action.url, template, match)
                val replacement = parseReplacementUrl(expanded) ?: return null
                if (!isWireSafeRequestTarget(replacement.requestTarget)) return null
                ResolvedRewrite.Transparent(expanded, replacement.authority)
            }
            is MitmRewriteAction.Redirect302 -> {
                val location = expandTarget(action.url, template, match).trim()
                // A `302` needs a real absolute URL and a wire-safe `Location` value; a
                // capture that expanded to a CR/LF/NUL would be a response-splitting vector.
                if (parseReplacementUrl(location) == null) return null
                if (!isWireSafeHeaderValue(location)) return null
                ResolvedRewrite.Respond(
                    HttpMessage.response(
                        status = 302,
                        url = message.url,
                        headers = listOf(HttpHeader("Location", location)),
                        body = ByteArray(0),
                        version = message.version
                    )
                )
            }
            is MitmRewriteAction.Reject200Text -> {
                val text = action.content.ifEmpty { DEFAULT_TEXT }
                ResolvedRewrite.Respond(
                    HttpMessage.response(
                        status = 200,
                        url = message.url,
                        headers = listOf(HttpHeader("Content-Type", "text/plain; charset=utf-8")),
                        body = text.toByteArray(StandardCharsets.UTF_8),
                        version = message.version
                    )
                )
            }
            MitmRewriteAction.Reject200Gif -> ResolvedRewrite.Respond(
                HttpMessage.response(
                    status = 200,
                    url = message.url,
                    headers = listOf(HttpHeader("Content-Type", "image/gif")),
                    body = TINY_GIF.copyOf(),
                    version = message.version
                )
            )
            is MitmRewriteAction.Reject200Data -> {
                val source = action.base64.ifEmpty { DEFAULT_DATA_BASE64 }
                val decoded = runCatching { Base64.getDecoder().decode(source) }.getOrNull() ?: ByteArray(0)
                ResolvedRewrite.Respond(
                    HttpMessage.response(
                        status = 200,
                        url = message.url,
                        headers = listOf(HttpHeader("Content-Type", "application/octet-stream")),
                        body = decoded,
                        version = message.version
                    )
                )
            }
        }
    }

    /** Expands a rewrite target's capture references, or returns it verbatim when it has none. */
    private fun expandTarget(url: String, template: MitmCaptureTemplate?, match: MatchResult): String =
        if (template != null && template.referencesCaptures) template.expand(match.groupValues) else url

    // MARK: - URL gate

    private fun matchGate(gate: Regex, normalizedUrl: String?): MatchResult? {
        if (normalizedUrl == null) return null
        return gate.find(normalizedUrl)
    }

    /**
     * Normalizes a URL for matching, or `null` when the gate must fail closed: no
     * URL at all, or one past the 8 KiB cap the reference never matches (a hostile
     * peer can't force an unbounded regex run by sending a giant URL).
     */
    private fun normalizeUrl(url: String?): String? {
        if (url == null) return null
        if (url.length > MAX_GATE_URL_LENGTH) return null
        return lowercasingHost(url)
    }

    /**
     * Lowercases only the scheme and authority; the path and query keep their case
     * (RFC 3986 makes the host case-insensitive but not the path). A trailing dot
     * on the authority (`example.com.`) is dropped so the FQDN form matches too.
     */
    private fun lowercasingHost(url: String): String {
        val sep = url.indexOf("://")
        if (sep < 0) return url
        val authStart = sep + 3
        var authEnd = authStart
        while (authEnd < url.length) {
            val ch = url[authEnd]
            if (ch == '/' || ch == '?' || ch == '#') break
            authEnd++
        }
        var authority = url.substring(authStart, authEnd).lowercase()
        if (authority.endsWith(".")) authority = authority.dropLast(1)
        return url.substring(0, authStart).lowercase() + authority + url.substring(authEnd)
    }

    // MARK: - Replacement-URL parsing

    private data class ReplacementUrl(val host: String, val port: Int?, val requestTarget: String) {
        /** `host` or `host:port`, bracketing an IPv6 literal, for a `Host` / `:authority`. */
        val authority: String
            get() {
                val bracketed = if (host.contains(":")) "[$host]" else host
                return if (port != null) "$bracketed:$port" else bracketed
            }
    }

    /**
     * Parses a rewrite replacement into host / port / request-target, or `null`
     * when it is not an absolute URL with a host. The request target is the
     * percent-encoded path (empty path → `/`) plus the query; the fragment is
     * dropped (it never travels to the origin).
     */
    private fun parseReplacementUrl(raw: String): ReplacementUrl? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val uri = runCatching { URI(trimmed) }.getOrNull() ?: return null
        var host = uri.host ?: return null
        if (host.isEmpty()) return null
        if (host.length >= 2 && host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length - 1)
        }
        val port: Int? = when {
            uri.port < 0 -> null
            uri.port > 65535 -> return null
            else -> uri.port
        }
        var target = uri.rawPath ?: ""
        if (target.isEmpty()) target = "/"
        val query = uri.rawQuery
        if (!query.isNullOrEmpty()) target += "?$query"
        return ReplacementUrl(host, port, target)
    }

    /**
     * A rewritten request target must carry no byte ≤ 0x20 or == 0x7F — a space,
     * control, or DEL in the request line is a smuggling vector. Bytes ≥ 0x80 are
     * multi-byte UTF-8 sequences whose every byte is ≥ 0x80, so a code point there
     * passes, exactly as the reference's byte-wise check does.
     */
    private fun isWireSafeRequestTarget(target: String): Boolean =
        target.none { it.code <= 0x20 || it.code == 0x7F }

    /** No CR, LF, or NUL — the response-splitting primitive (RFC 9110 §5.5). Spaces are allowed. */
    private fun isWireSafeHeaderValue(value: String): Boolean =
        value.none { it.code == 0x0D || it.code == 0x0A || it.code == 0x00 }

    // MARK: - Header rewrite

    private fun rewriteHost(headers: List<HttpHeader>, authority: String): List<HttpHeader> {
        if (headers.none { it.isNamed("Host") }) {
            return headers + HttpHeader("Host", authority)
        }
        var replaced = false
        return headers.mapNotNull { header ->
            if (header.isNamed("Host")) {
                if (!replaced) {
                    replaced = true
                    HttpHeader("Host", authority)
                } else {
                    null
                }
            } else {
                header
            }
        }
    }

    // MARK: - Body rewrite

    /**
     * Applies the matching body rules in rule order, composing over the bytes.
     * Consecutive rules of one kind run as a single group: `body-replace` rules
     * decode / compose / re-encode once (exactly as before, so the existing
     * text-body behaviour is byte-for-byte unchanged), and `body-json` rules
     * parse / patch / re-serialize once over one in-memory tree. When the two
     * kinds interleave, the group boundary re-reads the bytes — which is what
     * "compose in rule order" means for two transforms of the same body.
     */
    private fun applyBodyOps(ops: List<CompiledRule>, headers: List<HttpHeader>, body: ByteArray): ByteArray {
        var current = body
        var i = 0
        while (i < ops.size) {
            when (ops[i].operation) {
                is MitmOperation.BodyReplace -> {
                    val group = ArrayList<CompiledRule>()
                    while (i < ops.size && ops[i].operation is MitmOperation.BodyReplace) {
                        group.add(ops[i])
                        i++
                    }
                    current = applyBodyReplaces(group, headers, current)
                }
                is MitmOperation.BodyJson -> {
                    val group = ArrayList<MitmJsonOperation>()
                    while (i < ops.size && ops[i].operation is MitmOperation.BodyJson) {
                        group.add((ops[i].operation as MitmOperation.BodyJson).operation)
                        i++
                    }
                    current = applyBodyJson(group, headers, current)
                }
                // A non-body operation can never appear here (bodyOps is filtered to the two
                // body kinds), but skip defensively so the loop always makes progress.
                else -> i++
            }
        }
        return current
    }

    /**
     * Applies a run of `body-json` patches, but only to a body whose
     * `Content-Type` is a JSON media type; any other body is returned untouched.
     * The patch itself is total and fails closed — an invalid-JSON,
     * unresolved-path, oversized, or over-nested body comes back byte-identical
     * (see [MitmJsonPatch]).
     */
    private fun applyBodyJson(operations: List<MitmJsonOperation>, headers: List<HttpHeader>, body: ByteArray): ByteArray {
        if (!isJsonMediaType(headers)) return body
        return MitmJsonPatch.applyAll(operations, body)
    }

    /**
     * Whether the declared `Content-Type` is a JSON media type: `application/json`,
     * `text/json`, or any `+json` structured-suffix type (`application/ld+json`,
     * `application/vnd.api+json`, …). The media type is taken before the first
     * `;`, so a `charset` parameter does not defeat the check. A body with no
     * `Content-Type`, or a non-JSON one, is not patched.
     */
    private fun isJsonMediaType(headers: List<HttpHeader>): Boolean {
        val contentType = headers.firstOrNull { it.isNamed("Content-Type") }?.value ?: return false
        val mediaType = contentType.substringBefore(';').trim().lowercase()
        return mediaType == "application/json" || mediaType == "text/json" ||
            (mediaType.endsWith("+json") && mediaType.length > "+json".length)
    }

    /**
     * Runs every matching `body-replace` over the body, all or nothing. The body
     * is decoded once (UTF-8, falling back to ISO-8859-1, which accepts any byte
     * sequence), each rule's substitution composes in order, and the result is
     * re-encoded with the same charset. The contract is total: if the final text
     * cannot be re-encoded in the chosen charset (a replacement introduced a
     * character the body's bytes can't represent), the original bytes are returned
     * untouched.
     */
    private fun applyBodyReplaces(ops: List<CompiledRule>, headers: List<HttpHeader>, body: ByteArray): ByteArray {
        // A multi-byte charset (UTF-16, GBK, Shift_JIS, ...) must not be decoded
        // as bytes and rewritten: a search matching the ASCII-looking trail byte
        // of a multi-byte character would corrupt it and desynchronise the rest.
        // The reference leaves such bodies untouched, so body-replace only runs
        // on UTF-8 or single-byte text.
        if (isMultiByteCharset(declaredCharset(headers))) return body
        val (charset, decoded) = decodeBody(body)
        var current = decoded
        for (rule in ops) {
            val search = rule.bodySearch ?: continue
            val replacement = rule.bodyReplacement ?: continue
            current = search.replace(current) { match ->
                replacement.expand { index ->
                    if (index >= 0 && index < match.groupValues.size) match.groupValues[index] else null
                }
            }
        }
        return encodeBody(current, charset) ?: body
    }

    /** UTF-8 if the body is valid UTF-8, else ISO-8859-1 (which never fails to decode). */
    private fun decodeBody(body: ByteArray): Pair<Charset, String> {
        val utf8 = runCatching {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(body))
                .toString()
        }.getOrNull()
        return if (utf8 != null) StandardCharsets.UTF_8 to utf8
        else StandardCharsets.ISO_8859_1 to String(body, StandardCharsets.ISO_8859_1)
    }

    /** The charset named by `Content-Type`, or null when none is declared or it is unknown. */
    private fun declaredCharset(headers: List<HttpHeader>): Charset? {
        val contentType = headers.firstOrNull { it.isNamed("Content-Type") }?.value ?: return null
        val match = CHARSET_PARAM.find(contentType) ?: return null
        val name = match.groupValues[1].trim().trim('"')
        return try {
            if (name.isNotEmpty() && Charset.isSupported(name)) Charset.forName(name) else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Whether [charset] encodes some character to more than one byte.
     *
     * UTF-8 is treated as safe even though it is variable-width: [decodeBody]
     * only accepts a body as UTF-8 when it decodes without loss, so the
     * byte<->text mapping round-trips exactly. Single-byte charsets
     * (ISO-8859-1, US-ASCII, windows-1252) round-trip by construction. Everything
     * else (UTF-16, GBK, Shift_JIS, ...) is multi-byte and left untouched. A null
     * charset means none was declared, which is treated as safe text.
     */
    private fun isMultiByteCharset(charset: Charset?): Boolean {
        if (charset == null || charset == StandardCharsets.UTF_8) return false
        return try {
            charset.newEncoder().maxBytesPerChar() > 1.0f
        } catch (_: Exception) {
            true
        }
    }

    /** Re-encodes strictly; `null` when the text has characters the charset can't represent. */
    private fun encodeBody(text: String, charset: Charset): ByteArray? {
        return try {
            val encoded = charset.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text))
            ByteArray(encoded.remaining()).also { encoded.get(it) }
        } catch (_: CharacterCodingException) {
            null
        }
    }

    private companion object {
        /** A URL longer than this never matches; matches the reference's gate cap. */
        const val MAX_GATE_URL_LENGTH = 8 * 1024

        /** Pulls the `charset=` token out of a `Content-Type` value. */
        val CHARSET_PARAM = Regex("charset\\s*=\\s*([^;]+)", RegexOption.IGNORE_CASE)

        /** Non-empty so a client doesn't treat a zero-length reject `200` as an error. */
        const val DEFAULT_TEXT = "Success from Mythaia"

        /** Base64 of "Mythaia", used when a `reject-data` rule carries no payload. */
        const val DEFAULT_DATA_BASE64 = "TXl0aGFpYQ=="

        /** The canonical 43-byte 1×1 transparent GIF89a (the tracking-pixel payload). */
        val TINY_GIF = byteArrayOf(
            0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
            0x80.toByte(), 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
            0x00, 0x00, 0x00, 0x21, 0xF9.toByte(), 0x04, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x02, 0x02, 0x4C, 0x01, 0x00, 0x3B
        )
    }
}
