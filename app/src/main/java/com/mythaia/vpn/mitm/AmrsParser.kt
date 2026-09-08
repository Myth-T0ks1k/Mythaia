package com.mythaia.vpn.mitm

/**
 * Parses the `.amrs` interchange format into a validated [MitmRuleSet].
 *
 * The format is a sequence of header lines (`key = value`), rule lines
 * (`phase, operation, field…`), and section markers (`[Rule]`, `[Parameter]`),
 * in any order; blank lines and `#` / `//` comments are ignored. A `.amrs` file
 * is attacker-influenced — it can arrive from a subscription URL — so parsing
 * never throws and never hard-fails: a line that is neither a recognized header
 * nor a valid rule is dropped silently and the rest still imports, exactly as
 * [ClientHelloParser] returns `null` rather than raising on a malformed
 * ClientHello. That is why [parseRule] returns `null` for a rule it refuses
 * instead of signalling an error the caller must catch.
 *
 * Unlike the reference, which parses loosely and re-validates when it compiles a
 * rule for the data path, this parser folds the compile-time checks in: the
 * [MitmRule] list it returns is already validated (the `url-pattern` and any
 * `search` compile as a regex, header names are well-formed and non-framing,
 * header values carry no CR/LF/NUL), so [MitmRewriter] can trust it. A rule that
 * would be dropped at compile time is dropped here instead — the end effect (the
 * rule never fires) is identical.
 *
 * Only operation codes `0`–`4` are supported. `body-json` (`5`) and the
 * JavaScript operations (`100` / `101`) have no native transform in this port,
 * so their rule lines are dropped like any other unsupported line; a rule set
 * that leans on them loses those rules but still imports the rest.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
object AmrsParser {

    private enum class Section { RULE, PARAMETER, IGNORED }

    /** Header keys the format recognizes; everything else is treated as a possible rule line. */
    private val RECOGNIZED_HEADERS = setOf("name", "hostname", "icon-light", "icon-dark")

    /**
     * Framing and hop-by-hop header names a `header-add` / `header-replace` rule
     * may not set: changing them would rewrite how the body is framed and is the
     * request-/response-smuggling primitive (RFC 9112 §6.3.3, RFC 9110 §7.6.1).
     * `host` is here too: a transparent rewrite already sets it to the resolved
     * authority, so a rule adding a second `Host` produces a request RFC 9112
     * §3.2 requires a server to reject and is a routing-ambiguity primitive.
     * `header-delete` is deliberately not guarded — matching the reference, which
     * documents that deleting `Content-Length` is the author's own foot to shoot.
     */
    private val FRAMING_HEADERS = setOf(
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "proxy-connection", "upgrade", "te", "trailer", "host"
    )

    /**
     * Parses whole `.amrs` text into a rule set. Never fails: unrecognized or
     * malformed lines are dropped and what is left is returned.
     */
    fun parse(text: String): MitmRuleSet {
        var name = ""
        var suffixes: List<String> = emptyList()
        val rules = ArrayList<MitmRule>()
        var section = Section.RULE

        for (rawLine in text.lines()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            if (line.startsWith("#") || line.startsWith("//")) continue

            val nextSection = parseSection(line)
            if (nextSection != null) {
                section = nextSection
                continue
            }

            val header = parseHeader(line)
            if (header != null) {
                when (header.first) {
                    "name" -> name = header.second
                    "hostname" -> suffixes = header.second
                        .split(",")
                        .map { it.trim() }
                        .filter { it.isNotEmpty() }
                    // icon-light / icon-dark are recognized so they are consumed as headers
                    // rather than mis-parsed as rules, but their image bytes are UI-only.
                    else -> {}
                }
                continue
            }

            when (section) {
                // Stop compiling rules past the cap: `.amrs` is attacker-influenced
                // (subscription URLs), and parseRule compiles a regex per rule, so a
                // hostile set of millions of lines must not allocate proportionally.
                Section.RULE ->
                    if (rules.size < MitmRuleSet.MAX_RULE_COUNT) parseRule(line)?.let { rules.add(it) }
                // Parameter lines feed the (unported) script engine; recognize the section
                // so they aren't mistaken for rules, but keep nothing.
                Section.PARAMETER -> {}
                Section.IGNORED -> {}
            }
        }

        return MitmRuleSet(name = name, domainSuffixes = suffixes, rules = rules)
    }

    /**
     * Parses a single rule line, or `null` when it is malformed or names an
     * operation this port does not support. Exposed so a test can assert the
     * refusal directly.
     */
    fun parseRule(line: String): MitmRule? {
        val fields = splitCsv(line)
        if (fields.size < 2) return null
        val phaseCode = fields[0].toIntOrNull() ?: return null
        // The phase column must be a valid phase even for `rewrite`, whose own phase is
        // then forced to REQUEST; an out-of-range phase drops the whole line.
        val phase = HttpPhase.fromCode(phaseCode) ?: return null
        val opCode = fields[1].toIntOrNull() ?: return null
        val args = fields.drop(2)

        return when (opCode) {
            0 -> parseRewrite(args)
            1 -> parseHeaderMutation(phase, args) { name, value ->
                MitmOperation.HeaderAdd(name, value)
            }
            2 -> {
                if (args.size != 2) return null
                val urlPattern = args[0]
                val name = args[1]
                if (!isValidUrlPattern(urlPattern)) return null
                if (name.isEmpty() || !HttpHeader.isValidName(name)) return null
                MitmRule(phase, urlPattern, MitmOperation.HeaderDelete(name))
            }
            3 -> parseHeaderMutation(phase, args) { name, value ->
                MitmOperation.HeaderReplace(name, value)
            }
            4 -> {
                if (args.size != 3) return null
                val urlPattern = args[0]
                val search = args[1]
                val replacement = args[2]
                if (!isValidUrlPattern(urlPattern)) return null
                if (search.isEmpty() || !isValidRegex(search)) return null
                MitmRule(phase, urlPattern, MitmOperation.BodyReplace(search, replacement))
            }
            // 5 (body-json), 100 (script), 101 (stream-script): valid format, no native
            // transform in this port. Dropped like any other unsupported line.
            else -> null
        }
    }

    // MARK: - Rewrite (operation 0)

    private fun parseRewrite(args: List<String>): MitmRule? {
        if (args.size < 2) return null
        val urlPattern = args[0]
        if (!isValidUrlPattern(urlPattern)) return null
        val action = parseRewriteAction(args[1], args.drop(2)) ?: return null
        // `rewrite` is always request-phase regardless of the phase column, because it can
        // only act before the request leaves for upstream.
        return MitmRule(HttpPhase.REQUEST, urlPattern, MitmOperation.Rewrite(action))
    }

    private fun parseRewriteAction(subMode: String, fields: List<String>): MitmRewriteAction? {
        return when (subMode.trim()) {
            "0" -> {
                if (fields.size != 1) return null
                val url = fields[0].trim()
                if (!looksLikeAbsoluteUrlWithHost(url)) return null
                MitmRewriteAction.Transparent(url)
            }
            "1" -> {
                if (fields.size != 1) return null
                val url = fields[0].trim()
                if (!looksLikeAbsoluteUrlWithHost(url)) return null
                MitmRewriteAction.Redirect302(url)
            }
            "2" -> {
                if (fields.size > 1) return null
                MitmRewriteAction.Reject200Text(fields.firstOrNull() ?: "")
            }
            "3" -> {
                if (fields.isNotEmpty()) return null
                MitmRewriteAction.Reject200Gif
            }
            "4" -> {
                if (fields.size > 1) return null
                val base64 = fields.firstOrNull() ?: ""
                // A non-empty payload must be valid base64 or the rule is dropped; an empty
                // one resolves to the default payload at rewrite time.
                if (base64.isNotEmpty() && !isValidBase64(base64)) return null
                MitmRewriteAction.Reject200Data(base64)
            }
            else -> null
        }
    }

    // MARK: - Header mutations (operations 1 and 3)

    private fun parseHeaderMutation(
        phase: HttpPhase,
        args: List<String>,
        build: (name: String, value: String) -> MitmOperation
    ): MitmRule? {
        if (args.size != 3) return null
        val urlPattern = args[0]
        val name = args[1]
        val value = args[2]
        if (!isValidUrlPattern(urlPattern)) return null
        if (name.isEmpty() || !HttpHeader.isValidName(name)) return null
        if (isFramingHeader(name)) return null
        if (!isWireSafeHeaderValue(value)) return null
        return MitmRule(phase, urlPattern, build(name, value))
    }

    // MARK: - Line classification

    private fun parseSection(line: String): Section? {
        if (line.length < 2 || !line.startsWith("[") || !line.endsWith("]")) return null
        return when (line.substring(1, line.length - 1).trim().lowercase()) {
            "rule", "rules" -> Section.RULE
            "parameter", "parameters", "param", "params" -> Section.PARAMETER
            else -> Section.IGNORED
        }
    }

    private fun parseHeader(line: String): Pair<String, String>? {
        val equals = line.indexOf('=')
        if (equals < 0) return null
        val key = line.substring(0, equals).trim().lowercase()
        if (key !in RECOGNIZED_HEADERS) return null
        val value = line.substring(equals + 1).trim()
        return key to value
    }

    // MARK: - CSV

    /**
     * Splits a rule/parameter line on `,`. Whitespace around an unquoted field is
     * trimmed; a field beginning with `"` is read to the matching `"`, with `""`
     * inside it a literal `"`. A trailing comma yields a final empty field. This
     * mirrors the reference splitter byte for byte, including its handling of a
     * quoted field followed by stray characters before the comma (the character
     * after the closing quote is consumed as if it were the separator).
     */
    private fun splitCsv(input: String): List<String> {
        val fields = ArrayList<String>()
        val current = StringBuilder()
        val n = input.length
        var i = 0
        while (true) {
            while (i < n && (input[i] == ' ' || input[i] == '\t')) i++
            if (i < n && input[i] == '"') {
                i++
                while (i < n) {
                    val ch = input[i]
                    if (ch == '"') {
                        if (i + 1 < n && input[i + 1] == '"') {
                            current.append('"')
                            i += 2
                        } else {
                            i++
                            break
                        }
                    } else {
                        current.append(ch)
                        i++
                    }
                }
                while (i < n && (input[i] == ' ' || input[i] == '\t')) i++
            } else {
                while (i < n && input[i] != ',') {
                    current.append(input[i])
                    i++
                }
                val trimmed = current.toString().trim { it == ' ' || it == '\t' }
                current.setLength(0)
                current.append(trimmed)
            }
            fields.add(current.toString())
            current.setLength(0)
            if (i >= n) break
            i++
        }
        return fields
    }

    // MARK: - Validation helpers

    private fun isValidUrlPattern(pattern: String): Boolean =
        pattern.isNotEmpty() && isValidRegex(pattern)

    private fun isValidRegex(pattern: String): Boolean =
        runCatching { Regex(pattern) }.isSuccess

    private fun isFramingHeader(name: String): Boolean =
        name.lowercase() in FRAMING_HEADERS

    /**
     * A header value must carry no CR, LF, or NUL — the response-splitting
     * primitive once it reaches an HTTP/1 wire (RFC 9110 §5.5). Spaces and other
     * printable bytes are allowed: header values routinely contain them, so this
     * is intentionally looser than [HttpHeader.isValidValue], which also rejects
     * spaces for its own (request-target) callers.
     */
    private fun isWireSafeHeaderValue(value: String): Boolean =
        value.none { it == '\r' || it == '\n' || it == '\u0000' }

    private fun isValidBase64(text: String): Boolean =
        runCatching { java.util.Base64.getDecoder().decode(text) }.isSuccess

    /**
     * A loose gate matching the reference's import-time URL check: a non-empty
     * string with a `scheme://` and a non-empty authority. It intentionally does
     * not fully validate the URL — a `rewrite` target may carry `$1` capture
     * refs whose final shape is only known per request, so the strict check
     * (a parseable host, a wire-safe request target) is [MitmRewriter]'s job.
     */
    private fun looksLikeAbsoluteUrlWithHost(raw: String): Boolean {
        val trimmed = raw.trim()
        val sep = trimmed.indexOf("://")
        if (sep <= 0) return false
        var end = sep + 3
        while (end < trimmed.length) {
            val ch = trimmed[end]
            if (ch == '/' || ch == '?' || ch == '#') break
            end++
        }
        val authority = trimmed.substring(sep + 3, end)
        // Strip an optional userinfo; a bare `user@` with no host is not a host.
        val host = authority.substringAfterLast('@')
        return host.isNotEmpty()
    }
}
