package com.mythaia.vpn.mitm

/**
 * A replacement template with capture references to a `url-pattern` or a
 * `body-replace` `search` match.
 *
 * The reference format writes captures as `$0` for the whole match, `$1`…`$9`
 * for single-digit groups, `${10}`, `${11}`, … braced for any index, and `$$`
 * for a literal `$`; any other `$` stays literal. Parsing once up front into a
 * token list (rather than scanning the string on every substitution) keeps the
 * hot path — a body rewrite runs the template once per match — cheap, and lets
 * [staticReplacement] short-circuit the common literal-only case.
 *
 * A reference to a group that did not participate in the match (or is out of
 * range) expands to the empty string, never to a stray `$N`, so a template can
 * never leak an unresolved reference onto the wire.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
class MitmCaptureTemplate(raw: String) {

    private sealed interface Token {
        data class Literal(val text: String) : Token
        data class Group(val index: Int) : Token
    }

    private val tokens: List<Token>

    /** Whether any `$N` reference is present; lets a caller pick the static vs templated path. */
    val referencesCaptures: Boolean

    init {
        val out = ArrayList<Token>()
        val literal = StringBuilder()
        var refs = false
        val n = raw.length
        var i = 0

        fun flushLiteral() {
            if (literal.isNotEmpty()) {
                out.add(Token.Literal(literal.toString()))
                literal.setLength(0)
            }
        }
        fun appendGroup(index: Int) {
            flushLiteral()
            out.add(Token.Group(index))
            refs = true
        }

        while (i < n) {
            val c = raw[i]
            if (c != '$') {
                literal.append(c)
                i++
                continue
            }
            val next = if (i + 1 < n) raw[i + 1] else null
            when {
                next == '$' -> {
                    literal.append('$')
                    i += 2
                }
                next != null && next in '0'..'9' -> {
                    appendGroup(next - '0')
                    i += 2
                }
                next == '{' -> {
                    var j = i + 2
                    val digits = StringBuilder()
                    while (j < n && raw[j] in '0'..'9') {
                        digits.append(raw[j])
                        j++
                    }
                    // A well-formed `${N}` needs at least one digit, a closing brace, and an
                    // index that fits in an Int; anything else leaves the `$` literal (the
                    // brace is re-read as the next character), exactly as the reference does.
                    val index = digits.toString().toIntOrNull()
                    if (digits.isNotEmpty() && j < n && raw[j] == '}' && index != null) {
                        appendGroup(index)
                        i = j + 1
                    } else {
                        literal.append('$')
                        i++
                    }
                }
                else -> {
                    literal.append('$')
                    i++
                }
            }
        }
        flushLiteral()

        tokens = out
        referencesCaptures = refs
    }

    /**
     * Expands the template; a `null` from [captureLookup] (out of range or a
     * group that did not participate) contributes the empty string.
     */
    fun expand(captureLookup: (Int) -> String?): String {
        // Fast path: a literal-only template, the common case.
        val only = tokens.singleOrNull()
        if (only is Token.Literal) return only.text
        val sb = StringBuilder()
        for (token in tokens) {
            when (token) {
                is Token.Literal -> sb.append(token.text)
                is Token.Group -> captureLookup(token.index)?.let { sb.append(it) }
            }
        }
        return sb.toString()
    }

    /** Expands against a capture list (index 0 = whole match). */
    fun expand(captures: List<String?>): String =
        expand { index -> if (index >= 0 && index < captures.size) captures[index] else null }

    /**
     * The verbatim replacement when no captures are referenced (`$$` already
     * reduced to `$`), else `null`; lets a caller reuse a constant string.
     */
    val staticReplacement: String?
        get() = if (referencesCaptures) null else expand { null }
}
