package com.mythaia.vpn.mitm

/**
 * One `rewrite` sub-mode (operation `0`), the request-only verbs that answer or
 * redirect a request instead of, or before, letting it reach upstream.
 *
 * The `.amrs` format writes the sub-mode as a number after the operation code
 * (`0` transparent, `1` redirect, `2` reject-text, `3` reject-gif, `4`
 * reject-data); the numeric encoding lives in [AmrsParser], not here, because a
 * resolved action carries only the operands the rewriter needs.
 */
sealed class MitmRewriteAction {
    /**
     * Replace the whole request URL and dial the replacement host. The URL may
     * carry capture references (`$1`, `${10}`, …) to the `url-pattern` match, so
     * the final target is only known per request — see [MitmCaptureTemplate].
     */
    data class Transparent(val url: String) : MitmRewriteAction()

    /** Synthesize `302 Found` with `Location: <url>`; no upstream dial. */
    data class Redirect302(val url: String) : MitmRewriteAction()

    /** Synthesize `200 OK`, `text/plain`; empty content falls back to a default line. */
    data class Reject200Text(val content: String) : MitmRewriteAction()

    /** Synthesize `200 OK` with a canned 1×1 `image/gif` (the tracking-pixel payload). */
    object Reject200Gif : MitmRewriteAction()

    /** Synthesize `200 OK`, `application/octet-stream`; empty falls back to a default payload. */
    data class Reject200Data(val base64: String) : MitmRewriteAction()
}

/**
 * What a rule does when its `url-pattern` gate matches, one variant per ported
 * operation code.
 *
 * Only the operation codes with a native, socket-free transform are modelled:
 * `0` [Rewrite], `1` [HeaderAdd], `2` [HeaderDelete], `3` [HeaderReplace], and
 * `4` [BodyReplace]. The JavaScript operations (`100` / `101`) and the
 * declarative JSON edit (`5`) are deliberately absent — see [AmrsParser] and the
 * port notes for why they are dropped rather than half-implemented.
 */
sealed class MitmOperation {
    /** Operation `0`: request-only URL rewrite / redirect / reject. */
    data class Rewrite(val action: MitmRewriteAction) : MitmOperation()

    /** Operation `1`: append a header; never replaces an existing one of the same name. */
    data class HeaderAdd(val name: String, val value: String) : MitmOperation()

    /** Operation `2`: remove every header of this name (case-insensitive). */
    data class HeaderDelete(val name: String) : MitmOperation()

    /**
     * Operation `3`: overwrite the value of every header of this name
     * (case-insensitive) and normalize its spelling to [name]; a header that is
     * absent is left alone — this does not add it.
     */
    data class HeaderReplace(val name: String, val value: String) : MitmOperation()

    /**
     * Operation `4`: regex find-and-replace over the decompressed text body.
     * [search] is a regex; [replacement] carries the same capture references as
     * [MitmRewriteAction.Transparent]. Every matching rule fires, in rule order.
     */
    data class BodyReplace(val search: String, val replacement: String) : MitmOperation()
}

/**
 * A single `.amrs` rule: a [phase], a `url-pattern` gate, and an [operation].
 *
 * The only match condition the `.amrs` format defines is the whole-URL regex
 * [urlPattern] tested for the given [phase] — there is deliberately no match on
 * method, status, or individual header values (the reference model has none
 * either; the URL gate scopes by scheme/host/path and the rule-set's `hostname`
 * suffixes gate the host upstream of this). Keeping the pattern as a raw string
 * rather than a compiled regex keeps a rule value-comparable and lets a test
 * assert the parsed model against the format by hand; [MitmRewriter] compiles
 * the gate once when it is applied.
 *
 * A [MitmOperation.Rewrite] rule is always [HttpPhase.REQUEST] — the format
 * forces the phase for operation `0` regardless of the phase column, because a
 * rewrite can only act before the request leaves for upstream.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
data class MitmRule(
    val phase: HttpPhase,
    val urlPattern: String,
    val operation: MitmOperation
)
