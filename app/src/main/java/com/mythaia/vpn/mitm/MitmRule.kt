package com.mythaia.vpn.mitm

import kotlinx.serialization.json.JsonElement

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
 * `0` [Rewrite], `1` [HeaderAdd], `2` [HeaderDelete], `3` [HeaderReplace], `4`
 * [BodyReplace], and `5` [BodyJson]. The JavaScript operations (`100` / `101`)
 * are deliberately absent — see [AmrsParser] and the port notes for why they are
 * dropped rather than half-implemented.
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

    /**
     * Operation `5`: a declarative JSON-body patch. The [operation] carries the
     * already-parsed JSON path (or recursive key) and JSON value — the parser
     * compiles both up front and drops the rule if either is malformed, so
     * [MitmRewriter] can hand [operation] straight to [MitmJsonPatch]. Unlike
     * `body-replace` and `rewrite`, a `body-json` value carries no `$1` capture
     * references (the reference patch algorithm expands none), so no
     * [MitmCaptureTemplate] is compiled for it. Applied only to JSON bodies, in
     * rule order, composing with `body-replace` — see [MitmRewriter].
     */
    data class BodyJson(val operation: MitmJsonOperation) : MitmOperation()
}

/**
 * One resolved segment of a `body-json` path: an object [Key] or an array
 * [Index]. The `.amrs` path grammar (`$.a.b[0]`, `$["a.b"]`, …) is parsed into a
 * list of these by [MitmJsonPatch.parseJsonPath] at rule-compile time; a
 * negative or non-numeric bracket token becomes a [Key], never an [Index]
 * (matching the reference, which only reads an all-digit token as an index).
 */
sealed class JsonPathSegment {
    data class Key(val name: String) : JsonPathSegment()
    data class Index(val index: Int) : JsonPathSegment()
}

/**
 * A parsed `body-json` operation (the `.amrs` op-`5` sub-actions), mirroring the
 * reference's `MITMJSONOperation`. The path-based verbs carry a [JsonPathSegment]
 * list resolved by the parser; the recursive verbs carry a bare key that
 * [MitmJsonPatch] walks the whole document for. Values are pre-parsed into a
 * [JsonElement] (a bare string that is not itself valid JSON becomes a JSON
 * string), exactly as the reference's `parseValue` does.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
sealed class MitmJsonOperation {
    /** `add`: set [value] at [path]; creates the leaf key, never missing intermediates. */
    data class Add(val path: List<JsonPathSegment>, val value: JsonElement) : MitmJsonOperation()

    /** `replace`: overwrite [value] at [path] only when the leaf already exists. */
    data class Replace(val path: List<JsonPathSegment>, val value: JsonElement) : MitmJsonOperation()

    /** `delete`: remove the leaf at [path] (a key, or an in-range array element). */
    data class Delete(val path: List<JsonPathSegment>) : MitmJsonOperation()

    /** `replace-recursive`: overwrite every occurrence of [key] anywhere in the document with [value]. */
    data class ReplaceRecursive(val key: String, val value: JsonElement) : MitmJsonOperation()

    /** `delete-recursive`: remove every occurrence of [key] anywhere in the document. */
    data class DeleteRecursive(val key: String) : MitmJsonOperation()

    /** `remove-where-key-exists`: from the array at [path], drop every object element that has [key]. */
    data class RemoveWhereKeyExists(val path: List<JsonPathSegment>, val key: String) : MitmJsonOperation()

    /**
     * `remove-where-field-in`: from the array at [path], drop every object
     * element whose [field] value equals one of [values].
     */
    data class RemoveWhereFieldIn(
        val path: List<JsonPathSegment>,
        val field: String,
        val values: List<JsonElement>
    ) : MitmJsonOperation()
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
