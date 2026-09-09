package com.mythaia.vpn.mitm

import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * The pure `body-json` (operation `5`) transform: apply a parsed
 * [MitmJsonOperation] to a JSON body and return the re-serialized bytes.
 *
 * This is a total function of `(operation, body) -> bytes` with no sockets and no
 * exceptions on the connection. It fails **closed** in every ambiguous case — a
 * body that is not valid UTF-8 JSON, a path that does not resolve, a document
 * nested past [MAX_DEPTH], or a body past [Http1Codec.MAX_BUFFERED_BODY_BYTES] all
 * return the **original bytes unchanged**. A patch that resolves but changes
 * nothing (deleting an absent key, replacing a missing path) likewise returns the
 * original bytes, so a body no rule actually touched is never even reformatted.
 *
 * The document is parsed with the strict default [Json] (no lenient syntax, no
 * `NaN`/`Infinity`), walked/patched over immutable [JsonElement]s, and only
 * re-serialized when the tree genuinely changed. Because kotlinx builds an
 * immutable tree, the reference's in-place `NSMutable*` mutation and its
 * defensive `deepCopy` have no analog — structural sharing is safe.
 *
 * Two DoS guards bound the work a hostile body can force: a byte-cheap pre-scan
 * ([depthWithinLimit]) refuses documents nested past [MAX_DEPTH] **before** the
 * recursive parser ever sees them (so a nesting bomb cannot overflow the stack),
 * and the buffered-body cap refuses oversized bodies outright.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
object MitmJsonPatch {

    private val logger = MythaiaLogger("MitmJsonPatch")

    /** Strict, compact JSON: rejects `NaN`/`Infinity` and unquoted/lenient syntax; emits no whitespace. */
    private val json = Json

    /**
     * The maximum JSON nesting depth this transform will parse or emit. Chosen
     * well below the JVM stack ceiling so the strict recursive parser cannot be
     * driven to a `StackOverflowError` by a nesting bomb; a body (or a rule value)
     * nested deeper is treated as unpatchable and left unchanged. This is more
     * conservative than the reference's `maxRecursionDepth` of 600, which runs on
     * a different runtime — the tighter cap only ever fails closed.
     */
    private const val MAX_DEPTH = 200

    private enum class LeafMode { ADD, REPLACE, DELETE }

    // ---------------------------------------------------------------------
    // Compile-time parsing (called by AmrsParser)
    // ---------------------------------------------------------------------

    /**
     * Parses a `.amrs` JSON path (`$.a.b[0]`, `a["x.y"]`, `['k']`, …) into
     * segments, or `null` when it is malformed (an empty `.` segment, an
     * unterminated quote or bracket, an empty bracket, an overflowing index). A
     * leading `$` is optional; a bracket token is read as an [JsonPathSegment.Index]
     * only when it is all ASCII digits, otherwise as a [JsonPathSegment.Key]. An
     * empty path resolves to the whole document, exactly as the reference does.
     */
    fun parseJsonPath(raw: String): List<JsonPathSegment>? {
        val segments = ArrayList<JsonPathSegment>()
        val n = raw.length
        var i = 0
        if (n > 0 && raw[0] == '$') i = 1
        while (i < n) {
            when (raw[i]) {
                '.' -> {
                    i++
                    val name = StringBuilder()
                    while (i < n && raw[i] != '.' && raw[i] != '[') {
                        name.append(raw[i]); i++
                    }
                    if (name.isEmpty()) return null
                    segments.add(JsonPathSegment.Key(name.toString()))
                }
                '[' -> {
                    i++
                    val inner = StringBuilder()
                    // Scan past a quoted key first: it may itself contain `]` (`["a]b"]`).
                    if (i < n && (raw[i] == '"' || raw[i] == '\'')) {
                        val quote = raw[i]
                        inner.append(quote)
                        i++
                        while (i < n && raw[i] != quote) {
                            inner.append(raw[i]); i++
                        }
                        if (i >= n || raw[i] != quote) return null
                        inner.append(quote)
                        i++
                    }
                    while (i < n && raw[i] != ']') {
                        inner.append(raw[i]); i++
                    }
                    if (i >= n || raw[i] != ']') return null
                    i++
                    val token = inner.toString().trim()
                    if (token.length >= 2 &&
                        ((token.first() == '"' && token.last() == '"') ||
                            (token.first() == '\'' && token.last() == '\''))
                    ) {
                        segments.add(JsonPathSegment.Key(token.substring(1, token.length - 1)))
                    } else if (token.isNotEmpty() && token.all { it in '0'..'9' }) {
                        // toIntOrNull fails only on overflow — reject rather than fall through to a key.
                        val index = token.toIntOrNull() ?: return null
                        segments.add(JsonPathSegment.Index(index))
                    } else if (token.isNotEmpty()) {
                        segments.add(JsonPathSegment.Key(token))
                    } else {
                        return null
                    }
                }
                else -> {
                    // The first segment may omit the leading `.`.
                    val name = StringBuilder()
                    while (i < n && raw[i] != '.' && raw[i] != '[') {
                        name.append(raw[i]); i++
                    }
                    if (name.isEmpty()) return null
                    segments.add(JsonPathSegment.Key(name.toString()))
                }
            }
        }
        return segments
    }

    /**
     * Parses a rule's value string into a [JsonElement]: valid JSON (an object,
     * array, number, boolean, `null`, or quoted string) becomes that value;
     * anything else becomes a JSON string of the raw text — the reference's
     * `parseValue` semantics. A value nested past [MAX_DEPTH] is treated as a
     * plain string rather than parsed, so a hostile rule cannot overflow the
     * parser at compile time.
     */
    fun parseJsonValue(raw: String): JsonElement {
        if (!depthWithinLimit(raw)) return JsonPrimitive(raw)
        val parsed = runCatching { json.parseToJsonElement(raw) }.getOrNull() ?: return JsonPrimitive(raw)
        return asValueOrString(parsed, raw)
    }

    /**
     * Normalises a parsed value the reference's way. `parseToJsonElement` is
     * permissive enough to read a bare word (`x`) as an *unquoted* primitive,
     * which would re-serialize as invalid JSON; the reference treats only genuine
     * JSON scalars/containers as parsed and everything else as a JSON string. So a
     * non-string primitive whose content is not a canonical JSON literal (a
     * number, `true`, `false`, or `null`) is really bare text and is kept as a
     * string of the whole raw value.
     */
    private fun asValueOrString(parsed: JsonElement, raw: String): JsonElement {
        if (parsed is JsonPrimitive && !parsed.isString && !isCanonicalJsonLiteral(parsed.content)) {
            return JsonPrimitive(raw)
        }
        return parsed
    }

    private fun isCanonicalJsonLiteral(content: String): Boolean =
        content == "true" || content == "false" || content == "null" || content.toDoubleOrNull() != null

    /**
     * Parses a rule's value string into a list of [JsonElement]s for
     * `remove-where-field-in`: a JSON array yields its elements, any other JSON
     * value yields a one-element list, and unparseable text yields a one-element
     * list holding the raw string — the reference's `parseValues` semantics.
     */
    fun parseJsonValues(raw: String): List<JsonElement> {
        if (!depthWithinLimit(raw)) return listOf(JsonPrimitive(raw))
        val parsed = runCatching { json.parseToJsonElement(raw) }.getOrNull()
            ?: return listOf(JsonPrimitive(raw))
        return if (parsed is JsonArray) parsed.map { asValueOrString(it, it.toString()) }
        else listOf(asValueOrString(parsed, raw))
    }

    // ---------------------------------------------------------------------
    // Data-path application (called by MitmRewriter)
    // ---------------------------------------------------------------------

    /**
     * Applies a single [operation] to [body]. Convenience for [applyAll].
     */
    fun apply(operation: MitmJsonOperation, body: ByteArray): ByteArray =
        applyAll(listOf(operation), body)

    /**
     * Applies [operations] in order to [body] and returns the patched bytes, or
     * the original [body] unchanged in every fail-closed case (see the class
     * note). The body is parsed once and re-serialized once, so a run of
     * `body-json` rules composes over one in-memory tree — and a run whose *net*
     * effect changes nothing returns the original bytes, formatting and all,
     * exactly like the reference's batched `applyAll`.
     */
    fun applyAll(operations: List<MitmJsonOperation>, body: ByteArray): ByteArray {
        if (operations.isEmpty() || body.isEmpty()) return body
        if (body.size > Http1Codec.MAX_BUFFERED_BODY_BYTES) return body

        val text = decodeUtf8Strict(body) ?: return body
        // Bound nesting before the recursive parser runs, so a bomb cannot overflow the stack.
        if (!depthWithinLimit(text)) return body

        val root = runCatching { json.parseToJsonElement(text) }.getOrNull() ?: return body
        var patched = root
        for (operation in operations) {
            patched = runCatching { applyOp(operation, patched) }.getOrNull() ?: return body
        }
        // Nothing structurally changed: keep the original bytes (and their formatting) verbatim.
        if (patched == root) return body

        val out = runCatching { json.encodeToString(JsonElement.serializer(), patched) }.getOrNull() ?: run {
            // The strict encoder refuses non-finite numbers; a patched tree it cannot emit is
            // left as the original body rather than forwarded half-serialized. This should not
            // arise (the strict parser rejects NaN/Infinity on the way in), so note it if it does.
            logger.debug("body-json patch produced an unencodable document; leaving body unchanged")
            return body
        }
        val bytes = out.toByteArray(StandardCharsets.UTF_8)
        // Cap the OUTPUT too, not just the input: a hostile rule (e.g. replace-recursive
        // planting a large value at every occurrence of a key) can inflate a sub-cap body
        // into a huge one. Past the buffered-body cap, drop the patch and forward the
        // original rather than let an untrusted rule set drive an OOM.
        if (bytes.size > Http1Codec.MAX_BUFFERED_BODY_BYTES) {
            logger.warning("body-json patch exceeded the buffered-body cap; leaving body unchanged")
            return body
        }
        return bytes
    }

    private fun applyOp(op: MitmJsonOperation, root: JsonElement): JsonElement = when (op) {
        is MitmJsonOperation.Add ->
            applyAtPath(root, op.path, LeafMode.ADD, op.value)
        is MitmJsonOperation.Replace ->
            applyAtPath(root, op.path, LeafMode.REPLACE, op.value)
        is MitmJsonOperation.Delete ->
            applyAtPath(root, op.path, LeafMode.DELETE, null)
        is MitmJsonOperation.ReplaceRecursive ->
            replaceRecursive(root, op.key, op.value, 0)
        is MitmJsonOperation.DeleteRecursive ->
            deleteRecursive(root, op.key, 0)
        is MitmJsonOperation.RemoveWhereKeyExists ->
            removeWhere(root, op.path) { element -> !(element is JsonObject && element.containsKey(op.key)) }
        is MitmJsonOperation.RemoveWhereFieldIn ->
            removeWhere(root, op.path) { element -> keepForFieldIn(element, op.field, op.values) }
    }

    // ---------------------------------------------------------------------
    // Path application: add / replace / delete at a resolved leaf
    // ---------------------------------------------------------------------

    private fun applyAtPath(
        root: JsonElement,
        segments: List<JsonPathSegment>,
        mode: LeafMode,
        value: JsonElement?
    ): JsonElement {
        if (segments.isEmpty()) {
            // An empty path targets the whole document.
            return when (mode) {
                LeafMode.ADD, LeafMode.REPLACE -> value ?: root
                LeafMode.DELETE -> root
            }
        }
        return applyRec(root, segments, mode, value)
    }

    private fun applyRec(
        node: JsonElement,
        segments: List<JsonPathSegment>,
        mode: LeafMode,
        value: JsonElement?
    ): JsonElement {
        val head = segments.first()
        if (segments.size == 1) return applyLeaf(node, head, mode, value)
        // Missing intermediate node: leave the document unchanged (never fabricate a parent).
        val child = childNode(node, head) ?: return node
        val newChild = applyRec(child, segments.subList(1, segments.size), mode, value)
        return setExistingChild(node, head, newChild)
    }

    private fun applyLeaf(
        parent: JsonElement,
        leaf: JsonPathSegment,
        mode: LeafMode,
        value: JsonElement?
    ): JsonElement = when (leaf) {
        is JsonPathSegment.Key -> {
            val obj = parent as? JsonObject ?: return parent
            val map = LinkedHashMap<String, JsonElement>(obj)
            when (mode) {
                LeafMode.ADD -> if (value != null) map[leaf.name] = value
                LeafMode.REPLACE -> if (value != null && map.containsKey(leaf.name)) map[leaf.name] = value
                LeafMode.DELETE -> map.remove(leaf.name)
            }
            JsonObject(map)
        }
        is JsonPathSegment.Index -> {
            val arr = parent as? JsonArray ?: return parent
            val list = arr.toMutableList()
            val count = list.size
            val index = leaf.index
            when (mode) {
                LeafMode.ADD -> if (value != null) {
                    if (index in 0 until count) list[index] = value
                    else if (index == count) list.add(value)
                }
                LeafMode.REPLACE -> if (value != null && index in 0 until count) list[index] = value
                LeafMode.DELETE -> if (index in 0 until count) list.removeAt(index)
            }
            JsonArray(list)
        }
    }

    // ---------------------------------------------------------------------
    // Recursive key verbs
    // ---------------------------------------------------------------------

    private fun replaceRecursive(node: JsonElement, key: String, value: JsonElement, depth: Int): JsonElement {
        if (depth >= MAX_DEPTH) return node
        return when (node) {
            is JsonObject -> {
                val map = LinkedHashMap<String, JsonElement>(node.size)
                for ((k, v) in node) {
                    // The replaced value is planted verbatim; only siblings are recursed into.
                    map[k] = if (k == key) value else replaceRecursive(v, key, value, depth + 1)
                }
                JsonObject(map)
            }
            is JsonArray -> JsonArray(node.map { replaceRecursive(it, key, value, depth + 1) })
            else -> node
        }
    }

    private fun deleteRecursive(node: JsonElement, key: String, depth: Int): JsonElement {
        if (depth >= MAX_DEPTH) return node
        return when (node) {
            is JsonObject -> {
                val map = LinkedHashMap<String, JsonElement>(node.size)
                for ((k, v) in node) {
                    if (k == key) continue
                    map[k] = deleteRecursive(v, key, depth + 1)
                }
                JsonObject(map)
            }
            is JsonArray -> JsonArray(node.map { deleteRecursive(it, key, depth + 1) })
            else -> node
        }
    }

    // ---------------------------------------------------------------------
    // remove-where verbs: filter the array at a resolved path
    // ---------------------------------------------------------------------

    private fun removeWhere(
        root: JsonElement,
        path: List<JsonPathSegment>,
        keep: (JsonElement) -> Boolean
    ): JsonElement {
        val target = resolveNode(root, path) as? JsonArray ?: return root
        val filtered = target.filter(keep)
        if (filtered.size == target.size) return root
        return replaceNodeAtPath(root, path, JsonArray(filtered))
    }

    /** Keep an element unless it is an object whose [field] value equals one of [values]. */
    private fun keepForFieldIn(element: JsonElement, field: String, values: List<JsonElement>): Boolean {
        val obj = element as? JsonObject ?: return true
        val fieldValue = obj[field] ?: return true
        // JsonPrimitive equality compares (isString, content), so a JSON string "1", the number 1,
        // and the boolean true are all distinct — the reference's boolean-vs-number guard, for free.
        return values.none { it == fieldValue }
    }

    // ---------------------------------------------------------------------
    // Tree navigation / rebuild (immutable)
    // ---------------------------------------------------------------------

    private fun childNode(node: JsonElement, segment: JsonPathSegment): JsonElement? = when (segment) {
        is JsonPathSegment.Key -> (node as? JsonObject)?.get(segment.name)
        is JsonPathSegment.Index -> (node as? JsonArray)?.let {
            if (segment.index in 0 until it.size) it[segment.index] else null
        }
    }

    private fun resolveNode(root: JsonElement, segments: List<JsonPathSegment>): JsonElement? {
        var node: JsonElement = root
        for (segment in segments) {
            node = childNode(node, segment) ?: return null
        }
        return node
    }

    /** Rebuilds [node] with the child at [segment] replaced by [newChild]; unchanged if the container type mismatches. */
    private fun setExistingChild(node: JsonElement, segment: JsonPathSegment, newChild: JsonElement): JsonElement {
        return when (segment) {
            is JsonPathSegment.Key -> {
                val obj = node as? JsonObject ?: return node
                JsonObject(LinkedHashMap<String, JsonElement>(obj).apply { put(segment.name, newChild) })
            }
            is JsonPathSegment.Index -> {
                val arr = node as? JsonArray ?: return node
                if (segment.index !in 0 until arr.size) return node
                JsonArray(arr.toMutableList().apply { this[segment.index] = newChild })
            }
        }
    }

    private fun replaceNodeAtPath(node: JsonElement, segments: List<JsonPathSegment>, newNode: JsonElement): JsonElement {
        if (segments.isEmpty()) return newNode
        val head = segments.first()
        val child = childNode(node, head) ?: return node
        val newChild = replaceNodeAtPath(child, segments.subList(1, segments.size), newNode)
        return setExistingChild(node, head, newChild)
    }

    // ---------------------------------------------------------------------
    // Safety helpers
    // ---------------------------------------------------------------------

    /**
     * Whether [text] nests no deeper than [MAX_DEPTH]. A byte-cheap scan that
     * tracks string/escape state so a `{` or `[` inside a JSON string does not
     * count; returns false the instant depth would exceed the cap. Run before the
     * recursive parser so a nesting bomb is refused without ever being parsed.
     */
    private fun depthWithinLimit(text: String): Boolean {
        var depth = 0
        var inString = false
        var escaped = false
        for (c in text) {
            if (inString) {
                when {
                    escaped -> escaped = false
                    c == '\\' -> escaped = true
                    c == '"' -> inString = false
                }
            } else {
                when (c) {
                    '"' -> inString = true
                    '{', '[' -> {
                        depth++
                        if (depth > MAX_DEPTH) return false
                    }
                    '}', ']' -> if (depth > 0) depth--
                }
            }
        }
        return true
    }

    /** Decodes [body] as strict UTF-8, or `null` when it is not valid UTF-8 (JSON is a UTF-8 format). */
    private fun decodeUtf8Strict(body: ByteArray): String? = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(body))
            .toString()
    } catch (_: CharacterCodingException) {
        null
    }
}
