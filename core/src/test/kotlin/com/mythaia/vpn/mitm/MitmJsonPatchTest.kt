package com.mythaia.vpn.mitm

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * The `body-json` (op-5) patch algorithm, checked against JSON that is built by
 * hand — never read back from what the patcher emitted. Bodies are written as
 * compact JSON so the expected, independently-derived output is unambiguous:
 * kotlinx serializes objects/arrays with no whitespace and in insertion order.
 *
 * These assert the *pure* transform ([MitmJsonPatch.apply]); the Content-Type
 * gate and rule-order composition are exercised in [MitmRewriterTest].
 */
class MitmJsonPatchTest {

    private fun bytes(s: String) = s.toByteArray(StandardCharsets.UTF_8)
    private fun text(b: ByteArray) = String(b, StandardCharsets.UTF_8)
    private fun keyPath(vararg names: String): List<JsonPathSegment> = names.map { JsonPathSegment.Key(it) }

    // MARK: - add / replace at a path

    @Test
    fun addOverwritesExistingLeafKeepingKeyOrder() {
        val op = MitmJsonOperation.Add(keyPath("user", "vip"), JsonPrimitive(true))
        val out = MitmJsonPatch.apply(op, bytes("{\"user\":{\"vip\":false,\"name\":\"a\"}}"))
        assertEquals("{\"user\":{\"vip\":true,\"name\":\"a\"}}", text(out))
    }

    @Test
    fun addCreatesNewLeafKeyAtEnd() {
        val op = MitmJsonOperation.Add(keyPath("a"), JsonPrimitive(1))
        val out = MitmJsonPatch.apply(op, bytes("{\"b\":2}"))
        assertEquals("{\"b\":2,\"a\":1}", text(out))
    }

    @Test
    fun replaceOverwritesExistingLeaf() {
        val op = MitmJsonOperation.Replace(keyPath("a", "b"), JsonPrimitive("z"))
        val out = MitmJsonPatch.apply(op, bytes("{\"a\":{\"b\":\"y\"}}"))
        assertEquals("{\"a\":{\"b\":\"z\"}}", text(out))
    }

    @Test
    fun replaceLeavesBodyUnchangedWhenLeafAbsent() {
        val op = MitmJsonOperation.Replace(keyPath("missing"), JsonPrimitive(1))
        val original = "{\"a\":1}"
        // replace only fires on an existing key, so nothing changes and the original bytes come back.
        assertArrayEquals(bytes(original), MitmJsonPatch.apply(op, bytes(original)))
    }

    @Test
    fun addAppendsAtArrayEnd() {
        val op = MitmJsonOperation.Add(listOf(JsonPathSegment.Key("a"), JsonPathSegment.Index(2)), JsonPrimitive(3))
        val out = MitmJsonPatch.apply(op, bytes("{\"a\":[1,2]}"))
        assertEquals("{\"a\":[1,2,3]}", text(out))
    }

    @Test
    fun replaceRewritesArrayElementAtIndex() {
        val op = MitmJsonOperation.Replace(listOf(JsonPathSegment.Key("a"), JsonPathSegment.Index(1)), JsonPrimitive("x"))
        val out = MitmJsonPatch.apply(op, bytes("{\"a\":[\"p\",\"q\",\"r\"]}"))
        assertEquals("{\"a\":[\"p\",\"x\",\"r\"]}", text(out))
    }

    // MARK: - delete

    @Test
    fun deleteRemovesKey() {
        val op = MitmJsonOperation.Delete(keyPath("a", "secret"))
        val out = MitmJsonPatch.apply(op, bytes("{\"a\":{\"secret\":1,\"keep\":2}}"))
        assertEquals("{\"a\":{\"keep\":2}}", text(out))
    }

    @Test
    fun deleteOfAbsentKeyLeavesBodyUnchanged() {
        val op = MitmJsonOperation.Delete(keyPath("a", "nope"))
        val original = "{\"a\":{\"keep\":2}}"
        assertArrayEquals(bytes(original), MitmJsonPatch.apply(op, bytes(original)))
    }

    // MARK: - missing intermediate

    @Test
    fun pathIntoMissingIntermediateLeavesBodyUnchanged() {
        // 'b' does not exist under 'a', so 'a.b.c' cannot resolve; the reference never
        // fabricates the missing parent, so the document is left exactly as it was.
        val op = MitmJsonOperation.Add(keyPath("a", "b", "c"), JsonPrimitive(1))
        val original = "{\"a\":{}}"
        assertArrayEquals(bytes(original), MitmJsonPatch.apply(op, bytes(original)))
    }

    // MARK: - recursive verbs

    @Test
    fun replaceRecursiveOverwritesEveryOccurrence() {
        val op = MitmJsonOperation.ReplaceRecursive("token", JsonPrimitive("REDACTED"))
        val out = MitmJsonPatch.apply(op, bytes("{\"token\":\"a\",\"nested\":{\"token\":\"b\",\"x\":1}}"))
        assertEquals("{\"token\":\"REDACTED\",\"nested\":{\"token\":\"REDACTED\",\"x\":1}}", text(out))
    }

    @Test
    fun deleteRecursiveRemovesEveryOccurrence() {
        val op = MitmJsonOperation.DeleteRecursive("ad")
        val out = MitmJsonPatch.apply(op, bytes("{\"ad\":1,\"list\":[{\"ad\":2,\"id\":9},{\"id\":10}]}"))
        assertEquals("{\"list\":[{\"id\":9},{\"id\":10}]}", text(out))
    }

    // MARK: - remove-where verbs

    @Test
    fun removeWhereKeyExistsFiltersArray() {
        val op = MitmJsonOperation.RemoveWhereKeyExists(keyPath("items"), "ad")
        val out = MitmJsonPatch.apply(op, bytes("{\"items\":[{\"id\":1},{\"id\":2,\"ad\":true},{\"id\":3}]}"))
        assertEquals("{\"items\":[{\"id\":1},{\"id\":3}]}", text(out))
    }

    @Test
    fun removeWhereFieldInFiltersByValue() {
        val op = MitmJsonOperation.RemoveWhereFieldIn(
            keyPath("items"),
            "type",
            listOf(JsonPrimitive("ad"), JsonPrimitive("promo"))
        )
        val out = MitmJsonPatch.apply(
            op,
            bytes("{\"items\":[{\"type\":\"post\"},{\"type\":\"ad\"},{\"type\":\"promo\"},{\"type\":\"news\"}]}")
        )
        assertEquals("{\"items\":[{\"type\":\"post\"},{\"type\":\"news\"}]}", text(out))
    }

    @Test
    fun removeWhereFieldInDistinguishesBooleanFromString() {
        // The value string "true" parses to a JSON boolean; an element whose field is the
        // STRING "true" is a different value and must be kept.
        val op = MitmJsonOperation.RemoveWhereFieldIn(keyPath("items"), "flag", MitmJsonPatch.parseJsonValues("true"))
        val out = MitmJsonPatch.apply(op, bytes("{\"items\":[{\"flag\":true},{\"flag\":\"true\"}]}"))
        assertEquals("{\"items\":[{\"flag\":\"true\"}]}", text(out))
    }

    // MARK: - fail-closed cases

    @Test
    fun malformedJsonBodyLeftUnchanged() {
        val op = MitmJsonOperation.Add(keyPath("a"), JsonPrimitive(1))
        val original = "{not valid json"
        assertArrayEquals(bytes(original), MitmJsonPatch.apply(op, bytes(original)))
    }

    @Test
    fun emptyBodyLeftUnchanged() {
        val op = MitmJsonOperation.Add(keyPath("a"), JsonPrimitive(1))
        assertArrayEquals(ByteArray(0), MitmJsonPatch.apply(op, ByteArray(0)))
    }

    @Test
    fun invalidUtf8BodyLeftUnchanged() {
        val op = MitmJsonOperation.Add(keyPath("a"), JsonPrimitive(1))
        // 0xFF is not a valid UTF-8 lead byte; JSON is a UTF-8 format, so this fails closed.
        val original = byteArrayOf('{'.code.toByte(), 0xFF.toByte(), '}'.code.toByte())
        assertArrayEquals(original, MitmJsonPatch.apply(op, original.copyOf()))
    }

    @Test
    fun deeplyNestedBodyRefusedByDepthCapRatherThanApplied() {
        // A document nested far past the depth cap must be refused (returned byte-identical),
        // not parsed — the guard exists so a nesting bomb cannot overflow the parser stack.
        val depth = 500
        val deep = "{\"a\":".repeat(depth) + "1" + "}".repeat(depth)
        val op = MitmJsonOperation.DeleteRecursive("a")
        assertArrayEquals(bytes(deep), MitmJsonPatch.apply(op, bytes(deep)))

        // Sanity: the same op on a shallow document really fires, so the refusal above is a
        // real guard and not a vacuous no-op.
        val shallow = MitmJsonPatch.apply(op, bytes("{\"a\":1,\"b\":2}"))
        assertEquals("{\"b\":2}", text(shallow))
    }

    // MARK: - applyAll (a run of body-json rules over one parse)

    @Test
    fun applyAllComposesOperationsOverOneParse() {
        val ops = listOf(
            MitmJsonOperation.Add(keyPath("a"), JsonPrimitive(1)),
            MitmJsonOperation.Add(keyPath("b"), JsonPrimitive(2))
        )
        assertEquals("{\"a\":1,\"b\":2}", text(MitmJsonPatch.applyAll(ops, bytes("{}"))))
    }

    @Test
    fun applyAllNetNoOpReturnsOriginalBytes() {
        val ops = listOf(
            MitmJsonOperation.Add(keyPath("x"), JsonPrimitive(1)),
            MitmJsonOperation.Delete(keyPath("x"))
        )
        // The whitespace after ':' would be dropped by a reformat; a net no-op preserves it.
        val original = "{\"a\": 1}"
        assertArrayEquals(bytes(original), MitmJsonPatch.applyAll(ops, bytes(original)))
    }

    // MARK: - value typing (parseValue semantics)

    @Test
    fun jsonValueTypingMatchesReference() {
        // A JSON-looking value keeps its type; a bare word becomes a JSON string.
        val boolOp = MitmJsonOperation.Add(keyPath("v"), MitmJsonPatch.parseJsonValue("true"))
        assertEquals("{\"v\":true}", text(MitmJsonPatch.apply(boolOp, bytes("{\"v\":0}"))))

        val objOp = MitmJsonOperation.Add(keyPath("v"), MitmJsonPatch.parseJsonValue("{\"n\":1}"))
        assertEquals("{\"v\":{\"n\":1}}", text(MitmJsonPatch.apply(objOp, bytes("{\"v\":0}"))))

        val wordOp = MitmJsonOperation.Add(keyPath("v"), MitmJsonPatch.parseJsonValue("hello"))
        assertEquals("{\"v\":\"hello\"}", text(MitmJsonPatch.apply(wordOp, bytes("{\"v\":0}"))))
    }
}
