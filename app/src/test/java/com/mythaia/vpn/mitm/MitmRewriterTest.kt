package com.mythaia.vpn.mitm

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * Each rewrite is checked against the effect the format reference documents for
 * that operation, with the expected headers/body/URL built by hand — never read
 * back from what the rewriter emitted.
 */
class MitmRewriterTest {

    private fun rewriterOf(vararg rules: MitmRule) =
        MitmRewriter(MitmRuleSet(name = "t", domainSuffixes = listOf("example.com"), rules = rules.toList()))

    private fun request(url: String?, headers: List<HttpHeader> = emptyList(), body: ByteArray = ByteArray(0)) =
        HttpMessage.request("GET", url, headers, body)

    private fun response(url: String?, headers: List<HttpHeader> = emptyList(), body: ByteArray = ByteArray(0)) =
        HttpMessage.response(200, url, headers, body)

    private fun forward(result: MitmRewriteResult): HttpMessage {
        assertTrue("expected Forward but got $result", result is MitmRewriteResult.Forward)
        return (result as MitmRewriteResult.Forward).message
    }

    private fun respond(result: MitmRewriteResult): HttpMessage {
        assertTrue("expected Respond but got $result", result is MitmRewriteResult.Respond)
        return (result as MitmRewriteResult.Respond).response
    }

    // MARK: - header-add (1)

    @Test
    fun headerAddAppendsAtEnd() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-Trace-Id", "mythaia")))
        val msg = request("https://api.example.com/v2/x", listOf(HttpHeader("Host", "api.example.com")))
        val out = forward(r.rewrite(msg))
        assertEquals(
            listOf(HttpHeader("Host", "api.example.com"), HttpHeader("X-Trace-Id", "mythaia")),
            out.headers
        )
    }

    @Test
    fun headerAddDoesNotReplaceExisting() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("Accept", "application/json")))
        val msg = request("https://api.example.com/x", listOf(HttpHeader("Accept", "text/html")))
        val out = forward(r.rewrite(msg))
        assertEquals(listOf("text/html", "application/json"), out.headerValues("Accept"))
    }

    // MARK: - header-delete (2)

    @Test
    fun headerDeleteRemovesEveryMatchCaseInsensitively() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderDelete("Set-Cookie")))
        val msg = response(
            "https://example.com/x",
            listOf(
                HttpHeader("Set-Cookie", "a=1"),
                HttpHeader("set-cookie", "b=2"),   // different case, still deleted
                HttpHeader("Content-Type", "text/html")
            )
        )
        val out = forward(r.rewrite(msg))
        assertEquals(listOf(HttpHeader("Content-Type", "text/html")), out.headers)
    }

    // MARK: - header-replace (3)

    @Test
    fun headerReplaceOverwritesValueAndNormalizesName() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderReplace("Cache-Control", "no-store")))
        val msg = response("https://example.com/x", listOf(HttpHeader("cache-control", "max-age=60")))
        val out = forward(r.rewrite(msg))
        // Value overwritten AND the on-wire name normalized to the rule's spelling.
        assertEquals(listOf(HttpHeader("Cache-Control", "no-store")), out.headers)
    }

    @Test
    fun headerReplaceDoesNotAddAbsentHeader() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderReplace("Cache-Control", "no-store")))
        val msg = response("https://example.com/x", listOf(HttpHeader("Content-Type", "text/html")))
        val out = forward(r.rewrite(msg))
        assertEquals(listOf(HttpHeader("Content-Type", "text/html")), out.headers)
    }

    // MARK: - phase gating

    @Test
    fun responsePhaseRuleDoesNotFireOnRequest() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderAdd("X-R", "1")))
        val msg = request("https://example.com/x", listOf(HttpHeader("Host", "example.com")))
        assertEquals(msg, forward(r.rewrite(msg)))
    }

    @Test
    fun requestPhaseRuleDoesNotFireOnResponse() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-Q", "1")))
        val msg = response("https://example.com/x", listOf(HttpHeader("Content-Type", "text/html")))
        assertEquals(msg, forward(r.rewrite(msg)))
    }

    @Test
    fun rewriteRuleDoesNotFireOnResponse() {
        // rewrite is request-only; a response must pass through, never be rejected.
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Gif)))
        val msg = response("https://example.com/x", listOf(HttpHeader("Content-Type", "text/html")))
        assertEquals(msg, forward(r.rewrite(msg)))
    }

    // MARK: - rewrite / block (0)

    /** The canonical 43-byte 1×1 transparent GIF89a, taken from the format reference. */
    private val referenceTinyGif = byteArrayOf(
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
        0x80.toByte(), 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
        0x00, 0x00, 0x00, 0x21, 0xF9.toByte(), 0x04, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x02, 0x02, 0x4C, 0x01, 0x00, 0x3B
    )

    @Test
    fun rejectGifSynthesizesGifResponse() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Gif)))
        val out = respond(r.rewrite(request("https://tracker.example.com/pixel")))
        assertEquals(200, out.status)
        assertEquals("image/gif", out.header("Content-Type"))
        assertArrayEquals(referenceTinyGif, out.body)
    }

    @Test
    fun rejectTextSynthesizesPlainTextResponse() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Text("Blocked by policy"))))
        val out = respond(r.rewrite(request("https://example.com/x")))
        assertEquals(200, out.status)
        assertEquals("text/plain; charset=utf-8", out.header("Content-Type"))
        assertArrayEquals("Blocked by policy".toByteArray(StandardCharsets.UTF_8), out.body)
    }

    @Test
    fun rejectTextEmptyContentFallsBackToNonEmptyBody() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Text(""))))
        val out = respond(r.rewrite(request("https://example.com/x")))
        assertEquals("text/plain; charset=utf-8", out.header("Content-Type"))
        assertTrue("empty content should fall back to a default line", out.body.isNotEmpty())
    }

    @Test
    fun rejectDataDecodesBase64Body() {
        // "SGVsbG8=" is base64 for "Hello" (RFC 4648).
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Data("SGVsbG8="))))
        val out = respond(r.rewrite(request("https://example.com/x")))
        assertEquals(200, out.status)
        assertEquals("application/octet-stream", out.header("Content-Type"))
        assertArrayEquals(byteArrayOf('H'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'l'.code.toByte(), 'o'.code.toByte()), out.body)
    }

    @Test
    fun redirect302SynthesizesLocationResponse() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Redirect302("https://new.example.com/page"))))
        val out = respond(r.rewrite(request("https://old.example.com/page")))
        assertEquals(302, out.status)
        assertEquals("https://new.example.com/page", out.header("Location"))
        assertEquals(0, out.body.size)
    }

    @Test
    fun transparentRewriteReplacesUrlAndHost() {
        val r = rewriterOf(
            MitmRule(
                HttpPhase.REQUEST,
                "^https://example\\.com/old",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://upstream.example.com/new"))
            )
        )
        val msg = request("https://example.com/old", listOf(HttpHeader("Host", "example.com")))
        val out = forward(r.rewrite(msg))
        assertEquals("https://upstream.example.com/new", out.url)
        assertEquals("upstream.example.com", out.header("Host"))
        assertEquals("GET", out.method)
    }

    @Test
    fun transparentRewriteExpandsCaptureInTarget() {
        val r = rewriterOf(
            MitmRule(
                HttpPhase.REQUEST,
                "^https://example\\.com/old/(.*)",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://example.com/new/\$1"))
            )
        )
        val msg = request("https://example.com/old/path/42", listOf(HttpHeader("Host", "example.com")))
        val out = forward(r.rewrite(msg))
        assertEquals("https://example.com/new/path/42", out.url)
    }

    @Test
    fun firstMatchingRewriteWins() {
        val r = rewriterOf(
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Text("first"))),
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Gif))
        )
        val out = respond(r.rewrite(request("https://example.com/x")))
        assertEquals("text/plain; charset=utf-8", out.header("Content-Type"))
        assertArrayEquals("first".toByteArray(StandardCharsets.UTF_8), out.body)
    }

    @Test
    fun rewriteThatFailsToResolveLetsALaterRuleWin() {
        // The first rule matches, but its templated target expands to a URL with an
        // illegal space, so it can't resolve; the second rule should still fire.
        val r = rewriterOf(
            MitmRule(
                HttpPhase.REQUEST,
                "^https://ex\\.com/old/(.*)",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://up.com/\$1"))
            ),
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Gif))
        )
        val out = respond(r.rewrite(request("https://ex.com/old/a b")))
        assertEquals("image/gif", out.header("Content-Type"))
    }

    // MARK: - body-replace (4)

    @Test
    fun bodyReplaceRewritesEveryMatch() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("http://", "https://")))
        val msg = response("https://example.com/x", body = "go to http://a and http://b".toByteArray(StandardCharsets.UTF_8))
        val out = forward(r.rewrite(msg))
        assertEquals("go to https://a and https://b", String(out.body, StandardCharsets.UTF_8))
    }

    @Test
    fun bodyReplaceExpandsCaptureReferences() {
        // Spec example: reorder YYYY-MM-DD to DD/MM/YYYY via `$3/$2/$1`.
        val r = rewriterOf(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("(\\d{4})-(\\d{2})-(\\d{2})", "\$3/\$2/\$1"))
        )
        val msg = response("https://example.com/x", body = "date: 2026-09-09.".toByteArray(StandardCharsets.UTF_8))
        val out = forward(r.rewrite(msg))
        assertEquals("date: 09/09/2026.", String(out.body, StandardCharsets.UTF_8))
    }

    @Test
    fun bodyReplaceWithEmptyReplacementDeletesMatches() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("SECRET", "")))
        val msg = response("https://example.com/x", body = "a SECRET b SECRET c".toByteArray(StandardCharsets.UTF_8))
        val out = forward(r.rewrite(msg))
        assertEquals("a  b  c", String(out.body, StandardCharsets.UTF_8))
    }

    @Test
    fun bodyReplacesComposeInRuleOrder() {
        val r = rewriterOf(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("cat", "dog")),
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("dog", "fish"))
        )
        val msg = response("https://example.com/x", body = "cat".toByteArray(StandardCharsets.UTF_8))
        val out = forward(r.rewrite(msg))
        // First rule turns cat->dog, second turns that dog->fish.
        assertEquals("fish", String(out.body, StandardCharsets.UTF_8))
    }

    @Test
    fun bodyReplaceLeavesNonUtf8BodyByteIdenticalWhenNothingMatches() {
        val r = rewriterOf(MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("zzz", "yyy")))
        val original = byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x80.toByte(), 0x00)
        val msg = response("https://example.com/x", body = original.copyOf())
        val out = forward(r.rewrite(msg))
        assertArrayEquals(original, out.body)
    }

    // MARK: - URL gate

    @Test
    fun urlGateMatchesHostCaseInsensitively() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, "^https://api\\.example\\.com/", MitmOperation.HeaderAdd("X-H", "y")))
        val out = forward(r.rewrite(request("https://API.EXAMPLE.COM/path")))
        assertEquals("y", out.header("X-H"))
    }

    @Test
    fun urlGateKeepsPathCaseSensitive() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, "^https://api\\.example\\.com/PATH", MitmOperation.HeaderAdd("X-H", "y")))
        val out = forward(r.rewrite(request("https://api.example.com/path")))
        assertNull("path case must not be folded, so the gate must not match", out.header("X-H"))
    }

    @Test
    fun urlGateFailsClosedWhenUrlUnknown() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-H", "y")))
        val msg = request(null, listOf(HttpHeader("Host", "example.com")))
        assertEquals(msg, forward(r.rewrite(msg)))
    }

    @Test
    fun urlGateNeverMatchesOverlongUrl() {
        val r = rewriterOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-H", "y")))
        val longUrl = "https://example.com/" + "a".repeat(9000)
        val out = forward(r.rewrite(request(longUrl)))
        assertNull(out.header("X-H"))
    }

    // MARK: - end to end

    @Test
    fun parsedRuleSetBlocksWithGif() {
        val set = AmrsParser.parse(
            """
            name = Block Tracker
            hostname = tracker.example.com
            0, 0, .*, 3
            """.trimIndent()
        )
        val out = respond(MitmRewriter(set).rewrite(request("https://tracker.example.com/pixel")))
        assertEquals("image/gif", out.header("Content-Type"))
        assertArrayEquals(referenceTinyGif, out.body)
    }

    // MARK: - bodyEditable gate (a body the codec could not decode)

    @Test
    fun bodyReplaceIsSkippedButHeaderRuleStillFiresWhenBodyNotEditable() {
        // A body that arrived in a coding the codec could not decode is opaque
        // compressed bytes; running a body-replace regex over them would corrupt
        // the stream, so bodyEditable=false skips the body pass while the header
        // pass still applies.
        val opaque = byteArrayOf(0x1f.toByte(), 0x8b.toByte(), 0x08, 0x00, 0x13, 0x37, 0x00, 0x00)
        val r = rewriterOf(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace(".", "X")),
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderAdd("X-Mitm", "seen"))
        )
        val msg = response("https://x.example.com/a", body = opaque)

        // Sanity: with an editable body the replace really fires, so the skip is
        // a real guard rather than a vacuous pass.
        assertTrue(!forward(r.rewrite(msg, bodyEditable = true)).body.contentEquals(opaque))

        val out = forward(r.rewrite(msg, bodyEditable = false))
        assertArrayEquals(opaque, out.body)
        assertEquals("seen", out.header("X-Mitm"))
    }
}
