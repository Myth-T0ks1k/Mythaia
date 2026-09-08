package com.mythaia.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Snippets are written by hand from the `.amrs` format reference; expected
 * [MitmRule] values are built directly and compared for structural equality, so
 * a test fails if the parser reads a field into the wrong slot rather than
 * merely echoing whatever the parser produced.
 *
 * Note the raw-string quirk: `\.` in a `"""…"""` snippet is a literal
 * backslash-dot (raw strings do not process escapes), and `$1` is a literal
 * `$1` (a `$` before a digit is not a Kotlin template), which is exactly what
 * the `.amrs` bytes on disk would contain.
 */
class AmrsParserTest {

    @Test
    fun parsesCompleteExample() {
        val set = AmrsParser.parse(
            """
            name        = My Rule Set
            hostname    = example.com, api.example.org

            # request: transparently rewrite the whole URL to a new host
            0, 0, ^https://example\.com/old, 0, https://upstream.example.com/new
            # request: add a header on /api/ paths
            0, 1, ^/api/, X-Powered-By, Mythaia
            """.trimIndent()
        )

        assertEquals("My Rule Set", set.name)
        assertEquals(listOf("example.com", "api.example.org"), set.domainSuffixes)
        assertEquals(
            listOf(
                MitmRule(
                    HttpPhase.REQUEST,
                    "^https://example\\.com/old",
                    MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://upstream.example.com/new"))
                ),
                MitmRule(
                    HttpPhase.REQUEST,
                    "^/api/",
                    MitmOperation.HeaderAdd("X-Powered-By", "Mythaia")
                )
            ),
            set.rules
        )
    }

    @Test
    fun parsesHeaderDeleteOnResponsePhase() {
        assertEquals(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderDelete("Set-Cookie")),
            AmrsParser.parseRule("1, 2, .*, Set-Cookie")
        )
    }

    @Test
    fun parsesHeaderReplace() {
        assertEquals(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.HeaderReplace("Cache-Control", "no-store")),
            AmrsParser.parseRule("1, 3, .*, Cache-Control, no-store")
        )
    }

    @Test
    fun parsesBodyReplace() {
        assertEquals(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("http://", "https://")),
            AmrsParser.parseRule("1, 4, .*, http://, https://")
        )
    }

    @Test
    fun parsesRewriteSubModes() {
        assertEquals(
            MitmRule(HttpPhase.REQUEST, ".*/ads/", MitmOperation.Rewrite(MitmRewriteAction.Reject200Gif)),
            AmrsParser.parseRule("0, 0, .*/ads/, 3")
        )
        assertEquals(
            MitmRule(
                HttpPhase.REQUEST,
                "^https://old\\.example\\.com/page",
                MitmOperation.Rewrite(MitmRewriteAction.Redirect302("https://new.example.com/page"))
            ),
            AmrsParser.parseRule("0, 0, ^https://old\\.example\\.com/page, 1, https://new.example.com/page")
        )
        assertEquals(
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Text("Blocked"))),
            AmrsParser.parseRule("0, 0, .*, 2, Blocked")
        )
        assertEquals(
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.Rewrite(MitmRewriteAction.Reject200Data("TXl0aGFpYQ=="))),
            AmrsParser.parseRule("0, 0, .*, 4, TXl0aGFpYQ==")
        )
    }

    @Test
    fun rewritePhaseColumnIsForcedToRequest() {
        // Phase column says response, but `rewrite` (op 0) can only run on the request.
        val rule = AmrsParser.parseRule("1, 0, .*, 3")
        assertEquals(HttpPhase.REQUEST, rule?.phase)
    }

    @Test
    fun capturePatternRewriteKeepsTemplate() {
        assertEquals(
            MitmRule(
                HttpPhase.REQUEST,
                "^https://old\\.example\\.com/(.*)",
                MitmOperation.Rewrite(MitmRewriteAction.Transparent("https://new.example.com/\$1"))
            ),
            AmrsParser.parseRule("0, 0, ^https://old\\.example\\.com/(.*), 0, https://new.example.com/\$1")
        )
    }

    @Test
    fun refusesWrongFieldCount() {
        // header-add needs url-pattern, name, AND value.
        assertNull(AmrsParser.parseRule("0, 1, ^/api/, X-Powered-By"))
    }

    @Test
    fun refusesInvalidPhase() {
        assertNull(AmrsParser.parseRule("2, 1, .*, X, y"))
    }

    @Test
    fun refusesUncompilableUrlPattern() {
        // An unterminated character class is not a valid regex.
        assertNull(AmrsParser.parseRule("0, 1, [unterminated, X, y"))
    }

    @Test
    fun refusesEmptyUrlPattern() {
        assertNull(AmrsParser.parseRule("0, 1, , X, y"))
    }

    @Test
    fun refusesFramingHeaderMutation() {
        assertNull(AmrsParser.parseRule("0, 1, .*, Content-Length, 0"))
        assertNull(AmrsParser.parseRule("1, 3, .*, Transfer-Encoding, chunked"))
    }

    @Test
    fun refusesInvalidHeaderName() {
        // A space is not a valid header-name token (RFC 9110 §5.6.2).
        assertNull(AmrsParser.parseRule("0, 1, .*, Bad Name, y"))
    }

    @Test
    fun refusesCrOrLfOrNulInHeaderValue() {
        assertNull(AmrsParser.parseRule("0, 1, .*, X-H, va\rlue"))
        assertNull(AmrsParser.parseRule("0, 1, .*, X-H, va\nlue"))
        assertNull(AmrsParser.parseRule("0, 1, .*, X-H, va\u0000lue"))
    }

    @Test
    fun acceptsHeaderValueContainingSpaces() {
        // Spaces are legal in a header value (only CR/LF/NUL are barred), so a value
        // like a bearer token must survive. This is looser than the shared
        // HttpHeader.isValidValue, which also rejects spaces for its own callers.
        assertEquals(
            MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-H", "Bearer abc def")),
            AmrsParser.parseRule("0, 1, .*, X-H, Bearer abc def")
        )
    }

    @Test
    fun refusesUnparseableRewriteTarget() {
        // No scheme://host — not an absolute URL.
        assertNull(AmrsParser.parseRule("0, 0, .*, 0, /just/a/path"))
    }

    @Test
    fun refusesInvalidRejectDataBase64() {
        // Non-empty payload that is not valid base64.
        assertNull(AmrsParser.parseRule("0, 0, .*, 4, not!base64!"))
    }

    @Test
    fun dropsUnsupportedOperations() {
        // body-json (5), script (100), stream-script (101): valid format, unported.
        assertNull(AmrsParser.parseRule("1, 5, ^/api/user, add, \$.user.vip, true"))
        assertNull(AmrsParser.parseRule("0, 100, .*, Zm9v"))
        assertNull(AmrsParser.parseRule("1, 101, ^/events, Zm9v"))
    }

    @Test
    fun ignoresCommentsBlankLinesAndParameterSection() {
        val set = AmrsParser.parse(
            """
            # a comment
            name = Sectioned
            // another comment

            [Parameter]
            0, 1, .*, X-ShouldNotApply, v

            [Rule]
            0, 1, .*, X-Applied, y
            """.trimIndent()
        )

        assertEquals("Sectioned", set.name)
        // The line under [Parameter] must not become a rule; only the [Rule] line does.
        assertEquals(
            listOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-Applied", "y"))),
            set.rules
        )
    }

    @Test
    fun headerKeysAndSectionMarkersAreCaseInsensitive() {
        val set = AmrsParser.parse(
            """
            NAME = Upper
            HostName = a.com, b.com
            [RULES]
            0, 1, .*, X, y
            """.trimIndent()
        )
        assertEquals("Upper", set.name)
        assertEquals(listOf("a.com", "b.com"), set.domainSuffixes)
        assertEquals(1, set.rules.size)
    }

    @Test
    fun csvQuotingPreservesCommaInsideField() {
        assertEquals(
            MitmRule(HttpPhase.REQUEST, "^/", MitmOperation.HeaderAdd("X-Note", "value, with a comma")),
            AmrsParser.parseRule("0, 1, ^/, X-Note, \"value, with a comma\"")
        )
    }

    @Test
    fun doubledQuotesInsideQuotedFieldAreLiteral() {
        // The reference writes a literal `"price":` as `"""price"":"`.
        val rule = AmrsParser.parseRule("1, 4, .*, \"\"\"price\"\":\", \"\"\"cost\"\":\"")
        assertEquals(
            MitmRule(HttpPhase.RESPONSE, ".*", MitmOperation.BodyReplace("\"price\":", "\"cost\":")),
            rule
        )
    }

    @Test
    fun malformedLinesAreDroppedButValidOnesSurvive() {
        val set = AmrsParser.parse(
            """
            hostname = x.com
            garbage line that is not a rule
            0, 99, .*, whatever
            0, 1, .*, X-Kept, yes
            """.trimIndent()
        )
        assertEquals(
            listOf(MitmRule(HttpPhase.REQUEST, ".*", MitmOperation.HeaderAdd("X-Kept", "yes"))),
            set.rules
        )
        assertTrue(set.domainSuffixes.contains("x.com"))
    }
}
