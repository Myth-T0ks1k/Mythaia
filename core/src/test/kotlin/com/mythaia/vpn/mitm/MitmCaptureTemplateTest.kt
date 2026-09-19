package com.mythaia.vpn.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Expected outputs are worked out by hand from the documented capture grammar
 * (`$0` whole match, `$1`–`$9` single-digit groups, `${N}` braced, `$$` a
 * literal `$`, any other `$` literal), not read back from the implementation.
 */
class MitmCaptureTemplateTest {

    @Test
    fun singleDigitGroupsExpand() {
        val template = MitmCaptureTemplate("\$1-\$2")
        assertTrue(template.referencesCaptures)
        // captures[0] is the whole match; groups follow.
        assertEquals("a-b", template.expand(listOf("whole", "a", "b")))
    }

    @Test
    fun groupZeroIsWholeMatch() {
        assertEquals("WHOLE", MitmCaptureTemplate("\$0").expand(listOf("WHOLE", "x")))
    }

    @Test
    fun doubleDollarIsALiteralDollar() {
        val template = MitmCaptureTemplate("price: \$\$5")
        assertFalse(template.referencesCaptures)
        assertEquals("price: \$5", template.expand(listOf("ignored")))
        assertEquals("price: \$5", template.staticReplacement)
    }

    @Test
    fun bracedIndexReachesPastNine() {
        val captures = (0..10).map { "g$it" } // g0..g10
        assertEquals("g10", MitmCaptureTemplate("\${10}").expand(captures))
    }

    @Test
    fun nonParticipatingGroupExpandsEmpty() {
        // Index 3 is out of range for a 2-element capture list -> empty, never "$3".
        assertEquals("[]", MitmCaptureTemplate("[\$3]").expand(listOf("w", "a")))
    }

    @Test
    fun literalOnlyTemplateHasStaticReplacement() {
        val template = MitmCaptureTemplate("no references here")
        assertFalse(template.referencesCaptures)
        assertEquals("no references here", template.staticReplacement)
    }

    @Test
    fun referencingTemplateHasNoStaticReplacement() {
        assertNull(MitmCaptureTemplate("x\$1").staticReplacement)
    }

    @Test
    fun dateReorderMatchesBodyReplaceExample() {
        // From the spec's `body-replace` example: `$3/$2/$1` over YYYY-MM-DD groups.
        val template = MitmCaptureTemplate("\$3/\$2/\$1")
        assertEquals("09/09/2026", template.expand(listOf("2026-09-09", "2026", "09", "09")))
    }

    @Test
    fun malformedBraceStaysLiteral() {
        // `${x}` is not a valid braced index, so the `$` is literal and the braces follow.
        val template = MitmCaptureTemplate("\${x}")
        assertFalse(template.referencesCaptures)
        assertEquals("\${x}", template.expand(listOf("ignored")))
    }

    @Test
    fun dollarBeforeNonDigitStaysLiteral() {
        val template = MitmCaptureTemplate("cost is \$a")
        assertFalse(template.referencesCaptures)
        assertEquals("cost is \$a", template.expand(listOf("ignored")))
    }
}
