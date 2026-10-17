package com.mythaia.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The macOS wordings stand beside the texts they replace, in both languages. */
class StringsTest {

    @Test
    fun `every mac wording replaces a text that exists, in both languages`() {
        for (lang in Lang.entries) {
            val keys = S.keys(lang)
            for (key in keys.filter { it.endsWith("@mac") }) {
                assertTrue("$lang: $key has no base text", key.removeSuffix("@mac") in keys)
            }
        }
        val ru = S.keys(Lang.RU).filter { it.endsWith("@mac") }.toSet()
        val en = S.keys(Lang.EN).filter { it.endsWith("@mac") }.toSet()
        assertEquals(en, ru)
        assertTrue("tun_hint@mac" in en)
    }

    @Test
    fun `the right wording is picked for this system`() {
        val before = S.lang
        try {
            S.lang = Lang.EN
            val hint = S["tun_hint"]
            if (Platform.isMac) assertTrue(hint.contains("utun")) else assertTrue(hint.contains("Wintun"))
            assertEquals("missing_key_for_test", S["missing_key_for_test"])
        } finally {
            S.lang = before
        }
    }
}
