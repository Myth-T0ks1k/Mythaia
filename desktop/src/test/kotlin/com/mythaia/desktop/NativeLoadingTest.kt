package com.mythaia.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * DLL paths the JVM's code page cannot spell. The JVM itself cannot be made
 * to run under another code page in a test, so the code page is handed in.
 */
class NativeLoadingTest {
    // "Тест ňşý": Cyrillic, which cp1251 has, and three Turkmen letters it lacks.
    private val folder = "\u0422\u0435\u0441\u0442 \u0148\u015F\u00FD"

    @Test
    fun `a Russian code page spells Cyrillic but not the Turkmen letters`() {
        assertTrue(NativeLoading.spellable("C:\\\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C", "windows-1251"))
        assertFalse(NativeLoading.spellable("C:\\$folder\\app", "windows-1251"))
        assertFalse(NativeLoading.spellable("C:\\$folder\\app", "windows-1252"))
        assertTrue(NativeLoading.spellable("C:\\$folder\\app", "UTF-8"))
        // An unknown or missing code page is not a reason to rewrite a path.
        assertTrue(NativeLoading.spellable("C:\\$folder", null))
        assertTrue(NativeLoading.spellable("C:\\$folder", "no-such-charset"))
    }

    @Test
    fun `a spellable path is used as it is`() {
        val file = File("C:\\Program Files\\Mythaia Pro\\app\\resources\\mythaia_native.dll")
        assertEquals(file.absolutePath, NativeLoading.loadablePath(file, "windows-1251"))
    }

    @Test
    fun `an unspellable path is replaced by its short form, which exists`() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows"))
        val dir = Files.createTempDirectory("native-loading").toFile()
        try {
            val odd = File(dir, folder).apply { mkdirs() }
            val dll = File(odd, "x.dll").apply { writeText("not a dll") }
            val loadable = NativeLoading.loadablePath(dll, "windows-1251")
            val short = NativeLoading.shortPath(dll.absolutePath)
            if (short == null || !NativeLoading.spellable(short, "windows-1251")) {
                // A volume without 8.3 names: nothing better than the path itself.
                assertEquals(dll.absolutePath, loadable)
            } else {
                assertTrue("short form $loadable", NativeLoading.spellable(loadable, "windows-1251"))
                assertTrue(File(loadable).isFile)
                assertEquals(dll.canonicalFile, File(loadable).canonicalFile)
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
