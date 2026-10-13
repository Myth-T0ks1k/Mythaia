package com.mythaia.desktop.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files

/** The atomic write, and what happens to the data when the file cannot be replaced. */
class DesktopStoreTest {

    @Test
    fun `a write replaces the file and leaves no temp behind`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val file = File(dir, "settings.json")
            val store = DesktopStore()
            store.write(file, "one")
            store.write(file, "two")
            assertEquals("two", file.readText())
            assertFalse(File(dir, "settings.json.tmp").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `a file held open does not lose the new data`() {
        val dir = Files.createTempDirectory("mythaia-store").toFile()
        try {
            val file = File(dir, "configs.json")
            val store = DesktopStore()
            store.write(file, "old")
            // Java opens without FILE_SHARE_DELETE on Windows, so the replace
            // is refused while this is open; elsewhere it simply succeeds.
            RandomAccessFile(file, "r").use {
                store.write(file, "new")
            }
            val temp = File(dir, "configs.json.tmp")
            assertTrue("new text in the file or kept in the temp", file.readText() == "new" || temp.readText() == "new")
            // Once nothing holds it, the next write goes through and tidies up.
            store.write(file, "newer")
            assertEquals("newer", file.readText())
            assertFalse(temp.exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
