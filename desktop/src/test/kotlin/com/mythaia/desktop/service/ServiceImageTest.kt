package com.mythaia.desktop.service

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The service's copy of the app: what goes into it, how a newer copy
 * replaces an older one, and that links in either tree are never followed.
 */
class ServiceImageTest {
    private val root: File = Files.createTempDirectory("service image ").toFile()

    @After
    fun cleanUp() {
        ServiceImage.deleteTree(root.toPath())
    }

    /** A jpackage image: the launcher, app\ and runtime\, plus something that is not part of it. */
    private fun image(version: String): File {
        val dir = File(root, "Mythaia Pro $version").apply { mkdirs() }
        File(dir, "Mythaia Pro.exe").writeText("launcher $version")
        File(dir, "app/resources").mkdirs()
        File(dir, "app/desktop.jar").writeText("jar $version")
        File(dir, "app/resources/wintun.dll").writeText("dll $version")
        File(dir, "runtime/bin").mkdirs()
        File(dir, "runtime/bin/server.dll").writeText("jvm $version")
        File(dir, "notes.txt").writeText("not part of the image")
        return File(dir, "Mythaia Pro.exe")
    }

    @Test
    fun `copies the launcher, app and runtime and nothing else`() {
        val target = File(root, "Program Files/Mythaia Pro Service")
        val exe = ServiceImage.deploy(image("1"), target)

        assertEquals(File(target, "Mythaia Pro.exe"), exe)
        assertEquals("launcher 1", exe.readText())
        assertEquals("jar 1", File(target, "app/desktop.jar").readText())
        assertEquals("dll 1", File(target, "app/resources/wintun.dll").readText())
        assertEquals("jvm 1", File(target, "runtime/bin/server.dll").readText())
        assertFalse(File(target, "notes.txt").exists())
        assertFalse(File(target.parentFile, "Mythaia Pro Service.new").exists())
    }

    @Test
    fun `a newer image replaces the old copy whole`() {
        val target = File(root, "Program Files/Mythaia Pro Service")
        ServiceImage.deploy(image("1"), target)
        File(target, "app/stale.jar").writeText("left over from 1")
        // jpackage marks its files read-only; replacing them must still work.
        File(target, "app/desktop.jar").setReadOnly()

        ServiceImage.deploy(image("2"), target)

        assertEquals("launcher 2", File(target, "Mythaia Pro.exe").readText())
        assertEquals("jar 2", File(target, "app/desktop.jar").readText())
        assertFalse(File(target, "app/stale.jar").exists())
        assertFalse(File(target.parentFile, "Mythaia Pro Service.new").exists())
        assertFalse(File(target.parentFile, "Mythaia Pro Service.old").exists())
    }

    @Test
    fun `remove deletes the copy and its leftovers`() {
        val target = File(root, "Program Files/Mythaia Pro Service")
        ServiceImage.deploy(image("1"), target)
        File(target.parentFile, "Mythaia Pro Service.new/half").apply { parentFile.mkdirs(); writeText("x") }

        ServiceImage.remove(target)

        assertFalse(target.exists())
        assertFalse(File(target.parentFile, "Mythaia Pro Service.new").exists())
    }

    @Test
    fun `junctions are neither copied through nor deleted through`() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows"))
        val secret = File(root, "elsewhere").apply { mkdirs() }
        File(secret, "secret.txt").writeText("must stay")
        val exe = image("1")
        val junction = File(exe.parentFile, "app/linked")
        val made = ProcessBuilder("cmd", "/c", "mklink", "/J", junction.absolutePath, secret.absolutePath)
            .redirectErrorStream(true).start().let { it.inputStream.readBytes(); it.waitFor() == 0 }
        assumeTrue("mklink /J is unavailable", made)

        val target = File(root, "Program Files/Mythaia Pro Service")
        ServiceImage.deploy(exe, target)
        assertFalse(File(target, "app/linked").exists())

        ServiceImage.deleteTree(exe.parentFile.toPath())
        assertFalse(exe.parentFile.exists())
        assertTrue("the junction's target was deleted", File(secret, "secret.txt").isFile)
    }
}
