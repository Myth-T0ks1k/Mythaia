package com.mythaia.desktop.service

import com.mythaia.desktop.APP_VERSION
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * The whole install path against the real service control manager: the
 * UAC prompt, the elevated helper, the copy to Program Files, CreateService,
 * the service answering on its pipe, then removal. Runs only with
 * MYTHAIA_SERVICE_INSTALL_SMOKE set to a packaged `Mythaia Pro.exe` (put it
 * under a folder with spaces and non-Latin letters), and someone must accept
 * three UAC prompts.
 */
class ServiceInstallSmoke {
    @Test
    fun `installs into Program Files, answers and uninstalls`() {
        val exe = System.getenv("MYTHAIA_SERVICE_INSTALL_SMOKE")?.let(::File)
        assumeTrue(exe != null && exe.isFile)
        System.setProperty("jpackage.app-path", exe!!.absolutePath)
        val copy = ServiceImage.directory()

        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.install())
        assertTrue(ServiceInstaller.isInstalled())
        assertEquals("\"${File(copy, exe.name).absolutePath}\" --service", imagePath())
        assertTrue(File(copy, "runtime").isDirectory)
        // The copy is the administrators' alone: this unelevated process cannot plant a file in it.
        assertFalse("Program Files copy is writable by the user", canWrite(File(copy, "app")))

        val reply = awaitService()
        assertEquals(APP_VERSION, reply.appVersion)
        println("service answered from $copy, version ${reply.appVersion}")

        // Installing again over a registered service stops it, replaces the copy and starts it.
        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.install())
        awaitService()

        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.uninstall())
        assertFalse(ServiceInstaller.isInstalled())
        assertFalse("the Program Files copy is left behind", copy.exists())
    }

    private fun awaitService(): ServiceProtocol.Response {
        val deadline = System.currentTimeMillis() + 30_000
        while (System.currentTimeMillis() < deadline) {
            ServiceClient.ping()?.let { return it }
            Thread.sleep(500)
        }
        throw AssertionError("the service never opened its pipe")
    }

    private fun imagePath(): String = Advapi32Util.registryGetValue(
        WinReg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\${ServiceProtocol.SERVICE_NAME}", "ImagePath"
    ) as String

    private fun canWrite(dir: File): Boolean = try {
        val probe = File(dir, "probe-${System.nanoTime()}.txt")
        probe.writeText("x")
        probe.delete()
        true
    } catch (_: IOException) {
        false
    }
}
