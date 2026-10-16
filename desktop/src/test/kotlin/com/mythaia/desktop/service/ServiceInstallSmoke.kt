package com.mythaia.desktop.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * The whole install path against the real service control manager: the
 * UAC prompt, the elevated helper, CreateService, the service answering on
 * its pipe, then removal. Runs only with MYTHAIA_SERVICE_INSTALL_SMOKE set
 * to a packaged `Mythaia Pro.exe` (put it under a folder with spaces and
 * non-Latin letters), and someone must accept two UAC prompts.
 */
class ServiceInstallSmoke {
    @Test
    fun `installs, answers and uninstalls`() {
        val exe = System.getenv("MYTHAIA_SERVICE_INSTALL_SMOKE")?.let(::File)
        assumeTrue(exe != null && exe.isFile)
        System.setProperty("jpackage.app-path", exe!!.absolutePath)

        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.install())
        assertTrue(ServiceInstaller.isInstalled())
        val deadline = System.currentTimeMillis() + 30_000
        while (!ServiceClient.isAvailable() && System.currentTimeMillis() < deadline) Thread.sleep(500)
        assertTrue("the service never opened its pipe", ServiceClient.isAvailable())
        println("service answered; status: ${ServiceClient.status(0)?.running}")

        // Installing again over a registered service updates it instead of failing.
        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.install())

        assertEquals(ServiceInstaller.Outcome.DONE, ServiceInstaller.uninstall())
        assertFalse(ServiceInstaller.isInstalled())
    }
}
