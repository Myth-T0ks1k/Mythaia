package com.mythaia.desktop.service

import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.ptr.IntByReference
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The elevated helper's arguments go through one Windows command line.
 * Each must come back out of CommandLineToArgvW exactly as it went in —
 * the old installer lost the quotes around a path with spaces, and
 * `sc create` got `--service` as an argument of its own.
 */
class ServiceInstallerTest {
    private val samples = listOf(
        ServiceInstaller.INSTALL_ARG,
        "@C:\\Users\\Пользователь\\AppData\\Roaming\\Mythaia\\relaunch.args",
        "C:\\Users\\Пользователь\\Desktop\\Mythaia Pro\\Mythaia Pro.exe",
        "\"C:\\Program Files\\Mythaia Pro\\Mythaia Pro.exe\" --service",
        "C:\\folder with space\\",
        "a\\\\\"b",
        ""
    )

    @Test
    fun `plain arguments are left alone`() {
        assertEquals("--install-service", ServiceInstaller.commandLineArg("--install-service"))
        assertEquals("C:\\Users\\a\\b.args", ServiceInstaller.commandLineArg("C:\\Users\\a\\b.args"))
    }

    @Test
    fun `quoting follows the Windows rules`() {
        assertEquals("\"a b\"", ServiceInstaller.commandLineArg("a b"))
        assertEquals("\"C:\\dir x\\\\\"", ServiceInstaller.commandLineArg("C:\\dir x\\"))
        assertEquals("\"say \\\"hi\\\"\"", ServiceInstaller.commandLineArg("say \"hi\""))
        assertEquals("\"\"", ServiceInstaller.commandLineArg(""))
    }

    @Test
    fun `every argument survives CommandLineToArgvW`() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows"))
        val line = "helper.exe " + samples.joinToString(" ") { ServiceInstaller.commandLineArg(it) }
        val count = IntByReference()
        val argv: Pointer = Shell32.INSTANCE.CommandLineToArgvW(WString(line), count)
        try {
            val parsed = argv.getWideStringArray(0, count.value).drop(1)
            assertEquals(samples, parsed)
        } finally {
            Kernel32.INSTANCE.LocalFree(argv)
        }
    }
}
