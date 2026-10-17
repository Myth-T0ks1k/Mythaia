package com.mythaia.desktop.tun

import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.ptr.IntByReference
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The elevated relaunch hands its arguments to ShellExecuteEx as one
 * command line; the new instance must read back exactly what was meant,
 * including an argfile under a profile with a space and Cyrillic letters.
 */
class ElevationTest {

    @Test
    fun `relaunch arguments survive CommandLineToArgvW`() {
        assumeTrue(WindowsNet.isWindows)
        val arguments = listOf(
            "--tun",
            "@C:\\Users\\Иван Петров\\AppData\\Roaming\\Mythaia\\relaunch.args",
            "C:\\Program Files\\Mythaia Pro\\",
            "say \"hi\""
        )
        val line = "\"C:\\Program Files\\Mythaia Pro\\Mythaia Pro.exe\" " + Elevation.commandLine(arguments)
        val count = IntByReference()
        val argv: Pointer = Shell32.INSTANCE.CommandLineToArgvW(WString(line), count)
        try {
            assertEquals(arguments, argv.getWideStringArray(0, count.value).drop(1))
        } finally {
            Kernel32.INSTANCE.LocalFree(argv)
        }
    }

    @Test
    fun `plain arguments stay unquoted`() {
        assertEquals("--tun --minimized", Elevation.commandLine(listOf("--tun", "--minimized")))
    }
}
