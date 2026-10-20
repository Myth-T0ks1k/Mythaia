package com.mythaia.desktop.engine

import com.mythaia.desktop.AppPaths
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.WinReg
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * The crash restore of the system proxy. Everything here runs against the
 * test key the build points SystemProxy at (`mythaia.test.registryRoot`)
 * and the build's own APPDATA, never the real proxy settings.
 */
class ProxyGuardTest {
    private val root: String? = System.getProperty("mythaia.test.registryRoot")
    private val key get() = "$root\\Internet Settings"

    @After
    fun cleanUp() {
        val root = root
        if (!SystemProxy.isWindows || root == null) return
        runCatching { deleteTree(root) }
        // And the parent, once nothing else is under it.
        val parent = root.substringBeforeLast('\\')
        runCatching {
            if (Advapi32Util.registryGetKeys(WinReg.HKEY_CURRENT_USER, parent).isEmpty()) Advapi32Util.registryDeleteKey(WinReg.HKEY_CURRENT_USER, parent)
        }
        AppPaths.proxySnapshot.delete()
    }

    @Test
    fun `the guard is told the pid, the snapshot and the restore command`() {
        val command = ProxyGuard.guardCommand(
            File("C:/app/resources/mythaia-proxy-guard.exe"), 4242, File("C:/data/Mythaia/system-proxy-before.json"),
            listOf("C:/app/Mythaia Pro.exe", ProxyGuard.RESTORE_ARG)
        )
        assertEquals(
            listOf(
                File("C:/app/resources/mythaia-proxy-guard.exe").absolutePath, "--pid", "4242",
                "--snapshot", File("C:/data/Mythaia/system-proxy-before.json").absolutePath,
                "--run", "C:/app/Mythaia Pro.exe", "--restore-proxy"
            ),
            command
        )
    }

    @Test
    fun `a run from Gradle restores through its own JVM and class path`() {
        // No packaged launcher in a test run.
        val restore = ProxyGuard.restoreCommand()!!
        assertEquals(ProxyGuard.RESTORE_ARG, restore.last())
        assertEquals("com.mythaia.desktop.MainKt", restore[restore.size - 2])
        assertEquals("-cp", restore[1])
    }

    @Test
    fun `the crash restore puts back what was there before`() {
        assumeTrue(SystemProxy.isWindows && root != null)
        // The test key, as the user's settings might have been.
        Advapi32Util.registryCreateKey(WinReg.HKEY_CURRENT_USER, key)
        Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, key, "ProxyEnable", 0)
        Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, key, "ProxyServer", "corp.example:3128")
        Advapi32Util.registrySetStringValue(WinReg.HKEY_CURRENT_USER, key, "ProxyOverride", "<local>")

        SystemProxy.enable("127.0.0.1:10809", "localhost;127.*")
        assertEquals(1, Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, key, "ProxyEnable"))
        assertEquals("127.0.0.1:10809", Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, key, "ProxyServer"))
        assertTrue("snapshot written", AppPaths.proxySnapshot.isFile)

        // What the guard starts after the app was killed.
        assertEquals(0, ProxyGuard.restoreAfterCrash())
        assertEquals(0, Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, key, "ProxyEnable"))
        assertEquals("corp.example:3128", Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, key, "ProxyServer"))
        assertEquals("<local>", Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, key, "ProxyOverride"))
        assertFalse("snapshot gone", AppPaths.proxySnapshot.isFile)

        // A second run finds nothing to do.
        assertEquals(0, ProxyGuard.restoreAfterCrash())
    }

    @Test
    fun `the guard outlives a tree kill of the app and runs the restore only while the snapshot is there`() {
        val guard = File("native/out/mythaia-proxy-guard.exe").absoluteFile
        assumeTrue("needs desktop/native/build.cmd", SystemProxy.isWindows && guard.isFile)
        val dir = File("build/tmp/proxy-guard-smoke").absoluteFile.apply { deleteRecursively(); mkdirs() }
        val snapshot = File(dir, "system-proxy-before.json").apply { writeText("{}") }
        val marker = File(dir, "restored")

        // The stand-in app starts the guard itself, so the guard begins as
        // its child, and is killed with its whole tree, as End task does.
        val app = startAppWithGuard(guard, snapshot, marker)
        assertTrue("the guard did not start", waitFor(15_000) { guardsWatching(snapshot) > 0 })
        killTree(app.pid())
        assertTrue("the guard ran the restore", waitFor(10_000) { marker.isFile })
        assertTrue("the guard did not exit", waitFor(5_000) { guardsWatching(snapshot) == 0 })

        // A clean exit deletes the snapshot first: nothing is run then.
        marker.delete()
        snapshot.delete()
        val second = startAppWithGuard(guard, snapshot, marker)
        assertTrue("the guard did not start", waitFor(15_000) { guardsWatching(snapshot) > 0 })
        killTree(second.pid())
        assertTrue("the guard did not exit", waitFor(10_000) { guardsWatching(snapshot) == 0 })
        assertFalse("ran a restore with nothing to restore", marker.isFile)
        dir.deleteRecursively()
    }

    /** A PowerShell that starts the guard for its own pid, then idles. */
    private fun startAppWithGuard(guard: File, snapshot: File, marker: File): Process {
        val script = "& '${guard.absolutePath}' --pid \$PID --snapshot '${snapshot.absolutePath}' " +
            "--run cmd.exe /d /c copy /y NUL '${marker.absolutePath}'; Start-Sleep -Seconds 60"
        return ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectErrorStream(true)
            .start()
    }

    /**
     * Detached guard processes watching [snapshot]: the waiting second copy
     * after the first copy (whose parent is the app) has already exited.
     */
    private fun guardsWatching(snapshot: File): Int {
        val guards = ProcessHandle.allProcesses()
            .filter { p -> p.info().command().orElse("").endsWith("mythaia-proxy-guard.exe") }
            .filter { p -> p.info().commandLine().orElse("").let { it.isEmpty() || it.contains(snapshot.name) } }
            .toList()
        if (guards.any { it.parent().isPresent }) return 0
        return guards.size
    }

    private fun killTree(pid: Long) {
        ProcessBuilder("taskkill.exe", "/T", "/F", "/PID", pid.toString())
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectErrorStream(true)
            .start()
            .waitFor(10, TimeUnit.SECONDS)
    }

    private fun waitFor(millis: Long, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + millis
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(100)
        }
        return condition()
    }

    private fun deleteTree(path: String) {
        if (!Advapi32Util.registryKeyExists(WinReg.HKEY_CURRENT_USER, path)) return
        for (child in Advapi32Util.registryGetKeys(WinReg.HKEY_CURRENT_USER, path)) deleteTree("$path\\$child")
        Advapi32Util.registryDeleteKey(WinReg.HKEY_CURRENT_USER, path)
    }
}
