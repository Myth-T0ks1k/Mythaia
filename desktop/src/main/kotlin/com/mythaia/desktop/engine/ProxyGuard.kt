package com.mythaia.desktop.engine

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.util.MythaiaLogger
import java.io.File
import java.io.RandomAccessFile

/**
 * Gets the system proxy put back when the app dies without doing it.
 *
 * Proxy mode points every program on the PC at the app's local listener.
 * Ended from Task Manager or killed by a crash, the app never restores the
 * old settings, and the whole PC was offline until the app was started
 * again. Two things now cover that, neither needing administrator rights:
 *
 * - `mythaia-proxy-guard.exe` (desktop/native/proxy_guard.c), started once
 *   per run, waits on the app's process handle and, when the app is gone
 *   while [AppPaths.proxySnapshot] is still on disk, runs the app with
 *   [RESTORE_ARG]. It detaches from the app's process tree first, so "End
 *   task" does not take it along.
 * - A `RunOnce` entry, written while the proxy is set, runs the same
 *   restore at the next sign-in, for a power cut or a blue screen, where the
 *   guard dies too.
 *
 * Considered and not taken: a scheduled task (needs administrator rights
 * for most triggers), a second JVM as the watcher (tens of megabytes for
 * the whole session, a second "Mythaia Pro" in Task Manager), the service
 * (installed only by those who use TUN, and it runs as SYSTEM, not as the
 * user whose registry holds the proxy).
 */
object ProxyGuard {
    const val RESTORE_ARG = "--restore-proxy"
    private const val GUARD_EXE = "mythaia-proxy-guard.exe"
    private val logger = MythaiaLogger("ProxyGuard")

    /** The guard executable this run would start, or null. */
    fun guardExe(): File? {
        val cwd = File(System.getProperty("user.dir"))
        val candidates = buildList {
            System.getProperty("mythaia.proxy.guard")?.let { add(File(it)) }
            AppPaths.resourcesDir?.let { add(File(it, GUARD_EXE)) }
            add(File(cwd, "desktop/resources/windows-x64/$GUARD_EXE"))
            add(File(cwd, "resources/windows-x64/$GUARD_EXE"))
            add(File(cwd, "desktop/native/out/$GUARD_EXE"))
        }
        return candidates.firstOrNull { it.isFile }
    }

    /**
     * What the guard runs after a crash: the installed launcher, or, in a
     * run from Gradle, this same JVM and class path.
     */
    fun restoreCommand(): List<String>? {
        AppPaths.launcherExe()?.let { return listOf(it.absolutePath, RESTORE_ARG) }
        val java = ProcessHandle.current().info().command().orElse(null) ?: return null
        val classPath = System.getProperty("java.class.path")?.takeIf { it.isNotBlank() } ?: return null
        return listOf(java, "-cp", classPath, "com.mythaia.desktop.MainKt", RESTORE_ARG)
    }

    /** The guard's command line for watching process [pid]. */
    internal fun guardCommand(guard: File, pid: Long, snapshot: File, restore: List<String>): List<String> =
        listOf(guard.absolutePath, "--pid", pid.toString(), "--snapshot", snapshot.absolutePath, "--run") + restore

    /** Starts the guard for this process; once per run, from the window's instance. */
    fun start() {
        if (!SystemProxy.isWindows) return
        val guard = guardExe() ?: run {
            logger.warning("$GUARD_EXE not found: a killed app would leave the system proxy set")
            return
        }
        val restore = restoreCommand() ?: run {
            logger.warning("No way to run the restore after a crash; the proxy guard is off")
            return
        }
        val command = guardCommand(guard, ProcessHandle.current().pid(), AppPaths.proxySnapshot, restore)
        try {
            // The first copy only hands over to a detached second one and exits.
            ProcessBuilder(command)
                .redirectInput(ProcessBuilder.Redirect.from(File("NUL")))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .start()
            logger.info("Proxy guard started")
        } catch (e: Exception) {
            logger.warning("Proxy guard did not start: ${e.message}")
        }
    }

    /**
     * [RESTORE_ARG]: puts back the proxy a dead run left set, unless an app
     * instance is running again, which then owns the proxy (and restored any
     * leftover itself on start). Returns the exit code.
     */
    fun restoreAfterCrash(): Int {
        if (!AppPaths.proxySnapshot.isFile) {
            logger.info("Nothing to restore: no system proxy snapshot")
            SystemProxy.disarmRestoreAtSignIn()
            return 0
        }
        if (instanceRunning()) {
            logger.info("Mythaia Pro is running again; it looks after the system proxy itself")
            return 0
        }
        logger.warning("The last run ended without restoring the system proxy; restoring it now")
        SystemProxy.restoreIfLeftOver { !instanceRunning() }
        return 0
    }

    /**
     * Whether another instance holds the single-instance lock. The lock is
     * taken and let go at once; the window's start waits a moment for it, so
     * this probe cannot turn a starting app away.
     */
    private fun instanceRunning(): Boolean = try {
        RandomAccessFile(AppPaths.instanceLock, "rw").channel.use { channel ->
            val lock = channel.tryLock()
            lock?.release()
            lock == null
        }
    } catch (e: Exception) {
        // Cannot tell: leave the proxy to whoever has it.
        logger.warning("Cannot check for a running instance: ${e.message}")
        true
    }
}
