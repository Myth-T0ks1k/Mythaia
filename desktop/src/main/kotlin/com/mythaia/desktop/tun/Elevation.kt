package com.mythaia.desktop.tun

import com.mythaia.desktop.AppPaths
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Native
import com.sun.jna.win32.StdCallLibrary
import java.io.File
import java.lang.management.ManagementFactory

/**
 * Creating a Wintun adapter needs an administrator token. This answers
 * whether the process has one and, if not, starts another copy that does
 * (Windows shows the UAC prompt; the user may decline). On macOS the
 * question is whether the process runs as root; there is no relaunch there,
 * TUN mode goes through the service daemon instead.
 */
object Elevation {
    private val logger = MythaiaLogger("Elevation")

    @Suppress("FunctionName")
    private interface Shell32Ex : StdCallLibrary {
        fun IsUserAnAdmin(): Boolean
    }

    private val shell32: Shell32Ex? by lazy {
        runCatching { Native.load("shell32", Shell32Ex::class.java) }.getOrNull()
    }

    /** True when this process runs elevated (or as the built-in Administrator). */
    fun isElevated(): Boolean {
        if (com.mythaia.desktop.Platform.isMac) return MacUtun.isRoot()
        if (!WindowsNet.isWindows) return false
        return runCatching { shell32?.IsUserAnAdmin() ?: false }.getOrDefault(false)
    }

    /**
     * Starts this application again with [args], elevated, through
     * `Start-Process -Verb RunAs`. Returns true once the new process has
     * been launched (the UAC prompt was accepted); the caller decides
     * whether to exit this one. False when the prompt was declined or the
     * launch failed — [lastError] says which.
     */
    fun relaunchElevated(args: List<String> = listOf("--tun")): Boolean {
        lastError = null
        val (file, arguments) = try {
            launchCommand(args)
        } catch (e: Exception) {
            lastError = e.message ?: e.toString()
            logger.error("Cannot build the relaunch command: $lastError")
            return false
        }
        val script = buildString {
            append("Start-Process -FilePath ").append(psQuote(file))
            if (arguments.isNotEmpty()) {
                append(" -ArgumentList @(").append(arguments.joinToString(",") { psQuote(it) }).append(")")
            }
            append(" -WorkingDirectory ").append(psQuote(File(System.getProperty("user.dir")).absolutePath))
            append(" -Verb RunAs")
        }
        val result = WindowsNet.run(
            listOf("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script),
            timeoutSec = 120
        )
        if (!result.ok) {
            lastError = result.output.lineSequence().firstOrNull { it.isNotBlank() } ?: "exit ${result.exitCode}"
            logger.warning("Elevated relaunch did not start: $lastError")
            // Nobody will read it now; a launched instance reads its own at startup.
            argFile.delete()
            return false
        }
        logger.info("Elevated instance launched: $file ${arguments.joinToString(" ")}")
        return true
    }

    @Volatile
    var lastError: String? = null
        private set

    /**
     * Removes the argfile a relaunch left behind — the launching instance
     * exits as soon as the elevated one is up, so it cannot. Called at every
     * startup; a file younger than a minute may be the one a launch in
     * progress is about to read, and is left for the next time.
     */
    fun cleanupArgFile() {
        val file = argFile
        if (file.isFile && System.currentTimeMillis() - file.lastModified() > ARG_FILE_MAX_AGE_MS) file.delete()
    }

    private val argFile: File get() = File(AppPaths.dataDir, "relaunch.args")
    private const val ARG_FILE_MAX_AGE_MS = 60_000L

    /**
     * The executable and its arguments: the installed launcher when there
     * is one, else the running JVM with the same options, class path and
     * main class — those go through an `@argfile`, since a Gradle class
     * path does not fit on a command line.
     */
    internal fun launchCommand(args: List<String>): Pair<String, List<String>> {
        AppPaths.launcherExe()?.let { return it.absolutePath to args }

        val javaHome = System.getProperty("java.home") ?: throw IllegalStateException("java.home unset")
        val java = listOf("javaw.exe", "java.exe").map { File(javaHome, "bin/$it") }.firstOrNull { it.isFile }
            ?: throw IllegalStateException("no java launcher under $javaHome")
        val mainCommand = System.getProperty("sun.java.command") ?: throw IllegalStateException("sun.java.command unset")
        val mainClass = mainCommand.split(' ').first()
        val jvmArgs = ManagementFactory.getRuntimeMXBean().inputArguments
        val classPath = System.getProperty("java.class.path").orEmpty()

        val lines = ArrayList<String>()
        jvmArgs.forEach { lines += argQuote(it) }
        lines += "-cp"
        lines += argQuote(classPath)
        lines += mainClass
        args.forEach { lines += argQuote(it) }
        argFile.writeText(lines.joinToString("\n"))
        return java.absolutePath to listOf("@" + argFile.absolutePath)
    }

    /** PowerShell single-quoted literal. */
    internal fun psQuote(text: String): String = "'" + text.replace("'", "''") + "'"

    /** Java `@argfile` token: double-quoted with backslashes doubled. */
    internal fun argQuote(text: String): String = "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
