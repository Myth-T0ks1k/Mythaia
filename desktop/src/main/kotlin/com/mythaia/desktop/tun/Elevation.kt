package com.mythaia.desktop.tun

import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.service.ServiceInstaller
import com.mythaia.vpn.util.MythaiaLogger
import com.sun.jna.Native
import com.sun.jna.platform.win32.Kernel32Util
import com.sun.jna.platform.win32.Shell32
import com.sun.jna.platform.win32.ShellAPI
import com.sun.jna.platform.win32.WinError
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.win32.StdCallLibrary
import java.io.File
import java.lang.management.ManagementFactory

/**
 * Creating a Wintun adapter needs an administrator token. This answers
 * whether the process has one and, if not, starts another copy that does
 * (Windows shows the UAC prompt; the user may decline).
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
        if (!WindowsNet.isWindows) return false
        return runCatching { shell32?.IsUserAnAdmin() ?: false }.getOrDefault(false)
    }

    /**
     * Starts this application again with [args], elevated, through
     * ShellExecuteEx "runas" — the UAC prompt, as `ServiceInstaller` raises
     * it. No PowerShell in between: the path and arguments reach Windows as
     * they are, spaces and non-Latin letters included, and nothing waits on
     * a script host. Blocks while the prompt is up, so not on the UI thread.
     *
     * Returns true once the new process has been launched (the prompt was
     * accepted); the caller decides whether to exit this one. False when the
     * prompt was declined or the launch failed — [lastError] says which.
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
        val error = try {
            shellExecuteRunAs(file, arguments, File(System.getProperty("user.dir")).absolutePath)
        } catch (e: LinkageError) {
            // JNA's native part could not be loaded (blocked in %TEMP%).
            lastError = e.message ?: e.toString()
            logger.error("Cannot reach ShellExecuteEx: $lastError")
            argFile.delete()
            return false
        }
        if (error != 0) {
            lastError = if (error == WinError.ERROR_CANCELLED) {
                logger.info("The administrator prompt was declined")
                systemMessage(error) ?: "The administrator prompt was declined"
            } else {
                logger.warning("Elevated relaunch did not start (error $error)")
                systemMessage(error)?.let { "error $error: $it" } ?: "error $error"
            }
            // Nobody will read it now; a launched instance reads its own at startup.
            argFile.delete()
            return false
        }
        logger.info("Elevated instance launched: $file ${arguments.joinToString(" ")}")
        return true
    }

    /**
     * ShellExecuteEx with the "runas" verb, shown normally, started in
     * [directory]. Returns 0 once the process exists, else the Win32 error
     * (ERROR_CANCELLED when the prompt was declined). SEE_MASK_NOASYNC makes
     * the call return only after the launch has finished either way.
     */
    private fun shellExecuteRunAs(file: String, arguments: List<String>, directory: String): Int {
        val info = ShellAPI.SHELLEXECUTEINFO().apply {
            cbSize = size()
            fMask = SEE_MASK_NOASYNC
            lpVerb = "runas"
            lpFile = file
            lpParameters = commandLine(arguments)
            lpDirectory = directory
            nShow = WinUser.SW_SHOWNORMAL
        }
        if (Shell32.INSTANCE.ShellExecuteEx(info)) return 0
        return Native.getLastError().takeIf { it != 0 } ?: WinError.ERROR_GEN_FAILURE
    }

    /**
     * [arguments] as one Windows command line, each quoted the way
     * CommandLineToArgvW (and the launcher) reads it back.
     */
    internal fun commandLine(arguments: List<String>): String =
        arguments.joinToString(" ") { ServiceInstaller.commandLineArg(it) }

    /** The system's own text for [error], in the language of this Windows. */
    private fun systemMessage(error: Int): String? =
        runCatching { Kernel32Util.formatMessage(error).trim() }.getOrNull()?.takeIf { it.isNotEmpty() }

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
    private const val SEE_MASK_NOASYNC = 0x100

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

    /** Java `@argfile` token: double-quoted with backslashes doubled. */
    internal fun argQuote(text: String): String = "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
}
