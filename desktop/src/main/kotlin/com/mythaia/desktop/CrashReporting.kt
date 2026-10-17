package com.mythaia.desktop

import com.mythaia.vpn.util.MythaiaLogger
import java.io.File

/**
 * What a user can send when the app went away on its own.
 *
 * An exception nothing caught goes to the log with its stack; before this it
 * went to a console a packaged app does not have. A crash in native code
 * (the JNI library, JNA, Skia) takes the whole JVM down at once, and the only
 * trace is the `hs_err_pid*.log` the JVM writes to its working directory or,
 * failing that, to %TEMP% — where nobody looks. The next start copies those
 * into the log folder and writes the line that names the culprit to the log.
 */
object CrashReporting {
    private val logger = MythaiaLogger("Crash")

    /** How many native crash reports the log folder keeps. */
    private const val KEEP_REPORTS = 5

    /**
     * Logs uncaught exceptions from now on and collects the reports of
     * native crashes since the last start. True when one of them happened in
     * the graphics stack (Skia or a GPU driver).
     */
    fun install(): Boolean {
        Thread.setDefaultUncaughtExceptionHandler { thread, error -> logUncaught("thread ${thread.name}", error) }
        return try {
            collectNativeCrashReports()
        } catch (e: Exception) {
            logger.warning("Could not look for native crash reports: ${e.message}")
            false
        }
    }

    fun logUncaught(where: String, error: Throwable) {
        try {
            logger.error("Uncaught in $where: ${error.stackTraceToString().take(16_000)}")
        } catch (_: Throwable) {
            // Out of memory, most likely; there is nothing left to report with.
        }
    }

    private fun collectNativeCrashReports(): Boolean {
        val places = listOfNotNull(
            // -XX:ErrorFile in build.gradle.kts points here; the JVM falls back
            // to the working directory and then %TEMP% where it cannot write.
            AppPaths.resourcesDir?.parent,
            System.getProperty("user.dir"),
            AppPaths.launcherExe()?.parent,
            System.getProperty("java.io.tmpdir"),
            System.getenv("TEMP"),
            System.getenv("TMP")
        ).map { File(it).absoluteFile }.distinct()
        val reports = places.flatMap { dir ->
            dir.listFiles { f -> f.isFile && f.name.startsWith("hs_err_pid") && f.name.endsWith(".log") }?.toList().orEmpty()
        }.filter { isOurs(it) }.sortedBy { it.lastModified() }

        val logDir = AppPaths.logDir
        var graphics = false
        for (report in reports) {
            val copy = File(logDir, report.name)
            if (runCatching { report.copyTo(copy, overwrite = true) }.isFailure) continue
            val summary = summary(report)
            logger.error("The previous run crashed in native code: $summary (report: ${copy.name})")
            if (GRAPHICS_MODULES.containsMatchIn(summary)) graphics = true
            runCatching { report.delete() }
        }
        logDir.listFiles { f -> f.name.startsWith("hs_err_pid") }
            ?.sortedByDescending { it.lastModified() }
            ?.drop(KEEP_REPORTS)
            ?.forEach { runCatching { it.delete() } }
        return graphics
    }

    /**
     * Skia and the GPU drivers it calls into: Direct3D, DXGI, OpenGL, and the
     * NVIDIA, Intel and AMD user-mode drivers, by the names their DLLs carry.
     */
    private val GRAPHICS_MODULES = Regex(
        """\[(skiko|d3d|dxgi|opengl32|nvwgf|nvd3d|nvogl|nvldumd|igd|ig\d+icd|igxelp|amdxx|atidxx|atio6|atiu)[^\]]*\.dll""",
        RegexOption.IGNORE_CASE
    )

    /** Another Java program's report stays where it is. */
    private fun isOurs(report: File): Boolean = runCatching {
        report.bufferedReader().useLines { lines -> lines.take(4000).any { "com.mythaia.desktop" in it } }
    }.getOrDefault(false)

    /** The exception, the frame it happened in, and the thread. */
    private fun summary(report: File): String = runCatching {
        val lines = report.readLines().take(400)
        val parts = mutableListOf<String>()
        lines.firstOrNull { it.startsWith("#  EXCEPTION_") || it.startsWith("#  Internal Error") || it.contains("OutOfMemoryError") }
            ?.let { parts += it.removePrefix("#").trim() }
        val frame = lines.indexOfFirst { it.startsWith("# Problematic frame:") }
        if (frame >= 0 && frame + 1 < lines.size) parts += lines[frame + 1].removePrefix("#").trim()
        lines.firstOrNull { it.startsWith("Current thread") }?.let { parts += it.trim() }
        parts.joinToString(" | ").ifEmpty { "no summary" }
    }.getOrDefault("unreadable report")
}
