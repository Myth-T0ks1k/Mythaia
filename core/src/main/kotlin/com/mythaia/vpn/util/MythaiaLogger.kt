package com.mythaia.vpn.util

/**
 * Where log lines go. Android installs a LogCat writer at start; the desktop
 * app installs a file writer. Until one is installed lines go to stderr.
 */
interface LogBackend {
    fun log(level: MythaiaLogger.Level, category: String, message: String)
    fun debug(category: String, message: String)
}

/** The fallback backend: stderr, one line per entry. */
object ConsoleLogBackend : LogBackend {
    override fun log(level: MythaiaLogger.Level, category: String, message: String) {
        System.err.println("[${level.name.uppercase()}] $category: $message")
    }

    override fun debug(category: String, message: String) {
        System.err.println("[DEBUG] $category: $message")
    }
}

/**
 * Unified logger for Mythaia.
 *
 * `info`, `warning`, and `error` write to the platform log and optionally to a
 * log sink (the user-facing log viewer). `debug` writes to the platform log
 * only, and only when [debugEnabled] — the Android app sets that from
 * `BuildConfig.DEBUG`, mirroring iOS's `#if DEBUG` gate.
 */
class MythaiaLogger(private val category: String) {

    enum class Level { info, warning, error }

    fun info(message: String) {
        backend.log(Level.info, category, message)
        logSink?.invoke(message, Level.info)
    }

    fun warning(message: String) {
        backend.log(Level.warning, category, message)
        logSink?.invoke(message, Level.warning)
    }

    fun error(message: String) {
        backend.log(Level.error, category, message)
        logSink?.invoke(message, Level.error)
    }

    fun debug(message: String) {
        if (debugEnabled) {
            backend.debug(category, message)
        }
    }

    companion object {
        @Volatile
        var logSink: ((String, Level) -> Unit)? = null

        /** The platform writer. Replaced once at process start. */
        @Volatile
        var backend: LogBackend = ConsoleLogBackend

        /** Whether `debug` lines are written at all. */
        @Volatile
        var debugEnabled: Boolean = false
    }
}
