package com.mythaia.vpn.util

import android.util.Log
import com.mythaia.BuildConfig

/**
 * Unified logger for the Mythaia app.
 *
 * `info`, `warning`, and `error` write to LogCat and optionally to a log
 * sink (user-facing log viewer wired by the VPN service).
 * `debug` writes to LogCat only and is stripped in Release builds, mirroring
 * iOS's `#if DEBUG` gate in MythaiaLogger.swift.
 */
class MythaiaLogger(private val category: String) {

    enum class Level { info, warning, error }

    fun info(message: String) {
        Log.i(category, message)
        logSink?.invoke(message, Level.info)
    }

    fun warning(message: String) {
        Log.w(category, message)
        logSink?.invoke(message, Level.warning)
    }

    fun error(message: String) {
        Log.e(category, message)
        logSink?.invoke(message, Level.error)
    }

    fun debug(message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(category, message)
        }
    }

    companion object {
        @Volatile
        var logSink: ((String, Level) -> Unit)? = null
    }
}
