package com.mythaia

import android.app.Application
import android.system.ErrnoException
import android.util.Log
import com.mythaia.vpn.util.LogBackend
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.TransportErrorLogger

/** Process start: points the shared logger at LogCat before anything logs. */
class MythaiaApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        MythaiaLogger.backend = LogCatBackend
        MythaiaLogger.debugEnabled = BuildConfig.DEBUG
        TransportErrorLogger.errnoReader = { (it as? ErrnoException)?.errno }
    }
}

private object LogCatBackend : LogBackend {
    override fun log(level: MythaiaLogger.Level, category: String, message: String) {
        when (level) {
            MythaiaLogger.Level.info -> Log.i(category, message)
            MythaiaLogger.Level.warning -> Log.w(category, message)
            MythaiaLogger.Level.error -> Log.e(category, message)
        }
    }

    override fun debug(category: String, message: String) {
        Log.d(category, message)
    }
}
