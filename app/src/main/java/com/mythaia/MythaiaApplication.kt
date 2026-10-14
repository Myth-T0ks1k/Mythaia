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
        // Start reading the server store now, off the main thread: with a bulk
        // list it takes seconds, and the activity would otherwise wait for it
        // from scratch. ConfigRepository.get is synchronized, so the screen
        // takes the same instance, finished or nearly so.
        Thread({ com.mythaia.data.repository.ConfigRepository.get(this) }, "config-preload").start()
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
