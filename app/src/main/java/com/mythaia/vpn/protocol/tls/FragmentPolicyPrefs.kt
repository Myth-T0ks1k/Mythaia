package com.mythaia.vpn.protocol.tls

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.mythaia.data.model.FragmentSettings

/** Loads the fragmentation setting from the app's SharedPreferences. */
fun FragmentPolicy.reload(context: Context) {
    val prefs: SharedPreferences =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    set(read(prefs))
}

/** Reads the stored value, falling back to the defaults for anything unset. */
fun FragmentPolicy.read(prefs: SharedPreferences): FragmentSettings = FragmentSettings(
    isEnabled = prefs.getBoolean(FragmentPolicy.KEY_ENABLED, true),
    minLength = prefs.getInt(FragmentPolicy.KEY_MIN_LENGTH, FragmentSettings.DEFAULT_MIN_LENGTH),
    maxLength = prefs.getInt(FragmentPolicy.KEY_MAX_LENGTH, FragmentSettings.DEFAULT_MAX_LENGTH),
    minInterval = prefs.getInt(FragmentPolicy.KEY_MIN_INTERVAL, FragmentSettings.DEFAULT_MIN_INTERVAL),
    maxInterval = prefs.getInt(FragmentPolicy.KEY_MAX_INTERVAL, FragmentSettings.DEFAULT_MAX_INTERVAL)
)

/** Persists [settings] and publishes it to the running tunnel. */
fun FragmentPolicy.write(prefs: SharedPreferences, settings: FragmentSettings) {
    prefs.edit {
        putBoolean(FragmentPolicy.KEY_ENABLED, settings.isEnabled)
        putInt(FragmentPolicy.KEY_MIN_LENGTH, settings.minLength)
        putInt(FragmentPolicy.KEY_MAX_LENGTH, settings.maxLength)
        putInt(FragmentPolicy.KEY_MIN_INTERVAL, settings.minInterval)
        putInt(FragmentPolicy.KEY_MAX_INTERVAL, settings.maxInterval)
    }
    set(settings)
}
