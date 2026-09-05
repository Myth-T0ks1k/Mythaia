package com.mythaia.vpn.protocol.tls

import androidx.core.content.edit
import android.content.Context
import android.content.SharedPreferences
import com.mythaia.data.model.FragmentSettings

/**
 * Thread-safe cache of the global ClientHello-fragmentation setting.
 * [TlsClient] consults this at dial time so it observes the latest user
 * preferences without needing to rebuild every [TlsConfiguration].
 *
 * The same shape as [CertificatePolicy], and reloaded from the same places.
 */
object FragmentPolicy {

    const val KEY_ENABLED = "fragmentEnabled"
    const val KEY_MIN_LENGTH = "fragmentMinLength"
    const val KEY_MAX_LENGTH = "fragmentMaxLength"
    const val KEY_MIN_INTERVAL = "fragmentMinInterval"
    const val KEY_MAX_INTERVAL = "fragmentMaxInterval"

    @Volatile
    private var _settings: FragmentSettings = FragmentSettings()

    /** The tunnel-wide default, used by any server whose link carried no `fragment=`. */
    val settings: FragmentSettings
        get() = _settings

    fun reload(context: Context) {
        val prefs: SharedPreferences =
            context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        _settings = read(prefs)
    }

    /** Pushes a new value so callers see the change without waiting for a tunnel reload. */
    fun set(settings: FragmentSettings) {
        _settings = settings
    }

    /** Reads the stored value, falling back to the defaults for anything unset. */
    fun read(prefs: SharedPreferences): FragmentSettings = FragmentSettings(
        isEnabled = prefs.getBoolean(KEY_ENABLED, true),
        minLength = prefs.getInt(KEY_MIN_LENGTH, FragmentSettings.DEFAULT_MIN_LENGTH),
        maxLength = prefs.getInt(KEY_MAX_LENGTH, FragmentSettings.DEFAULT_MAX_LENGTH),
        minInterval = prefs.getInt(KEY_MIN_INTERVAL, FragmentSettings.DEFAULT_MIN_INTERVAL),
        maxInterval = prefs.getInt(KEY_MAX_INTERVAL, FragmentSettings.DEFAULT_MAX_INTERVAL)
    )

    /** Persists [settings] and publishes it to the running tunnel. */
    fun write(prefs: SharedPreferences, settings: FragmentSettings) {
        prefs.edit {
            putBoolean(KEY_ENABLED, settings.isEnabled)
            putInt(KEY_MIN_LENGTH, settings.minLength)
            putInt(KEY_MAX_LENGTH, settings.maxLength)
            putInt(KEY_MIN_INTERVAL, settings.minInterval)
            putInt(KEY_MAX_INTERVAL, settings.maxInterval)
        }
        set(settings)
    }
}
