package com.mythaia.vpn.protocol.tls

import com.mythaia.data.model.FragmentSettings

/**
 * Thread-safe cache of the global ClientHello-fragmentation setting.
 * [TlsClient] consults this at dial time so it observes the latest user
 * preferences without needing to rebuild every [TlsConfiguration].
 *
 * The same shape as [CertificatePolicy]. Each platform loads it from its own
 * store: Android from SharedPreferences (see `FragmentPolicyPrefs.kt` in the
 * app), the desktop app from its settings file.
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

    /** Pushes a new value so callers see the change without waiting for a tunnel reload. */
    fun set(settings: FragmentSettings) {
        _settings = settings
    }
}
