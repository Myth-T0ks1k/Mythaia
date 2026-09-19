package com.mythaia.vpn.protocol.tls

/**
 * Thread-safe cache of the global certificate-validation policy. [TlsClient]
 * consults this at validation time so it observes the latest user preferences
 * without needing to rebuild every [TlsConfiguration].
 *
 * Each platform loads it from its own store: Android from SharedPreferences
 * and the certificate repository (see `CertificatePolicyPrefs.kt` in the
 * app), the desktop app from its settings file.
 */
object CertificatePolicy {

    @Volatile
    private var _allowInsecure: Boolean = false

    @Volatile
    private var _trustedFingerprints: List<String> = emptyList()

    val allowInsecure: Boolean
        get() = _allowInsecure

    /** SHA-256 fingerprints the user has explicitly trusted (lowercase hex). */
    val trustedFingerprints: List<String>
        get() = _trustedFingerprints

    fun setTrustedFingerprints(fingerprints: List<String>) {
        _trustedFingerprints = fingerprints
    }

    /** Pushes the latest allowInsecure value so callers see the change without waiting
     *  for the tunnel to reload. */
    fun setAllowInsecure(value: Boolean) {
        _allowInsecure = value
    }
}
