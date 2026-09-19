package com.mythaia.vpn.protocol.tls

import android.content.Context
import android.content.SharedPreferences
import com.mythaia.data.repository.CertificateRepository

/** Loads the certificate policy from the app's SharedPreferences and certificate store. */
fun CertificatePolicy.reload(context: Context) {
    val prefs: SharedPreferences =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    setAllowInsecure(prefs.getBoolean("allowInsecure", false))
    setTrustedFingerprints(CertificateRepository(context).fingerprints.value)
}
