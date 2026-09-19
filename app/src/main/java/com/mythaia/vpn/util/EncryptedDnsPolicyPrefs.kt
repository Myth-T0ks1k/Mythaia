package com.mythaia.vpn.util

import android.content.Context
import android.content.SharedPreferences

/** Loads the encrypted-DNS setting from the app's SharedPreferences. */
fun EncryptedDnsPolicy.reload(context: Context) {
    val prefs: SharedPreferences =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    set(read(prefs))
}

fun EncryptedDnsPolicy.read(prefs: SharedPreferences): DnsUpstream = from(
    enabled = prefs.getBoolean("encryptedDnsEnabled", false),
    protocol = prefs.getString("encryptedDnsProtocol", "doh"),
    server = prefs.getString("encryptedDnsServer", "")
)
