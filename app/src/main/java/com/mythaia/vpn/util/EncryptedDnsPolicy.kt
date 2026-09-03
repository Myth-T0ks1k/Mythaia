package com.mythaia.vpn.util

import android.content.Context
import android.content.SharedPreferences

/**
 * Thread-safe cache of the encrypted-DNS setting, consulted by [DnsCache] on
 * every miss.
 *
 * The same shape as [com.mythaia.vpn.protocol.tls.CertificatePolicy], and
 * reloaded from the same places.
 */
object EncryptedDnsPolicy {

    @Volatile
    private var _upstream: DnsUpstream = DnsUpstream.System

    /**
     * Where lookups go. [DnsUpstream.System] whenever the feature is off, the
     * server field is empty, or what the user typed does not parse — in every
     * one of those cases the platform resolver is the right answer, not a
     * failure.
     */
    val upstream: DnsUpstream
        get() = _upstream

    val isEnabled: Boolean
        get() = _upstream !is DnsUpstream.System

    fun reload(context: Context) {
        val prefs: SharedPreferences =
            context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        _upstream = read(prefs)
    }

    /** Pushes a new value so callers see the change without a tunnel reload. */
    fun set(upstream: DnsUpstream) {
        _upstream = upstream
    }

    fun read(prefs: SharedPreferences): DnsUpstream {
        if (!prefs.getBoolean("encryptedDnsEnabled", false)) return DnsUpstream.System
        val protocol = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        val server = prefs.getString("encryptedDnsServer", "") ?: ""
        return DnsUpstream.from(protocol, server) ?: DnsUpstream.System
    }
}
