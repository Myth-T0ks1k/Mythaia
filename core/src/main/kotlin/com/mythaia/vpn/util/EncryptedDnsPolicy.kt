package com.mythaia.vpn.util

/**
 * Thread-safe cache of the encrypted-DNS setting, consulted by [DnsCache] on
 * every miss.
 *
 * The same shape as [com.mythaia.vpn.protocol.tls.CertificatePolicy]. Each
 * platform loads it from its own store (Android: `EncryptedDnsPolicyPrefs.kt`
 * in the app).
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

    /** Pushes a new value so callers see the change without a tunnel reload. */
    fun set(upstream: DnsUpstream) {
        _upstream = upstream
    }

    /** Builds the upstream from the three stored fields; [DnsUpstream.System] when off or unparsable. */
    fun from(enabled: Boolean, protocol: String?, server: String?): DnsUpstream {
        if (!enabled) return DnsUpstream.System
        return DnsUpstream.from(protocol ?: "doh", server ?: "") ?: DnsUpstream.System
    }
}
