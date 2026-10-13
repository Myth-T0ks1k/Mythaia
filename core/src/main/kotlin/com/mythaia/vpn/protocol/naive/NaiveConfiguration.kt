package com.mythaia.vpn.protocol.naive


class NaiveConfiguration(
    val proxyHost: String,
    val proxyPort: Int,
    val username: String?,
    val password: String?,
    /** TLS SNI override. Defaults to [proxyHost] when null. */
    val sni: String?,
    val scheme: NaiveScheme,
    /**
     * The server's TLS settings: "allow insecure", the pinned certificate,
     * the name to verify. Null means the defaults (full verification).
     */
    val tls: com.mythaia.data.model.TlsConfiguration? = null
) {
    enum class NaiveScheme {
        HTTP11,
        HTTP2
    }

    val effectiveSNI: String get() = sni ?: proxyHost

    /** What decides whether two Naive streams may share a connection. */
    val poolKey: String
        get() = "$proxyHost:$proxyPort:$effectiveSNI:" + (tls?.let {
            kotlinx.serialization.json.Json.encodeToString(com.mythaia.data.model.TlsConfiguration.serializer(), it)
        } ?: "")

    /** Base64-encoded `user:pass` for Proxy-Authorization, or null if no credentials. */
    val basicAuth: String?
        get() {
            if (username == null || password == null) return null
            return java.util.Base64.getEncoder().encodeToString("$username:$password".toByteArray())
        }
}
