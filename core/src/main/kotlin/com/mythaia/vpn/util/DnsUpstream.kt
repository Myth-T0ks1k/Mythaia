package com.mythaia.vpn.util

/** Where a DNS question is sent. */
sealed class DnsUpstream {

    /** Whatever the platform resolver would do. */
    object System : DnsUpstream()

    /** Plain UDP DNS (RFC 1035) at [server]:[port]. */
    data class Plain(val server: String, val port: Int = 53) : DnsUpstream()

    /** DNS over HTTPS (RFC 8484). [url] is the full query endpoint. */
    data class Doh(val url: String) : DnsUpstream()

    /** DNS over TLS (RFC 7858) at [server]:[port]. */
    data class Dot(val server: String, val port: Int = 853) : DnsUpstream()

    /** Short label for logs. */
    val text: String
        get() = when (this) {
            is System -> "system"
            is Plain -> "udp://$server:$port"
            is Doh -> url
            is Dot -> "tls://$server:$port"
        }

    /**
     * The hostname this upstream itself has to reach, or null when it is
     * already an address.
     *
     * Resolving a name through an upstream that is itself named by that name
     * would recurse, so callers exclude it.
     */
    val bootstrapHost: String?
        get() = when (this) {
            is System -> null
            is Plain -> server.takeUnless { DnsCache.isIpAddress(it) }
            is Dot -> server.takeUnless { DnsCache.isIpAddress(it) }
            is Doh -> runCatching { java.net.URI(url).host }.getOrNull()
                ?.takeUnless { DnsCache.isIpAddress(it) }
        }

    companion object {

        /**
         * Builds an upstream from the stored settings.
         *
         * [server] is what the user typed on the Encrypted DNS screen: a URL
         * for DoH, a hostname or address (optionally `host:port`) for DoT.
         * Returns null when the field is empty or unusable, which the caller
         * treats as "fall back to the system resolver".
         */
        fun from(protocol: String, server: String): DnsUpstream? {
            val trimmed = server.trim()
            if (trimmed.isEmpty()) return null

            return when (protocol) {
                "doh" -> {
                    val url = if (trimmed.startsWith("https://")) trimmed else "https://$trimmed"
                    // A DoH endpoint with no path is almost always a typo for
                    // the well-known one rather than a server rooted at /.
                    val normalised = runCatching { java.net.URI(url) }.getOrNull()?.let {
                        if (it.path.isNullOrEmpty() || it.path == "/") "${url.trimEnd('/')}/dns-query"
                        else url
                    } ?: return null
                    Doh(normalised)
                }
                "dot" -> {
                    val withoutScheme = trimmed.removePrefix("tls://")
                    val (host, port) = splitHostPort(withoutScheme, defaultPort = 853)
                        ?: return null
                    Dot(host, port)
                }
                else -> null
            }
        }

        /**
         * Splits `host`, `host:port`, `[v6]` or `[v6]:port`. A bare IPv6
         * literal has colons of its own, so it is only read as host:port when
         * bracketed.
         */
        private fun splitHostPort(text: String, defaultPort: Int): Pair<String, Int>? {
            if (text.startsWith("[")) {
                val close = text.indexOf(']')
                if (close < 0) return null
                val host = text.substring(1, close)
                if (host.isEmpty()) return null
                val rest = text.substring(close + 1)
                if (rest.isEmpty()) return host to defaultPort
                if (!rest.startsWith(":")) return null
                val port = rest.substring(1).toIntOrNull() ?: return null
                return if (port in 1..65535) host to port else null
            }

            val colon = text.lastIndexOf(':')
            // More than one colon and no brackets: a bare IPv6 literal.
            if (colon < 0 || text.indexOf(':') != colon) {
                return text.takeIf { it.isNotEmpty() }?.let { it to defaultPort }
            }
            val host = text.substring(0, colon)
            val port = text.substring(colon + 1).toIntOrNull() ?: return null
            if (host.isEmpty() || port !in 1..65535) return null
            return host to port
        }
    }
}
