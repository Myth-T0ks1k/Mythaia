package com.mythaia.data.model

/**
 * The `wg-quick` INI a WireGuard profile is stored as, written from the fields
 * a share link or a JSON outbound spreads the same settings over.
 *
 * Every importer goes through here instead of filling a [ProxyConfiguration]
 * itself: a server from a `wireguard://` link, an Xray outbound or a sing-box
 * endpoint becomes exactly the text a user could have pasted, is validated by
 * the one INI parser, and exports back as an INI like any other.
 */
internal object WireGuardIni {

    class Peer(
        val publicKey: String,
        val endpointHost: String,
        val endpointPort: Int,
        val presharedKey: String? = null,
        val allowedIps: List<String> = emptyList(),
        val keepalive: Int = 0
    )

    fun build(
        privateKey: String,
        addresses: List<String>,
        peer: Peer,
        mtu: Int? = null,
        reserved: ByteArray? = null,
        dns: List<String> = emptyList()
    ): String {
        val lines = ArrayList<String>()
        lines += "[Interface]"
        lines += "PrivateKey = ${normalizeKey(privateKey)}"
        val cleanAddresses = addresses.map { it.trim() }.filter { it.isNotEmpty() }.map(::withPrefix)
        if (cleanAddresses.isNotEmpty()) lines += "Address = ${cleanAddresses.joinToString(", ")}"
        val cleanDns = dns.map { it.trim() }.filter { it.isNotEmpty() }
        if (cleanDns.isNotEmpty()) lines += "DNS = ${cleanDns.joinToString(", ")}"
        if (mtu != null && mtu > 0) lines += "MTU = $mtu"
        // All zeroes is what Xray writes when there is nothing to say.
        if (reserved != null && reserved.size == 3 && reserved.any { it != 0.toByte() }) {
            lines += "Reserved = ${reserved.joinToString(",") { (it.toInt() and 0xFF).toString() }}"
        }
        lines += ""
        lines += "[Peer]"
        lines += "PublicKey = ${normalizeKey(peer.publicKey)}"
        peer.presharedKey?.takeIf { it.isNotBlank() }?.let { lines += "PresharedKey = ${normalizeKey(it)}" }
        val allowed = peer.allowedIps.map { it.trim() }.filter { it.isNotEmpty() }
            .ifEmpty { listOf("0.0.0.0/0", "::/0") }
        lines += "AllowedIPs = ${allowed.joinToString(", ")}"
        lines += "Endpoint = ${endpoint(peer.endpointHost, peer.endpointPort)}"
        if (peer.keepalive > 0) lines += "PersistentKeepalive = ${peer.keepalive}"
        return lines.joinToString("\n") + "\n"
    }

    /**
     * A key as the INI parser takes it: standard, padded base64.
     *
     * Links carry keys in whatever shape survived the trip — the URL-safe
     * alphabet, padding stripped, or hex as Xray also accepts — and each of
     * those is the same 32 bytes. Anything else is passed through untouched,
     * so the parser's refusal names the key that was actually there.
     */
    fun normalizeKey(text: String): String {
        val trimmed = text.trim()
        if (trimmed.length == 64 && trimmed.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            val bytes = ByteArray(32) { trimmed.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            return java.util.Base64.getEncoder().encodeToString(bytes)
        }
        val standard = trimmed.replace('-', '+').replace('_', '/')
        return standard.padEnd((standard.length + 3) / 4 * 4, '=')
    }

    /** `10.0.0.2` as `10.0.0.2/32`: the INI wants a prefix, JSON outbounds often omit it. */
    private fun withPrefix(address: String): String = when {
        address.contains('/') -> address
        address.contains(':') -> "${address.removePrefix("[").removeSuffix("]")}/128"
        else -> "$address/32"
    }

    /** `host:port`, an IPv6 literal bracketed as the INI's Endpoint requires. */
    fun endpoint(host: String, port: Int): String {
        val bare = host.trim().removePrefix("[").removeSuffix("]")
        return if (bare.contains(':')) "[$bare]:$port" else "$bare:$port"
    }

    /**
     * Reserved bytes from a JSON value: an array of three numbers (Xray,
     * sing-box) or a string in either form [com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parseReserved]
     * reads. Null when absent or not three bytes.
     */
    fun reservedFromJson(value: Any?): ByteArray? = when (value) {
        null -> null
        is org.json.JSONArray -> {
            val values = (0 until value.length()).map { value.optInt(it, -1) }
            if (values.size == 3 && values.all { it in 0..255 }) ByteArray(3) { values[it].toByte() } else null
        }
        is String -> com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parseReserved(value)
        else -> null
    }
}
