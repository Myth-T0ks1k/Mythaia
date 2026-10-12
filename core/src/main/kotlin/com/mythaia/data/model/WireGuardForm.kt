package com.mythaia.data.model

/**
 * A WireGuard / AmneziaWG profile as editable fields, for the field-by-field
 * editors on Android and Windows.
 *
 * The profile is stored as `wg-quick` INI text ([ProxyConfiguration.wireGuardConfig])
 * and that stays the source of truth: [fromIni] reads the keys the form shows,
 * keeps every other line (comments, keys a future build understands, peers
 * after the first) and [toIni] writes them back unchanged, so editing a
 * field in the form never loses something the form has no field for.
 */
data class WireGuardForm(
    val privateKey: String = "",
    val addresses: String = "",
    val dns: String = "",
    val mtu: String = "",
    val reserved: String = "",
    val publicKey: String = "",
    val presharedKey: String = "",
    val endpoint: String = "",
    val allowedIps: String = "0.0.0.0/0, ::/0",
    val keepalive: String = "",
    // AmneziaWG
    val jc: String = "",
    val jmin: String = "",
    val jmax: String = "",
    val s1: String = "",
    val s2: String = "",
    val h1: String = "",
    val h2: String = "",
    val h3: String = "",
    val h4: String = "",
    /** Interface lines the form does not edit, verbatim. */
    val extraInterface: List<String> = emptyList(),
    /** Peer lines the form does not edit, verbatim. */
    val extraPeer: List<String> = emptyList(),
    /** Everything after the first [Peer] section, verbatim. */
    val trailing: List<String> = emptyList()
) {
    /** Whether any AmneziaWG obfuscation field is set. */
    val isAmnezia: Boolean
        get() = listOf(jc, jmin, jmax, s1, s2, h1, h2, h3, h4).any { it.isNotBlank() }

    fun toIni(): String {
        val out = ArrayList<String>()
        out += "[Interface]"
        line(out, "PrivateKey", privateKey)
        line(out, "Address", addresses)
        line(out, "DNS", dns)
        line(out, "MTU", mtu)
        line(out, "Reserved", reserved)
        line(out, "Jc", jc); line(out, "Jmin", jmin); line(out, "Jmax", jmax)
        line(out, "S1", s1); line(out, "S2", s2)
        line(out, "H1", h1); line(out, "H2", h2); line(out, "H3", h3); line(out, "H4", h4)
        out += extraInterface
        out += ""
        out += "[Peer]"
        line(out, "PublicKey", publicKey)
        line(out, "PresharedKey", presharedKey)
        line(out, "AllowedIPs", allowedIps)
        line(out, "Endpoint", endpoint)
        line(out, "PersistentKeepalive", keepalive)
        out += extraPeer
        if (trailing.isNotEmpty()) {
            out += ""
            out += trailing
        }
        return out.joinToString("\n").trimEnd() + "\n"
    }

    private fun line(out: MutableList<String>, key: String, value: String) {
        val v = value.trim()
        if (v.isNotEmpty()) out += "$key = $v"
    }

    companion object {
        private val INTERFACE_KEYS = setOf(
            "privatekey", "address", "dns", "mtu", "reserved",
            "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"
        )
        private val PEER_KEYS = setOf("publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive")

        /** A fresh profile with a new key pair and the usual full-tunnel peer defaults. */
        fun blank(): WireGuardForm = WireGuardForm(privateKey = generatePrivateKey(), keepalive = "25")

        fun fromIni(text: String): WireGuardForm {
            var form = WireGuardForm(allowedIps = "")
            val extraInterface = ArrayList<String>()
            val extraPeer = ArrayList<String>()
            val trailing = ArrayList<String>()
            var section = ""
            var peersSeen = 0
            for (raw in text.lines()) {
                val trimmed = raw.trim()
                if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                    section = trimmed.substring(1, trimmed.length - 1).trim().lowercase()
                    if (section == "peer") peersSeen++
                    if (section == "peer" && peersSeen > 1 || section !in setOf("interface", "peer")) trailing += raw
                    continue
                }
                if (peersSeen > 1 || section !in setOf("interface", "peer")) {
                    if (trimmed.isNotEmpty() || trailing.isNotEmpty()) trailing += raw
                    continue
                }
                if (trimmed.isEmpty()) continue
                val eq = trimmed.indexOf('=')
                val key = if (eq > 0) trimmed.substring(0, eq).trim().lowercase() else ""
                val value = if (eq > 0) trimmed.substring(eq + 1).trim() else ""
                if (section == "interface") {
                    if (key !in INTERFACE_KEYS) { extraInterface += raw; continue }
                    form = when (key) {
                        "privatekey" -> form.copy(privateKey = value)
                        "address" -> form.copy(addresses = join(form.addresses, value))
                        "dns" -> form.copy(dns = join(form.dns, value))
                        "mtu" -> form.copy(mtu = value)
                        "reserved" -> form.copy(reserved = value)
                        "jc" -> form.copy(jc = value)
                        "jmin" -> form.copy(jmin = value)
                        "jmax" -> form.copy(jmax = value)
                        "s1" -> form.copy(s1 = value)
                        "s2" -> form.copy(s2 = value)
                        "h1" -> form.copy(h1 = value)
                        "h2" -> form.copy(h2 = value)
                        "h3" -> form.copy(h3 = value)
                        else -> form.copy(h4 = value)
                    }
                } else {
                    if (key !in PEER_KEYS) { extraPeer += raw; continue }
                    form = when (key) {
                        "publickey" -> form.copy(publicKey = value)
                        "presharedkey" -> form.copy(presharedKey = value)
                        "allowedips" -> form.copy(allowedIps = join(form.allowedIps, value))
                        "endpoint" -> form.copy(endpoint = value)
                        else -> form.copy(keepalive = value)
                    }
                }
            }
            return form.copy(extraInterface = extraInterface, extraPeer = extraPeer, trailing = trailing)
        }

        private fun join(existing: String, more: String): String =
            if (existing.isBlank()) more else "$existing, $more"

        /** A new X25519 private key, base64, as `wg genkey` prints it. */
        fun generatePrivateKey(): String {
            val (privateKey, _) = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.generateKeyPair()
            return java.util.Base64.getEncoder().encodeToString(privateKey)
        }

        /** The public key for [privateKey] (base64), or null when it is not a 32-byte key. */
        fun publicKeyOf(privateKey: String): String? = runCatching {
            val bytes = java.util.Base64.getDecoder().decode(WireGuardIni.normalizeKey(privateKey))
            if (bytes.size != 32) return null
            val pub = com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.publicKey(bytes)
            java.util.Base64.getEncoder().encodeToString(pub)
        }.getOrNull()
    }
}
