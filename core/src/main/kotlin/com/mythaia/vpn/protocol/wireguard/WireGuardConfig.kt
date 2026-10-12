package com.mythaia.vpn.protocol.wireguard

/**
 * AmneziaWG's obfuscation parameters.
 *
 * Plain WireGuard is trivially identifiable: fixed message sizes, fixed type
 * bytes in the first four octets. AmneziaWG sends junk packets before the
 * handshake, prepends junk to the handshake messages, and renumbers the types,
 * so none of those signatures survives. All zeroes and the defaults mean plain
 * WireGuard, which is what an ordinary `[Interface]` section produces.
 */
data class AmneziaSettings(
    /** Junk packets sent before the handshake. */
    val junkPacketCount: Int = 0,
    /** Size range of each junk packet, in bytes. */
    val junkPacketMinSize: Int = 0,
    val junkPacketMaxSize: Int = 0,
    /** Junk prepended to the initiation and to the response. */
    val initPacketJunkSize: Int = 0,
    val responsePacketJunkSize: Int = 0,
    /** Replacements for the four message type values. */
    val initPacketMagicHeader: Long = 1,
    val responsePacketMagicHeader: Long = 2,
    val underloadPacketMagicHeader: Long = 3,
    val transportPacketMagicHeader: Long = 4
) {

    /** Whether anything here differs from plain WireGuard. */
    val isEnabled: Boolean
        get() = junkPacketCount > 0 ||
            initPacketJunkSize > 0 ||
            responsePacketJunkSize > 0 ||
            renumbersTypes

    /** Whether H1-H4 replace the type words, which then own all four octets of them. */
    val renumbersTypes: Boolean
        get() = initPacketMagicHeader != 1L ||
            responsePacketMagicHeader != 2L ||
            underloadPacketMagicHeader != 3L ||
            transportPacketMagicHeader != 4L

    /**
     * The size to make one junk packet, drawn from the configured range.
     *
     * Returns 0 when no junk was asked for, which the caller reads as "send
     * nothing".
     */
    fun junkSize(random: java.security.SecureRandom): Int {
        if (junkPacketMaxSize <= 0) return 0
        val low = junkPacketMinSize.coerceAtLeast(0)
        val high = junkPacketMaxSize.coerceAtLeast(low)
        if (high == low) return low
        return low + random.nextInt(high - low + 1)
    }

    // The message type is a 32-bit field on the wire. H1-H4 are required to be
    // distinct and greater than 4, so they are normally well past a byte —
    // truncating one would put three zero octets on the wire and every packet
    // would be dropped by the peer.
    val initiationType: Int get() = initPacketMagicHeader.toInt()
    val responseType: Int get() = responsePacketMagicHeader.toInt()
    val cookieType: Int get() = underloadPacketMagicHeader.toInt()
    val transportType: Int get() = transportPacketMagicHeader.toInt()
}

/**
 * One `[Peer]` section.
 */
data class WireGuardPeer(
    val publicKey: ByteArray,
    val presharedKey: ByteArray? = null,
    val endpointHost: String,
    val endpointPort: Int,
    /** What this peer routes; `0.0.0.0/0` means everything. */
    val allowedIps: List<String> = listOf("0.0.0.0/0", "::/0"),
    /** Seconds between keepalives, or 0 for none. */
    val persistentKeepalive: Int = 0
) {
    override fun equals(other: Any?): Boolean =
        other is WireGuardPeer &&
            publicKey.contentEquals(other.publicKey) &&
            (presharedKey?.contentEquals(other.presharedKey ?: ByteArray(0)) ?: (other.presharedKey == null)) &&
            endpointHost == other.endpointHost &&
            endpointPort == other.endpointPort &&
            allowedIps == other.allowedIps &&
            persistentKeepalive == other.persistentKeepalive

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + (presharedKey?.contentHashCode() ?: 0)
        result = 31 * result + endpointHost.hashCode()
        result = 31 * result + endpointPort
        result = 31 * result + allowedIps.hashCode()
        result = 31 * result + persistentKeepalive
        return result
    }
}

/**
 * A parsed `wg-quick` configuration.
 *
 * The same INI a WireGuard or AmneziaWG client exports, so a user can paste one
 * unchanged.
 */
data class WireGuardConfig(
    val privateKey: ByteArray,
    /** Addresses to give the interface, as `address/prefix`. */
    val addresses: List<String>,
    val dnsServers: List<String>,
    val mtu: Int,
    val peer: WireGuardPeer,
    val amnezia: AmneziaSettings,
    /**
     * `Reserved = a,b,c`: three bytes written into octets 1-3 of every message
     * this side sends, where plain WireGuard has zeroes.
     *
     * Cloudflare WARP routes on them — they carry the client id its API hands
     * out — and drops a handshake without them, so a WARP profile that loses
     * this field connects nowhere. Xray, sing-box and v2rayNG all call it
     * `reserved`.
     */
    val reserved: ByteArray? = null
) {
    val publicKey: ByteArray get() = WireGuardCrypto.publicKey(privateKey)

    /**
     * [reserved] when it can be put on the wire, else null.
     *
     * AmneziaWG's H1-H4 already fill all four octets of the type word, so the
     * two cannot both apply; the renumbering wins because a server expecting
     * it drops anything else outright, while WARP is never an AmneziaWG peer.
     * `0,0,0` — Xray's default, written into many configs — is plain WireGuard
     * and is left null so nothing about the wire changes for it.
     */
    val headerReserved: ByteArray?
        get() = reserved?.takeIf { bytes -> !amnezia.renumbersTypes && bytes.any { it != 0.toByte() } }

    override fun equals(other: Any?): Boolean =
        other is WireGuardConfig &&
            privateKey.contentEquals(other.privateKey) &&
            addresses == other.addresses &&
            dnsServers == other.dnsServers &&
            mtu == other.mtu &&
            peer == other.peer &&
            amnezia == other.amnezia &&
            (reserved?.contentEquals(other.reserved ?: ByteArray(0)) ?: (other.reserved == null))

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + addresses.hashCode()
        result = 31 * result + dnsServers.hashCode()
        result = 31 * result + mtu
        result = 31 * result + peer.hashCode()
        result = 31 * result + amnezia.hashCode()
        result = 31 * result + (reserved?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        /** What wg-quick uses when the config does not say. */
        const val DEFAULT_MTU = 1420

        /**
         * Parses a `wg-quick` INI.
         *
         * Keys are matched case-insensitively, as wg-quick does. A config with
         * several peers keeps the first: this client dials one endpoint, and
         * silently using a peer the user did not expect would be worse than
         * saying so.
         *
         * @throws WireGuardError with what was missing or unusable.
         */
        fun parse(text: String): WireGuardConfig {
            var section = ""
            // Address, DNS and AllowedIPs may each be written over several
            // lines, and wg-quick takes the union. Every key accumulates;
            // single-valued ones are read back with `last`, so a repeated
            // PrivateKey or Endpoint still means the last one wins.
            val interfaceValues = HashMap<String, MutableList<String>>()
            val peerValues = HashMap<String, MutableList<String>>()
            var seenPeer = false

            for (rawLine in text.lines()) {
                // `#` and `;` both start a comment in the configs wg-quick writes.
                val line = rawLine.substringBefore('#').substringBefore(';').trim()
                if (line.isEmpty()) continue

                if (line.startsWith("[") && line.endsWith("]")) {
                    section = line.substring(1, line.length - 1).trim().lowercase()
                    if (section == "peer") {
                        // Only the first peer is kept; later ones are ignored
                        // rather than merged into it.
                        if (seenPeer) section = "extra-peer"
                        seenPeer = true
                    }
                    continue
                }

                val separator = line.indexOf('=')
                if (separator < 0) continue
                val key = line.substring(0, separator).trim().lowercase()
                val value = line.substring(separator + 1).trim()
                if (key.isEmpty()) continue

                when (section) {
                    "interface" -> interfaceValues.getOrPut(key) { mutableListOf() }.add(value)
                    "peer" -> peerValues.getOrPut(key) { mutableListOf() }.add(value)
                    else -> Unit
                }
            }

            fun one(values: Map<String, MutableList<String>>, key: String): String? =
                values[key]?.lastOrNull()

            val privateKey = one(interfaceValues, "privatekey")?.let { WireGuardCrypto.decodeKey(it) }
                ?: throw WireGuardError("[Interface] PrivateKey is missing or not a 32-byte key")

            if (!seenPeer) throw WireGuardError("no [Peer] section")

            val peerPublicKey = one(peerValues, "publickey")?.let { WireGuardCrypto.decodeKey(it) }
                ?: throw WireGuardError("[Peer] PublicKey is missing or not a 32-byte key")

            val endpoint = one(peerValues, "endpoint")
                ?: throw WireGuardError("[Peer] Endpoint is missing")
            val (host, port) = splitEndpoint(endpoint)

            val presharedKey = one(peerValues, "presharedkey")?.let {
                WireGuardCrypto.decodeKey(it)
                    ?: throw WireGuardError("[Peer] PresharedKey is not a 32-byte key")
            }

            // Clients disagree on the section; WARP generators put it under
            // either, and it means the same thing in both.
            val reserved = (one(interfaceValues, "reserved") ?: one(peerValues, "reserved"))?.let {
                parseReserved(it)
                    ?: throw WireGuardError("Reserved must be three bytes (a,b,c or base64), not \"$it\"")
            }

            return WireGuardConfig(
                privateKey = privateKey,
                addresses = splitAll(interfaceValues["address"]),
                dnsServers = splitAll(interfaceValues["dns"]),
                mtu = one(interfaceValues, "mtu")?.toIntOrNull()?.takeIf { it in 576..9000 }
                    ?: DEFAULT_MTU,
                peer = WireGuardPeer(
                    publicKey = peerPublicKey,
                    presharedKey = presharedKey,
                    endpointHost = host,
                    endpointPort = port,
                    allowedIps = splitAll(peerValues["allowedips"])
                        .ifEmpty { listOf("0.0.0.0/0", "::/0") },
                    persistentKeepalive = one(peerValues, "persistentkeepalive")?.toIntOrNull()
                        ?.takeIf { it in 0..65535 } ?: 0
                ),
                amnezia = parseAmnezia(interfaceValues),
                reserved = reserved
            )
        }

        /**
         * WARP's three reserved bytes as configs write them: decimal octets
         * (`1,2,3`, optionally bracketed, as Xray and v2rayNG do) or base64 of
         * the three bytes (`AQID`, sing-box's string form and what the WARP API
         * returns as `client_id`). Null when it is neither.
         */
        fun parseReserved(text: String): ByteArray? {
            val trimmed = text.trim().removePrefix("[").removeSuffix("]").trim()
            if (trimmed.isEmpty()) return null
            val parts = trimmed.split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() }
            if (parts.size == 3 && parts.all { p -> p.all { it.isDigit() } }) {
                val values = parts.map { it.toIntOrNull() ?: return null }
                if (values.any { it !in 0..255 }) return null
                return ByteArray(3) { values[it].toByte() }
            }
            if (parts.size != 1) return null
            val bytes = runCatching {
                java.util.Base64.getDecoder().decode(
                    trimmed.replace('-', '+').replace('_', '/').let { it.padEnd((it.length + 3) / 4 * 4, '=') }
                )
            }.getOrNull() ?: return null
            return bytes.takeIf { it.size == 3 }
        }

        private fun parseAmnezia(values: Map<String, MutableList<String>>): AmneziaSettings {
            fun int(key: String, fallback: Int) =
                values[key]?.lastOrNull()?.toIntOrNull()?.takeIf { it >= 0 } ?: fallback

            fun long(key: String, fallback: Long) =
                values[key]?.lastOrNull()?.toLongOrNull()?.takeIf { it in 0..0xFFFFFFFFL } ?: fallback

            return AmneziaSettings(
                junkPacketCount = int("jc", 0),
                junkPacketMinSize = int("jmin", 0),
                junkPacketMaxSize = int("jmax", 0),
                initPacketJunkSize = int("s1", 0),
                responsePacketJunkSize = int("s2", 0),
                initPacketMagicHeader = long("h1", 1),
                responsePacketMagicHeader = long("h2", 2),
                underloadPacketMagicHeader = long("h3", 3),
                transportPacketMagicHeader = long("h4", 4)
            )
        }

        /** `host:port`, or `[v6]:port`. */
        private fun splitEndpoint(endpoint: String): Pair<String, Int> {
            val text = endpoint.trim()
            if (text.startsWith("[")) {
                val close = text.indexOf(']')
                if (close < 0) throw WireGuardError("[Peer] Endpoint has no closing bracket")
                val host = text.substring(1, close)
                val rest = text.substring(close + 1)
                if (!rest.startsWith(":")) throw WireGuardError("[Peer] Endpoint has no port")
                val port = rest.substring(1).toIntOrNull()
                    ?: throw WireGuardError("[Peer] Endpoint port is not a number")
                if (host.isEmpty() || port !in 1..65535) {
                    throw WireGuardError("[Peer] Endpoint is not usable: $endpoint")
                }
                return host to port
            }

            val colon = text.lastIndexOf(':')
            if (colon < 0) throw WireGuardError("[Peer] Endpoint has no port")
            val host = text.substring(0, colon)
            // An unbracketed IPv6 literal would be split across its own colons.
            if (host.contains(':')) {
                throw WireGuardError("[Peer] IPv6 endpoint must be bracketed: $endpoint")
            }
            val port = text.substring(colon + 1).toIntOrNull()
                ?: throw WireGuardError("[Peer] Endpoint port is not a number")
            if (host.isEmpty() || port !in 1..65535) {
                throw WireGuardError("[Peer] Endpoint is not usable: $endpoint")
            }
            return host to port
        }

        /**
         * Every comma-separated entry across every occurrence of the key, in
         * the order written, without duplicates.
         */
        private fun splitAll(values: List<String>?): List<String> =
            values.orEmpty()
                .flatMap { it.split(",") }
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
    }
}
