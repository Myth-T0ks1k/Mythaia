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
            initPacketMagicHeader != 1L ||
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

    /** The transport message type this peer uses, as a byte. */
    val transportType: Byte get() = (transportPacketMagicHeader and 0xFF).toByte()
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
    val amnezia: AmneziaSettings
) {
    val publicKey: ByteArray get() = WireGuardCrypto.publicKey(privateKey)

    override fun equals(other: Any?): Boolean =
        other is WireGuardConfig &&
            privateKey.contentEquals(other.privateKey) &&
            addresses == other.addresses &&
            dnsServers == other.dnsServers &&
            mtu == other.mtu &&
            peer == other.peer &&
            amnezia == other.amnezia

    override fun hashCode(): Int {
        var result = privateKey.contentHashCode()
        result = 31 * result + addresses.hashCode()
        result = 31 * result + dnsServers.hashCode()
        result = 31 * result + mtu
        result = 31 * result + peer.hashCode()
        result = 31 * result + amnezia.hashCode()
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
            val interfaceValues = HashMap<String, String>()
            val peerValues = HashMap<String, String>()
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
                    "interface" -> interfaceValues[key] = value
                    "peer" -> peerValues[key] = value
                    else -> Unit
                }
            }

            val privateKey = interfaceValues["privatekey"]?.let { WireGuardCrypto.decodeKey(it) }
                ?: throw WireGuardError("[Interface] PrivateKey is missing or not a 32-byte key")

            if (!seenPeer) throw WireGuardError("no [Peer] section")

            val peerPublicKey = peerValues["publickey"]?.let { WireGuardCrypto.decodeKey(it) }
                ?: throw WireGuardError("[Peer] PublicKey is missing or not a 32-byte key")

            val endpoint = peerValues["endpoint"]
                ?: throw WireGuardError("[Peer] Endpoint is missing")
            val (host, port) = splitEndpoint(endpoint)

            val presharedKey = peerValues["presharedkey"]?.let {
                WireGuardCrypto.decodeKey(it)
                    ?: throw WireGuardError("[Peer] PresharedKey is not a 32-byte key")
            }

            return WireGuardConfig(
                privateKey = privateKey,
                addresses = splitList(interfaceValues["address"]),
                dnsServers = splitList(interfaceValues["dns"]),
                mtu = interfaceValues["mtu"]?.toIntOrNull()?.takeIf { it in 576..9000 } ?: DEFAULT_MTU,
                peer = WireGuardPeer(
                    publicKey = peerPublicKey,
                    presharedKey = presharedKey,
                    endpointHost = host,
                    endpointPort = port,
                    allowedIps = splitList(peerValues["allowedips"])
                        .ifEmpty { listOf("0.0.0.0/0", "::/0") },
                    persistentKeepalive = peerValues["persistentkeepalive"]?.toIntOrNull()
                        ?.takeIf { it in 0..65535 } ?: 0
                ),
                amnezia = parseAmnezia(interfaceValues)
            )
        }

        private fun parseAmnezia(values: Map<String, String>): AmneziaSettings {
            fun int(key: String, fallback: Int) =
                values[key]?.toIntOrNull()?.takeIf { it >= 0 } ?: fallback

            fun long(key: String, fallback: Long) =
                values[key]?.toLongOrNull()?.takeIf { it in 0..0xFFFFFFFFL } ?: fallback

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

        private fun splitList(value: String?): List<String> =
            value?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
    }
}
