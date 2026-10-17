import Foundation
import CryptoKit

/**
 * AmneziaWG's obfuscation parameters.
 *
 * Plain WireGuard is trivially identifiable: fixed message sizes, fixed type
 * bytes in the first four octets. AmneziaWG sends junk packets before the
 * handshake, prepends junk to the handshake messages, and renumbers the types,
 * so none of those signatures survives. All zeroes and the defaults mean plain
 * WireGuard, which is what an ordinary `[Interface]` section produces.
 */
public struct AmneziaSettings: Hashable {
    /// Junk packets sent before the handshake.
    public var junkPacketCount: Int
    /// Size range of each junk packet, in bytes.
    public var junkPacketMinSize: Int
    public var junkPacketMaxSize: Int
    /// Junk prepended to the initiation and to the response.
    public var initPacketJunkSize: Int
    public var responsePacketJunkSize: Int
    /// Replacements for the four message type values.
    public var initPacketMagicHeader: Int64
    public var responsePacketMagicHeader: Int64
    public var underloadPacketMagicHeader: Int64
    public var transportPacketMagicHeader: Int64

    public init(
        junkPacketCount: Int = 0,
        junkPacketMinSize: Int = 0,
        junkPacketMaxSize: Int = 0,
        initPacketJunkSize: Int = 0,
        responsePacketJunkSize: Int = 0,
        initPacketMagicHeader: Int64 = 1,
        responsePacketMagicHeader: Int64 = 2,
        underloadPacketMagicHeader: Int64 = 3,
        transportPacketMagicHeader: Int64 = 4
    ) {
        self.junkPacketCount = junkPacketCount
        self.junkPacketMinSize = junkPacketMinSize
        self.junkPacketMaxSize = junkPacketMaxSize
        self.initPacketJunkSize = initPacketJunkSize
        self.responsePacketJunkSize = responsePacketJunkSize
        self.initPacketMagicHeader = initPacketMagicHeader
        self.responsePacketMagicHeader = responsePacketMagicHeader
        self.underloadPacketMagicHeader = underloadPacketMagicHeader
        self.transportPacketMagicHeader = transportPacketMagicHeader
    }

    /// Whether anything here differs from plain WireGuard.
    public var isEnabled: Bool {
        junkPacketCount > 0 || initPacketJunkSize > 0 || responsePacketJunkSize > 0 || renumbersTypes
    }

    /// Whether H1-H4 replace the type words, which then own all four octets of them.
    public var renumbersTypes: Bool {
        initPacketMagicHeader != 1 || responsePacketMagicHeader != 2 ||
            underloadPacketMagicHeader != 3 || transportPacketMagicHeader != 4
    }

    /**
     * The size to make one junk packet, drawn from the configured range.
     *
     * Returns 0 when no junk was asked for, which the caller reads as "send
     * nothing".
     */
    public func junkSize() -> Int {
        if junkPacketMaxSize <= 0 { return 0 }
        let low = max(junkPacketMinSize, 0)
        let high = max(junkPacketMaxSize, low)
        if high == low { return low }
        return Int.random(in: low...high)
    }

    // The message type is a 32-bit field on the wire. H1-H4 are required to be
    // distinct and greater than 4, so they are normally well past a byte —
    // truncating one would put three zero octets on the wire and every packet
    // would be dropped by the peer.
    public var initiationType: UInt32 { UInt32(truncatingIfNeeded: initPacketMagicHeader) }
    public var responseType: UInt32 { UInt32(truncatingIfNeeded: responsePacketMagicHeader) }
    public var cookieType: UInt32 { UInt32(truncatingIfNeeded: underloadPacketMagicHeader) }
    public var transportType: UInt32 { UInt32(truncatingIfNeeded: transportPacketMagicHeader) }
}

/// One `[Peer]` section.
public struct WireGuardPeer: Hashable {
    public var publicKey: Data
    public var presharedKey: Data?
    public var endpointHost: String
    public var endpointPort: Int
    /// What this peer routes; `0.0.0.0/0` means everything.
    public var allowedIps: [String]
    /// Seconds between keepalives, or 0 for none.
    public var persistentKeepalive: Int

    public init(
        publicKey: Data,
        presharedKey: Data? = nil,
        endpointHost: String,
        endpointPort: Int,
        allowedIps: [String] = ["0.0.0.0/0", "::/0"],
        persistentKeepalive: Int = 0
    ) {
        self.publicKey = publicKey
        self.presharedKey = presharedKey
        self.endpointHost = endpointHost
        self.endpointPort = endpointPort
        self.allowedIps = allowedIps
        self.persistentKeepalive = persistentKeepalive
    }
}

/**
 * A parsed `wg-quick` configuration.
 *
 * The same INI a WireGuard or AmneziaWG client exports, so a user can paste one
 * unchanged.
 */
public struct WireGuardConfig: Hashable {
    public var privateKey: Data
    /// Addresses to give the interface, as `address/prefix`.
    public var addresses: [String]
    public var dnsServers: [String]
    public var mtu: Int
    public var peer: WireGuardPeer
    public var amnezia: AmneziaSettings
    /**
     * `Reserved = a,b,c`: three bytes written into octets 1-3 of every message
     * this side sends, where plain WireGuard has zeroes.
     *
     * Cloudflare WARP routes on them — they carry the client id its API hands
     * out — and drops a handshake without them, so a WARP profile that loses
     * this field connects nowhere. Xray, sing-box and v2rayNG all call it
     * `reserved`.
     */
    public var reserved: Data?

    /// What wg-quick uses when the config does not say.
    public static let defaultMtu = 1420

    public init(
        privateKey: Data,
        addresses: [String],
        dnsServers: [String],
        mtu: Int,
        peer: WireGuardPeer,
        amnezia: AmneziaSettings,
        reserved: Data? = nil
    ) {
        self.privateKey = privateKey
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.mtu = mtu
        self.peer = peer
        self.amnezia = amnezia
        self.reserved = reserved
    }

    /// The public key for `privateKey`; empty when it is not a usable key.
    public var publicKey: Data {
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey) else { return Data() }
        return key.publicKey.rawRepresentation
    }

    /**
     * `reserved` when it can be put on the wire, else nil.
     *
     * AmneziaWG's H1-H4 already fill all four octets of the type word, so the
     * two cannot both apply; the renumbering wins because a server expecting
     * it drops anything else outright, while WARP is never an AmneziaWG peer.
     * `0,0,0` — Xray's default, written into many configs — is plain WireGuard
     * and is left nil so nothing about the wire changes for it.
     */
    public var headerReserved: Data? {
        guard let bytes = reserved, !amnezia.renumbersTypes, bytes.contains(where: { $0 != 0 }) else { return nil }
        return bytes
    }

    /// Base64 as WireGuard configs write keys. Nil when it is not a 32-byte key.
    public static func decodeKey(_ text: String) -> Data? {
        guard let bytes = LinkText.base64Decode(LinkText.trim(text), urlSafe: false), bytes.count == 32 else { return nil }
        return bytes
    }

    public static func encodeKey(_ key: Data) -> String {
        key.base64EncodedString()
    }

    /**
     * Parses a `wg-quick` INI.
     *
     * Keys are matched case-insensitively, as wg-quick does. A config with
     * several peers keeps the first: this client dials one endpoint, and
     * silently using a peer the user did not expect would be worse than
     * saying so.
     *
     * Throws `invalidConfiguration` saying what was missing or unusable.
     */
    public static func parse(_ text: String) throws -> WireGuardConfig {
        var section = ""
        // Address, DNS and AllowedIPs may each be written over several
        // lines, and wg-quick takes the union. Every key accumulates;
        // single-valued ones are read back with `last`, so a repeated
        // PrivateKey or Endpoint still means the last one wins.
        var interfaceValues: [String: [String]] = [:]
        var peerValues: [String: [String]] = [:]
        var seenPeer = false

        for rawLine in LinkText.lines(text) {
            // `#` and `;` both start a comment in the configs wg-quick writes.
            var bytes = Array(rawLine.utf8)
            if let hash = bytes.firstIndex(of: UInt8(ascii: "#")) { bytes = Array(bytes[..<hash]) }
            if let semicolon = bytes.firstIndex(of: UInt8(ascii: ";")) { bytes = Array(bytes[..<semicolon]) }
            let line = LinkText.trim(LinkText.string(bytes))
            if line.isEmpty { continue }

            if LinkText.hasPrefix(line, "[") && LinkText.hasSuffix(line, "]") {
                let inner = LinkText.removeSuffix(LinkText.removePrefix(line, "["), "]")
                section = LinkText.trim(inner).lowercased()
                if section == "peer" {
                    // Only the first peer is kept; later ones are ignored
                    // rather than merged into it.
                    if seenPeer { section = "extra-peer" }
                    seenPeer = true
                }
                continue
            }

            let lineBytes = Array(line.utf8)
            guard let separator = lineBytes.firstIndex(of: UInt8(ascii: "=")) else { continue }
            let key = LinkText.trim(LinkText.string(lineBytes[..<separator])).lowercased()
            let value = LinkText.trim(LinkText.string(lineBytes[(separator + 1)...]))
            if key.isEmpty { continue }

            switch section {
            case "interface": interfaceValues[key, default: []].append(value)
            case "peer": peerValues[key, default: []].append(value)
            default: break
            }
        }

        func one(_ values: [String: [String]], _ key: String) -> String? {
            values[key]?.last
        }

        guard let privateKey = one(interfaceValues, "privatekey").flatMap({ decodeKey($0) }) else {
            throw MythaiaError.invalidConfiguration("[Interface] PrivateKey is missing or not a 32-byte key")
        }
        if !seenPeer { throw MythaiaError.invalidConfiguration("no [Peer] section") }

        guard let peerPublicKey = one(peerValues, "publickey").flatMap({ decodeKey($0) }) else {
            throw MythaiaError.invalidConfiguration("[Peer] PublicKey is missing or not a 32-byte key")
        }
        guard let endpoint = one(peerValues, "endpoint") else {
            throw MythaiaError.invalidConfiguration("[Peer] Endpoint is missing")
        }
        let (host, port) = try splitEndpoint(endpoint)

        var presharedKey: Data? = nil
        if let text = one(peerValues, "presharedkey") {
            guard let key = decodeKey(text) else {
                throw MythaiaError.invalidConfiguration("[Peer] PresharedKey is not a 32-byte key")
            }
            presharedKey = key
        }

        // Clients disagree on the section; WARP generators put it under
        // either, and it means the same thing in both.
        var reserved: Data? = nil
        if let text = one(interfaceValues, "reserved") ?? one(peerValues, "reserved") {
            guard let bytes = parseReserved(text) else {
                throw MythaiaError.invalidConfiguration("Reserved must be three bytes (a,b,c or base64), not \"\(text)\"")
            }
            reserved = bytes
        }

        var mtu = defaultMtu
        if let value = one(interfaceValues, "mtu").flatMap({ Int($0) }), value >= 576 && value <= 9000 {
            mtu = value
        }
        var keepalive = 0
        if let value = one(peerValues, "persistentkeepalive").flatMap({ Int($0) }), value >= 0 && value <= 65535 {
            keepalive = value
        }
        var allowed = splitAll(peerValues["allowedips"])
        if allowed.isEmpty { allowed = ["0.0.0.0/0", "::/0"] }

        return WireGuardConfig(
            privateKey: privateKey,
            addresses: splitAll(interfaceValues["address"]),
            dnsServers: splitAll(interfaceValues["dns"]),
            mtu: mtu,
            peer: WireGuardPeer(
                publicKey: peerPublicKey,
                presharedKey: presharedKey,
                endpointHost: host,
                endpointPort: port,
                allowedIps: allowed,
                persistentKeepalive: keepalive
            ),
            amnezia: parseAmnezia(interfaceValues),
            reserved: reserved
        )
    }

    /**
     * WARP's three reserved bytes as configs write them: decimal octets
     * (`1,2,3`, optionally bracketed, as Xray and v2rayNG do) or base64 of
     * the three bytes (`AQID`, sing-box's string form and what the WARP API
     * returns as `client_id`). Nil when it is neither.
     */
    public static func parseReserved(_ text: String) -> Data? {
        var trimmed = LinkText.trim(text)
        trimmed = LinkText.removePrefix(trimmed, "[")
        trimmed = LinkText.trim(LinkText.removeSuffix(trimmed, "]"))
        if trimmed.isEmpty { return nil }
        let separators: Set<UInt8> = [UInt8(ascii: ","), UInt8(ascii: " ")]
        let parts = LinkText.split(trimmed, anyOf: separators).map { LinkText.trim($0) }.filter { !$0.isEmpty }
        if parts.count == 3 && parts.allSatisfy({ LinkText.isDigits($0) }) {
            var out = Data()
            for part in parts {
                guard let value = Int(part), value >= 0 && value <= 255 else { return nil }
                out.append(UInt8(value))
            }
            return out
        }
        if parts.count != 1 { return nil }
        let standard = trimmed.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let bytes = LinkText.base64Decode(LinkText.padBase64(standard), urlSafe: false), bytes.count == 3 else {
            return nil
        }
        return bytes
    }

    private static func parseAmnezia(_ values: [String: [String]]) -> AmneziaSettings {
        func int(_ key: String, _ fallback: Int) -> Int {
            guard let value = values[key]?.last.flatMap({ Int($0) }), value >= 0 else { return fallback }
            return value
        }
        func long(_ key: String, _ fallback: Int64) -> Int64 {
            guard let value = values[key]?.last.flatMap({ Int64($0) }), value >= 0 && value <= 0xFFFF_FFFF else {
                return fallback
            }
            return value
        }
        return AmneziaSettings(
            junkPacketCount: int("jc", 0),
            junkPacketMinSize: int("jmin", 0),
            junkPacketMaxSize: int("jmax", 0),
            initPacketJunkSize: int("s1", 0),
            responsePacketJunkSize: int("s2", 0),
            initPacketMagicHeader: long("h1", 1),
            responsePacketMagicHeader: long("h2", 2),
            underloadPacketMagicHeader: long("h3", 3),
            transportPacketMagicHeader: long("h4", 4)
        )
    }

    /// `host:port`, or `[v6]:port`.
    private static func splitEndpoint(_ endpoint: String) throws -> (String, Int) {
        let text = LinkText.trim(endpoint)
        let bytes = Array(text.utf8)
        if bytes.first == UInt8(ascii: "[") {
            guard let close = bytes.firstIndex(of: UInt8(ascii: "]")) else {
                throw MythaiaError.invalidConfiguration("[Peer] Endpoint has no closing bracket")
            }
            let host = LinkText.string(bytes[1..<close])
            let rest = bytes[(close + 1)...]
            guard rest.first == UInt8(ascii: ":") else {
                throw MythaiaError.invalidConfiguration("[Peer] Endpoint has no port")
            }
            guard let port = Int(LinkText.string(rest.dropFirst())) else {
                throw MythaiaError.invalidConfiguration("[Peer] Endpoint port is not a number")
            }
            if host.isEmpty || port < 1 || port > 65535 {
                throw MythaiaError.invalidConfiguration("[Peer] Endpoint is not usable: \(endpoint)")
            }
            return (host, port)
        }

        guard let colon = bytes.lastIndex(of: UInt8(ascii: ":")) else {
            throw MythaiaError.invalidConfiguration("[Peer] Endpoint has no port")
        }
        let host = LinkText.string(bytes[..<colon])
        // An unbracketed IPv6 literal would be split across its own colons.
        if host.utf8.contains(UInt8(ascii: ":")) {
            throw MythaiaError.invalidConfiguration("[Peer] IPv6 endpoint must be bracketed: \(endpoint)")
        }
        guard let port = Int(LinkText.string(bytes[(colon + 1)...])) else {
            throw MythaiaError.invalidConfiguration("[Peer] Endpoint port is not a number")
        }
        if host.isEmpty || port < 1 || port > 65535 {
            throw MythaiaError.invalidConfiguration("[Peer] Endpoint is not usable: \(endpoint)")
        }
        return (host, port)
    }

    /**
     * Every comma-separated entry across every occurrence of the key, in
     * the order written, without duplicates.
     */
    private static func splitAll(_ values: [String]?) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for value in values ?? [] {
            for part in LinkText.split(value, UInt8(ascii: ",")) {
                let trimmed = LinkText.trim(part)
                if trimmed.isEmpty || seen.contains(trimmed) { continue }
                seen.insert(trimmed)
                out.append(trimmed)
            }
        }
        return out
    }
}
