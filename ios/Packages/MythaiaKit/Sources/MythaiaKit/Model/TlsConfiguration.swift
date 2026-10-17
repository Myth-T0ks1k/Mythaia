import Foundation

public enum TlsFingerprint: String, Codable, CaseIterable, Hashable {
    case chrome133 = "chrome_133"
    case firefox148 = "firefox_148"
    case safari26 = "safari_26"
    case ios14 = "ios_14"
    case edge85 = "edge_85"
    case android11 = "android_11"
    case qq11 = "qq_11"
    case browser360 = "360_7"
    case chrome120 = "chrome_120"
    case firefox120 = "firefox_120"
    case safari16 = "safari_16"
    case edge106 = "edge_106"
    case random = "random"

    public var raw: String { rawValue }

    /**
     * Whether this fingerprint's hello already carries an ECH extension.
     *
     * Modern Chrome and Firefox send a GREASE ECH stub on every connection, so
     * a real one replaces the stub in place and the hello keeps its shape. The
     * older profiles predate ECH and have no slot; a real extension on them is
     * appended, which changes their shape and is the caller's decision.
     */
    public var hasEchSlot: Bool {
        self == .chrome133 || self == .firefox148 || self == .chrome120 || self == .firefox120
    }

    public var displayName: String {
        switch self {
        case .chrome133: return "Chrome 133"
        case .firefox148: return "Firefox 148"
        case .safari26: return "Safari 26"
        case .ios14: return "iOS 14"
        case .edge85: return "Edge 85"
        case .android11: return "Android 11"
        case .qq11: return "QQ 11"
        case .browser360: return "360 Browser"
        case .chrome120: return "Chrome 120"
        case .firefox120: return "Firefox 120"
        case .safari16: return "Safari 16"
        case .edge106: return "Edge 106"
        case .random: return "Random"
        }
    }

    public static func fromRaw(_ value: String) -> TlsFingerprint {
        if let exact = TlsFingerprint(rawValue: value) { return exact }
        return fromGenericName(value) ?? .chrome133
    }

    /**
     * uTLS family names, which is what panels put in `fp=`: `chrome`,
     * `safari`, `edge`... Each maps to the newest profile of that family.
     */
    private static func fromGenericName(_ value: String) -> TlsFingerprint? {
        switch LinkText.trim(value).lowercased() {
        case "chrome": return .chrome133
        case "firefox": return .firefox148
        case "safari": return .safari26
        case "ios": return .ios14
        case "edge": return .edge85
        case "android": return .android11
        case "qq": return .qq11
        case "360": return .browser360
        case "random", "randomized": return .random
        default: return nil
        }
    }

    /**
     * Pool used when the user picks "Random". Android-only fingerprints
     * (android11, qq11, browser360) are kept for backward compatibility with
     * previously imported share links but excluded from the random pool.
     */
    public static let concreteFingerprints: [TlsFingerprint] = TlsFingerprint.allCases.filter {
        $0 != .random && $0 != .android11 && $0 != .qq11 && $0 != .browser360
    }

    /**
     * Picker entries for the server editor. Excludes the Android-only
     * fingerprints from the menu, but `fromRaw` still resolves them when
     * imported from URLs.
     */
    public static let pickerFingerprints: [TlsFingerprint] = TlsFingerprint.allCases.filter {
        $0 != .android11 && $0 != .qq11 && $0 != .browser360
    }

    /// Read through `fromRaw`, so a store written by a build with another
    /// profile still loads instead of failing on one server.
    public init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = TlsFingerprint.fromRaw(raw)
    }
}

/**
 * Negotiated TLS protocol version. The numeric `value` matches the on-the-wire
 * protocol version field (RFC 5246/RFC 8446).
 */
public enum TlsVersion: String, Codable, CaseIterable, Hashable {
    case tls12 = "tls12"
    case tls13 = "tls13"

    public var value: Int {
        switch self {
        case .tls12: return 0x0303
        case .tls13: return 0x0304
        }
    }

    public var displayName: String {
        switch self {
        case .tls12: return "TLS 1.2"
        case .tls13: return "TLS 1.3"
        }
    }

    /// Wire-compatible version string for URL query params (e.g. "1.2", "1.3").
    public var urlValue: String {
        switch self {
        case .tls12: return "1.2"
        case .tls13: return "1.3"
        }
    }
}

public struct TlsConfiguration: Codable, Hashable {
    public var serverName: String
    public var alpn: [String]?
    public var allowInsecure: Bool
    public var fingerprint: TlsFingerprint
    /// Minimum acceptable TLS version (nil = no minimum, accept any).
    public var minVersion: TlsVersion?
    /// Maximum acceptable TLS version (nil = no maximum, accept any).
    public var maxVersion: TlsVersion?
    /**
     * How this server's ClientHello goes out on a direct dial. Nil means the
     * link carried no `fragment=`, so the tunnel-wide default applies.
     */
    public var fragment: FragmentSettings?
    /**
     * An ECHConfigList, base64, as a DNS HTTPS record or a share link carries it.
     *
     * When present the real server name is encrypted and the config's public
     * name goes out in the clear instead. Kept as the text it arrived as: the
     * server matches on the config's exact bytes, and a re-serialised copy that
     * differed by a byte would be silently ignored rather than rejected.
     */
    public var echConfig: String?
    /**
     * Xray's `pinnedPeerCertSha256` (`pcs=`; Hysteria's `pinSHA256=`): hex
     * SHA-256 of certificates the server may present. A match is trusted
     * without a certificate authority — Xray 26 replaced `allowInsecure` with
     * this — and a mismatch fails even a CA-valid chain.
     */
    public var pinnedCertSha256: [String]?
    /// Xray's `verifyPeerCertByName` (`vcn=`): the name the certificate must carry when it is not the SNI.
    public var verifyName: String?

    public init(
        serverName: String,
        alpn: [String]? = nil,
        allowInsecure: Bool = false,
        fingerprint: TlsFingerprint = .chrome133,
        minVersion: TlsVersion? = nil,
        maxVersion: TlsVersion? = nil,
        fragment: FragmentSettings? = nil,
        echConfig: String? = nil,
        pinnedCertSha256: [String]? = nil,
        verifyName: String? = nil
    ) {
        self.serverName = serverName
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.fingerprint = fingerprint
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.fragment = fragment
        self.echConfig = echConfig
        self.pinnedCertSha256 = pinnedCertSha256
        self.verifyName = verifyName
    }

    private enum CodingKeys: String, CodingKey {
        case serverName, alpn, allowInsecure, fingerprint, minVersion, maxVersion
        case fragment, echConfig, pinnedCertSha256, verifyName
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try c.decode(String.self, forKey: .serverName)
        alpn = try c.decodeIfPresent([String].self, forKey: .alpn)
        allowInsecure = try c.decodeIfPresent(Bool.self, forKey: .allowInsecure) ?? false
        fingerprint = try c.decodeIfPresent(TlsFingerprint.self, forKey: .fingerprint) ?? .chrome133
        minVersion = try? c.decodeIfPresent(TlsVersion.self, forKey: .minVersion)
        maxVersion = try? c.decodeIfPresent(TlsVersion.self, forKey: .maxVersion)
        fragment = try c.decodeIfPresent(FragmentSettings.self, forKey: .fragment)
        echConfig = try c.decodeIfPresent(String.self, forKey: .echConfig)
        pinnedCertSha256 = try c.decodeIfPresent([String].self, forKey: .pinnedCertSha256)
        verifyName = try c.decodeIfPresent(String.self, forKey: .verifyName)
    }

    public static func parse(_ params: [String: String], serverAddress: String) -> TlsConfiguration? {
        if params["security"] != "tls" { return nil }
        let sni = ShareLinkParams.nonEmpty(params["sni"])
            ?? ShareLinkParams.transportHostParam(params)
            ?? serverAddress
        let alpn = ShareLinkParams.parseAlpn(params["alpn"])
        let allowInsecure = ShareLinkParams.isTruthy(params["allowInsecure"]) || ShareLinkParams.isTruthy(params["insecure"])
        let fp = params["fp"] ?? "chrome_133"
        return TlsConfiguration(
            serverName: sni,
            alpn: alpn,
            allowInsecure: allowInsecure,
            fingerprint: TlsFingerprint.fromRaw(fp),
            minVersion: parseTlsVersion(params["minVersion"]),
            maxVersion: parseTlsVersion(params["maxVersion"]),
            fragment: ShareLinkParams.parseFragmentParams(params),
            echConfig: ShareLinkParams.nonEmpty(params["ech"]),
            pinnedCertSha256: ShareLinkParams.parsePinnedCerts(params),
            verifyName: ShareLinkParams.nonEmpty(params["vcn"])
        )
    }

    /// A TLS version string ("1.0"–"1.3"). "1.0" and "1.1" are legacy and
    /// read as TLS 1.2, since nothing here speaks the deprecated versions.
    private static func parseTlsVersion(_ version: String?) -> TlsVersion? {
        switch version {
        case "1.0", "1.1", "1.2": return .tls12
        case "1.3": return .tls13
        default: return nil
        }
    }
}

public struct RealityConfiguration: Codable, Hashable {
    public var serverName: String
    /// The server's X25519 public key; stored as unpadded URL-safe base64.
    public var publicKey: Data
    /// Up to eight bytes; stored as hex.
    public var shortId: Data
    public var fingerprint: TlsFingerprint

    public init(serverName: String, publicKey: Data, shortId: Data, fingerprint: TlsFingerprint = .chrome133) {
        self.serverName = serverName
        self.publicKey = publicKey
        self.shortId = shortId
        self.fingerprint = fingerprint
    }

    private enum CodingKeys: String, CodingKey {
        case serverName, publicKey, shortId, fingerprint
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        serverName = try c.decode(String.self, forKey: .serverName)
        let key = try c.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        publicKey = LinkText.base64UrlToData(key) ?? Data()
        let sid = try c.decodeIfPresent(String.self, forKey: .shortId) ?? ""
        shortId = LinkText.hexDecode(sid) ?? Data()
        fingerprint = try c.decodeIfPresent(TlsFingerprint.self, forKey: .fingerprint) ?? .chrome133
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serverName, forKey: .serverName)
        try c.encode(LinkText.base64UrlEncode(publicKey), forKey: .publicKey)
        try c.encode(LinkText.hex(shortId), forKey: .shortId)
        try c.encode(fingerprint, forKey: .fingerprint)
    }

    public static func parse(_ params: [String: String]) throws -> RealityConfiguration? {
        if params["security"] != "reality" { return nil }
        guard let sni = ShareLinkParams.nonEmpty(params["sni"]) else {
            throw MythaiaError.parse("Missing Reality parameter: sni")
        }
        guard let pbk = ShareLinkParams.nonEmpty(params["pbk"]) else {
            throw MythaiaError.parse("Missing Reality parameter: pbk (public key)")
        }
        guard let publicKey = LinkText.base64UrlToData(pbk), publicKey.count == 32 else {
            throw MythaiaError.parse("Invalid Reality public key")
        }
        let sidText = params["sid"] ?? ""
        guard let shortId = LinkText.hexDecode(sidText) else {
            throw MythaiaError.parse("Invalid Reality short ID: \(sidText)")
        }
        if shortId.count > 8 { throw MythaiaError.parse("Reality short ID is longer than 8 bytes") }
        let fp = params["fp"] ?? "chrome_133"
        return RealityConfiguration(
            serverName: sni,
            publicKey: publicKey,
            shortId: shortId,
            fingerprint: TlsFingerprint.fromRaw(fp)
        )
    }
}
