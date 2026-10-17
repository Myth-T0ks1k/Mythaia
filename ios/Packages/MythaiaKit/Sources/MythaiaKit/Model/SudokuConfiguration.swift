import Foundation

/**
 * The settings a Sudoku outbound is described by.
 *
 * Every field here changes what goes on the wire, which is why the values are
 * normalised the moment a configuration is built rather than at each use: the
 * table fingerprint is a hash of the mode and the custom patterns, so a stray
 * space or a different letter case in a subscription link would otherwise
 * derive a different set of tables than the server built and nothing would
 * decode.
 *
 * The reference reads these out of JSON with several legacy spellings. The
 * spellings are preserved as the enums' ids, and the tolerant parsers below
 * accept what the legacy fields carried.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
public struct SudokuConfiguration: Hashable {
    /// The pre-shared key, or an Ed25519 private key in hex.
    public let key: String
    public let aeadMethod: SudokuAeadMethod
    /// Percentage of positions that get a padding byte, at the low end.
    public let paddingMin: Int
    /**
     * The high end of the same range.
     *
     * A maximum below the minimum is raised to it rather than rejected, so a
     * hand-edited configuration degrades to a fixed padding rate instead of
     * failing to connect.
     */
    public let paddingMax: Int
    public let asciiMode: SudokuAsciiMode
    /**
     * Bit patterns for custom wire layouts, in preference order.
     *
     * More than one entry means the client picks one per connection and tells
     * the server which by sending the table fingerprint in its client hello;
     * with a single entry both sides already agree and no fingerprint is sent.
     */
    public let customTables: [String]
    /**
     * Whether the server may send the downlink as whole Sudoku puzzles rather
     * than packed six-bit groups. It costs four wire bytes per byte instead of
     * four per three, and buys a downlink that looks like the uplink.
     */
    public let enablePureDownlink: Bool
    public let multiplex: SudokuMultiplex
    public let httpMask: SudokuHttpMaskConfiguration

    public static let defaultPaddingMin = 5
    public static let defaultPaddingMax = 15

    public init(
        key: String,
        aeadMethod: SudokuAeadMethod = .chacha20Poly1305,
        paddingMin: Int = SudokuConfiguration.defaultPaddingMin,
        paddingMax: Int = SudokuConfiguration.defaultPaddingMax,
        asciiMode: SudokuAsciiMode = .preferEntropy,
        customTables: [String] = [],
        enablePureDownlink: Bool = true,
        multiplex: SudokuMultiplex = .off,
        httpMask: SudokuHttpMaskConfiguration = SudokuHttpMaskConfiguration()
    ) {
        self.key = LinkText.trim(key)
        self.aeadMethod = aeadMethod
        let low = min(max(paddingMin, 0), 100)
        self.paddingMin = low
        self.paddingMax = min(max(paddingMax, low), 100)
        self.asciiMode = asciiMode
        self.customTables = SudokuConfiguration.normalizeCustomTables(customTables)
        self.enablePureDownlink = enablePureDownlink
        self.multiplex = multiplex
        self.httpMask = httpMask
    }

    /// Whether a client hello for this configuration carries a table hint.
    public var sendsTableHint: Bool { customTables.count > 1 }

    /**
     * Drops blank and repeated patterns, keeping the order they were given
     * in, and falls back to `legacy` — the older single-table field — only
     * when nothing usable came from the plural one.
     */
    public static func normalizeCustomTables(_ tables: [String], legacy: String = "") -> [String] {
        var seen = Set<String>()
        var normalized: [String] = []
        for table in tables {
            let trimmed = LinkText.trim(table)
            if trimmed.isEmpty || seen.contains(trimmed) { continue }
            seen.insert(trimmed)
            normalized.append(trimmed)
        }
        if !normalized.isEmpty { return normalized }
        let trimmedLegacy = LinkText.trim(legacy)
        return trimmedLegacy.isEmpty ? [] : [trimmedLegacy]
    }
}

/// The AEAD that protects each record.
public enum SudokuAeadMethod: String, Codable, CaseIterable, Hashable {
    case chacha20Poly1305 = "chacha20-poly1305"
    case aes128Gcm = "aes-128-gcm"
    /**
     * No record layer at all: the obfuscated stream carries the payload
     * directly. Only useful when something else already provides secrecy.
     */
    case none = "none"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .chacha20Poly1305: return "ChaCha20-Poly1305"
        case .aes128Gcm: return "AES-128-GCM"
        case .none: return "None"
        }
    }

    public static func fromId(_ value: String) -> SudokuAeadMethod? {
        SudokuAeadMethod(rawValue: LinkText.trim(value).lowercased())
    }
}

/**
 * Which wire layout each direction uses.
 *
 * The ASCII layout keeps every byte inside the printable range, which survives
 * middleboxes that expect text but is visibly not random; the entropy layout
 * spreads bytes over the whole octet space. The mixed modes exist because the
 * two directions are often inspected differently.
 */
public enum SudokuAsciiMode: String, Codable, CaseIterable, Hashable {
    case preferEntropy = "prefer_entropy"
    case preferAscii = "prefer_ascii"
    case upAsciiDownEntropy = "up_ascii_down_entropy"
    case upEntropyDownAscii = "up_entropy_down_ascii"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .preferEntropy: return "Prefer Entropy"
        case .preferAscii: return "Prefer ASCII"
        case .upAsciiDownEntropy: return "Up ASCII / Down Entropy"
        case .upEntropyDownAscii: return "Up Entropy / Down ASCII"
        }
    }

    /// The layout token for client-to-server traffic: `ascii` or `entropy`.
    public var uplinkToken: String {
        switch self {
        case .preferAscii, .upAsciiDownEntropy: return "ascii"
        case .preferEntropy, .upEntropyDownAscii: return "entropy"
        }
    }

    /// The same for server-to-client traffic.
    public var downlinkToken: String {
        switch self {
        case .preferAscii, .upEntropyDownAscii: return "ascii"
        case .preferEntropy, .upAsciiDownEntropy: return "entropy"
        }
    }

    /// The abbreviation a share link uses for the two symmetric modes.
    public var shortLinkToken: String {
        switch self {
        case .preferEntropy: return "entropy"
        case .preferAscii: return "ascii"
        case .upAsciiDownEntropy, .upEntropyDownAscii: return id
        }
    }

    /**
     * Parses a mode, accepting the abbreviations share links use and
     * treating an empty value as the default.
     *
     * Returns nil for anything else, because an unrecognised mode would
     * otherwise silently become the default and derive tables the server
     * does not share.
     */
    public static func fromNormalized(_ value: String) -> SudokuAsciiMode? {
        let raw = LinkText.trim(value).lowercased()
        switch raw {
        case "", "entropy", SudokuAsciiMode.preferEntropy.id: return .preferEntropy
        case "ascii", SudokuAsciiMode.preferAscii.id: return .preferAscii
        default: return SudokuAsciiMode(rawValue: raw)
        }
    }
}

/// How the obfuscated stream is dressed up as HTTP, if at all.
public enum SudokuHttpMaskMode: String, Codable, CaseIterable, Hashable {
    /// A single long POST whose body is the stream.
    case legacy = "legacy"
    case stream = "stream"
    case poll = "poll"
    /// Try `stream`; fall back to `poll` when it does not come up.
    case auto = "auto"
    case ws = "ws"

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .legacy: return "Legacy"
        case .stream: return "Stream"
        case .poll: return "Poll"
        case .auto: return "Auto"
        case .ws: return "WebSocket"
        }
    }

    public static func fromId(_ value: String) -> SudokuHttpMaskMode? {
        SudokuHttpMaskMode(rawValue: LinkText.trim(value).lowercased())
    }
}

/// Whether several proxied streams share one Sudoku connection.
public enum SudokuMultiplex: String, Codable, CaseIterable, Hashable {
    case off = "off"
    case auto = "auto"
    case on = "on"

    public var id: String { rawValue }

    public var displayName: String { id.uppercased() }

    /// Anything unrecognised means off, which is what the reference does.
    public static func fromNormalized(_ value: String) -> SudokuMultiplex {
        switch LinkText.trim(value).lowercased() {
        case "auto": return .auto
        case "on": return .on
        default: return .off
        }
    }
}

/**
 * The HTTP camouflage settings.
 *
 * `host` overrides the `Host` header, and `pathRoot` prefixes every request
 * path so one server can host the tunnel under an innocuous-looking directory.
 */
public struct SudokuHttpMaskConfiguration: Hashable {
    public let disable: Bool
    public let mode: SudokuHttpMaskMode
    public let tls: Bool
    public let host: String
    public let pathRoot: String

    public init(
        disable: Bool = false,
        mode: SudokuHttpMaskMode = .legacy,
        tls: Bool = false,
        host: String = "",
        pathRoot: String = ""
    ) {
        self.disable = disable
        self.mode = mode
        self.tls = tls
        self.host = LinkText.trim(host)
        self.pathRoot = SudokuHttpMaskConfiguration.normalizePathRoot(pathRoot)
    }

    /**
     * Strips surrounding whitespace and slashes, and rejects anything that
     * is not a single unreserved path segment.
     *
     * A rejected root becomes the empty string rather than an error: the
     * root is decoration, and refusing to connect over a mistyped one
     * would be worse than serving the tunnel from the default paths.
     */
    public static func normalizePathRoot(_ raw: String) -> String {
        var bytes = Array(LinkText.trim(raw).utf8)
        while bytes.first == UInt8(ascii: "/") { bytes.removeFirst() }
        while bytes.last == UInt8(ascii: "/") { bytes.removeLast() }
        if bytes.isEmpty { return "" }
        let allowed = bytes.allSatisfy { b in
            (b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 95 || b == 45
        }
        return allowed ? LinkText.string(bytes) : ""
    }
}

/// Which carrier a Nowhere flow direction rides on, by the name a share link uses.
public enum NowhereNetwork: String, Codable, CaseIterable, Hashable {
    case tcp = "tcp"
    case udp = "udp"

    public var wireName: String { rawValue }

    /// Parses the spelling used in a share link's query string.
    public static func fromWireName(_ value: String) -> NowhereNetwork? {
        NowhereNetwork(rawValue: value.lowercased())
    }
}
