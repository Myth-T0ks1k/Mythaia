import Foundation

public struct WebSocketConfiguration: Codable, Hashable {
    public var host: String
    public var path: String
    public var headers: [String: String]
    public var maxEarlyData: Int
    public var earlyDataHeaderName: String
    public var heartbeatPeriod: UInt32

    public init(
        host: String,
        path: String = "/",
        headers: [String: String] = [:],
        maxEarlyData: Int = 0,
        earlyDataHeaderName: String = "Sec-WebSocket-Protocol",
        heartbeatPeriod: UInt32 = 0
    ) {
        self.host = host
        self.path = path
        self.headers = headers
        self.maxEarlyData = maxEarlyData
        self.earlyDataHeaderName = earlyDataHeaderName
        self.heartbeatPeriod = heartbeatPeriod
    }

    private enum CodingKeys: String, CodingKey {
        case host, path, headers, maxEarlyData, earlyDataHeaderName, heartbeatPeriod
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(String.self, forKey: .host)
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? "/"
        headers = try c.decodeIfPresent([String: String].self, forKey: .headers) ?? [:]
        maxEarlyData = try c.decodeIfPresent(Int.self, forKey: .maxEarlyData) ?? 0
        earlyDataHeaderName = try c.decodeIfPresent(String.self, forKey: .earlyDataHeaderName) ?? "Sec-WebSocket-Protocol"
        heartbeatPeriod = try c.decodeIfPresent(UInt32.self, forKey: .heartbeatPeriod) ?? 0
    }

    public static func parse(_ params: [String: String], serverAddress: String) -> WebSocketConfiguration {
        // parseQueryParams has already percent-decoded every value; a
        // second pass would turn a literal "%20" in the path into a space.
        let host = ShareLinkParams.nonEmpty(params["host"]) ?? serverAddress
        let path = ShareLinkParams.nonEmpty(params["path"]) ?? "/"
        let maxEarlyData = params["ed"].flatMap { Int($0) } ?? 0
        let earlyDataHeader = ShareLinkParams.nonEmpty(params["eh"]) ?? "Sec-WebSocket-Protocol"
        return WebSocketConfiguration(
            host: host,
            path: path,
            maxEarlyData: maxEarlyData,
            earlyDataHeaderName: earlyDataHeader
        )
    }
}

public struct HttpUpgradeConfiguration: Codable, Hashable {
    public var host: String
    public var path: String
    public var headers: [String: String]

    public init(host: String, path: String = "/", headers: [String: String] = [:]) {
        self.host = host
        self.path = path
        self.headers = headers
    }

    private enum CodingKeys: String, CodingKey {
        case host, path, headers
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(String.self, forKey: .host)
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? "/"
        headers = try c.decodeIfPresent([String: String].self, forKey: .headers) ?? [:]
    }

    public static func parse(_ params: [String: String], serverAddress: String) -> HttpUpgradeConfiguration {
        let host = ShareLinkParams.nonEmpty(params["host"]) ?? serverAddress
        var path = ShareLinkParams.nonEmpty(params["path"]) ?? "/"
        if !LinkText.hasPrefix(path, "/") { path = "/" + path }
        return HttpUpgradeConfiguration(host: host, path: path)
    }
}

public enum XHttpMode: String, Codable, CaseIterable, Hashable {
    case auto = "auto"
    case streamOne = "stream-one"
    case packetUp = "packet-up"
    case streamUp = "stream-up"

    public var raw: String { rawValue }

    public var displayName: String {
        switch self {
        case .auto: return "Auto"
        case .streamOne: return "Stream One"
        case .packetUp: return "Packet Up"
        case .streamUp: return "Stream Up"
        }
    }

    public static func fromRaw(_ value: String) -> XHttpMode {
        XHttpMode(rawValue: value) ?? .auto
    }
}

/// Metadata placement for session ID, sequence numbers, and padding.
public enum XHttpPlacement: String, Codable, CaseIterable, Hashable {
    case path = "path"
    case query = "query"
    case header = "header"
    case cookie = "cookie"
    case queryInHeader = "queryInHeader"
    case body = "body"

    public var raw: String { rawValue }

    public static func fromRaw(_ value: String) -> XHttpPlacement {
        XHttpPlacement(rawValue: value) ?? .queryInHeader
    }
}

/// X-Padding generation method.
public enum XHttpPaddingMethod: String, Codable, CaseIterable, Hashable {
    case repeatX = "repeat-x"
    case tokenish = "tokenish"

    public var raw: String { rawValue }

    public static func fromRaw(_ value: String) -> XHttpPaddingMethod {
        XHttpPaddingMethod(rawValue: value) ?? .repeatX
    }
}

public struct XHttpConfiguration: Codable, Hashable {
    public var host: String
    public var path: String
    public var mode: XHttpMode
    public var headers: [String: String]
    public var noGrpcHeader: Bool
    public var scMaxEachPostBytes: Int
    public var scMinPostsIntervalMs: Int
    public var xPaddingBytesFrom: Int
    public var xPaddingBytesTo: Int
    public var xPaddingObfsMode: Bool
    public var xPaddingKey: String
    public var xPaddingHeader: String
    public var xPaddingPlacement: XHttpPlacement
    public var xPaddingMethod: XHttpPaddingMethod
    public var uplinkHTTPMethod: String
    public var sessionPlacement: XHttpPlacement
    public var sessionKey: String
    public var seqPlacement: XHttpPlacement
    public var seqKey: String
    public var uplinkDataPlacement: XHttpPlacement
    public var uplinkDataKey: String
    public var uplinkChunkSize: Int

    public init(
        host: String,
        path: String = "/",
        mode: XHttpMode = .auto,
        headers: [String: String] = [:],
        noGrpcHeader: Bool = false,
        scMaxEachPostBytes: Int = 1_000_000,
        scMinPostsIntervalMs: Int = 30,
        xPaddingBytesFrom: Int = 100,
        xPaddingBytesTo: Int = 1000,
        xPaddingObfsMode: Bool = false,
        xPaddingKey: String = "x_padding",
        xPaddingHeader: String = "X-Padding",
        xPaddingPlacement: XHttpPlacement = .queryInHeader,
        xPaddingMethod: XHttpPaddingMethod = .repeatX,
        uplinkHTTPMethod: String = "POST",
        sessionPlacement: XHttpPlacement = .path,
        sessionKey: String = "",
        seqPlacement: XHttpPlacement = .path,
        seqKey: String = "",
        uplinkDataPlacement: XHttpPlacement = .body,
        uplinkDataKey: String = "",
        uplinkChunkSize: Int = 0
    ) {
        self.host = host
        self.path = path
        self.mode = mode
        self.headers = headers
        self.noGrpcHeader = noGrpcHeader
        self.scMaxEachPostBytes = scMaxEachPostBytes
        self.scMinPostsIntervalMs = scMinPostsIntervalMs
        self.xPaddingBytesFrom = xPaddingBytesFrom
        self.xPaddingBytesTo = xPaddingBytesTo
        self.xPaddingObfsMode = xPaddingObfsMode
        self.xPaddingKey = xPaddingKey
        self.xPaddingHeader = xPaddingHeader
        self.xPaddingPlacement = xPaddingPlacement
        self.xPaddingMethod = xPaddingMethod
        self.uplinkHTTPMethod = uplinkHTTPMethod
        self.sessionPlacement = sessionPlacement
        self.sessionKey = sessionKey
        self.seqPlacement = seqPlacement
        self.seqKey = seqKey
        self.uplinkDataPlacement = uplinkDataPlacement
        self.uplinkDataKey = uplinkDataKey
        self.uplinkChunkSize = uplinkChunkSize
    }

    private enum CodingKeys: String, CodingKey {
        case host, path, mode, headers
        case noGrpcHeader = "noGRPCHeader"
        case scMaxEachPostBytes, scMinPostsIntervalMs, xPaddingBytesFrom, xPaddingBytesTo
        case xPaddingObfsMode, xPaddingKey, xPaddingHeader, xPaddingPlacement, xPaddingMethod
        case uplinkHTTPMethod, sessionPlacement, sessionKey, seqPlacement, seqKey
        case uplinkDataPlacement, uplinkDataKey, uplinkChunkSize
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(String.self, forKey: .host)
        path = try c.decodeIfPresent(String.self, forKey: .path) ?? "/"
        mode = (try? c.decodeIfPresent(XHttpMode.self, forKey: .mode)) ?? .auto
        headers = try c.decodeIfPresent([String: String].self, forKey: .headers) ?? [:]
        noGrpcHeader = try c.decodeIfPresent(Bool.self, forKey: .noGrpcHeader) ?? false
        scMaxEachPostBytes = try c.decodeIfPresent(Int.self, forKey: .scMaxEachPostBytes) ?? 1_000_000
        scMinPostsIntervalMs = try c.decodeIfPresent(Int.self, forKey: .scMinPostsIntervalMs) ?? 30
        xPaddingBytesFrom = try c.decodeIfPresent(Int.self, forKey: .xPaddingBytesFrom) ?? 100
        xPaddingBytesTo = try c.decodeIfPresent(Int.self, forKey: .xPaddingBytesTo) ?? 1000
        xPaddingObfsMode = try c.decodeIfPresent(Bool.self, forKey: .xPaddingObfsMode) ?? false
        xPaddingKey = try c.decodeIfPresent(String.self, forKey: .xPaddingKey) ?? "x_padding"
        xPaddingHeader = try c.decodeIfPresent(String.self, forKey: .xPaddingHeader) ?? "X-Padding"
        xPaddingPlacement = (try? c.decodeIfPresent(XHttpPlacement.self, forKey: .xPaddingPlacement)) ?? .queryInHeader
        xPaddingMethod = (try? c.decodeIfPresent(XHttpPaddingMethod.self, forKey: .xPaddingMethod)) ?? .repeatX
        uplinkHTTPMethod = try c.decodeIfPresent(String.self, forKey: .uplinkHTTPMethod) ?? "POST"
        sessionPlacement = (try? c.decodeIfPresent(XHttpPlacement.self, forKey: .sessionPlacement)) ?? .path
        sessionKey = try c.decodeIfPresent(String.self, forKey: .sessionKey) ?? ""
        seqPlacement = (try? c.decodeIfPresent(XHttpPlacement.self, forKey: .seqPlacement)) ?? .path
        seqKey = try c.decodeIfPresent(String.self, forKey: .seqKey) ?? ""
        uplinkDataPlacement = (try? c.decodeIfPresent(XHttpPlacement.self, forKey: .uplinkDataPlacement)) ?? .body
        uplinkDataKey = try c.decodeIfPresent(String.self, forKey: .uplinkDataKey) ?? ""
        uplinkChunkSize = try c.decodeIfPresent(Int.self, forKey: .uplinkChunkSize) ?? 0
    }

    public var normalizedPath: String {
        var p = XHttpConfiguration.splitPath(path).path
        if !LinkText.hasPrefix(p, "/") { p = "/" + p }
        if !LinkText.hasSuffix(p, "/") { p += "/" }
        return p
    }

    public var normalizedQuery: String {
        XHttpConfiguration.splitPath(path).query ?? ""
    }

    private static func splitPath(_ path: String) -> (path: String, query: String?) {
        let bytes = Array(path.utf8)
        guard let q = bytes.firstIndex(of: UInt8(ascii: "?")) else { return (path, nil) }
        return (LinkText.string(bytes[..<q]), LinkText.string(bytes[(q + 1)...]))
    }

    /// Normalized session key, auto-determined by placement if not set.
    public var normalizedSessionKey: String {
        if !sessionKey.isEmpty { return sessionKey }
        switch sessionPlacement {
        case .header: return "X-Session"
        case .cookie, .query: return "x_session"
        default: return ""
        }
    }

    /// Normalized seq key, auto-determined by placement if not set.
    public var normalizedSeqKey: String {
        if !seqKey.isEmpty { return seqKey }
        switch seqPlacement {
        case .header: return "X-Seq"
        case .cookie, .query: return "x_seq"
        default: return ""
        }
    }

    public func generatePadding() -> String {
        // A hand-edited range written backwards is read as the range it names.
        let low = min(xPaddingBytesFrom, xPaddingBytesTo)
        let high = max(xPaddingBytesFrom, xPaddingBytesTo)
        let length = Int.random(in: max(0, low)...max(0, high))
        switch xPaddingMethod {
        case .repeatX:
            return String(repeating: "X", count: length)
        case .tokenish:
            return XHttpConfiguration.generateTokenishPadding(length)
        }
    }

    public func toExtraJson() -> String {
        var parts: [String] = []
        if noGrpcHeader { parts.append("\"noGRPCHeader\":true") }
        if scMaxEachPostBytes != 1_000_000 { parts.append("\"scMaxEachPostBytes\":\(scMaxEachPostBytes)") }
        if scMinPostsIntervalMs != 30 { parts.append("\"scMinPostsIntervalMs\":\(scMinPostsIntervalMs)") }
        if xPaddingBytesFrom != 100 { parts.append("\"xPaddingBytesFrom\":\(xPaddingBytesFrom)") }
        if xPaddingBytesTo != 1000 { parts.append("\"xPaddingBytesTo\":\(xPaddingBytesTo)") }
        if xPaddingObfsMode { parts.append("\"xPaddingObfsMode\":true") }
        if xPaddingKey != "x_padding" { parts.append("\"xPaddingKey\":" + ImportJSON.quote(xPaddingKey)) }
        if xPaddingHeader != "X-Padding" { parts.append("\"xPaddingHeader\":" + ImportJSON.quote(xPaddingHeader)) }
        if xPaddingPlacement != .queryInHeader { parts.append("\"xPaddingPlacement\":\"\(xPaddingPlacement.raw)\"") }
        if xPaddingMethod != .repeatX { parts.append("\"xPaddingMethod\":\"\(xPaddingMethod.raw)\"") }
        if uplinkHTTPMethod != "POST" { parts.append("\"uplinkHTTPMethod\":" + ImportJSON.quote(uplinkHTTPMethod)) }
        if sessionPlacement != .path { parts.append("\"sessionPlacement\":\"\(sessionPlacement.raw)\"") }
        if !sessionKey.isEmpty { parts.append("\"sessionKey\":" + ImportJSON.quote(sessionKey)) }
        if seqPlacement != .path { parts.append("\"seqPlacement\":\"\(seqPlacement.raw)\"") }
        if !seqKey.isEmpty { parts.append("\"seqKey\":" + ImportJSON.quote(seqKey)) }
        if uplinkDataPlacement != .body { parts.append("\"uplinkDataPlacement\":\"\(uplinkDataPlacement.raw)\"") }
        if !uplinkDataKey.isEmpty { parts.append("\"uplinkDataKey\":" + ImportJSON.quote(uplinkDataKey)) }
        if uplinkChunkSize != 0 { parts.append("\"uplinkChunkSize\":\(uplinkChunkSize)") }
        if !headers.isEmpty {
            // Sorted, so one configuration always writes one link.
            let entries = headers.keys.sorted().map { key -> String in
                ImportJSON.quote(key) + ":" + ImportJSON.quote(headers[key] ?? "")
            }
            parts.append("\"headers\":{" + entries.joined(separator: ",") + "}")
        }
        return parts.isEmpty ? "" : "{" + parts.joined(separator: ",") + "}"
    }

    public static func parse(_ params: [String: String], serverAddress: String) -> XHttpConfiguration {
        let host = ShareLinkParams.nonEmpty(params["host"]) ?? serverAddress
        let path = ShareLinkParams.nonEmpty(params["path"]) ?? "/"
        let mode = XHttpMode.fromRaw(params["mode"] ?? "auto")
        // Panels differ on how many times they percent-encode the JSON;
        // parseQueryParams decoded once, so a value still starting with
        // "%7B" was encoded twice.
        var extra = params["extra"] ?? ""
        if LinkText.hasPrefix(extra, "%7B", ignoreCase: true) { extra = percentDecode(extra) }
        if !LinkText.isBlank(extra) {
            return fromExtraJson(host: host, path: path, mode: mode, extraJson: extra)
        }
        return XHttpConfiguration(host: host, path: path, mode: mode)
    }

    public static func fromExtraJson(host: String, path: String, mode: XHttpMode, extraJson: String) -> XHttpConfiguration {
        if LinkText.isBlank(extraJson) { return XHttpConfiguration(host: host, path: path, mode: mode) }
        guard let json = try? ImportJSON.parseObject(extraJson) else {
            return XHttpConfiguration(host: host, path: path, mode: mode)
        }

        // Panels write these as numbers, as "500000", as "100-1000",
        // or as {"from":N,"to":N}; all four are the same statement.
        let scMaxEachPostBytes = xrayRange(json.opt("scMaxEachPostBytes"))?.to ?? 1_000_000
        let scMinPostsIntervalMs = xrayRange(json.opt("scMinPostsIntervalMs"))?.to ?? 30

        var xPaddingFrom = 100
        var xPaddingTo = 1000
        if let range = xrayRange(json.opt("xPaddingBytes")) {
            xPaddingFrom = range.from
            xPaddingTo = range.to
        }
        // Also accept flat xPaddingBytesFrom/xPaddingBytesTo keys.
        if !json.has("xPaddingBytes") {
            xPaddingFrom = json.optInt("xPaddingBytesFrom", xPaddingFrom)
            xPaddingTo = json.optInt("xPaddingBytesTo", xPaddingTo)
        }

        let uplinkDataPlacement = XHttpPlacement.fromRaw(json.optString("uplinkDataPlacement", "body"))
        let defaultUplinkDataKey: String
        let defaultUplinkChunkSize: Int
        switch uplinkDataPlacement {
        case .header:
            defaultUplinkDataKey = "X-Data"
            defaultUplinkChunkSize = 4096
        case .cookie:
            defaultUplinkDataKey = "x_data"
            defaultUplinkChunkSize = 3072
        default:
            defaultUplinkDataKey = ""
            defaultUplinkChunkSize = 0
        }

        var headers: [String: String] = [:]
        if let h = json.optObject("headers") {
            for key in h.keys {
                headers[key] = h.optString(key, "")
            }
        }

        return XHttpConfiguration(
            host: host,
            path: path,
            mode: mode,
            headers: headers,
            noGrpcHeader: json.optBoolean("noGRPCHeader", false),
            scMaxEachPostBytes: scMaxEachPostBytes,
            scMinPostsIntervalMs: scMinPostsIntervalMs,
            xPaddingBytesFrom: xPaddingFrom,
            xPaddingBytesTo: xPaddingTo,
            xPaddingObfsMode: json.optBoolean("xPaddingObfsMode", false),
            xPaddingKey: json.optString("xPaddingKey", "x_padding"),
            xPaddingHeader: json.optString("xPaddingHeader", "X-Padding"),
            xPaddingPlacement: XHttpPlacement.fromRaw(json.optString("xPaddingPlacement", "queryInHeader")),
            xPaddingMethod: XHttpPaddingMethod.fromRaw(json.optString("xPaddingMethod", "repeat-x")),
            uplinkHTTPMethod: json.optString("uplinkHTTPMethod", "POST"),
            sessionPlacement: XHttpPlacement.fromRaw(json.optString("sessionPlacement", "path")),
            sessionKey: json.optString("sessionKey", ""),
            seqPlacement: XHttpPlacement.fromRaw(json.optString("seqPlacement", "path")),
            seqKey: json.optString("seqKey", ""),
            uplinkDataPlacement: uplinkDataPlacement,
            uplinkDataKey: json.optString("uplinkDataKey", defaultUplinkDataKey),
            uplinkChunkSize: json.optInt("uplinkChunkSize", defaultUplinkChunkSize)
        )
    }

    /**
     * An Xray Int32Range in any of its spellings — `500`, `"500"`,
     * `"100-1000"`, `{"from":100,"to":1000}` — as (from, to). Nil when
     * absent or unreadable.
     */
    static func xrayRange(_ value: ImportJSON?) -> (from: Int, to: Int)? {
        guard let value = value else { return nil }
        switch value {
        case .object(let object):
            let missing = Int(Int32.min)
            let to = object.optInt("to", missing)
            let from = object.optInt("from", to)
            return to == missing ? nil : (from, to)
        case .number:
            guard let n = value.intValue else { return nil }
            return (n, n)
        case .string(let s):
            let t = LinkText.trim(s)
            let bytes = Array(t.utf8)
            // Searched from the second character, so a negative number is not a range.
            var dash: Int? = nil
            if bytes.count > 1 {
                dash = bytes[1...].firstIndex(of: UInt8(ascii: "-"))
            }
            if let dash = dash, dash > 0 {
                let from = Int(LinkText.trim(LinkText.string(bytes[..<dash])))
                let to = Int(LinkText.trim(LinkText.string(bytes[(dash + 1)...])))
                if let from = from, let to = to { return (from, to) }
                return nil
            }
            guard let n = Int(t) else { return nil }
            return (n, n)
        default:
            return nil
        }
    }

    private static let tokenishChars: [Character] = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

    /**
     * Generates pseudo-random alphanumeric padding that looks like a token.
     * Target Huffman byte length: ceil(length / 0.8) to compensate for
     * HTTP/2 Huffman compression.
     */
    public static func generateTokenishPadding(_ length: Int) -> String {
        let charCount = Int((Double(length) / 0.8).rounded(.up))
        var generator = SystemRandomNumberGenerator()
        var out = ""
        out.reserveCapacity(max(0, charCount))
        var i = 0
        while i < charCount {
            let index = Int.random(in: 0..<tokenishChars.count, using: &generator)
            out.append(tokenishChars[index])
            i += 1
        }
        return out
    }
}
