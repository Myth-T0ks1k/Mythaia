import Foundation

/**
 * gRPC transport configuration.
 *
 *  - `serviceName` has two interpretations:
 *    * Plain name (e.g. `"example"`) — standard stream names `Tun` / `TunMulti` are used;
 *      path becomes `/<serviceName>/Tun` (or `/TunMulti`).
 *    * Custom path (starts with `/`, e.g. `"/my/service/TunName"`) — treated as the full
 *      path; segments are URL-path-escaped.
 *  - `authority` is the HTTP/2 `:authority` header; when empty it is derived from the TLS
 *    SNI / Reality server name / server address at dial time.
 *  - `multiMode` toggles the `TunMulti` stream (MultiHunk) instead of `Tun` (Hunk). A single
 *    Hunk is wire-compatible with a one-element MultiHunk, so encoding always emits one
 *    data element per message regardless of mode.
 */
public struct GrpcConfiguration: Codable, Hashable {
    public var serviceName: String
    public var authority: String
    public var multiMode: Bool
    public var userAgent: String
    public var initialWindowsSize: Int
    public var idleTimeout: Int
    public var healthCheckTimeout: Int
    public var permitWithoutStream: Bool

    /// Default gRPC service name used when `serviceName` is empty.
    public static let defaultServiceName = "xray.transport.internet.grpc.encoding.GRPCService"

    public init(
        serviceName: String = "",
        authority: String = "",
        multiMode: Bool = false,
        userAgent: String = "",
        initialWindowsSize: Int = 0,
        idleTimeout: Int = 0,
        healthCheckTimeout: Int = 0,
        permitWithoutStream: Bool = false
    ) {
        self.serviceName = serviceName
        self.authority = authority
        self.multiMode = multiMode
        self.userAgent = userAgent
        self.initialWindowsSize = initialWindowsSize
        self.idleTimeout = idleTimeout
        self.healthCheckTimeout = healthCheckTimeout
        self.permitWithoutStream = permitWithoutStream
    }

    private enum CodingKeys: String, CodingKey {
        case serviceName, authority, multiMode, userAgent, initialWindowsSize
        case idleTimeout, healthCheckTimeout, permitWithoutStream
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        serviceName = try c.decodeIfPresent(String.self, forKey: .serviceName) ?? ""
        authority = try c.decodeIfPresent(String.self, forKey: .authority) ?? ""
        multiMode = try c.decodeIfPresent(Bool.self, forKey: .multiMode) ?? false
        userAgent = try c.decodeIfPresent(String.self, forKey: .userAgent) ?? ""
        initialWindowsSize = try c.decodeIfPresent(Int.self, forKey: .initialWindowsSize) ?? 0
        idleTimeout = try c.decodeIfPresent(Int.self, forKey: .idleTimeout) ?? 0
        healthCheckTimeout = try c.decodeIfPresent(Int.self, forKey: .healthCheckTimeout) ?? 0
        permitWithoutStream = try c.decodeIfPresent(Bool.self, forKey: .permitWithoutStream) ?? false
    }

    public static func parse(_ params: [String: String]) -> GrpcConfiguration {
        let mode = (params["mode"] ?? "gun").lowercased()
        let permit = params["permit_without_stream"].map { $0 != "false" && $0 != "0" } ?? false
        return GrpcConfiguration(
            serviceName: params["serviceName"] ?? "",
            authority: params["authority"] ?? "",
            multiMode: mode == "multi",
            userAgent: params["userAgent"] ?? "",
            initialWindowsSize: params["initial_windows_size"].flatMap { Int($0) } ?? 0,
            idleTimeout: params["idle_timeout"].flatMap { Int($0) } ?? 0,
            healthCheckTimeout: params["health_check_timeout"].flatMap { Int($0) } ?? 0,
            permitWithoutStream: permit
        )
    }

    /// HTTP/2 `:authority` value. Priority: explicit config → TLS SNI → Reality SNI → server.
    public func resolvedAuthority(tlsServerName: String?, realityServerName: String?, serverAddress: String) -> String {
        if !authority.isEmpty { return authority }
        if let name = tlsServerName, !name.isEmpty { return name }
        if let name = realityServerName, !name.isEmpty { return name }
        return serverAddress
    }

    /**
     * HTTP/2 `:path` value for this transport.
     *  - Plain `serviceName`: path = `/<url-escaped serviceName>/Tun` (or `/TunMulti`).
     *  - `serviceName` starting with `/`: treated as a full custom path. The part between
     *    the first and last `/` becomes the service path (each segment URL-escaped); the
     *    part after the last `/` is the stream name. For multi mode, if the last segment
     *    contains `|`, the first half is Tun and the second is TunMulti.
     */
    public func resolvedPath() -> String {
        let name = serviceName.isEmpty ? GrpcConfiguration.defaultServiceName : serviceName
        let bytes = Array(name.utf8)
        if bytes.first != UInt8(ascii: "/") {
            let stream = multiMode ? "TunMulti" : "Tun"
            return "/" + GrpcConfiguration.urlPathEscape(name) + "/" + stream
        }

        // As Xray's getServiceName: a lone leading slash is both ends of the service part.
        let lastSlash = max(1, bytes.lastIndex(of: UInt8(ascii: "/")) ?? 0)
        let serviceRaw = LinkText.string(bytes[1..<lastSlash])
        let endingPath = lastSlash + 1 <= bytes.count ? LinkText.string(bytes[(lastSlash + 1)...]) : ""

        let servicePart = LinkText.split(serviceRaw, UInt8(ascii: "/"))
            .map { GrpcConfiguration.urlPathEscape($0) }
            .joined(separator: "/")

        let parts = LinkText.split(endingPath, UInt8(ascii: "|"))
        let streamName: String
        if multiMode {
            streamName = parts.count >= 2 ? parts[1] : parts[0]
        } else {
            streamName = parts[0]
        }

        let prefix = servicePart.isEmpty ? "" : "/" + servicePart
        return prefix + "/" + GrpcConfiguration.urlPathEscape(streamName)
    }

    private static let hexDigits: [UInt8] = Array("0123456789ABCDEF".utf8)

    /**
     * Go's `url.PathEscape`, which Xray applies to each segment of the service
     * name, exactly: unreserved characters (RFC 3986 §2.3: letters, digits,
     * `-_.~`) and the sub-delims `$&+:=@` stay; `/;,?` and every other byte of
     * the UTF-8 form are percent-encoded, uppercase hex. Form encoding escapes
     * `~`, `@`, `:` and friends and keeps `*`, so a service name with any of
     * them asked for a path the server did not serve.
     */
    static func urlPathEscape(_ value: String) -> String {
        let keepSymbols: Set<UInt8> = Set("-_.~$&+:=@".utf8)
        var out: [UInt8] = []
        for c in value.utf8 {
            let keep = c < 0x80 && ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || keepSymbols.contains(c))
            if keep {
                out.append(c)
            } else {
                out.append(UInt8(ascii: "%"))
                out.append(hexDigits[Int(c >> 4)])
                out.append(hexDigits[Int(c & 0x0F)])
            }
        }
        return LinkText.string(out)
    }
}
