import Foundation
import CryptoKit

/// The `proxies:` list of a Clash (mihomo) config.
public enum ClashProxyParser {

    public struct ParseResult {
        public var configurations: [ProxyConfiguration]
        public var skippedCount: Int
    }

    public static func parse(_ yamlString: String) throws -> ParseResult {
        guard let document = ClashYAML.parse(yamlString) else {
            throw MythaiaError.parse("Invalid Clash YAML: Failed to parse YAML document")
        }
        guard let root = document.objectValue else {
            throw MythaiaError.parse("Invalid Clash YAML: Root document is not a mapping")
        }
        guard let proxies = root.optArray("proxies") else {
            throw MythaiaError.parse("Clash YAML is missing 'proxies' key.")
        }

        var configurations: [ProxyConfiguration] = []
        var skippedCount = 0
        for element in proxies {
            if let proxy = element.objectValue, let config = parseProxy(proxy) {
                configurations.append(config)
            } else {
                skippedCount += 1
            }
        }
        return ParseResult(configurations: configurations, skippedCount: skippedCount)
    }

    /**
     * The `server` field with any URL-style brackets removed: Clash accepts
     * `[2001:db8::1]`, but the address is stored bare and bracketed again on
     * export, which would otherwise double up.
     */
    private static func serverOf(_ node: ImportJSONObject) -> String? {
        let raw = LinkText.trim(node.optString("server"))
        if raw.isEmpty { return nil }
        if LinkText.hasPrefix(raw, "[") && LinkText.hasSuffix(raw, "]") {
            return LinkText.removeSuffix(LinkText.removePrefix(raw, "["), "]")
        }
        return raw
    }

    /// The `port` field when it is a usable port.
    private static func portOf(_ node: ImportJSONObject) -> UInt16? {
        let port = node.optInt("port", -1)
        if port <= 0 || port > Int(UInt16.max) { return nil }
        return UInt16(port)
    }

    /// A list of non-empty strings, or nil for none.
    private static func alpnOf(_ node: ImportJSONObject) -> [String]? {
        guard let array = node.optArray("alpn") else { return nil }
        var out: [String] = []
        for index in 0..<array.count {
            let value = array.optString(index)
            if !value.isEmpty { out.append(value) }
        }
        return out.isEmpty ? nil : out
    }

    private static func parseProxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        let proxyType = node.optString("type")
        if proxyType == "ss" { return parseShadowsocksProxy(node) }
        if proxyType == "socks5" || proxyType == "socks" { return parseSocks5Proxy(node) }
        if proxyType == "trojan" { return parseTrojanProxy(node) }
        if proxyType == "hysteria2" || proxyType == "hy2" { return parseHysteria2Proxy(node) }
        if proxyType == "anytls" { return parseAnyTlsProxy(node) }
        if proxyType == "vmess" { return parseVmessProxy(node) }
        if proxyType != "vless" { return nil }

        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let uuidString = ShareLinkParams.nonEmpty(node.optString("uuid")),
              let uuid = parseXrayUuid(uuidString) else { return nil }
        guard let port = portOf(node) else { return nil }

        // Transport: tcp (default) or ws. Anything else (h2, grpc, httpupgrade,
        // xhttp, kcp) is skipped rather than imported as TCP, which would give
        // a server that can never connect.
        let network = ShareLinkParams.nonEmpty(node.optString("network")) ?? "tcp"
        let transport: String
        switch network {
        case "tcp": transport = "tcp"
        case "ws": transport = "ws"
        default: return nil
        }

        let encryption = node.optString("encryption", "none")
        let flow = ShareLinkParams.nonEmpty(node.optString("flow", ""))

        // Security: reality > tls > none
        let tlsEnabled = node.optBoolean("tls", false)
        let realityOpts = node.optObject("reality-opts")
        let security: String
        if realityOpts != nil {
            security = "reality"
        } else if tlsEnabled {
            security = "tls"
        } else {
            security = "none"
        }

        // Common TLS/Reality fields
        let serverName = ShareLinkParams.nonEmpty(node.optString("servername", ""))
            ?? ShareLinkParams.nonEmpty(node.optString("sni", ""))
            ?? server
        let skipCertVerify = node.optBoolean("skip-cert-verify", false)
        let clientFP = ShareLinkParams.nonEmpty(node.optString("client-fingerprint", ""))
        let fingerprint = TlsFingerprint.fromRaw(mapFingerprint(clientFP))
        let alpn = alpnOf(node)

        var tlsConfig: TlsConfiguration? = nil
        if security == "tls" {
            tlsConfig = TlsConfiguration(
                serverName: serverName,
                alpn: alpn,
                allowInsecure: skipCertVerify,
                fingerprint: fingerprint
            )
        }

        var realityConfig: RealityConfiguration? = nil
        if security == "reality", let opts = realityOpts {
            let pubKeyStr = opts.optString("public-key", "")
            let shortIdStr = opts.optString("short-id", "")
            guard let publicKey = LinkText.base64UrlToData(pubKeyStr), publicKey.count == 32 else { return nil }
            realityConfig = RealityConfiguration(
                serverName: serverName,
                publicKey: publicKey,
                shortId: LinkText.hexDecode(shortIdStr) ?? Data(),
                fingerprint: fingerprint
            )
        }

        var wsConfig: WebSocketConfiguration? = nil
        var httpUpgradeConfig: HttpUpgradeConfiguration? = nil
        if transport == "ws" {
            var wsPath = "/"
            var wsHost = server
            var wsHeaders: [String: String] = [:]
            var maxEarlyData = 0
            var earlyDataHeaderName = ""
            var isHttpUpgrade = false

            if let wo = node.optObject("ws-opts") {
                wsPath = wo.optString("path", "/")
                // v2ray-http-upgrade flag: treat as HTTPUpgrade instead of WebSocket
                isHttpUpgrade = wo.optBoolean("v2ray-http-upgrade", false)
                maxEarlyData = wo.optInt("max-early-data", 0)
                earlyDataHeaderName = wo.optString("early-data-header-name", "")
                if let headers = wo.optObject("headers") {
                    for key in headers.keys {
                        let value = headers.optString(key, "")
                        wsHeaders[key] = value
                        if key.lowercased() == "host" { wsHost = value }
                    }
                }
            }

            if isHttpUpgrade {
                httpUpgradeConfig = HttpUpgradeConfiguration(host: wsHost, path: wsPath, headers: wsHeaders)
            } else {
                wsConfig = WebSocketConfiguration(
                    host: wsHost,
                    path: wsPath,
                    headers: wsHeaders,
                    maxEarlyData: maxEarlyData,
                    earlyDataHeaderName: earlyDataHeaderName.isEmpty ? "Sec-WebSocket-Protocol" : earlyDataHeaderName
                )
            }
        }

        let effectiveTransport = httpUpgradeConfig != nil ? "httpupgrade" : transport

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: uuid,
            encryption: encryption,
            transport: effectiveTransport,
            flow: flow,
            security: security,
            tls: tlsConfig,
            reality: realityConfig,
            websocket: wsConfig,
            httpUpgrade: httpUpgradeConfig
        )
    }

    /**
     * Parses a Clash `type: ss` node. Only bare Shadowsocks is spoken — any
     * plugin (obfs, v2ray-plugin, shadow-tls, restls), configured transport
     * other than plain TCP, or TLS wrapper causes the node to be skipped rather
     * than silently downgraded.
     */
    private static func parseShadowsocksProxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let password = ShareLinkParams.nonEmpty(node.optString("password")) else { return nil }
        guard let cipher = ShareLinkParams.nonEmpty(node.optString("cipher")) else { return nil }
        guard ProxyConfiguration.isSupportedShadowsocksMethod(cipher) else { return nil }
        guard let port = portOf(node) else { return nil }

        let network = ShareLinkParams.nonEmpty(node.optString("network", "")) ?? node.optString("plugin-opts-network", "tcp")
        if network != "tcp" { return nil }
        if node.optBoolean("tls", false) { return nil }
        if !node.optString("plugin", "").isEmpty { return nil }

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(),
            encryption: "none",
            transport: "tcp",
            security: "none",
            outboundProtocol: .shadowsocks,
            ssPassword: password,
            ssMethod: cipher
        )
    }

    /**
     * Parses a Clash `type: trojan` node into a Trojan outbound. Reality, ECH,
     * gRPC, the Trojan-Go SS layer, and any transport other than bare TCP
     * cause the node to be skipped rather than silently downgraded to a
     * different wire format.
     */
    private static func parseTrojanProxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let password = ShareLinkParams.nonEmpty(node.optString("password")) else { return nil }
        guard let port = portOf(node) else { return nil }

        if node.optString("network", "tcp") != "tcp" { return nil }
        if node.optObject("reality-opts") != nil { return nil }
        if node.optObject("ech-opts") != nil { return nil }
        if node.optObject("grpc-opts") != nil { return nil }
        if let ssOpts = node.optObject("ss-opts"), ssOpts.optBoolean("enabled", false) { return nil }

        let sni = ShareLinkParams.nonEmpty(node.optString("servername", ""))
            ?? ShareLinkParams.nonEmpty(node.optString("sni", ""))
            ?? server
        let clientFP = ShareLinkParams.nonEmpty(node.optString("client-fingerprint", ""))
        let tls = TlsConfiguration(
            serverName: sni,
            alpn: alpnOf(node),
            allowInsecure: node.optBoolean("skip-cert-verify", false),
            fingerprint: TlsFingerprint.fromRaw(mapFingerprint(clientFP))
        )

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for Trojan
            encryption: "none",
            transport: "tcp",
            security: "tls",
            tls: tls,
            outboundProtocol: .trojan,
            trojanPassword: password,
            trojanTls: tls
        )
    }

    /**
     * Clash `type: hysteria2`.
     *
     * Hysteria2 runs over QUIC, so there is no `network` to honour and TLS is
     * not optional.
     */
    private static func parseHysteria2Proxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let password = ShareLinkParams.nonEmpty(node.optString("password"))
            ?? ShareLinkParams.nonEmpty(node.optString("auth")) else { return nil }
        guard let port = portOf(node) else { return nil }

        // A port range means the server hops between ports, which this
        // client does not do. Better skipped than imported as something that
        // cannot connect.
        if !node.optString("ports", "").isEmpty { return nil }

        var obfuscation: String? = nil
        let obfs = node.optString("obfs", "")
        // `obfs: none` means no obfuscation, not a type to refuse at dial.
        if !obfs.isEmpty && obfs.lowercased() != "none" { obfuscation = obfs.lowercased() }
        let obfuscationPassword = node.optObject("obfs-password")?.serialized()
            ?? ShareLinkParams.nonEmpty(node.optString("obfs-password", ""))

        // Clash spells the bandwidth `up`/`down` and allows a unit suffix;
        // only a plain number is meaningful here, and absence stays absence.
        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(), // placeholder; Hysteria2 authenticates by password
            encryption: "none",
            transport: "tcp",
            security: "tls",
            tls: passwordProtocolTls(node, server: server),
            outboundProtocol: .hysteria2,
            password: password,
            hysteriaUpMbps: bandwidthMbps(node, "up"),
            hysteriaDownMbps: bandwidthMbps(node, "down"),
            obfuscation: obfuscation,
            obfuscationPassword: obfuscationPassword
        )
    }

    /**
     * Clash `type: vmess`.
     *
     * `alterId` must be 0. A non-zero value selects the legacy
     * MD5-authenticated header that v2ray removed in 2022; importing such a
     * node would produce an entry that can never authenticate, so it is
     * skipped instead.
     */
    private static func parseVmessProxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let uuidString = ShareLinkParams.nonEmpty(node.optString("uuid")),
              let uuid = parseXrayUuid(uuidString) else { return nil }
        guard let port = portOf(node) else { return nil }

        if node.optInt("alterId", 0) != 0 { return nil }

        // Reality is a different handshake, not a variant of TLS. Importing the
        // node without it would produce an entry that looks fine and can never
        // connect, so it is skipped and counted as unsupported instead.
        if node.optObject("reality-opts") != nil { return nil }

        let transport: String
        switch node.optString("network", "tcp") {
        case "ws": transport = "ws"
        case "tcp": transport = "tcp"
        default: return nil
        }

        // `v2ray-http-upgrade` means the node speaks HTTP Upgrade, not
        // WebSocket: no frame headers and no masking. Importing it as a
        // WebSocket would put frame headers on the wire that the server does
        // not expect.
        let wsOpts = node.optObject("ws-opts")
        if wsOpts?.optBoolean("v2ray-http-upgrade", false) == true { return nil }

        let useTls = node.optBoolean("tls", false)
        let wsHeaders = wsOpts?.optObject("headers")
        let wsHost = ShareLinkParams.nonEmpty(wsHeaders?.optString("Host"))
            ?? ShareLinkParams.nonEmpty(wsHeaders?.optString("host"))

        var websocket: WebSocketConfiguration? = nil
        if transport == "ws" {
            websocket = WebSocketConfiguration(
                host: wsHost ?? server,
                path: ShareLinkParams.nonEmpty(wsOpts?.optString("path")) ?? "/"
            )
        }

        var tls: TlsConfiguration? = nil
        if useTls {
            let sni = ShareLinkParams.nonEmpty(node.optString("servername", ""))
                ?? ShareLinkParams.nonEmpty(node.optString("sni", ""))
                ?? wsHost
                ?? server
            tls = TlsConfiguration(
                serverName: sni,
                allowInsecure: node.optBoolean("skip-cert-verify", false),
                fingerprint: TlsFingerprint.fromRaw(
                    mapFingerprint(ShareLinkParams.nonEmpty(node.optString("client-fingerprint", "")))
                )
            )
        }

        let cipher = node.optString("cipher", "")
        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: uuid,
            encryption: "none",
            transport: transport,
            security: useTls ? "tls" : "none",
            tls: tls,
            websocket: websocket,
            outboundProtocol: .vmess,
            vmessSecurity: (cipher.isEmpty || cipher == "auto") ? nil : cipher
        )
    }

    /// Clash `type: anytls`. TLS is mandatory.
    private static func parseAnyTlsProxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let password = ShareLinkParams.nonEmpty(node.optString("password")) else { return nil }
        guard let port = portOf(node) else { return nil }

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(), // placeholder; AnyTLS authenticates by password
            encryption: "none",
            transport: "tcp",
            security: "tls",
            tls: passwordProtocolTls(node, server: server),
            outboundProtocol: .anytls,
            password: password
        )
    }

    /// The TLS block the password-authenticated Clash types share.
    private static func passwordProtocolTls(_ node: ImportJSONObject, server: String) -> TlsConfiguration {
        let sni = ShareLinkParams.nonEmpty(node.optString("sni", ""))
            ?? ShareLinkParams.nonEmpty(node.optString("servername", ""))
            ?? server
        let clientFP = ShareLinkParams.nonEmpty(node.optString("client-fingerprint", ""))
        return TlsConfiguration(
            serverName: sni,
            alpn: alpnOf(node),
            allowInsecure: node.optBoolean("skip-cert-verify", false),
            fingerprint: TlsFingerprint.fromRaw(mapFingerprint(clientFP))
        )
    }

    /**
     * Clash writes Hysteria2 bandwidth as a bare number or with a unit
     * (`100 mbps`, `50mbps`). Anything else is left nil, which is what tells
     * the client to use BBR rather than Brutal.
     */
    private static func bandwidthMbps(_ node: ImportJSONObject, _ key: String) -> Int? {
        guard let raw = node.opt(key) else { return nil }
        if case .number = raw {
            guard let value = raw.intValue, value > 0 else { return nil }
            return value
        }
        let text = LinkText.trim(raw.text).lowercased()
        let digits = String(text.prefix(while: { $0 >= "0" && $0 <= "9" }))
        if digits.isEmpty { return nil }
        guard let value = Int(digits), value > 0 else { return nil }
        let unit = LinkText.trim(String(text.dropFirst(digits.count)))
        switch unit {
        case "", "m", "mb", "mbps": return value
        case "g", "gb", "gbps": return value * 1000
        case "k", "kb", "kbps": return value / 1000 > 0 ? value / 1000 : nil
        default: return nil
        }
    }

    private static func parseSocks5Proxy(_ node: ImportJSONObject) -> ProxyConfiguration? {
        guard let name = ShareLinkParams.nonEmpty(node.optString("name")) else { return nil }
        guard let server = serverOf(node) else { return nil }
        guard let port = portOf(node) else { return nil }

        // SOCKS5 is spoken strictly in the clear — reject SOCKS5-over-TLS
        // nodes rather than silently downgrading them.
        if node.optBoolean("tls", false) { return nil }

        // Some Clash forks use snake_case (user/pass) instead of username/password.
        let username = ShareLinkParams.nonEmpty(node.optString("username", ""))
            ?? ShareLinkParams.nonEmpty(node.optString("user", ""))
        let password = ShareLinkParams.nonEmpty(node.optString("password", ""))
            ?? ShareLinkParams.nonEmpty(node.optString("pass", ""))

        return ProxyConfiguration(
            name: name,
            serverAddress: server,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for SOCKS5
            encryption: "none",
            outboundProtocol: .socks5,
            socks5Username: username,
            socks5Password: password
        )
    }

    /**
     * Parses a UUID the way Xray-core does (common/uuid/uuid.go ParseString):
     * length 32–36 is hex/standard-form decoded; length 1–30 is derived as
     * `SHA1(zero_uuid || input)[0..16]` with RFC 4122 v5 + variant bits stamped.
     */
    static func parseXrayUuid(_ str: String) -> UUID? {
        let length = str.count
        if length >= 32 && length <= 36 {
            if let uuid = UUID(uuidString: str) { return uuid }
            if length == 32, let bytes = LinkText.hexDecode(str), bytes.count == 16 {
                return uuidFromBytes(Array(bytes))
            }
            return nil
        }
        if length < 1 || length > 30 { return nil }

        var input = Data(repeating: 0, count: 16)
        input.append(contentsOf: Array(str.utf8))
        var bytes = Array(Insecure.SHA1.hash(data: input)).prefix(16).map { $0 }
        bytes[6] = (bytes[6] & 0x0F) | (5 << 4)
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return uuidFromBytes(bytes)
    }

    private static func uuidFromBytes(_ b: [UInt8]) -> UUID {
        UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                    b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
    }

    private static func mapFingerprint(_ fp: String?) -> String {
        switch fp?.lowercased() {
        case "chrome": return TlsFingerprint.chrome133.raw
        case "firefox": return TlsFingerprint.firefox148.raw
        case "safari": return TlsFingerprint.safari26.raw
        case "ios": return TlsFingerprint.ios14.raw
        case "edge": return TlsFingerprint.edge85.raw
        case "random": return TlsFingerprint.random.raw
        // The Android-only fingerprints (android_11/qq_11/360_7) are
        // deliberately not mapped here, so a Clash import resolves the same
        // on every platform.
        default: return fp ?? TlsFingerprint.chrome133.raw
        }
    }
}
