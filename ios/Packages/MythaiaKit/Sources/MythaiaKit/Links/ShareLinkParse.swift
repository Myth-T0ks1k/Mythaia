import Foundation

/// Share links read into servers. Every error is `MythaiaError.parse` with
/// the reason the link was refused.
extension ProxyConfiguration {

    /// URL scheme prefixes `fromUrl` recognises.
    public static let parsableUrlPrefixes: [String] = [
        "vless://", "trojan://", "ss://",
        "hysteria2://", "hy2://", "anytls://", "vmess://", "tuic://",
        "sudoku://", "nowhere://",
        "socks5://", "socks://", "https://",
        "wireguard://", "wg://",
    ]

    /// Whether `fromUrl` can parse `url`.
    public static func canParseUrl(_ url: String) -> Bool {
        parsableUrlPrefixes.contains { LinkText.hasPrefix(url, $0) }
    }

    /**
     * Parses one share link. `naiveProtocol` decides what an `https://` link
     * is when the caller knows (an HTTPS proxy or an HTTP/2 one); without it
     * the link's own `http=1.1` marker does.
     */
    public static func fromUrl(_ url: String, naiveProtocol: OutboundProtocol? = nil) throws -> ProxyConfiguration {
        if LinkText.hasPrefix(url, "ss://") { return try fromShadowsocksUrl(url) }
        if LinkText.hasPrefix(url, "socks5://") || LinkText.hasPrefix(url, "socks://") { return try fromSocks5Url(url) }
        if LinkText.hasPrefix(url, "https://") { return try fromNaiveUrl(url, protocolOverride: naiveProtocol) }
        if LinkText.hasPrefix(url, "vless://") { return try fromVlessUrl(url) }
        if LinkText.hasPrefix(url, "trojan://") { return try fromTrojanUrl(url) }
        if LinkText.hasPrefix(url, "hysteria2://") { return try fromHysteria2Url(url, scheme: "hysteria2://") }
        if LinkText.hasPrefix(url, "hy2://") { return try fromHysteria2Url(url, scheme: "hy2://") }
        if LinkText.hasPrefix(url, "anytls://") { return try fromAnyTlsUrl(url) }
        if LinkText.hasPrefix(url, "vmess://") { return try fromVmessUrl(url) }
        if LinkText.hasPrefix(url, "tuic://") { return try fromTuicUrl(url) }
        if LinkText.hasPrefix(url, "sudoku://") { return try fromSudokuUrl(url) }
        if LinkText.hasPrefix(url, "nowhere://") { return try fromNowhereUrl(url) }
        if LinkText.hasPrefix(url, "wireguard://") { return try fromWireGuardUrl(url, scheme: "wireguard://") }
        if LinkText.hasPrefix(url, "wg://") { return try fromWireGuardUrl(url, scheme: "wg://") }
        throw MythaiaError.parse(
            "URL must start with vless://, trojan://, ss://, vmess://, hysteria2://, hy2://, anytls://, tuic://, sudoku://, nowhere://, wireguard://, wg://, socks5://, or https://"
        )
    }

    // MARK: - Pieces every link shares

    /// A link cut into its parts: what precedes `?`, the query, and the decoded `#` name.
    private struct LinkParts {
        var remaining: [UInt8]
        var query: String?
        var fragmentName: String?
    }

    /// Takes the `#name` off the end (last `#`) and then the `?query` (first `?`).
    private static func splitLink(_ url: String, scheme: String, takeQuery: Bool = true) -> LinkParts {
        var remaining = Array(LinkText.removePrefix(url, scheme).utf8)
        var fragmentName: String? = nil
        if let hash = remaining.lastIndex(of: UInt8(ascii: "#")) {
            fragmentName = percentDecode(LinkText.string(remaining[(hash + 1)...]))
            remaining = Array(remaining[..<hash])
        }
        var query: String? = nil
        if takeQuery, let q = remaining.firstIndex(of: UInt8(ascii: "?")) {
            query = LinkText.string(remaining[(q + 1)...])
            remaining = Array(remaining[..<q])
        }
        return LinkParts(remaining: remaining, query: query, fragmentName: fragmentName)
    }

    /// The authority after `@`: a trailing `/` and any path after it dropped.
    private static func serverPart(_ bytes: ArraySlice<UInt8>) -> String {
        var part = Array(bytes)
        if part.last == UInt8(ascii: "/") { part.removeLast() }
        if let slash = part.firstIndex(of: UInt8(ascii: "/")) { part = Array(part[..<slash]) }
        return LinkText.string(part)
    }

    /**
     * The parts every `password@host:port?query#name` link shares.
     *
     * Trojan predates this helper and keeps its own copy; the newer schemes
     * are all this shape.
     */
    private struct UserInfoLink {
        var password: String
        var host: String
        var port: UInt16
        var params: [String: String]
        var name: String?
    }

    /// `defaultPort` is used when the authority carries no port. Hysteria2 and
    /// AnyTLS both default to 443, and a link written without one is common
    /// enough that rejecting it is the wrong answer.
    private static func decomposeUserInfoLink(_ url: String, scheme: String, defaultPort: UInt16? = nil) throws -> UserInfoLink {
        let parts = splitLink(url, scheme: scheme)
        // lastIndex: a password may itself contain '@'.
        guard let at = parts.remaining.lastIndex(of: UInt8(ascii: "@")) else {
            let label = LinkText.removeSuffix(scheme, "://")
            throw MythaiaError.parse("Missing @ separator in \(label) URL")
        }
        let password = percentDecode(LinkText.string(parts.remaining[..<at]))
        let server = serverPart(parts.remaining[(at + 1)...])
        let (host, port) = try ShareLinkParams.parseHostPort(server, defaultPort: defaultPort)
        return UserInfoLink(
            password: password,
            host: host,
            port: port,
            params: ShareLinkParams.parseQueryParams(parts.query),
            name: ShareLinkParams.nonEmpty(parts.fragmentName)
        )
    }

    /// The shared TLS block of the password-authenticated schemes.
    private static func passwordProtocolTls(_ params: [String: String], host: String) -> TlsConfiguration {
        let sni = ShareLinkParams.nonEmpty(params["sni"]) ?? host
        let insecure = ShareLinkParams.isTruthy(params["insecure"]) || ShareLinkParams.isTruthy(params["allowInsecure"])
        return TlsConfiguration(
            serverName: sni,
            alpn: ShareLinkParams.parseAlpn(params["alpn"]),
            allowInsecure: insecure,
            fingerprint: TlsFingerprint.fromRaw(params["fp"] ?? "chrome_133"),
            echConfig: ShareLinkParams.nonEmpty(params["ech"]),
            pinnedCertSha256: ShareLinkParams.parsePinnedCerts(params),
            verifyName: ShareLinkParams.nonEmpty(params["vcn"])
        )
    }

    // MARK: - WireGuard

    /**
     * WireGuard as a share link, in the two shapes clients write:
     *
     * - v2rayNG: `wireguard://<private key>@host:port?publickey=…&address=10.0.0.2/32,fd00::2/128&mtu=1420&reserved=1,2,3&presharedkey=…#name`
     * - Hiddify / sing-box: `wg://host:port?pk=<private key>&local_address=…&peer_pk=…&pre_shared_key=…&reserved=…&mtu=…#name`
     *
     * Generators mix the two freely — a `wg://` with the key as userinfo, a
     * `wireguard://` with `peer_pk` — so every spelling is accepted under
     * either scheme, keys case-insensitively. The link becomes the INI it
     * stands for and is stored as that, like a pasted config.
     */
    private static func fromWireGuardUrl(_ url: String, scheme: String) throws -> ProxyConfiguration {
        let parts = splitLink(url, scheme: scheme)
        let fragmentName = parts.fragmentName.flatMap { LinkText.isBlank($0) ? nil : $0 }
        var params: [String: String] = [:]
        for (key, value) in ShareLinkParams.parseQueryParams(parts.query) {
            params[key.lowercased()] = value
        }
        func param(_ names: String...) -> String? {
            for name in names {
                if let value = params[name], !LinkText.isBlank(value) { return value }
            }
            return nil
        }

        // A base64 key may end in '=' and contain '/', but never '@'.
        let remaining = parts.remaining
        let at = remaining.lastIndex(of: UInt8(ascii: "@"))
        let userInfo = at.map { percentDecode(LinkText.string(remaining[..<$0])) }
        var server = at.map { Array(remaining[($0 + 1)...]) } ?? remaining
        while server.last == UInt8(ascii: "/") { server.removeLast() }
        let (host, port) = try ShareLinkParams.parseHostPort(LinkText.string(server), defaultPort: 51820)

        let privateKey: String
        if let info = userInfo, !LinkText.isBlank(info) {
            privateKey = info
        } else if let fromQuery = param("pk", "privatekey", "private_key", "secretkey", "secret_key") {
            privateKey = fromQuery
        } else {
            throw MythaiaError.parse("WireGuard link has no private key")
        }
        guard let publicKey = param("publickey", "public_key", "peer_pk", "peer_public_key", "peerpublickey", "pbk") else {
            throw MythaiaError.parse("WireGuard link has no peer public key")
        }

        var reserved: Data? = nil
        if let text = param("reserved") {
            guard let bytes = WireGuardConfig.parseReserved(text) else {
                throw MythaiaError.parse("WireGuard reserved must be three bytes: \(text)")
            }
            reserved = bytes
        }

        let ini = WireGuardIni.build(
            privateKey: privateKey,
            addresses: LinkText.split(param("address", "local_address", "localaddress", "ip") ?? "", UInt8(ascii: ",")),
            peer: WireGuardIni.Peer(
                publicKey: publicKey,
                endpointHost: host,
                endpointPort: Int(port),
                presharedKey: param("presharedkey", "pre_shared_key", "preshared_key", "psk"),
                allowedIps: LinkText.split(param("allowedips", "allowed_ips") ?? "", UInt8(ascii: ",")),
                keepalive: param("keepalive", "persistentkeepalive", "persistent_keepalive").flatMap { Int($0) } ?? 0
            ),
            mtu: param("mtu").flatMap { Int($0) },
            reserved: reserved,
            dns: LinkText.split(param("dns") ?? "", UInt8(ascii: ","))
        )
        return try fromWireGuardConfig(ini, name: fragmentName)
    }

    /**
     * Whether this text is a `wg-quick` config rather than a share link.
     *
     * WireGuard has no URL scheme — a peer hands out the INI itself — so a
     * paste is recognised by its shape.
     */
    public static func looksLikeWireGuardConfig(_ text: String) -> Bool {
        let lower = text.lowercased()
        return LinkText.contains(lower, "[interface]") &&
            LinkText.contains(lower, "privatekey") &&
            LinkText.contains(lower, "[peer]")
    }

    /**
     * Builds a profile from a `wg-quick` INI, WireGuard or AmneziaWG.
     *
     * The text is kept verbatim so a key this build does not know survives
     * a round trip; parsing here only validates it and pulls out the
     * endpoint for the list and the latency check.
     */
    public static func fromWireGuardConfig(_ text: String, name: String? = nil) throws -> ProxyConfiguration {
        let parsed: WireGuardConfig
        do {
            parsed = try WireGuardConfig.parse(text)
        } catch {
            throw MythaiaError.parse(ShareLinkParams.message(error))
        }
        let label: String
        if let name = name, !LinkText.isBlank(name) {
            label = name
        } else {
            label = parsed.amnezia.isEnabled ? "AmneziaWG" : "WireGuard"
        }
        return ProxyConfiguration(
            name: label,
            serverAddress: parsed.peer.endpointHost,
            serverPort: UInt16(parsed.peer.endpointPort),
            uuid: UUID(), // placeholder; WireGuard has no user id
            encryption: "none",
            transport: "udp",
            security: "none",
            outboundProtocol: .wireguard,
            wireGuardConfig: text
        )
    }

    // MARK: - TUIC

    /**
     * `tuic://uuid:password@host:port?sni=…&alpn=…#name`.
     *
     * The UUID is the user part and the password the password part, which
     * is the shape every TUIC client uses even though the specification
     * itself says nothing about links.
     */
    private static func fromTuicUrl(_ url: String) throws -> ProxyConfiguration {
        let link = try decomposeUserInfoLink(url, scheme: "tuic://", defaultPort: 443)
        // decomposeUserInfoLink hands back the whole userinfo as `password`
        // because every other scheme that uses it has no user part; TUIC
        // does, so it is split here rather than there.
        let bytes = Array(link.password.utf8)
        guard let colon = bytes.firstIndex(of: UInt8(ascii: ":")), colon > 0 else {
            throw MythaiaError.parse("tuic:// needs uuid:password")
        }
        // Already percent-decoded by decomposeUserInfoLink; decoding again
        // would turn a literal "%41" in the password into "A".
        guard let uuid = UUID(uuidString: LinkText.string(bytes[..<colon])) else {
            throw MythaiaError.parse("tuic:// user is not a UUID")
        }
        let password = LinkText.string(bytes[(colon + 1)...])

        let params = link.params
        let sni = ShareLinkParams.nonEmpty(params["sni"]) ?? link.host
        let insecure = ShareLinkParams.isTruthy(params["allow_insecure"]) ||
            ShareLinkParams.isTruthy(params["allowInsecure"]) ||
            ShareLinkParams.isTruthy(params["insecure"])
        return ProxyConfiguration(
            name: link.name ?? link.host,
            serverAddress: link.host,
            serverPort: link.port,
            uuid: uuid,
            encryption: "none",
            transport: "quic",
            security: "tls",
            tls: TlsConfiguration(
                serverName: sni,
                alpn: ShareLinkParams.parseAlpn(params["alpn"]),
                allowInsecure: insecure,
                fingerprint: TlsFingerprint.fromRaw(params["fp"] ?? "chrome_133"),
                echConfig: ShareLinkParams.nonEmpty(params["ech"]),
                pinnedCertSha256: ShareLinkParams.parsePinnedCerts(params),
                verifyName: ShareLinkParams.nonEmpty(params["vcn"])
            ),
            outboundProtocol: .tuic,
            password: password
        )
    }

    // MARK: - Nowhere

    /**
     * `nowhere://key@host:port?up=…&down=…&mux=…&sni=…&alpn=…&ech=…#name`.
     *
     * The key is the whole userinfo (no user:pass split), as with the other
     * password-authenticated schemes. Carriers are resolved the reference's
     * way — an explicit `up`/`down` wins, then a shared `net`, then the
     * default `udp` in both directions — and the resolved wire names are
     * stored so the config is self-describing rather than relying on the
     * dial layer's default. `mux=1` only means multiplexing when a stream
     * carrier is present to honour it; an unrecognised carrier or `mux`
     * value is rejected here rather than dialled wrongly. TLS is mandatory
     * (the carrier is QUIC or TLS-on-TCP), so a config is always built with
     * a `TlsConfiguration`; `sni=none` means "no override", i.e. fall back
     * to the host.
     */
    private static func fromNowhereUrl(_ url: String) throws -> ProxyConfiguration {
        let link = try decomposeUserInfoLink(url, scheme: "nowhere://", defaultPort: 443)
        let params = link.params

        guard !link.password.isEmpty else { throw MythaiaError.parse("Missing Nowhere key") }
        let key = link.password
        // The key length is a single byte on the auth frame's wire.
        if key.utf8.count > 255 { throw MythaiaError.parse("Nowhere key too long") }

        let net = params["net"]
        let uplink = try resolveNowhereCarrier(params["up"], net: net, name: "up")
        let downlink = try resolveNowhereCarrier(params["down"], net: net, name: "down")
        let multiplex: Bool
        switch params["mux"] {
        case nil, "0"?:
            multiplex = false
        case "1"?:
            multiplex = uplink == .tcp || downlink == .tcp
        default:
            throw MythaiaError.parse("Invalid Nowhere mux value")
        }

        let rawSni = params["sni"]
        let sni: String
        if let raw = rawSni, !raw.isEmpty, raw != "none" {
            sni = raw
        } else {
            sni = link.host
        }
        var alpn: [String]? = nil
        if let value = params["alpn"] {
            if value.isEmpty || value.utf8.count > 255 {
                throw MythaiaError.parse("Invalid Nowhere ALPN")
            }
            alpn = [value]
        }
        let tls = TlsConfiguration(
            serverName: sni,
            alpn: alpn,
            allowInsecure: ShareLinkParams.isTruthy(params["insecure"]) || ShareLinkParams.isTruthy(params["allowInsecure"]),
            echConfig: ShareLinkParams.nonEmpty(params["ech"]),
            pinnedCertSha256: ShareLinkParams.parsePinnedCerts(params),
            verifyName: ShareLinkParams.nonEmpty(params["vcn"])
        )

        return ProxyConfiguration(
            name: link.name ?? "Nowhere",
            serverAddress: link.host,
            serverPort: link.port,
            uuid: UUID(), // placeholder; Nowhere authenticates by key
            encryption: "none",
            transport: "quic",
            security: "tls",
            tls: tls,
            outboundProtocol: .nowhere,
            password: key,
            nowhereUplink: uplink.wireName,
            nowhereDownlink: downlink.wireName,
            nowhereMultiplex: multiplex
        )
    }

    /**
     * Resolves one Nowhere carrier direction, porting the reference's
     * precedence: an explicit `up`/`down` value first, then a shared `net`,
     * then the default `udp`. An unknown spelling is an error rather than a
     * silent fallback, because the flow header would otherwise name a
     * carrier the user never chose.
     */
    private static func resolveNowhereCarrier(_ explicit: String?, net: String?, name: String) throws -> NowhereNetwork {
        if let explicit = explicit {
            guard let network = NowhereNetwork.fromWireName(explicit) else {
                throw MythaiaError.parse("Invalid Nowhere \(name) value")
            }
            return network
        }
        if let net = net {
            guard let network = NowhereNetwork.fromWireName(net) else {
                throw MythaiaError.parse("Invalid Nowhere net value")
            }
            return network
        }
        return .udp
    }

    // MARK: - Sudoku

    /**
     * `sudoku://` + base64url of a compact JSON object — the reference's
     * short link. Everything a Sudoku dial needs is packed into single- and
     * two-letter keys, so this decodes the body, pulls the required
     * `h`/`p`/`k` (host, port, key), and folds the rest into the flat
     * `sudoku*` fields through the same tolerant parsers
     * `toSudokuConfiguration` reads them back with. Enum values are resolved
     * the reference's way and stored as their stable ids; the padding pair is
     * not part of the short link and stays nil so it defaults on the way back
     * in. An unknown enum spelling degrades to that field's default rather
     * than failing the import, which is what keeps a link from a newer build
     * still dialable.
     */
    private static func fromSudokuUrl(_ url: String) throws -> ProxyConfiguration {
        let encoded = LinkText.trim(LinkText.removePrefix(url, "sudoku://"))
        if encoded.isEmpty { throw MythaiaError.parse("Empty sudoku:// link") }
        guard let decoded = decodeBase64Text(encoded),
              let json = try? ImportJSON.parseObject(decoded) else {
            throw MythaiaError.parse("Invalid Sudoku short link payload")
        }

        guard let host = ShareLinkParams.nonEmpty(json.optString("h")),
              let key = ShareLinkParams.nonEmpty(json.optString("k")) else {
            throw MythaiaError.parse("Sudoku short link is missing required fields")
        }
        guard let portText = json.opt("p")?.text, let portInt = Int(LinkText.trim(portText)) else {
            throw MythaiaError.parse("Invalid Sudoku short link port")
        }
        if portInt < 1 || portInt > 65535 { throw MythaiaError.parse("Invalid Sudoku short link port") }

        // Absent/unknown enums resolve to the reference's short-link
        // defaults: aead → none, ascii → prefer-entropy, mask mode → legacy,
        // mux → off. The resolved ids are stored so the export mirrors them.
        let aead = SudokuAeadMethod.fromId(json.optString("e", SudokuAeadMethod.none.id)) ?? SudokuAeadMethod.none
        let asciiMode = SudokuAsciiMode.fromNormalized(json.optString("a", SudokuAsciiMode.preferEntropy.shortLinkToken))
            ?? SudokuAsciiMode.preferEntropy
        let name = ShareLinkParams.nonEmpty(LinkText.trim(json.optString("n"))) ?? host

        // The plural `ts` is preferred; a legacy single-table field
        // (`t`/`table`/`custom_table`) is folded in only when it is absent.
        let legacyTable = LinkText.trim(
            ShareLinkParams.nonEmpty(json.optString("t"))
                ?? ShareLinkParams.nonEmpty(json.optString("table"))
                ?? json.optString("custom_table")
        )
        var rawTables: [String] = []
        if let array = json.optArray("ts") {
            for index in 0..<array.count { rawTables.append(array.optString(index)) }
        }
        let customTables = SudokuConfiguration.normalizeCustomTables(rawTables, legacy: legacyTable)

        let maskMode = SudokuHttpMaskMode.fromId(json.optString("hm", SudokuHttpMaskMode.legacy.id)) ?? SudokuHttpMaskMode.legacy
        let multiplex = SudokuMultiplex.fromNormalized(json.optString("hx", ""))

        return ProxyConfiguration(
            name: name,
            serverAddress: host,
            serverPort: UInt16(portInt),
            uuid: UUID(), // placeholder; Sudoku authenticates by key
            encryption: "none",
            transport: "tcp",
            security: "none",
            outboundProtocol: .sudoku,
            sudokuKey: key,
            sudokuAeadMethod: aead.id,
            sudokuAsciiMode: asciiMode.id,
            sudokuCustomTables: customTables,
            // `x` is the inverse flag: present-and-true disables pure downlink.
            sudokuEnablePureDownlink: !json.optBoolean("x", false),
            sudokuMultiplex: multiplex.id,
            sudokuHttpMaskDisable: json.optBoolean("hd", false),
            sudokuHttpMaskMode: maskMode.id,
            sudokuHttpMaskTls: json.optBoolean("ht", false),
            sudokuHttpMaskHost: ShareLinkParams.nonEmpty(json.optString("hh")),
            sudokuHttpMaskPathRoot: ShareLinkParams.nonEmpty(json.optString("hy"))
        )
    }

    // MARK: - Trojan

    /**
     * Parses a Trojan URL. Format:
     * `trojan://password@host:port?sni=...&alpn=h2%2Chttp%2F1.1&fp=chrome_133#name`
     * TLS is mandatory — there is no plaintext Trojan variant on the wire.
     */
    private static func fromTrojanUrl(_ url: String) throws -> ProxyConfiguration {
        let parts = splitLink(url, scheme: "trojan://")
        guard let at = parts.remaining.lastIndex(of: UInt8(ascii: "@")) else {
            throw MythaiaError.parse("Missing @ separator in trojan URL")
        }
        // Whole userinfo is the password (trojan-gfw spec — no user:pass split).
        let password = percentDecode(LinkText.string(parts.remaining[..<at]))
        let server = serverPart(parts.remaining[(at + 1)...])
        let (host, port) = try ShareLinkParams.parseHostPort(server)
        let params = ShareLinkParams.parseQueryParams(parts.query)

        let sni = ShareLinkParams.nonEmpty(params["sni"])
            ?? ShareLinkParams.nonEmpty(params["peer"])
            ?? ShareLinkParams.transportHostParam(params)
            ?? host

        let type = ShareLinkParams.nonEmpty(params["type"]) ?? "tcp"
        let transport: String
        switch type {
        case "tcp", "ws", "httpupgrade", "grpc", "xhttp": transport = type
        case "splithttp": transport = "xhttp"
        default: throw MythaiaError.parse("trojan: \(type) transport is not supported")
        }

        let tls = TlsConfiguration(
            serverName: sni,
            alpn: ShareLinkParams.parseAlpn(params["alpn"]),
            allowInsecure: ShareLinkParams.isTruthy(params["allowInsecure"]) || ShareLinkParams.isTruthy(params["insecure"]),
            fingerprint: TlsFingerprint.fromRaw(params["fp"] ?? "chrome_133"),
            fragment: ShareLinkParams.parseFragmentParams(params),
            echConfig: ShareLinkParams.nonEmpty(params["ech"]),
            pinnedCertSha256: ShareLinkParams.parsePinnedCerts(params),
            verifyName: ShareLinkParams.nonEmpty(params["vcn"])
        )

        var xhttpParams = params
        xhttpParams["host"] = params["host"] ?? sni

        return ProxyConfiguration(
            name: parts.fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for Trojan
            encryption: "none",
            transport: transport,
            security: "tls",
            tls: tls,
            websocket: transport == "ws" ? WebSocketConfiguration.parse(params, serverAddress: host) : nil,
            httpUpgrade: transport == "httpupgrade" ? HttpUpgradeConfiguration.parse(params, serverAddress: host) : nil,
            xhttp: transport == "xhttp" ? XHttpConfiguration.parse(xhttpParams, serverAddress: host) : nil,
            grpc: transport == "grpc" ? GrpcConfiguration.parse(params) : nil,
            outboundProtocol: .trojan,
            trojanPassword: password,
            trojanTls: tls
        )
    }

    // MARK: - VMess

    /**
     * `vmess://` + base64 of a JSON object — the "v2rayN" form every panel
     * writes. There is also a query-string spelling in the wild; it is rare
     * enough, and ambiguous enough, that only the JSON form is accepted.
     *
     * `aid` (alterId) must be 0: the legacy MD5-authenticated header it
     * selects was removed from v2ray in 2022, and pretending to support it
     * would produce a connection that silently never authenticates.
     */
    private static func fromVmessUrl(_ url: String) throws -> ProxyConfiguration {
        let payload = LinkText.trim(LinkText.removePrefix(url, "vmess://"))
        if payload.isEmpty { throw MythaiaError.parse("Empty vmess:// link") }

        guard let decoded = decodeBase64Flexible(payload) else {
            throw MythaiaError.parse("vmess:// payload is not base64")
        }
        guard let json = try? ImportJSON.parseObject(decoded) else {
            throw MythaiaError.parse("vmess:// payload is not JSON")
        }

        guard let host = ShareLinkParams.nonEmpty(json.optString("add")) else {
            throw MythaiaError.parse("vmess: missing add")
        }
        guard let portText = json.opt("port")?.text, let portValue = Int(LinkText.trim(portText)) else {
            throw MythaiaError.parse("vmess: missing or malformed port")
        }
        if portValue < 1 || portValue > 65535 { throw MythaiaError.parse("vmess: port out of range") }

        guard let idText = ShareLinkParams.nonEmpty(json.optString("id")) else {
            throw MythaiaError.parse("vmess: missing id")
        }
        guard let id = UUID(uuidString: idText) else {
            throw MythaiaError.parse("vmess: id is not a UUID")
        }

        // aid may be a number or a string depending on who wrote the link.
        let alterId = json.opt("aid").flatMap { Int(LinkText.trim($0.text)) } ?? 0
        if alterId != 0 {
            throw MythaiaError.parse(
                "vmess: alterId \(alterId) is the removed legacy header; only alterId 0 (AEAD) is supported"
            )
        }

        let network = ShareLinkParams.nonEmpty(json.optString("net")) ?? "tcp"
        let transport: String
        switch network {
        case "ws": transport = "ws"
        case "tcp": transport = "tcp"
        case "httpupgrade": transport = "httpupgrade"
        case "grpc", "gun": transport = "grpc"
        case "xhttp", "splithttp": transport = "xhttp"
        default: throw MythaiaError.parse("vmess: \(network) transport is not supported yet")
        }
        // "type" is the header obfuscation (http camouflage etc.). Nothing
        // here speaks it, and a server expecting it never answers a plain
        // request, so refuse rather than import a dead entry. Over gRPC
        // the same field carries the mode instead ("multi"), which is
        // what this exporter writes.
        let headerType = LinkText.trim(json.optString("type"))
        let isGrpcMode = transport == "grpc" && headerType == "multi"
        if !headerType.isEmpty && headerType != "none" && !isGrpcMode {
            throw MythaiaError.parse("vmess: \(headerType) header obfuscation is not supported")
        }

        let tlsField = json.optString("tls")
        let useTls = tlsField == "tls" || tlsField == "1" || tlsField == "true"
        let sni = ShareLinkParams.nonEmpty(json.optString("sni"))
            ?? ShareLinkParams.nonEmpty(json.optString("host"))
            ?? host
        let alpn = ShareLinkParams.nonEmpty(json.optString("alpn")).map { LinkText.split($0, UInt8(ascii: ",")) }
        // v2rayN writes this either way round depending on its version.
        let allowInsecureText = json.optString("allowInsecure")
        let verifyCertText = json.optString("verify_cert")
        let allowInsecure = allowInsecureText == "true" || allowInsecureText == "1" ||
            verifyCertText == "false" || verifyCertText == "0"

        var tls: TlsConfiguration? = nil
        if useTls {
            let cleanAlpn = alpn.map { list in list.map { LinkText.trim($0) }.filter { !$0.isEmpty } }
            tls = TlsConfiguration(
                serverName: sni,
                alpn: cleanAlpn,
                allowInsecure: allowInsecure,
                fingerprint: TlsFingerprint.fromRaw(ShareLinkParams.nonEmpty(json.optString("fp")) ?? "chrome_133"),
                pinnedCertSha256: ShareLinkParams.parsePinnedCerts(["pcs": json.optString("pcs")]),
                verifyName: ShareLinkParams.nonEmpty(json.optString("vcn"))
            )
        }

        let hostField = ShareLinkParams.nonEmpty(json.optString("host"))
        let pathField = ShareLinkParams.nonEmpty(json.optString("path")) ?? "/"

        var websocket: WebSocketConfiguration? = nil
        if transport == "ws" {
            websocket = WebSocketConfiguration(host: hostField ?? host, path: pathField)
        }
        var httpUpgrade: HttpUpgradeConfiguration? = nil
        if transport == "httpupgrade" {
            httpUpgrade = HttpUpgradeConfiguration(host: hostField ?? host, path: pathField)
        }
        // v2rayN puts the service name in `path` and the mode in `type`.
        var grpc: GrpcConfiguration? = nil
        if transport == "grpc" {
            grpc = GrpcConfiguration(
                serviceName: json.optString("path"),
                authority: json.optString("authority"),
                multiMode: json.optString("type") == "multi" || json.optString("mode") == "multi"
            )
        }
        var xhttp: XHttpConfiguration? = nil
        if transport == "xhttp" {
            xhttp = XHttpConfiguration.fromExtraJson(
                host: hostField ?? sni,
                path: pathField,
                mode: XHttpMode.fromRaw(ShareLinkParams.nonEmpty(json.optString("mode")) ?? "auto"),
                extraJson: json.optString("extra")
            )
        }

        let scy = json.optString("scy")
        return ProxyConfiguration(
            name: ShareLinkParams.nonEmpty(json.optString("ps")) ?? host,
            serverAddress: host,
            serverPort: UInt16(portValue),
            uuid: id,
            encryption: "none",
            transport: transport,
            security: useTls ? "tls" : "none",
            tls: tls,
            websocket: websocket,
            httpUpgrade: httpUpgrade,
            xhttp: xhttp,
            grpc: grpc,
            outboundProtocol: .vmess,
            vmessSecurity: (scy.isEmpty || scy == "auto") ? nil : scy
        )
    }

    /**
     * Base64 that may or may not be padded, and may be either alphabet.
     *
     * Panels are inconsistent about all three, and a link that fails to
     * decode over punctuation is the most avoidable kind of import failure.
     */
    private static func decodeBase64Flexible(_ text: String) -> String? {
        let normalised = LinkText.trim(text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/"))
        let padded: String
        switch normalised.utf8.count % 4 {
        case 2: padded = normalised + "=="
        case 3: padded = normalised + "="
        case 0: padded = normalised
        default: return nil
        }
        guard let bytes = LinkText.base64Decode(padded, urlSafe: false) else { return nil }
        return LinkText.utf8(bytes)
    }

    // MARK: - Hysteria2 and AnyTLS

    /**
     * `hysteria2://password@host:port?sni=…&upmbps=…&downmbps=…&obfs=salamander&obfs-password=…#name`,
     * and the `hy2://` spelling of the same thing.
     *
     * TLS is mandatory; Hysteria2 runs over QUIC and has no plaintext form.
     */
    private static func fromHysteria2Url(_ url: String, scheme: String) throws -> ProxyConfiguration {
        let link = try decomposeUserInfoLink(url, scheme: scheme, defaultPort: 443)
        let params = link.params
        let tls = passwordProtocolTls(params, host: link.host)

        // `obfs=none` is how some panels spell "no obfuscation"; kept
        // verbatim it is refused at every dial as a type this build
        // does not speak.
        var obfuscation: String? = nil
        if let obfs = params["obfs"], !obfs.isEmpty, obfs.lowercased() != "none" {
            obfuscation = obfs.lowercased()
        }
        let salamander = finalMaskSalamander(params["fm"])
        return ProxyConfiguration(
            name: link.name ?? link.host,
            serverAddress: link.host,
            serverPort: link.port,
            uuid: UUID(), // placeholder; Hysteria2 authenticates by password
            encryption: "none",
            transport: "tcp",
            security: "tls",
            tls: tls,
            outboundProtocol: .hysteria2,
            password: link.password,
            // Absence is information: the bandwidth pair is what selects
            // Brutal over BBR, so no default is filled in here.
            hysteriaUpMbps: params["upmbps"].flatMap { Int($0) },
            hysteriaDownMbps: params["downmbps"].flatMap { Int($0) },
            obfuscation: obfuscation ?? salamander?.type,
            obfuscationPassword: ShareLinkParams.nonEmpty(params["obfs-password"]) ?? salamander?.password
        )
    }

    /**
     * The Salamander obfuscation a FinalMask `fm=` document carries under
     * `udp`: `{"udp":[{"type":"salamander","settings":{"password":"…"}}]}`.
     * Type and password, or nil.
     */
    private static func finalMaskSalamander(_ fm: String?) -> (type: String, password: String)? {
        guard let fm = fm, !LinkText.isBlank(fm) else { return nil }
        guard let root = try? ImportJSON.parseObject(fm), let udp = root.optArray("udp") else { return nil }
        for element in udp {
            guard let mask = element.objectValue else { continue }
            if mask.optString("type") != "salamander" { continue }
            guard let password = ShareLinkParams.nonEmpty(mask.optObject("settings")?.optString("password")) else { continue }
            return ("salamander", password)
        }
        return nil
    }

    /// `anytls://password@host:port?sni=…&alpn=…&fp=…#name`. TLS is mandatory.
    private static func fromAnyTlsUrl(_ url: String) throws -> ProxyConfiguration {
        let link = try decomposeUserInfoLink(url, scheme: "anytls://", defaultPort: 443)
        return ProxyConfiguration(
            name: link.name ?? link.host,
            serverAddress: link.host,
            serverPort: link.port,
            uuid: UUID(), // placeholder; AnyTLS authenticates by password
            encryption: "none",
            transport: "tcp",
            security: "tls",
            tls: passwordProtocolTls(link.params, host: link.host),
            outboundProtocol: .anytls,
            password: link.password
        )
    }

    // MARK: - VLESS

    private static func fromVlessUrl(_ url: String) throws -> ProxyConfiguration {
        // The query goes first: a path or host value may itself contain
        // "@" (Telegram-branded panels do this), and finding the separator
        // before splitting it off would swallow the whole authority.
        let parts = splitLink(url, scheme: "vless://")
        guard let at = parts.remaining.lastIndex(of: UInt8(ascii: "@")) else {
            throw MythaiaError.parse("Missing @ separator")
        }
        let uuidString = LinkText.string(parts.remaining[..<at])
        guard let uuid = UUID(uuidString: percentDecode(uuidString)) else {
            throw MythaiaError.parse("Invalid UUID: \(uuidString)")
        }
        let hostPort = serverPart(parts.remaining[(at + 1)...])
        let (host, port) = try ShareLinkParams.parseHostPort(hostPort)
        let params = ShareLinkParams.parseQueryParams(parts.query)

        let encryption = params["encryption"] ?? "none"
        let flow = params["flow"]
        let security = params["security"] ?? "none"
        // kcp, quic, h2 and the rest have no dialer here; stored as they
        // are they would only fail at connect time, with a vaguer message.
        let type = ShareLinkParams.nonEmpty(params["type"]) ?? "tcp"
        let transport: String
        switch type {
        case "tcp", "ws", "httpupgrade", "grpc", "xhttp": transport = type
        case "splithttp": transport = "xhttp"
        case "raw": transport = "tcp"
        default: throw MythaiaError.parse("vless: \(type) transport is not supported")
        }
        // Header obfuscation (http camouflage) is not spoken either, and a
        // server expecting it never answers a plain request.
        let headerType = LinkText.trim(params["headerType"] ?? "")
        if !headerType.isEmpty && headerType != "none" {
            throw MythaiaError.parse("vless: \(headerType) header obfuscation is not supported")
        }

        var testseed: [UInt32]? = nil
        if let text = params["testseed"] {
            let values = LinkText.split(text, UInt8(ascii: ",")).compactMap { UInt32($0) }
            if values.count >= 4 { testseed = Array(values.prefix(4)) }
        }

        var realityConfig: RealityConfiguration? = nil
        if security == "reality" {
            realityConfig = try RealityConfiguration.parse(params)
        }
        let tlsConfig = security == "tls" ? TlsConfiguration.parse(params, serverAddress: host) : nil
        let wsConfig = transport == "ws" ? WebSocketConfiguration.parse(params, serverAddress: host) : nil
        let httpUpgradeConfig = transport == "httpupgrade" ? HttpUpgradeConfiguration.parse(params, serverAddress: host) : nil
        var xhttpConfig: XHttpConfiguration? = nil
        if transport == "xhttp" {
            // Fall back to TLS/Reality SNI for XHTTP host.
            var xhttpParams = params
            xhttpParams["host"] = params["host"] ?? tlsConfig?.serverName ?? realityConfig?.serverName ?? host
            xhttpConfig = XHttpConfiguration.parse(xhttpParams, serverAddress: host)
        }
        let grpcConfig = transport == "grpc" ? GrpcConfiguration.parse(params) : nil

        let muxEnabled = params["mux"].map { $0 != "false" && $0 != "0" } ?? true
        let xudpEnabled = params["xudp"].map { $0 != "false" && $0 != "0" } ?? true

        return ProxyConfiguration(
            name: parts.fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: uuid,
            encryption: encryption,
            transport: transport,
            flow: flow,
            security: security,
            tls: tlsConfig,
            reality: realityConfig,
            websocket: wsConfig,
            httpUpgrade: httpUpgradeConfig,
            xhttp: xhttpConfig,
            grpc: grpcConfig,
            testseed: testseed ?? ProxyConfiguration.defaultTestseed,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled
        )
    }

    // MARK: - Shadowsocks

    private static func fromShadowsocksUrl(_ url: String) throws -> ProxyConfiguration {
        let parts = splitLink(url, scheme: "ss://", takeQuery: false)
        let remaining = parts.remaining

        let method: String
        let password: String
        let host: String
        let port: UInt16

        if let at = remaining.firstIndex(of: UInt8(ascii: "@")) {
            // SIP002 format: userinfo@host:port. The userinfo may be
            // either literal method:password or base64(method:password).
            let userInfo = LinkText.string(remaining[..<at])
            var server = Array(remaining[(at + 1)...])

            if let q = server.firstIndex(of: UInt8(ascii: "?")) {
                // A SIP003 plugin (obfs, v2ray-plugin) changes the wire
                // format; without the plugin the server never answers.
                let queryParams = ShareLinkParams.parseQueryParams(LinkText.string(server[(q + 1)...]))
                if let plugin = queryParams["plugin"], !LinkText.isBlank(plugin) {
                    throw MythaiaError.parse("Shadowsocks plugins are not supported: \(plugin)")
                }
                server = Array(server[..<q])
            }
            if let slash = server.firstIndex(of: UInt8(ascii: "/")) {
                server = Array(server[..<slash])
            }

            let decoded = try decodeShadowsocksUserInfo(userInfo)
            method = decoded.method
            password = decoded.password
            let hostPort = try ShareLinkParams.parseHostPort(LinkText.string(server))
            host = hostPort.host
            port = hostPort.port
        } else {
            // Legacy format: base64(method:password@host:port).
            guard let decoded = decodeBase64Text(LinkText.string(remaining)) else {
                throw MythaiaError.parse("Invalid SS URL encoding")
            }
            let bytes = Array(decoded.utf8)
            guard let colon = bytes.firstIndex(of: UInt8(ascii: ":")) else {
                throw MythaiaError.parse("Missing method:password separator")
            }
            method = LinkText.string(bytes[..<colon])
            let rest = Array(bytes[(colon + 1)...])
            guard let lastAt = rest.lastIndex(of: UInt8(ascii: "@")) else {
                throw MythaiaError.parse("Missing @ separator in decoded SS URL")
            }
            password = LinkText.string(rest[..<lastAt])
            let hostPort = try ShareLinkParams.parseHostPort(LinkText.string(rest[(lastAt + 1)...]))
            host = hostPort.host
            port = hostPort.port
        }

        if !isSupportedShadowsocksMethod(method) {
            throw MythaiaError.parse("Unsupported SS method: \(method)")
        }

        return ProxyConfiguration(
            name: parts.fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for SS
            encryption: "none",
            transport: "tcp",
            security: "none",
            outboundProtocol: .shadowsocks,
            ssPassword: password,
            ssMethod: method
        )
    }

    /// The methods the Shadowsocks client speaks: the AEAD ciphers, the
    /// 2022 ones and `none`, under the spellings links use.
    static func isSupportedShadowsocksMethod(_ method: String) -> Bool {
        switch method.lowercased() {
        case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "none", "plain",
             "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
            return true
        default:
            return false
        }
    }

    private static func decodeShadowsocksUserInfo(_ rawUserInfo: String) throws -> (method: String, password: String) {
        let rawBytes = Array(rawUserInfo.utf8)
        if let colon = rawBytes.firstIndex(of: UInt8(ascii: ":")) {
            return (LinkText.string(rawBytes[..<colon]), percentDecode(LinkText.string(rawBytes[(colon + 1)...])))
        }
        // Some generators percent-encode the base64 padding ("%3D").
        let userInfo = rawBytes.contains(UInt8(ascii: "%")) ? percentDecode(rawUserInfo) : rawUserInfo
        guard let decoded = decodeBase64Text(userInfo) else {
            throw MythaiaError.parse("Invalid SS user info encoding")
        }
        let bytes = Array(decoded.utf8)
        guard let colon = bytes.firstIndex(of: UInt8(ascii: ":")) else {
            throw MythaiaError.parse("Invalid SS user info format")
        }
        return (LinkText.string(bytes[..<colon]), LinkText.string(bytes[(colon + 1)...]))
    }

    /// Padded, then the URL-safe alphabet, then the standard one.
    static func decodeBase64Text(_ value: String) -> String? {
        let padded = LinkText.padBase64(value)
        if let bytes = LinkText.base64Decode(padded, urlSafe: true) { return LinkText.utf8(bytes) }
        if let bytes = LinkText.base64Decode(padded, urlSafe: false) { return LinkText.utf8(bytes) }
        return nil
    }

    // MARK: - Naive (HTTPS proxy)

    private static func fromNaiveUrl(_ url: String, protocolOverride: OutboundProtocol?) throws -> ProxyConfiguration {
        guard LinkText.hasPrefix(url, "https://") else {
            throw MythaiaError.parse("Naive URL must start with https://")
        }
        let parts = splitLink(url, scheme: "https://")
        guard let at = parts.remaining.lastIndex(of: UInt8(ascii: "@")) else {
            throw MythaiaError.parse("Missing @ separator in naive URL")
        }
        let userInfo = Array(parts.remaining[..<at])
        var server = Array(parts.remaining[(at + 1)...])
        if let slash = server.firstIndex(of: UInt8(ascii: "/")) { server = Array(server[..<slash]) }

        guard let colon = userInfo.firstIndex(of: UInt8(ascii: ":")) else {
            throw MythaiaError.parse("Missing password in naive URL (expected user:pass)")
        }
        let username = percentDecode(LinkText.string(userInfo[..<colon]))
        let password = percentDecode(LinkText.string(userInfo[(colon + 1)...]))

        // An https:// link without a port means 443, as it would in a browser.
        let (host, port) = try ShareLinkParams.parseHostPort(LinkText.string(server), defaultPort: 443)
        let params = ShareLinkParams.parseQueryParams(parts.query)

        // `http=1.1` is this exporter's own marker for an HTTPS (HTTP/1.1)
        // proxy; without it the scheme means HTTP/2, as it does to every
        // other client.
        let marked: OutboundProtocol = params["http"] == "1.1" ? OutboundProtocol.naiveHttp11 : OutboundProtocol.naiveHttp2
        let proto: OutboundProtocol = protocolOverride ?? marked
        // TLS settings only when the link has any, so a plain link keeps
        // the defaults it always had.
        let insecure = ShareLinkParams.isTruthy(params["insecure"]) || ShareLinkParams.isTruthy(params["allowInsecure"])
        let pins = ShareLinkParams.parsePinnedCerts(params)
        let verifyName = ShareLinkParams.nonEmpty(params["vcn"])
        let sni = ShareLinkParams.nonEmpty(params["sni"])
        var tls: TlsConfiguration? = nil
        if insecure || pins != nil || verifyName != nil || sni != nil {
            tls = TlsConfiguration(
                serverName: sni ?? host,
                allowInsecure: insecure,
                pinnedCertSha256: pins,
                verifyName: verifyName
            )
        }
        return ProxyConfiguration(
            name: parts.fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for naive
            encryption: "none",
            tls: tls,
            outboundProtocol: proto,
            naiveUsername: username,
            naivePassword: password,
            naiveProtocol: proto == .naiveHttp11 ? NaiveProtocol.http11 : NaiveProtocol.http2
        )
    }

    // MARK: - SOCKS5

    /**
     * Parse a SOCKS5 URL into configuration.
     * Format: socks5://user:pass@host:port#name  or  socks5://host:port#name
     */
    private static func fromSocks5Url(_ url: String) throws -> ProxyConfiguration {
        let scheme = LinkText.hasPrefix(url, "socks5://") ? "socks5://" : "socks://"
        // Nothing in the query is read, but left in place it would be
        // taken for part of the port.
        let parts = splitLink(url, scheme: scheme)
        let remaining = parts.remaining

        var username: String? = nil
        var password: String? = nil
        var server: [UInt8]
        if let at = remaining.lastIndex(of: UInt8(ascii: "@")) {
            let userInfo = Array(remaining[..<at])
            server = Array(remaining[(at + 1)...])
            if let colon = userInfo.firstIndex(of: UInt8(ascii: ":")) {
                username = percentDecode(LinkText.string(userInfo[..<colon]))
                password = percentDecode(LinkText.string(userInfo[(colon + 1)...]))
            } else {
                username = percentDecode(LinkText.string(userInfo))
            }
        } else {
            server = remaining
        }
        if let slash = server.firstIndex(of: UInt8(ascii: "/")) { server = Array(server[..<slash]) }

        let (host, port) = try ShareLinkParams.parseHostPort(LinkText.string(server))

        return ProxyConfiguration(
            name: parts.fragmentName ?? "Untitled",
            serverAddress: host,
            serverPort: port,
            uuid: UUID(), // placeholder, not used for SOCKS5
            encryption: "none",
            outboundProtocol: .socks5,
            socks5Username: username,
            socks5Password: password
        )
    }
}
