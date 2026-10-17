import Foundation

/**
 * One server: where it is, which protocol it speaks and how its stream is
 * dressed (TLS, Reality, a transport), plus the chain it is dialled through.
 *
 * Share links parse into this (`fromUrl`) and export back out of it
 * (`toUrl`); see Links/ for both directions.
 */
public struct ProxyConfiguration: Codable, Hashable, Identifiable {
    public var id: UUID
    public var name: String
    public var serverAddress: String
    public var serverPort: UInt16
    public var resolvedIP: String?
    public var uuid: UUID
    public var encryption: String
    public var transport: String
    public var flow: String?
    public var security: String
    public var tls: TlsConfiguration?
    public var reality: RealityConfiguration?
    public var websocket: WebSocketConfiguration?
    public var httpUpgrade: HttpUpgradeConfiguration?
    public var xhttp: XHttpConfiguration?
    public var grpc: GrpcConfiguration?
    public var testseed: [UInt32]
    public var muxEnabled: Bool
    public var xudpEnabled: Bool
    public var subscriptionId: UUID?
    public var outboundProtocol: OutboundProtocol
    public var ssPassword: String?
    public var ssMethod: String?
    public var socks5Username: String?
    public var socks5Password: String?
    public var naiveUsername: String?
    public var naivePassword: String?
    public var naiveProtocol: NaiveProtocol?
    public var trojanPassword: String?
    /// Trojan's mandatory TLS configuration.
    public var trojanTls: TlsConfiguration?
    /// Hysteria2, AnyTLS, TUIC and Nowhere authenticate with a single password (Nowhere's key).
    public var password: String?
    /**
     * Hysteria2's declared bandwidth. Their presence is what selects Brutal
     * congestion control over BBR, so absence is information — left nil
     * rather than defaulted.
     */
    public var hysteriaUpMbps: Int?
    public var hysteriaDownMbps: Int?
    /// Hysteria2 obfuscation, currently only `salamander`.
    public var obfuscation: String?
    /**
     * VMess body cipher: `aes-128-gcm`, `chacha20-poly1305`, `none` or
     * `zero`. Nil means the link said `auto`, or said nothing.
     */
    public var vmessSecurity: String?
    public var obfuscationPassword: String?
    /**
     * The peer's `wg-quick` INI, verbatim, for WireGuard and AmneziaWG.
     *
     * Kept as the text the user pasted rather than exploded into fields: it is
     * the format every peer hands out, it round-trips through export without
     * losing a key this build does not know yet, and it is what
     * `WireGuardConfig.parse` reads.
     */
    public var wireGuardConfig: String?
    /**
     * Nowhere carrier selection, stored as the link spelled them (`udp`, `tcp`).
     * Nil means the reference default, which is `udp` in both directions.
     */
    public var nowhereUplink: String?
    public var nowhereDownlink: String?
    /// Whether Nowhere may share one stream carrier across flows.
    public var nowhereMultiplex: Bool
    /**
     * Sudoku carrier settings, flattened into plain stored values, exactly as
     * Nowhere stores `nowhereUplink`/`nowhereDownlink` rather than a nested
     * object. Each enum is kept as its stable id, and `toSudokuConfiguration`
     * folds these back into a `SudokuConfiguration` at dial time through that
     * type's own tolerant parsers. A nil field means "use the
     * `SudokuConfiguration` default", so the padding pair — which the short
     * link never carries — stays nil and defaults on the way in.
     */
    public var sudokuKey: String?
    public var sudokuAeadMethod: String?
    public var sudokuPaddingMin: Int?
    public var sudokuPaddingMax: Int?
    public var sudokuAsciiMode: String?
    public var sudokuCustomTables: [String]
    public var sudokuEnablePureDownlink: Bool
    public var sudokuMultiplex: String?
    public var sudokuHttpMaskDisable: Bool
    public var sudokuHttpMaskMode: String?
    public var sudokuHttpMaskTls: Bool
    public var sudokuHttpMaskHost: String?
    public var sudokuHttpMaskPathRoot: String?
    /// The servers dialled first, in order; the last of them carries this one.
    public var chain: [ProxyConfiguration]?

    public static let defaultTestseed: [UInt32] = [900, 500, 900, 256]

    public init(
        id: UUID = UUID(),
        name: String,
        serverAddress: String,
        serverPort: UInt16,
        resolvedIP: String? = nil,
        uuid: UUID,
        encryption: String,
        transport: String = "tcp",
        flow: String? = nil,
        security: String = "none",
        tls: TlsConfiguration? = nil,
        reality: RealityConfiguration? = nil,
        websocket: WebSocketConfiguration? = nil,
        httpUpgrade: HttpUpgradeConfiguration? = nil,
        xhttp: XHttpConfiguration? = nil,
        grpc: GrpcConfiguration? = nil,
        testseed: [UInt32] = ProxyConfiguration.defaultTestseed,
        muxEnabled: Bool = true,
        xudpEnabled: Bool = true,
        subscriptionId: UUID? = nil,
        outboundProtocol: OutboundProtocol = .vless,
        ssPassword: String? = nil,
        ssMethod: String? = nil,
        socks5Username: String? = nil,
        socks5Password: String? = nil,
        naiveUsername: String? = nil,
        naivePassword: String? = nil,
        naiveProtocol: NaiveProtocol? = nil,
        trojanPassword: String? = nil,
        trojanTls: TlsConfiguration? = nil,
        password: String? = nil,
        hysteriaUpMbps: Int? = nil,
        hysteriaDownMbps: Int? = nil,
        obfuscation: String? = nil,
        vmessSecurity: String? = nil,
        obfuscationPassword: String? = nil,
        wireGuardConfig: String? = nil,
        nowhereUplink: String? = nil,
        nowhereDownlink: String? = nil,
        nowhereMultiplex: Bool = false,
        sudokuKey: String? = nil,
        sudokuAeadMethod: String? = nil,
        sudokuPaddingMin: Int? = nil,
        sudokuPaddingMax: Int? = nil,
        sudokuAsciiMode: String? = nil,
        sudokuCustomTables: [String] = [],
        sudokuEnablePureDownlink: Bool = true,
        sudokuMultiplex: String? = nil,
        sudokuHttpMaskDisable: Bool = false,
        sudokuHttpMaskMode: String? = nil,
        sudokuHttpMaskTls: Bool = false,
        sudokuHttpMaskHost: String? = nil,
        sudokuHttpMaskPathRoot: String? = nil,
        chain: [ProxyConfiguration]? = nil
    ) {
        self.id = id
        self.name = name
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.resolvedIP = resolvedIP
        self.uuid = uuid
        self.encryption = encryption
        self.transport = transport
        self.flow = flow
        self.security = security
        self.tls = tls
        self.reality = reality
        self.websocket = websocket
        self.httpUpgrade = httpUpgrade
        self.xhttp = xhttp
        self.grpc = grpc
        self.testseed = testseed
        self.muxEnabled = muxEnabled
        self.xudpEnabled = xudpEnabled
        self.subscriptionId = subscriptionId
        self.outboundProtocol = outboundProtocol
        self.ssPassword = ssPassword
        self.ssMethod = ssMethod
        self.socks5Username = socks5Username
        self.socks5Password = socks5Password
        self.naiveUsername = naiveUsername
        self.naivePassword = naivePassword
        self.naiveProtocol = naiveProtocol
        self.trojanPassword = trojanPassword
        self.trojanTls = trojanTls
        self.password = password
        self.hysteriaUpMbps = hysteriaUpMbps
        self.hysteriaDownMbps = hysteriaDownMbps
        self.obfuscation = obfuscation
        self.vmessSecurity = vmessSecurity
        self.obfuscationPassword = obfuscationPassword
        self.wireGuardConfig = wireGuardConfig
        self.nowhereUplink = nowhereUplink
        self.nowhereDownlink = nowhereDownlink
        self.nowhereMultiplex = nowhereMultiplex
        self.sudokuKey = sudokuKey
        self.sudokuAeadMethod = sudokuAeadMethod
        self.sudokuPaddingMin = sudokuPaddingMin
        self.sudokuPaddingMax = sudokuPaddingMax
        self.sudokuAsciiMode = sudokuAsciiMode
        self.sudokuCustomTables = sudokuCustomTables
        self.sudokuEnablePureDownlink = sudokuEnablePureDownlink
        self.sudokuMultiplex = sudokuMultiplex
        self.sudokuHttpMaskDisable = sudokuHttpMaskDisable
        self.sudokuHttpMaskMode = sudokuHttpMaskMode
        self.sudokuHttpMaskTls = sudokuHttpMaskTls
        self.sudokuHttpMaskHost = sudokuHttpMaskHost
        self.sudokuHttpMaskPathRoot = sudokuHttpMaskPathRoot
        self.chain = chain
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, serverAddress, serverPort, resolvedIP, uuid, encryption, transport, flow, security
        case tls, reality, websocket, httpUpgrade, xhttp, grpc, testseed, muxEnabled, xudpEnabled
        case subscriptionId, outboundProtocol, ssPassword, ssMethod, socks5Username, socks5Password
        case naiveUsername, naivePassword, naiveProtocol, trojanPassword, trojanTls, password
        case hysteriaUpMbps, hysteriaDownMbps, obfuscation, vmessSecurity, obfuscationPassword
        case wireGuardConfig, nowhereUplink, nowhereDownlink, nowhereMultiplex
        case sudokuKey, sudokuAeadMethod, sudokuPaddingMin, sudokuPaddingMax, sudokuAsciiMode
        case sudokuCustomTables, sudokuEnablePureDownlink, sudokuMultiplex, sudokuHttpMaskDisable
        case sudokuHttpMaskMode, sudokuHttpMaskTls, sudokuHttpMaskHost, sudokuHttpMaskPathRoot, chain
    }

    /// Every key but the five a server cannot exist without may be missing:
    /// stores written by older builds lack the fields added since.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decode(String.self, forKey: .name)
        serverAddress = try c.decode(String.self, forKey: .serverAddress)
        serverPort = try c.decode(UInt16.self, forKey: .serverPort)
        resolvedIP = try c.decodeIfPresent(String.self, forKey: .resolvedIP)
        uuid = try c.decode(UUID.self, forKey: .uuid)
        encryption = try c.decode(String.self, forKey: .encryption)
        transport = try c.decodeIfPresent(String.self, forKey: .transport) ?? "tcp"
        flow = try c.decodeIfPresent(String.self, forKey: .flow)
        security = try c.decodeIfPresent(String.self, forKey: .security) ?? "none"
        tls = try c.decodeIfPresent(TlsConfiguration.self, forKey: .tls)
        reality = try c.decodeIfPresent(RealityConfiguration.self, forKey: .reality)
        websocket = try c.decodeIfPresent(WebSocketConfiguration.self, forKey: .websocket)
        httpUpgrade = try c.decodeIfPresent(HttpUpgradeConfiguration.self, forKey: .httpUpgrade)
        xhttp = try c.decodeIfPresent(XHttpConfiguration.self, forKey: .xhttp)
        grpc = try c.decodeIfPresent(GrpcConfiguration.self, forKey: .grpc)
        testseed = try c.decodeIfPresent([UInt32].self, forKey: .testseed) ?? ProxyConfiguration.defaultTestseed
        muxEnabled = try c.decodeIfPresent(Bool.self, forKey: .muxEnabled) ?? true
        xudpEnabled = try c.decodeIfPresent(Bool.self, forKey: .xudpEnabled) ?? true
        subscriptionId = try c.decodeIfPresent(UUID.self, forKey: .subscriptionId)
        outboundProtocol = try c.decodeIfPresent(OutboundProtocol.self, forKey: .outboundProtocol) ?? .vless
        ssPassword = try c.decodeIfPresent(String.self, forKey: .ssPassword)
        ssMethod = try c.decodeIfPresent(String.self, forKey: .ssMethod)
        socks5Username = try c.decodeIfPresent(String.self, forKey: .socks5Username)
        socks5Password = try c.decodeIfPresent(String.self, forKey: .socks5Password)
        naiveUsername = try c.decodeIfPresent(String.self, forKey: .naiveUsername)
        naivePassword = try c.decodeIfPresent(String.self, forKey: .naivePassword)
        naiveProtocol = try? c.decodeIfPresent(NaiveProtocol.self, forKey: .naiveProtocol)
        trojanPassword = try c.decodeIfPresent(String.self, forKey: .trojanPassword)
        trojanTls = try c.decodeIfPresent(TlsConfiguration.self, forKey: .trojanTls)
        password = try c.decodeIfPresent(String.self, forKey: .password)
        hysteriaUpMbps = try c.decodeIfPresent(Int.self, forKey: .hysteriaUpMbps)
        hysteriaDownMbps = try c.decodeIfPresent(Int.self, forKey: .hysteriaDownMbps)
        obfuscation = try c.decodeIfPresent(String.self, forKey: .obfuscation)
        vmessSecurity = try c.decodeIfPresent(String.self, forKey: .vmessSecurity)
        obfuscationPassword = try c.decodeIfPresent(String.self, forKey: .obfuscationPassword)
        wireGuardConfig = try c.decodeIfPresent(String.self, forKey: .wireGuardConfig)
        nowhereUplink = try c.decodeIfPresent(String.self, forKey: .nowhereUplink)
        nowhereDownlink = try c.decodeIfPresent(String.self, forKey: .nowhereDownlink)
        nowhereMultiplex = try c.decodeIfPresent(Bool.self, forKey: .nowhereMultiplex) ?? false
        sudokuKey = try c.decodeIfPresent(String.self, forKey: .sudokuKey)
        sudokuAeadMethod = try c.decodeIfPresent(String.self, forKey: .sudokuAeadMethod)
        sudokuPaddingMin = try c.decodeIfPresent(Int.self, forKey: .sudokuPaddingMin)
        sudokuPaddingMax = try c.decodeIfPresent(Int.self, forKey: .sudokuPaddingMax)
        sudokuAsciiMode = try c.decodeIfPresent(String.self, forKey: .sudokuAsciiMode)
        sudokuCustomTables = try c.decodeIfPresent([String].self, forKey: .sudokuCustomTables) ?? []
        sudokuEnablePureDownlink = try c.decodeIfPresent(Bool.self, forKey: .sudokuEnablePureDownlink) ?? true
        sudokuMultiplex = try c.decodeIfPresent(String.self, forKey: .sudokuMultiplex)
        sudokuHttpMaskDisable = try c.decodeIfPresent(Bool.self, forKey: .sudokuHttpMaskDisable) ?? false
        sudokuHttpMaskMode = try c.decodeIfPresent(String.self, forKey: .sudokuHttpMaskMode)
        sudokuHttpMaskTls = try c.decodeIfPresent(Bool.self, forKey: .sudokuHttpMaskTls) ?? false
        sudokuHttpMaskHost = try c.decodeIfPresent(String.self, forKey: .sudokuHttpMaskHost)
        sudokuHttpMaskPathRoot = try c.decodeIfPresent(String.self, forKey: .sudokuHttpMaskPathRoot)
        chain = try c.decodeIfPresent([ProxyConfiguration].self, forKey: .chain)
    }

    // MARK: - Derived values

    public var connectAddress: String { resolvedIP ?? serverAddress }

    /// RFC 3986 §3.2.2: IPv6 literals must be bracketed in URL authority components.
    public var bracketedServerAddress: String {
        serverAddress.utf8.contains(UInt8(ascii: ":")) ? "[\(serverAddress)]" : serverAddress
    }

    /// `host:port` as a user reads it, with an IPv6 literal bracketed.
    public var displayEndpoint: String { "\(bracketedServerAddress):\(serverPort)" }

    /**
     * The TLS this server dials with: Trojan keeps its own, everything else
     * uses `tls` (VLESS and VMess only when security is "tls").
     */
    private var effectiveTls: TlsConfiguration? {
        switch outboundProtocol {
        case .trojan:
            return trojanTls ?? tls
        case .vless, .vmess:
            return security == "tls" ? tls : nil
        default:
            return tls
        }
    }

    /**
     * Whether this server's certificate goes unchecked: "allow insecure" on
     * and no pinned certificate (a pin is checked either way). UNSAFE, which
     * the server list says on the row.
     */
    public var skipsCertificateCheck: Bool {
        guard let tls = effectiveTls else { return false }
        return tls.allowInsecure && (tls.pinnedCertSha256 ?? []).isEmpty
    }

    /// The Host this server's transport sends, or the gRPC authority; nil for none.
    var transportHost: String? {
        let raw: String?
        switch transport {
        case "ws": raw = websocket?.host
        case "httpupgrade": raw = httpUpgrade?.host
        case "xhttp": raw = xhttp?.host
        case "grpc": raw = grpc?.authority
        default: raw = nil
        }
        guard let text = raw else { return nil }
        return ShareLinkParams.firstName(text)
    }

    /// The server name a link without `sni` reads back as.
    var impliedServerName: String { transportHost ?? serverAddress }

    /**
     * This server with its TLS name taken from the transport's Host when the
     * name it has is an IP address.
     *
     * An IP is never sent as SNI, so such a server — a CDN given by IP with
     * the domain only in `host=`, stored before links fell back to the Host
     * — reached the CDN with no name and got 421 Misdirected Request. Applied
     * where every dial starts, so stored servers work without a refresh.
     */
    public func withTransportHostSni() -> ProxyConfiguration {
        guard let host = transportHost, !ShareLinkParams.isIpLiteralHost(host) else { return self }
        func fixed(_ t: TlsConfiguration?) -> TlsConfiguration? {
            guard var t = t else { return nil }
            guard ShareLinkParams.isIpLiteralHost(t.serverName) || LinkText.isBlank(t.serverName) else { return nil }
            t.serverName = host
            return t
        }
        let tlsFixed = fixed(tls)
        let trojanFixed = fixed(trojanTls)
        if tlsFixed == nil && trojanFixed == nil { return self }
        var copy = self
        copy.tls = tlsFixed ?? tls
        copy.trojanTls = trojanFixed ?? trojanTls
        return copy
    }

    /// Equality of everything that describes the server, leaving out its
    /// identity, where it came from and the address it last resolved to.
    public func contentEquals(_ other: ProxyConfiguration) -> Bool {
        var a = self
        var b = other
        a.id = b.id
        a.resolvedIP = nil
        b.resolvedIP = nil
        a.subscriptionId = nil
        b.subscriptionId = nil
        return a == b
    }

    public func withChain(_ chain: [ProxyConfiguration]?) -> ProxyConfiguration {
        var copy = self
        copy.chain = chain
        return copy
    }

    /**
     * Turns the flat `sudoku*` fields back into a `SudokuConfiguration` for the
     * dial.
     *
     * Each absent field falls back to the `SudokuConfiguration` default rather
     * than to whatever a share link happened to omit, and every value passes
     * through that type's own tolerant parser so a stray case or a legacy
     * spelling resolves the same way the importer resolved it. The key is the
     * one field with no default: a Sudoku outbound that lost it cannot dial,
     * so its absence is an error rather than a silent empty key.
     */
    public func toSudokuConfiguration() throws -> SudokuConfiguration {
        guard let key = ShareLinkParams.nonEmpty(sudokuKey) else {
            throw MythaiaError.protocolError("Sudoku key not set")
        }
        let aead = sudokuAeadMethod.flatMap { SudokuAeadMethod.fromId($0) } ?? SudokuAeadMethod.chacha20Poly1305
        let ascii = sudokuAsciiMode.flatMap { SudokuAsciiMode.fromNormalized($0) } ?? SudokuAsciiMode.preferEntropy
        let multiplex = sudokuMultiplex.map { SudokuMultiplex.fromNormalized($0) } ?? SudokuMultiplex.off
        let maskMode = sudokuHttpMaskMode.flatMap { SudokuHttpMaskMode.fromId($0) } ?? SudokuHttpMaskMode.legacy
        return SudokuConfiguration(
            key: key,
            aeadMethod: aead,
            paddingMin: sudokuPaddingMin ?? SudokuConfiguration.defaultPaddingMin,
            paddingMax: sudokuPaddingMax ?? SudokuConfiguration.defaultPaddingMax,
            asciiMode: ascii,
            customTables: sudokuCustomTables,
            enablePureDownlink: sudokuEnablePureDownlink,
            multiplex: multiplex,
            httpMask: SudokuHttpMaskConfiguration(
                disable: sudokuHttpMaskDisable,
                mode: maskMode,
                tls: sudokuHttpMaskTls,
                host: sudokuHttpMaskHost ?? "",
                pathRoot: sudokuHttpMaskPathRoot ?? ""
            )
        )
    }
}
