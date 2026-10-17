import Foundation

/// The security layer of one hop: none, TLS, or REALITY.
enum DialSecurity {
    case none
    case tls(TlsConfiguration)
    case reality(RealityConfiguration)
}

/// Builds the stack for a server, hop by hop: the connection to the hop's
/// server (TCP for the first, a flow through the previous hop for the
/// rest), then TLS or REALITY, then the transport (WebSocket, HTTPUpgrade,
/// gRPC, XHTTP), then the protocol's request for the next hop's server — or,
/// on the last hop, for the target.
public enum Dialer {
    /// Linear backoff between attempts: 200, 400, 600, 800 ms.
    static let maxRetryAttempts = 5
    static let retryBaseDelayNanoseconds: UInt64 = 200_000_000

    /// How long one TCP connect may take inside the overall deadline.
    static let connectTimeout: Double = 10

    static let visionFlow = "xtls-rprx-vision"
    static let browserDefaultAlpn = ["h2", "http/1.1"]

    /// A TCP flow to `target` through `configuration`, its chain included.
    public static func connect(_ configuration: ProxyConfiguration, to target: Endpoint,
                               initialData: Data? = nil, timeout: Double = 15) async throws -> ByteStream {
        let hops = (configuration.chain ?? []).map { $0.withTransportHostSni() } + [configuration.withTransportHostSni()]
        for hop in hops {
            try checkDialable(hop)
        }
        // A chain fails as a whole: retrying a hop would need the hops before
        // it again, so only a single server is retried here.
        let attempts = hops.count == 1 ? maxRetryAttempts : 1
        let resources = DialResources()
        return try await runDial(timeout: timeout, what: "connecting to \(configuration.name)", resources: resources) { () async throws -> ByteStream in
            try await Dialer.withRetries(attempts, resources: resources) { () async throws -> ByteStream in
                try await Dialer.dialChain(hops, target: target, initialData: initialData, resources: resources)
            }
        }
    }

    /// A TCP flow to `target` without a proxy.
    public static func direct(to target: Endpoint, timeout: Double = 10) async throws -> ByteStream {
        return try await TCPStream.connect(host: target.host, port: target.port, timeout: timeout)
    }

    // MARK: - Checks before any connection

    /// Refuses, before anything is dialled, what this build cannot dial.
    static func checkDialable(_ hop: ProxyConfiguration) throws {
        switch hop.outboundProtocol {
        case .vless:
            try checkVlessEncryption(hop)
            try checkVision(hop)
        case .trojan, .vmess, .shadowsocks, .socks5, .naiveHttp11:
            return
        default:
            throw MythaiaError.unsupported(hop.outboundProtocol.displayName)
        }
    }

    /// Post-quantum VLESS encryption is not ported. A value other than
    /// "none" fails the dial rather than being ignored: ignoring it would
    /// silently downgrade to plaintext and leak the UUID and payload.
    static func checkVlessEncryption(_ hop: ProxyConfiguration) throws {
        let encryption = hop.encryption.trimmingCharacters(in: .whitespaces)
        if !(encryption.isEmpty || encryption == "none") {
            throw MythaiaError.unsupported("VLESS encryption")
        }
    }

    /// Vision pads a raw TLS stream, so it needs TCP under it and TLS or
    /// REALITY around it. Checked before anything is written: the header
    /// carries the UUID, which would otherwise cross the wire in the clear.
    static func checkVision(_ hop: ProxyConfiguration) throws {
        guard isVisionFlow(hop.flow) else { return }
        let transport = transportName(hop.transport)
        if transport != "tcp" {
            throw MythaiaError.invalidConfiguration("Vision flow is not supported over \(transportDisplayName(transport)) transport")
        }
        if case .none = try vlessSecurity(hop, transport: transport) {
            throw MythaiaError.invalidConfiguration("Vision requires outer TLS or REALITY transport")
        }
    }

    // MARK: - The chain

    static func dialChain(_ hops: [ProxyConfiguration], target: Endpoint, initialData: Data?,
                          resources: DialResources) async throws -> ByteStream {
        var below: ByteStream? = nil
        for index in 0..<hops.count {
            let hop = hops[index]
            let isLast = index == hops.count - 1
            let hopTarget: Endpoint
            if isLast {
                hopTarget = target
            } else {
                // The next hop's name goes out, not its resolved address: the
                // hop resolves it on its own side.
                hopTarget = Endpoint(host: hops[index + 1].serverAddress, port: hops[index + 1].serverPort)
            }
            let stream = try await dialHop(
                hop,
                below: below,
                prefix: Array(hops[0..<index]),
                target: hopTarget,
                initialData: isLast ? initialData : nil,
                resources: resources
            )
            resources.track(stream)
            below = stream
        }
        guard let result = below else {
            throw MythaiaError.invalidConfiguration("there is no server to dial")
        }
        return result
    }

    /// One hop: `below` is the flow to this hop's server through the hops
    /// before it (nil for the first, which dials directly); `prefix` is those
    /// hops, for transports that open more connections later.
    private static func dialHop(_ hop: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                target: Endpoint, initialData: Data?, resources: DialResources) async throws -> ByteStream {
        switch hop.outboundProtocol {
        case .vless:
            return try await dialVless(hop, below: below, prefix: prefix, target: target, initialData: initialData, resources: resources)
        case .trojan:
            return try await dialTrojan(hop, below: below, prefix: prefix, target: target, initialData: initialData, resources: resources)
        case .vmess:
            return try await dialVmess(hop, below: below, prefix: prefix, target: target, initialData: initialData, resources: resources)
        case .shadowsocks:
            return try await dialShadowsocks(hop, below: below, target: target, initialData: initialData, resources: resources)
        case .socks5:
            return try await dialSocks(hop, below: below, target: target, initialData: initialData, resources: resources)
        case .naiveHttp11:
            return try await dialHttp11(hop, below: below, target: target, initialData: initialData, resources: resources)
        default:
            throw MythaiaError.unsupported(hop.outboundProtocol.displayName)
        }
    }

    // MARK: - Protocols

    static func isVisionFlow(_ flow: String?) -> Bool {
        return flow == visionFlow || flow == visionFlow + "-udp443"
    }

    private static func dialVless(_ hop: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                  target: Endpoint, initialData: Data?, resources: DialResources) async throws -> ByteStream {
        try checkVlessEncryption(hop)
        try checkVision(hop)
        let isVision = isVisionFlow(hop.flow)
        let transport = transportName(hop.transport)
        let security = try vlessSecurity(hop, transport: transport)

        let pipe = try await openPipe(hop, below: below, prefix: prefix, security: security, transport: transport,
                                      needsSession: isVision, resources: resources)
        let header = VlessProtocol.encodeRequestHeader(
            uuid: hop.uuid,
            command: .tcp,
            destinationAddress: target.host,
            destinationPort: target.port,
            flow: isVision ? visionFlow : nil
        )
        let base = VlessConnection(pipe.stream)

        if isVision {
            // Vision needs the bytes under the outer TLS for direct copy,
            // which only this app's own TLS session gives.
            guard let session = pipe.session else {
                throw MythaiaError.unsupported("XTLS Vision without this app's own TLS")
            }
            let vision = VlessVisionConnection(
                base,
                userUUID: VlessProtocol.uuidToBytes(hop.uuid),
                testseed: hop.testseed.map { Int($0) },
                raw: session
            )
            try await vision.sendRequest(header, initialData: initialData)
            return vision
        }

        var request = header
        if let initialData = initialData {
            request.append(initialData)
        }
        try await base.send(request)
        return base
    }

    private static func dialTrojan(_ hop: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                   target: Endpoint, initialData: Data?, resources: DialResources) async throws -> ByteStream {
        let password = try trojanPassword(hop)
        let tls = try trojanTls(hop)
        let pipe = try await openPipe(hop, below: below, prefix: prefix, security: .tls(tls),
                                      transport: transportName(hop.transport), needsSession: false, resources: resources)
        let trojan = TrojanConnection(pipe.stream, password: password, destinationHost: target.host, destinationPort: target.port)
        // The request header rides the first write, so it goes out now even
        // when the app has sent nothing yet: SSH, SMTP, IMAP all wait for the
        // server's banner, and the server cannot send one until it has
        // learnt the destination.
        try await trojan.send(initialData ?? Data())
        return trojan
    }

    private static func dialVmess(_ hop: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                  target: Endpoint, initialData: Data?, resources: DialResources) async throws -> ByteStream {
        let security = VmessSecurity.fromRaw(hop.vmessSecurity)
        let sealed = try VmessProtocol.sealRequest(id: hop.uuid, host: target.host, port: target.port,
                                                   command: VmessProtocol.commandTCP, security: security)
        let pipe = try await openPipe(hop, below: below, prefix: prefix, security: try vmessSecurity(hop),
                                      transport: transportName(hop.transport), needsSession: false, resources: resources)
        let connection = VmessConnection(pipe.stream, session: sealed.session, requestHeader: sealed.bytes)
        // The header is only written by the first send, so an empty
        // initialData still has to flush it.
        try await connection.send(initialData ?? Data())
        return connection
    }

    private static func dialShadowsocks(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                                        initialData: Data?, resources: DialResources) async throws -> ByteStream {
        guard let method = hop.ssMethod else {
            throw MythaiaError.invalidConfiguration("Shadowsocks method not configured")
        }
        guard let password = hop.ssPassword else {
            throw MythaiaError.invalidConfiguration("Shadowsocks password not configured")
        }
        guard let cipher = ShadowsocksCipher.fromMethod(method) else {
            throw ShadowsocksError.invalidMethod(method)
        }
        var pskList: [Data] = []
        if cipher.isSS2022 {
            guard let decoded = ShadowsocksKeyDerivation.decodePSKList(password, keySize: cipher.keySize) else {
                throw ShadowsocksError.invalidPSK
            }
            pskList = decoded
        }

        let base = try await openSecured(hop, below: below, security: .none, alpn: [], needsSession: false, resources: resources).stream
        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: target.host, port: target.port)
        let connection: ByteStream
        if cipher.isSS2022 {
            connection = Shadowsocks2022Connection(base, cipher: cipher, pskList: pskList, addressHeader: addressHeader)
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            connection = ShadowsocksConnection(base, cipher: cipher, masterKey: masterKey, addressHeader: addressHeader)
        }
        // The address header rides the first write, so it goes out now even
        // when the app has sent nothing: a server-speaks-first protocol never
        // gets its banner until the server knows where to connect. A chunk
        // carrying only the header is valid AEAD, and 2022 pads an empty
        // initial payload.
        try await connection.send(initialData ?? Data())
        return connection
    }

    private static func dialSocks(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                                  initialData: Data?, resources: DialResources) async throws -> ByteStream {
        let base = try await openSecured(hop, below: below, security: .none, alpn: [], needsSession: false, resources: resources).stream
        let stream = try await SocksClient.connect(over: base, to: target, username: hop.socks5Username, password: hop.socks5Password)
        if let initialData = initialData, !initialData.isEmpty {
            try await stream.send(initialData)
        }
        return stream
    }

    private static func dialHttp11(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                                   initialData: Data?, resources: DialResources) async throws -> ByteStream {
        // The server's own TLS settings (allow insecure, pins) with the name
        // and ALPN this proxy is dialled with.
        let tls = hop.tls ?? TlsConfiguration(serverName: hop.serverAddress)
        let secured = try await openSecured(hop, below: below, security: .tls(tls), alpn: ["http/1.1"],
                                            needsSession: false, resources: resources)
        let stream = try await NaiveHttp11Connection.openTunnel(over: secured.stream, destination: target,
                                                                username: hop.naiveUsername, password: hop.naivePassword)
        if let initialData = initialData, !initialData.isEmpty {
            try await stream.send(initialData)
        }
        return stream
    }

    // MARK: - Security choices

    /// VLESS decides by the settings it has, as the Kotlin client does: TLS
    /// settings mean TLS, REALITY settings REALITY. REALITY carries no
    /// WebSocket or HTTPUpgrade (Xray has no such combination).
    static func vlessSecurity(_ hop: ProxyConfiguration, transport: String) throws -> DialSecurity {
        let wantsReality = hop.security == "reality" || (hop.security != "tls" && hop.tls == nil && hop.reality != nil)
        if wantsReality {
            guard let reality = hop.reality else {
                throw MythaiaError.invalidConfiguration("REALITY is selected but its settings are missing")
            }
            if transport == "ws" || transport == "httpupgrade" {
                throw MythaiaError.unsupported("REALITY with the \(transportDisplayName(transport)) transport")
            }
            return .reality(reality)
        }
        if let tls = hop.tls {
            return .tls(tls)
        }
        if hop.security == "tls" {
            throw MythaiaError.invalidConfiguration("TLS is selected but its settings are missing")
        }
        return .none
    }

    /// VMess runs over TLS only when security is "tls"; REALITY is VLESS-only.
    static func vmessSecurity(_ hop: ProxyConfiguration) throws -> DialSecurity {
        if hop.security == "reality" {
            throw MythaiaError.unsupported("REALITY with VMess")
        }
        if hop.security == "tls", let tls = hop.tls {
            return .tls(tls)
        }
        return .none
    }

    /// Trojan mandates TLS: its own settings, or the shared ones.
    static func trojanTls(_ hop: ProxyConfiguration) throws -> TlsConfiguration {
        guard let tls = hop.trojanTls ?? hop.tls else {
            throw MythaiaError.invalidConfiguration("Trojan requires TLS configuration")
        }
        return tls
    }

    static func trojanPassword(_ hop: ProxyConfiguration) throws -> String {
        guard let password = hop.trojanPassword, !password.isEmpty else {
            throw MythaiaError.invalidConfiguration("Trojan password not set")
        }
        return password
    }

    // MARK: - Transport

    /// The transport name, with its aliases folded: Xray renamed `tcp` to
    /// `raw`, and `splithttp` is XHTTP's old name.
    static func transportName(_ raw: String) -> String {
        let name = raw.lowercased()
        switch name {
        case "", "tcp", "raw": return "tcp"
        case "splithttp": return "xhttp"
        default: return name
        }
    }

    static func transportDisplayName(_ transport: String) -> String {
        switch transport {
        case "ws": return "WebSocket"
        case "httpupgrade": return "HTTP upgrade"
        case "xhttp": return "XHTTP"
        case "grpc": return "gRPC"
        default: return transport
        }
    }

    /// The ALPN a hop offers. WebSocket and HTTPUpgrade are HTTP/1.1
    /// upgrades: a server allowed to pick h2 would read the upgrade request
    /// as a bogus HTTP/2 preface and hang up. gRPC needs h2. REALITY keeps the
    /// browser default its fingerprint sends.
    static func alpn(transport: String, security: DialSecurity) -> [String] {
        if case .reality = security { return browserDefaultAlpn }
        switch transport {
        case "ws", "httpupgrade":
            return ["http/1.1"]
        case "grpc":
            return ["h2"]
        default:
            if case .tls(let tls) = security, let configured = tls.alpn, !configured.isEmpty {
                return configured
            }
            return browserDefaultAlpn
        }
    }

    enum XHttpVersion {
        case http11
        case http2
    }

    /// HTTP version for XHTTP: REALITY always HTTP/2; no TLS plain HTTP/1.1;
    /// TLS with a single "http/1.1" ALPN HTTP/1.1; a single "h3" would need
    /// QUIC; everything else HTTP/2.
    static func xhttpVersion(_ security: DialSecurity) throws -> XHttpVersion {
        switch security {
        case .reality:
            return .http2
        case .none:
            return .http11
        case .tls(let tls):
            let configured = (tls.alpn ?? []).map { $0.lowercased() }
            if configured.count != 1 { return .http2 }
            if configured[0] == "http/1.1" { return .http11 }
            if configured[0] == "h3" {
                throw MythaiaError.unsupported("XHTTP over HTTP/3 (QUIC)")
            }
            return .http2
        }
    }

    /// The ALPN XHTTP offers: only values a TCP connection can carry.
    static func xhttpAlpn(_ version: XHttpVersion, security: DialSecurity) -> [String] {
        if case .reality = security { return browserDefaultAlpn }
        switch version {
        case .http11:
            return ["http/1.1"]
        case .http2:
            if case .tls(let tls) = security, let configured = tls.alpn {
                let filtered = configured.filter { $0.lowercased() == "h2" || $0.lowercased() == "http/1.1" }
                if filtered.isEmpty || (filtered.count == 1 && filtered[0].lowercased() == "http/1.1") {
                    return browserDefaultAlpn
                }
                return filtered
            }
            return browserDefaultAlpn
        }
    }

    /// The HTTP/2 `:authority` for gRPC: the configured one, else the TLS
    /// name, else the REALITY name, else the server address.
    static func grpcAuthority(_ grpc: GrpcConfiguration, hop: ProxyConfiguration, security: DialSecurity) -> String {
        if !grpc.authority.isEmpty { return grpc.authority }
        switch security {
        case .tls(let tls) where !tls.serverName.isEmpty:
            return tls.serverName
        case .reality(let reality) where !reality.serverName.isEmpty:
            return reality.serverName
        default:
            return hop.serverAddress
        }
    }

    struct HopPipe {
        let stream: ByteStream
        /// This app's own TLS session under the transport, when there is one
        /// and nothing sits between it and the protocol.
        let session: TLSSessionStream?
    }

    /// The secured connection plus the transport on top.
    static func openPipe(_ hop: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                         security: DialSecurity, transport: String, needsSession: Bool,
                         resources: DialResources) async throws -> HopPipe {
        switch transport {
        case "tcp":
            let secured = try await openSecured(hop, below: below, security: security,
                                                alpn: alpn(transport: transport, security: security),
                                                needsSession: needsSession, resources: resources)
            return HopPipe(stream: secured.stream, session: secured.session)

        case "ws":
            guard let websocket = hop.websocket else {
                throw MythaiaError.invalidConfiguration("ws transport with no WebSocket configuration")
            }
            let secured = try await openSecured(hop, below: below, security: security,
                                                alpn: alpn(transport: transport, security: security),
                                                needsSession: false, resources: resources)
            let stream = try await WebSocketTransport.open(over: secured.stream, configuration: websocket, earlyData: nil)
            resources.track(stream)
            return HopPipe(stream: stream, session: nil)

        case "httpupgrade":
            guard let httpUpgrade = hop.httpUpgrade else {
                throw MythaiaError.invalidConfiguration("httpupgrade transport with no configuration")
            }
            let secured = try await openSecured(hop, below: below, security: security,
                                                alpn: alpn(transport: transport, security: security),
                                                needsSession: false, resources: resources)
            let stream = try await HTTPUpgradeTransport.open(over: secured.stream, configuration: httpUpgrade)
            resources.track(stream)
            return HopPipe(stream: stream, session: nil)

        case "grpc":
            guard let grpc = hop.grpc else {
                throw MythaiaError.invalidConfiguration("grpc transport with no configuration")
            }
            let secured = try await openSecured(hop, below: below, security: security,
                                                alpn: alpn(transport: transport, security: security),
                                                needsSession: false, resources: resources)
            let authority = grpcAuthority(grpc, hop: hop, security: security)
            let stream = try await GRPCTransport.open(over: secured.stream, configuration: grpc, authority: authority)
            resources.track(stream)
            return HopPipe(stream: stream, session: nil)

        case "xhttp":
            guard let xhttp = hop.xhttp else {
                throw MythaiaError.invalidConfiguration("xhttp transport with no configuration")
            }
            let version = try xhttpVersion(security)
            let offered = xhttpAlpn(version, security: security)
            // The first connection is opened here, so the version the server
            // actually chose is known before XHTTP starts speaking.
            let first = try await openSecured(hop, below: below, security: security, alpn: offered,
                                              needsSession: false, resources: resources)
            let speaking: String?
            if case .none = security {
                speaking = nil
            } else {
                speaking = first.negotiatedALPN ?? (version == .http2 ? "h2" : "http/1.1")
            }
            let firstStream = DialFirstStream(first.stream)
            let dial: () async throws -> ByteStream = {
                if let stream = firstStream.take() {
                    return stream
                }
                return try await Dialer.redialSecured(hop, prefix: prefix, security: security, alpn: offered)
            }
            let authority = xhttp.host.isEmpty ? hop.serverAddress : xhttp.host
            let stream = try await XHTTPTransport.open(configuration: xhttp, authority: authority, alpn: speaking, dial: dial)
            resources.track(stream)
            return HopPipe(stream: stream, session: nil)

        default:
            throw MythaiaError.unsupported("the \(transport) transport")
        }
    }

    /// A fresh secured connection to `hop`'s server, through the hops before
    /// it rebuilt from scratch: XHTTP may need several connections.
    private static func redialSecured(_ hop: ProxyConfiguration, prefix: [ProxyConfiguration],
                                      security: DialSecurity, alpn: [String]) async throws -> ByteStream {
        let resources = DialResources()
        return try await runDial(timeout: connectTimeout, what: "connecting to \(hop.name)", resources: resources) { () async throws -> ByteStream in
            var below: ByteStream? = nil
            if !prefix.isEmpty {
                below = try await Dialer.dialChain(prefix, target: Endpoint(host: hop.serverAddress, port: hop.serverPort),
                                                   initialData: nil, resources: resources)
            }
            let secured = try await Dialer.openSecured(hop, below: below, security: security, alpn: alpn,
                                                       needsSession: false, resources: resources)
            return secured.stream
        }
    }

    struct Secured {
        let stream: ByteStream
        let session: TLSSessionStream?
        let negotiatedALPN: String?
    }

    /// The connection to the hop's server with its security layer. A first
    /// hop with plain TLS uses the system's TLS; a hop through another hop,
    /// REALITY, and Vision (which needs the bytes under the TLS records) use
    /// this app's own TLS 1.3 client.
    static func openSecured(_ hop: ProxyConfiguration, below: ByteStream?, security: DialSecurity, alpn: [String],
                            needsSession: Bool, resources: DialResources) async throws -> Secured {
        let host = hop.connectAddress
        let port = hop.serverPort

        if below == nil && !needsSession, case .tls(let tls) = security {
            let stream = try await SystemTLSStream.connect(host: host, port: port,
                                                           options: tlsOptions(tls, alpn: alpn), timeout: connectTimeout)
            resources.track(stream)
            return Secured(stream: stream, session: nil, negotiatedALPN: stream.negotiatedALPN)
        }

        let base: ByteStream
        if let below = below {
            base = below
        } else {
            let tcp = try await TCPStream.connect(host: host, port: port, timeout: connectTimeout)
            resources.track(tcp)
            base = tcp
        }

        switch security {
        case .none:
            return Secured(stream: base, session: nil, negotiatedALPN: nil)
        case .tls(let tls):
            let session = try await TLSClient.handshake(over: base, options: tlsOptions(tls, alpn: alpn), fingerprint: tls.fingerprint)
            resources.track(session)
            return Secured(stream: session, session: session, negotiatedALPN: session.negotiatedALPN)
        case .reality(let reality):
            let stream = try await RealityClient.handshake(over: base, configuration: reality, alpn: alpn)
            resources.track(stream)
            let session = stream as? TLSSessionStream
            return Secured(stream: stream, session: session, negotiatedALPN: session?.negotiatedALPN)
        }
    }

    static func tlsOptions(_ tls: TlsConfiguration, alpn: [String]) -> TLSClientOptions {
        return TLSClientOptions(
            serverName: tls.serverName,
            alpn: alpn,
            allowInsecure: tls.allowInsecure,
            pinnedCertSHA256: pinnedDigests(tls.pinnedCertSha256),
            minVersion: tls.minVersion,
            maxVersion: tls.maxVersion
        )
    }

    /// Hex SHA-256 pins (colons allowed) as bytes; anything else is skipped.
    static func pinnedDigests(_ pins: [String]?) -> [Data] {
        guard let pins = pins else { return [] }
        var out = [Data]()
        for pin in pins {
            let hex = Array(pin.replacingOccurrences(of: ":", with: "").lowercased().utf8)
            guard hex.count == 64 else { continue }
            var bytes = [UInt8]()
            bytes.reserveCapacity(32)
            var valid = true
            var i = 0
            while i < hex.count {
                guard let high = hexValue(hex[i]), let low = hexValue(hex[i + 1]) else {
                    valid = false
                    break
                }
                bytes.append(high << 4 | low)
                i += 2
            }
            if valid {
                out.append(Data(bytes))
            }
        }
        return out
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }

    // MARK: - Deadline and retries

    /// Runs `operation` within `timeout`. On timeout every connection the
    /// dial opened is closed — that is what unblocks a handshake waiting on
    /// a silent server — and the dial fails with `timeout(what)`.
    static func runDial<T>(timeout: Double, what: String, resources: DialResources,
                           _ operation: @escaping () async throws -> T) async throws -> T {
        let outcome = DialOutcome<T>()
        do {
            try await withThrowingTaskGroup(of: Void.self, returning: Void.self) { group in
                group.addTask {
                    let value = try await operation()
                    if !outcome.succeed(value) {
                        // The deadline won the race: nobody takes this value.
                        Dialer.closeValue(value)
                        throw MythaiaError.timeout(what)
                    }
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(max(0, timeout) * 1_000_000_000))
                    if outcome.timeOut() {
                        resources.closeAll()
                        throw MythaiaError.timeout(what)
                    }
                }
                defer { group.cancelAll() }
                _ = try await group.next()
            }
        } catch {
            resources.closeAll()
            throw error
        }
        guard let value = outcome.takeValue() else {
            resources.closeAll()
            throw MythaiaError.timeout(what)
        }
        resources.release()
        return value
    }

    private static func closeValue<T>(_ value: T) {
        if let stream = value as? ByteStream {
            stream.close()
        } else if let datagrams = value as? DatagramStream {
            datagrams.close()
        }
    }

    /// Up to `attempts` tries with linear backoff. What cannot get better by
    /// trying again — a configuration this build refuses, a certificate that
    /// does not verify — fails at once.
    static func withRetries<T>(_ attempts: Int, resources: DialResources,
                               _ attempt: () async throws -> T) async throws -> T {
        var lastError: Error = MythaiaError.connectFailed("all attempts failed")
        for index in 0..<max(1, attempts) {
            if index > 0 {
                try await Task.sleep(nanoseconds: retryBaseDelayNanoseconds * UInt64(index))
            }
            try Task.checkCancellation()
            do {
                return try await attempt()
            } catch {
                resources.closeTracked()
                if Task.isCancelled || !isRetryable(error) {
                    throw error
                }
                lastError = error
                Log.debug("Dial attempt \(index + 1)/\(attempts) failed: \(error.localizedDescription)")
            }
        }
        throw lastError
    }

    static func isRetryable(_ error: Error) -> Bool {
        if error is CancellationError { return false }
        guard let failure = error as? MythaiaError else { return true }
        switch failure {
        case .invalidConfiguration, .unsupported, .parse:
            return false
        case .tls(let why):
            let lowered = why.lowercased()
            return !(lowered.contains("certificate") || lowered.contains("trust") || lowered.contains("pin"))
        case .http(let code, _):
            return code != 407
        default:
            return true
        }
    }
}

/// Every connection a dial has opened, so a failure or a timeout can close
/// them all — nothing else holds them until the dial returns.
final class DialResources: @unchecked Sendable {
    private let lock = NSLock()
    private var streams: [ByteStream] = []
    private var datagrams: [DatagramStream] = []
    private var finished = false

    func track(_ stream: ByteStream) {
        lock.lock()
        if finished {
            lock.unlock()
            stream.close()
            return
        }
        streams.append(stream)
        lock.unlock()
    }

    func track(_ datagram: DatagramStream) {
        lock.lock()
        if finished {
            lock.unlock()
            datagram.close()
            return
        }
        datagrams.append(datagram)
        lock.unlock()
    }

    /// Closes what one failed attempt opened; the next attempt starts clean.
    func closeTracked() {
        lock.lock()
        let openStreams = streams
        let openDatagrams = datagrams
        streams = []
        datagrams = []
        lock.unlock()
        for stream in openStreams.reversed() {
            stream.close()
        }
        for datagram in openDatagrams {
            datagram.close()
        }
    }

    /// Closes everything, and anything tracked from now on as it arrives.
    func closeAll() {
        lock.lock()
        finished = true
        lock.unlock()
        closeTracked()
    }

    /// The dial succeeded: the caller owns the connections now.
    func release() {
        lock.lock()
        streams = []
        datagrams = []
        finished = true
        lock.unlock()
    }
}

/// The value a dial produced, handed out of its task; whichever of the
/// value and the deadline comes first wins, exactly once.
final class DialOutcome<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?
    private var succeeded = false
    private var timedOut = false

    /// False when the deadline already passed.
    func succeed(_ newValue: T) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if timedOut { return false }
        value = newValue
        succeeded = true
        return true
    }

    /// False when the value already arrived.
    func timeOut() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if succeeded { return false }
        timedOut = true
        return true
    }

    func takeValue() -> T? {
        lock.lock()
        defer { lock.unlock() }
        let out = value
        value = nil
        return out
    }
}

/// The connection opened before XHTTP starts, handed to its first dial.
final class DialFirstStream: @unchecked Sendable {
    private let lock = NSLock()
    private var stream: ByteStream?

    init(_ stream: ByteStream) {
        self.stream = stream
    }

    func take() -> ByteStream? {
        lock.lock()
        defer { lock.unlock() }
        let out = stream
        stream = nil
        return out
    }
}
