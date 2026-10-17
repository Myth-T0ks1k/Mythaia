import Foundation

extension Dialer {
    /// A UDP flow to `target` through `configuration` (VLESS, Trojan, VMess UDP over the stream;
    /// SOCKS5 UDP ASSOCIATE; Shadowsocks UDP). Each packet is one datagram to or from `target`.
    public static func connectUDP(_ configuration: ProxyConfiguration, to target: Endpoint,
                                  timeout: Double = 15) async throws -> DatagramStream {
        let config = configuration.withTransportHostSni()
        let chain = (config.chain ?? []).map { $0.withTransportHostSni() }
        try checkUdpDialable(config, target: target)
        // Shadowsocks UDP goes straight to its server, so only the other
        // protocols need their chain dialable.
        if config.outboundProtocol != .shadowsocks {
            for hop in chain {
                try checkDialable(hop)
            }
        }
        let attempts = chain.isEmpty ? maxRetryAttempts : 1
        let resources = DialResources()
        return try await runDial(timeout: timeout, what: "connecting to \(config.name)", resources: resources) { () async throws -> DatagramStream in
            try await Dialer.withRetries(attempts, resources: resources) { () async throws -> DatagramStream in
                try await Dialer.dialUdp(config, chain: chain, target: target, resources: resources)
            }
        }
    }

    /// A UDP flow to `target` without a proxy.
    public static func directUDP(to target: Endpoint) async throws -> DatagramStream {
        return try await UdpSocketConnection.connect(host: target.host, port: target.port, timeout: connectTimeout)
    }

    /// Refuses, before anything is dialled, a UDP flow this server cannot carry.
    static func checkUdpDialable(_ config: ProxyConfiguration, target: Endpoint) throws {
        switch config.outboundProtocol {
        case .vless:
            try checkVlessEncryption(config)
            try checkVision(config)
            // Vision drops UDP to port 443 unless the -udp443 flow variant
            // asks for it: that is QUIC, and refusing it sends the app back
            // to TCP, where Vision does its work.
            if isVisionFlow(config.flow) && target.port == 443 && config.flow != visionFlow + "-udp443" {
                throw MythaiaError.unsupported("UDP to port 443 through XTLS Vision")
            }
        case .trojan, .vmess, .socks5, .shadowsocks:
            return
        case .anytls:
            _ = try anyTlsSecurity(config)
        case .hysteria2, .tuic:
            return
        case .naiveHttp11, .naiveHttp2:
            throw MythaiaError.unsupported("UDP through \(config.outboundProtocol.displayName)")
        default:
            throw MythaiaError.unsupported(config.outboundProtocol.displayName)
        }
    }

    static func dialUdp(_ config: ProxyConfiguration, chain: [ProxyConfiguration], target: Endpoint,
                        resources: DialResources) async throws -> DatagramStream {
        if config.outboundProtocol == .shadowsocks {
            // Shadowsocks UDP is per-packet AEAD over real UDP; the protocol
            // has no UDP command for a stream, so it goes straight to the
            // server even behind a chain.
            let mode = try ShadowsocksUdpConnection.mode(method: config.ssMethod, password: config.ssPassword)
            let socket = try await UdpSocketConnection.connect(host: config.connectAddress, port: config.serverPort, timeout: connectTimeout)
            resources.track(socket)
            let connection = ShadowsocksUdpConnection(socket: socket, mode: mode, destinationHost: target.host, destinationPort: target.port)
            resources.track(connection)
            return connection
        }
        if isQuicProtocol(config.outboundProtocol) {
            // QUIC datagrams on the server's pooled connection; see DialerQuic.
            return try await dialQuicUdp(config, chain: chain, target: target, resources: resources)
        }

        var below: ByteStream? = nil
        if !chain.isEmpty {
            below = try await dialChain(chain, target: Endpoint(host: config.serverAddress, port: config.serverPort),
                                        initialData: nil, resources: resources)
        }

        switch config.outboundProtocol {
        case .vless:
            return try await dialVlessUdp(config, below: below, prefix: chain, target: target, resources: resources)
        case .trojan:
            return try await dialTrojanUdp(config, below: below, prefix: chain, target: target, resources: resources)
        case .vmess:
            return try await dialVmessUdp(config, below: below, prefix: chain, target: target, resources: resources)
        case .socks5:
            return try await dialSocksUdp(config, below: below, target: target, resources: resources)
        case .anytls:
            return try await dialAnyTlsUdp(config, below: below, target: target, resources: resources)
        default:
            throw MythaiaError.unsupported(config.outboundProtocol.displayName)
        }
    }

    /// VLESS UDP: the UDP command, then length-prefixed datagrams. Vision
    /// pads TCP only, so the request carries no flow.
    private static func dialVlessUdp(_ config: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                     target: Endpoint, resources: DialResources) async throws -> DatagramStream {
        let transport = transportName(config.transport)
        let security = try vlessSecurity(config, transport: transport)
        let pipe = try await openPipe(config, below: below, prefix: prefix, security: security, transport: transport,
                                      needsSession: false, resources: resources)
        let header = VlessProtocol.encodeRequestHeader(
            uuid: config.uuid,
            command: .udp,
            destinationAddress: target.host,
            destinationPort: target.port,
            flow: nil
        )
        let base = VlessConnection(pipe.stream)
        try await base.send(header)
        let connection = VlessUdpConnection(base)
        resources.track(connection)
        return connection
    }

    /// Trojan UDP: the UDP command goes with the first datagram.
    private static func dialTrojanUdp(_ config: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                      target: Endpoint, resources: DialResources) async throws -> DatagramStream {
        let password = try trojanPassword(config)
        let tls = try trojanTls(config)
        let pipe = try await openPipe(config, below: below, prefix: prefix, security: .tls(tls),
                                      transport: transportName(config.transport), needsSession: false, resources: resources)
        let connection = TrojanUdpConnection(pipe.stream, password: password, destinationHost: target.host, destinationPort: target.port)
        resources.track(connection)
        return connection
    }

    /// VMess UDP: the UDP command, then one datagram per chunk.
    private static func dialVmessUdp(_ config: ProxyConfiguration, below: ByteStream?, prefix: [ProxyConfiguration],
                                     target: Endpoint, resources: DialResources) async throws -> DatagramStream {
        let security = VmessSecurity.fromRaw(config.vmessSecurity)
        let sealed = try VmessProtocol.sealRequest(id: config.uuid, host: target.host, port: target.port,
                                                   command: VmessProtocol.commandUDP, security: security)
        let pipe = try await openPipe(config, below: below, prefix: prefix, security: try vmessSecurity(config),
                                      transport: transportName(config.transport), needsSession: false, resources: resources)
        let stream = VmessConnection(pipe.stream, session: sealed.session, requestHeader: sealed.bytes)
        // Flushes the request header.
        try await stream.send(Data())
        let connection = VmessUdpConnection(stream)
        resources.track(connection)
        return connection
    }

    /// SOCKS5 UDP ASSOCIATE: the control connection goes the way TCP would,
    /// the datagrams to the relay port at the server's own address — servers
    /// typically answer with a local or private IP the client cannot reach.
    private static func dialSocksUdp(_ config: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                                     resources: DialResources) async throws -> DatagramStream {
        let control = try await openSecured(config, below: below, security: .none, alpn: [],
                                            needsSession: false, resources: resources).stream
        let relay = try await SocksClient.udpAssociate(over: control, username: config.socks5Username,
                                                       password: config.socks5Password)
        let socket = try await UdpSocketConnection.connect(host: config.connectAddress, port: relay.port, timeout: connectTimeout)
        resources.track(socket)
        let connection = SocksUdpConnection(control: control, socket: socket, destinationHost: target.host, destinationPort: target.port)
        resources.track(connection)
        return connection
    }
}
