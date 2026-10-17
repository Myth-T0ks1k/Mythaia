import Foundation

/// The protocols whose connections outlive one flow: AnyTLS sessions and
/// NaiveProxy's HTTP/2 connections are pooled per server, and each dial is
/// one more stream on them.
extension Dialer {
    /// Closes the pooled connections that dialling `configuration` (its chain
    /// included) left without a flow. Meant for after a one-off dial such as
    /// a latency test: pooled connections outlive their dial on purpose, which
    /// is right for the server in use and wrong for a test across a
    /// subscription of thousands. Connections still carrying flows are left
    /// alone, so testing the server in use never cuts them.
    public static func releasePooledSessions(_ configuration: ProxyConfiguration) {
        let hops = (configuration.chain ?? []) + [configuration]
        for raw in hops {
            let hop = raw.withTransportHostSni()
            switch hop.outboundProtocol {
            case .anytls:
                AnyTlsPool.releaseIdle(hop.id)
            case .naiveHttp2:
                NaiveSessionPool.shared.releaseIdle(NaiveSessionPool.key(for: hop))
            default:
                break
            }
        }
    }

    /// AnyTLS runs over this app's own TLS client, never the system's: its
    /// padding scheme is defined in TLS records, and only our TLS session
    /// turns each write into a record of its own.
    static func anyTlsSecurity(_ hop: ProxyConfiguration) throws -> DialSecurity {
        guard let tls = hop.tls else {
            throw MythaiaError.invalidConfiguration("AnyTLS requires TLS configuration")
        }
        return .tls(tls)
    }

    static func dialAnyTls(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                           initialData: Data?, resources: DialResources) async throws -> ByteStream {
        let stream = try await openAnyTlsStream(hop, below: below, host: target.host, port: target.port, resources: resources)
        if let initialData = initialData, !initialData.isEmpty {
            try await stream.send(initialData)
        }
        return stream
    }

    /// UDP rides a stream addressed to a reserved name (sing-box's
    /// udp-over-tcp v2); the server recognises the name and switches.
    static func dialAnyTlsUdp(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                              resources: DialResources) async throws -> DatagramStream {
        let stream = try await openAnyTlsStream(hop, below: below, host: AnyTlsProtocol.udpOverTcpHost, port: 443, resources: resources)
        let connection = AnyTlsUdpConnection(stream, destinationHost: target.host, destinationPort: target.port)
        resources.track(connection)
        return connection
    }

    private static func openAnyTlsStream(_ hop: ProxyConfiguration, below: ByteStream?, host: String, port: UInt16,
                                         resources: DialResources) async throws -> AnyTlsStream {
        let security = try anyTlsSecurity(hop)
        let offered = alpn(transport: "tcp", security: security)
        // Behind a chain the session runs over this dial's own flow, so it
        // serves this stream alone.
        return try await AnyTlsClient.openStream(hop, host: host, port: port, pooled: below == nil) { () async throws -> ByteStream in
            let secured = try await Dialer.openSecured(hop, below: below, security: security, alpn: offered,
                                                       needsSession: true, resources: resources)
            return secured.stream
        }
    }

    /// NaiveProxy over HTTP/2, pooled per server when dialled directly.
    static func dialHttp2(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                          initialData: Data?, resources: DialResources) async throws -> ByteStream {
        // The server's own TLS settings (allow insecure, pins) with the name
        // and ALPN this proxy is dialled with.
        let tls = hop.tls ?? TlsConfiguration(serverName: hop.serverAddress)
        let pooled = below == nil
        let dialTls: () async throws -> ByteStream
        if pooled {
            // A pooled connection belongs to the pool, not to this dial: it
            // is made outside the dial's bookkeeping, or a timeout here would
            // close it under the other tunnels on it.
            dialTls = {
                let secured = try await Dialer.openSecured(hop, below: nil, security: .tls(tls), alpn: ["h2"],
                                                           needsSession: false, resources: DialResources())
                try Dialer.requireHttp2(secured, hop: hop)
                return secured.stream
            }
        } else {
            dialTls = {
                let secured = try await Dialer.openSecured(hop, below: below, security: .tls(tls), alpn: ["h2"],
                                                           needsSession: false, resources: resources)
                try Dialer.requireHttp2(secured, hop: hop)
                return secured.stream
            }
        }
        let stream = try await NaiveClient.connectHttp2(hop, target: target, pooled: pooled, dialTls: dialTls)
        if let initialData = initialData, !initialData.isEmpty {
            try await stream.send(initialData)
        }
        return stream
    }

    /// A server that answered the TLS handshake with another protocol than
    /// h2 would read the HTTP/2 preface as garbage; say so instead.
    static func requireHttp2(_ secured: Secured, hop: ProxyConfiguration) throws {
        if let chosen = secured.negotiatedALPN, chosen != "h2" {
            secured.stream.close()
            throw MythaiaError.protocolError("\(hop.name) does not speak HTTP/2 (it chose \(chosen)); use an HTTPS (HTTP/1.1) link for it")
        }
    }
}
