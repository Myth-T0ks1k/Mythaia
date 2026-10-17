import Foundation

/// Hysteria2 and TUIC: flows on a pooled QUIC connection per server.
///
/// Both run over UDP straight to their server, so neither can sit behind
/// another hop of a chain — a QUIC connection cannot be carried inside a TCP
/// flow — and dialling one there directly would silently skip the hops
/// before it. As the first hop of a chain a QUIC server carries the next
/// hop's stream like any other.
extension Dialer {
    static func isQuicProtocol(_ protocolKind: OutboundProtocol) -> Bool {
        return protocolKind == .hysteria2 || protocolKind == .tuic
    }

    static func dialQuic(_ hop: ProxyConfiguration, below: ByteStream?, target: Endpoint,
                         initialData: Data?, resources: DialResources) async throws -> ByteStream {
        if below != nil {
            throw MythaiaError.unsupported("\(hop.outboundProtocol.displayName) behind another server of a chain")
        }
        switch hop.outboundProtocol {
        case .hysteria2:
            return try await QuicClientPool.hysteria(hop).connect(host: target.host, port: target.port, initialData: initialData)
        case .tuic:
            return try await QuicClientPool.tuic(hop).connect(host: target.host, port: target.port, initialData: initialData)
        default:
            throw MythaiaError.unsupported(hop.outboundProtocol.displayName)
        }
    }

    static func dialQuicUdp(_ config: ProxyConfiguration, chain: [ProxyConfiguration], target: Endpoint,
                            resources: DialResources) async throws -> DatagramStream {
        if !chain.isEmpty {
            throw MythaiaError.unsupported("UDP through \(config.outboundProtocol.displayName) behind a chain")
        }
        let flow: DatagramStream
        switch config.outboundProtocol {
        case .hysteria2:
            flow = try await QuicClientPool.hysteria(config).connectUDP(host: target.host, port: target.port)
        case .tuic:
            flow = try await QuicClientPool.tuic(config).connectUDP(host: target.host, port: target.port)
        default:
            throw MythaiaError.unsupported(config.outboundProtocol.displayName)
        }
        resources.track(flow)
        return flow
    }
}
