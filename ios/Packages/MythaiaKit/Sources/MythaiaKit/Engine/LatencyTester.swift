import Foundation

/// What a measurement times.
///
/// TCP is the cheapest and says only that the port answers; handshake proves
/// the credentials and the protocol work; HTTP goes all the way through the
/// proxy to the internet, and is what Auto ranks by.
public enum LatencyKind: String, Codable, CaseIterable {
    /// The TCP connect to the server (the first hop of a chain). A server
    /// that listens on UDP only gets the handshake instead, since a TCP
    /// connect to it proves nothing.
    case tcp
    /// Time to a finished proxy handshake: TCP, TLS or REALITY, transport
    /// and protocol, through every hop of a chain.
    case handshake
    /// Time for an HTTP round trip through the proxy, the "real" ping.
    case http
}

/// Server latency, as the server list and Auto show it.
///
/// The HTTP test asks captive.apple.com over plain HTTP, so no destination
/// TLS handshake is timed or can fail on a certificate.
public enum LatencyTester {
    static let probeHost = "captive.apple.com"
    static let probePort: UInt16 = 80

    /// Milliseconds, or nil when the server failed or `timeout` (seconds,
    /// for the whole test) ran out.
    public static func measure(
        _ configuration: ProxyConfiguration,
        kind: LatencyKind,
        timeout: Double = 5
    ) async -> Int? {
        // A layer-3 interface has no per-flow dial to time.
        if configuration.outboundProtocol == .wireguard { return nil }
        let bag = StreamBag()
        let nanoseconds = UInt64(max(0.1, timeout) * 1_000_000_000)
        // Closing the streams at the deadline is what ends a read that would
        // otherwise wait on a server that went quiet.
        let watchdog = Task {
            try? await Task.sleep(nanoseconds: nanoseconds)
            bag.closeAll()
        }
        defer {
            watchdog.cancel()
            bag.closeAll()
        }
        do {
            switch kind {
            case .tcp:
                return try await connectTime(configuration, timeout: timeout, bag: bag)
            case .handshake:
                return try await handshakeTime(configuration, timeout: timeout, bag: bag)
            case .http:
                return try await roundTripTime(configuration, timeout: timeout, bag: bag)
            }
        } catch {
            Log.warning("Latency test failed for \(configuration.name): \(LocalProxyServer.describe(error))")
            return nil
        }
    }

    /// Whether the server takes its first packets over UDP (QUIC).
    static func listensOnUdp(_ configuration: ProxyConfiguration) -> Bool {
        switch configuration.outboundProtocol {
        case .hysteria2, .tuic:
            return true
        case .nowhere:
            let uplink = configuration.nowhereUplink ?? "udp"
            return uplink.lowercased() == "udp"
        default:
            return false
        }
    }

    /// Times the TCP connect alone, to the first hop of a chain or the
    /// server itself.
    private static func connectTime(_ configuration: ProxyConfiguration, timeout: Double, bag: StreamBag) async throws -> Int {
        let first = configuration.chain?.first ?? configuration
        if listensOnUdp(first) {
            return try await handshakeTime(configuration, timeout: timeout, bag: bag)
        }
        let host = first.resolvedIP ?? first.serverAddress
        let started = DispatchTime.now().uptimeNanoseconds
        let stream = try await TCPStream.connect(host: host, port: first.serverPort, timeout: timeout)
        let elapsed = elapsedMilliseconds(since: started)
        stream.close()
        return max(1, elapsed)
    }

    /// Times the whole dial: TCP, TLS or REALITY, and the protocol's own
    /// request, through every hop of a chain. Nothing is sent to the
    /// internet.
    private static func handshakeTime(_ configuration: ProxyConfiguration, timeout: Double, bag: StreamBag) async throws -> Int {
        let target = Endpoint(host: probeHost, port: probePort)
        let started = DispatchTime.now().uptimeNanoseconds
        let stream = try await Dialer.connect(configuration, to: target, initialData: nil, timeout: timeout)
        let elapsed = elapsedMilliseconds(since: started)
        stream.close()
        return max(1, elapsed)
    }

    /// Opens the proxy connection and sends a warm-up request (untimed: it
    /// drains the proxy's own buffers and finishes a lazy handshake), then
    /// times the second request from send to the first bytes of its answer:
    /// the network's round trip through the proxy, not the handshake.
    private static func roundTripTime(_ configuration: ProxyConfiguration, timeout: Double, bag: StreamBag) async throws -> Int {
        let target = Endpoint(host: probeHost, port: probePort)
        let stream = try bag.add(try await Dialer.connect(configuration, to: target, initialData: nil, timeout: timeout))
        let reader = StreamReader(stream)

        let warmup = "HEAD / HTTP/1.1\r\nHost: \(probeHost)\r\n\r\n"
        try await stream.send(Data(warmup.utf8))
        let warmupHead = try await reader.readThrough(HTTPInbound.headTerminator, limit: 16 * 1024)
        let warmupStatus = statusLine(warmupHead)
        guard warmupStatus.contains("200") else {
            throw MythaiaError.protocolError("unexpected warm-up status: \(warmupStatus.isEmpty ? "no response" : warmupStatus)")
        }
        _ = reader.drain()

        let timed = "HEAD / HTTP/1.1\r\nHost: \(probeHost)\r\nConnection: close\r\n\r\n"
        try await stream.send(Data(timed.utf8))
        let started = DispatchTime.now().uptimeNanoseconds
        guard let answer = try await reader.readSome() else {
            throw MythaiaError.protocolError("no response")
        }
        let elapsed = elapsedMilliseconds(since: started)
        let status = statusLine(answer)
        guard status.contains("200") else {
            throw MythaiaError.protocolError("unexpected status: \(status.isEmpty ? "no response" : status)")
        }
        return max(1, elapsed)
    }

    private static func statusLine(_ data: Data) -> String {
        let text = String(decoding: data.prefix(256), as: UTF8.self)
        guard let line = text.components(separatedBy: "\r\n").first else { return "" }
        return line
    }

    private static func elapsedMilliseconds(since start: UInt64) -> Int {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now > start else { return 0 }
        return Int((now - start) / 1_000_000)
    }

    /// The streams a test opened, closed together at its deadline or end.
    final class StreamBag: @unchecked Sendable {
        private let lock = NSLock()
        private var streams: [ByteStream] = []
        private var closed = false

        /// Keeps `stream` for closing; once the bag is closed, closes it at
        /// once and throws, since the test's time is up.
        func add(_ stream: ByteStream) throws -> ByteStream {
            lock.lock()
            if closed {
                lock.unlock()
                stream.close()
                throw MythaiaError.timeout("latency test")
            }
            streams.append(stream)
            lock.unlock()
            return stream
        }

        func closeAll() {
            lock.lock()
            closed = true
            let all = streams
            streams = []
            lock.unlock()
            for stream in all {
                stream.close()
            }
        }
    }
}
