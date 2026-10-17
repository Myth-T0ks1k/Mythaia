import Foundation

/// Server latency for a WireGuard profile: a real handshake against the peer,
/// timed from the initiation leaving to the response arriving.
///
/// Nothing else would mean anything. A layer-3 interface has no per-flow dial
/// to time, and the peer answers only a well-formed initiation under the right
/// key, so a reply proves the endpoint is reachable *and* that the profile is
/// valid — more than the stream-proxy probes establish.
enum WireGuardProbe {
    /// Milliseconds, or nil when the peer did not answer with a response that
    /// authenticates within `timeout` seconds.
    static func measure(_ configuration: ProxyConfiguration, timeout: Double) async -> Int? {
        do {
            return try await handshakeTime(configuration, timeout: timeout)
        } catch {
            Log.warning("Latency test failed for \(configuration.name): \(error.localizedDescription)")
            return nil
        }
    }

    private static func handshakeTime(_ configuration: ProxyConfiguration, timeout: Double) async throws -> Int {
        guard let text = configuration.wireGuardConfig, !text.isEmpty else {
            throw MythaiaError.invalidConfiguration("\(configuration.name) has no WireGuard configuration")
        }
        let parsed = try WireGuardConfig.parse(text)
        let amnezia = parsed.amnezia
        guard let port = UInt16(exactly: parsed.peer.endpointPort), port != 0 else {
            throw MythaiaError.invalidConfiguration("WireGuard endpoint port \(parsed.peer.endpointPort)")
        }

        let localPublic = try WireGuardCrypto.publicKey([UInt8](parsed.privateKey))
        let handshake = WireGuardHandshake(
            localPrivateKey: [UInt8](parsed.privateKey),
            localPublicKey: localPublic,
            peerPublicKey: [UInt8](parsed.peer.publicKey),
            presharedKey: parsed.peer.presharedKey.map { [UInt8]($0) }
                ?? [UInt8](repeating: 0, count: WireGuardCrypto.keySize),
            initiationType: amnezia.initiationType,
            responseType: amnezia.responseType,
            initiationJunkSize: amnezia.initPacketJunkSize,
            responseJunkSize: amnezia.responsePacketJunkSize,
            // WARP ignores an initiation without its client id, so the probe
            // would time out on a profile that connects fine.
            reserved: parsed.headerReserved.map { [UInt8]($0) }
        )

        let budget = max(0.5, timeout)
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(budget * 1_000_000_000)
        let socket = try await UdpSocketConnection.connect(host: parsed.peer.endpointHost, port: port, timeout: budget)
        // Closing the socket at the deadline is what ends a receive that would
        // otherwise wait for a peer that never answers.
        let connected = DispatchTime.now().uptimeNanoseconds
        let remaining = deadline > connected ? deadline - connected : 0
        let watchdog = Task {
            try? await Task.sleep(nanoseconds: remaining)
            socket.close()
        }
        defer {
            watchdog.cancel()
            socket.close()
        }

        let initiation = try handshake.buildInitiation()
        let started = DispatchTime.now().uptimeNanoseconds
        try await socket.send(Data(initiation))
        guard let reply = try await socket.receive(), !reply.isEmpty else {
            throw MythaiaError.timeout("WireGuard handshake with \(parsed.peer.endpointHost)")
        }
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = now > started ? Int((now - started) / 1_000_000) : 0

        // Only the peer that holds the key can produce a response this parses,
        // so anything else is a failure rather than a fast answer.
        _ = try handshake.consumeResponse([UInt8](reply))
        return max(1, elapsed)
    }
}
