import Foundation

/// TUIC v5 over QUIC.
///
/// What makes TUIC quick is what it leaves out: there are no responses. The
/// client sends `Connect` and begins relaying on the same stream immediately,
/// without waiting to hear that the far side succeeded — a server that cannot
/// reach the target says so by closing the stream. That saves a round trip on
/// every connection and means a failure surfaces as a closed stream rather
/// than as an error message.
///
/// The password never goes on the wire: it becomes a token through the TLS
/// exporter, keyed to this session, so a token captured from one connection
/// is worthless on any other.
///
/// Written from the TUIC specification (protocol version 0x05).
final class TuicClient: @unchecked Sendable {
    static let alpn = "h3"
    /// tuic-client's own default. The server's `max_idle_time` defaults to
    /// 10 s, so a 10 s heartbeat raced the server's idle timer and often
    /// arrived after it had already dropped the association; 3 s stays well
    /// inside it.
    static let heartbeatIntervalNanoseconds: UInt64 = 3_000_000_000
    /// The TUIC packet size assumed while QUIC cannot say yet; see Hysteria's.
    static let maxUdpDatagram = 1100
    static let establishTimeout: Double = 15

    let configuration: ProxyConfiguration
    let key: String
    let core: QuicClientCore<TuicSession>

    private let lock = NSLock()
    private var udpFlows: [Int: WeakQuicUdpFlow] = [:]
    private var nextAssociation: Int
    private var nextPacketId = 0
    private let reassembler = UdpReassembler()
    /// The connection a handshake is under way on, so closing the client
    /// ends it at once instead of letting it run out its timeout.
    private var connecting: QuicConnection?

    init(configuration: ProxyConfiguration, key: String) {
        self.configuration = configuration
        self.key = key
        self.core = QuicClientCore(name: "TUIC \(configuration.name)", establishTimeout: TuicClient.establishTimeout)
        self.nextAssociation = Int(DispatchTime.now().uptimeNanoseconds & 0xFFFF)
    }

    var isClosed: Bool { core.isClosed }

    /// A relayed TCP stream. The initial data rides out behind the command on
    /// the same stream, which is the point of a protocol that does not wait.
    func connect(host: String, port: UInt16, initialData: Data?) async throws -> ByteStream {
        core.beginDial()
        defer { core.endDial() }
        let session = try await core.session { try await self.openSession() }
        guard let stream = session.quic.openStream() else {
            throw MythaiaError.connectFailed("TUIC: no stream credit left")
        }
        do {
            var request = TuicProtocol.connect(host: host, port: port)
            if let initialData = initialData {
                request.append(contentsOf: initialData)
            }
            try await stream.send(Data(request))
        } catch {
            stream.close()
            throw error
        }
        core.flowOpened()
        return QuicClientFlow(stream) { [weak self] in
            self?.core.flowClosed()
        }
    }

    /// A UDP flow to `host`:`port`: a TUIC association relayed in QUIC
    /// datagrams (the "native" relay mode every server speaks). There is no
    /// setup message; the first packet opens it and `Dissociate` ends it.
    func connectUDP(host: String, port: UInt16) async throws -> DatagramStream {
        core.beginDial()
        defer { core.endDial() }
        _ = try await core.session { try await self.openSession() }
        lock.lock()
        var id = 0
        repeat {
            nextAssociation = (nextAssociation + 1) & 0xFFFF
            id = nextAssociation
        } while udpFlows[id]?.flow != nil
        lock.unlock()
        let association = id
        let flow = QuicUdpFlow(
            transmit: { [weak self] payload in
                guard let self = self else { throw MythaiaError.closed }
                try await self.sendUdp(association, host: host, port: port, payload: [UInt8](payload))
            },
            onClose: { [weak self] in
                self?.udpFlowClosed(association)
            }
        )
        lock.lock()
        udpFlows[association] = WeakQuicUdpFlow(flow: flow)
        lock.unlock()
        core.flowOpened()
        return flow
    }

    private func sendUdp(_ association: Int, host: String, port: UInt16, payload: [UInt8]) async throws {
        let session = try await core.session { try await self.openSession() }
        let overhead = TuicProtocol.headerSize + TuicProtocol.packetHeaderSize + TuicProtocol.encodeAddress(host: host, port: port).count
        // Split only above what one packet carries now, as tuic-rs does.
        let available = session.quic.maxDatagramPayload()
        let room = max(1, (available > 0 ? available : TuicClient.maxUdpDatagram) - overhead)
        lock.lock()
        let packetId = nextPacketId
        nextPacketId = (nextPacketId + 1) & 0xFFFF
        lock.unlock()
        let count = max(1, (payload.count + room - 1) / room)
        if count > 255 {
            throw MythaiaError.protocolError("TUIC: UDP payload of \(payload.count) bytes is too large")
        }
        for index in 0..<count {
            let piece = count == 1 ? payload : Array(payload[(index * room)..<min(payload.count, (index + 1) * room)])
            let packet = TuicProtocol.Packet(associationId: association, packetId: packetId, fragmentTotal: count,
                                             fragmentId: index, host: host, port: port, payload: piece)
            session.quic.sendDatagram(TuicProtocol.packet(packet))
        }
    }

    /// Routes a datagram from the server to its association, reassembling
    /// fragments. On the QUIC engine queue: it must not wait for anything.
    private func onDatagram(_ data: Data) {
        guard let packet = TuicProtocol.parsePacket([UInt8](data)) else { return }
        lock.lock()
        let flow = udpFlows[packet.associationId]?.flow
        lock.unlock()
        guard let target = flow else { return }
        let key = Int64(packet.associationId) << 16 | Int64(packet.packetId)
        guard let whole = reassembler.add(packetKey: key, fragmentId: packet.fragmentId,
                                          fragmentCount: packet.fragmentTotal, payload: packet.payload) else { return }
        target.deliver(Data(whole))
    }

    /// Tells the server an association is over, so it frees the socket now
    /// rather than on its timeout.
    private func udpFlowClosed(_ association: Int) {
        lock.lock()
        udpFlows.removeValue(forKey: association)
        lock.unlock()
        core.flowClosed()
        guard let session = core.currentSession else { return }
        Task {
            guard let stream = session.quic.openUniStream() else { return }
            do {
                try await stream.send(Data(TuicProtocol.dissociate(associationId: association)))
                try await stream.finish()
            } catch {
                stream.close()
            }
        }
    }

    /// Ends everything: the session, the heartbeat, every UDP flow.
    func close() {
        core.close()
        lock.lock()
        let flows = udpFlows.values.compactMap { $0.flow }
        udpFlows.removeAll()
        let handshake = connecting
        connecting = nil
        lock.unlock()
        handshake?.close()
        flows.forEach { $0.close() }
    }

    /// Records the connection a handshake runs on; false when the client
    /// was closed meanwhile and the handshake must not start.
    private func beginHandshake(_ quic: QuicConnection) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if core.isClosed { return false }
        connecting = quic
        return true
    }

    private func endHandshake(_ quic: QuicConnection) {
        lock.lock()
        if connecting === quic { connecting = nil }
        lock.unlock()
    }

    // MARK: - Session

    private func openSession() async throws -> TuicSession {
        let tls = configuration.tls
        let sni = tls.map { $0.serverName.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
        let quic = QuicConnection(
            serverName: configuration.connectAddress,
            serverPort: configuration.serverPort,
            alpn: [TuicClient.alpn],
            tuning: .naive,
            fingerprint: tls?.fingerprint ?? .chrome133,
            tlsServerName: sni ?? configuration.serverAddress,
            allowInsecure: tls?.allowInsecure ?? false,
            pinnedCertSha256: tls?.pinnedCertSha256,
            verifyName: tls?.verifyName
        )
        quic.setDatagramHandler { [weak self] data in
            self?.onDatagram(data)
        }
        guard beginHandshake(quic) else {
            throw MythaiaError.connectFailed("TUIC session closed")
        }
        defer { endHandshake(quic) }
        do {
            try await quic.connect()
            try await authenticate(quic)
        } catch {
            // Otherwise the freshly built connection leaks until its idle
            // timeout, and every later dial builds and leaks another.
            quic.close()
            throw error
        }
        return TuicSession(quic: quic)
    }

    /// Sends `Authenticate` on a unidirectional stream. The token is the TLS
    /// exporter's output with the UUID's sixteen raw bytes as the label and the
    /// password as the context — the raw bytes, as tuic-rs and sing-quic both
    /// use, not the UUID's text, which every server rejects as a mismatch. It
    /// is fire-and-forget: a server that rejects it simply stops relaying.
    private func authenticate(_ quic: QuicConnection) async throws {
        guard let password = configuration.password ?? configuration.trojanPassword else {
            throw MythaiaError.invalidConfiguration("TUIC password not set")
        }
        let uuid = configuration.uuid
        guard let token = quic.exportKeyingMaterial(label: TuicProtocol.uuidBytes(uuid),
                                                    context: Array(password.utf8),
                                                    length: TuicProtocol.tokenLength) else {
            throw MythaiaError.protocolError("TUIC: no keying material to build a token from")
        }
        guard let stream = quic.openUniStream() else {
            throw MythaiaError.protocolError("TUIC: no stream for authentication")
        }
        do {
            try await stream.send(Data(try TuicProtocol.authenticate(uuid: uuid, token: token)))
            try await stream.finish()
        } catch {
            stream.close()
            throw error
        }
    }
}

/// One TUIC connection, with the heartbeat that keeps it alive while anything
/// relays: a datagram rather than a stream, because losing one costs nothing
/// and the next tick sends another.
final class TuicSession: QuicPooledSession, @unchecked Sendable {
    let quic: QuicConnection
    private let heartbeat: Task<Void, Never>

    init(quic: QuicConnection) {
        self.quic = quic
        let connection = quic
        self.heartbeat = Task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: TuicClient.heartbeatIntervalNanoseconds)
                } catch {
                    return
                }
                if !connection.isConnected { return }
                connection.sendDatagram(TuicProtocol.heartbeat())
            }
        }
    }

    var isUsable: Bool { quic.isConnected }

    func close() {
        heartbeat.cancel()
        quic.close()
    }
}
