import Foundation

/// Hysteria2: a proxy that authenticates over HTTP/3 and then speaks its own
/// framing on plain QUIC streams.
///
/// The connection opens as ordinary HTTP/3 and the client makes one request —
/// a POST to `hysteria/auth` carrying the password. That request exists to
/// look like a website: a server that does not recognise the credentials
/// serves whatever it is masquerading as, so a prober sees a real site rather
/// than a refused proxy. Only after a 233 does anything proxy-shaped happen,
/// and from then on the streams carry Hysteria's own framing rather than HTTP.
///
/// One client per server (see `QuicClientPool`): every flow is a stream or a
/// UDP session on the one QUIC connection.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class HysteriaClient: @unchecked Sendable {
    static let alpn = "h3"
    /// The largest TCP response this waits for before giving up on it.
    static let maxResponse = 8192
    /// The Hysteria UDP message size assumed while QUIC cannot say yet: one
    /// that fits a packet on any path after the packet header, AEAD tag and
    /// frame header.
    static let maxUdpDatagram = 1100
    /// The whole session setup: QUIC handshake, HTTP/3 and authentication.
    static let establishTimeout: Double = 20

    let configuration: ProxyConfiguration
    let key: String
    let core: QuicClientCore<HysteriaSession>

    private let lock = NSLock()
    private var udpFlows: [Int64: WeakQuicUdpFlow] = [:]
    private var nextUdpSession: Int64
    private var nextPacketId = 0
    private let reassembler = UdpReassembler()
    /// The connection a handshake is under way on, so closing the client
    /// ends it at once instead of letting it run out its timeout.
    private var connecting: QuicConnection?

    init(configuration: ProxyConfiguration, key: String) {
        self.configuration = configuration
        self.key = key
        self.core = QuicClientCore(name: "Hysteria2 \(configuration.name)", establishTimeout: HysteriaClient.establishTimeout)
        self.nextUdpSession = Int64(DispatchTime.now().uptimeNanoseconds & 0x7FFF_FFFF)
    }

    var isClosed: Bool { core.isClosed }

    // MARK: - Dial

    /// A proxied TCP stream to `host`:`port`. The session is brought up on
    /// first use and shared afterwards.
    func connect(host: String, port: UInt16, initialData: Data?) async throws -> ByteStream {
        core.beginDial()
        defer { core.endDial() }
        let session = try await core.session { try await self.openSession() }
        guard let stream = session.quic.openStream() else {
            throw MythaiaError.connectFailed("Hysteria2: no stream credit left")
        }
        do {
            let request = HysteriaProtocol.encodeTcpRequest(address: HysteriaProtocol.formatAddress(host: host, port: port))
            try await stream.send(Data(request))
            let (response, leftover) = try await readTcpResponse(stream)
            if !response.isOk {
                throw MythaiaError.connectFailed("Hysteria2 server refused \(Endpoint(host: host, port: port)): \(response.message)")
            }
            if let initialData = initialData, !initialData.isEmpty {
                try await stream.send(initialData)
            }
            // Bytes that arrived with the TCPResponse are the start of the
            // proxied payload — a server-first banner (SSH, SMTP, IMAP) — and
            // are handed back as the first receive rather than dropped.
            let base: ByteStream = leftover.isEmpty ? stream : PrefixedStream(stream, prefix: Data(leftover))
            core.flowOpened()
            return QuicClientFlow(base) { [weak self] in
                self?.core.flowClosed()
            }
        } catch {
            // A refusal, a read that never completed, or a failed send all
            // leave the stream open in the session otherwise.
            stream.close()
            throw error
        }
    }

    /// A UDP flow to `host`:`port`, carried in QUIC datagrams. Each flow is a
    /// Hysteria UDP session of its own: a 32-bit id the server answers under,
    /// with no setup message — the first datagram opens it, and the server
    /// forgets it after its idle timeout.
    func connectUDP(host: String, port: UInt16) async throws -> DatagramStream {
        core.beginDial()
        defer { core.endDial() }
        let session = try await core.session { try await self.openSession() }
        if !session.udpEnabled {
            throw MythaiaError.unsupported("UDP: this Hysteria2 server does not relay it")
        }
        lock.lock()
        nextUdpSession = (nextUdpSession + 1) & 0xFFFF_FFFF
        let id = nextUdpSession
        lock.unlock()
        let address = HysteriaProtocol.formatAddress(host: host, port: port)
        let flow = QuicUdpFlow(
            transmit: { [weak self] payload in
                guard let self = self else { throw MythaiaError.closed }
                try await self.sendUdp(id, address: address, payload: [UInt8](payload))
            },
            onClose: { [weak self] in
                self?.udpFlowClosed(id)
            }
        )
        lock.lock()
        udpFlows[id] = WeakQuicUdpFlow(flow: flow)
        lock.unlock()
        core.flowOpened()
        return flow
    }

    /// One UDP payload as one datagram, or as numbered fragments when it does
    /// not fit — QUIC Initial packets from an app are 1200+ bytes on their own.
    private func sendUdp(_ sessionId: Int64, address: String, payload: [UInt8]) async throws {
        let session = try await core.session { try await self.openSession() }
        lock.lock()
        let packetId = nextPacketId
        nextPacketId = (nextPacketId + 1) & 0xFFFF
        lock.unlock()
        let messages = HysteriaProtocol.fragmentUdp(sessionId: sessionId, packetId: packetId, address: address,
                                                    payload: payload, maxDatagramSize: HysteriaClient.datagramLimit(session.quic))
        if messages.isEmpty {
            throw MythaiaError.protocolError("Hysteria2: UDP payload of \(payload.count) bytes is too large")
        }
        for message in messages {
            if !session.quic.sendDatagram(message.encode()) {
                Log.debug("[Hysteria2] UDP datagram dropped, the QUIC connection is gone")
                return
            }
        }
    }

    /// The largest Hysteria UDP message sent whole: what one QUIC packet
    /// carries on this path now, as the official client sends. Messages over
    /// it are split, which some servers never reassemble, so splitting below
    /// it lost every large packet there.
    static func datagramLimit(_ quic: QuicConnection) -> Int {
        let room = quic.maxDatagramPayload()
        return room > 0 ? room : maxUdpDatagram
    }

    private func udpFlowClosed(_ id: Int64) {
        lock.lock()
        udpFlows.removeValue(forKey: id)
        lock.unlock()
        core.flowClosed()
    }

    /// Routes a datagram from the server to its flow, reassembling fragments.
    /// On the QUIC engine queue: it must not wait for anything.
    private func onDatagram(_ data: Data) {
        guard let message = HysteriaProtocol.decodeUdpMessage([UInt8](data)) else {
            Log.debug("[Hysteria2] undecodable datagram (\(data.count) bytes)")
            return
        }
        lock.lock()
        let flow = udpFlows[message.sessionId]?.flow
        lock.unlock()
        guard let target = flow else { return }
        let key = message.sessionId << 16 | Int64(message.packetId)
        guard let whole = reassembler.add(packetKey: key, fragmentId: message.fragId,
                                          fragmentCount: message.fragCount, payload: message.payload) else { return }
        target.deliver(Data(whole))
    }

    /// Ends everything: the session and every UDP flow.
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

    private func openSession() async throws -> HysteriaSession {
        // The link's obfs/obfs-password; a type this build does not speak is
        // refused here rather than dialled in the clear.
        let obfuscation = HysteriaObfuscation.make(type: configuration.obfuscation, password: configuration.obfuscationPassword)
        if obfuscation == nil, let type = configuration.obfuscation, !type.isEmpty {
            throw MythaiaError.unsupported("Hysteria2 obfuscation \(type)")
        }
        let obfuscator = try obfuscation.map { try HysteriaObfuscators.make($0) }
        let tls = configuration.tls
        let sni = tls.map { $0.serverName.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
        let quic = QuicConnection(
            serverName: configuration.connectAddress,
            serverPort: configuration.serverPort,
            alpn: [HysteriaClient.alpn],
            // NAIVE grants the unidirectional stream credit HTTP/3 needs for
            // the server's control stream, which authentication rides on.
            tuning: .naive,
            fingerprint: tls?.fingerprint ?? .chrome133,
            tlsServerName: sni ?? configuration.serverAddress,
            allowInsecure: tls?.allowInsecure ?? false,
            pinnedCertSha256: tls?.pinnedCertSha256,
            verifyName: tls?.verifyName,
            obfuscator: obfuscator
        )
        // Registered before the handshake so no reply to a UDP flow is lost
        // to a session that is still coming up.
        quic.setDatagramHandler { [weak self] data in
            self?.onDatagram(data)
        }
        guard beginHandshake(quic) else {
            throw MythaiaError.connectFailed("Hysteria2 session closed")
        }
        defer { endHandshake(quic) }
        do {
            try await quic.connect()
            // Plain SETTINGS: with H3_DATAGRAM announced, the server's HTTP/3
            // layer takes every QUIC datagram for itself and UDP goes silent.
            let http3 = Http3Connection(quic: quic, settings: Http3Framer.plainClientSettings)
            try await http3.start()
            let auth = try await authenticate(http3)
            return HysteriaSession(quic: quic, http3: http3, udpEnabled: auth.udpSupported,
                                   serverReceiveBytesPerSecond: auth.serverRxBytesPerSec ?? 0)
        } catch {
            // Otherwise the connection — socket, timer, ngtcp2 handle — would
            // leak until its idle timeout, and every later dial would build
            // and leak another.
            quic.close()
            throw error
        }
    }

    /// The masquerading authentication request. A wrong password does not get
    /// an error — it gets whatever website the server pretends to be — so
    /// anything that is not 233 is a refusal, not something to parse.
    private func authenticate(_ http3: Http3Connection) async throws -> HysteriaProtocol.AuthResponse {
        guard let password = configuration.password ?? configuration.trojanPassword, !password.isEmpty else {
            throw MythaiaError.invalidConfiguration("Hysteria2 password not set")
        }
        let headers = QpackEncoder.encodePostHeaders(
            authority: HysteriaProtocol.authAuthority,
            path: HysteriaProtocol.authPath,
            extraHeaders: HysteriaProtocol.authRequestHeaders(password: password, clientRxBytesPerSec: declaredReceiveRate())
        )
        let stream = try await http3.request(headers: headers, fin: true)
        defer { stream.close() }
        let fields = try await readResponseHeaders(stream)
        guard let auth = HysteriaProtocol.parseAuthResponse(fields), auth.isAccepted else {
            // Deliberately vague: nothing here tells a bad password from a
            // host that was never a Hysteria server.
            throw MythaiaError.protocolError("Hysteria2 authentication refused")
        }
        Log.debug("[Hysteria2] authenticated, udp=\(auth.udpSupported)")
        return auth
    }

    /// What this client says it can receive, in bytes per second; zero means
    /// "you decide", which the server reads as its own detection.
    private func declaredReceiveRate() -> Int64 {
        let mbps = configuration.hysteriaDownMbps ?? 0
        return mbps <= 0 ? 0 : Int64(mbps) * 125_000
    }

    // MARK: - Reading

    /// Reads until the response HEADERS frame is complete, then decodes it.
    private func readResponseHeaders(_ stream: QuicStream) async throws -> [Http3Field] {
        var buffer: [UInt8] = []
        while true {
            switch Http3Framer.parse(buffer) {
            case .complete(let frame, let consumed):
                if frame.knownType == .headers {
                    guard let fields = QpackEncoder.decodeHeaders(frame.payload) else {
                        throw MythaiaError.protocolError("Hysteria2: unreadable response headers")
                    }
                    return fields
                }
                buffer = Array(buffer[consumed...])
                continue
            case .malformed(let reason):
                throw MythaiaError.protocolError("Hysteria2: \(reason)")
            case .incomplete:
                break
            }
            guard let chunk = try await stream.receive() else {
                throw MythaiaError.protocolError("Hysteria2: connection closed during authentication")
            }
            buffer.append(contentsOf: chunk)
            if buffer.count > Int(Http3Framer.fieldSectionSizeLimit) {
                throw MythaiaError.protocolError("Hysteria2: response headers too large")
            }
        }
    }

    /// Reads the proxy's answer to a TCP request, and whatever followed it in
    /// the same read: the start of the proxied payload.
    private func readTcpResponse(_ stream: QuicStream) async throws -> (HysteriaProtocol.TcpResponse, [UInt8]) {
        var buffer: [UInt8] = []
        while true {
            if let response = HysteriaProtocol.parseTcpResponse(buffer) {
                return (response, Array(buffer[response.consumed...]))
            }
            guard let chunk = try await stream.receive() else {
                throw MythaiaError.connectFailed("Hysteria2: the server closed the stream before answering")
            }
            buffer.append(contentsOf: chunk)
            if buffer.count > HysteriaClient.maxResponse {
                throw MythaiaError.protocolError("Hysteria2: response never completed")
            }
        }
    }
}

/// One authenticated Hysteria2 connection.
final class HysteriaSession: QuicPooledSession, @unchecked Sendable {
    let quic: QuicConnection
    let http3: Http3Connection
    /// Whether the server will carry UDP for us.
    let udpEnabled: Bool
    /// The rate the server told us to send at, from `Hysteria-CC-RX`; 0 for auto.
    let serverReceiveBytesPerSecond: Int64

    init(quic: QuicConnection, http3: Http3Connection, udpEnabled: Bool, serverReceiveBytesPerSecond: Int64) {
        self.quic = quic
        self.http3 = http3
        self.udpEnabled = udpEnabled
        self.serverReceiveBytesPerSecond = serverReceiveBytesPerSecond
    }

    var isUsable: Bool { quic.isConnected }

    func close() {
        http3.close()
        quic.close()
    }
}
