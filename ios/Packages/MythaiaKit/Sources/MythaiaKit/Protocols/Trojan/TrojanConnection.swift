import Foundation

/// A Trojan TCP stream over a TLS-backed stream.
///
/// The request header — `hex(sha224(password)) + CRLF + cmd + addr:port + CRLF`
/// — is prepended to the first write and travels inside the same TLS record;
/// an empty first write sends exactly the header, which is how the dialer
/// flushes it at connect time for flows where the server speaks first (SSH,
/// SMTP, IMAP). Reads pass through: Trojan servers reply without framing.
final class TrojanConnection: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let lock = NSLock()
    private var pendingHeader: Data?

    init(_ inner: ByteStream, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.pendingHeader = TrojanProtocol.buildRequestHeader(
            passwordKey: TrojanProtocol.passwordKey(password),
            command: TrojanProtocol.commandTCP,
            host: destinationHost,
            port: destinationPort
        )
    }

    func send(_ data: Data) async throws {
        var payload = consumeHeader() ?? Data()
        payload.append(data)
        if payload.isEmpty { return }
        try await inner.send(payload)
    }

    func receive() async throws -> Data? {
        while true {
            guard let data = try await inner.receive() else { return nil }
            if !data.isEmpty { return data }
        }
    }

    func close() {
        inner.close()
    }

    /// The request header on the first call, nil after.
    private func consumeHeader() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let header = pendingHeader
        pendingHeader = nil
        return header
    }
}

/// Trojan UDP over the TLS stream.
///
/// Each outgoing datagram is framed as `addr:port + length + CRLF + payload`
/// behind the Trojan UDP request header, which goes once, with the first
/// datagram. Inbound stream bytes are buffered and one payload is returned
/// per receive, the per-packet header dropped.
final class TrojanUdpConnection: DatagramStream, @unchecked Sendable {
    private let inner: ByteStream
    private let passwordKey: Data
    private let destinationHost: String
    private let destinationPort: UInt16
    private let lock = NSLock()
    private var headerSent = false
    private var receiveBuffer = [UInt8]()

    init(_ inner: ByteStream, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.passwordKey = TrojanProtocol.passwordKey(password)
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }

    /// A datagram the framing cannot carry is dropped here, as the network
    /// would drop an oversized packet — not truncated (the receiver would get
    /// garbage) and not fatal (one odd packet must not end the association).
    func send(_ packet: Data) async throws {
        if packet.count > TrojanProtocol.maxUdpPayloadLength {
            Log.warning("Trojan UDP: dropping a \(packet.count)-byte datagram to \(destinationHost):\(destinationPort); the framing carries at most \(TrojanProtocol.maxUdpPayloadLength)")
            return
        }
        let framed = try frame(packet)
        try await inner.send(framed)
    }

    func receive() async throws -> Data? {
        while true {
            if let payload = try nextPacket(appending: nil) { return payload }
            guard let data = try await inner.receive() else { return nil }
            if let payload = try nextPacket(appending: data) { return payload }
        }
    }

    func close() {
        lock.lock()
        receiveBuffer = []
        lock.unlock()
        inner.close()
    }

    /// Prepends the one-shot request header (first call only) to a framed packet.
    private func frame(_ payload: Data) throws -> Data {
        let packet = try TrojanProtocol.encodeUDPPacket(host: destinationHost, port: destinationPort, payload: payload)
        lock.lock()
        let needsHeader = !headerSent
        headerSent = true
        lock.unlock()
        if needsHeader {
            var out = TrojanProtocol.buildRequestHeader(
                passwordKey: passwordKey,
                command: TrojanProtocol.commandUDP,
                host: destinationHost,
                port: destinationPort
            )
            out.append(packet)
            return out
        }
        return packet
    }

    private func nextPacket(appending data: Data?) throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let data = data {
            receiveBuffer.append(contentsOf: data)
        }
        guard let decoded = try TrojanProtocol.tryDecodeUDPPacket(receiveBuffer, from: 0) else {
            return nil
        }
        receiveBuffer.removeFirst(decoded.consumed)
        return decoded.payload
    }
}
