import Foundation
import Network

/// A ping for servers that listen on UDP only: Hysteria2 and TUIC. A TCP
/// connect means nothing there — the port is closed to TCP.
///
/// It sends one QUIC long-header packet carrying a reserved version
/// (RFC 9000 §15, `0x?a?a?a?a`). A QUIC server answers such a packet with
/// Version Negotiation straight away, before any cryptography and without
/// keeping state, so the reply times the round trip to the server's own QUIC
/// endpoint. Servers only answer packets of at least 1200 bytes (the
/// anti-amplification rule), so the probe is padded to that. Hysteria2's
/// obfuscation is applied when the server uses one: it drops anything else.
enum QuicPing {
    /// The smallest datagram a server answers with Version Negotiation.
    static let probeSize = 1200
    /// A version no server speaks, from the range reserved to force negotiation.
    static let reservedVersion: UInt32 = 0x1a2a_3a4a
    /// Length of each random connection id in the probe.
    static let cidLength = 8

    /// One probe: long header, reserved version, random 8-byte connection
    /// ids, zero padding.
    static func probe() -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: probeSize)
        // Long header form and fixed bit set; the type bits are left random,
        // as they mean nothing under an unknown version.
        packet[0] = 0xC0 | UInt8.random(in: 0..<0x10)
        packet[1] = UInt8(truncatingIfNeeded: reservedVersion >> 24)
        packet[2] = UInt8(truncatingIfNeeded: reservedVersion >> 16)
        packet[3] = UInt8(truncatingIfNeeded: reservedVersion >> 8)
        packet[4] = UInt8(truncatingIfNeeded: reservedVersion)
        packet[5] = UInt8(cidLength)
        let destination = TLSWire.randomBytes(cidLength)
        let source = TLSWire.randomBytes(cidLength)
        for index in 0..<cidLength {
            packet[6 + index] = destination[index]
            packet[7 + cidLength + index] = source[index]
        }
        packet[6 + cidLength] = UInt8(cidLength)
        return packet
    }

    /// Whether `datagram` is a Version Negotiation packet (long header, version 0).
    static func isVersionNegotiation(_ datagram: [UInt8]) -> Bool {
        return datagram.count >= 7 && datagram[0] & 0x80 != 0 &&
            datagram[1] == 0 && datagram[2] == 0 && datagram[3] == 0 && datagram[4] == 0
    }

    /// The obfuscator a Hysteria2 server expects its probe disguised with,
    /// or nil.
    static func obfuscator(for configuration: ProxyConfiguration) -> HysteriaObfuscator? {
        guard configuration.outboundProtocol == .hysteria2,
              let obfuscation = HysteriaObfuscation.make(type: configuration.obfuscation,
                                                         password: configuration.obfuscationPassword) else { return nil }
        return try? HysteriaObfuscators.make(obfuscation)
    }

    /// Pings `configuration`'s server. Milliseconds, or nil when nothing came
    /// back. The probe goes out up to `attempts` times, each waiting
    /// `window` seconds, since one lost datagram would otherwise read as a
    /// dead server; the time is measured from the probe that was answered.
    /// Anything from the server's address proves its QUIC endpoint is there:
    /// Version Negotiation in the clear, or the same disguised.
    static func ping(_ configuration: ProxyConfiguration, attempts: Int = 3, window: Double = 1) async -> Int? {
        guard let port = NWEndpoint.Port(rawValue: configuration.serverPort), configuration.serverPort != 0 else { return nil }
        let parameters = NWParameters.udp
        parameters.preferNoProxies = true
        let connection = NWConnection(host: NWEndpoint.Host(configuration.connectAddress), port: port, using: parameters)
        let socket = PingSocket(connection: connection)
        defer { socket.close() }
        guard await socket.start(timeout: window * Double(attempts)) else { return nil }
        let disguise = QuicPing.obfuscator(for: configuration)
        for _ in 0..<max(1, attempts) {
            let packet = probe()
            let datagrams = disguise?.seal(packet) ?? [packet]
            let started = DispatchTime.now().uptimeNanoseconds
            for datagram in datagrams {
                socket.send(datagram)
            }
            if await socket.awaitReply(timeout: window) {
                let elapsed = (DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
                return max(1, Int(elapsed))
            }
        }
        return nil
    }

    /// The probe's UDP socket: every callback resumes its waiter exactly once.
    private final class PingSocket: @unchecked Sendable {
        private let connection: NWConnection
        private let queue = DispatchQueue(label: "com.mythaia.quic.ping")
        private let lock = NSLock()
        private var readyWaiter: CheckedContinuation<Bool, Never>?
        private var replyWaiter: CheckedContinuation<Bool, Never>?
        private var replied = false
        private var closed = false

        init(connection: NWConnection) {
            self.connection = connection
        }

        func start(timeout: Double) async -> Bool {
            return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                lock.lock()
                readyWaiter = continuation
                lock.unlock()
                connection.stateUpdateHandler = { [weak self] state in
                    switch state {
                    case .ready:
                        self?.finishStart(true)
                        self?.receive()
                    case .failed, .waiting, .cancelled:
                        self?.finishStart(false)
                        self?.finishReply(false)
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    self?.finishStart(false)
                }
            }
        }

        private func finishStart(_ ok: Bool) {
            lock.lock()
            let waiter = readyWaiter
            readyWaiter = nil
            lock.unlock()
            waiter?.resume(returning: ok)
        }

        private func receive() {
            connection.receiveMessage { [weak self] content, _, _, error in
                guard let self = self else { return }
                if let content = content, !content.isEmpty {
                    self.lock.lock()
                    self.replied = true
                    self.lock.unlock()
                    self.finishReply(true)
                }
                if error == nil {
                    self.receive()
                }
            }
        }

        func send(_ datagram: [UInt8]) {
            connection.send(content: Data(datagram), completion: .idempotent)
        }

        /// True once anything has come back, waiting up to `timeout` for it.
        func awaitReply(timeout: Double) async -> Bool {
            return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                lock.lock()
                if replied || closed {
                    let answer = replied
                    lock.unlock()
                    continuation.resume(returning: answer)
                    return
                }
                replyWaiter = continuation
                lock.unlock()
                queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    self?.finishReply(false)
                }
            }
        }

        private func finishReply(_ answer: Bool) {
            lock.lock()
            let waiter = replyWaiter
            replyWaiter = nil
            lock.unlock()
            waiter?.resume(returning: answer)
        }

        func close() {
            lock.lock()
            closed = true
            lock.unlock()
            finishStart(false)
            finishReply(false)
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
    }
}
