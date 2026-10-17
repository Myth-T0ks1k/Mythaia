import Foundation
import Network

/// A connected UDP socket (Network.framework) as a `DatagramStream`: direct
/// UDP flows, the SOCKS5 UDP relay and Shadowsocks UDP all send their
/// datagrams through one of these.
final class UdpSocketConnection: DatagramStream, @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var closed = false

    private init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    /// A UDP socket connected to `host`:`port` (a name is resolved by the
    /// system). Fails when there is no route rather than waiting for one.
    static func connect(host: String, port: UInt16, timeout: Double = 10) async throws -> UdpSocketConnection {
        guard let nwPort = NWEndpoint.Port(rawValue: port), port != 0 else {
            throw MythaiaError.invalidConfiguration("UDP port \(port) is not valid")
        }
        let queue = DispatchQueue(label: "com.mythaia.udp")
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
        let socket = UdpSocketConnection(connection: connection, queue: queue)
        do {
            try await socket.start(timeout: timeout, target: "\(host):\(port)")
        } catch {
            socket.close()
            throw error
        }
        return socket
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    private func start(timeout: Double, target: String) async throws {
        let gate = UdpStartGate()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            gate.install(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    gate.finish(nil)
                case .failed(let error):
                    gate.finish(MythaiaError.connectFailed("UDP to \(target): \(error.localizedDescription)"))
                case .waiting(let error):
                    gate.finish(MythaiaError.connectFailed("UDP to \(target): \(error.localizedDescription)"))
                case .cancelled:
                    gate.finish(MythaiaError.closed)
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                gate.finish(MythaiaError.timeout("UDP to \(target)"))
            }
        }
    }

    func send(_ packet: Data) async throws {
        if isClosed { throw MythaiaError.closed }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: packet, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: MythaiaError.connectFailed("UDP send failed: \(error.localizedDescription)"))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func receive() async throws -> Data? {
        if isClosed { return nil }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            connection.receiveMessage { [weak self] content, _, _, error in
                let ended = self?.isClosed ?? true
                if let error = error {
                    if ended {
                        continuation.resume(returning: nil)
                    } else {
                        continuation.resume(throwing: MythaiaError.connectFailed("UDP receive failed: \(error.localizedDescription)"))
                    }
                    return
                }
                if ended {
                    continuation.resume(returning: nil)
                    return
                }
                continuation.resume(returning: content ?? Data())
            }
        }
    }

    func close() {
        lock.lock()
        let wasClosed = closed
        closed = true
        lock.unlock()
        if !wasClosed {
            connection.cancel()
        }
    }
}

/// Resumes the start continuation exactly once, whichever of ready, failure
/// or the timer comes first.
private final class UdpStartGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var done = false

    func install(_ continuation: CheckedContinuation<Void, Error>) {
        lock.lock()
        self.continuation = continuation
        lock.unlock()
    }

    func finish(_ error: Error?) {
        lock.lock()
        if done {
            lock.unlock()
            return
        }
        done = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        if let error = error {
            pending?.resume(throwing: error)
        } else {
            pending?.resume()
        }
    }
}
