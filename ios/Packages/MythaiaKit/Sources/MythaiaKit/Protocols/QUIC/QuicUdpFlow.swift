import Foundation

/// A UDP flow carried in QUIC datagrams: `send` hands one payload to the
/// protocol's framing, `receive` returns one payload the dispatcher routed
/// here. Unreliable by design, as UDP is — a full inbox drops the oldest.
final class QuicUdpFlow: DatagramStream, @unchecked Sendable {
    /// How many payloads wait for a reader before the oldest is dropped.
    static let inboxCapacity = 256

    private let transmit: (Data) async throws -> Void
    private let onClose: () -> Void
    private let lock = NSLock()
    private var inbox: [Data] = []
    private var waiter: CheckedContinuation<Data?, Error>?
    private var closed = false

    init(transmit: @escaping (Data) async throws -> Void, onClose: @escaping () -> Void) {
        self.transmit = transmit
        self.onClose = onClose
    }

    deinit {
        // A flow nobody closed still releases its session id.
        lock.lock()
        let wasClosed = closed
        closed = true
        lock.unlock()
        if !wasClosed { onClose() }
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    /// A payload from the server for this flow.
    func deliver(_ payload: Data) {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        if let pending = waiter {
            waiter = nil
            lock.unlock()
            pending.resume(returning: payload)
            return
        }
        inbox.append(payload)
        if inbox.count > QuicUdpFlow.inboxCapacity {
            inbox.removeFirst(inbox.count - QuicUdpFlow.inboxCapacity)
        }
        lock.unlock()
    }

    func send(_ packet: Data) async throws {
        if isClosed { throw MythaiaError.closed }
        try await transmit(packet)
    }

    func receive() async throws -> Data? {
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
                lock.lock()
                if !inbox.isEmpty {
                    let next = inbox.removeFirst()
                    lock.unlock()
                    continuation.resume(returning: next)
                    return
                }
                if closed {
                    lock.unlock()
                    continuation.resume(returning: nil)
                    return
                }
                if waiter != nil {
                    lock.unlock()
                    continuation.resume(throwing: MythaiaError.protocolError("two reads at once on one UDP flow"))
                    return
                }
                waiter = continuation
                lock.unlock()
            }
        } onCancel: {
            self.close()
        }
    }

    func close() {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        inbox.removeAll()
        let pending = waiter
        waiter = nil
        lock.unlock()
        pending?.resume(returning: nil)
        onClose()
    }
}

/// Reassembles fragmented UDP messages: both protocols split a payload too
/// large for one datagram into numbered pieces under one packet id. Partial
/// messages are kept for a few seconds and then dropped, as the protocols'
/// own implementations do, so a lost fragment costs one packet and no memory.
final class UdpReassembler: @unchecked Sendable {
    /// A UDP packet reassembles in milliseconds on any working path; 2 s is
    /// already generous.
    static let staleMilliseconds: Int64 = 2_000

    /// A ceiling on half-assembled packets, so a flood of lone fragments
    /// cannot grow the table without bound.
    static let maxPartials = 1024

    private struct Partial {
        var pieces: [[UInt8]?]
        let started: Int64
        let order: UInt64
    }

    private let lock = NSLock()
    private var partials: [Int64: Partial] = [:]
    private var nextOrder: UInt64 = 0
    private let clock: () -> Int64

    /// `clock` is milliseconds; injectable so expiry can be tested without waiting.
    init(clock: @escaping () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) {
        self.clock = clock
    }

    /// The whole payload once every piece of `packetKey` has arrived, else nil.
    func add(packetKey: Int64, fragmentId: Int, fragmentCount: Int, payload: [UInt8]) -> [UInt8]? {
        if fragmentCount <= 1 { return payload }
        if fragmentId < 0 || fragmentId >= fragmentCount { return nil }
        lock.lock()
        defer { lock.unlock() }
        let now = clock()

        // Drop stale partials on every insert, not only when the table is
        // large. The key is (session << 16 | packetId) with a 16-bit packet
        // id, so a fragment of packet N and one of packet N+65536 share a key:
        // without a short expiry an orphaned fragment of the first would be
        // glued onto the second and corrupt it.
        partials = partials.filter { now - $0.value.started <= UdpReassembler.staleMilliseconds }

        var entry: Partial
        if let existing = partials[packetKey], existing.pieces.count == fragmentCount {
            entry = existing
        } else {
            // No partial, or one whose fragment count disagrees — a stale key
            // collision. Start fresh rather than glue mismatched pieces.
            nextOrder &+= 1
            entry = Partial(pieces: [[UInt8]?](repeating: nil, count: fragmentCount), started: now, order: nextOrder)
            if partials[packetKey] == nil && partials.count >= UdpReassembler.maxPartials {
                if let oldest = partials.min(by: { $0.value.order < $1.value.order }) {
                    partials.removeValue(forKey: oldest.key)
                }
            }
        }

        entry.pieces[fragmentId] = payload
        if entry.pieces.contains(where: { $0 == nil }) {
            partials[packetKey] = entry
            return nil
        }
        partials.removeValue(forKey: packetKey)
        var out: [UInt8] = []
        for piece in entry.pieces {
            if let piece = piece { out.append(contentsOf: piece) }
        }
        return out
    }
}
