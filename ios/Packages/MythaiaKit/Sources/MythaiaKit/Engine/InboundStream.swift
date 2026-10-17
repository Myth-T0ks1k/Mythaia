import Foundation
import Network

/// A connection accepted by the local proxy, as a `ByteStream`.
///
/// One receive is outstanding on the connection at a time. A read that gives
/// up waiting (`read(waitingAtMost:)`) leaves that receive in place, and
/// whatever it brings is handed to the next read: the short wait for a
/// client's first bytes must never lose them.
final class InboundStream: ByteStream, @unchecked Sendable {
    enum ReadOutcome {
        case data(Data)
        case end
        case failed(Error)
        case timedOut
    }

    /// The most one receive returns; the relay keeps one chunk per direction
    /// in flight, so this bounds the memory a busy connection holds.
    static let maximumChunk = 32 * 1024

    let connection: NWConnection
    private let queue: DispatchQueue
    private let lock = NSLock()
    /// An outcome that arrived when nobody was waiting.
    private var stash: ReadOutcome?
    private var receiving = false
    private var ended = false
    private var closed = false
    private var waiter: ((ReadOutcome) -> Void)?
    private var waiterToken: UInt64 = 0

    init(_ connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    func start() {
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed:
                self?.close()
            case .cancelled:
                self?.close()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    func send(_ data: Data) async throws {
        if isClosed { throw MythaiaError.closed }
        let connection = self.connection
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func receive() async throws -> Data? {
        let outcome = await next(timeout: nil)
        switch outcome {
        case .data(let data):
            return data
        case .end:
            return nil
        case .failed(let error):
            throw error
        case .timedOut:
            throw MythaiaError.timeout("reading from the client")
        }
    }

    /// The next chunk, the end, or `.timedOut` after `seconds` with the
    /// receive left running for the next read.
    func read(waitingAtMost seconds: Double) async -> ReadOutcome {
        await next(timeout: seconds)
    }

    func close() {
        lock.lock()
        let wasClosed = closed
        closed = true
        let pending = waiter
        waiter = nil
        lock.unlock()
        if !wasClosed {
            connection.cancel()
        }
        pending?(.failed(MythaiaError.closed))
    }

    private func next(timeout: Double?) async -> ReadOutcome {
        await withCheckedContinuation { (continuation: CheckedContinuation<ReadOutcome, Never>) in
            lock.lock()
            if let ready = stash {
                stash = nil
                lock.unlock()
                continuation.resume(returning: ready)
                return
            }
            if ended {
                lock.unlock()
                continuation.resume(returning: .end)
                return
            }
            if closed {
                lock.unlock()
                continuation.resume(returning: .failed(MythaiaError.closed))
                return
            }
            waiterToken &+= 1
            let token = waiterToken
            waiter = { outcome in
                continuation.resume(returning: outcome)
            }
            let mustReceive = !receiving
            receiving = true
            lock.unlock()
            if mustReceive {
                issueReceive()
            }
            if let timeout {
                queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
                    self?.expire(token)
                }
            }
        }
    }

    private func expire(_ token: UInt64) {
        lock.lock()
        guard token == waiterToken, let pending = waiter else {
            lock.unlock()
            return
        }
        waiter = nil
        lock.unlock()
        pending(.timedOut)
    }

    private func issueReceive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: InboundStream.maximumChunk) { data, _, isComplete, error in
            self.deliver(data: data, isComplete: isComplete, error: error)
        }
    }

    private func deliver(data: Data?, isComplete: Bool, error: NWError?) {
        let outcome: ReadOutcome
        var endsAfter = false
        if let data, !data.isEmpty {
            outcome = .data(data)
            endsAfter = isComplete
        } else if let error {
            outcome = .failed(error)
        } else if isComplete {
            outcome = .end
            endsAfter = true
        } else {
            // Neither bytes nor an end: ask again.
            issueReceive()
            return
        }
        lock.lock()
        receiving = false
        if endsAfter {
            ended = true
        }
        let pending = waiter
        waiter = nil
        if pending == nil {
            stash = outcome
        }
        lock.unlock()
        pending?(outcome)
    }
}
