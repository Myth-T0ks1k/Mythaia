import Foundation

/// An async lock for the writers of one connection: frames written by several
/// tasks must reach the wire whole and in the order they took the lock.
/// Waiters are served first come, first served. Not cancellable: it is only
/// ever held around one write.
final class TransportAsyncMutex: @unchecked Sendable {
    private let lock = NSLock()
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init() {}

    func acquire() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            self.lock.lock()
            if !self.locked {
                self.locked = true
                self.lock.unlock()
                continuation.resume()
                return
            }
            self.waiters.append(continuation)
            self.lock.unlock()
        }
    }

    /// Hands the lock straight to the next waiter, so nobody can barge in
    /// between and reorder the writes.
    func release() {
        lock.lock()
        if waiters.isEmpty {
            locked = false
            lock.unlock()
            return
        }
        let next = waiters.removeFirst()
        lock.unlock()
        next.resume()
    }
}

/// A value that arrives once, awaited by any number of tasks: a handshake's
/// outcome, a flow-control window opening. Settling it a second time is a
/// no-op, so the side that finishes first decides.
final class TransportDeferred<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Value, Error>?
    private var waiters: [(id: UInt64, continuation: CheckedContinuation<Value, Error>)] = []
    private var nextWaiterID: UInt64 = 0

    init() {}

    var isCompleted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return result != nil
    }

    @discardableResult
    func complete(_ value: Value) -> Bool {
        settle(.success(value))
    }

    @discardableResult
    func fail(_ error: Error) -> Bool {
        settle(.failure(error))
    }

    private func settle(_ outcome: Result<Value, Error>) -> Bool {
        lock.lock()
        if result != nil {
            lock.unlock()
            return false
        }
        result = outcome
        let pending = waiters
        waiters = []
        lock.unlock()
        for waiter in pending {
            waiter.continuation.resume(with: outcome)
        }
        return true
    }

    /// The value, or the failure; a cancelled waiter leaves with
    /// CancellationError and the value stays for the others.
    func wait() async throws -> Value {
        let id = reserveWaiterID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Value, Error>) in
                self.lock.lock()
                if let settled = self.result {
                    self.lock.unlock()
                    continuation.resume(with: settled)
                    return
                }
                if Task.isCancelled {
                    self.lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.waiters.append((id: id, continuation: continuation))
                self.lock.unlock()
            }
        } onCancel: {
            self.cancelWaiter(id)
        }
    }

    private func reserveWaiterID() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        nextWaiterID &+= 1
        return nextWaiterID
    }

    private func cancelWaiter(_ id: UInt64) {
        lock.lock()
        guard let index = waiters.firstIndex(where: { $0.id == id }) else {
            lock.unlock()
            return
        }
        let waiter = waiters.remove(at: index)
        lock.unlock()
        waiter.continuation.resume(throwing: CancellationError())
    }
}

/// An unbounded queue from one producer to its readers, closed once: what is
/// already queued is still read after the close, and only then does the
/// reader see the end (nil) or the failure the channel was closed with.
final class TransportChannel<Element>: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: [Element] = []
    private var head = 0
    private var closed = false
    private var closeError: Error?
    private var waiters: [(id: UInt64, continuation: CheckedContinuation<Element?, Error>)] = []
    private var nextWaiterID: UInt64 = 0

    init() {}

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    /// Queues `element`; false once the channel is closed.
    @discardableResult
    func trySend(_ element: Element) -> Bool {
        lock.lock()
        if closed {
            lock.unlock()
            return false
        }
        if !waiters.isEmpty {
            let waiter = waiters.removeFirst()
            lock.unlock()
            waiter.continuation.resume(returning: element)
            return true
        }
        buffer.append(element)
        lock.unlock()
        return true
    }

    /// Closes the channel, with `error` for a failure or nil for a clean
    /// end. Only the first close counts.
    @discardableResult
    func close(_ error: Error? = nil) -> Bool {
        lock.lock()
        if closed {
            lock.unlock()
            return false
        }
        closed = true
        closeError = error
        let pending = waiters
        waiters = []
        lock.unlock()
        for waiter in pending {
            if let error = error {
                waiter.continuation.resume(throwing: error)
            } else {
                waiter.continuation.resume(returning: nil)
            }
        }
        return true
    }

    /// The next queued element without waiting, or nil.
    func tryReceive() -> Element? {
        lock.lock()
        defer { lock.unlock() }
        return popLocked()
    }

    /// The next element; nil after a clean close, the close's error after a
    /// failed one, in both cases only once the queue is drained.
    func receive() async throws -> Element? {
        let id = reserveWaiterID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Element?, Error>) in
                self.lock.lock()
                if let element = self.popLocked() {
                    self.lock.unlock()
                    continuation.resume(returning: element)
                    return
                }
                if self.closed {
                    let error = self.closeError
                    self.lock.unlock()
                    if let error = error {
                        continuation.resume(throwing: error)
                    } else {
                        continuation.resume(returning: nil)
                    }
                    return
                }
                if Task.isCancelled {
                    self.lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                self.waiters.append((id: id, continuation: continuation))
                self.lock.unlock()
            }
        } onCancel: {
            self.cancelWaiter(id)
        }
    }

    private func popLocked() -> Element? {
        guard head < buffer.count else { return nil }
        let element = buffer[head]
        head += 1
        if head == buffer.count {
            buffer.removeAll(keepingCapacity: buffer.count <= 64)
            head = 0
        } else if head >= 64 && head * 2 >= buffer.count {
            buffer.removeFirst(head)
            head = 0
        }
        return element
    }

    private func reserveWaiterID() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        nextWaiterID &+= 1
        return nextWaiterID
    }

    private func cancelWaiter(_ id: UInt64) {
        lock.lock()
        guard let index = waiters.firstIndex(where: { $0.id == id }) else {
            lock.unlock()
            return
        }
        let waiter = waiters.remove(at: index)
        lock.unlock()
        waiter.continuation.resume(throwing: CancellationError())
    }
}

/// A transport's own error that knows how to say itself as a MythaiaError,
/// the only kind the layers above show the user.
protocol TransportErrorConvertible: Error {
    var mythaiaError: MythaiaError { get }
}

enum TransportErrors {
    /// `error` as the layers above expect it. Cancellation passes through
    /// untouched: whoever cancelled is waiting for exactly that.
    static func map(_ error: Error) -> Error {
        if error is MythaiaError { return error }
        if error is CancellationError { return error }
        if let convertible = error as? TransportErrorConvertible {
            return convertible.mythaiaError
        }
        return MythaiaError.protocolError(error.localizedDescription)
    }
}

/// The stream a transport hands to the protocol above it: the transport's
/// own errors come out as MythaiaError.
final class TransportErrorMappingStream: ByteStream, @unchecked Sendable {
    let inner: ByteStream

    init(_ inner: ByteStream) {
        self.inner = inner
    }

    func send(_ data: Data) async throws {
        do {
            try await inner.send(data)
        } catch {
            throw TransportErrors.map(error)
        }
    }

    func receive() async throws -> Data? {
        do {
            return try await inner.receive()
        } catch {
            throw TransportErrors.map(error)
        }
    }

    func close() {
        inner.close()
    }
}

enum TransportEncoding {
    /// RFC 4648 §5 base64url without padding, as Xray reads early data.
    static func base64URL(_ data: Data) -> String {
        var text = data.base64EncodedString()
        text = text.replacingOccurrences(of: "+", with: "-")
        text = text.replacingOccurrences(of: "/", with: "_")
        while text.hasSuffix("=") {
            text.removeLast()
        }
        return text
    }

    static func randomBytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        var out: [UInt8] = []
        out.reserveCapacity(count)
        for _ in 0..<count {
            out.append(UInt8.random(in: UInt8.min...UInt8.max, using: &generator))
        }
        return out
    }

    /// Where `\r\n\r\n` starts in `bytes` at or after `from`, or nil.
    static func headerEnd(_ bytes: [UInt8], from start: Int = 0) -> Int? {
        if bytes.count < 4 { return nil }
        var i = max(0, start)
        let last = bytes.count - 4
        while i <= last {
            if bytes[i] == 0x0D && bytes[i + 1] == 0x0A && bytes[i + 2] == 0x0D && bytes[i + 3] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }
}

/// Monotonic nanoseconds for idle and keepalive timing; wall-clock changes
/// must not fire or postpone a keepalive.
func transportMonotonicNanos() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds
}
