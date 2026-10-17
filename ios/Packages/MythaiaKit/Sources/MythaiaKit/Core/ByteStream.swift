import Foundation

/// A reliable, ordered, bidirectional byte stream: a TCP connection, a TLS
/// session over one, a WebSocket, or a proxy protocol's flow over any of
/// them. Every layer of a dial is one of these wrapping the next.
///
/// One task sends and one task receives at a time; the two may run
/// concurrently. Implementations must allow `close()` from any thread.
public protocol ByteStream: AnyObject {
    /// Writes all of `data`. Throws once the stream is closed or has failed.
    func send(_ data: Data) async throws
    /// The next chunk from the peer, never empty; nil after a clean end of stream.
    func receive() async throws -> Data?
    /// Closes both directions. Calls in progress and later calls fail.
    func close()
}

/// A datagram flow: every `send` is one packet and every `receive` returns one.
public protocol DatagramStream: AnyObject {
    func send(_ packet: Data) async throws
    /// The next packet; nil once the flow has ended.
    func receive() async throws -> Data?
    func close()
}

/// Errors every layer throws. The message is shown to the user as is, so it
/// says what failed in plain words.
public enum MythaiaError: Error, LocalizedError, Equatable {
    case closed
    case timeout(String)
    case connectFailed(String)
    case protocolError(String)
    case tls(String)
    case unsupported(String)
    case invalidConfiguration(String)
    case parse(String)
    case http(Int, String)

    public var errorDescription: String? {
        switch self {
        case .closed: return "Connection closed"
        case .timeout(let what): return "Timed out: \(what)"
        case .connectFailed(let why): return "Could not connect: \(why)"
        case .protocolError(let why): return "Protocol error: \(why)"
        case .tls(let why): return "TLS error: \(why)"
        case .unsupported(let what): return "Not supported: \(what)"
        case .invalidConfiguration(let why): return "Invalid configuration: \(why)"
        case .parse(let why): return "Could not read: \(why)"
        case .http(let code, let why): return "HTTP \(code): \(why)"
        }
    }
}

/// A host and port, the host being a domain name or an IP literal (IPv6
/// without brackets).
public struct Endpoint: Hashable, Codable, CustomStringConvertible {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

/// Buffered reading on top of a `ByteStream` for the parsers that need exact
/// lengths or delimiters (proxy reply headers, TLS records, HTTP heads).
/// Owned by one reading task.
///
/// The buffer is always a fresh `Data` whose indices start at zero: slicing
/// `Data` (which `removeFirst` does, `Data` being its own subsequence) keeps
/// the parent's indices, and every offset below assumes zero-based ones.
public final class StreamReader {
    public let stream: ByteStream
    private var buffer = Data()

    public init(_ stream: ByteStream) {
        self.stream = stream
    }

    /// Bytes already read from the stream and not yet consumed.
    public var buffered: Int { buffer.count }

    /// Exactly `count` bytes; throws `closed` if the stream ends first.
    public func readExactly(_ count: Int) async throws -> Data {
        while buffer.count < count {
            guard let chunk = try await stream.receive() else { throw MythaiaError.closed }
            buffer.append(chunk)
        }
        return take(count)
    }

    /// Whatever is buffered, or else the next chunk; nil at end of stream.
    public func readSome() async throws -> Data? {
        if !buffer.isEmpty {
            let out = buffer
            buffer = Data()
            return out
        }
        return try await stream.receive()
    }

    /// Everything up to and including `delimiter`. Throws `parse` once more
    /// than `limit` bytes arrive without it.
    public func readThrough(_ delimiter: Data, limit: Int = 64 * 1024) async throws -> Data {
        var searchFrom = 0
        while true {
            let lower = max(0, searchFrom - delimiter.count)
            if let range = buffer.range(of: delimiter, in: lower..<buffer.count) {
                return take(range.upperBound)
            }
            if buffer.count > limit { throw MythaiaError.parse("header too long") }
            searchFrom = buffer.count
            guard let chunk = try await stream.receive() else { throw MythaiaError.closed }
            buffer.append(chunk)
        }
    }

    /// Puts bytes back in front of what is buffered.
    public func unread(_ data: Data) {
        guard !data.isEmpty else { return }
        var joined = Data(data)
        joined.append(buffer)
        buffer = joined
    }

    /// The first `count` bytes, leaving the rest as a new zero-based buffer.
    private func take(_ count: Int) -> Data {
        let out = Data(buffer.prefix(count))
        buffer = count >= buffer.count ? Data() : Data(buffer.suffix(from: count))
        return out
    }

    /// Hands back whatever is buffered, leaving the reader empty; used when
    /// a parser is done and the stream changes hands.
    public func drain() -> Data {
        let out = buffer
        buffer = Data()
        return out
    }
}

/// A `ByteStream` that first returns bytes a parser read ahead, then reads
/// the underlying stream. Lets a layer hand its leftovers to the next one.
public final class PrefixedStream: ByteStream {
    private let inner: ByteStream
    private var prefix: Data?
    private let lock = NSLock()

    public init(_ inner: ByteStream, prefix: Data) {
        self.inner = inner
        self.prefix = prefix.isEmpty ? nil : prefix
    }

    public func send(_ data: Data) async throws {
        try await inner.send(data)
    }

    public func receive() async throws -> Data? {
        lock.lock()
        let pending = prefix
        prefix = nil
        lock.unlock()
        if let pending { return pending }
        return try await inner.receive()
    }

    public func close() {
        inner.close()
    }
}

/// Runs `operation`, failing with `timeout(what)` after `seconds`.
///
/// The result travels through a box rather than as the task group's child
/// result, because a task group needs a `Sendable` result type and most
/// results here (streams) are not.
public func withTimeout<T>(
    _ seconds: Double,
    _ what: String,
    _ operation: @escaping () async throws -> T
) async throws -> T {
    let box = TimeoutResultBox<T>()
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
            box.set(try await operation())
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw MythaiaError.timeout(what)
        }
        defer { group.cancelAll() }
        _ = try await group.next()
    }
    guard let value = box.get() else { throw MythaiaError.timeout(what) }
    return value
}

private final class TimeoutResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?

    func set(_ newValue: T) {
        lock.lock(); value = newValue; lock.unlock()
    }

    func get() -> T? {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

/// Copies both directions between two streams until either side ends, then
/// closes both. Returns the bytes moved (a to b, b to a).
@discardableResult
public func relay(_ a: ByteStream, _ b: ByteStream) async -> (up: Int64, down: Int64) {
    let counter = RelayCounter()
    await withTaskGroup(of: Void.self) { group in
        group.addTask {
            do {
                while let chunk = try await a.receive() {
                    try await b.send(chunk)
                    counter.add(up: Int64(chunk.count))
                }
            } catch {}
            a.close()
            b.close()
        }
        group.addTask {
            do {
                while let chunk = try await b.receive() {
                    try await a.send(chunk)
                    counter.add(down: Int64(chunk.count))
                }
            } catch {}
            a.close()
            b.close()
        }
    }
    return counter.totals
}

private final class RelayCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var up: Int64 = 0
    private var down: Int64 = 0

    func add(up bytes: Int64) {
        lock.lock(); up += bytes; lock.unlock()
    }

    func add(down bytes: Int64) {
        lock.lock(); down += bytes; lock.unlock()
    }

    var totals: (up: Int64, down: Int64) {
        lock.lock(); defer { lock.unlock() }
        return (up, down)
    }
}
