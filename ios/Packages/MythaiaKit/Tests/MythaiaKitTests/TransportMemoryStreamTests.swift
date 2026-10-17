import Foundation
import XCTest
@testable import MythaiaKit

/// Two ByteStreams joined back to back in memory: what one end sends the
/// other receives. Closing an end fails its own pending read and is the end
/// of the stream to the other.
final class MemoryStreamPair {
    final class End: ByteStream, @unchecked Sendable {
        let inbox = TransportChannel<Data>()
        var peer: End?
        private let lock = NSLock()
        private var closed = false

        var isClosed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return closed
        }

        func send(_ data: Data) async throws {
            if isClosed { throw MythaiaError.closed }
            if data.isEmpty { return }
            guard let peer = peer, peer.inbox.trySend(Data(data)) else {
                throw MythaiaError.closed
            }
        }

        func receive() async throws -> Data? {
            if isClosed { throw MythaiaError.closed }
            return try await inbox.receive()
        }

        func close() {
            lock.lock()
            if closed {
                lock.unlock()
                return
            }
            closed = true
            lock.unlock()
            inbox.close(MythaiaError.closed)
            peer?.inbox.close()
        }

        /// Puts `data` straight into this end's inbox, as if the peer had
        /// sent it. Synchronous, so the order of a test's calls is the order
        /// on the wire.
        func inject(_ data: Data) {
            inbox.trySend(data)
        }
    }

    let client: End
    let server: End

    init() {
        client = End()
        server = End()
        client.peer = server
        server.peer = client
    }
}

/// Hands out the given reads in order, then the end of the stream; records
/// every write.
final class TransportScriptedStream: ByteStream, @unchecked Sendable {
    private let lock = NSLock()
    private var reads: [Data]
    private var written: [Data] = []
    private var closed = false

    init(_ reads: [Data]) {
        self.reads = reads
    }

    var sent: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return written
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    func send(_ data: Data) async throws {
        record(data)
    }

    func receive() async throws -> Data? {
        nextRead()
    }

    func close() {
        lock.lock()
        closed = true
        lock.unlock()
    }

    private func record(_ data: Data) {
        lock.lock()
        written.append(Data(data))
        lock.unlock()
    }

    private func nextRead() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if reads.isEmpty { return nil }
        return reads.removeFirst()
    }
}

enum TransportTestSupport {
    /// Bytes from hex digits; spaces are ignored.
    static func bytes(_ hex: String) -> [UInt8] {
        let digits = Array(hex.filter { !$0.isWhitespace })
        var out: [UInt8] = []
        var i = 0
        while i + 1 < digits.count {
            out.append(UInt8(String(digits[i...(i + 1)]), radix: 16)!)
            i += 2
        }
        return out
    }

    static func hex(_ text: String) -> Data {
        Data(bytes(text))
    }

    /// The error `body` throws, or nil when it returns.
    static func error(of body: () async throws -> Void) async -> Error? {
        do {
            try await body()
            return nil
        } catch {
            return error
        }
    }

    /// Polls `condition` every 10 ms; false if it is still false after `timeout` seconds.
    static func waitUntil(timeout: Double = 3, _ condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return false }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return true
    }
}

final class TransportMemoryStreamTests: XCTestCase {

    func testWhatOneEndSendsTheOtherReceivesThenTheEnd() async throws {
        let pair = MemoryStreamPair()
        try await pair.client.send(Data("one".utf8))
        try await pair.client.send(Data("two".utf8))
        pair.client.close()
        let first = try await pair.server.receive()
        let second = try await pair.server.receive()
        let end = try await pair.server.receive()
        XCTAssertEqual(first, Data("one".utf8))
        XCTAssertEqual(second, Data("two".utf8))
        XCTAssertNil(end)
    }

    func testAChannelIsDrainedBeforeItsFailureIsReported() async throws {
        let channel = TransportChannel<Int>()
        channel.trySend(1)
        channel.close(MythaiaError.closed)
        XCTAssertFalse(channel.trySend(2))
        let first = try await channel.receive()
        XCTAssertEqual(first, 1)
        let error = await TransportTestSupport.error { _ = try await channel.receive() }
        XCTAssertEqual(error as? MythaiaError, .closed)
    }

    func testAWaitingReceiverIsWokenByTheNextElement() async throws {
        let channel = TransportChannel<Int>()
        let reader = Task { try await channel.receive() }
        try await Task.sleep(nanoseconds: 20_000_000)
        channel.trySend(7)
        let value = try await reader.value
        XCTAssertEqual(value, 7)
    }

    func testACancelledReceiverLeavesWithoutTakingAnything() async throws {
        let channel = TransportChannel<Int>()
        let reader = Task { try await channel.receive() }
        try await Task.sleep(nanoseconds: 20_000_000)
        reader.cancel()
        let error = await TransportTestSupport.error { _ = try await reader.value }
        XCTAssertTrue(error is CancellationError, "\(String(describing: error))")
        channel.trySend(9)
        XCTAssertEqual(channel.tryReceive(), 9)
    }

    func testADeferredSettlesOnceAndWakesEveryWaiter() async throws {
        let deferred = TransportDeferred<Int>()
        let a = Task { try await deferred.wait() }
        let b = Task { try await deferred.wait() }
        try await Task.sleep(nanoseconds: 20_000_000)
        XCTAssertTrue(deferred.complete(3))
        XCTAssertFalse(deferred.fail(MythaiaError.closed))
        let first = try await a.value
        let second = try await b.value
        let late = try await deferred.wait()
        XCTAssertEqual([first, second, late], [3, 3, 3])
    }

    func testTheMutexHandsOverInOrder() async throws {
        let mutex = TransportAsyncMutex()
        let log = TransportChannel<Int>()
        await mutex.acquire()
        let waiters = (1...3).map { index in
            Task {
                await mutex.acquire()
                log.trySend(index)
                mutex.release()
            }
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertNil(log.tryReceive(), "a waiter ran while the lock was held")
        mutex.release()
        for waiter in waiters {
            await waiter.value
        }
        var seen: [Int] = []
        while let value = log.tryReceive() {
            seen.append(value)
        }
        XCTAssertEqual(seen.sorted(), [1, 2, 3])
    }

    func testBase64URLHasNoPaddingAndTheURLAlphabet() {
        // FB FF is "+/8=" in standard base64.
        XCTAssertEqual(TransportEncoding.base64URL(Data([0xFB, 0xFF])), "-_8")
        XCTAssertEqual(TransportEncoding.base64URL(Data("hello".utf8)), "aGVsbG8")
        XCTAssertEqual(TransportEncoding.base64URL(Data()), "")
    }

    func testTheHeadEndIsFoundWhereverItIs() {
        let bytes = Array("HTTP/1.1 101 OK\r\nA: b\r\n\r\nrest".utf8)
        // "HTTP/1.1 101 OK" is 15 bytes, CRLF, "A: b" at 17...20, the empty line at 21.
        XCTAssertEqual(TransportEncoding.headerEnd(bytes), 21)
        XCTAssertNil(TransportEncoding.headerEnd(Array("HTTP/1.1 101\r\n\r".utf8)))
    }

    func testTransportErrorsComeOutAsMythaiaErrors() {
        XCTAssertEqual(TransportErrors.map(Http2Error.goaway) as? MythaiaError, .protocolError("HTTP/2 GOAWAY received"))
        XCTAssertEqual(TransportErrors.map(Http2Error.tunnelFailed("404")) as? MythaiaError,
                       .http(404, "the server refused the request"))
        XCTAssertEqual(TransportErrors.map(XHttpError.connectionClosed) as? MythaiaError, .closed)
        XCTAssertEqual(TransportErrors.map(MythaiaError.timeout("x")) as? MythaiaError, .timeout("x"))
        XCTAssertTrue(TransportErrors.map(CancellationError()) is CancellationError)
    }
}
