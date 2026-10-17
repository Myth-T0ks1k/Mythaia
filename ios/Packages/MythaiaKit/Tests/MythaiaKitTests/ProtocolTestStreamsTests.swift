import Foundation
import XCTest
@testable import MythaiaKit

/// In-memory streams for the protocol tests.
enum ProtocolTestStreams {
    /// Records every write and answers reads from a script; after the
    /// script, fails with `failure` or ends cleanly.
    final class Scripted: ByteStream, @unchecked Sendable {
        private let lock = NSLock()
        private var recorded: [Data] = []
        private var reads: [Data]
        private let failure: Error?
        private var isClosed = false

        init(reads: [Data] = [], failure: Error? = nil) {
            self.reads = reads
            self.failure = failure
        }

        /// Every write, in order.
        var writes: [Data] {
            lock.lock()
            defer { lock.unlock() }
            return recorded
        }

        /// Everything written, as one run of bytes.
        var written: Data {
            var out = Data()
            for write in writes {
                out.append(write)
            }
            return out
        }

        var closed: Bool {
            lock.lock()
            defer { lock.unlock() }
            return isClosed
        }

        func queue(_ data: Data) {
            lock.lock()
            reads.append(data)
            lock.unlock()
        }

        func send(_ data: Data) async throws {
            try record(data)
        }

        func receive() async throws -> Data? {
            return try next()
        }

        func close() {
            lock.lock()
            isClosed = true
            lock.unlock()
        }

        private func record(_ data: Data) throws {
            lock.lock()
            defer { lock.unlock() }
            if isClosed { throw MythaiaError.closed }
            recorded.append(Data(data))
        }

        private func next() throws -> Data? {
            lock.lock()
            defer { lock.unlock() }
            if !reads.isEmpty {
                return reads.removeFirst()
            }
            if let failure = failure {
                throw failure
            }
            return nil
        }
    }

    /// One end of an in-memory connection: what one end sends, the other
    /// receives, chunk for chunk.
    final class PipeEnd: ByteStream, @unchecked Sendable {
        private let lock = NSLock()
        private var queue: [Data] = []
        private var waiter: CheckedContinuation<Data?, Error>?
        private var ended = false
        weak var peer: PipeEnd?

        func send(_ data: Data) async throws {
            guard let peer = currentPeer(), !hasEnded() else { throw MythaiaError.closed }
            peer.deliver(Data(data))
        }

        func receive() async throws -> Data? {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
                lock.lock()
                if !queue.isEmpty {
                    let data = queue.removeFirst()
                    lock.unlock()
                    continuation.resume(returning: data)
                    return
                }
                if ended {
                    lock.unlock()
                    continuation.resume(returning: nil)
                    return
                }
                waiter = continuation
                lock.unlock()
            }
        }

        func close() {
            finish()
            currentPeer()?.finish()
        }

        private func currentPeer() -> PipeEnd? {
            lock.lock()
            defer { lock.unlock() }
            return peer
        }

        private func hasEnded() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return ended
        }

        fileprivate func deliver(_ data: Data) {
            lock.lock()
            if let waiting = waiter {
                waiter = nil
                lock.unlock()
                waiting.resume(returning: data)
                return
            }
            queue.append(data)
            lock.unlock()
        }

        fileprivate func finish() {
            lock.lock()
            ended = true
            let waiting = waiter
            waiter = nil
            lock.unlock()
            waiting?.resume(returning: nil)
        }
    }

    /// Two connected ends. Both are returned strongly held; each holds the
    /// other weakly, so the test owns their lifetime.
    static func pair() -> (PipeEnd, PipeEnd) {
        let a = PipeEnd()
        let b = PipeEnd()
        a.peer = b
        b.peer = a
        return (a, b)
    }

    static func hex(_ text: String) -> Data {
        var out = [UInt8]()
        var high: UInt8?
        for c in text.utf8 {
            let value: UInt8
            switch c {
            case 0x30...0x39: value = c - 0x30
            case 0x61...0x66: value = c - 0x61 + 10
            case 0x41...0x46: value = c - 0x41 + 10
            default: continue
            }
            if let h = high {
                out.append(h << 4 | value)
                high = nil
            } else {
                high = value
            }
        }
        return Data(out)
    }

    static func hexString(_ data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    static func be16(_ data: Data, _ at: Int) -> Int {
        let bytes = [UInt8](data)
        return (Int(bytes[at]) << 8) | Int(bytes[at + 1])
    }

    /// `n` bytes of `i mod 251`, the input pattern of the BLAKE3 vectors.
    static func sequence(_ n: Int) -> Data {
        var out = [UInt8](repeating: 0, count: n)
        for i in 0..<n {
            out[i] = UInt8(i % 251)
        }
        return Data(out)
    }
}

final class ProtocolTestStreamsTests: XCTestCase {
    func testPipeCarriesChunksBothWaysAndEnds() async throws {
        let (a, b) = ProtocolTestStreams.pair()
        try await a.send(Data("ping".utf8))
        let first = try await b.receive()
        XCTAssertEqual(first, Data("ping".utf8))

        try await b.send(Data("pong".utf8))
        let second = try await a.receive()
        XCTAssertEqual(second, Data("pong".utf8))

        a.close()
        let end = try await b.receive()
        XCTAssertNil(end)
    }

    func testScriptedReplaysThenFails() async throws {
        let stream = ProtocolTestStreams.Scripted(reads: [Data([1])], failure: MythaiaError.connectFailed("reset"))
        let first = try await stream.receive()
        XCTAssertEqual(first, Data([1]))
        do {
            _ = try await stream.receive()
            XCTFail("expected the scripted failure")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .connectFailed("reset"))
        }
    }
}
