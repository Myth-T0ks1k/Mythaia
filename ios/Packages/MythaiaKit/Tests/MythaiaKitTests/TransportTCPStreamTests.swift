import Foundation
import Network
import XCTest
@testable import MythaiaKit

/// A TCP listener on the loopback interface that either echoes the first
/// read and hangs up, or holds every connection open and silent.
final class TransportLocalListener: @unchecked Sendable {
    enum Behaviour {
        case echoOnceThenClose
        case holdOpen
    }

    private let listener: NWListener
    private let queue = DispatchQueue(label: "com.mythaia.tests.listener")
    private let lock = NSLock()
    private var held: [NWConnection] = []
    private let ready = TransportDeferred<UInt16>()

    init(_ behaviour: Behaviour) throws {
        listener = try NWListener(using: .tcp, on: .any)
        listener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                if let port = self.listener.port?.rawValue {
                    self.ready.complete(port)
                }
            case .failed(let error):
                self.ready.fail(error)
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self = self else { return }
            self.keep(connection)
            connection.start(queue: self.queue)
            if case .echoOnceThenClose = behaviour {
                connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, _, _ in
                    connection.send(content: data, completion: .contentProcessed({ _ in
                        connection.cancel()
                    }))
                }
            }
        }
        listener.start(queue: queue)
    }

    private func keep(_ connection: NWConnection) {
        lock.lock()
        held.append(connection)
        lock.unlock()
    }

    func port() async throws -> UInt16 {
        try await ready.wait()
    }

    func stop() {
        lock.lock()
        let connections = held
        held = []
        lock.unlock()
        for connection in connections {
            connection.cancel()
        }
        listener.cancel()
    }
}

final class TransportTCPStreamTests: XCTestCase {

    func testAConnectionSendsReceivesAndSeesThePeersEnd() async throws {
        let listener = try TransportLocalListener(.echoOnceThenClose)
        defer { listener.stop() }
        let port = try await listener.port()

        let stream = try await TCPStream.connect(host: "127.0.0.1", port: port, timeout: 5)
        try await stream.send(Data("ping".utf8))
        let echoed = try await stream.receive()
        XCTAssertEqual(echoed, Data("ping".utf8))
        let end = try await stream.receive()
        XCTAssertNil(end)
        stream.close()
    }

    func testClosingFailsAReadInProgressAndEveryLaterCall() async throws {
        let listener = try TransportLocalListener(.holdOpen)
        defer { listener.stop() }
        let port = try await listener.port()

        let stream = try await TCPStream.connect(host: "127.0.0.1", port: port, timeout: 5)
        let reading = Task { try await stream.receive() }
        try await Task.sleep(nanoseconds: 100_000_000)
        stream.close()
        let readError = await TransportTestSupport.error { _ = try await reading.value }
        XCTAssertEqual(readError as? MythaiaError, .closed)
        let sendError = await TransportTestSupport.error { try await stream.send(Data("x".utf8)) }
        XCTAssertEqual(sendError as? MythaiaError, .closed)
        // A second close is harmless.
        stream.close()
    }

    func testCancellingTheReadingTaskClosesTheConnection() async throws {
        let listener = try TransportLocalListener(.holdOpen)
        defer { listener.stop() }
        let port = try await listener.port()

        let stream = try await TCPStream.connect(host: "127.0.0.1", port: port, timeout: 5)
        let reading = Task { try await stream.receive() }
        try await Task.sleep(nanoseconds: 100_000_000)
        reading.cancel()
        let error = await TransportTestSupport.error { _ = try await reading.value }
        XCTAssertNotNil(error)
        let sendError = await TransportTestSupport.error { try await stream.send(Data("x".utf8)) }
        XCTAssertEqual(sendError as? MythaiaError, .closed)
    }

    func testARefusedConnectionFailsInsteadOfWaitingOutTheTimeout() async throws {
        // A port that was just listened on and is closed again refuses.
        let listener = try TransportLocalListener(.holdOpen)
        let port = try await listener.port()
        listener.stop()
        try await Task.sleep(nanoseconds: 100_000_000)

        let started = Date()
        let error = await TransportTestSupport.error { _ = try await TCPStream.connect(host: "127.0.0.1", port: port, timeout: 5) }
        XCTAssertNotNil(error)
        XCTAssertTrue(error is MythaiaError, "\(String(describing: error))")
        XCTAssertLessThan(Date().timeIntervalSince(started), 4)
    }
}
