import Foundation
import XCTest
@testable import MythaiaKit

/// A server ends a proxied stream with a close frame. A normal one is the end
/// of the data, not a failure: reported as one, the stack reset the app's
/// connection and dropped what it had not yet read (a log full of "WebSocket
/// closed (1005)" from a CDN-fronted server).
final class WebSocketCloseTests: XCTestCase {

    private let upgrade = Data("HTTP/1.1 101 Switching Protocols\r\n\r\n".utf8)

    private func binary(_ payload: [UInt8]) -> [UInt8] {
        [0x82, UInt8(payload.count)] + payload
    }

    private func closeFrame(_ code: Int?) -> [UInt8] {
        guard let code = code else { return [0x88, 0] }
        return [0x88, 2, UInt8((code >> 8) & 0xFF), UInt8(code & 0xFF)]
    }

    private func connection(_ frames: [[UInt8]]) -> (WebSocketConnection, TransportScriptedStream) {
        // The last data frame and the close arrive in one read, as they do off a CDN.
        var joined: [UInt8] = []
        for frame in frames {
            joined.append(contentsOf: frame)
        }
        let transport = TransportScriptedStream([upgrade, Data(joined)])
        let ws = WebSocketConnection(inner: transport, settings: WebSocketConnection.Settings(host: "example.com"))
        return (ws, transport)
    }

    func testAnEmptyCloseAfterTheLastDataIsTheEndOfTheStream() async throws {
        let (ws, transport) = connection([binary(Array("tail".utf8)), closeFrame(nil)])
        try await ws.performUpgrade()
        let tail = try await ws.receive()
        XCTAssertEqual(tail, Data("tail".utf8))
        let end = try await ws.receive()
        XCTAssertNil(end)
        // The close is answered with an empty close: 1005 is never sent.
        let reply = [UInt8](try XCTUnwrap(transport.sent.last))
        XCTAssertEqual(reply[0], 0x88)
        XCTAssertEqual(reply[1] & 0x7F, 0)
    }

    func testNormalClosureAndGoingAwayEndTheStreamToo() async throws {
        for code in [1000, 1001] {
            let (ws, transport) = connection([binary([1, 2, 3]), closeFrame(code)])
            try await ws.performUpgrade()
            let data = try await ws.receive()
            XCTAssertEqual(data, Data([1, 2, 3]))
            let end = try await ws.receive()
            XCTAssertNil(end, "code \(code)")
            // The code is echoed back, masked like every client frame.
            let reply = [UInt8](try XCTUnwrap(transport.sent.last))
            XCTAssertEqual(reply[0], 0x88)
            XCTAssertEqual(reply[1], 0x82)
            let mask = Array(reply[2..<6])
            XCTAssertEqual(reply[6] ^ mask[0], UInt8(code >> 8))
            XCTAssertEqual(reply[7] ^ mask[1], UInt8(code & 0xFF))
        }
    }

    func testACloseReportingAFaultStillFails() async throws {
        let (ws, _) = connection([closeFrame(1011)])
        try await ws.performUpgrade()
        let error = await TransportTestSupport.error { _ = try await ws.receive() }
        XCTAssertEqual(error as? WebSocketError, .connectionClosed(code: 1011, reason: ""))
    }

    func testTheTransportReportsTheFaultAsAMythaiaError() async throws {
        let transport = TransportScriptedStream([upgrade, Data(closeFrame(1011))])
        let stream = try await WebSocketTransport.open(over: transport, configuration: WebSocketConfiguration(host: "example.com"), earlyData: nil)
        let error = await TransportTestSupport.error { _ = try await stream.receive() }
        XCTAssertEqual(error as? MythaiaError, .protocolError("WebSocket closed (1011): "))
    }
}
