import Foundation
import XCTest
@testable import MythaiaKit

final class TransportHTTPUpgradeTests: XCTestCase {

    private let switching = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

    func testTheRequestIsAWebSocketUpgradeAndTheBytesAfterThe101ComeFirst() async throws {
        let transport = TransportScriptedStream([Data((switching + "early").utf8), Data("later".utf8)])
        let configuration = HttpUpgradeConfiguration(host: "cdn.example.com", path: "/up", headers: ["X-Extra": "1"])
        let stream = try await HTTPUpgradeTransport.open(over: transport, configuration: configuration)

        let request = String(decoding: try XCTUnwrap(transport.sent.first), as: UTF8.self)
        XCTAssertTrue(request.hasPrefix("GET /up HTTP/1.1\r\nHost: cdn.example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Extra: 1\r\nUser-Agent: Mozilla/5.0 "), request)
        XCTAssertTrue(request.hasSuffix("\r\n\r\n"))

        let first = try await stream.receive()
        XCTAssertEqual(first, Data("early".utf8))
        let second = try await stream.receive()
        XCTAssertEqual(second, Data("later".utf8))
        let end = try await stream.receive()
        XCTAssertNil(end)

        // After the upgrade the bytes go through untouched, no framing.
        try await stream.send(Data("raw".utf8))
        XCTAssertEqual(transport.sent.last, Data("raw".utf8))
    }

    func testTheHeadersAreComparedWithoutCase() async throws {
        let response = "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\nCONNECTION: upgrade\r\n\r\n"
        let transport = TransportScriptedStream([Data(response.utf8)])
        _ = try await HTTPUpgradeTransport.open(over: transport, configuration: HttpUpgradeConfiguration(host: "h"))
    }

    func testA101WithoutTheUpgradeHeadersIsRefused() async throws {
        let transport = TransportScriptedStream([Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".utf8)])
        let error = await TransportTestSupport.error {
            _ = try await HTTPUpgradeTransport.open(over: transport, configuration: HttpUpgradeConfiguration(host: "h"))
        }
        XCTAssertEqual(error as? MythaiaError, .protocolError("HTTP upgrade failed: Missing Upgrade/Connection headers in 101 response"))
        XCTAssertTrue(transport.isClosed)
    }

    func testAnotherStatusIsRefused() async throws {
        let transport = TransportScriptedStream([Data("HTTP/1.1 404 Not Found\r\n\r\n".utf8)])
        let error = await TransportTestSupport.error {
            _ = try await HTTPUpgradeTransport.open(over: transport, configuration: HttpUpgradeConfiguration(host: "h"))
        }
        XCTAssertEqual(error as? MythaiaError, .protocolError("HTTP upgrade failed: Expected HTTP 101, got: HTTP/1.1 404 Not Found"))
    }

    func testAResponseHeadSplitOverReadsIsWaitedFor() async throws {
        let bytes = Array(switching.utf8)
        let transport = TransportScriptedStream([Data(bytes[0..<10]), Data(bytes[10..<40]), Data(bytes[40...])])
        let stream = try await HTTPUpgradeTransport.open(over: transport, configuration: HttpUpgradeConfiguration(host: "h"))
        let end = try await stream.receive()
        XCTAssertNil(end)
    }
}
