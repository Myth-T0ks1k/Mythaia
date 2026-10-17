import Foundation
import XCTest
@testable import MythaiaKit

final class WebSocketHandshakeTests: XCTestCase {

    private let upgrade = Data("HTTP/1.1 101 Switching Protocols\r\n\r\n".utf8)

    /// RFC 6455 §1.3's worked example.
    func testTheAcceptValueMatchesTheRFCExample() {
        XCTAssertEqual(WebSocketConnection.acceptValue(forKey: "dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    }

    func testTheUpgradeRequestCarriesTheKeyHeadersAndADefaultUserAgent() async throws {
        let transport = TransportScriptedStream([upgrade])
        let settings = WebSocketConnection.Settings(host: "cdn.example.com", path: "/ws?ed=2048", headers: [("X-Extra", "1")])
        let ws = WebSocketConnection(inner: transport, settings: settings)
        try await ws.performUpgrade()

        let request = String(decoding: try XCTUnwrap(transport.sent.first), as: UTF8.self)
        XCTAssertTrue(request.hasPrefix("GET /ws?ed=2048 HTTP/1.1\r\nHost: cdn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"))
        XCTAssertTrue(request.contains("\r\nSec-WebSocket-Version: 13\r\n"))
        XCTAssertTrue(request.contains("\r\nX-Extra: 1\r\n"))
        XCTAssertTrue(request.contains("\r\nUser-Agent: Mozilla/5.0 "))
        XCTAssertTrue(request.hasSuffix("\r\n\r\n"))

        let keyLine = try XCTUnwrap(request.components(separatedBy: "\r\n").first { $0.hasPrefix("Sec-WebSocket-Key: ") })
        let key = String(keyLine.dropFirst("Sec-WebSocket-Key: ".count))
        XCTAssertEqual(Data(base64Encoded: key)?.count, 16)
    }

    func testAConfiguredUserAgentReplacesTheDefault() async throws {
        let transport = TransportScriptedStream([upgrade])
        let settings = WebSocketConnection.Settings(host: "h", headers: [("user-agent", "custom")])
        try await WebSocketConnection(inner: transport, settings: settings).performUpgrade()
        let request = String(decoding: try XCTUnwrap(transport.sent.first), as: UTF8.self)
        XCTAssertTrue(request.contains("\r\nuser-agent: custom\r\n"))
        XCTAssertFalse(request.contains("Mozilla"))
    }

    func testEarlyDataRidesInTheHeaderAndTheRestFollowsAsAFrame() async throws {
        let transport = TransportScriptedStream([upgrade])
        let configuration = WebSocketConfiguration(host: "h", maxEarlyData: 2)
        _ = try await WebSocketTransport.open(over: transport, configuration: configuration, earlyData: Data([0xFB, 0xFF, 0x01]))

        let sent = transport.sent
        XCTAssertEqual(sent.count, 2)
        let request = String(decoding: sent[0], as: UTF8.self)
        // FB FF is "+/8=" in standard base64; base64url without padding is "-_8".
        XCTAssertTrue(request.contains("\r\nSec-WebSocket-Protocol: -_8\r\n"), request)

        let frame = [UInt8](sent[1])
        XCTAssertEqual(frame[0], 0x82)
        XCTAssertEqual(frame[1], 0x81)
        XCTAssertEqual(frame[6] ^ frame[2], 0x01)
    }

    func testAResponseOtherThan101FailsTheUpgrade() async throws {
        let transport = TransportScriptedStream([Data("HTTP/1.1 403 Forbidden\r\n\r\n".utf8)])
        let ws = WebSocketConnection(inner: transport, settings: WebSocketConnection.Settings(host: "h"))
        let error = await TransportTestSupport.error { _ = try await ws.performUpgrade() }
        XCTAssertEqual(error as? WebSocketError, .upgradeFailed("Expected HTTP 101, got: HTTP/1.1 403 Forbidden"))
    }

    func testAWrongAcceptValueFailsTheUpgrade() async throws {
        let response = Data("HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: bogus\r\n\r\n".utf8)
        let ws = WebSocketConnection(inner: TransportScriptedStream([response]), settings: WebSocketConnection.Settings(host: "h"))
        let error = await TransportTestSupport.error { _ = try await ws.performUpgrade() }
        XCTAssertEqual(error as? WebSocketError, .upgradeFailed("Sec-WebSocket-Accept does not match the key"))
    }

    func testTheOpenFailureClosesTheStreamBelow() async throws {
        let transport = TransportScriptedStream([])
        let error = await TransportTestSupport.error {
            _ = try await WebSocketTransport.open(over: transport, configuration: WebSocketConfiguration(host: "h"), earlyData: nil)
        }
        XCTAssertEqual(error as? MythaiaError, .protocolError("WebSocket upgrade failed: Empty response from server"))
        XCTAssertTrue(transport.isClosed)
    }

    func testBytesAfterTheResponseHeadAreTheFirstFrame() async throws {
        var response = [UInt8](upgrade)
        response.append(contentsOf: [0x82, 0x02, 0x68, 0x69])
        let ws = WebSocketConnection(inner: TransportScriptedStream([Data(response)]), settings: WebSocketConnection.Settings(host: "h"))
        try await ws.performUpgrade()
        let data = try await ws.receive()
        XCTAssertEqual(data, Data("hi".utf8))
    }

    func testAPingIsAnsweredWithItsPayload() async throws {
        let frames = TransportTestSupport.hex("89 02 61 62 82 01 78")
        let transport = TransportScriptedStream([upgrade, frames])
        let ws = WebSocketConnection(inner: transport, settings: WebSocketConnection.Settings(host: "h"))
        try await ws.performUpgrade()
        let data = try await ws.receive()
        XCTAssertEqual(data, Data("x".utf8))

        let pong = [UInt8](try XCTUnwrap(transport.sent.last))
        XCTAssertEqual(pong[0], 0x8A)
        XCTAssertEqual(pong[1], 0x82)
        XCTAssertEqual([pong[6] ^ pong[2], pong[7] ^ pong[3]], Array("ab".utf8))
    }
}
