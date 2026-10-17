import Foundation
import XCTest
@testable import MythaiaKit

final class WebSocketFrameSizeTests: XCTestCase {

    private let upgrade = Data("HTTP/1.1 101 Switching Protocols\r\n\r\n".utf8)

    /// An unmasked binary frame header with the 64-bit length form.
    private func frameHeader(_ length: UInt64) -> [UInt8] {
        var header: [UInt8] = [0x82, 127]
        for i in 0..<8 {
            header.append(UInt8((length >> UInt64(56 - 8 * i)) & 0xFF))
        }
        return header
    }

    private func pieces(_ bytes: [UInt8], _ size: Int) -> [Data] {
        var out: [Data] = []
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + size, bytes.count)
            out.append(Data(bytes[offset..<end]))
            offset = end
        }
        return out
    }

    func testAFrameLargerThanAMegabyteIsReceivedWhole() async throws {
        let payload = (0..<(2 * 1024 * 1024)).map { UInt8(truncatingIfNeeded: $0) }
        let reads = [upgrade] + pieces(frameHeader(UInt64(payload.count)) + payload, 65_536)
        let ws = WebSocketConnection(inner: TransportScriptedStream(reads), settings: WebSocketConnection.Settings(host: "example.com"))
        try await ws.performUpgrade()
        let received = try await ws.receive()
        XCTAssertEqual(received, Data(payload))
    }

    func testAFrameDeclaringMoreThanTheMaximumIsRefusedAtOnce() async throws {
        let reads = [upgrade, Data(frameHeader(17 * 1024 * 1024))]
        let ws = WebSocketConnection(inner: TransportScriptedStream(reads), settings: WebSocketConnection.Settings(host: "example.com"))
        try await ws.performUpgrade()
        let error = await TransportTestSupport.error { _ = try await ws.receive() }
        guard case .some(.invalidFrame(_)) = error as? WebSocketError else {
            return XCTFail("expected an invalid frame, got \(String(describing: error))")
        }
    }

    /// RFC 6455 §5.7: a masked "Hello" from client to server.
    func testAMaskedFrameMatchesTheRFCExample() {
        let frame = WebSocketConnection.buildFrame(opcode: 0x01, payload: Array("Hello".utf8), maskKey: [0x37, 0xFA, 0x21, 0x3D])
        XCTAssertEqual([UInt8](frame), TransportTestSupport.bytes("81 85 37 fa 21 3d 7f 9f 4d 51 58"))
    }

    func testTheLengthTakesTheFormItsSizeNeeds() {
        let mask: [UInt8] = [0, 0, 0, 0]
        let medium = [UInt8](WebSocketConnection.buildFrame(opcode: 0x02, payload: [UInt8](repeating: 1, count: 126), maskKey: mask))
        XCTAssertEqual(Array(medium[0..<4]), [0x82, 0xFE, 0x00, 0x7E])
        XCTAssertEqual(medium.count, 4 + 4 + 126)

        let large = [UInt8](WebSocketConnection.buildFrame(opcode: 0x02, payload: [UInt8](repeating: 1, count: 65_536), maskKey: mask))
        XCTAssertEqual(Array(large[0..<10]), [0x82, 0xFF, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00])
        XCTAssertEqual(large.count, 10 + 4 + 65_536)
    }

    func testAMaskedServerFrameIsUnmasked() async throws {
        let frame = TransportTestSupport.hex("82 85 37 fa 21 3d 7f 9f 4d 51 58")
        let ws = WebSocketConnection(inner: TransportScriptedStream([upgrade, frame]), settings: WebSocketConnection.Settings(host: "example.com"))
        try await ws.performUpgrade()
        let received = try await ws.receive()
        XCTAssertEqual(received, Data("Hello".utf8))
    }

    func testAFragmentedMessageComesOutPieceByPiece() async throws {
        // "Hel" without FIN, then a continuation frame "lo" with it.
        let frames = TransportTestSupport.hex("02 03 48 65 6c 80 02 6c 6f")
        let ws = WebSocketConnection(inner: TransportScriptedStream([upgrade, frames]), settings: WebSocketConnection.Settings(host: "example.com"))
        try await ws.performUpgrade()
        var message = Data()
        while let piece = try await ws.receive() {
            message.append(piece)
        }
        XCTAssertEqual(message, Data("Hello".utf8))
    }
}
