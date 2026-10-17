import Foundation
import XCTest
@testable import MythaiaKit

/// What a Trojan connection puts on the wire, write by write.
///
/// The request header is the only thing that tells the server where to
/// connect, and it rides the first write. A flow whose server speaks first
/// (SSH, SMTP, IMAP) never produces a first write of its own, so the dialer
/// flushes the header with an empty payload — and that write has to be the
/// header exactly, nothing more and nothing less.
final class TrojanConnectionTests: XCTestCase {
    private func expectedHeader(command: UInt8, host: String, port: UInt16) -> Data {
        // Built from its parts, the hash computed independently.
        var out = Data("bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd".utf8) // hex(SHA-224("pw"))
        out.append(contentsOf: [0x0D, 0x0A, command])
        out.append(contentsOf: [0x03, UInt8(host.utf8.count)])
        out.append(contentsOf: Array(host.utf8))
        out.append(contentsOf: [UInt8(port >> 8), UInt8(port & 0xFF), 0x0D, 0x0A])
        return out
    }

    func testEmptyFirstWriteCarriesExactlyTheRequestHeader() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let connection = TrojanConnection(inner, password: "pw", destinationHost: "example.com", destinationPort: 443)

        try await connection.send(Data())
        XCTAssertEqual(inner.writes, [expectedHeader(command: 0x01, host: "example.com", port: 443)])

        // The header is spent: the next write is the payload alone.
        try await connection.send(Data("hello".utf8))
        XCTAssertEqual(inner.writes.count, 2)
        XCTAssertEqual(inner.writes[1], Data("hello".utf8))
    }

    func testFirstWriteWithDataPutsHeaderAndDataInOneWrite() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let connection = TrojanConnection(inner, password: "pw", destinationHost: "example.com", destinationPort: 443)

        try await connection.send(Data("GET / HTTP/1.1\r\n".utf8))

        var expected = expectedHeader(command: 0x01, host: "example.com", port: 443)
        expected.append(Data("GET / HTTP/1.1\r\n".utf8))
        XCTAssertEqual(inner.writes, [expected])
    }

    func testRepliesPassThroughUnframed() async throws {
        let inner = ProtocolTestStreams.Scripted(reads: [Data("HTTP/1.1 200 OK".utf8)])
        let connection = TrojanConnection(inner, password: "pw", destinationHost: "example.com", destinationPort: 80)
        let reply = try await connection.receive()
        XCTAssertEqual(reply, Data("HTTP/1.1 200 OK".utf8))
        let end = try await connection.receive()
        XCTAssertNil(end)
    }

    func testOversizedDatagramIsDroppedNotTruncatedAndNotFatal() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let connection = TrojanUdpConnection(inner, password: "pw", destinationHost: "example.com", destinationPort: 53)

        try await connection.send(Data(count: TrojanProtocol.maxUdpPayloadLength + 1))
        XCTAssertEqual(inner.writes.count, 0, "nothing goes out for a datagram the framing cannot carry")

        // The association is still usable, and the request header still goes
        // out with the first datagram that is actually sent.
        try await connection.send(Data(repeating: 7, count: 10))
        XCTAssertEqual(inner.writes.count, 1)
        var expected = expectedHeader(command: 0x03, host: "example.com", port: 53)
        expected.append(contentsOf: [0x03, 11])
        expected.append(contentsOf: Array("example.com".utf8))
        expected.append(contentsOf: [0x00, 53, 0x00, 10, 0x0D, 0x0A])
        expected.append(Data(repeating: 7, count: 10))
        XCTAssertEqual(inner.writes[0], expected)

        // Later datagrams carry no request header.
        try await connection.send(Data([1]))
        XCTAssertEqual(inner.writes[1], try TrojanProtocol.encodeUDPPacket(host: "example.com", port: 53, payload: Data([1])))
    }

    func testUdpRepliesAreSplitIntoDatagrams() async throws {
        let one = try TrojanProtocol.encodeUDPPacket(host: "1.1.1.1", port: 53, payload: Data([0xAA]))
        let two = try TrojanProtocol.encodeUDPPacket(host: "1.1.1.1", port: 53, payload: Data([0xBB, 0xCC]))
        var both = one
        both.append(two)
        let raw = [UInt8](both)
        let inner = ProtocolTestStreams.Scripted(reads: [Data(raw[0..<3]), Data(raw[3...])])
        let connection = TrojanUdpConnection(inner, password: "pw", destinationHost: "1.1.1.1", destinationPort: 53)
        let first = try await connection.receive()
        XCTAssertEqual(first, Data([0xAA]))
        let second = try await connection.receive()
        XCTAssertEqual(second, Data([0xBB, 0xCC]))
    }
}
