import Foundation
import XCTest
@testable import MythaiaKit

/// The VLESS request header — the app's primary protocol.
///
/// Every field is fixed width and there is no length prefix on the header as
/// a whole, so the server reads it positionally: a byte in the wrong place
/// shifts everything after it and the connection fails in a way that looks
/// like a network problem.
final class VlessProtocolTests: XCTestCase {
    private let uuid = UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811")!

    private func bytes(_ data: Data) -> [UInt8] { [UInt8](data) }

    // MARK: - uuidToBytes

    func testUuidBecomesItsSixteenBigEndianBytes() {
        let raw = bytes(VlessProtocol.uuidToBytes(uuid))
        XCTAssertEqual(raw.count, 16)
        XCTAssertEqual(raw[0], 0xB8)
        XCTAssertEqual(raw[1], 0x31)
        XCTAssertEqual(raw[2], 0x38)
        XCTAssertEqual(raw[3], 0x1D)
        XCTAssertEqual(raw[15], 0x11)
        // Independently: the canonical text without dashes is their hex.
        XCTAssertEqual(
            ProtocolTestStreams.hexString(Data(raw)),
            uuid.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        )
    }

    func testAllZeroAndAllOnesUuids() {
        XCTAssertEqual(VlessProtocol.uuidToBytes(UUID(uuidString: "00000000-0000-0000-0000-000000000000")!), Data(count: 16))
        XCTAssertEqual(
            VlessProtocol.uuidToBytes(UUID(uuidString: "ffffffff-ffff-ffff-ffff-ffffffffffff")!),
            Data(repeating: 0xFF, count: 16)
        )
    }

    // MARK: - Request header

    func testTcpRequestToAHostnameHasTheDocumentedLayout() {
        let header = bytes(VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "example.com", destinationPort: 443))
        var at = 0
        XCTAssertEqual(header[at], 0x00); at += 1                      // version
        XCTAssertEqual(Array(header[at..<(at + 16)]), bytes(VlessProtocol.uuidToBytes(uuid))); at += 16
        XCTAssertEqual(header[at], 0); at += 1                         // no addons
        XCTAssertEqual(header[at], VlessCommand.tcp.rawValue); at += 1
        // Port is big-endian.
        XCTAssertEqual(header[at], 0x01); at += 1
        XCTAssertEqual(header[at], 0xBB); at += 1
        XCTAssertEqual(header[at], VlessAddressType.domain.rawValue); at += 1
        XCTAssertEqual(Int(header[at]), "example.com".utf8.count); at += 1
        XCTAssertEqual(Array(header[at..<(at + 11)]), Array("example.com".utf8)); at += 11
        XCTAssertEqual(header.count, at)
    }

    func testIPv4DestinationUsesTheAddressForm() {
        let header = bytes(VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "93.184.216.34", destinationPort: 80))
        let typeAt = 1 + 16 + 1 + 1 + 2
        XCTAssertEqual(header[typeAt], VlessAddressType.ipv4.rawValue)
        XCTAssertEqual(Array(header[(typeAt + 1)..<(typeAt + 5)]), [93, 184, 216, 34])
        XCTAssertEqual(header.count, typeAt + 5)
    }

    func testIPv6DestinationUsesSixteenBytes() {
        let header = bytes(VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "2001:db8::1", destinationPort: 443))
        let typeAt = 1 + 16 + 1 + 1 + 2
        XCTAssertEqual(header[typeAt], VlessAddressType.ipv6.rawValue)
        XCTAssertEqual(header[typeAt + 1], 0x20)
        XCTAssertEqual(header[typeAt + 2], 0x01)
        XCTAssertEqual(header[typeAt + 16], 0x01)
        XCTAssertEqual(header.count, typeAt + 17)
    }

    func testPortIsBigEndianAcrossItsRange() {
        for port: UInt16 in [1, 80, 443, 8080, 32768, 65535] {
            let header = VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "93.184.216.34", destinationPort: port)
            XCTAssertEqual(ProtocolTestStreams.be16(header, 1 + 16 + 1 + 1), Int(port), "port \(port)")
        }
    }

    /// A mux session multiplexes many destinations, so the header stops
    /// after the command; an address would shift every later field.
    func testMuxCommandCarriesNoDestination() {
        let header = bytes(VlessProtocol.encodeRequestHeader(uuid: uuid, command: .mux, destinationAddress: "example.com", destinationPort: 443))
        XCTAssertEqual(header.count, 1 + 16 + 1 + 1)
        XCTAssertEqual(header[header.count - 1], VlessCommand.mux.rawValue)
    }

    func testFlowIsALengthDelimitedProtobufField() {
        let flow = "xtls-rprx-vision"
        let header = bytes(VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "example.com", destinationPort: 443, flow: flow))
        let addonsLengthAt = 1 + 16
        let addonsLength = Int(header[addonsLengthAt])
        XCTAssertEqual(addonsLength, 2 + flow.utf8.count)
        // Field 1, wire type 2, then the length, then the text.
        XCTAssertEqual(header[addonsLengthAt + 1], 0x0A)
        XCTAssertEqual(Int(header[addonsLengthAt + 2]), flow.utf8.count)
        XCTAssertEqual(Array(header[(addonsLengthAt + 3)..<(addonsLengthAt + 3 + flow.utf8.count)]), Array(flow.utf8))
        XCTAssertEqual(header[addonsLengthAt + 1 + addonsLength], VlessCommand.tcp.rawValue)
    }

    func testNoFlowMeansAZeroAddonsLength() {
        let withoutFlow = VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "example.com", destinationPort: 443, flow: nil)
        let withEmptyFlow = VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "example.com", destinationPort: 443, flow: "")
        XCTAssertEqual(withoutFlow, withEmptyFlow)
        XCTAssertEqual(bytes(withoutFlow)[1 + 16], 0)
    }

    // MARK: - Response header

    func testResponseHeaderReportsTheBytesItConsumed() {
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([0, 0, 1, 2, 3])), 2)
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([0, 3, 9, 9, 9, 1, 2])), 5)
    }

    func testIncompleteResponseHeaderConsumesNothing() {
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data()), 0)
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([0])), 0)
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([0, 5, 1, 2])), 0)
    }

    func testResponseOfAnotherVersionConsumesNothing() {
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([1, 0])), 0)
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(Data([0xFF, 0])), 0)
    }

    func testOffsetIsHonoured() {
        let buffer = Data([9, 9, 0, 0, 1, 2])
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(buffer, offset: 2), 2)
        XCTAssertEqual(VlessProtocol.decodeResponseHeader(buffer, offset: 5), 0)
    }

    func testCommandAndAddressTypeValuesMatchTheWire() {
        XCTAssertEqual(VlessCommand.tcp.rawValue, 1)
        XCTAssertEqual(VlessCommand.udp.rawValue, 2)
        XCTAssertEqual(VlessCommand.mux.rawValue, 3)
        XCTAssertEqual(VlessAddressType.ipv4.rawValue, 1)
        XCTAssertEqual(VlessAddressType.domain.rawValue, 2)
        XCTAssertEqual(VlessAddressType.ipv6.rawValue, 3)
        for command in VlessCommand.allCases {
            XCTAssertEqual(VlessCommand.fromByte(command.rawValue), command)
        }
        XCTAssertNil(VlessCommand.fromByte(9))
        XCTAssertNil(VlessAddressType.fromByte(9))
    }

    // MARK: - Response header stripping on the stream

    /// The header arrives split across reads (WebSocket, XHTTP and HTTP/2
    /// deliver it so); the first payload byte must still be the first byte
    /// the caller sees, and a read holding only header must not look like
    /// the end of the stream.
    func testFragmentedResponseHeaderIsStrippedAcrossReads() async throws {
        let inner = ProtocolTestStreams.Scripted(reads: [
            Data([0x00]),
            Data([0x02, 0xAA]),
            Data([0xBB]),
            Data([0x41, 0x42]),
            Data([0x43]),
        ])
        let connection = VlessConnection(inner)
        let first = try await connection.receive()
        XCTAssertEqual(first, Data([0x41, 0x42]))
        let second = try await connection.receive()
        XCTAssertEqual(second, Data([0x43]))
        let end = try await connection.receive()
        XCTAssertNil(end)
    }

    func testPayloadInTheSameReadAsTheHeaderIsKept() async throws {
        let inner = ProtocolTestStreams.Scripted(reads: [Data([0x00, 0x00, 0x48, 0x49])])
        let connection = VlessConnection(inner)
        let first = try await connection.receive()
        XCTAssertEqual(first, Data([0x48, 0x49]))
    }

    func testSendsPassThroughUnchanged() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let connection = VlessConnection(inner)
        try await connection.send(Data([1, 2, 3]))
        XCTAssertEqual(inner.writes, [Data([1, 2, 3])])
    }
}
