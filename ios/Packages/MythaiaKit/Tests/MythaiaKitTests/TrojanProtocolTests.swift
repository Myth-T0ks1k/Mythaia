import Foundation
import XCTest
@testable import MythaiaKit

/// Trojan's wire encoding.
///
/// The server compares the password hash byte for byte and falls back to its
/// decoy site on any mismatch, so a wrong byte anywhere here looks like a
/// working connection to an unrelated website rather than an error.
final class TrojanProtocolTests: XCTestCase {
    private func bytes(_ data: Data) -> [UInt8] { [UInt8](data) }

    // MARK: - passwordKey

    func testPasswordKeyIsSha224As56LowercaseHexBytes() {
        // SHA-224("pw"), computed by OpenSSL.
        let key = TrojanProtocol.passwordKey("pw")
        XCTAssertEqual(key.count, 56)
        XCTAssertEqual(String(decoding: key, as: UTF8.self), "bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd")
        // Lowercase specifically: an uppercase rendering is a different
        // string on the server side and silently lands on the decoy site.
        XCTAssertFalse(bytes(key).contains { $0 >= 0x41 && $0 <= 0x46 })
    }

    func testNonAsciiPasswordHashesItsUtf8Bytes() {
        let password = "пароль密碼"
        let key = TrojanProtocol.passwordKey(password)
        let expected = ProtocolTestStreams.hexString(DigestHelper.sha224(Data(password.utf8)))
        XCTAssertEqual(String(decoding: key, as: UTF8.self), expected)
    }

    // MARK: - encodeAddressPort

    func testIPv4DestinationEncodesAsType1AndFourBytes() {
        XCTAssertEqual(bytes(TrojanProtocol.encodeAddressPort(host: "93.184.216.34", port: 443)),
                       [0x01, 93, 184, 216, 34, 0x01, 0xBB])
    }

    func testIPv6DestinationEncodesAsType4AndSixteenBytes() {
        let encoded = bytes(TrojanProtocol.encodeAddressPort(host: "2001:db8::1", port: 8080))
        XCTAssertEqual(encoded.count, 1 + 16 + 2)
        XCTAssertEqual(encoded[0], 0x04)
        XCTAssertEqual(encoded[1], 0x20)
        XCTAssertEqual(encoded[2], 0x01)
        XCTAssertEqual(encoded[17], 0x1F) // 8080 = 0x1F90
        XCTAssertEqual(encoded[18], 0x90)
    }

    func testHostnameEncodesAsType3WithALengthPrefix() {
        let encoded = bytes(TrojanProtocol.encodeAddressPort(host: "example.com", port: 443))
        XCTAssertEqual(encoded[0], 0x03)
        XCTAssertEqual(Int(encoded[1]), 11)
        XCTAssertEqual(Array(encoded[2..<13]), Array("example.com".utf8))
        XCTAssertEqual(Array(encoded[13...]), [0x01, 0xBB])
    }

    func testLongNameIsTrimmedNotOverflowed() {
        let long = String(repeating: "a", count: 300) + ".example"
        let encoded = bytes(TrojanProtocol.encodeAddressPort(host: long, port: 443))
        XCTAssertEqual(encoded[0], 0x03)
        XCTAssertEqual(Int(encoded[1]), 255)
        XCTAssertEqual(encoded.count, 1 + 1 + 255 + 2)
    }

    func testPortIsBigEndianAcrossItsRange() {
        for port: UInt16 in [1, 80, 443, 8080, 32768, 65535] {
            let encoded = TrojanProtocol.encodeAddressPort(host: "example.com", port: port)
            XCTAssertEqual(ProtocolTestStreams.be16(encoded, encoded.count - 2), Int(port), "port \(port)")
        }
    }

    // MARK: - buildRequestHeader

    func testRequestHeaderIsHashCrlfCommandAddressCrlf() {
        let key = TrojanProtocol.passwordKey("pw")
        let header = bytes(TrojanProtocol.buildRequestHeader(passwordKey: key, command: TrojanProtocol.commandTCP, host: "example.com", port: 443))
        XCTAssertEqual(Array(header[0..<56]), bytes(key))
        XCTAssertEqual(header[56], 0x0D)
        XCTAssertEqual(header[57], 0x0A)
        XCTAssertEqual(header[58], TrojanProtocol.commandTCP)
        let address = bytes(TrojanProtocol.encodeAddressPort(host: "example.com", port: 443))
        XCTAssertEqual(Array(header[59..<(59 + address.count)]), address)
        XCTAssertEqual(header[59 + address.count], 0x0D)
        XCTAssertEqual(header[60 + address.count], 0x0A)
        XCTAssertEqual(header.count, 61 + address.count)
    }

    // MARK: - UDP framing

    func testUdpPacketLayoutAndRoundTrip() throws {
        let payload = Data((0..<200).map { UInt8($0) })
        let packet = try TrojanProtocol.encodeUDPPacket(host: "example.com", port: 53, payload: payload)
        let raw = bytes(packet)
        // address(1+1+11) + port(2) + length(2) + CRLF + payload
        XCTAssertEqual(raw[0], 0x03)
        XCTAssertEqual(ProtocolTestStreams.be16(packet, 13), 53)
        XCTAssertEqual(ProtocolTestStreams.be16(packet, 15), 200)
        XCTAssertEqual(Array(raw[17..<19]), [0x0D, 0x0A])
        XCTAssertEqual(Array(raw[19...]), bytes(payload))

        let decoded = try TrojanProtocol.tryDecodeUDPPacket(packet)
        XCTAssertEqual(decoded?.payload, payload)
        XCTAssertEqual(decoded?.consumed, packet.count)
    }

    func testShortBufferDecodesToNothingRatherThanGuessing() throws {
        let packet = bytes(try TrojanProtocol.encodeUDPPacket(host: "example.com", port: 53, payload: Data(count: 100)))
        for cut in 0..<packet.count {
            XCTAssertNil(try TrojanProtocol.tryDecodeUDPPacket(Data(packet[0..<cut])), "cut=\(cut)")
        }
        XCTAssertNotNil(try TrojanProtocol.tryDecodeUDPPacket(Data(packet)))
    }

    func testTwoPacketsInOneBufferAreConsumedOneAtATime() throws {
        let first = try TrojanProtocol.encodeUDPPacket(host: "a.example", port: 53, payload: Data(repeating: 1, count: 10))
        let second = try TrojanProtocol.encodeUDPPacket(host: "b.example", port: 53, payload: Data(repeating: 2, count: 20))
        var both = first
        both.append(second)

        let decoded = try XCTUnwrap(try TrojanProtocol.tryDecodeUDPPacket(both))
        XCTAssertEqual(decoded.consumed, first.count)
        XCTAssertEqual(decoded.payload, Data(repeating: 1, count: 10))

        let next = try XCTUnwrap(try TrojanProtocol.tryDecodeUDPPacket(Data(bytes(both)[decoded.consumed...])))
        XCTAssertEqual(next.payload, Data(repeating: 2, count: 20))
    }

    /// A truncated datagram is corrupt at the receiver; the caller must get
    /// to drop it whole, which it cannot if the encoder hides the loss.
    func testOversizedPayloadIsRefusedRatherThanCut() throws {
        XCTAssertThrowsError(try TrojanProtocol.encodeUDPPacket(host: "example.com", port: 53,
                                                                 payload: Data(count: TrojanProtocol.maxUdpPayloadLength + 500)))
        let packet = try TrojanProtocol.encodeUDPPacket(host: "example.com", port: 53, payload: Data(count: TrojanProtocol.maxUdpPayloadLength))
        XCTAssertEqual(try TrojanProtocol.tryDecodeUDPPacket(packet)?.payload.count, TrojanProtocol.maxUdpPayloadLength)
    }

    func testUnknownAddressTypeIsAnError() {
        XCTAssertThrowsError(try TrojanProtocol.tryDecodeUDPPacket(Data([0x09, 0, 0, 0, 0, 0, 0, 0])))
    }
}
