import Foundation
import XCTest
@testable import MythaiaKit

/// The TUIC v5 wire format, against the field widths its specification prints.
///
/// Every expected byte here is written out by hand from SPEC.md rather than
/// taken from the encoder, because an encoder and a decoder that were written
/// together agree with each other whether or not either agrees with a server.
final class TuicProtocolTests: XCTestCase {

    func testTheCommandAndAddressTypeNumbersAreTheOnesTheSpecAssigns() {
        XCTAssertEqual(TuicProtocol.version, 0x05)
        XCTAssertEqual(TuicProtocol.cmdAuthenticate, 0x00)
        XCTAssertEqual(TuicProtocol.cmdConnect, 0x01)
        XCTAssertEqual(TuicProtocol.cmdPacket, 0x02)
        XCTAssertEqual(TuicProtocol.cmdDissociate, 0x03)
        XCTAssertEqual(TuicProtocol.cmdHeartbeat, 0x04)

        XCTAssertEqual(TuicProtocol.addrNone, 0xFF)
        XCTAssertEqual(TuicProtocol.addrDomain, 0x00)
        XCTAssertEqual(TuicProtocol.addrIpv4, 0x01)
        XCTAssertEqual(TuicProtocol.addrIpv6, 0x02)
    }

    func testAuthenticateIsVersionTypeSixteenBytesOfUuidThenTheToken() throws {
        let uuid = try XCTUnwrap(UUID(uuidString: "01020304-0506-0708-090A-0B0C0D0E0F10"))
        let token = [UInt8](repeating: 0xAB, count: 32)
        let encoded = try TuicProtocol.authenticate(uuid: uuid, token: token)

        XCTAssertEqual(encoded.count, 2 + 16 + 32)
        XCTAssertEqual(encoded[0], 0x05)
        XCTAssertEqual(encoded[1], 0x00)
        // The UUID goes on the wire big-endian, most significant byte first.
        XCTAssertEqual(
            Array(encoded[2..<18]),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        )
        XCTAssertEqual(Array(encoded[18..<50]), token)
    }

    func testATokenOfTheWrongLengthIsRefusedRatherThanPadded() {
        XCTAssertThrowsError(try TuicProtocol.authenticate(uuid: UUID(), token: [UInt8](repeating: 0, count: 16)))
    }

    func testConnectCarriesTheAddressAndNothingElse() {
        let encoded = TuicProtocol.connect(host: "1.2.3.4", port: 443)
        XCTAssertEqual(encoded, [0x05, 0x01, 0x01, 1, 2, 3, 4, 0x01, 0xBB])
    }

    func testADomainAddressIsALengthByteThenTheNameThenThePort() {
        let encoded = TuicProtocol.connect(host: "example.com", port: 80)
        let expected: [UInt8] = [0x05, 0x01, 0x00, 11] + Array("example.com".utf8) + [0x00, 0x50]
        XCTAssertEqual(encoded, expected)
    }

    func testAnIpv6AddressTakesSixteenBytesUnderItsOwnType() {
        let encoded = TuicProtocol.connect(host: "2001:db8::1", port: 443)
        XCTAssertEqual(encoded.count, 2 + 1 + 16 + 2)
        XCTAssertEqual(encoded[2], 0x02)
        // 2001:0db8:0000:0000:0000:0000:0000:0001, then port 443.
        XCTAssertEqual(
            Array(encoded[3...]),
            [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
             0x01, 0xBB]
        )
        // Decoding spells every group out rather than compressing the zeros.
        let address = TuicProtocol.parseAddress(encoded, offset: 2)
        XCTAssertEqual(address, TuicProtocol.Address(host: "2001:db8:0:0:0:0:0:1", port: 443, size: 19))
    }

    func testAHostnameIsNeverResolvedWhileEncoding() {
        // Resolving a name here would perform a DNS lookup on whichever thread
        // happened to send a packet.
        let encoded = TuicProtocol.connect(host: "localhost", port: 80)
        XCTAssertEqual(encoded[2], TuicProtocol.addrDomain)
    }

    func testDissociateAndHeartbeatAreTheShortestCommandsThereAre() {
        XCTAssertEqual(TuicProtocol.dissociate(associationId: 0x1234), [0x05, 0x03, 0x12, 0x34])
        XCTAssertEqual(TuicProtocol.heartbeat(), [0x05, 0x04])
    }

    func testAPacketHeaderIsEightBytesInTheOrderTheSpecPrints() {
        let packet = TuicProtocol.Packet(
            associationId: 0x0102,
            packetId: 0x0304,
            fragmentTotal: 3,
            fragmentId: 0,
            host: "1.2.3.4",
            port: 53,
            payload: [9, 9]
        )
        let encoded = TuicProtocol.packet(packet)
        XCTAssertEqual(encoded.count, 19)
        guard encoded.count == 19 else { return }

        // ver type assoc(2) pkt(2) total(1) frag(1) size(2) then the address.
        XCTAssertEqual(Array(encoded[0..<10]), [0x05, 0x02, 0x01, 0x02, 0x03, 0x04, 0x03, 0x00, 0x00, 0x02])
        XCTAssertEqual(Array(encoded[10..<17]), [0x01, 1, 2, 3, 4, 0x00, 0x35])
        XCTAssertEqual(Array(encoded[17..<19]), [9, 9])
    }

    func testOnlyTheFirstFragmentCarriesAnAddress() {
        // Repeating it would waste room in every fragment of a datagram that
        // was split precisely because room was short.
        let later = TuicProtocol.packet(
            TuicProtocol.Packet(associationId: 1, packetId: 1, fragmentTotal: 3, fragmentId: 1,
                                host: "example.com", port: 53, payload: [7])
        )
        XCTAssertEqual(later.count, 2 + 8 + 1 + 1)
        guard later.count > 10 else { return }
        XCTAssertEqual(later[10], TuicProtocol.addrNone)
    }

    func testAPacketDecodesBackToWhatWasEncoded() {
        let original = TuicProtocol.Packet(
            associationId: 65535,
            packetId: 4242,
            fragmentTotal: 1,
            fragmentId: 0,
            host: "example.com",
            port: 5353,
            payload: (0..<100).map { UInt8($0) }
        )
        XCTAssertEqual(TuicProtocol.parsePacket(TuicProtocol.packet(original)), original)
    }

    func testALaterFragmentDecodesWithNoAddress() throws {
        let original = TuicProtocol.Packet(associationId: 1, packetId: 2, fragmentTotal: 4, fragmentId: 2,
                                           host: nil, port: 0, payload: [1, 2, 3])
        let decoded = try XCTUnwrap(TuicProtocol.parsePacket(TuicProtocol.packet(original)))
        XCTAssertNil(decoded.host)
        XCTAssertEqual(decoded.fragmentId, 2)
        XCTAssertEqual(decoded.payload, [1, 2, 3])
    }

    func testATruncatedOrWrongTypedPacketIsDroppedNotMisread() {
        // These arrive in unreliable datagrams, so a short one is ordinary.
        XCTAssertNil(TuicProtocol.parsePacket([]))
        XCTAssertNil(TuicProtocol.parsePacket([0x05, 0x02, 0x00]))
        // A size field claiming more payload than the datagram holds.
        XCTAssertNil(TuicProtocol.parsePacket([0x05, 0x02, 0, 1, 0, 1, 1, 0, 0xFF, 0xFF, 0xFF]))
        // Wrong version.
        XCTAssertNil(TuicProtocol.parsePacket([0x04, 0x02, 0, 1, 0, 1, 1, 0, 0, 0, 0xFF]))
        // Wrong command.
        XCTAssertNil(TuicProtocol.parsePacket([0x05, 0x01, 0, 1, 0, 1, 1, 0, 0, 0, 0xFF]))
    }

    func testAnAddressTypeTheSpecDoesNotDefineIsRefused() {
        XCTAssertNil(TuicProtocol.parseAddress([0x7F, 1, 2, 3, 4, 0, 80], offset: 0))
    }

    func testAnAddressThatRunsPastTheBufferIsRefused() {
        XCTAssertNil(TuicProtocol.parseAddress([0x01, 1, 2], offset: 0))
        XCTAssertNil(TuicProtocol.parseAddress([0x00, 20, 0x61], offset: 0))
        XCTAssertNil(TuicProtocol.parseAddress([], offset: 0))
    }

    func testANoneAddressOccupiesExactlyOneByte() throws {
        let address = try XCTUnwrap(TuicProtocol.parseAddress([0xFF], offset: 0))
        XCTAssertNil(address.host)
        XCTAssertEqual(address.size, 1)
    }
}
