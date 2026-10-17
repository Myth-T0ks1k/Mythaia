import Foundation
import XCTest
@testable import MythaiaKit

/// The expectations here are written out from the Hysteria 2 specification and
/// from the reference implementation's own constants, byte by byte, rather than
/// captured from this encoder. A codec compared only against itself agrees with
/// its own mistakes, and the wire format is the whole contract with the server.
final class HysteriaProtocolTests: XCTestCase {

    /// Builds a buffer from literal bytes, UTF-8 text and other buffers.
    private func wire(_ parts: Any...) -> [UInt8] {
        var out: [UInt8] = []
        for part in parts {
            switch part {
            case let byte as Int:
                out.append(UInt8(truncatingIfNeeded: byte))
            case let text as String:
                out.append(contentsOf: Array(text.utf8))
            case let bytes as [UInt8]:
                out.append(contentsOf: bytes)
            default:
                XCTFail("unsupported part: \(part)")
            }
        }
        return out
    }

    private func isAsciiLetterOrDigit(_ byte: UInt8) -> Bool {
        return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
    }

    /// "münchen.example:80", spelled with an escape so the byte count does not
    /// depend on how this file was normalised.
    private let munich = "m\u{00FC}nchen.example:80"

    // MARK: - Constants

    func testTheProtocolsNumbersAreTheOnesTheSpecificationNames() {
        XCTAssertEqual(HysteriaProtocol.tcpRequestFrameType, 0x401)
        XCTAssertEqual(HysteriaProtocol.closeErrCodeOk, 0x100)
        XCTAssertEqual(HysteriaProtocol.closeErrCodeProtocolError, 0x101)
        XCTAssertEqual(HysteriaProtocol.tcpResponseStatusOk, 0)
        XCTAssertEqual(HysteriaProtocol.authSuccessStatus, 233)

        XCTAssertEqual(HysteriaProtocol.authAuthority, "hysteria")
        XCTAssertEqual(HysteriaProtocol.authPath, "/auth")
        XCTAssertEqual(HysteriaProtocol.headerStatus, ":status")
        XCTAssertEqual(HysteriaProtocol.headerAuth, "hysteria-auth")
        XCTAssertEqual(HysteriaProtocol.headerCcRx, "hysteria-cc-rx")
        XCTAssertEqual(HysteriaProtocol.headerPadding, "hysteria-padding")
        XCTAssertEqual(HysteriaProtocol.headerUdp, "hysteria-udp")
        XCTAssertEqual(HysteriaProtocol.headerContentLength, "content-length")
        XCTAssertEqual(HysteriaProtocol.ccRxAuto, "auto")

        XCTAssertEqual(HysteriaProtocol.authPaddingRange, 256...2047)
        XCTAssertEqual(HysteriaProtocol.tcpRequestPaddingRange, 64...511)

        XCTAssertEqual(HysteriaProtocol.maxAddressLength, 2048)
        XCTAssertEqual(HysteriaProtocol.maxResponseMessageLength, 2048)
        XCTAssertEqual(HysteriaProtocol.maxPaddingLength, 4096)

        XCTAssertEqual(HysteriaProtocol.udpHeaderFixedSize, 8)
        XCTAssertEqual(HysteriaProtocol.maxFragments, 255)
    }

    func testTheTcpRequestFrameTypeIsTwoBytesOnTheWire() {
        // 0x401 as a QUIC varint (RFC 9000 §16): the two-byte form, prefix 0b01
        // over the value, so 0x0401 becomes 0x4401.
        XCTAssertEqual(try QuicVarInt.encode(HysteriaProtocol.tcpRequestFrameType), [0x44, 0x01])
    }

    // MARK: - Addresses

    func testAnAddressIsHostColonPortWithIpv6InBrackets() {
        // RFC 3986 §3.2.2: an IPv6 literal is bracketed so its colons cannot be
        // read as the port separator.
        XCTAssertEqual(HysteriaProtocol.formatAddress(host: "1.2.3.4", port: 443), "1.2.3.4:443")
        XCTAssertEqual(HysteriaProtocol.formatAddress(host: "example.com", port: 80), "example.com:80")
        XCTAssertEqual(HysteriaProtocol.formatAddress(host: "2001:db8::1", port: 8443), "[2001:db8::1]:8443")
        XCTAssertEqual(HysteriaProtocol.formatAddress(host: "::1", port: 53), "[::1]:53")
        XCTAssertEqual(HysteriaProtocol.formatAddress(host: "fe80::1%eth0", port: 9), "[fe80::1%eth0]:9")
    }

    func testEveryAddressFormSurvivesADatagramRoundTrip() throws {
        let addresses = [
            HysteriaProtocol.formatAddress(host: "1.2.3.4", port: 443),
            HysteriaProtocol.formatAddress(host: "255.255.255.255", port: 65535),
            HysteriaProtocol.formatAddress(host: "2001:db8::1", port: 8443),
            HysteriaProtocol.formatAddress(host: "::1", port: 53),
            HysteriaProtocol.formatAddress(host: "example.com", port: 80),
            HysteriaProtocol.formatAddress(host: String(repeating: "a-very-long-subdomain.", count: 8) + "example.com", port: 1),
            munich,
        ]
        for address in addresses {
            let message = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: 1, fragId: 0, fragCount: 1,
                                                          address: address, payload: [0x01])
            let decoded = HysteriaProtocol.decodeUdpMessage(message.encode())
            XCTAssertEqual(decoded?.address, address)
        }
    }

    func testTheAddressLengthCountsBytesNotCharacters() throws {
        // "münchen.example:80" is 18 characters but 19 bytes in UTF-8.
        let address = munich
        XCTAssertEqual(address.count, 18)
        XCTAssertEqual(address.utf8.count, 19)

        let encoded = try HysteriaProtocol.UdpMessage(sessionId: 0, packetId: 0, fragId: 0, fragCount: 1,
                                                      address: address, payload: [0xFF]).encode()
        XCTAssertEqual(encoded[HysteriaProtocol.udpHeaderFixedSize], 19)
        XCTAssertEqual(HysteriaProtocol.decodeUdpMessage(encoded)?.address, address)
    }

    // MARK: - TCP framing

    func testATcpRequestIsTheFrameTypeTheAddressAndThePadding() {
        // varint(0x401) | varint(15) | "example.com:443" | varint(4) | "PAD!"
        let expected = wire(0x44, 0x01, 0x0F, "example.com:443", 0x04, "PAD!")
        let actual = HysteriaProtocol.encodeTcpRequest(address: "example.com:443", padding: Array("PAD!".utf8))
        XCTAssertEqual(actual, expected)
    }

    func testATcpRequestWithNoPaddingStillCarriesAZeroLength() {
        // The padding length field is not optional, so an unpadded request is
        // six bytes of prefix and a lone zero.
        let expected = wire(0x44, 0x01, 0x03, "a:1", 0x00)
        XCTAssertEqual(HysteriaProtocol.encodeTcpRequest(address: "a:1", padding: []), expected)
    }

    func testALongAddressUsesTheTwoByteLengthForm() {
        let host = String(repeating: "h", count: 200)
        let address = "\(host):443" // 204 bytes
        XCTAssertEqual(address.utf8.count, 204)
        // 204 needs the two-byte varint form: 0x40 | (204 >> 8) = 0x40, then 204.
        let expected = wire(0x44, 0x01, 0x40, 0xCC, address, 0x00)
        XCTAssertEqual(HysteriaProtocol.encodeTcpRequest(address: address, padding: []), expected)
    }

    func testTheDefaultTcpRequestPaddingStaysInsideTheReferencesRange() throws {
        for _ in 0..<50 {
            let request = HysteriaProtocol.encodeTcpRequest(address: "a:1")
            // 2 (frame type) + 1 (address length) + 3 (address) = 6 bytes of prefix.
            let padLength = try XCTUnwrap(QuicVarInt.decode(request, 6), "no padding length in the request")
            XCTAssertTrue(HysteriaProtocol.tcpRequestPaddingRange.contains(Int(padLength.value)),
                          "padding length \(padLength.value)")
            XCTAssertEqual(request.count, 6 + padLength.size + Int(padLength.value))
        }
    }

    func testATcpResponseIsAStatusAMessageAndPadding() throws {
        let buffer = wire(0x00, 0x02, "hi", 0x03, "xyz")
        let response = HysteriaProtocol.parseTcpResponse(buffer)
        XCTAssertEqual(response, HysteriaProtocol.TcpResponse(status: 0, message: "hi", consumed: 8))
        XCTAssertTrue(try XCTUnwrap(response).isOk)
    }

    func testANonZeroStatusIsARefusalThatStillCarriesItsMessage() throws {
        let buffer = wire(0x01, 0x0C, "no such host", 0x00)
        let response = HysteriaProtocol.parseTcpResponse(buffer)
        XCTAssertEqual(response, HysteriaProtocol.TcpResponse(status: 1, message: "no such host", consumed: 15))
        XCTAssertFalse(try XCTUnwrap(response).isOk)
    }

    func testTheConsumedCountStopsAtTheEndOfTheResponse() throws {
        let payload = "proxied bytes"
        let buffer = wire(0x00, 0x00, 0x02, "ab", payload)
        let response = try XCTUnwrap(HysteriaProtocol.parseTcpResponse(buffer))
        XCTAssertEqual(response.consumed, 5)
        XCTAssertEqual(response.message, "")
        XCTAssertEqual(Array(buffer[response.consumed...]), Array(payload.utf8))
    }

    func testATcpResponseIsNotParsedUntilEveryFieldHasArrived() {
        let whole = wire(0x00, 0x02, "hi", 0x03, "xyz")
        for length in 0..<whole.count {
            XCTAssertNil(HysteriaProtocol.parseTcpResponse(Array(whole[0..<length])),
                         "prefix of \(length) bytes must not parse")
        }
        XCTAssertNotNil(HysteriaProtocol.parseTcpResponse(whole))
    }

    func testATcpResponseRefusesLengthsPastTheReferencesLimits() {
        // 2049 > maxResponseMessageLength; two-byte varint 0x48 0x01.
        XCTAssertNil(HysteriaProtocol.parseTcpResponse(wire(0x00, 0x48, 0x01)))
        // 4097 > maxPaddingLength; two-byte varint 0x50 0x01.
        XCTAssertNil(HysteriaProtocol.parseTcpResponse(wire(0x00, 0x00, 0x50, 0x01)))
    }

    func testAMessageOfExactlyTheMaximumLengthIsStillAccepted() throws {
        let message = String(repeating: "m", count: HysteriaProtocol.maxResponseMessageLength)
        // 2048 as a two-byte varint: 0x40 | (2048 >> 8) = 0x48, then 0x00.
        let buffer = wire(0x00, 0x48, 0x00, message, 0x00)
        let response = try XCTUnwrap(HysteriaProtocol.parseTcpResponse(buffer))
        XCTAssertEqual(response.message, message)
        XCTAssertEqual(response.consumed, buffer.count)
    }

    // MARK: - UDP datagram framing

    func testADatagramIsTheFixedHeaderTheAddressAndThePayload() throws {
        // sessionId(4) | packetId(2) | fragId(1) | fragCount(1) |
        // varint(addrLen) | addr | payload
        let expected = wire(
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06,
            0x01,
            0x03,
            0x0A, "1.2.3.4:53",
            0xDE, 0xAD, 0xBE, 0xEF
        )
        let message = try HysteriaProtocol.UdpMessage(
            sessionId: 0x0102_0304,
            packetId: 0x0506,
            fragId: 1,
            fragCount: 3,
            address: "1.2.3.4:53",
            payload: [0xDE, 0xAD, 0xBE, 0xEF]
        )
        XCTAssertEqual(message.encode(), expected)
        XCTAssertEqual(HysteriaProtocol.decodeUdpMessage(expected), message)
    }

    func testTheHeaderFieldsAreBigEndianAtTheirSpecOffsets() throws {
        let encoded = try HysteriaProtocol.UdpMessage(
            sessionId: 0xDEAD_BEEF,
            packetId: 0xBEEF,
            fragId: 0x7F,
            fragCount: 0x80,
            address: "a:1",
            payload: [0x00]
        ).encode()
        XCTAssertEqual(Array(encoded[0..<4]), [0xDE, 0xAD, 0xBE, 0xEF])
        XCTAssertEqual(Array(encoded[4..<6]), [0xBE, 0xEF])
        XCTAssertEqual(encoded[6], 0x7F)
        XCTAssertEqual(encoded[7], 0x80)
    }

    func testTheUnsignedEdgesOfTheHeaderRoundTripWithoutGoingNegative() throws {
        let message = try HysteriaProtocol.UdpMessage(
            sessionId: 0xFFFF_FFFF,
            packetId: 0xFFFF,
            fragId: 254,
            fragCount: 255,
            address: "[::1]:65535",
            payload: [0x7F, 0x80]
        )
        let decoded = try XCTUnwrap(HysteriaProtocol.decodeUdpMessage(message.encode()))
        XCTAssertEqual(decoded.sessionId, 0xFFFF_FFFF)
        XCTAssertEqual(decoded.packetId, 0xFFFF)
        XCTAssertEqual(decoded.fragId, 254)
        XCTAssertEqual(decoded.fragCount, 255)
        XCTAssertEqual(decoded, message)
    }

    func testAnOutOfRangeHeaderFieldIsRefusedRatherThanTruncated() {
        for sessionId: Int64 in [-1, 0x1_0000_0000] {
            XCTAssertThrowsError(try HysteriaProtocol.UdpMessage(sessionId: sessionId, packetId: 0, fragId: 0, fragCount: 1,
                                                                 address: "a:1", payload: [0x00]),
                                 "session id \(sessionId)")
        }
        XCTAssertThrowsError(try HysteriaProtocol.UdpMessage(sessionId: 0, packetId: 0x1_0000, fragId: 0, fragCount: 1,
                                                             address: "a:1", payload: [0x00]))
        XCTAssertThrowsError(try HysteriaProtocol.UdpMessage(sessionId: 0, packetId: 0, fragId: 256, fragCount: 1,
                                                             address: "a:1", payload: [0x00]))
        XCTAssertThrowsError(try HysteriaProtocol.UdpMessage(sessionId: 0, packetId: 0, fragId: 0, fragCount: 256,
                                                             address: "a:1", payload: [0x00]))
    }

    func testATruncatedDatagramIsRejectedRatherThanMisparsed() {
        let whole = wire(0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x03, "a:1", 0xAA)
        XCTAssertNotNil(HysteriaProtocol.decodeUdpMessage(whole))
        for length in 0..<whole.count {
            XCTAssertNil(HysteriaProtocol.decodeUdpMessage(Array(whole[0..<length])),
                         "prefix of \(length) bytes must not parse")
        }
    }

    func testADatagramWhoseAddressLengthOverrunsTheBufferIsRejected() {
        // A two-byte varint saying 200 (0x40 0xC8), with three address bytes.
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x40, 0xC8, "a:1", 0xAA)))
        // An eight-byte length varint that the datagram is too short to hold.
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0xC0, 0x00, 0x00)))
    }

    func testADatagramWithNoPayloadAfterTheAddressIsRejected() {
        // The address ends exactly at the end of the datagram, so there is
        // nothing to forward; a stream of these would otherwise take a
        // reassembly slot each.
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, "a:1")))
        // One payload byte is enough.
        XCTAssertNotNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, "a:1", 0x00)))
    }

    func testADatagramWithAnEmptyOrOversizedAddressIsRejected() {
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x00, 0xAA)))
        // 2049 > maxAddressLength; two-byte varint 0x48 0x01.
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x48, 0x01, 0xAA)))
    }

    func testAnAddressThatIsNotValidUtf8IsRejectedNotReplaced() {
        // 0xFF and 0xFE never appear in UTF-8; substituting U+FFFD here would
        // mean proxying to a destination nobody named.
        let invalid: [UInt8] = [0x61, 0xFF, 0xFE]
        XCTAssertNil(HysteriaProtocol.decodeUdpMessage(wire(0, 0, 0, 1, 0, 2, 0, 1, 0x03, invalid, 0xAA)))
    }

    func testTheHeaderSizeMatchesWhatEncodingActuallySpends() throws {
        XCTAssertEqual(HysteriaProtocol.udpHeaderSize(address: "1.2.3.4:53"), 8 + 1 + 10)

        let longAddress = String(repeating: "h", count: 96) + ":443" // 100 bytes, two-byte varint
        XCTAssertEqual(longAddress.utf8.count, 100)
        XCTAssertEqual(HysteriaProtocol.udpHeaderSize(address: longAddress), 8 + 2 + 100)

        for address in ["1.2.3.4:53", longAddress, munich] {
            let payload = (0..<37).map { UInt8($0) }
            let encoded = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: 1, fragId: 0, fragCount: 1,
                                                          address: address, payload: payload).encode()
            XCTAssertEqual(encoded.count - payload.count, HysteriaProtocol.udpHeaderSize(address: address), address)
        }
    }

    // MARK: - Fragmentation

    func testAPayloadThatFitsIsOneUnfragmentedMessage() {
        let address = "1.2.3.4:53"
        let headerSize = HysteriaProtocol.udpHeaderSize(address: address) // 19
        let payload = (0..<10).map { UInt8($0) }

        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 7, packetId: 9, address: address, payload: payload,
                                                     maxDatagramSize: headerSize + 10)
        XCTAssertEqual(fragments.count, 1)
        XCTAssertEqual(fragments.first?.fragId, 0)
        XCTAssertEqual(fragments.first?.fragCount, 1)
        XCTAssertEqual(fragments.first?.payload, payload)
        XCTAssertEqual(fragments.first?.encode().count, headerSize + 10)
    }

    func testOneByteTooManyBecomesTwoFragments() {
        let address = "1.2.3.4:53"
        let headerSize = HysteriaProtocol.udpHeaderSize(address: address)
        let payload = (0..<11).map { UInt8($0) }

        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 7, packetId: 9, address: address, payload: payload,
                                                     maxDatagramSize: headerSize + 10)
        XCTAssertEqual(fragments.count, 2)
        XCTAssertEqual(fragments.map { $0.payload.count }, [10, 1])
        XCTAssertTrue(fragments.allSatisfy { $0.fragCount == 2 })
        XCTAssertEqual(fragments.map { $0.fragId }, [0, 1])
    }

    func testFragmentsAreNumberedInOrderAndNoneExceedsTheDatagramBudget() {
        let address = "1.2.3.4:53"
        let headerSize = HysteriaProtocol.udpHeaderSize(address: address)
        let maxDatagramSize = headerSize + 10
        let payload = (0..<25).map { UInt8($0 + 1) }

        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 0x1122_3344, packetId: 0x0102, address: address,
                                                     payload: payload, maxDatagramSize: maxDatagramSize)
        XCTAssertEqual(fragments.count, 3)
        XCTAssertEqual(fragments.map { $0.payload.count }, [10, 10, 5])

        for (index, fragment) in fragments.enumerated() {
            XCTAssertEqual(fragment.fragId, index)
            XCTAssertEqual(fragment.fragCount, 3)
            XCTAssertEqual(fragment.sessionId, 0x1122_3344)
            XCTAssertEqual(fragment.packetId, 0x0102)
            XCTAssertEqual(fragment.address, address)
            XCTAssertLessThanOrEqual(fragment.encode().count, maxDatagramSize)
        }

        var rejoined: [UInt8] = []
        for fragment in fragments {
            rejoined.append(contentsOf: fragment.payload)
        }
        XCTAssertEqual(rejoined, payload)
    }

    func testAPayloadNeedingMoreThan255FragmentsCannotBeFramed() {
        let address = "1.2.3.4:53"
        let headerSize = HysteriaProtocol.udpHeaderSize(address: address)
        let maxDatagramSize = headerSize + 10

        // Exactly 255 chunks is the most a one-byte fragment count can express.
        let atLimit = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 1, address: address,
                                                   payload: [UInt8](repeating: 0, count: 2550),
                                                   maxDatagramSize: maxDatagramSize)
        XCTAssertEqual(atLimit.count, 255)
        XCTAssertEqual(atLimit.last?.fragCount, 255)

        let overLimit = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 1, address: address,
                                                     payload: [UInt8](repeating: 0, count: 2551),
                                                     maxDatagramSize: maxDatagramSize)
        XCTAssertTrue(overLimit.isEmpty)
    }

    // MARK: - Reassembly

    func testTheDefragmentersBoundsAreTheReferences() {
        XCTAssertEqual(HysteriaDefragmenter.maxSlots, 32)
        XCTAssertEqual(HysteriaDefragmenter.slotTtlNanos, 10 * 1_000_000_000)
    }

    func testAnUnfragmentedMessagePassesStraightThrough() throws {
        let defragmenter = HysteriaDefragmenter()
        let payload: [UInt8] = [0x01, 0x02]
        let whole = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: 1, fragId: 0, fragCount: 1,
                                                    address: "a:1", payload: payload)
        XCTAssertEqual(defragmenter.accept(whole), payload)
        XCTAssertEqual(defragmenter.slotCount, 0)
    }

    func testFragmentsArrivingInOrderReassembleOnTheLastOne() {
        let defragmenter = HysteriaDefragmenter()
        let payload = (0..<25).map { UInt8($0 + 1) }
        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 42, address: "a:1", payload: payload,
                                                     maxDatagramSize: HysteriaProtocol.udpHeaderSize(address: "a:1") + 10)
        XCTAssertEqual(fragments.count, 3)
        guard fragments.count == 3 else { return }

        XCTAssertNil(defragmenter.accept(fragments[0]))
        XCTAssertNil(defragmenter.accept(fragments[1]))
        XCTAssertEqual(defragmenter.accept(fragments[2]), payload)
        XCTAssertEqual(defragmenter.slotCount, 0)
    }

    func testFragmentsArrivingOutOfOrderReassembleInTheRightOrder() {
        let payload = (0..<25).map { UInt8($0 + 1) }
        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 42, address: "a:1", payload: payload,
                                                     maxDatagramSize: HysteriaProtocol.udpHeaderSize(address: "a:1") + 10)
        XCTAssertEqual(fragments.count, 3)
        guard fragments.count == 3 else { return }

        for order in [[2, 0, 1], [1, 2, 0], [2, 1, 0]] {
            let defragmenter = HysteriaDefragmenter()
            let results = order.map { defragmenter.accept(fragments[$0]) }
            XCTAssertNil(results[0], "order \(order)")
            XCTAssertNil(results[1], "order \(order)")
            XCTAssertEqual(results[2], payload, "order \(order)")
            XCTAssertEqual(defragmenter.slotCount, 0, "order \(order)")
        }
    }

    func testARepeatedFragmentCannotCompleteAPacketThatIsStillShort() {
        let defragmenter = HysteriaDefragmenter()
        let payload = (0..<25).map { UInt8($0 + 1) }
        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 42, address: "a:1", payload: payload,
                                                     maxDatagramSize: HysteriaProtocol.udpHeaderSize(address: "a:1") + 10)
        XCTAssertEqual(fragments.count, 3)
        guard fragments.count == 3 else { return }

        XCTAssertNil(defragmenter.accept(fragments[0]))
        XCTAssertNil(defragmenter.accept(fragments[0]))
        XCTAssertNil(defragmenter.accept(fragments[0]))
        XCTAssertNil(defragmenter.accept(fragments[1]))
        XCTAssertEqual(defragmenter.accept(fragments[2]), payload)
    }

    func testTwoPacketsInFlightAtOnceStayApart() {
        let defragmenter = HysteriaDefragmenter()
        let address = "a:1"
        let budget = HysteriaProtocol.udpHeaderSize(address: address) + 10
        let first = [UInt8](repeating: 0x11, count: 15)
        let second = [UInt8](repeating: 0x22, count: 15)
        let a = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 100, address: address, payload: first,
                                             maxDatagramSize: budget)
        let b = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 200, address: address, payload: second,
                                             maxDatagramSize: budget)
        XCTAssertEqual(a.count, 2)
        XCTAssertEqual(b.count, 2)
        guard a.count == 2, b.count == 2 else { return }

        XCTAssertNil(defragmenter.accept(a[0]))
        XCTAssertNil(defragmenter.accept(b[1]))
        XCTAssertEqual(defragmenter.slotCount, 2)
        XCTAssertEqual(defragmenter.accept(b[0]), second)
        XCTAssertEqual(defragmenter.accept(a[1]), first)
        XCTAssertEqual(defragmenter.slotCount, 0)
    }

    func testAFragmentIndexPastTheFragmentCountOpensNoSlot() throws {
        let defragmenter = HysteriaDefragmenter()
        let bogus = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: 5, fragId: 3, fragCount: 3,
                                                    address: "a:1", payload: [0x01])
        XCTAssertNil(defragmenter.accept(bogus))
        XCTAssertEqual(defragmenter.slotCount, 0)
    }

    func testAStaleHalfAssembledPacketIsDroppedRatherThanJoinedYearsLater() {
        var now: Int64 = 0
        let defragmenter = HysteriaDefragmenter(clock: { now })
        let payload = (0..<15).map { UInt8($0 + 1) }
        let fragments = HysteriaProtocol.fragmentUdp(sessionId: 1, packetId: 42, address: "a:1", payload: payload,
                                                     maxDatagramSize: HysteriaProtocol.udpHeaderSize(address: "a:1") + 10)
        XCTAssertEqual(fragments.count, 2)
        guard fragments.count == 2 else { return }

        XCTAssertNil(defragmenter.accept(fragments[0]))
        now = HysteriaDefragmenter.slotTtlNanos + 1

        // The slot has expired, so the second fragment starts a fresh one and
        // the packet is not completed by the piece that arrived too long ago.
        XCTAssertNil(defragmenter.accept(fragments[1]))
        XCTAssertEqual(defragmenter.slotCount, 1)
        // The re-sent first fragment completes the new slot.
        XCTAssertEqual(defragmenter.accept(fragments[0]), payload)
    }

    func testTheReassemblyTableNeverGrowsPastItsBound() throws {
        let defragmenter = HysteriaDefragmenter(maxSlots: 4, clock: { 0 })
        for index in 0..<20 {
            let fragment = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: index, fragId: 0, fragCount: 2,
                                                           address: "a:1", payload: [UInt8(index)])
            XCTAssertNil(defragmenter.accept(fragment))
            XCTAssertLessThanOrEqual(defragmenter.slotCount, 4, "after \(index) packets")
        }
        XCTAssertEqual(defragmenter.slotCount, 4)
    }

    func testClearingDropsEverythingInFlight() throws {
        let defragmenter = HysteriaDefragmenter()
        let fragment = try HysteriaProtocol.UdpMessage(sessionId: 1, packetId: 1, fragId: 0, fragCount: 2,
                                                       address: "a:1", payload: [0x01])
        XCTAssertNil(defragmenter.accept(fragment))
        XCTAssertEqual(defragmenter.slotCount, 1)
        defragmenter.clear()
        XCTAssertEqual(defragmenter.slotCount, 0)
    }

    func testAPayloadSurvivesFragmentationTheWireAndShuffledReassembly() throws {
        let address = HysteriaProtocol.formatAddress(host: "2001:db8::1", port: 5353)
        let budget = HysteriaProtocol.udpHeaderSize(address: address) + 64
        let payload = (0..<1000).map { UInt8(($0 * 31) & 0xFF) }

        let datagrams = HysteriaProtocol
            .fragmentUdp(sessionId: 0xFEED_FACE, packetId: 0xABCD, address: address, payload: payload,
                         maxDatagramSize: budget)
            .map { $0.encode() }
        XCTAssertEqual(datagrams.count, 16)
        XCTAssertTrue(datagrams.allSatisfy { $0.count <= budget })

        let defragmenter = HysteriaDefragmenter()
        var assembled: [UInt8]? = nil
        // Reversed, so the final fragment is the first one seen.
        for datagram in datagrams.reversed() {
            let message = try XCTUnwrap(HysteriaProtocol.decodeUdpMessage(datagram))
            XCTAssertEqual(message.sessionId, 0xFEED_FACE)
            XCTAssertEqual(message.packetId, 0xABCD)
            XCTAssertEqual(message.address, address)
            if let result = defragmenter.accept(message) {
                XCTAssertNil(assembled, "completed more than once")
                assembled = result
            }
        }
        XCTAssertEqual(assembled, payload)
    }

    // MARK: - Padding

    func testPaddingIsDrawnFromTheAlphabetTheReferenceUses() {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
        XCTAssertEqual(alphabet.count, 62)
        XCTAssertEqual(HysteriaProtocol.paddingAlphabet, alphabet)

        let padding = HysteriaProtocol.randomPadding(length: 4096)
        XCTAssertEqual(padding.count, 4096)
        for byte in padding where !alphabet.contains(byte) {
            XCTFail("byte \(byte) is outside the alphabet")
        }
    }

    func testNoPaddingAtAllIsAnEmptyBufferNotACrash() {
        XCTAssertEqual(HysteriaProtocol.randomPadding(length: 0).count, 0)
        XCTAssertEqual(HysteriaProtocol.randomPadding(length: -1).count, 0)
    }

    func testTheAuthPaddingHeaderStaysInsideTheReferencesRange() {
        for _ in 0..<50 {
            let padding = HysteriaProtocol.randomPaddingString()
            XCTAssertTrue(HysteriaProtocol.authPaddingRange.contains(padding.utf8.count),
                          "length \(padding.utf8.count)")
            XCTAssertTrue(padding.utf8.allSatisfy { isAsciiLetterOrDigit($0) })
        }
    }

    func testPaddingDiffersBetweenCalls() {
        let first = HysteriaProtocol.randomPadding(length: 256)
        let second = HysteriaProtocol.randomPadding(length: 256)
        XCTAssertNotEqual(first, second)
    }

    // MARK: - Authentication

    func testTheAuthRequestCarriesThePasswordTheRateAndThePadding() {
        let headers = HysteriaProtocol.authRequestHeaders(password: "hunter2", clientRxBytesPerSec: 12_500_000,
                                                          padding: "PAD")
        XCTAssertEqual(headers, [
            Http3Field(name: "hysteria-auth", value: "hunter2"),
            Http3Field(name: "hysteria-cc-rx", value: "12500000"),
            Http3Field(name: "hysteria-padding", value: "PAD"),
            Http3Field(name: "content-length", value: "0"),
        ])
    }

    func testARateOfZeroIsWhatAsksTheServerToMeasureForItself() {
        let headers = HysteriaProtocol.authRequestHeaders(password: "p", clientRxBytesPerSec: 0, padding: "")
        XCTAssertEqual(headers.first(where: { $0.name == "hysteria-cc-rx" })?.value, "0")
    }

    func testStatus233IsTheOnlyAcceptance() throws {
        let accepted = try XCTUnwrap(HysteriaProtocol.parseAuthResponse([
            Http3Field(name: ":status", value: "233"),
            Http3Field(name: "hysteria-udp", value: "true"),
            Http3Field(name: "hysteria-cc-rx", value: "1000"),
        ]))
        XCTAssertTrue(accepted.isAccepted)
        XCTAssertTrue(accepted.udpSupported)
        XCTAssertEqual(accepted.serverRxBytesPerSec, 1000)

        for status in ["200", "232", "234", "404", "500"] {
            let response = try XCTUnwrap(HysteriaProtocol.parseAuthResponse([Http3Field(name: ":status", value: status)]))
            XCTAssertFalse(response.isAccepted, "status \(status)")
            XCTAssertEqual(response.status, Int(status))
        }
    }

    func testUdpSupportIsOffUnlessTheServerSaysTrue() throws {
        func udp(_ value: String?) throws -> Bool {
            var headers = [Http3Field(name: ":status", value: "233")]
            if let value = value {
                headers.append(Http3Field(name: "hysteria-udp", value: value))
            }
            return try XCTUnwrap(HysteriaProtocol.parseAuthResponse(headers)).udpSupported
        }

        XCTAssertTrue(try udp("true"))
        XCTAssertTrue(try udp("True"))
        XCTAssertTrue(try udp("TRUE"))
        XCTAssertFalse(try udp("false"))
        XCTAssertFalse(try udp("1"))
        XCTAssertFalse(try udp("yes"))
        XCTAssertFalse(try udp(""))
        XCTAssertFalse(try udp(nil))
    }

    func testAutoIsADifferentAnswerFromADeclaredRateOfZero() throws {
        func rate(_ value: String?) throws -> Int64? {
            var headers = [Http3Field(name: ":status", value: "233")]
            if let value = value {
                headers.append(Http3Field(name: "hysteria-cc-rx", value: value))
            }
            return try XCTUnwrap(HysteriaProtocol.parseAuthResponse(headers)).serverRxBytesPerSec
        }

        XCTAssertNil(try rate("auto"))
        XCTAssertNil(try rate("AUTO"))
        XCTAssertEqual(try rate("0"), 0)
        XCTAssertEqual(try rate("not a number"), 0)
        XCTAssertEqual(try rate(nil), 0)
        XCTAssertEqual(try rate("4294967296"), 4_294_967_296)
    }

    func testAReplyWithoutAUsableStatusIsAFailureNotARefusal() {
        XCTAssertNil(HysteriaProtocol.parseAuthResponse([]))
        XCTAssertNil(HysteriaProtocol.parseAuthResponse([Http3Field(name: "hysteria-udp", value: "true")]))
        XCTAssertNil(HysteriaProtocol.parseAuthResponse([Http3Field(name: ":status", value: "two hundred")]))
        XCTAssertNil(HysteriaProtocol.parseAuthResponse([Http3Field(name: ":status", value: "")]))
        // HTTP/3 lowercases header names, so a capitalised one is not a match.
        XCTAssertNil(HysteriaProtocol.parseAuthResponse([Http3Field(name: ":Status", value: "233")]))
    }
}
