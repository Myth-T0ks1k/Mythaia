import Foundation
import XCTest
@testable import MythaiaKit

/// The data phase.
///
/// The two sides are built with the keys crossed, the way a real pair is, so a
/// message one produces is read by the other rather than by itself; and the
/// first messages of a known session are pinned to bytes an independent
/// implementation sealed.
final class WireGuardTransportTests: XCTestCase {
    private func hex(_ text: String) -> [UInt8] { WireGuardTestSupport.hex(text) }
    private func hexString(_ data: Data) -> String { WireGuardTestSupport.hexString(data) }

    private let keyA: [UInt8] = (0..<32).map { UInt8($0) }
    private let keyB: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 3 + 1) }
    private let indexClient: UInt32 = 0x1111_1111
    private let indexServer: UInt32 = 0x2222_2222

    /// The client: sends with A, receives with B.
    private func makeClient() -> WireGuardTransport {
        WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: indexServer, localIndex: indexClient)
    }

    /// The server: the mirror image.
    private func makeServer() -> WireGuardTransport {
        WireGuardTransport(sendKey: keyB, receiveKey: keyA, peerIndex: indexClient, localIndex: indexServer)
    }

    private func bytes(_ text: String) -> Data { Data(text.utf8) }

    // MARK: - Known answers

    /// The session of the handshake known-answer test: what the client sends
    /// first, and a packet the server sealed under counter 7.
    func testTheFirstMessagesOfAKnownSessionMatchAnIndependentImplementation() throws {
        let sendKey = hex("70b842fb1beddecdbeeb23d36a47abdf053c31abdf92f1ed4e61f6bb00b76523")
        let receiveKey = hex("b79c413369c96a35baf9f53e1962f4521f07fba6c9fe2a4d941b75e2d33ec7a7")
        let transport = WireGuardTransport(sendKey: sendKey, receiveKey: receiveKey, peerIndex: 0x1122_3344, localIndex: 0x0102_0304)

        // A 20-byte IPv4 header, padded to 32 before sealing.
        let packet = Data(hex("450000140405060708090a0b0c0d0e0f10111213"))
        XCTAssertEqual(
            hexString(try transport.encapsulate(packet)),
            "04000000443322110000000000000000b8a93264cb6be0932014f37a5c59ab1af1b0c965fa9a59636bd82fcbe6d9b3fb"
                + "87f027eb8536f9c08376b15b27b6fcf0"
        )
        // The keepalive that follows is counter 1 and only a tag.
        XCTAssertEqual(
            hexString(try transport.encapsulate(Data())),
            "04000000443322110100000000000000ac979e28c6dfbdc93cb285a1981ec0af"
        )

        let incoming = Data(hex(
            "04000000040302010700000000000000346345b204142dc24f7ea53b4d952e0a1469bdf2e70c69fb4e9f3971f8c9f6fd"
                + "956b0eadfdff4ebd3741f8809e3c5c3b"
        ))
        let opened = try XCTUnwrap(transport.decapsulate(incoming))
        // 28 bytes of packet and 4 of padding.
        XCTAssertEqual(opened.count, 32)
        XCTAssertEqual(hexString(opened.prefix(28)), "4500001c6465666768696a6b6c6d6e6f707172737475767778797a7b")
        XCTAssertEqual(WireGuardTunnel.ipPacketLength(opened), 28)
    }

    // MARK: - Framing

    func testAMessageCarriesThePeerIndexAndTheCounterLittleEndian() throws {
        let message = [UInt8](try makeClient().encapsulate(bytes("packet")))

        XCTAssertEqual(WireGuardHandshake.readLe32(message, 0), WireGuardHandshake.messageTransport)
        XCTAssertEqual(Array(message[1..<4]), [0, 0, 0])
        // Addressed to the peer's index, not our own.
        XCTAssertEqual(WireGuardHandshake.readLe32(message, 4), indexServer)
        XCTAssertEqual(WireGuardHandshake.readLe64(message, 8), 0)
    }

    func testTheCounterAdvancesByOnePerPacket() throws {
        let transport = makeClient()
        for expected in UInt64(0)..<5 {
            let message = try transport.encapsulate(bytes("x"))
            XCTAssertEqual(WireGuardHandshake.readLe64(message, 8), expected)
        }
        XCTAssertEqual(transport.packetsSent, 5)
    }

    func testThePlaintextIsPaddedToAMultipleOfSixteen() throws {
        // Padding is what stops the ciphertext length being the packet length.
        for size in [1, 15, 16, 17, 31, 32, 100] {
            let message = try makeClient().encapsulate(Data(count: size))
            let ciphertext = message.count - WireGuardTransport.headerSize - WireGuardCrypto.tagSize
            XCTAssertEqual(ciphertext % 16, 0, "size \(size)")
            XCTAssertGreaterThanOrEqual(ciphertext, size, "size \(size)")
            XCTAssertLessThan(ciphertext, size + 16, "size \(size)")
        }
        // An empty packet — a keepalive — is not padded up to a full block.
        let keepalive = try makeClient().encapsulate(Data())
        XCTAssertEqual(keepalive.count, WireGuardTransport.headerSize + WireGuardCrypto.tagSize)
    }

    // MARK: - Round trip

    func testWhatTheClientSendsTheServerReads() throws {
        let client = makeClient()
        let server = makeServer()

        for i in 0..<10 {
            let packet = Data((0..<40).map { UInt8(truncatingIfNeeded: i + $0) })
            let opened = server.decapsulate(try client.encapsulate(packet))
            XCTAssertNotNil(opened, "packet \(i)")
            // Padding rides along; the real length comes from the IP header.
            XCTAssertEqual(opened?.prefix(packet.count), packet)
        }
    }

    func testAKeepaliveOpensToNothing() throws {
        let opened = makeServer().decapsulate(try makeClient().encapsulate(Data()))
        XCTAssertEqual(opened?.count, 0)
    }

    func testAMessageThatIsASliceOpensToo() throws {
        // A received datagram may be a slice whose indices do not start at 0.
        var framed = Data([0xEE, 0xEE, 0xEE])
        framed.append(try makeClient().encapsulate(bytes("sliced")))
        let slice = framed[3...]
        XCTAssertEqual(makeServer().decapsulate(slice)?.prefix(6), bytes("sliced"))
    }

    // MARK: - Rejection

    func testAMessageForAnotherSessionIsIgnored() throws {
        let message = [UInt8](try makeClient().encapsulate(bytes("x")))

        // Addressed to somebody else's index.
        var misaddressed = message
        WireGuardHandshake.writeLe32(&misaddressed, 4, 0x9999_9999)
        XCTAssertNil(makeServer().decapsulate(Data(misaddressed)))

        // Not a transport message.
        var wrongType = message
        WireGuardHandshake.writeLe32(&wrongType, 0, WireGuardHandshake.messageInitiation)
        XCTAssertNil(makeServer().decapsulate(Data(wrongType)))
    }

    func testATamperedOrTruncatedMessageIsIgnored() throws {
        let message = try makeClient().encapsulate(Data(count: 64))

        for cut in 0..<(WireGuardTransport.headerSize + WireGuardCrypto.tagSize) {
            XCTAssertNil(makeServer().decapsulate(message.prefix(cut)), "cut=\(cut)")
        }

        var tampered = [UInt8](message)
        tampered[WireGuardTransport.headerSize] ^= 1
        XCTAssertNil(makeServer().decapsulate(Data(tampered)))
    }

    func testTheWrongKeyDoesNotOpenTheMessage() throws {
        let message = try makeClient().encapsulate(bytes("x"))
        let stranger = WireGuardTransport(
            sendKey: [UInt8](repeating: 0, count: 32),
            receiveKey: [UInt8](repeating: 0, count: 32),
            peerIndex: indexClient,
            localIndex: indexServer
        )
        XCTAssertNil(stranger.decapsulate(message))
    }

    // MARK: - Replay window

    func testTheSamePacketIsNotAcceptedTwice() throws {
        let client = makeClient()
        let server = makeServer()

        let message = try client.encapsulate(bytes("x"))
        XCTAssertNotNil(server.decapsulate(message))
        XCTAssertNil(server.decapsulate(message), "a replay was accepted")
    }

    func testPacketsThatArriveOutOfOrderAreStillAccepted() throws {
        // Reordering is normal on any real path; only a repeat is a replay.
        let client = makeClient()
        let server = makeServer()

        let messages = try (0..<10).map { try client.encapsulate(Data([UInt8($0)])) }
        for message in messages.reversed() {
            XCTAssertNotNil(server.decapsulate(message))
        }
        // And none of them a second time.
        for message in messages {
            XCTAssertNil(server.decapsulate(message))
        }
    }

    func testAPacketOlderThanTheWindowIsRefused() throws {
        let client = makeClient()
        let server = makeServer()

        let first = try client.encapsulate(bytes("first"))

        // Move the window well past it.
        for i in 0..<(Int(WireGuardTransport.windowSize) + 10) {
            _ = try client.encapsulate(Data([UInt8(truncatingIfNeeded: i)]))
        }
        let recent = try client.encapsulate(bytes("recent"))
        XCTAssertNotNil(server.decapsulate(recent))

        // The first one is now too far behind to be distinguishable from a
        // replay, so it goes.
        XCTAssertNil(server.decapsulate(first))
    }

    func testALargeJumpForwardDoesNotLeaveStaleBitsBehind() throws {
        // After the window slides, the counters it moved over must read as
        // unseen — otherwise a later packet landing on a stale bit is dropped
        // as a replay it never was.
        let client = makeClient()
        let server = makeServer()

        _ = try client.encapsulate(bytes("x"))  // counter 0, never delivered

        var skipped: [Data] = []
        for i in 0..<100 {
            skipped.append(try client.encapsulate(Data([UInt8(i)])))
        }

        // Deliver the last one first, then the earlier ones: all must be
        // accepted exactly once.
        XCTAssertNotNil(server.decapsulate(skipped[skipped.count - 1]))
        for message in skipped.dropLast() {
            XCTAssertNotNil(server.decapsulate(message))
        }
        for message in skipped {
            XCTAssertNil(server.decapsulate(message))
        }
    }

    func testTheWindowWrapsWithoutForgettingWhatItHolds() throws {
        // Counters a whole window apart share a bit; sliding over one must
        // clear it for the new counter, and nothing else.
        let client = makeClient()
        let server = makeServer()
        var messages: [Data] = []
        for i in 0..<(Int(WireGuardTransport.windowSize) * 2 + 5) {
            messages.append(try client.encapsulate(Data([UInt8(truncatingIfNeeded: i)])))
        }
        for message in messages {
            XCTAssertNotNil(server.decapsulate(message))
        }
        for message in messages.suffix(Int(WireGuardTransport.windowSize) - 1) {
            XCTAssertNil(server.decapsulate(message))
        }
    }

    func testTheSendLimitsArePositiveAndOrdered() throws {
        // A sign error here would make every session look exhausted at counter
        // zero and refuse to send anything at all.
        XCTAssertGreaterThan(WireGuardTransport.rekeyAfterMessages, 0)
        XCTAssertGreaterThan(WireGuardTransport.rejectAfterMessages, WireGuardTransport.rekeyAfterMessages)
        XCTAssertEqual(WireGuardTransport.rejectAfterMessages, UInt64.max - 8192)

        let transport = makeClient()
        XCTAssertFalse(transport.needsRekey)
        XCTAssertFalse(transport.isExhausted)
        _ = try transport.encapsulate(bytes("x"))
    }

    // MARK: - AmneziaWG type renumbering

    func testARenumberedTransportTypeIsUsedOnBothSides() throws {
        // AmneziaWG replaces the four message types so a filter matching on
        // WireGuard's constants sees nothing it recognises. H4 is required to
        // exceed 4 and is generated up to 2^31, so it does not fit in a byte.
        let type: UInt32 = 0x7060_9579
        let client = WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: indexServer, localIndex: indexClient, transportType: type)
        let server = WireGuardTransport(sendKey: keyB, receiveKey: keyA, peerIndex: indexClient, localIndex: indexServer, transportType: type)

        let message = try client.encapsulate(bytes("x"))
        XCTAssertNotNil(server.decapsulate(message))

        // Asserted against the bytes a peer reads, not against our own writer:
        // a round trip alone passes just as happily when both sides truncate.
        XCTAssertEqual([UInt8](message.prefix(4)), [0x79, 0x95, 0x60, 0x70])

        // A peer still expecting the standard type does not read it.
        let standard = WireGuardTransport(sendKey: keyB, receiveKey: keyA, peerIndex: indexClient, localIndex: indexServer)
        XCTAssertNil(standard.decapsulate(message))
    }

    func testTwoHeadersSharingALowByteAreToldApart() throws {
        // The whole 32-bit word is the type. Comparing only its low byte would
        // let one AmneziaWG peer's traffic be accepted as another's.
        let ours: UInt32 = 0x1122_3344
        let theirs: UInt32 = 0x5566_7744

        let client = WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: indexServer, localIndex: indexClient, transportType: theirs)
        let server = WireGuardTransport(sendKey: keyB, receiveKey: keyA, peerIndex: indexClient, localIndex: indexServer, transportType: ours)

        XCTAssertNil(server.decapsulate(try client.encapsulate(bytes("x"))))
    }

    func testPlainWireGuardStillWritesType4WithThreeZeroBytes() throws {
        let message = try makeClient().encapsulate(bytes("x"))
        XCTAssertEqual([UInt8](message.prefix(4)), [4, 0, 0, 0])
    }
}
