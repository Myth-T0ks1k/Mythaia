import Foundation
import XCTest
@testable import MythaiaKit

/// Cloudflare WARP's `Reserved` bytes: how configs spell them, and where they
/// go on the wire.
final class WireGuardReservedTests: XCTestCase {
    private let privateKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8($0) }))
    private let peerKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))

    private func config(extraInterface: String = "", extraPeer: String = "") -> String {
        """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 172.16.0.2/32
        \(extraInterface)

        [Peer]
        PublicKey = \(peerKey)
        Endpoint = 192.0.2.10:2408
        \(extraPeer)
        """
    }

    // MARK: - Parsing

    func testReservedIsReadFromTheInterfaceAsDecimalBytes() throws {
        let parsed = try WireGuardConfig.parse(config(extraInterface: "Reserved = 12, 34, 56"))
        XCTAssertEqual(parsed.reserved, Data([12, 34, 56]))
        XCTAssertEqual(parsed.headerReserved, Data([12, 34, 56]))
    }

    func testReservedIsReadFromThePeerAndAsBase64() throws {
        // "AQID" is base64 of 01 02 03, the form WARP's API returns client_id in.
        let parsed = try WireGuardConfig.parse(config(extraPeer: "Reserved = AQID"))
        XCTAssertEqual(parsed.reserved, Data([1, 2, 3]))
    }

    func testTheSpellingsConfigsUseAllParse() {
        XCTAssertEqual(WireGuardConfig.parseReserved("1,2,3"), Data([1, 2, 3]))
        XCTAssertEqual(WireGuardConfig.parseReserved("[1, 2, 3]"), Data([1, 2, 3]))
        XCTAssertEqual(WireGuardConfig.parseReserved("255,0,127"), Data([255, 0, 127]))
        XCTAssertEqual(WireGuardConfig.parseReserved("AQID"), Data([1, 2, 3]))
        XCTAssertNil(WireGuardConfig.parseReserved("1,2"))
        XCTAssertNil(WireGuardConfig.parseReserved("1,2,256"))
        XCTAssertNil(WireGuardConfig.parseReserved("AQIDBA=="))
        XCTAssertNil(WireGuardConfig.parseReserved(""))
    }

    func testAnUnusableReservedIsRefusedRatherThanDropped() {
        XCTAssertThrowsError(try WireGuardConfig.parse(config(extraInterface: "Reserved = 1,2"))) { error in
            XCTAssertTrue(error.localizedDescription.contains("Reserved"), error.localizedDescription)
        }
    }

    func testNoReservedOrAllZeroesLeavesTheWireAlone() throws {
        XCTAssertNil(try WireGuardConfig.parse(config()).reserved)
        XCTAssertNil(try WireGuardConfig.parse(config()).headerReserved)
        let zeroes = try WireGuardConfig.parse(config(extraInterface: "Reserved = 0,0,0"))
        XCTAssertNotNil(zeroes.reserved)
        XCTAssertNil(zeroes.headerReserved)
    }

    func testAmneziaWGRenumberingWinsOverReserved() throws {
        let parsed = try WireGuardConfig.parse(
            config(extraInterface: "Reserved = 1,2,3\nH1 = 1234567\nH2 = 2345678\nH3 = 3456789\nH4 = 4567890")
        )
        XCTAssertEqual(parsed.reserved, Data([1, 2, 3]))
        XCTAssertNil(parsed.headerReserved)

        // Junk alone does not take the type word, so Reserved still applies.
        let junkOnly = try WireGuardConfig.parse(config(extraInterface: "Reserved = 1,2,3\nJc = 3\nJmin = 10\nJmax = 20"))
        XCTAssertEqual(junkOnly.headerReserved, Data([1, 2, 3]))
    }

    // MARK: - The wire

    private let reserved: [UInt8] = [0x0A, 0x0B, 0x0C]
    private let keyA: [UInt8] = (0..<32).map { UInt8($0) }
    private let keyB: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 3 + 1) }

    func testTransportMessagesCarryTheReservedBytesAfterTheType() throws {
        let client = WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: 2, localIndex: 1, reserved: reserved)
        let message = [UInt8](try client.encapsulate(Data("packet".utf8)))

        XCTAssertEqual(Array(message[0..<4]), [4, 0x0A, 0x0B, 0x0C])
        XCTAssertEqual(WireGuardHandshake.readLe32(message, 4), 2)
    }

    func testWithReservedSetAReceivedMessageIsMatchedOnItsLowOctet() throws {
        let server = WireGuardTransport(sendKey: keyB, receiveKey: keyA, peerIndex: 1, localIndex: 2)
        var fromServer = [UInt8](try server.encapsulate(Data("reply".utf8)))
        // WARP puts its own bytes into the reserved octets of what it sends.
        fromServer[1] = 0x55
        fromServer[2] = 0x66
        fromServer[3] = 0x77

        let client = WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: 2, localIndex: 1, reserved: reserved)
        XCTAssertEqual(client.decapsulate(Data(fromServer))?.prefix(5), Data("reply".utf8))

        // Plain WireGuard keeps comparing the whole word.
        let plain = WireGuardTransport(sendKey: keyA, receiveKey: keyB, peerIndex: 2, localIndex: 1)
        XCTAssertNil(plain.decapsulate(Data(fromServer)))
    }

    func testTheTypeComparisonOnlyRelaxesWhenReservedIsInUse() {
        XCTAssertTrue(WireGuardHandshake.isType(0x7766_5504, 4, reserved))
        XCTAssertFalse(WireGuardHandshake.isType(0x7766_5503, 4, reserved))
        XCTAssertFalse(WireGuardHandshake.isType(0x7766_5504, 4, nil))
        XCTAssertTrue(WireGuardHandshake.isType(4, 4, nil))
    }

    // MARK: - The handshake

    func testReservedGoesIntoOctets1To3OfTheInitiationAfterTheMacs() throws {
        let client = WireGuardTestSupport.keyPair()
        let server = WireGuardTestSupport.keyPair()
        let stamp: [UInt8] = [0x11, 0x22, 0x33]

        let message = try WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            reserved: stamp
        ).buildInitiation(index: 7)

        XCTAssertEqual(message.count, WireGuardHandshake.initiationSize)
        XCTAssertEqual(Array(message[0..<4]), [1, 0x11, 0x22, 0x33])

        // mac1 is over the message as plain WireGuard would have it, which is
        // what WARP checks after clearing its reserved octets.
        var zeroed = Array(message[0..<116])
        zeroed[1] = 0
        zeroed[2] = 0
        zeroed[3] = 0
        let expected = WireGuardCrypto.mac(key: WireGuardCrypto.hash(Array("mac1----".utf8), server.publicKey), data: zeroed)
        XCTAssertEqual(Array(message[116..<132]), expected)
    }

    func testAWarpStylePeerCompletesTheHandshakeWithItsOwnReservedBytes() throws {
        let client = WireGuardTestSupport.keyPair()
        let server = WireGuardTestSupport.keyPair()
        let stamp: [UInt8] = [0x11, 0x22, 0x33]

        let handshake = WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            reserved: stamp
        )
        let initiation = try handshake.buildInitiation(index: 9)
        // The server clears the octets before it reads the message...
        var cleared = initiation
        cleared[1] = 0
        cleared[2] = 0
        cleared[3] = 0
        let responder = try WireGuardTestSupport.respond(cleared, responderPrivate: server.privateKey, responderPublic: server.publicKey)
        // ...and writes its own into the reply.
        var reply = responder.response
        reply[1] = 0x44
        reply[2] = 0x55
        reply[3] = 0x66

        let keys = try handshake.consumeResponse(reply)
        XCTAssertEqual(keys.sendKey, responder.receiveKey)

        // Without Reserved configured the same reply is not a response.
        let plain = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        _ = try plain.buildInitiation(index: 9)
        XCTAssertThrowsError(try plain.consumeResponse(reply))
    }
}
