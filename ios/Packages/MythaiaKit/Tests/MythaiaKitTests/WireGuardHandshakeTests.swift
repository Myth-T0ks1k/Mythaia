import Foundation
import XCTest
@testable import MythaiaKit

/// The handshake, driven against the responder in `WireGuardTestSupport`
/// (written out from the WireGuard paper's own responder steps), and pinned
/// byte for byte to messages an independent implementation produced from the
/// same inputs.
final class WireGuardHandshakeTests: XCTestCase {
    private typealias Support = WireGuardTestSupport

    private func hex(_ text: String) -> [UInt8] { Support.hex(text) }
    private func hexString(_ bytes: [UInt8]) -> String { Support.hexString(bytes) }

    // MARK: - Known answers

    // Fixed inputs for the known-answer tests. Every byte of the expected
    // messages below was computed outside this code base (Python's hashlib
    // BLAKE2s and hmac, and OpenSSL's X25519 and ChaCha20-Poly1305), from the
    // paper's steps: a mistake in the order of the steps, a field's offset or
    // a primitive shows up here even when this client agrees with itself.
    private let clientPrivate: [UInt8] = (0..<32).map { UInt8(0x40 + $0) }
    private let serverPrivate: [UInt8] = (0..<32).map { UInt8(0x80 + $0) }
    private let initiatorEphemeral: [UInt8] = (0..<32).map { UInt8(0xC0 + $0) }
    private let responderEphemeral: [UInt8] = (0..<32).map { UInt8(0x20 + $0) }
    private let knownIndex: UInt32 = 0x0102_0304
    private var knownTimestamp: [UInt8] { WireGuardCrypto.tai64n(millis: 1_700_000_000_123) }

    private let knownClientPublic = "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"
    private let knownServerPublic = "493e82fc74464a59268817623d2053c5eb8e2cc4a988b4fee179ec6b010d531d"

    private let knownInitiation = "0100000004030201dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d44"
        + "b8fb4c563553c61ed4155cfe91c9fdb4164ac2a736bff8cbffc443cd462b7ca00446ec1491e224d9df5d5e6d5f69c7e6"
        + "fecb9770a4253e66303eab8d9f1fc421dd6a164c9b7378380c13ef713cddeab6b7a4b5abc57baf683ffd69e9"
        + "00000000000000000000000000000000"

    private let knownResponse = "020000004433221104030201358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        + "8a78916d7bfbc686dff567a20385b31cf8871b78322238b8f761d0b6aa056fdf00000000000000000000000000000000"

    private func knownClient(presharedKey: [UInt8] = [UInt8](repeating: 0, count: 32)) throws -> WireGuardHandshake {
        let clientPublic = try WireGuardCrypto.publicKey(clientPrivate)
        let serverPublic = try WireGuardCrypto.publicKey(serverPrivate)
        return WireGuardHandshake(
            localPrivateKey: clientPrivate,
            localPublicKey: clientPublic,
            peerPublicKey: serverPublic,
            presharedKey: presharedKey
        )
    }

    func testTheKnownKeysAreTheOnesTheVectorsUse() throws {
        XCTAssertEqual(hexString(try WireGuardCrypto.publicKey(clientPrivate)), knownClientPublic)
        XCTAssertEqual(hexString(try WireGuardCrypto.publicKey(serverPrivate)), knownServerPublic)
    }

    func testTheInitiationMatchesAnIndependentImplementation() throws {
        let client = try knownClient()
        let message = try client.buildInitiation(index: knownIndex, timestamp: knownTimestamp, ephemeralPrivateKey: initiatorEphemeral)
        XCTAssertEqual(hexString(message), knownInitiation)
    }

    func testTheIndependentResponseYieldsTheIndependentKeys() throws {
        let client = try knownClient()
        _ = try client.buildInitiation(index: knownIndex, timestamp: knownTimestamp, ephemeralPrivateKey: initiatorEphemeral)
        let keys = try client.consumeResponse(hex(knownResponse))

        XCTAssertEqual(keys.localIndex, knownIndex)
        XCTAssertEqual(keys.peerIndex, 0x1122_3344)
        XCTAssertEqual(hexString(keys.sendKey), "70b842fb1beddecdbeeb23d36a47abdf053c31abdf92f1ed4e61f6bb00b76523")
        XCTAssertEqual(hexString(keys.receiveKey), "b79c413369c96a35baf9f53e1962f4521f07fba6c9fe2a4d941b75e2d33ec7a7")
    }

    func testOurResponderProducesTheIndependentResponse() throws {
        // The test responder, fed the same ephemeral, must write the same
        // bytes; otherwise the tests that lean on it prove nothing.
        let result = try Support.respond(
            hex(knownInitiation),
            responderPrivate: serverPrivate,
            responderPublic: try WireGuardCrypto.publicKey(serverPrivate),
            responderEphemeral: responderEphemeral
        )
        XCTAssertEqual(hexString(result.response), knownResponse)
        XCTAssertEqual(result.timestamp, knownTimestamp)
        XCTAssertEqual(hexString(result.initiatorStatic), knownClientPublic)
    }

    func testAPresharedKeyChangesTheKnownKeys() throws {
        let psk: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 5) }
        let client = try knownClient(presharedKey: psk)
        let message = try client.buildInitiation(index: knownIndex, timestamp: knownTimestamp, ephemeralPrivateKey: initiatorEphemeral)
        // The PSK enters only after the initiation, which is unchanged by it.
        XCTAssertEqual(hexString(message), knownInitiation)

        let response = "020000004433221104030201358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
            + "549999931220a87b6c9ac1e11413aa96abc536541c62c4f8c6078241be2912b300000000000000000000000000000000"
        let keys = try client.consumeResponse(hex(response))
        XCTAssertEqual(hexString(keys.sendKey), "ac788fb9e13d5f6c85c8572ce53bf3da5ce0c9d6b0d254e38399ea35930c34fd")
        XCTAssertEqual(hexString(keys.receiveKey), "3f5f077766c46321078394fc883d3ddc80036bab7e95623738648f75e27c3446")
    }

    func testMac2IsTheCookiesMacOverTheMessageAndMac1() throws {
        let client = try knownClient()
        client.cookie = (0..<16).map { UInt8(0xA0 + $0) }
        let message = try client.buildInitiation(index: knownIndex, timestamp: knownTimestamp, ephemeralPrivateKey: initiatorEphemeral)
        // Everything up to mac2 is as without a cookie; mac2 is the
        // independent implementation's.
        XCTAssertEqual(hexString(Array(message[0..<132])), String(knownInitiation.prefix(264)))
        XCTAssertEqual(hexString(Array(message[132..<148])), "282effddb1fb975cf26b0066499d481b")
    }

    // MARK: - Message shape

    func testTheInitiationIs148BytesWithTheFieldsWhereTheSpecPutsThem() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let message = try handshake.buildInitiation(index: 0x0102_0304)

        XCTAssertEqual(message.count, WireGuardHandshake.initiationSize)
        XCTAssertEqual(WireGuardHandshake.readLe32(message, 0), WireGuardHandshake.messageInitiation)
        // Three reserved zero bytes, which some deployments do inspect.
        XCTAssertEqual(message[1], 0)
        XCTAssertEqual(message[2], 0)
        XCTAssertEqual(message[3], 0)
        // The index is little-endian, unlike every length in the protocol.
        XCTAssertEqual(WireGuardHandshake.readLe32(message, 4), 0x0102_0304)
        XCTAssertEqual(message[4], 0x04)

        // mac2 is zero until the peer sends a cookie.
        XCTAssertEqual(Array(message[132..<148]), [UInt8](repeating: 0, count: 16))
    }

    func testMac1ProvesKnowledgeOfThePeerPublicKey() throws {
        // A server drops a message whose mac1 does not verify without doing any
        // asymmetric work, which is what makes flooding it expensive.
        let client = Support.keyPair()
        let server = Support.keyPair()

        let message = try WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
            .buildInitiation()

        let expected = WireGuardCrypto.mac(
            key: WireGuardCrypto.hash(Array("mac1----".utf8), server.publicKey),
            data: Array(message[0..<116])
        )
        XCTAssertEqual(Array(message[116..<132]), expected)
    }

    func testTwoInitiationsNeverRepeatTheirEphemeralKey() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let a = try WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey).buildInitiation()
        let b = try WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey).buildInitiation()
        XCTAssertNotEqual(Array(a[8..<40]), Array(b[8..<40]))
    }

    // MARK: - Full handshake

    func testAHandshakeWithAnIndependentResponderAgreesOnTheTransportKeys() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let initiation = try handshake.buildInitiation(index: 42)

        let responder = try Support.respond(initiation, responderPrivate: server.privateKey, responderPublic: server.publicKey)

        // The responder recovered who we are and when we said it.
        XCTAssertEqual(responder.initiatorStatic, client.publicKey)
        XCTAssertEqual(responder.timestamp.count, 12)

        let keys = try handshake.consumeResponse(responder.response)
        XCTAssertEqual(keys.localIndex, 42)
        XCTAssertEqual(keys.peerIndex, 0x1122_3344)

        // What one side sends with, the other receives with.
        XCTAssertEqual(keys.sendKey, responder.receiveKey)
        XCTAssertEqual(keys.receiveKey, responder.sendKey)
        XCTAssertNotEqual(keys.sendKey, keys.receiveKey)
    }

    func testAPacketEncryptedWithTheAgreedKeysOpensOnTheOtherSide() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let responder = try Support.respond(try handshake.buildInitiation(), responderPrivate: server.privateKey, responderPublic: server.publicKey)
        let keys = try handshake.consumeResponse(responder.response)

        let packet = Array("an IP packet".utf8)
        let sealed = try WireGuardCrypto.seal(key: keys.sendKey, counter: 0, plaintext: packet, aad: [])
        XCTAssertEqual(WireGuardCrypto.open(key: responder.receiveKey, counter: 0, ciphertext: sealed, aad: []), packet)
    }

    func testAPresharedKeyChangesTheTransportKeysAndBothSidesMustHaveIt() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()
        let psk: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 5) }

        // Both sides with the same PSK: agreement, and different keys from the
        // no-PSK case.
        let withPsk = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey, presharedKey: psk)
        let response = try Support.respond(try withPsk.buildInitiation(), responderPrivate: server.privateKey, responderPublic: server.publicKey, presharedKey: psk)
        let keys = try withPsk.consumeResponse(response.response)
        XCTAssertEqual(keys.sendKey, response.receiveKey)

        let withoutPsk = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let plainResponse = try Support.respond(try withoutPsk.buildInitiation(), responderPrivate: server.privateKey, responderPublic: server.publicKey)
        XCTAssertNotEqual(keys.sendKey, try withoutPsk.consumeResponse(plainResponse.response).sendKey)

        // A mismatched PSK fails the response's authentication rather than
        // producing keys that silently do not work.
        let mismatched = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey, presharedKey: psk)
        let plainForMismatch = try Support.respond(try mismatched.buildInitiation(), responderPrivate: server.privateKey, responderPublic: server.publicKey)
        XCTAssertThrowsError(try mismatched.consumeResponse(plainForMismatch.response))
    }

    func testTheWrongServerKeyFailsAtTheResponderNotSilentlyLater() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()
        let wrong = Support.keyPair()

        // The client believes the server has a key it does not.
        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: wrong.publicKey)
        let initiation = try handshake.buildInitiation()
        XCTAssertThrowsError(try Support.respond(initiation, responderPrivate: server.privateKey, responderPublic: server.publicKey))
    }

    // MARK: - Malformed responses

    func testAMalformedResponseIsRefused() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let good = try Support.respond(try handshake.buildInitiation(index: 7), responderPrivate: server.privateKey, responderPublic: server.publicKey).response

        var wrongType = good
        WireGuardHandshake.writeLe32(&wrongType, 0, WireGuardHandshake.messageInitiation)
        // Echoes somebody else's index.
        var otherIndex = good
        WireGuardHandshake.writeLe32(&otherIndex, 8, 99)
        // Tampered ephemeral.
        var tampered = good
        tampered[12] ^= 1

        let bads: [[UInt8]] = [[], Array(good[0..<(WireGuardHandshake.responseSize - 1)]), good + [0], wrongType, otherIndex, tampered]
        for bad in bads {
            let fresh = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
            _ = try fresh.buildInitiation(index: 7)
            XCTAssertThrowsError(try fresh.consumeResponse(bad), "a \(bad.count)-byte response")
        }
    }

    func testARefusedResponseLeavesTheHandshakeAbleToFinish() throws {
        // A forged or mangled reply must not spoil the state the genuine one
        // needs: the handshake keeps nothing from a response it refused.
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
        let responder = try Support.respond(try handshake.buildInitiation(index: 5), responderPrivate: server.privateKey, responderPublic: server.publicKey)

        var forged = responder.response
        forged[50] ^= 0xFF
        XCTAssertThrowsError(try handshake.consumeResponse(forged))

        let keys = try handshake.consumeResponse(responder.response)
        XCTAssertEqual(keys.sendKey, responder.receiveKey)
    }

    // MARK: - AmneziaWG wire tweaks

    func testH1ReplacesTheWholeInitiationTypeWord() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let handshake = WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            initiationType: 0x1A2B_3C4D
        )
        let message = try handshake.buildInitiation(index: 7)

        XCTAssertEqual(message.count, WireGuardHandshake.initiationSize)
        XCTAssertEqual(Array(message[0..<4]), [0x4D, 0x3C, 0x2B, 0x1A])
    }

    func testPlainWireGuardWritesType1WithThreeZeroBytes() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let message = try WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
            .buildInitiation(index: 7)
        XCTAssertEqual(Array(message[0..<4]), [1, 0, 0, 0])
    }

    func testS1PrependsJunkWithoutDisturbingTheMessageBehindIt() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let junkSize = 15
        let plain = try WireGuardHandshake(localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey)
            .buildInitiation(index: 7)
        let junked = try WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            initiationJunkSize: junkSize
        ).buildInitiation(index: 7)

        XCTAssertEqual(junked.count, WireGuardHandshake.initiationSize + junkSize)
        // The type word starts after the junk, not at offset 0.
        XCTAssertEqual(WireGuardHandshake.readLe32(junked, junkSize), 1)
        // Index is echoed in the same place relative to the message start.
        XCTAssertEqual(WireGuardHandshake.readLe32(plain, 4), WireGuardHandshake.readLe32(junked, junkSize + 4))
        // And the message behind the junk is one a responder accepts.
        let responder = try Support.respond(Array(junked[junkSize...]), responderPrivate: server.privateKey, responderPublic: server.publicKey)
        XCTAssertEqual(responder.initiatorStatic, client.publicKey)
    }

    func testS2JunkIsStrippedFromTheResponseBeforeItIsParsed() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()

        let junkSize = 30
        let handshake = WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            responseJunkSize: junkSize
        )
        let initiation = try handshake.buildInitiation(index: 7)
        let responder = try Support.respond(initiation, responderPrivate: server.privateKey, responderPublic: server.publicKey)

        let keys = try handshake.consumeResponse(WireGuardCrypto.randomBytes(junkSize) + responder.response)
        XCTAssertEqual(keys.localIndex, 7)
        XCTAssertEqual(keys.sendKey, responder.receiveKey)
    }

    func testH2RenumbersTheResponseTypeOnTheWholeWord() throws {
        let client = Support.keyPair()
        let server = Support.keyPair()
        let h2: UInt32 = 0x2A3B_4C5D

        let handshake = WireGuardHandshake(
            localPrivateKey: client.privateKey, localPublicKey: client.publicKey, peerPublicKey: server.publicKey,
            responseType: h2
        )
        let responder = try Support.respond(try handshake.buildInitiation(index: 7), responderPrivate: server.privateKey, responderPublic: server.publicKey)

        // A response still carrying type 2 is not this peer's response...
        XCTAssertThrowsError(try handshake.consumeResponse(responder.response))
        // ...and one with H2 is, every octet of it.
        var renumbered = responder.response
        WireGuardHandshake.writeLe32(&renumbered, 0, h2)
        XCTAssertEqual(Array(renumbered[0..<4]), [0x5D, 0x4C, 0x3B, 0x2A])
        let keys = try handshake.consumeResponse(renumbered)
        XCTAssertEqual(keys.sendKey, responder.receiveKey)
    }

    // MARK: - Helpers

    func testLittleEndianHelpersRoundTrip() {
        var buffer = [UInt8](repeating: 0, count: 8)
        for value: UInt32 in [0, 1, UInt32.max, 0x7FFF_FFFF, 0x8000_0000, 0x0102_0304] {
            WireGuardHandshake.writeLe32(&buffer, 0, value)
            XCTAssertEqual(WireGuardHandshake.readLe32(buffer, 0), value)
            XCTAssertEqual(WireGuardHandshake.readLe32(Data(buffer), 0), value)
        }
        for value: UInt64 in [0, 1, UInt64.max, 0x7FFF_FFFF_FFFF_FFFF, 0x0102_0304_0506_0708] {
            WireGuardHandshake.writeLe64(&buffer, 0, value)
            XCTAssertEqual(WireGuardHandshake.readLe64(buffer, 0), value)
            XCTAssertEqual(WireGuardHandshake.readLe64(Data(buffer), 0), value)
        }
        WireGuardHandshake.writeLe32(&buffer, 0, 0x0102_0304)
        XCTAssertEqual(Array(buffer[0..<4]), [0x04, 0x03, 0x02, 0x01])
        // A slice that does not start at index 0 is read from its own start.
        let sliced = Data([0xFF, 0x04, 0x03, 0x02, 0x01])[1...]
        XCTAssertEqual(WireGuardHandshake.readLe32(sliced, 0), 0x0102_0304)
    }
}
