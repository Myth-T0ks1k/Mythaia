import Foundation
import XCTest
@testable import MythaiaKit

/// What the WireGuard tests share: hex helpers, and a responder written out
/// from the WireGuard paper's own responder steps.
///
/// The responder is the point of the exercise: a client tested against itself
/// agrees with itself whatever the order of its operations. This one follows
/// the published sequence — including the one place the two sides genuinely
/// differ, where the responder's transport keys come out of KDF2 the other way
/// round — so an ordering mistake in the client shows up as keys that do not
/// match. It deliberately shares nothing with the client beyond the
/// primitives, which are pinned to vectors of their own.
enum WireGuardTestSupport {

    struct ResponderFailure: Error, CustomStringConvertible {
        let description: String
    }

    /// What the responder ends up with.
    struct ResponderResult {
        let response: [UInt8]
        let sendKey: [UInt8]
        let receiveKey: [UInt8]
        let initiatorStatic: [UInt8]
        let timestamp: [UInt8]
    }

    static let responderIndex: UInt32 = 0x1122_3344

    static func hex(_ text: String) -> [UInt8] {
        [UInt8](ProtocolTestStreams.hex(text))
    }

    static func hexString(_ bytes: [UInt8]) -> String {
        ProtocolTestStreams.hexString(Data(bytes))
    }

    static func hexString(_ data: Data) -> String {
        ProtocolTestStreams.hexString(data)
    }

    static func keyPair() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        WireGuardCrypto.generateKeyPair()
    }

    /// The responder half, step for step from the paper. Throws where a real
    /// responder would drop the initiation.
    static func respond(
        _ initiation: [UInt8],
        responderPrivate: [UInt8],
        responderPublic: [UInt8],
        presharedKey: [UInt8] = [UInt8](repeating: 0, count: 32),
        responderEphemeral: [UInt8]? = nil
    ) throws -> ResponderResult {
        guard initiation.count == WireGuardHandshake.initiationSize else {
            throw ResponderFailure(description: "initiation is \(initiation.count) bytes")
        }
        guard WireGuardHandshake.readLe32(initiation, 0) == WireGuardHandshake.messageInitiation else {
            throw ResponderFailure(description: "not an initiation")
        }

        let senderIndex = WireGuardHandshake.readLe32(initiation, 4)
        let initiatorEphemeral = Array(initiation[8..<40])
        let encryptedStatic = Array(initiation[40..<88])
        let encryptedTimestamp = Array(initiation[88..<116])

        var c = WireGuardCrypto.hash(WireGuardHandshake.construction)
        var h = WireGuardCrypto.hash(WireGuardCrypto.hash(c, WireGuardHandshake.identifier), responderPublic)

        c = WireGuardCrypto.kdf(c, initiatorEphemeral, count: 1)[0]
        h = WireGuardCrypto.hash(h, initiatorEphemeral)

        let es = try WireGuardCrypto.sharedSecret(responderPrivate, initiatorEphemeral)
        var derived = WireGuardCrypto.kdf(c, es, count: 2)
        c = derived[0]
        guard let initiatorStatic = WireGuardCrypto.open(key: derived[1], counter: 0, ciphertext: encryptedStatic, aad: h) else {
            throw ResponderFailure(description: "responder could not open the static key")
        }
        h = WireGuardCrypto.hash(h, encryptedStatic)

        let ss = try WireGuardCrypto.sharedSecret(responderPrivate, initiatorStatic)
        derived = WireGuardCrypto.kdf(c, ss, count: 2)
        c = derived[0]
        guard let timestamp = WireGuardCrypto.open(key: derived[1], counter: 0, ciphertext: encryptedTimestamp, aad: h) else {
            throw ResponderFailure(description: "responder could not open the timestamp")
        }
        h = WireGuardCrypto.hash(h, encryptedTimestamp)

        // --- response ---
        let ephemeralPrivate: [UInt8]
        let ephemeralPublic: [UInt8]
        if let given = responderEphemeral {
            ephemeralPrivate = given
            ephemeralPublic = try WireGuardCrypto.publicKey(given)
        } else {
            let pair = WireGuardCrypto.generateKeyPair()
            ephemeralPrivate = pair.privateKey
            ephemeralPublic = pair.publicKey
        }
        c = WireGuardCrypto.kdf(c, ephemeralPublic, count: 1)[0]
        h = WireGuardCrypto.hash(h, ephemeralPublic)

        let ee = try WireGuardCrypto.sharedSecret(ephemeralPrivate, initiatorEphemeral)
        c = WireGuardCrypto.kdf(c, ee, count: 1)[0]
        let se = try WireGuardCrypto.sharedSecret(ephemeralPrivate, initiatorStatic)
        c = WireGuardCrypto.kdf(c, se, count: 1)[0]

        let three = WireGuardCrypto.kdf(c, presharedKey, count: 3)
        c = three[0]
        h = WireGuardCrypto.hash(h, three[1])

        let empty = try WireGuardCrypto.seal(key: three[2], counter: 0, plaintext: [], aad: h)
        h = WireGuardCrypto.hash(h, empty)

        var body = [UInt8](repeating: 0, count: 12)
        WireGuardHandshake.writeLe32(&body, 0, WireGuardHandshake.messageResponse)
        WireGuardHandshake.writeLe32(&body, 4, responderIndex)
        WireGuardHandshake.writeLe32(&body, 8, senderIndex)
        body.append(contentsOf: ephemeralPublic)
        body.append(contentsOf: empty)

        let mac1 = WireGuardCrypto.mac(
            key: WireGuardCrypto.hash(Array("mac1----".utf8), initiatorStatic),
            data: body
        )
        let response = body + mac1 + [UInt8](repeating: 0, count: 16)

        // The responder's transport keys are KDF2 the other way round from the
        // initiator's: its send key is the initiator's receive key.
        let transport = WireGuardCrypto.kdf(c, [], count: 2)
        return ResponderResult(
            response: response,
            sendKey: transport[1],
            receiveKey: transport[0],
            initiatorStatic: initiatorStatic,
            timestamp: timestamp
        )
    }

    /// A wg-quick INI for a client with `privateKey` talking to `peerPublicKey`.
    static func ini(
        privateKey: [UInt8],
        peerPublicKey: [UInt8],
        extraInterface: String = "",
        extraPeer: String = ""
    ) -> String {
        """
        [Interface]
        PrivateKey = \(WireGuardConfig.encodeKey(Data(privateKey)))
        Address = 10.0.0.2/32
        \(extraInterface)

        [Peer]
        PublicKey = \(WireGuardConfig.encodeKey(Data(peerPublicKey)))
        Endpoint = 192.0.2.1:51820
        AllowedIPs = 0.0.0.0/0
        \(extraPeer)
        """
    }
}
