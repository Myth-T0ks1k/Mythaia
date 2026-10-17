import Foundation
import XCTest
@testable import MythaiaKit

/// The WireGuard primitives, checked against published vectors rather than
/// against themselves.
///
/// A round trip through one implementation proves nothing about the wire: both
/// ends share any mistake. So the pieces that have RFC vectors are pinned to
/// them, and the rest to values computed by an independent implementation.
final class WireGuardCryptoTests: XCTestCase {
    private func hex(_ text: String) -> [UInt8] { WireGuardTestSupport.hex(text) }
    private func hexString(_ bytes: [UInt8]) -> String { WireGuardTestSupport.hexString(bytes) }

    // MARK: - BLAKE2s (RFC 7693)

    func testBlake2s256MatchesItsRfc7693Vector() {
        XCTAssertEqual(
            hexString(WireGuardCrypto.hash(Array("abc".utf8))),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        )
        // The empty input, which the construction hash effectively relies on
        // behaving like any other.
        XCTAssertEqual(WireGuardCrypto.hash([]).count, 32)
    }

    func testHashingSeveralPartsIsHashingTheirConcatenation() {
        // The handshake always hashes a running value followed by one field, so
        // a wrong order or a missing part would be invisible in a round trip.
        let a = Array("one".utf8)
        let b = Array("two".utf8)
        XCTAssertEqual(WireGuardCrypto.hash(a + b), WireGuardCrypto.hash(a, b))
        XCTAssertNotEqual(WireGuardCrypto.hash(a, b), WireGuardCrypto.hash(b, a))
    }

    func testKeyedBlake2sIsComputedAtTheRequestedLength() {
        let key: [UInt8] = (0..<32).map { UInt8($0) }
        let data = Array("message".utf8)

        let full = WireGuardCrypto.mac(key: key, data: data, length: 32)
        let short = WireGuardCrypto.mac(key: key, data: data, length: 16)
        XCTAssertEqual(full.count, 32)
        XCTAssertEqual(short.count, 16)

        // Computed independently: BLAKE2s keyed at a shorter digest length is
        // NOT the prefix of the longer one, which is why the length has to be
        // passed to the digest rather than sliced afterwards.
        XCTAssertEqual(hexString(short), "2b75eb9c63ca8524ff53d01905b406eb")
        XCTAssertNotEqual(short, Array(full[0..<16]))
    }

    /// The Noise constants every handshake starts from, as other WireGuard
    /// implementations hard-code them: C0 = HASH(CONSTRUCTION) and
    /// H0 = HASH(C0 ‖ IDENTIFIER).
    func testTheInitialChainingKeyAndHashAreTheProtocolsOwn() {
        let c = WireGuardCrypto.hash(WireGuardHandshake.construction)
        XCTAssertEqual(hexString(c), "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
        XCTAssertEqual(
            hexString(WireGuardCrypto.hash(c, WireGuardHandshake.identifier)),
            "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3"
        )
    }

    // MARK: - X25519 (RFC 7748 §6.1)

    func testX25519MatchesItsRfc7748Vector() throws {
        let alicePrivate = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let alicePublic = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        let bobPrivate = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

        XCTAssertEqual(try WireGuardCrypto.publicKey(alicePrivate), alicePublic)
        XCTAssertEqual(try WireGuardCrypto.publicKey(bobPrivate), bobPublic)
        let aliceShared = try WireGuardCrypto.sharedSecret(alicePrivate, bobPublic)
        let bobShared = try WireGuardCrypto.sharedSecret(bobPrivate, alicePublic)
        XCTAssertEqual(hexString(aliceShared), shared)
        XCTAssertEqual(hexString(bobShared), shared)
    }

    func testALowOrderPublicKeyIsRefusedRatherThanAgreedWith() {
        // These force an all-zero secret, which the peer also knows. Accepting
        // one would let anyone who can inject a key fix the session keys.
        let privateKey = WireGuardCrypto.generateKeyPair().privateKey
        var one = [UInt8](repeating: 0, count: 32)
        one[0] = 1
        for lowOrder in [
            [UInt8](repeating: 0, count: 32),
            one,
            hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ] {
            XCTAssertThrowsError(try WireGuardCrypto.sharedSecret(privateKey, lowOrder), hexString(lowOrder))
        }
    }

    func testKeysOfTheWrongSizeAreRefused() {
        XCTAssertThrowsError(try WireGuardCrypto.sharedSecret([UInt8](repeating: 1, count: 31), [UInt8](repeating: 9, count: 32)))
        XCTAssertThrowsError(try WireGuardCrypto.publicKey([UInt8](repeating: 1, count: 16)))
    }

    // MARK: - Nonce

    func testTheNonceIsFourZeroBytesThenALittleEndianCounter() {
        XCTAssertEqual(WireGuardCrypto.nonce(0), [UInt8](repeating: 0, count: 12))

        let one = WireGuardCrypto.nonce(1)
        XCTAssertEqual(Array(one[0..<4]), [0, 0, 0, 0])
        XCTAssertEqual(one[4], 1)
        XCTAssertEqual(one[11], 0)

        // Little-endian: the low byte comes first, which is the opposite of
        // every length field in the protocol and easy to get backwards.
        let big = WireGuardCrypto.nonce(0x0102_0304_0506_0708)
        XCTAssertEqual(big[4], 0x08)
        XCTAssertEqual(big[11], 0x01)
    }

    // MARK: - AEAD

    func testSealingAndOpeningRoundTripAndTheAadIsAuthenticated() throws {
        let key: [UInt8] = (0..<32).map { UInt8($0) }
        let plaintext = Array("the packet".utf8)
        let aad = Array("the running hash".utf8)

        let sealed = try WireGuardCrypto.seal(key: key, counter: 7, plaintext: plaintext, aad: aad)
        XCTAssertEqual(sealed.count, plaintext.count + WireGuardCrypto.tagSize)
        XCTAssertEqual(WireGuardCrypto.open(key: key, counter: 7, ciphertext: sealed, aad: aad), plaintext)

        // Every input is bound: a different counter, AAD or key all fail.
        XCTAssertNil(WireGuardCrypto.open(key: key, counter: 8, ciphertext: sealed, aad: aad))
        XCTAssertNil(WireGuardCrypto.open(key: key, counter: 7, ciphertext: sealed, aad: Array("other".utf8)))
        XCTAssertNil(WireGuardCrypto.open(key: [UInt8](repeating: 0, count: 32), counter: 7, ciphertext: sealed, aad: aad))

        var tampered = sealed
        tampered[0] ^= 1
        XCTAssertNil(WireGuardCrypto.open(key: key, counter: 7, ciphertext: tampered, aad: aad))
    }

    func testAnEmptyPlaintextSealsToJustTheTag() throws {
        // The handshake response encrypts nothing at all, so this is a real case.
        let key: [UInt8] = (0..<32).map { UInt8($0) }
        let sealed = try WireGuardCrypto.seal(key: key, counter: 0, plaintext: [], aad: Array("h".utf8))
        XCTAssertEqual(sealed.count, WireGuardCrypto.tagSize)
        XCTAssertEqual(WireGuardCrypto.open(key: key, counter: 0, ciphertext: sealed, aad: Array("h".utf8))?.count, 0)
    }

    // MARK: - XChaCha20-Poly1305 (cookie replies)

    func testACookieReplyOpensAsAnIndependentImplementationSealedIt() {
        // Sealed outside this code base with HChaCha20 (checked against the
        // draft's vector) and OpenSSL's ChaCha20-Poly1305: the cookie a0..af
        // under HASH("cookie--" ‖ server public key), nonce 50..67, with a
        // mac1 as the additional data.
        let reply = hex(
            "0300000004030201505152535455565758595a5b5c5d5e5f6061626364656667"
                + "434ae983237606e9a1418f2d1b7c33760aa463263048077619a0dcfbaa165378"
        )
        let key = hex("23b7a311e570828599f9fbae0fe93831e400ae7d2ffefbe021918af9313f1bb7")
        let mac1 = hex("3cddeab6b7a4b5abc57baf683ffd69e9")
        let cookie = WireGuardCrypto.xopen(key: key, nonce: Array(reply[8..<32]), ciphertext: Array(reply[32..<64]), aad: mac1)
        XCTAssertEqual(cookie, (0..<16).map { UInt8(0xA0 + $0) })

        // A different mac1 or a changed byte does not open: a reply cannot be
        // moved onto another initiation.
        var otherMac1 = mac1
        otherMac1[0] ^= 1
        XCTAssertNil(WireGuardCrypto.xopen(key: key, nonce: Array(reply[8..<32]), ciphertext: Array(reply[32..<64]), aad: otherMac1))
        var tampered = Array(reply[32..<64])
        tampered[3] ^= 0x80
        XCTAssertNil(WireGuardCrypto.xopen(key: key, nonce: Array(reply[8..<32]), ciphertext: tampered, aad: mac1))
    }

    // MARK: - KDF

    func testTheKdfIsHkdfOverHmacBlake2s() {
        let chainingKey: [UInt8] = (0..<32).map { UInt8($0) }
        let input = Array("input".utf8)

        // Written out here from RFC 5869 rather than called through the same
        // helper, so the chaining is checked against the construction.
        let prk = WireGuardCrypto.hmac(key: chainingKey, data: input)
        let t1 = WireGuardCrypto.hmac(key: prk, data: [0x01])
        let t2 = WireGuardCrypto.hmac(key: prk, data: t1 + [0x02])
        let t3 = WireGuardCrypto.hmac(key: prk, data: t2 + [0x03])

        let one = WireGuardCrypto.kdf(chainingKey, input, count: 1)
        XCTAssertEqual(one.count, 1)
        XCTAssertEqual(one[0], t1)

        let three = WireGuardCrypto.kdf(chainingKey, input, count: 3)
        XCTAssertEqual(three, [t1, t2, t3])
        XCTAssertTrue(three.allSatisfy { $0.count == 32 })
        // And the values themselves, from an independent HMAC.
        XCTAssertEqual(hexString(t1), "87b7f70b24183c6db5dc4f6d9f4c47cdb203321aa2a0bef714896adb3107a040")
    }

    // MARK: - TAI64N

    func testTheTimestampIsTai64nAndIncreasesWithTime() {
        let early = WireGuardCrypto.tai64n(millis: 1_000_000_000_000)
        let late = WireGuardCrypto.tai64n(millis: 1_000_000_001_000)
        XCTAssertEqual(early.count, 12)

        // The responder keeps the greatest timestamp per peer and rejects
        // anything not greater, so the byte order has to make later compare
        // greater lexicographically.
        XCTAssertTrue(hexString(late) > hexString(early))

        // The seconds field is the 2^62 base plus the Unix second count.
        let seconds: UInt64 = 1_000_000_000_000 / 1000
        var value: UInt64 = 0
        for index in 0..<8 {
            value = (value << 8) | UInt64(early[index])
        }
        XCTAssertEqual(value, 0x4000_0000_0000_000A + seconds)

        // Big-endian nanoseconds after it.
        XCTAssertEqual(hexString(WireGuardCrypto.tai64n(millis: 1_700_000_000_123)), "400000006553f10a0754d4c0")
    }

    // MARK: - Key encoding

    func testKeysRoundTripThroughBase64AsConfigsWriteThem() throws {
        let pair = WireGuardCrypto.generateKeyPair()
        XCTAssertEqual(pair.privateKey.count, 32)
        XCTAssertEqual(pair.publicKey.count, 32)
        XCTAssertEqual(try WireGuardCrypto.publicKey(pair.privateKey), pair.publicKey)

        let text = WireGuardConfig.encodeKey(Data(pair.publicKey))
        XCTAssertEqual(text.count, 44)
        XCTAssertEqual(WireGuardConfig.decodeKey(text), Data(pair.publicKey))
        XCTAssertEqual(WireGuardConfig.decodeKey("  \(text)  "), Data(pair.publicKey))
    }

    func testAnythingThatIsNotA32ByteKeyIsRefused() {
        XCTAssertNil(WireGuardConfig.decodeKey(""))
        XCTAssertNil(WireGuardConfig.decodeKey("not base64!!"))
        // Valid base64 of the wrong length is the case worth catching: it
        // decodes cleanly and would otherwise be used as a key.
        XCTAssertNil(WireGuardConfig.decodeKey(Data(count: 16).base64EncodedString()))
        XCTAssertNil(WireGuardConfig.decodeKey(Data(count: 33).base64EncodedString()))
    }
}
