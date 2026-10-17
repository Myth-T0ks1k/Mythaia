import Foundation
import XCTest
@testable import MythaiaKit

/// Packet protection, checked against published numbers rather than against
/// itself.
///
/// The split follows the specifications. RFC 9001 does not define an AEAD — it
/// borrows all three from TLS 1.3 — so the algorithms are checked against the
/// numbered test cases in McGrew and Viega's GCM specification, the ones NIST
/// adopted, and against RFC 8439 §2.8.2 for ChaCha20-Poly1305. What RFC 9001
/// does define is how QUIC uses them: a 16-byte tag, a nonce built from the
/// packet number (§5.3), and the Initial keys every connection starts on
/// (§5.2, worked through in Appendix A). Those are checked against the RFC's
/// own text, through this module and through the vendored C stack the live
/// connection actually uses.
final class QuicCryptoUnitTests: XCTestCase {

    private func hex(_ text: String) -> [UInt8] {
        let digits = text.filter { !$0.isWhitespace }
        var out: [UInt8] = []
        out.reserveCapacity(digits.count / 2)
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            out.append(UInt8(digits[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    private func flipped(_ bytes: [UInt8], at index: Int, mask: UInt8 = 0x01) -> [UInt8] {
        var out = bytes
        out[index] ^= mask
        return out
    }

    // MARK: - RFC 9001 §5.3: what QUIC fixes

    func testTheTagIsSixteenBytesAndTheNonceTwelveForEverySuite() {
        XCTAssertEqual(QuicCrypto.tagLength, 16)
        XCTAssertEqual(QuicCrypto.nonceLength, 12)
    }

    func testTheKeyLengthsAreThoseOfTheTls13SuitesQuicAllows() {
        XCTAssertEqual(QuicCrypto.Aead.aes128Gcm.keyLength, 16)
        XCTAssertEqual(QuicCrypto.Aead.aes256Gcm.keyLength, 32)
        XCTAssertEqual(QuicCrypto.Aead.chacha20Poly1305.keyLength, 32)
    }

    func testSealingCostsExactlyTheTag() throws {
        let plaintext = (0..<37).map { UInt8($0) }
        for aead in QuicCrypto.Aead.allCases {
            let key = (0..<aead.keyLength).map { UInt8($0 + 1) }
            let nonce = [UInt8](repeating: 0, count: 12)
            let sealed = try QuicCrypto.seal(aead, key: key, nonce: nonce, plaintext: plaintext, aad: [])
            XCTAssertEqual(sealed.count, plaintext.count + 16, "\(aead)")
        }
    }

    func testThePacketNumberIsLeftPaddedAndExclusiveOredIntoTheIv() throws {
        // RFC 9001 §5.3: the reconstructed packet number in network byte
        // order, zero-padded on the left to the width of the IV, XOR the IV.
        XCTAssertEqual(
            try QuicCrypto.nonce(iv: [UInt8](repeating: 0, count: 12), packetNumber: 0x0102_0304_0506_0708),
            hex("00000000 0102030405060708")
        )

        // Packet number zero leaves the IV alone, which is what an XOR with
        // zero has to do — and is why the first packet's nonce is the IV.
        let iv = hex("fa044b2f42a3fd3b46fb255c")
        XCTAssertEqual(try QuicCrypto.nonce(iv: iv, packetNumber: 0), iv)

        // Only the trailing eight bytes can ever move, because a packet number
        // is at most 62 bits. Here the largest one QUIC can express.
        XCTAssertEqual(
            try QuicCrypto.nonce(iv: [UInt8](repeating: 0xFF, count: 12), packetNumber: QuicVarInt.max),
            hex("ffffffff c000000000000000")
        )
    }

    func testConsecutivePacketsGetNoncesThatDifferOnlyInTheLowBytes() throws {
        let iv = hex("0ac1493ca1905853b0bba03e")
        XCTAssertEqual(try QuicCrypto.nonce(iv: iv, packetNumber: 1), hex("0ac1493ca1905853b0bba03f"))
        XCTAssertEqual(try QuicCrypto.nonce(iv: iv, packetNumber: 2), hex("0ac1493ca1905853b0bba03c"))
        XCTAssertEqual(try QuicCrypto.nonce(iv: iv, packetNumber: 0x80), hex("0ac1493ca1905853b0bba0be"))
        XCTAssertEqual(try QuicCrypto.nonce(iv: iv, packetNumber: 0x100), hex("0ac1493ca1905853b0bba13e"))
    }

    func testAnIvTooShortToHoldAPacketNumberIsRefused() {
        for size in 0...7 {
            XCTAssertThrowsError(
                try QuicCrypto.nonce(iv: [UInt8](repeating: 0, count: size), packetNumber: 1),
                "expected a refusal for a \(size)-byte IV"
            )
        }
    }

    func testANegativePacketNumberIsABugRatherThanAWrap() {
        XCTAssertThrowsError(try QuicCrypto.nonce(iv: [UInt8](repeating: 0, count: 12), packetNumber: -1))
    }

    // MARK: - RFC 9001 §5.2 and Appendix A: the Initial keys

    func testTheInitialSecretsAreTheOnesAppendixADerives() {
        // Appendix A.1: the client picks 0x8394c8f03e515708 as the
        // destination connection id, and both directions' Initial secrets
        // follow from it and the version 1 salt alone.
        let secrets = QuicCrypto.initialSecrets(destinationConnectionId: hex("8394c8f03e515708"))
        XCTAssertEqual(secrets.client, hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"))
        XCTAssertEqual(secrets.server, hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"))
    }

    func testTheClientInitialPacketKeysAreTheOnesAppendixADerives() {
        // "quic key", "quic iv" and "quic hp" over the client secret. The
        // Initial packets are always AES-128-GCM, so the key is 16 bytes.
        let secret = hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        let keys = QuicCrypto.packetProtectionKeys(secret: secret, keyLength: 16)
        XCTAssertEqual(keys.key, hex("1f369613dd76d5467730efcbe3b1a22d"))
        XCTAssertEqual(keys.iv, hex("fa044b2f42a3fd3b46fb255c"))
        XCTAssertEqual(keys.hp, hex("9f50449e04a0e810283a1e9933adedd2"))
    }

    func testTheServerInitialPacketKeysAreTheOnesAppendixADerives() {
        let secret = hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        let keys = QuicCrypto.packetProtectionKeys(secret: secret, keyLength: 16)
        XCTAssertEqual(keys.key, hex("cf3a5331653c364c88f0f379b6067e37"))
        XCTAssertEqual(keys.iv, hex("0ac1493ca1905853b0bba03e"))
        XCTAssertEqual(keys.hp, hex("c206b8d9b9f0f37644430b490eeaa314"))
    }

    func testTheNativeStackReproducesAppendixA() {
        // The live tunnel seals and opens packets in the vendored C, not here.
        // Its self-test drives the same appendix through ngtcp2 and its
        // crypto backend and names the first step that disagrees.
        XCTAssertNil(QuicNativeSelfTest.run(), "the native QUIC stack disagrees with RFC 9001 Appendix A")
        XCTAssertFalse(QuicNativeSelfTest.ngtcp2Version.isEmpty)
    }

    // MARK: - AES-128-GCM, against McGrew and Viega's test cases

    func testGcmTestCase1AnEmptyMessageIsStillAuthenticated() throws {
        let sealed = try QuicCrypto.seal(
            .aes128Gcm,
            key: [UInt8](repeating: 0, count: 16),
            nonce: [UInt8](repeating: 0, count: 12),
            plaintext: [],
            aad: []
        )
        XCTAssertEqual(sealed, hex("58e2fccefa7e3061367f1d57a4e7455a"))
    }

    func testGcmTestCase2OneBlockUnderAZeroKey() throws {
        let sealed = try QuicCrypto.seal(
            .aes128Gcm,
            key: [UInt8](repeating: 0, count: 16),
            nonce: [UInt8](repeating: 0, count: 12),
            plaintext: [UInt8](repeating: 0, count: 16),
            aad: []
        )
        XCTAssertEqual(sealed, hex("0388dace60b6a392f328c2b971b2fe78 ab6e47d42cec13bdf53a67b21257bddf"))
    }

    func testGcmTestCase3FourBlocksNoAssociatedData() throws {
        let key = hex("feffe9928665731c6d6a8f9467308308")
        let nonce = hex("cafebabefacedbaddecaf888")
        let plaintext = hex("""
            d9313225f88406e5a55909c5aff5269a
            86a7a9531534f7da2e4c303d8a318a72
            1c3c0c95956809532fcf0e2449a6b525
            b16aedf5aa0de657ba637b391aafd255
            """)
        let expected = hex("""
            42831ec2217774244b7221b784d0d49c
            e3aa212f2c02a4e035c17e2329aca12e
            21d514b25466931c7d8f6a5aac84aa05
            1ba30b396a0aac973d58e091473f5985
            4d5c2af327cd64a62cf35abd2ba6fab4
            """)

        let sealed = try QuicCrypto.seal(.aes128Gcm, key: key, nonce: nonce, plaintext: plaintext, aad: [])
        XCTAssertEqual(sealed, expected)
        XCTAssertEqual(
            try QuicCrypto.open(.aes128Gcm, key: key, nonce: nonce, sealed: expected, aad: []),
            plaintext
        )
    }

    func testGcmTestCase4AssociatedDataChangesTheTagButNotTheCiphertext() throws {
        let key = hex("feffe9928665731c6d6a8f9467308308")
        let nonce = hex("cafebabefacedbaddecaf888")
        let plaintext = hex("""
            d9313225f88406e5a55909c5aff5269a
            86a7a9531534f7da2e4c303d8a318a72
            1c3c0c95956809532fcf0e2449a6b525
            b16aedf5aa0de657ba637b39
            """)
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let expected = hex("""
            42831ec2217774244b7221b784d0d49c
            e3aa212f2c02a4e035c17e2329aca12e
            21d514b25466931c7d8f6a5aac84aa05
            1ba30b396a0aac973d58e091
            5bc94fbc3221a5db94fae95ae7121a47
            """)

        let sealed = try QuicCrypto.seal(.aes128Gcm, key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        XCTAssertEqual(sealed, expected)

        // This is the property QUIC leans on: the header is the associated
        // data, so a rewritten header fails to open rather than decrypting to
        // something plausible.
        let tampered = flipped(aad, at: 0)
        XCTAssertNil(try QuicCrypto.open(.aes128Gcm, key: key, nonce: nonce, sealed: sealed, aad: tampered))
    }

    // MARK: - AES-256-GCM

    func testGcmTestCase13AnEmptyMessageUnderA256BitZeroKey() throws {
        let sealed = try QuicCrypto.seal(
            .aes256Gcm,
            key: [UInt8](repeating: 0, count: 32),
            nonce: [UInt8](repeating: 0, count: 12),
            plaintext: [],
            aad: []
        )
        XCTAssertEqual(sealed, hex("530f8afbc74536b9a963b4f1c4cb738b"))
    }

    func testGcmTestCase14OneBlockUnderA256BitZeroKey() throws {
        let sealed = try QuicCrypto.seal(
            .aes256Gcm,
            key: [UInt8](repeating: 0, count: 32),
            nonce: [UInt8](repeating: 0, count: 12),
            plaintext: [UInt8](repeating: 0, count: 16),
            aad: []
        )
        XCTAssertEqual(sealed, hex("cea7403d4d606b6e074ec5d3baf39d18 d0d1c8a799996bf0265b98b5d48ab919"))
    }

    // MARK: - ChaCha20-Poly1305, against RFC 8439 §2.8.2

    func testTheRfc8439AeadExample() throws {
        let key = hex("""
            808182838485868788898a8b8c8d8e8f
            909192939495969798999a9b9c9d9e9f
            """)
        let nonce = hex("070000004041424344454647")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        let expected = hex("""
            d31a8d34648e60db7b86afbc53ef7ec2
            a4aded51296e08fea9e2b5a736ee62d6
            3dbea45e8ca9671282fafb69da92728b
            1a71de0a9e060b2905d6a5b67ecd3b36
            92ddbd7f2d778b8c9803aee328091b58
            fab324e4fad675945585808b4831d7bc
            3ff4def08e4b7a9de576d26586cec64b
            6116
            1ae10b594f09e26a7e902ecbd0600691
            """)

        // The RFC's ciphertext and tag open under the RFC's key, nonce and
        // associated data, which only a correct key, nonce and tag layout
        // allows. What comes out is the RFC's 114-byte ASCII sentence: a
        // wrong keystream would turn it into bytes that are almost never all
        // printable.
        let plaintext = try XCTUnwrap(
            try QuicCrypto.open(.chacha20Poly1305, key: key, nonce: nonce, sealed: expected, aad: aad)
        )
        XCTAssertEqual(plaintext.count, 114)
        XCTAssertEqual(Array(plaintext.prefix(7)), Array("Ladies ".utf8))
        XCTAssertTrue(plaintext.allSatisfy { $0 >= 0x20 && $0 <= 0x7E })

        // Sealing it again reproduces the RFC's bytes exactly.
        let sealed = try QuicCrypto.seal(.chacha20Poly1305, key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        XCTAssertEqual(sealed, expected)
    }

    // MARK: - What a receiver does with a packet that will not open

    func testAFlippedByteAnywhereInTheSealedPacketFailsToOpen() throws {
        let plaintext = Array("one QUIC packet payload".utf8)
        let aad = hex("c300000001088394c8f03e51570800")

        for aead in QuicCrypto.Aead.allCases {
            let key = (0..<aead.keyLength).map { UInt8(truncatingIfNeeded: $0 * 7 + 3) }
            let nonce = try QuicCrypto.nonce(iv: (0..<12).map { UInt8($0) }, packetNumber: 42)
            let sealed = try QuicCrypto.seal(aead, key: key, nonce: nonce, plaintext: plaintext, aad: aad)
            XCTAssertEqual(try QuicCrypto.open(aead, key: key, nonce: nonce, sealed: sealed, aad: aad), plaintext)

            for index in 0..<sealed.count {
                let broken = flipped(sealed, at: index)
                XCTAssertNil(
                    try QuicCrypto.open(aead, key: key, nonce: nonce, sealed: broken, aad: aad),
                    "\(aead) at \(index)"
                )
            }
        }
    }

    func testTheWrongNonceOrTheWrongKeyOpensNothing() throws {
        let plaintext = Array("payload".utf8)
        let zeroIv = [UInt8](repeating: 0, count: 12)
        for aead in QuicCrypto.Aead.allCases {
            let key = (0..<aead.keyLength).map { UInt8($0 + 9) }
            let nonce = try QuicCrypto.nonce(iv: zeroIv, packetNumber: 5)
            let sealed = try QuicCrypto.seal(aead, key: key, nonce: nonce, plaintext: plaintext, aad: [])

            let neighbour = try QuicCrypto.nonce(iv: zeroIv, packetNumber: 6)
            XCTAssertNil(try QuicCrypto.open(aead, key: key, nonce: neighbour, sealed: sealed, aad: []), "\(aead)")

            let otherKey = flipped(key, at: 0, mask: 0x80)
            XCTAssertNil(try QuicCrypto.open(aead, key: otherKey, nonce: nonce, sealed: sealed, aad: []), "\(aead)")

            // Associated data that was not there when it was sealed.
            XCTAssertNil(try QuicCrypto.open(aead, key: key, nonce: nonce, sealed: sealed, aad: [0]), "\(aead)")
        }
    }

    func testAnythingShorterThanTheTagCannotBeAuthentic() throws {
        let key = [UInt8](repeating: 0, count: 16)
        let nonce = [UInt8](repeating: 0, count: 12)
        for size in 0..<QuicCrypto.tagLength {
            XCTAssertNil(
                try QuicCrypto.open(
                    .aes128Gcm, key: key, nonce: nonce, sealed: [UInt8](repeating: 0, count: size), aad: []
                ),
                "\(size) bytes"
            )
        }
        // Exactly the tag is the empty message, which does open.
        let empty = try QuicCrypto.seal(.aes128Gcm, key: key, nonce: nonce, plaintext: [], aad: [])
        XCTAssertEqual(empty.count, QuicCrypto.tagLength)
        XCTAssertNotNil(try QuicCrypto.open(.aes128Gcm, key: key, nonce: nonce, sealed: empty, aad: []))
    }

    func testAKeyOrNonceOfTheWrongLengthIsRefusedRatherThanPadded() {
        // A size mismatch is this side's bug, not something a network can
        // produce, so it is not folded into the nil that means "discard".
        for aead in QuicCrypto.Aead.allCases {
            XCTAssertThrowsError(
                try QuicCrypto.seal(
                    aead,
                    key: [UInt8](repeating: 0, count: aead.keyLength - 1),
                    nonce: [UInt8](repeating: 0, count: 12),
                    plaintext: [],
                    aad: []
                ),
                "expected a refusal for a short \(aead) key"
            )
            XCTAssertThrowsError(
                try QuicCrypto.seal(
                    aead,
                    key: [UInt8](repeating: 0, count: aead.keyLength),
                    nonce: [UInt8](repeating: 0, count: 8),
                    plaintext: [],
                    aad: []
                ),
                "expected a refusal for an 8-byte \(aead) nonce"
            )
            // Opening is held to the same rule: a wrong length throws rather
            // than reading as a packet that merely failed to authenticate.
            XCTAssertThrowsError(
                try QuicCrypto.open(
                    aead,
                    key: [UInt8](repeating: 0, count: aead.keyLength),
                    nonce: [UInt8](repeating: 0, count: 8),
                    sealed: [UInt8](repeating: 0, count: 16),
                    aad: []
                ),
                "expected a refusal for an 8-byte \(aead) nonce on open"
            )
        }
    }

    func testAPacketSealedUnderOneSuiteDoesNotOpenUnderAnother() throws {
        let key = (0..<32).map { UInt8($0) }
        let nonce = (0..<12).map { UInt8($0 + 1) }
        let plaintext = Array("cross-suite".utf8)

        let gcm = try QuicCrypto.seal(.aes256Gcm, key: key, nonce: nonce, plaintext: plaintext, aad: [])
        XCTAssertNil(try QuicCrypto.open(.chacha20Poly1305, key: key, nonce: nonce, sealed: gcm, aad: []))

        let chacha = try QuicCrypto.seal(.chacha20Poly1305, key: key, nonce: nonce, plaintext: plaintext, aad: [])
        XCTAssertNil(try QuicCrypto.open(.aes256Gcm, key: key, nonce: nonce, sealed: chacha, aad: []))
    }
}
