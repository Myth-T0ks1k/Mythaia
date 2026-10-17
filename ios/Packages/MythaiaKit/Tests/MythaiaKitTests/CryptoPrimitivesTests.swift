import Foundation
import XCTest
@testable import MythaiaKit

/// The primitives CryptoKit lacks, and the thin wrappers over the ones it
/// has, pinned against published vectors and against values computed by
/// OpenSSL — never against what this code itself emits.
final class CryptoPrimitivesTests: XCTestCase {
    private func hex(_ text: String) -> Data { ProtocolTestStreams.hex(text) }
    private func hexString(_ data: Data) -> String { ProtocolTestStreams.hexString(data) }
    private func hexString(_ bytes: [UInt8]) -> String { ProtocolTestStreams.hexString(Data(bytes)) }

    // MARK: - SHAKE128 / SHA3

    func testShake128OfEmptyInput() {
        var shake = Shake128()
        let out = shake.squeeze(32)
        XCTAssertEqual(hexString(out), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    }

    func testShake128OfTheFox() {
        var shake = Shake128(seed: Data("The quick brown fox jumps over the lazy dog".utf8))
        let out = shake.squeeze(32)
        XCTAssertEqual(hexString(out), "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e")
    }

    /// VMess reads the stream two bytes at a time, far past the 168-byte
    /// rate; every permutation boundary has to fall in the same place.
    func testShake128ReadInPiecesCrossesTheRateIntact() {
        var pieces = Shake128()
        var collected = [UInt8]()
        for _ in 0..<200 {
            collected.append(contentsOf: pieces.squeeze(2))
        }
        var whole = Shake128()
        let oneShot = whole.squeeze(400)
        XCTAssertEqual(collected, oneShot)
        // The last 32 of 400 bytes, from OpenSSL.
        XCTAssertEqual(hexString(Array(collected[368...])), "3a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b")
    }

    func testShake128SeededWithTheVmessTestIv() {
        var iv = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 {
            iv[i] = UInt8((i * 3) & 0xFF)
        }
        var shake = Shake128(seed: Data(iv))
        let out = shake.squeeze(8)
        XCTAssertEqual(hexString(out), "3d1613e6ca00ebbe")
    }

    func testCopyingAShakeForksTheStream() {
        var original = Shake128(seed: Data([1, 2, 3]))
        var copy = original
        let fromCopy = copy.squeeze(4)
        let fromOriginal = original.squeeze(4)
        XCTAssertEqual(fromCopy, fromOriginal)
    }

    func testSha3Vectors() {
        XCTAssertEqual(hexString(Keccak.sha3_256(Data())), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        XCTAssertEqual(hexString(Keccak.sha3_256(Data("abc".utf8))), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        // 200 bytes: absorbs across the 136-byte rate.
        let long = Data(repeating: 0x61, count: 200)
        XCTAssertEqual(hexString(Keccak.sha3_256(long)), "cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387")
    }

    // MARK: - Checksums

    func testFnv1aVectors() {
        XCTAssertEqual(FNV1a.hash32(Data()), 0x811C_9DC5)
        XCTAssertEqual(FNV1a.hash32(Data("a".utf8)), 0xE40C_292C)
        XCTAssertEqual(FNV1a.hash32(Data("foobar".utf8)), 0xBF9C_F968)
    }

    func testCrc32Vectors() {
        XCTAssertEqual(CRC32Checksum.compute(Data()), 0)
        XCTAssertEqual(CRC32Checksum.compute(Data("123456789".utf8)), 0xCBF4_3926)
    }

    // MARK: - Digests

    func testSha224() {
        XCTAssertEqual(hexString(DigestHelper.sha224(Data("abc".utf8))), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        XCTAssertEqual(hexString(DigestHelper.sha224(Data("pw".utf8))), "bebeef056d2fc0c96fbdd3372c8b766a0d3b5bac45cc56a4f15235cd")
    }

    // MARK: - AES

    func testAesEcbMatchesFips197() throws {
        let key = Data(Array(0..<16).map { UInt8($0) })
        let plain = hex("00112233445566778899aabbccddeeff")
        let cipher = try AesEcb.encrypt(key: key, block: plain)
        XCTAssertEqual(hexString(cipher), "69c4e0d86a7b0430d8cdb78070b4c55a")
        XCTAssertEqual(try AesEcb.decrypt(key: key, block: cipher), plain)
    }

    func testAesEcbRefusesAnythingButOneBlock() {
        XCTAssertThrowsError(try AesEcb.encrypt(key: Data(count: 16), block: Data(count: 15)))
        XCTAssertThrowsError(try AesEcb.encrypt(key: Data(count: 16), block: Data(count: 32)))
    }

    /// McGrew and Viega's GCM test cases 1 and 2: ciphertext then tag.
    func testAesGcmLayoutIsCiphertextThenTag() throws {
        let key = Data(count: 16)
        let nonce = Data(count: 12)
        let empty = try RawAEAD.aesGcmSeal(key: key, nonce: nonce, plaintext: Data())
        XCTAssertEqual(hexString(empty), "58e2fccefa7e3061367f1d57a4e7455a")

        let sealed = try RawAEAD.aesGcmSeal(key: key, nonce: nonce, plaintext: Data(count: 16))
        XCTAssertEqual(hexString(sealed), "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")

        let detached = try RawAEAD.aesGcmSealDetached(key: key, nonce: nonce, plaintext: Data(count: 16))
        XCTAssertEqual(hexString(detached.ciphertext), "0388dace60b6a392f328c2b971b2fe78")
        XCTAssertEqual(hexString(detached.tag), "ab6e47d42cec13bdf53a67b21257bddf")

        XCTAssertEqual(try RawAEAD.aesGcmOpen(key: key, nonce: nonce, sealed: sealed), Data(count: 16))
    }

    func testAesGcmRejectsATamperedTag() throws {
        let key = Data(count: 32)
        let nonce = Data(count: 12)
        var sealed = [UInt8](try RawAEAD.aesGcmSeal(key: key, nonce: nonce, plaintext: Data("secret".utf8), aad: Data([9])))
        sealed[sealed.count - 1] ^= 0x01
        XCTAssertThrowsError(try RawAEAD.aesGcmOpen(key: key, nonce: nonce, sealed: Data(sealed), aad: Data([9])))
    }

    // MARK: - ChaCha20-Poly1305

    /// RFC 8439 §2.8.2.
    func testChaChaPolyMatchesRfc8439() throws {
        let key = Data(Array(0x80...0x9F).map { UInt8($0) })
        let nonce = hex("070000004041424344454647")
        let aad = hex("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let sealed = try RawAEAD.chaChaPolySeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        let expected = "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
            + "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            + "3ff4def08e4b7a9de576d26586cec64b6116"
            + "1ae10b594f09e26a7e902ecbd0600691"
        XCTAssertEqual(hexString(sealed), expected)
        XCTAssertEqual(try RawAEAD.chaChaPolyOpen(key: key, nonce: nonce, sealed: sealed, aad: aad), plaintext)
    }

    // MARK: - XChaCha20-Poly1305

    /// draft-irtf-cfrg-xchacha §2.2.1.
    func testHChaCha20() {
        let key = Array(0..<32).map { UInt8($0) }
        let nonce = [UInt8](hex("000000090000004a0000000031415927"))
        let subkey = XChaCha20Poly1305.hChaCha20(key: key, nonce: nonce)
        XCTAssertEqual(hexString(subkey), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    /// The key and nonce of draft-irtf-cfrg-xchacha §A.3.1 sealing "hello"
    /// without AAD (Shadowsocks uses none); the expected bytes come from
    /// OpenSSL's ChaCha20-Poly1305 under the HChaCha20 subkey.
    func testXChaChaSealsAsTheDraftConstructs() throws {
        let key = Data(Array(0x80...0x9F).map { UInt8($0) })
        let nonce = Data(Array(0x40...0x57).map { UInt8($0) })
        let sealed = try XChaCha20Poly1305.seal(key: key, nonce: nonce, plaintext: Data("hello".utf8))
        XCTAssertEqual(hexString(sealed), "99691f98341dd36f38612714761a64a3525f94a617")
        XCTAssertEqual(try XChaCha20Poly1305.open(key: key, nonce: nonce, ciphertext: sealed), Data("hello".utf8))
    }

    // MARK: - HKDF

    func testHkdfSha256MatchesRfc5869Case1() {
        let okm = HKDFHelper.sha256(
            inputKeyMaterial: Data(repeating: 0x0B, count: 22),
            salt: Data(Array(0..<13).map { UInt8($0) }),
            info: Data(Array(0xF0...0xF9).map { UInt8($0) }),
            outputByteCount: 42
        )
        XCTAssertEqual(hexString(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    }

    func testHkdfSha1MatchesRfc5869Case4() {
        let okm = HKDFHelper.sha1(
            inputKeyMaterial: Data(repeating: 0x0B, count: 11),
            salt: Data(Array(0..<13).map { UInt8($0) }),
            info: Data(Array(0xF0...0xF9).map { UInt8($0) }),
            outputByteCount: 42
        )
        XCTAssertEqual(hexString(okm), "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896")
    }

    func testRandomBytesHaveTheLengthAsked() {
        XCTAssertEqual(CryptoRandom.bytes(0).count, 0)
        XCTAssertEqual(CryptoRandom.bytes(37).count, 37)
        XCTAssertNotEqual(CryptoRandom.bytes(32), CryptoRandom.bytes(32))
        XCTAssertEqual(CryptoRandom.int(below: 0), 0)
        for _ in 0..<100 {
            XCTAssertTrue((0..<7).contains(CryptoRandom.int(below: 7)))
        }
    }
}
