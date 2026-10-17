import Foundation
import XCTest
@testable import MythaiaKit

/// BLAKE2s pinned to published vectors and to values from an independent
/// implementation, never to what this port emits.
///
/// RFC 7693 gives one plain vector and a self-test that hashes every digest
/// length WireGuard could use, keyed and unkeyed, over inputs straddling the
/// 64-byte block; the reference package's KAT gives the keyed vectors. The
/// rest (block boundaries, HMAC, HKDF) were computed with Python's hashlib
/// and hmac modules, which share no code with this one.
final class Blake2sTests: XCTestCase {
    private func hexString(_ bytes: [UInt8]) -> String { WireGuardTestSupport.hexString(bytes) }

    private let key32: [UInt8] = (0..<32).map { UInt8($0) }

    func testRfc7693Vector() {
        XCTAssertEqual(
            hexString(Blake2s.hash(Array("abc".utf8))),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        )
    }

    func testTheEmptyInputIsOneZeroBlock() {
        XCTAssertEqual(
            hexString(Blake2s.hash([])),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        )
    }

    func testKeyedVectorsOfTheReferenceKat() {
        // Key 00..1f; inputs empty and a single zero byte. The empty one is
        // the key block alone, compressed as the last block.
        XCTAssertEqual(
            hexString(Blake2s.hash([], key: key32)),
            "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"
        )
        XCTAssertEqual(
            hexString(Blake2s.hash([0], key: key32)),
            "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"
        )
    }

    /// RFC 7693 Appendix E: every digest length in {16, 20, 28, 32} over
    /// inputs of {0, 3, 64, 65, 255, 1024} bytes, plain and keyed with a key
    /// as long as the digest, all hashed into one 32-byte result.
    func testRfc7693SelfTest() {
        func sequence(_ length: Int, seed: UInt32) -> [UInt8] {
            var a: UInt32 = 0xDEAD_4BAD &* seed
            var b: UInt32 = 1
            var out: [UInt8] = []
            for _ in 0..<length {
                let t = a &+ b
                a = b
                b = t
                out.append(UInt8(truncatingIfNeeded: t >> 24))
            }
            return out
        }

        var grand = Blake2s(outputLength: 32)
        for outputLength in [16, 20, 28, 32] {
            for inputLength in [0, 3, 64, 65, 255, 1024] {
                let input = sequence(inputLength, seed: UInt32(inputLength))
                grand.update(Blake2s.hash(input, outputLength: outputLength))
                let key = sequence(outputLength, seed: UInt32(outputLength))
                grand.update(Blake2s.hash(input, outputLength: outputLength, key: key))
            }
        }
        XCTAssertEqual(
            hexString(grand.finalize()),
            "6a411f08ce25adcdfb02aba641451cec53c598b24f4fc787fbdc88797f4c1dfe"
        )
    }

    func testBlockBoundaries() {
        // The last block, full or not, carries the final flag: a full block
        // compressed too early (or a partial one too late) changes these.
        let expected: [(Int, String)] = [
            (55, "f4495470f226c8c214be08fdfad4bc4a2a9dbea9136a210df0d4b64929e6fc14"),
            (64, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"),
            (65, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"),
            (128, "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"),
            (129, "5bd169e67c82c2c2e98ef7008bdf261f2ddf30b1c00f9e7f275bb3e8a28dc9a2"),
            (1000, "1c067a5e746fb0f6734efac9a8cdb0e11061f0077f255184365c690115392501"),
        ]
        for (length, digest) in expected {
            let input = [UInt8](ProtocolTestStreams.sequence(length))
            XCTAssertEqual(hexString(Blake2s.hash(input)), digest, "input length \(length)")
        }
    }

    func testFeedingInPiecesIsFeedingItWhole() {
        let input = [UInt8](ProtocolTestStreams.sequence(1000))
        let whole = Blake2s.hash(input, key: key32)
        for piece in [1, 7, 63, 64, 65, 500] {
            var hasher = Blake2s(key: key32)
            var at = 0
            while at < input.count {
                let end = min(input.count, at + piece)
                hasher.update(input[at..<end])
                at = end
            }
            XCTAssertEqual(hasher.finalize(), whole, "pieces of \(piece)")
        }
    }

    func testAShortDigestIsNotThePrefixOfALongOne() {
        // The length is in the parameter block, so a 16-byte MAC has to be
        // asked for at 16 bytes: cutting a 32-byte one down gives other bytes.
        let message = Array("message".utf8)
        let short = Blake2s.hash(message, outputLength: 16, key: key32)
        let long = Blake2s.hash(message, outputLength: 32, key: key32)
        XCTAssertEqual(hexString(short), "2b75eb9c63ca8524ff53d01905b406eb")
        XCTAssertEqual(hexString(long), "fce1b30584dffd5fb5809dda7b1359f4bac57620ba220df3fdbd8d6411b66d1d")
        XCTAssertNotEqual(short, Array(long[0..<16]))
    }

    func testHmacOverBlake2s() {
        XCTAssertEqual(
            hexString(Blake2s.hmac(key: key32, data: Array("input".utf8))),
            "bbe722d569a4845b94c23b9ae71c3dc04877099c376a541d26f313ca7348fd3a"
        )
        // A key longer than the block is hashed first, as RFC 2104 says.
        XCTAssertEqual(
            hexString(Blake2s.hmac(key: [UInt8](repeating: 0xAA, count: 100), data: Array("data".utf8))),
            "e5ef37ed9204f4a5d0bb1c1d9b1d72c9ff61eb6ad7f78ce8d54798b2d8107c46"
        )
    }

    func testHkdfOverHmacBlake2s() {
        let blocks = Blake2s.hkdf(salt: key32, input: Array("input".utf8), count: 3)
        XCTAssertEqual(blocks.count, 3)
        XCTAssertEqual(hexString(blocks[0]), "87b7f70b24183c6db5dc4f6d9f4c47cdb203321aa2a0bef714896adb3107a040")
        XCTAssertEqual(hexString(blocks[1]), "538a02e1eb2e31b7e4d4b82476d1fe2acf50085d3fb584537279195f5d1f5824")
        XCTAssertEqual(hexString(blocks[2]), "9ad858025593be88de0f9442a589cfe84a88dc19e4753d93684d1c5efc4837f9")
    }
}
