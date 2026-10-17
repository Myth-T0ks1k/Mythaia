import Foundation
import XCTest
@testable import MythaiaKit

/// Salamander against a vector computed from the specification, not from this
/// code: BLAKE2b-256("hunter2" ‖ 00..07), XORed over 0..39.
///
/// A round trip alone would pass just as happily with the wrong hash, the wrong
/// concatenation order, or the wrong key period — every one of which would look
/// fine locally and fail against a real Hysteria server.
final class HysteriaSalamanderObfuscatorTests: XCTestCase {

    private func makeObfuscator() throws -> SalamanderObfuscator {
        return try SalamanderObfuscator(password: "hunter2")
    }

    private func hexString(_ bytes: [UInt8]) -> String {
        return bytes.map { byte -> String in
            let digits = String(byte, radix: 16)
            return digits.count == 1 ? "0" + digits : digits
        }.joined()
    }

    private func bytes(_ hex: String) -> [UInt8] {
        let digits = Array(hex.utf8)
        var out: [UInt8] = []
        var index = 0
        while index + 1 < digits.count {
            let pair = String(decoding: digits[index..<(index + 2)], as: UTF8.self)
            guard let value = UInt8(pair, radix: 16) else {
                XCTFail("not hex: \(pair)")
                return []
            }
            out.append(value)
            index += 2
        }
        return out
    }

    func testTheKeystreamAndCiphertextMatchTheSpecification() throws {
        let obfuscator = try makeObfuscator()
        let salt = (0..<8).map { UInt8($0) }
        let payload = (0..<40).map { UInt8($0) }

        // Built by hand so `open` is exercised against bytes this code did not
        // produce: salt, then the expected ciphertext.
        let datagram = salt + bytes(
            "1c05ead77db308d53fd696368937ac1ea332d699072a9d7d49aa42c1a7696c2e3c25caf75d9328f5"
        )
        XCTAssertEqual(try XCTUnwrap(obfuscator.open(datagram)), payload)
    }

    func testASealedPacketOpensBackToItself() throws {
        let obfuscator = try makeObfuscator()
        let payload = (0..<1200).map { UInt8(truncatingIfNeeded: $0 * 7) }
        let sealed = obfuscator.seal(payload)
        XCTAssertEqual(sealed.count, SalamanderObfuscator.saltLength + payload.count)
        XCTAssertEqual(try XCTUnwrap(obfuscator.open(sealed)), payload)
    }

    func testEveryDatagramGetsAFreshSalt() throws {
        // The same salt twice would reuse the keystream, which for an XOR
        // cipher means the two packets XOR to each other's plaintext.
        let obfuscator = try makeObfuscator()
        let payload = [UInt8](repeating: 0x41, count: 64)
        var salts = Set<String>()
        for _ in 0..<64 {
            salts.insert(hexString(Array(obfuscator.seal(payload)[0..<8])))
        }
        XCTAssertEqual(salts.count, 64)
    }

    func testTheKeystreamRepeatsEvery32BytesAndNotSooner() throws {
        // A zero payload leaves the raw keystream, so its period is visible.
        let obfuscator = try makeObfuscator()
        let sealed = obfuscator.seal([UInt8](repeating: 0, count: 96))
        let stream = Array(sealed[8...])
        XCTAssertEqual(Array(stream[32..<64]), Array(stream[0..<32]))
        XCTAssertEqual(Array(stream[64..<96]), Array(stream[0..<32]))
    }

    func testADifferentPasswordGivesADifferentKeystream() throws {
        let obfuscator = try makeObfuscator()
        let payload = [UInt8](repeating: 0, count: 32)
        let salt = [UInt8](repeating: 9, count: 8)
        let other = try SalamanderObfuscator(password: "different")
        let mine = try XCTUnwrap(obfuscator.open(salt + payload))
        let theirs = try XCTUnwrap(other.open(salt + payload))
        XCTAssertNotEqual(mine, theirs)
    }

    func testADatagramTooShortToHoldASaltIsDroppedNotPassedThrough() throws {
        // Handing the raw bytes back would deliver un-deobfuscated data to
        // QUIC. The reference returns 0 bytes written, i.e. drops it.
        let obfuscator = try makeObfuscator()
        XCTAssertNil(obfuscator.open([UInt8](repeating: 1, count: 8)))
        XCTAssertNil(obfuscator.open([]))
        XCTAssertNil(obfuscator.open([UInt8](repeating: 0, count: 3)))
    }

    func testAPasswordBelowTheReferenceMinimumIsRefused() {
        XCTAssertThrowsError(try SalamanderObfuscator(password: "abc"), "expected a refusal for a 3-byte password")
    }
}
