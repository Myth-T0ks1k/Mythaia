import Foundation
import XCTest
@testable import MythaiaKit

/// RFC 9000 Appendix A.1 gives four worked examples of the varint encoding.
/// They are the test: a codec checked only against itself would agree with
/// its own mistakes.
final class QuicVarIntTests: XCTestCase {

    func testTheEightByteExampleFromTheRfc() throws {
        let bytes: [UInt8] = [0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C]
        XCTAssertEqual(QuicVarInt.decode(bytes), QuicVarInt.Decoded(value: 151_288_809_941_952_652, size: 8))
        XCTAssertEqual(try QuicVarInt.encode(151_288_809_941_952_652), bytes)
    }

    func testTheFourByteExampleFromTheRfc() throws {
        let bytes: [UInt8] = [0x9D, 0x7F, 0x3E, 0x7D]
        XCTAssertEqual(QuicVarInt.decode(bytes), QuicVarInt.Decoded(value: 494_878_333, size: 4))
        XCTAssertEqual(try QuicVarInt.encode(494_878_333), bytes)
    }

    func testTheTwoByteExampleFromTheRfc() throws {
        let bytes: [UInt8] = [0x7B, 0xBD]
        XCTAssertEqual(QuicVarInt.decode(bytes), QuicVarInt.Decoded(value: 15_293, size: 2))
        XCTAssertEqual(try QuicVarInt.encode(15_293), bytes)
    }

    func testTheOneByteExampleFromTheRfc() throws {
        let bytes: [UInt8] = [0x25]
        XCTAssertEqual(QuicVarInt.decode(bytes), QuicVarInt.Decoded(value: 37, size: 1))
        XCTAssertEqual(try QuicVarInt.encode(37), bytes)
    }

    func testTheRfcsTwoByteEncodingOfAValueThatFitsInOneIsStillRead() {
        // 0x40 0x25 is 37 written the long way. A decoder must accept it even
        // though an encoder would not produce it.
        XCTAssertEqual(QuicVarInt.decode([0x40, 0x25]), QuicVarInt.Decoded(value: 37, size: 2))
    }

    func testEachSizeBoundaryPicksTheShortestForm() {
        XCTAssertEqual(QuicVarInt.sizeOf(0), 1)
        XCTAssertEqual(QuicVarInt.sizeOf(63), 1)
        XCTAssertEqual(QuicVarInt.sizeOf(64), 2)
        XCTAssertEqual(QuicVarInt.sizeOf(16_383), 2)
        XCTAssertEqual(QuicVarInt.sizeOf(16_384), 4)
        XCTAssertEqual(QuicVarInt.sizeOf(1_073_741_823), 4)
        XCTAssertEqual(QuicVarInt.sizeOf(1_073_741_824), 8)
        XCTAssertEqual(QuicVarInt.sizeOf(QuicVarInt.max), 8)
    }

    func testEveryBoundaryValueSurvivesARoundTrip() throws {
        let values: [Int64] = [
            0, 1, 63, 64, 16_383, 16_384,
            1_073_741_823, 1_073_741_824, QuicVarInt.max,
        ]
        for value in values {
            let encoded = try QuicVarInt.encode(value)
            XCTAssertEqual(
                QuicVarInt.decode(encoded),
                QuicVarInt.Decoded(value: value, size: encoded.count),
                "value \(value)"
            )
        }
    }

    func testATruncatedVarintIsNothingRatherThanAGuess() {
        XCTAssertNil(QuicVarInt.decode([]))
        XCTAssertNil(QuicVarInt.decode([0x40]))
        XCTAssertNil(QuicVarInt.decode([0x80, 0x00]))
        XCTAssertNil(QuicVarInt.decode([0xC0, 0x00, 0x00, 0x00]))
        XCTAssertNil(QuicVarInt.decode([0x25], 1))
    }

    func testWritingAtAnOffsetLeavesTheRestOfTheBufferAlone() {
        var buffer = [UInt8](repeating: 0xEE, count: 6)
        let written = QuicVarInt.write(&buffer, 2, 15_293)
        XCTAssertEqual(written, 2)
        XCTAssertEqual(buffer, [0xEE, 0xEE, 0x7B, 0xBD, 0xEE, 0xEE])
        XCTAssertEqual(QuicVarInt.decode(buffer, 2), QuicVarInt.Decoded(value: 15_293, size: 2))
    }

    func testAValueTheEncodingCannotExpressIsRefused() {
        let refused: [Int64] = [-1, QuicVarInt.max + 1, Int64.max]
        for bad in refused {
            XCTAssertFalse(QuicVarInt.isEncodable(bad), "\(bad)")
            XCTAssertThrowsError(try QuicVarInt.encode(bad), "expected a refusal for \(bad)")
        }
    }
}
