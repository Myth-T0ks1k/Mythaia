import Foundation
import XCTest
@testable import MythaiaKit

/// The padding algorithm, checked against the reference implementation's
/// `Session.writeConn` case by case.
///
/// Each case is worked out from the Go source rather than from this code,
/// which is the only way a test of a wire format means anything: a shaping
/// bug both ends share would round-trip perfectly and still be visible to
/// exactly the observer the scheme exists to defeat.
final class ProtocolAnyTlsShapingTests: XCTestCase {
    private func payload(_ n: Int) -> [UInt8] {
        return (0..<n).map { UInt8($0 % 251) }
    }

    func testPayloadLongerThanTheRecordIsCutAtTheRecordSize() {
        let writes = AnyTlsProtocol.shapeWrites(payload(100), sizes: [30])
        XCTAssertEqual(writes.count, 2)
        XCTAssertEqual(writes[0], Array(payload(100)[0..<30]))
        // The rest follows as its own write once the sizes run out.
        XCTAssertEqual(writes[1], Array(payload(100)[30..<100]))
    }

    func testShortPayloadIsToppedUpWithAWasteFrameToTheRecordSize() {
        // 20 bytes into a 100-byte record: 100 - 20 - 7 = 73 bytes of waste.
        let writes = AnyTlsProtocol.shapeWrites(payload(20), sizes: [100])
        XCTAssertEqual(writes.count, 1)
        XCTAssertEqual(writes[0].count, 100)
        let waste = AnyTlsProtocol.readHeader(writes[0], offset: 20)
        XCTAssertEqual(waste, AnyTlsProtocol.Header(command: AnyTlsProtocol.cmdWaste, streamId: 0, length: 73))
    }

    /// 96 into 100 leaves 4 bytes — less than a 7-byte header, so no waste
    /// frame fits and the record simply goes out short.
    func testSlackTooSmallForAFrameHeaderIsLeftAlone() {
        let writes = AnyTlsProtocol.shapeWrites(payload(96), sizes: [100])
        XCTAssertEqual(writes.count, 1)
        XCTAssertEqual(writes[0].count, 96)
    }

    func testExhaustedPayloadProducesARecordOfPureWaste() {
        let writes = AnyTlsProtocol.shapeWrites(payload(10), sizes: [10, 50])
        XCTAssertEqual(writes.count, 2)
        XCTAssertEqual(writes[0].count, 10)
        // The second record carries nothing but a waste frame of that length.
        XCTAssertEqual(writes[1].count, AnyTlsProtocol.headerSize + 50)
        let waste = AnyTlsProtocol.readHeader(writes[1])
        XCTAssertEqual(waste.command, AnyTlsProtocol.cmdWaste)
        XCTAssertEqual(waste.length, 50)
    }

    /// What keeps a small request from being followed by padding that would
    /// itself be the signature.
    func testCheckMarkStopsTheSequenceOnceThePayloadIsSpent() {
        let writes = AnyTlsProtocol.shapeWrites(payload(10), sizes: [10, AnyTlsProtocol.checkMark, 500, 500])
        XCTAssertEqual(writes.count, 1)
        XCTAssertEqual(writes[0].count, 10)
    }

    func testCheckMarkIsPassedOverWhilePayloadRemains() {
        let writes = AnyTlsProtocol.shapeWrites(payload(100), sizes: [30, AnyTlsProtocol.checkMark, 30])
        XCTAssertEqual(writes.map { $0.count }, [30, 30, 40])
    }

    func testNoSizesMeansOneWriteUnchanged() {
        let writes = AnyTlsProtocol.shapeWrites(payload(1234), sizes: [])
        XCTAssertEqual(writes, [payload(1234)])
    }

    func testEmptyPayloadWithNoSizesWritesNothing() {
        XCTAssertEqual(AnyTlsProtocol.shapeWrites([], sizes: []).count, 0)
    }

    /// Whatever the scheme does, it may only add waste — never drop or
    /// reorder what the caller asked to send.
    func testEveryByteOfThePayloadSurvivesTheShaping() {
        let original = payload(3000)
        let sizes = [400, AnyTlsProtocol.checkMark, 600, AnyTlsProtocol.checkMark, 900]
        let writes = AnyTlsProtocol.shapeWrites(original, sizes: sizes)

        var rebuilt = [UInt8]()
        for write in writes {
            var i = 0
            while i < write.count {
                // A waste frame is only ever appended whole at the end of a
                // record, so anything that is not one is payload.
                if write.count - i >= AnyTlsProtocol.headerSize {
                    let header = AnyTlsProtocol.readHeader(write, offset: i)
                    if header.command == AnyTlsProtocol.cmdWaste && i + AnyTlsProtocol.headerSize + header.length == write.count {
                        break
                    }
                }
                rebuilt.append(write[i])
                i += 1
            }
        }
        XCTAssertEqual(rebuilt, original)
    }

    /// "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000": a large
    /// payload uses every size; the checks never fire because data remains.
    func testDefaultSchemeShapesPacketTwoIntoNineRecordsAtMost() {
        let sizes = AnyTlsPaddingScheme.defaultScheme.recordSizes(2)
        let writes = AnyTlsProtocol.shapeWrites(payload(60_000), sizes: sizes)
        // Five sized records, then the remainder.
        XCTAssertEqual(writes.count, 6)
        XCTAssertTrue((400...500).contains(writes[0].count))
        for i in 1...4 {
            XCTAssertTrue((500...1000).contains(writes[i].count))
        }
    }
}
