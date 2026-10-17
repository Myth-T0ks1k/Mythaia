import Foundation
import XCTest
@testable import MythaiaKit

/// RFC 9000 §18. The encoding is checked against bytes written out by hand
/// from the specification, not against the decoder in the same file — the
/// two agree with each other whether or not they agree with a server.
final class QuicTransportParametersTests: XCTestCase {

    private typealias Parameter = QuicTuning.TransportParameter

    func testAnIntegerParameterIsIdLengthThenTheValueAsAVarint() {
        // initial_max_data (0x04) = 16384. 16384 needs the four-byte varint
        // form, so: id 04, length 04, value 80 00 40 00.
        let encoded = QuicTransportParameters.encode([
            Parameter(id: QuicTransportParameterId.initialMaxData, value: 16_384),
        ])
        XCTAssertEqual(encoded, [0x04, 0x04, 0x80, 0x00, 0x40, 0x00])
    }

    func testASmallValueTakesTheOneByteFormAndTheWholeParameterIsThreeBytes() {
        // initial_max_streams_uni (0x09) = 3 fits in one varint byte.
        let encoded = QuicTransportParameters.encode([
            Parameter(id: QuicTransportParameterId.initialMaxStreamsUni, value: 3),
        ])
        XCTAssertEqual(encoded, [0x09, 0x01, 0x03])
    }

    func testAFlagIsWrittenWithAZeroLengthRatherThanLeftOut() {
        // disable_active_migration carries no value; its presence is the whole
        // message, so omitting it would say the opposite of what was meant.
        let encoded = QuicTransportParameters.encode([
            Parameter(id: QuicTransportParameterId.disableActiveMigration, value: nil),
        ])
        XCTAssertEqual(encoded, [0x0c, 0x00])
    }

    func testParametersKeepTheOrderTheyWereGiven() {
        let encoded = QuicTransportParameters.encode([
            Parameter(id: QuicTransportParameterId.maxIdleTimeout, value: 30_000),
            Parameter(id: QuicTransportParameterId.initialMaxStreamsBidi, value: 1),
        ])
        // 30000 is a four-byte varint (80 00 75 30), then 08 01 01.
        XCTAssertEqual(encoded, [0x01, 0x04, 0x80, 0x00, 0x75, 0x30, 0x08, 0x01, 0x01])
    }

    func testWhatWasEncodedDecodesBackToTheSameParameters() {
        let original: [Parameter] = [
            Parameter(id: QuicTransportParameterId.maxIdleTimeout, value: 30_000),
            Parameter(id: QuicTransportParameterId.initialMaxData, value: Int64(64 * 1024 * 1024)),
            Parameter(id: QuicTransportParameterId.initialMaxStreamsBidi, value: 1024),
            Parameter(id: QuicTransportParameterId.disableActiveMigration, value: nil),
        ]
        let decoded = QuicTransportParameters.decode(QuicTransportParameters.encode(original))
        XCTAssertEqual(decoded, original)
    }

    func testAParameterThisBuildDoesNotKnowIsKeptNotDropped() throws {
        // RFC 9000 §18.1: an unknown transport parameter must be ignored rather
        // than treated as an error, and the caller may understand it even if
        // this object does not.
        // 0x3B is 59 in the one-byte form: the top two bits select the width,
        // so 0x7B would be a two-byte varint and mean something else entirely.
        let decoded = try XCTUnwrap(QuicTransportParameters.decode([0x3B, 0x01, 0x05]))
        XCTAssertEqual(decoded.count, 1)
        XCTAssertEqual(decoded.first?.id, 59)
        XCTAssertEqual(decoded.first?.value, 5)
    }

    func testATruncatedOrOverLongParameterIsRefusedRatherThanGuessedAt() {
        // Length runs past the end of the buffer.
        XCTAssertNil(QuicTransportParameters.decode([0x04, 0x08, 0x00]))
        // Length claims one byte but the varint inside needs four.
        XCTAssertNil(QuicTransportParameters.decode([0x04, 0x01, 0x80]))
        // A length that does not frame its value exactly.
        XCTAssertNil(QuicTransportParameters.decode([0x04, 0x04, 0x01, 0x00, 0x00, 0x00]))
        // An identifier cut off mid-varint.
        XCTAssertNil(QuicTransportParameters.decode([0x80]))
    }

    func testNothingAtAllDecodesToNothingAtAll() {
        let empty: [Parameter] = []
        XCTAssertEqual(QuicTransportParameters.decode([]), empty)
    }

    func testTheExtensionWrapperIsTheDraftFreeIdentifierAndATwoByteLength() {
        // 0x39 is the assigned value. A server that only knows the 0xffa5 the
        // drafts used will ignore this, so the number matters more than most.
        let body: [UInt8] = [0x09, 0x01, 0x03]
        let wrapped = QuicTransportParameters.asExtension(body)

        XCTAssertEqual(wrapped, [0x00, 0x39, 0x00, 0x03, 0x09, 0x01, 0x03])
        XCTAssertEqual(QuicTransportParameters.extensionType, 0x0039)
    }

    func testEveryTuningPresetEncodesAndDecodesBackUnchanged() {
        let presets: [(name: String, tuning: QuicTuning)] = [
            ("naive", QuicTuning.naive),
            ("nowhere", QuicTuning.nowhere),
        ]
        for (name, tuning) in presets {
            let encoded = QuicTransportParameters.encode(tuning.advertisedParameters)
            let decoded = QuicTransportParameters.decode(encoded)
            XCTAssertNotNil(decoded, name)
            XCTAssertEqual(decoded, tuning.advertisedParameters, name)
            // Small enough to sit in a ClientHello without pushing it over an
            // initial datagram, which would need a second flight to complete.
            XCTAssertLessThan(encoded.count, 128, "\(name): \(encoded.count) bytes")
        }
    }
}
