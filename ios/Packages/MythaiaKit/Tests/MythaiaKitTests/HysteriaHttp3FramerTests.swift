import Foundation
import XCTest
@testable import MythaiaKit

/// Frame-layer tests written against RFC 9114 rather than against the encoder.
///
/// Every expected byte string below is spelled out as literals worked out from
/// the specification's own field layouts and registered codepoints — the frame
/// type registry in §11.2.1, the frame definitions in §7.2, the error codes in
/// §8.1, and QUIC's varint rules from RFC 9000 §16 for the lengths. A codec
/// checked by encoding and then decoding its own output only proves it is
/// self-consistent, which is exactly the property a wrong codec also has.
final class HysteriaHttp3FramerTests: XCTestCase {

    /// Asserts that no proper prefix of a complete frame parses. This is the
    /// property the QUIC stream reader leans on: a read can end on any byte
    /// boundary, including inside a varint.
    private func assertEveryTruncationIsIncomplete(_ frame: [UInt8],
                                                   file: StaticString = #filePath, line: UInt = #line) {
        for length in 0..<frame.count {
            XCTAssertEqual(
                Http3Framer.parse(Array(frame[0..<length])),
                Http3Framer.ParseResult.incomplete,
                "a \(length)-byte prefix of a \(frame.count)-byte frame must not parse",
                file: file, line: line
            )
        }
    }

    /// The frame and byte count of a complete parse, or a failure.
    private func completeFrame(_ result: Http3Framer.ParseResult,
                               file: StaticString = #filePath,
                               line: UInt = #line) -> (frame: Http3Framer.Frame, consumed: Int)? {
        if case .complete(let frame, let consumed) = result {
            return (frame, consumed)
        }
        XCTFail("expected a complete frame, got \(result)", file: file, line: line)
        return nil
    }

    private let hello: [UInt8] = Array("hello".utf8)

    // MARK: - Registered codepoints

    func testFrameTypeCodesAreTheOnesRfc9114Registers() {
        XCTAssertEqual(Http3FrameType.data.rawValue, 0x00)
        XCTAssertEqual(Http3FrameType.headers.rawValue, 0x01)
        XCTAssertEqual(Http3FrameType.cancelPush.rawValue, 0x03)
        XCTAssertEqual(Http3FrameType.settings.rawValue, 0x04)
        XCTAssertEqual(Http3FrameType.pushPromise.rawValue, 0x05)
        XCTAssertEqual(Http3FrameType.goaway.rawValue, 0x07)
        XCTAssertEqual(Http3FrameType.maxPushId.rawValue, 0x0D)
    }

    func testTheCodepointsHttp2BurnedHaveNoNameHere() {
        // RFC 9114 §11.2.1 reserves 0x02, 0x06, 0x08 and 0x09 because HTTP/2
        // used them; receiving one is H3_FRAME_UNEXPECTED, so a lookup that
        // resolved them to a usable type would be actively wrong.
        for reserved: Int64 in [0x02, 0x06, 0x08, 0x09] {
            XCTAssertNil(Http3FrameType(rawValue: reserved),
                         "0x\(String(reserved, radix: 16)) must not name a frame type")
        }
    }

    func testSettingsIdentifiersAreTheOnesTheirRfcsRegister() {
        XCTAssertEqual(Http3SettingsId.qpackMaxTableCapacity.rawValue, 0x01)
        XCTAssertEqual(Http3SettingsId.maxFieldSectionSize.rawValue, 0x06)
        XCTAssertEqual(Http3SettingsId.qpackBlockedStreams.rawValue, 0x07)
        XCTAssertEqual(Http3SettingsId.enableConnectProtocol.rawValue, 0x08)
        XCTAssertEqual(Http3SettingsId.h3Datagram.rawValue, 0x33)
    }

    func testErrorCodesAreTheRfc9114Section8Point1Table() {
        XCTAssertEqual(Http3ErrorCode.noError.rawValue, 0x0100)
        XCTAssertEqual(Http3ErrorCode.generalProtocolError.rawValue, 0x0101)
        XCTAssertEqual(Http3ErrorCode.internalError.rawValue, 0x0102)
        XCTAssertEqual(Http3ErrorCode.streamCreationError.rawValue, 0x0103)
        XCTAssertEqual(Http3ErrorCode.closedCriticalStream.rawValue, 0x0104)
        XCTAssertEqual(Http3ErrorCode.frameUnexpected.rawValue, 0x0105)
        XCTAssertEqual(Http3ErrorCode.frameError.rawValue, 0x0106)
        XCTAssertEqual(Http3ErrorCode.excessiveLoad.rawValue, 0x0107)
        XCTAssertEqual(Http3ErrorCode.idError.rawValue, 0x0108)
        XCTAssertEqual(Http3ErrorCode.settingsError.rawValue, 0x0109)
        XCTAssertEqual(Http3ErrorCode.missingSettings.rawValue, 0x010A)
        XCTAssertEqual(Http3ErrorCode.requestRejected.rawValue, 0x010B)
        XCTAssertEqual(Http3ErrorCode.requestCancelled.rawValue, 0x010C)
        XCTAssertEqual(Http3ErrorCode.requestIncomplete.rawValue, 0x010D)
        XCTAssertEqual(Http3ErrorCode.messageError.rawValue, 0x010E)
        XCTAssertEqual(Http3ErrorCode.connectError.rawValue, 0x010F)
        XCTAssertEqual(Http3ErrorCode.versionFallback.rawValue, 0x0110)

        // The registered range is contiguous, so a gap or a typo above would
        // still be caught even if the same mistake were made twice.
        XCTAssertEqual(Http3ErrorCode.allCases.count, 17)
        for (index, code) in Http3ErrorCode.allCases.enumerated() {
            XCTAssertEqual(code.rawValue, 0x0100 + Int64(index))
        }
    }

    // MARK: - DATA

    func testADataFrameIsType0x00ThenALengthThenTheBody() throws {
        // RFC 9114 §7.2.1. "hello" is 5 bytes, so the length is the one-byte
        // varint 0x05, and the ASCII follows unchanged.
        let expected: [UInt8] = [0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
        XCTAssertEqual(Http3Framer.dataFrame(hello), expected)

        let parsed = Http3Framer.parse(expected)
        XCTAssertEqual(
            parsed,
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x00, payload: hello), bytesConsumed: 7)
        )
        let frame = try XCTUnwrap(completeFrame(parsed)).frame
        XCTAssertEqual(frame.knownType, Http3FrameType.data)
    }

    func testAnEmptyDataFrameIsTwoBytesAndItsOnlyPrefixIsIncomplete() {
        let expected: [UInt8] = [0x00, 0x00]
        XCTAssertEqual(Http3Framer.dataFrame([]), expected)
        XCTAssertEqual(
            Http3Framer.parse(expected),
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x00, payload: []), bytesConsumed: 2)
        )
        assertEveryTruncationIsIncomplete(expected)
    }

    // MARK: - HEADERS

    func testAHeadersFrameIsType0x01WrappedAroundAnOpaqueFieldSection() {
        // The payload is the encoded field section from RFC 9204 Appendix B.1:
        // a 2-byte prefix of zeroes, then a literal field line with a static
        // name reference to :path, then the 11-byte value "/index.html".
        // Fifteen bytes in total, so the frame's length varint is 0x0F.
        let headerBlock: [UInt8] = [
            0x00, 0x00, 0x51, 0x0B,
            0x2F, 0x69, 0x6E, 0x64, 0x65, 0x78, 0x2E, 0x68, 0x74, 0x6D, 0x6C,
        ]
        XCTAssertEqual(headerBlock.count, 15)

        let expected: [UInt8] = [
            0x01, 0x0F,
            0x00, 0x00, 0x51, 0x0B,
            0x2F, 0x69, 0x6E, 0x64, 0x65, 0x78, 0x2E, 0x68, 0x74, 0x6D, 0x6C,
        ]
        XCTAssertEqual(Http3Framer.headersFrame(headerBlock), expected)

        XCTAssertEqual(
            Http3Framer.parse(expected),
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x01, payload: headerBlock), bytesConsumed: 17)
        )
        assertEveryTruncationIsIncomplete(expected)
    }

    // MARK: - SETTINGS

    func testTheClientSettingsFrameIsByteForByteWhatTheSettingsSayItShouldBe() {
        // Payload, per RFC 9114 §7.2.4, is identifier/value varint pairs:
        //   0x01 0x00                -> QPACK_MAX_TABLE_CAPACITY = 0
        //   0x07 0x00                -> QPACK_BLOCKED_STREAMS = 0
        //   0x06 0x80 0x04 0x00 0x00 -> MAX_FIELD_SECTION_SIZE = 262144, which
        //                               is above 16383 so RFC 9000 §16 puts it
        //                               in the four-byte form 0x80 | 0x00040000
        //   0x08 0x01                -> ENABLE_CONNECT_PROTOCOL = 1
        //   0x33 0x01                -> H3_DATAGRAM = 1
        // Thirteen payload bytes, behind type 0x04 and length 0x0D.
        let expected: [UInt8] = [
            0x04, 0x0D,
            0x01, 0x00,
            0x07, 0x00,
            0x06, 0x80, 0x04, 0x00, 0x00,
            0x08, 0x01,
            0x33, 0x01,
        ]
        XCTAssertEqual(Http3Framer.clientSettingsFrame(), expected)
        XCTAssertEqual(Http3Framer.fieldSectionSizeLimit, 262_144)
        assertEveryTruncationIsIncomplete(expected)
    }

    func testASettingsPayloadReadsBackAsThePairsTheWireBytesDescribe() throws {
        let wire: [UInt8] = [
            0x04, 0x0D,
            0x01, 0x00,
            0x07, 0x00,
            0x06, 0x80, 0x04, 0x00, 0x00,
            0x08, 0x01,
            0x33, 0x01,
        ]
        let parsed = try XCTUnwrap(completeFrame(Http3Framer.parse(wire)))
        XCTAssertEqual(parsed.frame.knownType, Http3FrameType.settings)
        XCTAssertEqual(parsed.consumed, 15)

        XCTAssertEqual(
            Http3Framer.parseSettings(parsed.frame.payload),
            [
                Http3Setting(id: 1, value: 0),
                Http3Setting(id: 7, value: 0),
                Http3Setting(id: 6, value: 262_144),
                Http3Setting(id: 8, value: 1),
                Http3Setting(id: 0x33, value: 1),
            ]
        )
    }

    func testASettingsPairThatRunsOffTheEndOfItsPayloadIsRefused() {
        // An identifier with no value, and a value varint that claims two bytes
        // but supplies one. Both are H3_SETTINGS_ERROR, not short reads: the
        // frame length already said where the payload ends.
        XCTAssertNil(Http3Framer.parseSettings([0x01]))
        XCTAssertNil(Http3Framer.parseSettings([0x01, 0x00, 0x06, 0x40]))
        XCTAssertEqual(Http3Framer.parseSettings([]), [])
    }

    func testARepeatedSettingsIdentifierIsReportedRatherThanCollapsed() {
        // RFC 9114 §7.2.4.1 makes a duplicate identifier a connection error, so
        // the parser has to hand both occurrences over for the caller to notice.
        XCTAssertEqual(
            Http3Framer.parseSettings([0x06, 0x00, 0x06, 0x01]),
            [Http3Setting(id: 0x06, value: 0), Http3Setting(id: 0x06, value: 1)]
        )
    }

    // MARK: - Multi-byte varints

    func testALengthPast63MovesIntoTheTwoByteVarintForm() {
        // 64 is the first value RFC 9000 §16 cannot fit in one byte: the
        // two-byte form is 0x40 in the top bits and 64 in the remaining
        // fourteen, which is 0x40 0x40.
        let payload = [UInt8](repeating: 0xAB, count: 64)
        let frame = Http3Framer.dataFrame(payload)

        XCTAssertEqual(Array(frame.prefix(3)), [0x00, 0x40, 0x40])
        XCTAssertEqual(frame.count, 3 + 64)

        XCTAssertEqual(
            Http3Framer.parse(frame),
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x00, payload: payload), bytesConsumed: 67)
        )
        assertEveryTruncationIsIncomplete(frame)
    }

    func testALengthPast16383MovesIntoTheFourByteVarintForm() {
        // 16384 is 0x00004000, so the four-byte form is 0x80 0x00 0x40 0x00.
        let payload = (0..<16_384).map { UInt8(truncatingIfNeeded: $0) }
        let frame = Http3Framer.dataFrame(payload)

        XCTAssertEqual(Array(frame.prefix(5)), [0x00, 0x80, 0x00, 0x40, 0x00])
        XCTAssertEqual(frame.count, 5 + 16_384)

        // Spot-checking the boundary rather than all 16389 prefixes: one byte
        // short is still incomplete, the exact size is the whole frame.
        XCTAssertEqual(Http3Framer.parse(Array(frame.dropLast())), Http3Framer.ParseResult.incomplete)
        XCTAssertEqual(
            Http3Framer.parse(frame),
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x00, payload: payload), bytesConsumed: frame.count)
        )
    }

    func testAFrameTypePast63AlsoTakesAMultiByteVarint() throws {
        // RFC 9114 §7.2.8 reserves types of the form 0x1f * N + 0x21. N = 1
        // gives 64, the first type that needs two bytes, encoded 0x40 0x40.
        let greased: Int64 = 0x1F * 1 + 0x21
        XCTAssertEqual(greased, 64)

        let frame = Http3Framer.frame(greased, [0xFF])
        XCTAssertEqual(frame, [0x40, 0x40, 0x01, 0xFF])

        let parsed = Http3Framer.parse(frame)
        XCTAssertEqual(
            parsed,
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 64, payload: [0xFF]), bytesConsumed: 4)
        )
        // Nothing names a greased type, and that is the point: it must survive
        // the parser intact so the caller can ignore it deliberately.
        XCTAssertNil(try XCTUnwrap(completeFrame(parsed)).frame.knownType)
        assertEveryTruncationIsIncomplete(frame)
    }

    func testALengthWrittenInALongerFormThanNeededIsStillAccepted() {
        // RFC 9000 §16 permits a non-minimal encoding, so a peer may send the
        // length 5 as the two-byte 0x40 0x05. Refusing it would be an interop
        // bug that only shows up against that one peer.
        let wire: [UInt8] = [0x00, 0x40, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
        XCTAssertEqual(
            Http3Framer.parse(wire),
            Http3Framer.ParseResult.complete(Http3Framer.Frame(type: 0x00, payload: hello), bytesConsumed: 8)
        )
    }

    // MARK: - Partial buffers and offsets

    func testAHeaderSplitInsideItsTypeVarintWaitsForMore() {
        // The two-byte type 0x40 0x40 with only its first byte present. There
        // is no length to read yet, and guessing one would desynchronise the
        // whole stream.
        XCTAssertEqual(Http3Framer.parse([0x40]), Http3Framer.ParseResult.incomplete)
        XCTAssertEqual(Http3Framer.parse([0x40, 0x40]), Http3Framer.ParseResult.incomplete)
        XCTAssertEqual(Http3Framer.parse([]), Http3Framer.ParseResult.incomplete)
    }

    func testAnExhaustedBufferIsIncompleteRatherThanAnError() {
        let frame = Http3Framer.dataFrame([0x01, 0x02])
        XCTAssertEqual(Http3Framer.parse(frame, offset: frame.count), Http3Framer.ParseResult.incomplete)
    }

    func testFramesArrivingBackToBackAreWalkedWithBytesConsumed() throws {
        let first = Http3Framer.headersFrame([0x00, 0x00, 0xD1])
        let second = Http3Framer.dataFrame(Array("hi".utf8))
        let stream = first + second

        let a = try XCTUnwrap(completeFrame(Http3Framer.parse(stream, offset: 0)))
        XCTAssertEqual(a.consumed, first.count)
        XCTAssertEqual(a.frame.knownType, Http3FrameType.headers)

        let b = try XCTUnwrap(completeFrame(Http3Framer.parse(stream, offset: a.consumed)))
        XCTAssertEqual(b.consumed, second.count)
        XCTAssertEqual(b.frame.knownType, Http3FrameType.data)
        XCTAssertEqual(b.frame.payload, Array("hi".utf8))

        XCTAssertEqual(
            Http3Framer.parse(stream, offset: a.consumed + b.consumed),
            Http3Framer.ParseResult.incomplete
        )
    }

    func testAFrameThatArrivesOneByteAtATimeParsesExactlyOnceAtTheEnd() {
        let frame = Http3Framer.clientSettingsFrame()
        var completions = 0
        for available in 0...frame.count {
            switch Http3Framer.parse(Array(frame[0..<available])) {
            case .complete(_, let consumed):
                completions += 1
                XCTAssertEqual(available, frame.count)
                XCTAssertEqual(consumed, frame.count)
            case .incomplete:
                break
            case .malformed(let reason):
                XCTFail("a truncated frame is not malformed: \(reason)")
            }
        }
        XCTAssertEqual(completions, 1)
    }

    func testATruncatedFrameAtANonZeroOffsetIsStillIncomplete() {
        let prefix = Http3Framer.dataFrame([0xAA])
        let frame = Http3Framer.clientSettingsFrame()
        let stream = prefix + frame

        for length in prefix.count..<stream.count {
            XCTAssertEqual(
                Http3Framer.parse(Array(stream[0..<length]), offset: prefix.count),
                Http3Framer.ParseResult.incomplete,
                "offset \(prefix.count) into a \(length)-byte buffer"
            )
        }
        XCTAssertNotNil(completeFrame(Http3Framer.parse(stream, offset: prefix.count)))
    }

    // MARK: - Bad input

    func testALengthNoBufferCouldEverHoldIsMalformedNotIncomplete() {
        // Type 0x00 then the largest varint, 2^62-1 in the eight-byte form.
        // Reporting this as incomplete would leave a reader buffering the
        // connection until the heap ran out.
        let wire: [UInt8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        let result = Http3Framer.parse(wire)
        if case .malformed = result {
            // expected
        } else {
            XCTFail("expected malformed, got \(result)")
        }
    }

    func testANegativeOffsetNeverYieldsAFrame() {
        // A negative offset is a caller's bug, not wire data. Whatever the
        // parser reports, it must not read before the start of the buffer and
        // hand back a frame made of it.
        let result = Http3Framer.parse(Http3Framer.dataFrame([]), offset: -1)
        if case .complete = result {
            XCTFail("a negative offset produced a frame: \(result)")
        }
    }

    // MARK: - Payload ownership

    func testAParsedPayloadDoesNotAliasTheBufferItCameFrom() throws {
        // A zero-copy slice would make the frame change under the caller as
        // soon as the receive buffer is reused. Owning its bytes is what lets
        // a parsed frame outlive the read.
        var buffer = Http3Framer.dataFrame([0x11, 0x22, 0x33])
        let parsed = try XCTUnwrap(completeFrame(Http3Framer.parse(buffer)))

        buffer[2] = 0x99
        XCTAssertEqual(buffer[2], 0x99)
        XCTAssertEqual(parsed.frame.payload, [0x11, 0x22, 0x33])
    }

    func testFramesCompareByTheirBytesSoTestsCannotPassOnIdentityAlone() {
        let a = Http3Framer.Frame(type: 0x00, payload: [0x01, 0x02])
        let b = Http3Framer.Frame(type: 0x00, payload: [0x01, 0x02])
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, Http3Framer.Frame(type: 0x01, payload: [0x01, 0x02]))
        XCTAssertNotEqual(a, Http3Framer.Frame(type: 0x00, payload: [0x01, 0x03]))
    }

    // MARK: - Unidirectional stream types (RFC 9114 §6.2)
    //
    // The type is a varint, and reading it as a byte is a mistake that only
    // shows up against a peer that greases — which is a peer behaving correctly.

    func testTheStreamTypeRegistryValuesAreTheOnesTheRfcAssigns() {
        XCTAssertEqual(Http3Framer.streamTypeControl, 0x00)
        XCTAssertEqual(Http3Framer.streamTypePush, 0x01)
        XCTAssertEqual(Http3Framer.streamTypeQpackEncoder, 0x02)
        XCTAssertEqual(Http3Framer.streamTypeQpackDecoder, 0x03)
    }

    func testAControlStreamAnnouncesItselfInOneByte() {
        XCTAssertEqual(Http3Framer.uniStreamType(Http3Framer.streamTypeControl), [0x00])
    }

    func testTheStreamTypeDeclarationReadsBackWithTheBytesItUsed() {
        let encoded = Http3Framer.uniStreamType(Http3Framer.streamTypeQpackDecoder)
        XCTAssertEqual(Http3Framer.readUniStreamType(encoded), QuicVarInt.Decoded(value: 3, size: 1))
    }

    func testAGreasedStreamTypeIsReadAtItsFullWidthNotAsOneByte() throws {
        // Greased types are 0x1f * N + 0x21, which are large on purpose so that
        // an implementation reading a single byte misidentifies the stream.
        let greased: Int64 = 0x1F * 4 + 0x21
        let encoded = Http3Framer.uniStreamType(greased)
        let decoded = try XCTUnwrap(Http3Framer.readUniStreamType(encoded))

        XCTAssertEqual(decoded.value, greased)
        XCTAssertEqual(decoded.size, encoded.count)
    }

    func testAnEmptyBufferHasNoStreamTypeYet() {
        XCTAssertNil(Http3Framer.readUniStreamType([]))
    }

    func testAStreamTypeCutOffMidVarintWaitsRatherThanGuessing() {
        // 0x40 opens a two-byte varint, so one byte is not enough.
        XCTAssertNil(Http3Framer.readUniStreamType([0x40]))
    }

    func testTheOpeningOfAControlStreamIsItsTypeThenSettings() throws {
        let opening = Http3Framer.uniStreamType(Http3Framer.streamTypeControl) + Http3Framer.clientSettingsFrame()

        XCTAssertEqual(opening.first, 0x00)
        // What follows the type must parse as a SETTINGS frame; a server that
        // reads anything else here closes the connection.
        let rest = Array(opening.dropFirst())
        let parsed = try XCTUnwrap(completeFrame(Http3Framer.parse(rest)))
        XCTAssertEqual(parsed.frame.knownType, Http3FrameType.settings)
    }
}
