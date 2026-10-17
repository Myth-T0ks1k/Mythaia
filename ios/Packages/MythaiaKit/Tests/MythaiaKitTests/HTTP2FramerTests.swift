import Foundation
import XCTest
@testable import MythaiaKit

/// The frame-level details of RFC 9113 §4.1, §6.1 and §6.2 the session relies on.
final class HTTP2FramerTests: XCTestCase {

    private func hex(_ text: String) -> Data {
        TransportTestSupport.hex(text)
    }

    func testDataPaddingIsStrippedOnlyWhenTheFlagSaysSo() {
        let padded = Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: hex("02 61 62 00 00"))
        XCTAssertEqual(Http2Framer.dataPayload(padded), hex("61 62"))

        let plain = Http2Frame(type: .data, flags: 0, streamID: 1, payload: hex("02 61 62 00 00"))
        XCTAssertEqual(Http2Framer.dataPayload(plain), hex("02 61 62 00 00"))

        // All padding is allowed; padding past the payload is not.
        let empty = Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: hex("02 00 00"))
        XCTAssertEqual(Http2Framer.dataPayload(empty)?.count, 0)
        XCTAssertNil(Http2Framer.dataPayload(Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: hex("03 00 00"))))
        XCTAssertNil(Http2Framer.dataPayload(Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: Data())))
    }

    func testHeadersLoseTheirPaddingAndPriorityBlockBeforeHPACKSeesThem() {
        let flags = Http2FrameFlags.endHeaders | Http2FrameFlags.padded | Http2FrameFlags.priority
        let frame = Http2Frame(type: .headers, flags: flags, streamID: 1, payload: hex("01 80 00 00 03 ff 88 00"))
        XCTAssertEqual(Http2Framer.headerBlockFragment(frame), hex("88"))

        let priorityOnly = Http2Frame(type: .headers, flags: Http2FrameFlags.priority, streamID: 1, payload: hex("00 00 00 00 10 88"))
        XCTAssertEqual(Http2Framer.headerBlockFragment(priorityOnly), hex("88"))

        // A priority block that does not fit.
        XCTAssertNil(Http2Framer.headerBlockFragment(Http2Frame(type: .headers, flags: Http2FrameFlags.priority, streamID: 1, payload: hex("00 00"))))
    }

    func testContinuationIsAFrameTypeOfItsOwn() {
        let buffer = Http2Buffer()
        buffer.append(Http2Framer.serialize(Http2Frame(type: .continuation, flags: Http2FrameFlags.endHeaders, streamID: 3, payload: hex("88"))))
        let frame = Http2Framer.deserialize(buffer)
        XCTAssertEqual(frame?.type, .continuation)
        XCTAssertEqual(frame?.streamID, 3)
        XCTAssertEqual(frame?.payload, hex("88"))
    }

    func testFramesSerializeToTheWireFormat() {
        XCTAssertEqual(Http2Framer.serialize(Http2Framer.settingsAckFrame()), hex("000000 04 01 00000000"))
        XCTAssertEqual(Http2Framer.serialize(Http2Framer.windowUpdateFrame(streamID: 0, increment: 1_073_741_824)),
                       hex("000004 08 00 00000000 40000000"))
        XCTAssertEqual(Http2Framer.serialize(Http2Framer.dataFrame(streamID: 1, payload: Data("hi".utf8), endStream: true)),
                       hex("000002 00 01 00000001 6869"))
        XCTAssertEqual(Http2Framer.serialize(Http2Framer.settingsFrame([(0x2, 0), (0x4, 4_194_304)])),
                       hex("00000c 04 00 00000000 0002 00000000 0004 00400000"))
        XCTAssertEqual(Http2Framer.serialize(Http2Framer.rstStreamFrame(streamID: 5, errorCode: Http2Framer.ErrorCode.cancel)),
                       hex("000004 03 00 00000005 00000008"))
    }

    func testAFrameIsOnlyTakenOnceItIsComplete() {
        let buffer = Http2Buffer()
        let wire = Http2Framer.serialize(Http2Framer.dataFrame(streamID: 7, payload: Data("hello".utf8)))
        let bytes = [UInt8](wire)
        buffer.append(Data(bytes[0..<4]))
        XCTAssertNil(Http2Framer.deserialize(buffer))
        buffer.append(Data(bytes[4..<12]))
        XCTAssertNil(Http2Framer.deserialize(buffer))
        buffer.append(Data(bytes[12...]))
        let frame = Http2Framer.deserialize(buffer)
        XCTAssertEqual(frame, Http2Frame(type: .data, flags: 0, streamID: 7, payload: Data("hello".utf8)))
        XCTAssertTrue(buffer.isEmpty)
    }

    func testTheReservedBitOfTheStreamIDIsIgnored() {
        let buffer = Http2Buffer()
        buffer.append(hex("000000 06 00 80000003"))
        XCTAssertEqual(Http2Framer.deserialize(buffer)?.streamID, 3)
    }

    func testAnUnknownFrameTypeBecomesAnEmptyPlaceholder() {
        let buffer = Http2Buffer()
        // Type 0x2 (PRIORITY) on stream 3, five bytes.
        buffer.append(hex("000005 02 00 00000003 0000000010"))
        let frame = Http2Framer.deserialize(buffer)
        XCTAssertEqual(frame, Http2Frame(type: .data, flags: 0, streamID: 3, payload: Data()))
        XCTAssertTrue(buffer.isEmpty)
    }

    func testControlPayloadsParse() {
        let settings = Http2Framer.parseSettings(hex("0003 00000064 0004 00010000"))
        XCTAssertEqual(settings.count, 2)
        XCTAssertEqual(settings[0].0, 3)
        XCTAssertEqual(settings[0].1, 100)
        XCTAssertEqual(settings[1].0, 4)
        XCTAssertEqual(settings[1].1, 65_536)
        XCTAssertEqual(Http2Framer.parseWindowUpdate(hex("80000010")), 16)
        XCTAssertNil(Http2Framer.parseWindowUpdate(hex("0000")))
        XCTAssertEqual(Http2Framer.parseGoaway(hex("00000005 00000002")), Http2Framer.GoawayData(lastStreamID: 5, errorCode: 2))
        XCTAssertEqual(Http2Framer.parseRstStream(hex("00000008")), 8)
    }
}
