import Foundation
import XCTest
@testable import MythaiaKit

final class XHTTPChunkedTransferTests: XCTestCase {

    func testChunksComeOutAsTheyComplete() throws {
        let decoder = ChunkedTransferDecoder()
        try decoder.feed(Data("5\r\nhel".utf8))
        XCTAssertNil(try decoder.nextChunk())
        try decoder.feed(Data("lo\r\n3;ext=1\r\nabc\r\n0\r\n\r\n".utf8))
        XCTAssertEqual(try decoder.nextChunk(), Data("hello".utf8))
        XCTAssertEqual(try decoder.nextChunk(), Data("abc".utf8))
        XCTAssertNil(try decoder.nextChunk())
        XCTAssertTrue(decoder.isFinished)
    }

    func testABodyThatIsNotChunkedIsAnErrorNotAnEndlessWait() throws {
        let decoder = ChunkedTransferDecoder()
        try decoder.feed(Data("<html>not what was asked for</html>\r\n".utf8))
        XCTAssertThrowsError(try decoder.nextChunk()) { error in
            guard case .some(.httpError(_)) = error as? XHttpError else {
                return XCTFail("\(error)")
            }
        }
    }

    func testASizeLineThatNeverEndsIsAnErrorToo() throws {
        let decoder = ChunkedTransferDecoder()
        try decoder.feed(Data(repeating: 0x61, count: 2048))
        XCTAssertThrowsError(try decoder.nextChunk())
    }

    func testAChunkLargerThanWhatIsBufferedIsRefusedUpFront() throws {
        let decoder = ChunkedTransferDecoder()
        try decoder.feed(Data("ffffffff\r\n".utf8))
        XCTAssertThrowsError(try decoder.nextChunk())
    }

    func testPendingBytesAreCapped() throws {
        let decoder = ChunkedTransferDecoder()
        try decoder.feed(Data("3fffff\r\n".utf8))
        XCTAssertThrowsError(try decoder.feed(Data(count: ChunkedTransferDecoder.maxPendingBytes)))
    }

    func testTheEncoderWritesHexSizesAndTheTerminator() {
        XCTAssertEqual(ChunkedTransferEncoder.encode(Data("hello".utf8)), Data("5\r\nhello\r\n".utf8))
        let big = ChunkedTransferEncoder.encode(Data(repeating: 0x61, count: 255))
        XCTAssertEqual(Data([UInt8](big)[0..<4]), Data("ff\r\n".utf8))
        XCTAssertEqual(ChunkedTransferEncoder.encodeTerminator(), Data("0\r\n\r\n".utf8))
    }
}
