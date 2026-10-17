import Foundation
import XCTest
@testable import MythaiaKit

/// HPACK, checked against RFC 7541's own appendix examples.
///
/// The Huffman table and the integer encoding are the two places a
/// from-scratch HPACK usually goes wrong, and both have published vectors,
/// so this is verified against the RFC rather than against the encoder that
/// produced it.
final class HPACKTests: XCTestCase {

    private func hex(_ text: String) -> Data {
        TransportTestSupport.hex(text)
    }

    private func huffman(_ text: String) -> String? {
        HpackHuffman.decode(TransportTestSupport.bytes(text)).map { String(decoding: $0, as: UTF8.self) }
    }

    private func fields(_ pairs: [(String, String)]) -> [HpackHeader] {
        pairs.map { HpackHeader($0.0, $0.1) }
    }

    // MARK: - Huffman (RFC 7541 Appendix C.4)

    func testHuffmanDecodesTheRFCRequestExamples() {
        XCTAssertEqual(huffman("f1e3c2e5f23a6ba0ab90f4ff"), "www.example.com")
        XCTAssertEqual(huffman("a8eb10649cbf"), "no-cache")
        XCTAssertEqual(huffman("25a849e95ba97d7f"), "custom-key")
        XCTAssertEqual(huffman("25a849e95bb8e8b4bf"), "custom-value")
    }

    func testHuffmanDecodesTheResponseExamplesToo() {
        // C.6.1
        XCTAssertEqual(huffman("6402"), "302")
        XCTAssertEqual(huffman("aec3771a4b"), "private")
        XCTAssertEqual(huffman("d07abe941054d444a8200595040b8166e082a62d1bff"), "Mon, 21 Oct 2013 20:13:21 GMT")
    }

    func testMalformedHuffmanInputIsRefusedRatherThanHalfDecoded() {
        // A truncated code, and padding that is not all ones, are both errors
        // the RFC says to treat as a decoding failure.
        XCTAssertNil(huffman("ff"))
        // An over-long run of ones is the EOS symbol, which must not appear.
        XCTAssertNil(huffman("ffffffff"))
    }

    // MARK: - Integers (RFC 7541 Appendix C.1)

    func testIntegersEncodeAsTheRFCExamples() {
        XCTAssertEqual(HpackEncoder.encodeInteger(10, prefixBits: 5), [0x0A])
        XCTAssertEqual(HpackEncoder.encodeInteger(1337, prefixBits: 5), [0x1F, 0x9A, 0x0A])
        XCTAssertEqual(HpackEncoder.encodeInteger(42, prefixBits: 8), [0x2A])
    }

    // MARK: - Header decoding (RFC 7541 Appendix C.3)

    func testDecodesTheRFCRequestSequenceWithADynamicTable() {
        let decoder = HpackDecoder()

        // C.3.1, the first request.
        let first = decoder.decode(hex("828684 41 0f 7777772e6578616d706c652e636f6d"))
        XCTAssertEqual(first, fields([
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ]))

        // C.3.2: the second request refers back into the dynamic table the
        // first one populated. Decoding it right is the whole point of
        // keeping a decoder across blocks.
        let second = decoder.decode(hex("828684be 58 08 6e6f2d6361636865"))
        XCTAssertEqual(second, fields([
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ]))
    }

    func testDecodesHuffmanCodedLiterals() {
        // C.4.1: the same request as C.3.1 with the value Huffman-coded.
        let headers = HpackDecoder().decode(hex("828684 41 8c f1e3c2e5f23a6ba0ab90f4ff"))
        XCTAssertEqual(headers?.last, HpackHeader(":authority", "www.example.com"))
    }

    func testADecoderWithoutStateDoesNotResolveADynamicReference() {
        // 0xbe indexes the dynamic table, which is empty here.
        XCTAssertNil(HpackDecoder().decode(hex("be")))
    }

    func testTruncatedHeaderBlocksAreRefused() {
        // Each of these stops partway through a field; none may produce a
        // partial header list read past its end.
        let complete = TransportTestSupport.bytes("828684 41 0f 7777772e6578616d706c652e636f6d")
        for cut in 1..<complete.count {
            if let result = HpackDecoder().decode(Data(complete[0..<cut])) {
                // A prefix that happens to be a complete, shorter block is fine.
                XCTAssertLessThanOrEqual(result.count, 4, "cut \(cut) produced \(result)")
            }
        }
        XCTAssertNil(HpackDecoder().decode(Data(complete[0..<5])))
    }

    func testAnIndexOfZeroIsNotAHeader() {
        // RFC 7541 §6.1: index 0 is not usable and must be treated as an error.
        XCTAssertNil(HpackDecoder().decode(Data([0x80])))
    }

    // MARK: - Encoding

    func testABlockIsLiteralsWithoutIndexingNamedFromTheStaticTable() {
        // :method is static entry 2: 0000 0010, then "GET" raw.
        XCTAssertEqual([UInt8](HpackEncoder.encodeHeaderBlock([HpackHeader(":method", "GET")])),
                       TransportTestSupport.bytes("02 03 474554"))
        // A name not in the table is written out, lowercased.
        XCTAssertEqual([UInt8](HpackEncoder.encodeHeaderBlock([HpackHeader("X-Ab", "c")])),
                       TransportTestSupport.bytes("00 04 782d6162 01 63"))
    }

    func testAConnectRequestNamesTheMethodAndAuthorityFromTheStaticTable() {
        let block = HpackEncoder.encodeConnectRequest(authority: "example.com:443", extraHeaders: [])
        XCTAssertEqual(HpackDecoder().decode(block), fields([(":method", "CONNECT"), (":authority", "example.com:443")]))
    }

    func testExtraHeadersSurviveTheRoundTrip() {
        let extras = fields([
            ("user-agent", "Mozilla/5.0"),
            ("padding", String(repeating: "x", count: 200)),
            ("x-custom-name", "value"),
        ])
        let block = HpackEncoder.encodeConnectRequest(authority: "example.com:443", extraHeaders: extras)
        XCTAssertEqual(HpackDecoder().decode(block), fields([(":method", "CONNECT"), (":authority", "example.com:443")]) + extras)
    }

    func testALongValueCrossesTheIntegerContinuationBoundary() {
        // A string of 127 bytes or more needs HPACK's multi-byte integer form.
        for length in [126, 127, 128, 255, 256, 16383, 16384] {
            let value = String(repeating: "v", count: length)
            let block = HpackEncoder.encodeConnectRequest(authority: "h", extraHeaders: [HpackHeader("padding", value)])
            let decoded = HpackDecoder().decode(block)
            XCTAssertEqual(decoded?.last?.value, value, "length \(length)")
        }
    }

    func testANonASCIIValueRoundTripsAsUTF8() {
        let value = "значение値"
        let block = HpackEncoder.encodeConnectRequest(authority: "h", extraHeaders: [HpackHeader("x-name", value)])
        XCTAssertEqual(HpackDecoder().decode(block)?.last?.value, value)
    }

    func testTheDecoderCanBeResetBetweenConnections() {
        let decoder = HpackDecoder()
        _ = decoder.decode(hex("828684 41 0f 7777772e6578616d706c652e636f6d"))
        decoder.reset()
        // The dynamic entry the first block added is gone.
        XCTAssertNil(decoder.decode(hex("be")))
    }

    func testTheStatelessDecoderKeepsItsTableForOneBlock() {
        XCTAssertEqual(HpackEncoder.decodeHeaders(hex("40 05 782d666f6f 03 626172 be")),
                       fields([("x-foo", "bar"), ("x-foo", "bar")]))
        XCTAssertNil(HpackEncoder.decodeHeaders(hex("be")))
    }

    // MARK: - Dynamic table size (RFC 7541 §4)

    func testTheDynamicTableEvictsItsOldestEntriesAtItsSizeLimit() {
        // Each entry is 5 + 3 + 32 = 40 bytes: a 100-byte table holds two.
        let decoder = HpackDecoder(maxTableSize: 100)
        _ = decoder.decode(hex("40 05 782d666f6f 03 626172")) // x-foo: bar
        _ = decoder.decode(hex("40 05 782d626172 03 626172")) // x-bar: bar
        _ = decoder.decode(hex("40 05 782d62617a 03 626172")) // x-baz: bar, x-foo evicted

        XCTAssertEqual(decoder.decode(hex("be bf")), fields([("x-baz", "bar"), ("x-bar", "bar")]))
        // Index 64 was x-foo; the encoder knows it is gone, and so must we.
        XCTAssertNil(decoder.decode(hex("c0")))
    }

    func testAnEntryLargerThanTheTableEmptiesItAndIsNotAdded() {
        let decoder = HpackDecoder(maxTableSize: 50)
        _ = decoder.decode(hex("40 05 782d666f6f 03 626172")) // 40 bytes
        // 5 + 20 + 32 = 57 bytes: §4.4.
        var block = hex("40 05 782d626172 14")
        block.append(Data(repeating: 0x61, count: 20))
        _ = decoder.decode(block)
        XCTAssertNil(decoder.decode(hex("be")))
    }

    func testADynamicTableSizeUpdateShrinksTheTable() {
        let decoder = HpackDecoder()
        _ = decoder.decode(hex("40 05 782d666f6f 03 626172"))
        // A size update to 0: everything goes.
        XCTAssertEqual(decoder.decode(hex("20")), [])
        XCTAssertNil(decoder.decode(hex("be")))
        // Back up to the maximum (4096), and entries are kept again.
        XCTAssertEqual(decoder.decode(hex("3f e1 1f 40 05 782d666f6f 03 626172")), fields([("x-foo", "bar")]))
        XCTAssertEqual(decoder.decode(hex("be")), fields([("x-foo", "bar")]))
    }

    func testASizeUpdatePastWhatWeAdvertisedIsADecodingError() {
        // 5000 with a 5-bit prefix: 0x3f, then 4969 as e9 26. We advertised 4096.
        XCTAssertNil(HpackDecoder(maxTableSize: 4096).decode(hex("3f e9 26")))
        // Within a larger advertised size it is fine.
        XCTAssertEqual(HpackDecoder(maxTableSize: 65536).decode(hex("3f e9 26")), [])
    }
}
