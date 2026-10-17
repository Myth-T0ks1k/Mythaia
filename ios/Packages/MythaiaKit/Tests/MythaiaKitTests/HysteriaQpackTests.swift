import Foundation
import XCTest
@testable import MythaiaKit

/// QPACK, checked against RFC 9204's published values rather than against the
/// encoder that produced them.
///
/// Every expectation below comes from one of three places: the static table in
/// RFC 9204 Appendix A, the prefixed integer algorithm of RFC 9204 §4.1.1 (which
/// is RFC 7541 §5.1, so its Appendix C.1 examples apply verbatim), or the field
/// line diagrams of §4.5. The Huffman strings are RFC 7541 Appendix C.4's own.
/// A codec compared only with itself agrees with its own mistakes.
final class HysteriaQpackTests: XCTestCase {

    /// Bytes from hex digits; spaces are ignored so field lines can be grouped.
    private func hex(_ text: String) -> [UInt8] {
        let digits = Array(text.replacingOccurrences(of: " ", with: "").utf8)
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

    /// The UTF-8 bytes of `text` as hex digits, for splicing into `hex`.
    private func ascii(_ text: String) -> String {
        return text.utf8.map { byte -> String in
            let digits = String(byte, radix: 16)
            return digits.count == 1 ? "0" + digits : digits
        }.joined()
    }

    private func field(_ name: String, _ value: String) -> Http3Field {
        return Http3Field(name: name, value: value)
    }

    // MARK: - Static table (RFC 9204 Appendix A)

    func testStaticTableEntriesSitAtTheirPublishedIndices() {
        // A spread across the table, including the pseudo-headers this client
        // encodes by index and the non-contiguous status codes at 63 onwards.
        let published: [(index: Int64, name: String, value: String)] = [
            (0, ":authority", ""),
            (1, ":path", "/"),
            (2, "age", "0"),
            (4, "content-length", "0"),
            (14, "set-cookie", ""),
            (15, ":method", "CONNECT"),
            (16, ":method", "DELETE"),
            (17, ":method", "GET"),
            (18, ":method", "HEAD"),
            (19, ":method", "OPTIONS"),
            (20, ":method", "POST"),
            (21, ":method", "PUT"),
            (22, ":scheme", "http"),
            (23, ":scheme", "https"),
            (24, ":status", "103"),
            (25, ":status", "200"),
            (26, ":status", "304"),
            (27, ":status", "404"),
            (28, ":status", "503"),
            (29, "accept", "*/*"),
            (30, "accept", "application/dns-message"),
            (31, "accept-encoding", "gzip, deflate, br"),
            (32, "accept-ranges", "bytes"),
            (34, "access-control-allow-headers", "content-type"),
            (35, "access-control-allow-origin", "*"),
            (41, "cache-control", "public, max-age=31536000"),
            (44, "content-type", "application/dns-message"),
            (52, "content-type", "text/html; charset=utf-8"),
            (54, "content-type", "text/plain;charset=utf-8"),
            (55, "range", "bytes=0-"),
            (58, "strict-transport-security", "max-age=31536000; includesubdomains; preload"),
            (62, "x-xss-protection", "1; mode=block"),
            (63, ":status", "100"),
            (64, ":status", "204"),
            (65, ":status", "206"),
            (66, ":status", "302"),
            (67, ":status", "400"),
            (68, ":status", "403"),
            (69, ":status", "421"),
            (70, ":status", "425"),
            (71, ":status", "500"),
            (73, "access-control-allow-credentials", "FALSE"),
            (74, "access-control-allow-credentials", "TRUE"),
            (77, "access-control-allow-methods", "get, post, options"),
            (85, "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
            (91, "purpose", "prefetch"),
            (95, "user-agent", ""),
            (97, "x-frame-options", "deny"),
            (98, "x-frame-options", "sameorigin"),
        ]

        for entry in published {
            XCTAssertEqual(QpackEncoder.staticTableEntry(entry.index), field(entry.name, entry.value),
                           "index \(entry.index)")
        }
    }

    func testTheStaticTableStopsAt98() {
        // Appendix A defines 0...98; anything else is a decompression failure
        // rather than an entry to guess at.
        XCTAssertEqual(QpackEncoder.staticTableSize, 99)
        XCTAssertNotNil(QpackEncoder.staticTableEntry(98))
        XCTAssertNil(QpackEncoder.staticTableEntry(99))
        XCTAssertNil(QpackEncoder.staticTableEntry(-1))
        XCTAssertNil(QpackEncoder.staticTableEntry(Int64(Int32.max)))
    }

    // MARK: - Prefixed integers (RFC 9204 §4.1.1 / RFC 7541 Appendix C.1)

    func testTheRfc7541AppendixC1IntegerExamplesEncodeAsPublished() {
        // C.1.1: 10 in a 5-bit prefix fits, so it is one byte.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(10, prefixBits: 5, prefix: 0x00), hex("0a"))
        // C.1.2: 1337 in a 5-bit prefix fills the prefix and continues.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(1337, prefixBits: 5, prefix: 0x00), hex("1f9a0a"))
        // C.1.3: 42 starting at an octet boundary, i.e. an 8-bit prefix.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(42, prefixBits: 8, prefix: 0x00), hex("2a"))
    }

    func testTheRfc7541AppendixC1IntegerExamplesDecodeBack() {
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(hex("0a"), offset: 0, prefixBits: 5),
                       QpackEncoder.PrefixedInteger(value: 10, size: 1))
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(hex("1f9a0a"), offset: 0, prefixBits: 5),
                       QpackEncoder.PrefixedInteger(value: 1337, size: 3))
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(hex("2a"), offset: 0, prefixBits: 8),
                       QpackEncoder.PrefixedInteger(value: 42, size: 1))
    }

    /// For a prefix of N bits the largest single-byte value is 2^N - 2; 2^N - 1
    /// fills the prefix and forces a continuation byte even though the remainder
    /// is zero. These expectations are worked out from the RFC's pseudocode, one
    /// row per prefix width, rather than taken from the encoder's output.
    func testEveryPrefixWidthSpillsIntoContinuationBytesAtTheSameBoundary() {
        // Per prefix width, the encodings of the four values around and beyond
        // the boundary: mask-1, mask, mask+127, mask+128.
        let cases: [(prefixBits: Int, mask: Int64, expected: [String])] = [
            (1, 1, ["00", "0100", "017f", "018001"]),
            (2, 3, ["02", "0300", "037f", "038001"]),
            (3, 7, ["06", "0700", "077f", "078001"]),
            (4, 15, ["0e", "0f00", "0f7f", "0f8001"]),
            (5, 31, ["1e", "1f00", "1f7f", "1f8001"]),
            (6, 63, ["3e", "3f00", "3f7f", "3f8001"]),
            (7, 127, ["7e", "7f00", "7f7f", "7f8001"]),
            (8, 255, ["fe", "ff00", "ff7f", "ff8001"]),
        ]

        for testCase in cases {
            let values: [Int64] = [testCase.mask - 1, testCase.mask, testCase.mask + 127, testCase.mask + 128]
            for (value, wanted) in zip(values, testCase.expected) {
                let encoded = QpackEncoder.encodePrefixedInteger(value, prefixBits: testCase.prefixBits, prefix: 0x00)
                XCTAssertEqual(encoded, hex(wanted), "\(value) in \(testCase.prefixBits) bits")
                XCTAssertEqual(
                    QpackEncoder.decodePrefixedInteger(hex(wanted), offset: 0, prefixBits: testCase.prefixBits),
                    QpackEncoder.PrefixedInteger(value: value, size: hex(wanted).count),
                    "\(value) in \(testCase.prefixBits) bits"
                )
            }
        }
    }

    func testThePatternBitsAboveThePrefixArePreservedAndThenIgnored() {
        // An indexed field line is 1 T index(6+); index 6 with T=1 is 0xc6.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(6, prefixBits: 6, prefix: 0xC0), hex("c6"))
        // Index 63 fills the prefix, so the pattern bits ride on a 0xff byte.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(63, prefixBits: 6, prefix: 0xC0), hex("ff00"))
        // Decoding masks the pattern away again.
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(hex("c6"), offset: 0, prefixBits: 6),
                       QpackEncoder.PrefixedInteger(value: 6, size: 1))
    }

    func testQpackPrefixedIntegersAreNotQuicVarints() throws {
        // 15293 is one of RFC 9000 Appendix A.1's worked varint examples. The
        // two encodings share neither length nor bytes, which is exactly why
        // reaching for the wrong one is such an easy interop bug.
        XCTAssertEqual(try QuicVarInt.encode(15293), hex("7bbd"))
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(15293, prefixBits: 5, prefix: 0x00), hex("1f9e77"))

        // And reading one as the other does not merely fail, it lies: the QUIC
        // form read as a 5-bit-prefix integer yields a different number.
        let misread = try XCTUnwrap(QpackEncoder.decodePrefixedInteger(hex("7bbd"), offset: 0, prefixBits: 5))
        XCTAssertNotEqual(misread.value, 15293)
    }

    func testAnUnterminatedContinuationRunIsRefused() {
        // Every byte has its high bit set, so the integer never ends.
        XCTAssertNil(QpackEncoder.decodePrefixedInteger(hex("1f8080808080"), offset: 0, prefixBits: 5))
        // And an empty or out-of-range offset has nothing to read.
        XCTAssertNil(QpackEncoder.decodePrefixedInteger([], offset: 0, prefixBits: 5))
        XCTAssertNil(QpackEncoder.decodePrefixedInteger(hex("1f"), offset: 5, prefixBits: 5))
    }

    func testAnIntegerBeyond2ToThe62IsRefusedRatherThanWrapped() {
        // RFC 9204 §4.1.1 caps QPACK integers at 2^62 - 1; a longer run of
        // continuation bytes must not fold back into a small positive value.
        XCTAssertNil(QpackEncoder.decodePrefixedInteger(hex("ffffffffffffffffffff7f"), offset: 0, prefixBits: 8))

        // The boundary value itself still round-trips.
        let max = QpackEncoder.encodePrefixedInteger(QpackEncoder.maxInteger, prefixBits: 8, prefix: 0x00)
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(max, offset: 0, prefixBits: 8),
                       QpackEncoder.PrefixedInteger(value: QpackEncoder.maxInteger, size: max.count))
    }

    func testAnOutOfRangeIntegerIsClampedRatherThanWrapped() {
        // A negative value or one past the QPACK ceiling is a caller error. The
        // encoder clamps rather than refuses, so what has to hold is that
        // neither turns into some other number on the wire: -1 is written as
        // 0, and 2^62 as the ceiling itself.
        XCTAssertEqual(QpackEncoder.encodePrefixedInteger(-1, prefixBits: 7, prefix: 0x00), hex("00"))

        let pastCeiling = QpackEncoder.encodePrefixedInteger(QpackEncoder.maxInteger + 1, prefixBits: 7, prefix: 0x00)
        XCTAssertEqual(pastCeiling,
                       QpackEncoder.encodePrefixedInteger(QpackEncoder.maxInteger, prefixBits: 7, prefix: 0x00))
        XCTAssertEqual(QpackEncoder.decodePrefixedInteger(pastCeiling, offset: 0, prefixBits: 7)?.value,
                       QpackEncoder.maxInteger)
    }

    // MARK: - Field line representations (RFC 9204 §4.5)

    func testAConnectFieldSectionMatchesTheBytesTheRfcPrescribes() {
        let block = QpackEncoder.encodeConnectHeaders(authority: "example.com:443")

        // 00 00  field section prefix: Required Insert Count 0, Delta Base 0 (4.5.1)
        // cf     indexed field line, T=1, index 15 = :method CONNECT       (4.5.2)
        // 50     literal with name reference, N=0 T=1, index 0 = :authority(4.5.4)
        // 0f     string literal, H=0, length 15                            (4.1.2)
        XCTAssertEqual(block, hex("0000 cf 50 0f " + ascii("example.com:443")))
    }

    func testAnIndexedFieldLineDecodesFromItsPublishedIndex() {
        // c0 | 25 = d9 is :status 200.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 d9")), [field(":status", "200")])
        // Index 63 fills the 6-bit prefix, so it needs a continuation byte.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 ff00")), [field(":status", "100")])
        // 98 is the last entry: 98 - 63 = 0x23.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 ff23")), [field("x-frame-options", "sameorigin")])
        // 99 does not exist.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 ff24")))
    }

    func testALiteralWithNameReferenceResolvesTheNameFromTheStaticTable() {
        // 51 = literal with name reference, index 1 = :path; then "/" raw.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 51 01 2f")), [field(":path", "/")])
        // Index 15 fills the 4-bit prefix: 5f 00. The value overrides CONNECT.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 5f00 03 " + ascii("GET"))), [field(":method", "GET")])
        // Index 95 = user-agent, 95 - 15 = 0x50.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000 5f50 07 " + ascii("Mythaia"))),
                       [field("user-agent", "Mythaia")])
        // A name index past the table is a failure, not a skipped field line.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 5f54 01 78")))
    }

    func testALiteralFieldLineDecodesWithAndWithoutHuffman() {
        // Both blocks carry custom-key: custom-value. The Huffman strings are
        // RFC 7541 Appendix C.4.3's own, so this checks the H bit against the
        // spec rather than against whatever this encoder happens to emit.
        //
        // 27 03  literal with literal name, N=0 H=0, name length 10
        // 0c     value string literal, H=0, length 12
        let raw = hex("0000 2703 " + ascii("custom-key") + " 0c " + ascii("custom-value"))
        XCTAssertEqual(QpackEncoder.decodeHeaders(raw), [field("custom-key", "custom-value")])

        // 2f 01  literal with literal name, N=0 H=1, name length 8
        // 89     value string literal, H=1, length 9
        let huffman = hex("0000 2f01 25a849e95ba97d7f 89 25a849e95bb8e8b4bf")
        XCTAssertEqual(QpackEncoder.decodeHeaders(huffman), [field("custom-key", "custom-value")])

        // The Huffman form really is shorter, which is the only reason the H bit
        // exists; if these were equal one of the two blocks would be wrong.
        XCTAssertLessThan(huffman.count, raw.count)
    }

    func testAHuffmanStringThatIsNotAValidCodeIsRefused() {
        // A lone 0xff is a truncated code that runs into EOS, which the Huffman
        // decoder rejects, and that refusal has to reach the caller rather than
        // yield an empty value.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 2703 " + ascii("custom-key") + " 81 ff")))
    }

    func testIllFormedUtf8InAValueIsRefused() {
        // 0xff can never appear in UTF-8. Substituting U+FFFD here would hand the
        // caller a header value that is not what the peer sent.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 2703 " + ascii("custom-key") + " 02 fffe")))
    }

    // MARK: - Dynamic table references

    func testReferencesToTheDynamicTableAreRefused() {
        // We advertise QPACK_MAX_TABLE_CAPACITY = 0, so none of these can be
        // resolved and none may be silently dropped either.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 80")), "indexed, T=0")
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 40")), "name ref, T=0")
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 10")), "indexed post-base")
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("0000 00")), "name ref post-base")
    }

    func testANonZeroRequiredInsertCountIsRefused() {
        // The prefix says the peer inserted entries we never agreed to hold.
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("01 00 d9")))
    }

    func testAFieldSectionShorterThanItsPrefixIsRefused() {
        XCTAssertNil(QpackEncoder.decodeHeaders([]))
        XCTAssertNil(QpackEncoder.decodeHeaders(hex("00")))
        // A bare prefix with no field lines is legal and carries nothing.
        XCTAssertEqual(QpackEncoder.decodeHeaders(hex("0000")), [])
    }

    func testTruncatedFieldSectionsAreRefusedRatherThanHalfDecoded() {
        let complete = QpackEncoder.encodeConnectHeaders(
            authority: "example.com:443",
            extraHeaders: [field("user-agent", "Mythaia")]
        )
        for cut in 1..<complete.count {
            if let decoded = QpackEncoder.decodeHeaders(Array(complete[0..<cut])) {
                // A prefix that happens to end on a field line boundary is a
                // shorter but well-formed block; what must never happen is a
                // decode that reads past the end.
                XCTAssertLessThan(decoded.count, 3, "cut=\(cut) produced \(decoded)")
            }
        }
    }

    // MARK: - Request encoding

    func testAConnectFieldSectionRoundTrips() {
        let block = QpackEncoder.encodeConnectHeaders(authority: "example.com:443")
        XCTAssertEqual(QpackEncoder.decodeHeaders(block), [
            field(":method", "CONNECT"),
            field(":authority", "example.com:443"),
        ])
    }

    func testExtendedConnectCarriesThePseudoHeadersRfc9220MakesMandatory() {
        let block = QpackEncoder.encodeConnectHeaders(
            authority: "proxy.example:443",
            protocolPseudo: "connect-udp",
            path: "/.well-known/masque/udp/192.0.2.1/443/"
        )
        XCTAssertEqual(QpackEncoder.decodeHeaders(block), [
            field(":method", "CONNECT"),
            field(":protocol", "connect-udp"),
            field(":scheme", "https"),
            field(":path", "/.well-known/masque/udp/192.0.2.1/443/"),
            field(":authority", "proxy.example:443"),
        ])
    }

    func testExtendedConnectDefaultsThePathWhenNoneIsGiven() throws {
        let block = QpackEncoder.encodeConnectHeaders(
            authority: "proxy.example:443",
            protocolPseudo: "websocket"
        )
        let decoded = try XCTUnwrap(QpackEncoder.decodeHeaders(block))
        XCTAssertGreaterThan(decoded.count, 3)
        guard decoded.count > 3 else { return }
        XCTAssertEqual(decoded[3], field(":path", "/"))
    }

    func testPostAndGetUseTheirStaticTableEntries() {
        // 0000 then c0|20 = d4 for :method POST, then c0|23 = d7 for :scheme https.
        let post = QpackEncoder.encodePostHeaders(authority: "example.com", path: "/upload")
        XCTAssertEqual(Array(post.prefix(4)), hex("0000 d4 d7"))

        let get = QpackEncoder.encodeRequestHeaders(method: "GET", authority: "example.com", path: "/")
        XCTAssertEqual(Array(get.prefix(4)), hex("0000 d1 d7"))

        XCTAssertEqual(QpackEncoder.decodeHeaders(post), [
            field(":method", "POST"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/upload"),
        ])
    }

    func testAMethodOutsideTheStaticTableIsSpelledOut() {
        let block = QpackEncoder.encodeRequestHeaders(method: "PATCH", authority: "example.com", path: "/thing")
        XCTAssertEqual(QpackEncoder.decodeHeaders(block), [
            field(":method", "PATCH"),
            field(":scheme", "https"),
            field(":authority", "example.com"),
            field(":path", "/thing"),
        ])
        // The method is a literal field line, not an index: 001 N H len(3+), and
        // ":method" is 7 bytes, which is exactly where the 3-bit prefix fills.
        XCTAssertEqual(Array(block.prefix(11)), hex("0000 27 00 " + ascii(":method")))
    }

    func testFieldNamesAreLowercasedBecauseHttp3ForbidsUppercase() throws {
        let block = QpackEncoder.encodeRequestHeaders(
            method: "GET", authority: "example.com", path: "/",
            extraHeaders: [field("X-Custom-Name", "MixedCaseValue")]
        )
        let decoded = try XCTUnwrap(QpackEncoder.decodeHeaders(block))
        // The name is folded; the value is not, since only names are restricted.
        XCTAssertEqual(decoded.last, field("x-custom-name", "MixedCaseValue"))
    }

    func testValuesCrossingTheStringLengthBoundarySurvive() {
        // A string literal's length uses a 7-bit prefix, so 127 bytes is where a
        // continuation byte appears and 16383 is where a second one does.
        for length in [0, 1, 126, 127, 128, 254, 255, 16382, 16383, 16384] {
            let value = String(repeating: "v", count: length)
            let block = QpackEncoder.encodeRequestHeaders(
                method: "GET", authority: "h", path: "/", extraHeaders: [field("padding", value)]
            )
            let decoded = QpackEncoder.decodeHeaders(block)
            XCTAssertNotNil(decoded, "length \(length)")
            XCTAssertEqual(decoded?.last?.value, value, "length \(length)")
        }
    }

    func testALongFieldNameCrossesItsOwn3BitBoundary() {
        // Names use a 3-bit length prefix, so the continuation starts at 7.
        for length in [1, 6, 7, 8, 133, 134, 135] {
            let name = String(repeating: "x", count: length)
            let block = QpackEncoder.encodeRequestHeaders(
                method: "GET", authority: "h", path: "/", extraHeaders: [field(name, "v")]
            )
            let decoded = QpackEncoder.decodeHeaders(block)
            XCTAssertNotNil(decoded, "length \(length)")
            XCTAssertEqual(decoded?.last, field(name, "v"), "length \(length)")
        }
    }

    func testNonAsciiValuesRoundTripAsUtf8() {
        // "значение值": Cyrillic and CJK, two and three bytes per character.
        let value = "\u{0437}\u{043D}\u{0430}\u{0447}\u{0435}\u{043D}\u{0438}\u{0435}\u{503C}"
        let block = QpackEncoder.encodeRequestHeaders(
            method: "GET", authority: "h", path: "/", extraHeaders: [field("x-name", value)]
        )
        XCTAssertEqual(QpackEncoder.decodeHeaders(block)?.last?.value, value)
    }

    func testEveryFieldSectionStartsWithTheTwoBytePrefix() {
        let blocks = [
            QpackEncoder.encodeConnectHeaders(authority: "h"),
            QpackEncoder.encodeConnectHeaders(authority: "h", protocolPseudo: "connect-udp"),
            QpackEncoder.encodePostHeaders(authority: "h", path: "/"),
            QpackEncoder.encodeRequestHeaders(method: "HEAD", authority: "h", path: "/"),
        ]
        for block in blocks {
            XCTAssertEqual(Array(block.prefix(2)), hex("0000"))
        }
    }
}
