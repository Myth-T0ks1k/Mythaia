import XCTest
@testable import MythaiaKit

/// TLS 1.3 record protection against records sealed by an independent AEAD
/// implementation: key 00..0f (or 00..1f), IV a0..ab, the sequence number
/// XORed into the IV, the header as AAD, the content type inside.
final class TLSRecordTests: XCTestCase {

    private let key128 = (0..<16).map { UInt8($0) }
    private let key256 = (0..<32).map { UInt8($0) }
    private let iv = (0..<12).map { UInt8(0xA0 + $0) }

    private func suite(_ code: Int) throws -> Tls13Suite {
        return try XCTUnwrap(Tls13Suite.forCode(code))
    }

    private func split(_ record: [UInt8]) -> (header: [UInt8], body: [UInt8]) {
        return (Array(record[0..<5]), Array(record[5...]))
    }

    func testAes128GcmRecordsAtSequenceZeroAndOne() throws {
        var cipher = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let first = try cipher.seal(Array("hello".utf8), contentType: 0x17)
        XCTAssertEqual(TLSWire.hex(first), "1703030016c2e354d7119eb4e3c26f9a2769c0df1e4a089219fbd8")
        let second = try cipher.seal(Array("world!".utf8), contentType: 0x17)
        XCTAssertEqual(TLSWire.hex(second), "1703030017489514f6cecb9bfca6298cbbabd08cce734c0120fa2269")
        XCTAssertEqual(cipher.sequence, 2)

        var reader = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let one = split(first)
        let opened = try reader.open(header: one.header, body: one.body)
        XCTAssertEqual(opened.contentType, 0x17)
        XCTAssertEqual(opened.content, Array("hello".utf8))
        let two = split(second)
        XCTAssertEqual(try reader.open(header: two.header, body: two.body).content, Array("world!".utf8))
    }

    func testAes256GcmAtSequenceSeven() throws {
        var cipher = TLSRecordCipher(suite: try suite(0x1302), key: key256, iv: iv)
        for _ in 0..<7 {
            _ = try cipher.seal([0x00], contentType: 0x17)
        }
        let record = try cipher.seal(Array("hello".utf8), contentType: 0x17)
        XCTAssertEqual(TLSWire.hex(record), "1703030016b3a9277644e3b692476e18ac3ac58e4a431bafeb59ef")
    }

    func testChaCha20Poly1305AtSequenceTwo() throws {
        var cipher = TLSRecordCipher(suite: try suite(0x1303), key: key256, iv: iv)
        _ = try cipher.seal([0x01], contentType: 0x17)
        _ = try cipher.seal([0x02], contentType: 0x17)
        let record = try cipher.seal(Array("hello".utf8), contentType: 0x17)
        XCTAssertEqual(TLSWire.hex(record), "1703030016b24fda667efad1bc07f8c76175a1528972b113ce65fc")
    }

    func testPaddingAfterTheContentTypeIsRemoved() throws {
        var reader = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let record = split(TLSTestHex.bytes("1703030016dae75cac7e893b70ac23d1bff9923aa4b028c2edb671"))
        let opened = try reader.open(header: record.header, body: record.body)
        XCTAssertEqual(opened.contentType, 0x17)
        XCTAssertEqual(opened.content, Array("pad".utf8))
    }

    func testARecordOfOnlyZerosHasNoContentType() throws {
        var reader = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let record = split(TLSTestHex.bytes("1703030013aa863852bf87d79bdf8bf550cb101a19e7da3f"))
        XCTAssertThrowsError(try reader.open(header: record.header, body: record.body))
    }

    func testAFailedOpenDoesNotUseUpASequenceNumber() throws {
        var reader = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let good = split(TLSTestHex.bytes("1703030016c2e354d7119eb4e3c26f9a2769c0df1e4a089219fbd8"))
        var tampered = good.body
        tampered[0] ^= 0x01
        XCTAssertThrowsError(try reader.open(header: good.header, body: tampered))
        XCTAssertEqual(reader.sequence, 0)
        XCTAssertEqual(try reader.open(header: good.header, body: good.body).content, Array("hello".utf8))
        XCTAssertEqual(reader.sequence, 1)
    }

    func testTheHeaderIsAuthenticated() throws {
        var reader = TLSRecordCipher(suite: try suite(0x1301), key: key128, iv: iv)
        let good = split(TLSTestHex.bytes("1703030016c2e354d7119eb4e3c26f9a2769c0df1e4a089219fbd8"))
        var header = good.header
        header[2] = 0x01
        XCTAssertThrowsError(try reader.open(header: header, body: good.body))
    }

    func testNonceIsTheIvXorTheSequenceNumber() {
        let nonce = TLSWire.xorNonce(iv, 0x0102030405060708)
        XCTAssertEqual(TLSWire.hex(nonce), "a0a1a2a3a5a7a5a3adafada3")
        XCTAssertEqual(TLSWire.xorNonce(iv, 0), iv)
    }

    func testCodepointsAndAlerts() {
        XCTAssertEqual(TLSWire.codepoint(0x1301), "0x1301")
        XCTAssertEqual(TLSWire.codepoint(0x17), "0x0017")
        XCTAssertEqual(TLSAlert.describe(level: 2, description: 40), "fatal handshake_failure")
        XCTAssertEqual(TLSAlert.describe(level: 1, description: 0), "warning close_notify")
    }
}
