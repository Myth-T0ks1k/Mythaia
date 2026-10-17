import Foundation
import XCTest
@testable import MythaiaKit

final class GRPCTransportTests: XCTestCase {

    private func ascii(_ text: String) -> [UInt8] {
        Array(text.utf8)
    }

    // MARK: - Paths

    func testTheServiceNameIsEscapedAsGosPathEscapeDoes() {
        XCTAssertEqual(GrpcConfiguration(serviceName: "my@svc").resolvedPath(), "/my@svc/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "a b*").resolvedPath(), "/a%20b%2A/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "x/y").resolvedPath(), "/x%2Fy/Tun")
        // Unreserved and the sub-delims Go keeps in a path segment.
        XCTAssertEqual(GrpcConfiguration(serviceName: "~u.n-d_r$&+:=@", multiMode: true).resolvedPath(), "/~u.n-d_r$&+:=@/TunMulti")
        // The sub-delims it does not, and UTF-8 byte by byte, uppercase.
        XCTAssertEqual(GrpcConfiguration(serviceName: "п;,?%").resolvedPath(), "/%D0%BF%3B%2C%3F%25/Tun")
    }

    func testACustomPathEscapesEachSegmentOnItsOwn() {
        XCTAssertEqual(GrpcConfiguration(serviceName: "/a b/c/Stream").resolvedPath(), "/a%20b/c/Stream")
        XCTAssertEqual(GrpcConfiguration(serviceName: "/svc/Tun|TunMulti").resolvedPath(), "/svc/Tun")
        XCTAssertEqual(GrpcConfiguration(serviceName: "/svc/Tun|TunMulti", multiMode: true).resolvedPath(), "/svc/TunMulti")
        // A lone leading slash, as Xray reads it: no service part, the rest from index 2.
        XCTAssertEqual(GrpcConfiguration(serviceName: "/Tun").resolvedPath(), "/un")
    }

    func testTheDefaultServiceName() {
        XCTAssertEqual(GrpcConfiguration().resolvedPath(), "/xray.transport.internet.grpc.encoding.GRPCService/Tun")
    }

    // MARK: - Framing

    func testTheRequestHeadersAreTheBytesXraysClientSends() {
        let block = [UInt8](GrpcCodec.requestHeaders(authority: "example.com", path: "/svc/Tun", userAgent: "ua"))
        var expected: [UInt8] = []
        func byte(_ value: UInt8) {
            expected.append(value)
        }
        // A raw string: its length (all under 127, so one byte, H = 0), then its bytes.
        func string(_ text: String) {
            expected.append(UInt8(text.utf8.count))
            expected.append(contentsOf: text.utf8)
        }
        // :authority (static 1), literal with incremental indexing: 01 000001.
        byte(0x41)
        string("example.com")
        // :method POST (static 3), indexed.
        byte(0x83)
        // :path (static 4).
        byte(0x44)
        string("/svc/Tun")
        // :scheme https (static 7), indexed.
        byte(0x87)
        // content-type (static 31).
        byte(0x5F)
        string("application/grpc")
        // New names: 0x40, the name, the value.
        byte(0x40)
        string("te")
        string("trailers")
        byte(0x40)
        string("grpc-encoding")
        string("identity")
        byte(0x40)
        string("grpc-accept-encoding")
        string("identity")
        // user-agent (static 58).
        byte(0x7A)
        string("ua")
        XCTAssertEqual(block, expected)
        XCTAssertEqual(Array(block[0..<2]), [0x41, 0x0B])

        let decoded = HpackDecoder().decode(Data(block))
        XCTAssertEqual(decoded, [
            HpackHeader(":authority", "example.com"),
            HpackHeader(":method", "POST"),
            HpackHeader(":path", "/svc/Tun"),
            HpackHeader(":scheme", "https"),
            HpackHeader("content-type", "application/grpc"),
            HpackHeader("te", "trailers"),
            HpackHeader("grpc-encoding", "identity"),
            HpackHeader("grpc-accept-encoding", "identity"),
            HpackHeader("user-agent", "ua"),
        ])
    }

    func testAHunkIsTagOneThenAVarintLength() {
        XCTAssertEqual([UInt8](GrpcCodec.encodeHunk(Data("abc".utf8))), [0x0A, 0x03] + ascii("abc"))
        // 200 = 0b1_1001000: 0xC8 then 0x01.
        let long = [UInt8](GrpcCodec.encodeHunk(Data(count: 200)))
        XCTAssertEqual(Array(long[0..<3]), [0x0A, 0xC8, 0x01])
        XCTAssertEqual(long.count, 203)
    }

    func testAMessageHasTheFiveBytePrefix() {
        XCTAssertEqual([UInt8](GrpcCodec.wrapMessage(Data([0x0A, 0x01, 0x7A]))), [0x00, 0x00, 0x00, 0x00, 0x03, 0x0A, 0x01, 0x7A])
    }

    func testMessagesAreReassembledAcrossChunks() throws {
        let reader = GrpcCodec.MessageReader()
        let message = [UInt8](GrpcCodec.wrapMessage(GrpcCodec.encodeHunk(Data("hello".utf8))))
        reader.add(Data(message[0..<3]))
        XCTAssertNil(try reader.next())
        reader.add(Data(message[3..<9]))
        XCTAssertNil(try reader.next())
        reader.add(Data(message[9...]))
        XCTAssertEqual(try reader.next(), Data("hello".utf8))
        XCTAssertNil(try reader.next())
    }

    func testAMultiHunkIsItsDataConcatenatedAndOtherFieldsAreSkipped() throws {
        // data "ab", an unknown varint field 2 = 150, data "c".
        let message = TransportTestSupport.bytes("0a 02 6162 10 9601 0a 01 63")
        XCTAssertEqual(try GrpcCodec.decodeHunks(message), Data("abc".utf8))
        XCTAssertThrowsError(try GrpcCodec.decodeHunks(TransportTestSupport.bytes("0a 05 6162")))
    }

    func testACompressedOrOversizedMessageIsRefused() {
        let compressed = GrpcCodec.MessageReader()
        compressed.add(Data([0x01, 0, 0, 0, 0]))
        XCTAssertThrowsError(try compressed.next()) { error in
            XCTAssertEqual(error as? GrpcError, .compressedMessageUnsupported)
        }
        let oversized = GrpcCodec.MessageReader()
        oversized.add(Data([0x00, 0x01, 0x00, 0x00, 0x01]))
        XCTAssertThrowsError(try oversized.next())
    }

    func testTrailersWithAFailingStatusAreAnError() {
        let failure = GrpcCodec.failureIn([HpackHeader("grpc-status", "7"), HpackHeader("grpc-message", "denied")])
        XCTAssertEqual(failure, .callFailed(status: 7, statusName: "PERMISSION_DENIED", detail: "denied"))
        XCTAssertNil(GrpcCodec.failureIn([HpackHeader("grpc-status", "0")]))
        XCTAssertNil(GrpcCodec.failureIn(nil))
    }

    // MARK: - A call end to end

    func testACallOverHTTP2CarriesHunksBothWaysAndEndsWithItsTrailers() async throws {
        let server = HTTP2TestServer()
        defer { server.stop() }
        let configuration = GrpcConfiguration(serviceName: "svc")
        let opening = Task { try await GRPCTransport.open(over: server.pair.client, configuration: configuration, authority: "example.com") }

        // The request goes out with the preface, before the server's SETTINGS.
        let request = await server.awaitFrame { $0.type == .headers && $0.streamID == 1 }
        let requestBlock = try XCTUnwrap(request?.payload)
        let requestHeaders = try XCTUnwrap(HpackDecoder().decode(requestBlock))
        XCTAssertTrue(requestHeaders.contains(HpackHeader(":path", "/svc/Tun")))
        XCTAssertTrue(requestHeaders.contains(HpackHeader(":authority", "example.com")))
        XCTAssertFalse(try XCTUnwrap(request).hasFlag(Http2FrameFlags.endStream))

        server.serverSends(Http2Framer.settingsFrame([]))
        let tunnel = try await opening.value

        try await tunnel.send(Data("hello".utf8))
        let upload = await server.awaitFrame { $0.type == .data && $0.streamID == 1 }
        XCTAssertEqual(upload?.payload, TransportTestSupport.hex("00 00000007 0a 05 68656c6c6f"))

        let response = HpackEncoder.encodeHeaderBlock([HpackHeader(":status", "200"), HpackHeader("content-type", "application/grpc")])
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: response))
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: GrpcCodec.wrapMessage(GrpcCodec.encodeHunk(Data("world".utf8)))))
        let received = try await tunnel.receive()
        XCTAssertEqual(received, Data("world".utf8))

        let trailers = HpackEncoder.encodeHeaderBlock([HpackHeader("grpc-status", "0")])
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: trailers, endStream: true))
        let end = try await tunnel.receive()
        XCTAssertNil(end)
        tunnel.close()
    }

    func testAFailedCallIsReportedAsAMythaiaError() async throws {
        let server = HTTP2TestServer()
        defer { server.stop() }
        server.serverSends(Http2Framer.settingsFrame([]))
        let tunnel = try await GRPCTransport.open(over: server.pair.client, configuration: GrpcConfiguration(), authority: "h")
        let trailersOnly = HpackEncoder.encodeHeaderBlock([
            HpackHeader(":status", "200"),
            HpackHeader("grpc-status", "12"),
            HpackHeader("grpc-message", "no such method"),
        ])
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: trailersOnly, endStream: true))
        let error = await TransportTestSupport.error { _ = try await tunnel.receive() }
        XCTAssertEqual(error as? MythaiaError, .protocolError("gRPC call failed: UNIMPLEMENTED (12) — no such method"))
        tunnel.close()
    }

    func testAServerThatIsNotHTTP2FailsTheOpenAndClosesTheStream() async throws {
        let pair = MemoryStreamPair()
        let opening = Task { try await GRPCTransport.open(over: pair.client, configuration: GrpcConfiguration(), authority: "h") }
        // An HTTP/1.1 answer and a hang-up.
        _ = try await pair.server.receive()
        try await pair.server.send(Data("HTTP/1.1 400 Bad Request\r\n\r\n".utf8))
        pair.server.close()
        let error = await TransportTestSupport.error { _ = try await opening.value }
        XCTAssertNotNil(error)
        XCTAssertTrue(error is MythaiaError, "\(String(describing: error))")
        XCTAssertTrue(pair.client.isClosed)
    }
}
