import Foundation
import XCTest
@testable import MythaiaKit

/// Hands the dials out in order, as a server's connections would come.
final class XHTTPDialQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var streams: [ByteStream]

    init(_ streams: [ByteStream]) {
        self.streams = streams
    }

    func next() throws -> ByteStream {
        lock.lock()
        defer { lock.unlock() }
        if streams.isEmpty { throw MythaiaError.connectFailed("no more connections in the test") }
        return streams.removeFirst()
    }
}

final class XHTTPTransportTests: XCTestCase {

    /// Reads from `stream` until a request or response head is complete;
    /// returns the head and what followed it.
    private func readHead(_ stream: ByteStream) async throws -> (String, [UInt8]) {
        var buffer: [UInt8] = []
        while true {
            let chunk = try await stream.receive()
            let data = try XCTUnwrap(chunk, "the stream ended before a head")
            buffer.append(contentsOf: data)
            if let end = TransportEncoding.headerEnd(buffer) {
                return (String(decoding: buffer[0..<(end + 4)], as: UTF8.self), Array(buffer[(end + 4)...]))
            }
        }
    }

    // MARK: - HTTP/1.1 requests

    func testThePacketUpDownloadIsAGetWithTheSessionInThePath() {
        let configuration = XHttpConfiguration(host: "example.com", path: "/path", mode: .packetUp, headers: ["User-Agent": "UA"],
                                               xPaddingBytesFrom: 3, xPaddingBytesTo: 3)
        let connection = XHttpConnection(download: TransportScriptedStream([]), configuration: configuration, mode: .packetUp,
                                         sessionId: "sid", uploadFactory: nil)
        let request = String(decoding: connection.buildDownloadGETRequest(), as: UTF8.self)
        XCTAssertEqual(request, "GET /path/sid/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: UA\r\nReferer: https://example.com/path/sid/?x_padding=XXX\r\n\r\n")
    }

    func testAPacketPostPlacesTheSessionTheSequenceAndThePaddingWhereConfigured() {
        let configuration = XHttpConfiguration(
            host: "h", path: "/p?a=1", mode: .packetUp, headers: ["X-Extra": "1", "User-Agent": "UA"],
            xPaddingBytesFrom: 2, xPaddingBytesTo: 2, xPaddingObfsMode: true, xPaddingPlacement: .cookie,
            sessionPlacement: .header, seqPlacement: .query
        )
        let connection = XHttpConnection(download: TransportScriptedStream([]), configuration: configuration, mode: .packetUp,
                                         sessionId: "sid", uploadFactory: nil)
        let post = String(decoding: connection.buildSinglePost(Data("abc".utf8), seq: 5), as: UTF8.self)
        let expected = "POST /p/?a=1&x_seq=5 HTTP/1.1\r\n"
            + "X-Session: sid\r\n"
            + "Host: h\r\n"
            + "User-Agent: UA\r\n"
            + "Cookie: x_padding=XX\r\n"
            + "Content-Length: 3\r\n"
            + "Connection: keep-alive\r\n"
            + "X-Extra: 1\r\n"
            + "\r\n"
            + "abc"
        XCTAssertEqual(post, expected)
    }

    func testUplinkDataInHeadersIsBase64URLInChunks() {
        let configuration = XHttpConfiguration(
            host: "h", path: "/", mode: .packetUp, headers: ["User-Agent": "UA"],
            xPaddingBytesFrom: 1, xPaddingBytesTo: 1,
            uplinkDataPlacement: .header, uplinkDataKey: "X-Data", uplinkChunkSize: 4
        )
        let connection = XHttpConnection(download: TransportScriptedStream([]), configuration: configuration, mode: .packetUp,
                                         sessionId: "sid", uploadFactory: nil)
        let post = String(decoding: connection.buildSinglePost(Data([0xFB, 0xFF, 0x01, 0x02]), seq: 0), as: UTF8.self)
        // FB FF 01 02 is "+/8BAg==" in standard base64.
        XCTAssertTrue(post.hasPrefix("POST /sid/0 HTTP/1.1\r\nX-Data-0: -_8B\r\nX-Data-1: Ag\r\nX-Data-Length: 6\r\nX-Data-Upstream: 1\r\n"), post)
        XCTAssertTrue(post.contains("\r\nContent-Length: 0\r\n"))
        XCTAssertTrue(post.hasSuffix("\r\n\r\n"))
    }

    // MARK: - HTTP/2 requests

    func testTheHTTP2DownloadHeadersCarryTheSessionAndDropHopByHopHeaders() throws {
        let configuration = XHttpConfiguration(host: "h", path: "/x", mode: .packetUp,
                                               headers: ["User-Agent": "UA", "X-Extra": "1", "Connection": "drop"],
                                               xPaddingBytesFrom: 1, xPaddingBytesTo: 1)
        let session = Http2Session(dial: { TransportScriptedStream([]) })
        let connection = XHttpConnection(session: session, configuration: configuration, mode: .packetUp, sessionId: "sid")
        let block = connection.encodeH2RequestHeaders(method: "GET", includeMeta: true)
        // :authority "h" as a literal with incremental indexing, then GET indexed.
        XCTAssertEqual(Array([UInt8](block)[0..<4]), [0x41, 0x01, 0x68, 0x82])
        XCTAssertEqual(HpackDecoder().decode(block), [
            HpackHeader(":authority", "h"),
            HpackHeader(":method", "GET"),
            HpackHeader(":path", "/x/sid"),
            HpackHeader(":scheme", "https"),
            HpackHeader("user-agent", "UA"),
            HpackHeader("referer", "https://h/x/?x_padding=X"),
            HpackHeader("x-extra", "1"),
        ])

        let upload = connection.encodeH2UploadHeaders(seq: 3, contentLength: 10)
        XCTAssertEqual(HpackDecoder().decode(upload), [
            HpackHeader(":authority", "h"),
            HpackHeader(":method", "POST"),
            HpackHeader(":path", "/x/sid/3"),
            HpackHeader(":scheme", "https"),
            HpackHeader("content-length", "10"),
            HpackHeader("user-agent", "UA"),
            HpackHeader("referer", "https://h/x/?x_padding=X"),
            HpackHeader("x-extra", "1"),
        ])
        session.close()
    }

    // MARK: - Tunnels end to end

    func testHTTP3IsRefused() async {
        let error = await TransportTestSupport.error {
            _ = try await XHTTPTransport.open(configuration: XHttpConfiguration(host: "h"), authority: "h", alpn: "h3",
                                              dial: { TransportScriptedStream([]) })
        }
        XCTAssertEqual(error as? MythaiaError, .unsupported("XHTTP over HTTP/3"))
    }

    func testStreamOneOverHTTP11() async throws {
        let pair = MemoryStreamPair()
        let client = pair.client
        let configuration = XHttpConfiguration(host: "example.com", path: "/x", mode: .streamOne)
        let opening = Task {
            try await XHTTPTransport.open(configuration: configuration, authority: "example.com", alpn: nil, dial: { client })
        }

        let (request, _) = try await readHead(pair.server)
        XCTAssertTrue(request.hasPrefix("POST /x/ HTTP/1.1\r\nHost: example.com\r\n"), request)
        XCTAssertTrue(request.contains("\r\nTransfer-Encoding: chunked\r\n"))
        XCTAssertTrue(request.contains("\r\nContent-Type: application/grpc\r\n"))

        try await pair.server.send(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".utf8))
        let tunnel = try await opening.value
        let first = try await tunnel.receive()
        XCTAssertEqual(first, Data("hello".utf8))

        try await tunnel.send(Data("abc".utf8))
        let upload = try await pair.server.receive()
        XCTAssertEqual(upload, Data("3\r\nabc\r\n".utf8))

        try await pair.server.send(Data("0\r\n\r\n".utf8))
        let end = try await tunnel.receive()
        XCTAssertNil(end)
        tunnel.close()
    }

    func testPacketUpOverHTTP11UsesASecondConnectionForThePosts() async throws {
        let download = MemoryStreamPair()
        let upload = MemoryStreamPair()
        let dials = XHTTPDialQueue([download.client, upload.client])
        let configuration = XHttpConfiguration(host: "h", path: "/x", mode: .packetUp, scMinPostsIntervalMs: 0,
                                               xPaddingBytesFrom: 1, xPaddingBytesTo: 1)
        let opening = Task {
            try await XHTTPTransport.open(configuration: configuration, authority: "h", alpn: "http/1.1", dial: { try dials.next() })
        }

        let (get, _) = try await readHead(download.server)
        XCTAssertTrue(get.hasPrefix("GET /x/"), get)
        let requestLine = get.components(separatedBy: "\r\n")[0]
        let sessionId = String(requestLine.dropFirst("GET /x/".count).dropLast("/ HTTP/1.1".count))
        XCTAssertEqual(sessionId.count, 36)
        XCTAssertEqual(sessionId, sessionId.lowercased())

        try await download.server.send(Data("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".utf8))
        let tunnel = try await opening.value

        try await tunnel.send(Data("hi".utf8))
        let (post, body) = try await readHead(upload.server)
        XCTAssertTrue(post.hasPrefix("POST /x/\(sessionId)/0 HTTP/1.1\r\n"), post)
        XCTAssertTrue(post.contains("\r\nContent-Length: 2\r\n"))
        XCTAssertEqual(body, Array("hi".utf8))

        try await download.server.send(Data("2\r\nyo\r\n".utf8))
        let received = try await tunnel.receive()
        XCTAssertEqual(received, Data("yo".utf8))
        tunnel.close()
        XCTAssertTrue(upload.client.isClosed)
    }

    func testPacketUpOverHTTP2MakesEachPostAStream() async throws {
        let server = HTTP2TestServer()
        defer { server.stop() }
        let client = server.pair.client
        let configuration = XHttpConfiguration(host: "h", path: "/x", mode: .packetUp, scMinPostsIntervalMs: 0,
                                               xPaddingBytesFrom: 1, xPaddingBytesTo: 1)
        let opening = Task {
            try await XHTTPTransport.open(configuration: configuration, authority: "h", alpn: "h2", dial: { client })
        }
        let decoder = HpackDecoder()

        // The download GET, its HEADERS ending the request.
        let getFrame = await server.awaitFrame { $0.type == .headers && $0.streamID == 1 }
        let get = try XCTUnwrap(getFrame)
        XCTAssertTrue(get.hasFlag(Http2FrameFlags.endStream))
        let getHeaders = try XCTUnwrap(decoder.decode(get.payload))
        XCTAssertTrue(getHeaders.contains(HpackHeader(":method", "GET")))
        let path = try XCTUnwrap(getHeaders.first { $0.name == ":path" }?.value)
        XCTAssertTrue(path.hasPrefix("/x/"), path)
        let sessionId = String(path.dropFirst("/x/".count))

        server.serverSends(Http2Framer.settingsFrame([]))
        let tunnel = try await opening.value

        try await tunnel.send(Data("hi".utf8))
        let postFrame = await server.awaitFrame { $0.type == .headers && $0.streamID == 3 }
        let post = try XCTUnwrap(postFrame)
        let postHeaders = try XCTUnwrap(decoder.decode(post.payload))
        XCTAssertTrue(postHeaders.contains(HpackHeader(":method", "POST")))
        XCTAssertTrue(postHeaders.contains(HpackHeader(":path", "/x/\(sessionId)/0")))
        XCTAssertTrue(postHeaders.contains(HpackHeader("content-length", "2")))
        let bodyFrame = await server.awaitFrame { $0.type == .data && $0.streamID == 3 }
        let body = try XCTUnwrap(bodyFrame)
        XCTAssertEqual(body.payload, Data("hi".utf8))
        XCTAssertTrue(body.hasFlag(Http2FrameFlags.endStream))

        let ok = HpackEncoder.encodeHeaderBlock([HpackHeader(":status", "200")])
        server.serverSends(Http2Framer.headersFrame(streamID: 3, headerBlock: ok, endStream: true))
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: ok))
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: Data("yo".utf8)))
        let received = try await tunnel.receive()
        XCTAssertEqual(received, Data("yo".utf8))
        tunnel.close()
    }
}
