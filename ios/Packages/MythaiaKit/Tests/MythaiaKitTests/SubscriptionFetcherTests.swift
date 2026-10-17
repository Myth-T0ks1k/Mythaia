import XCTest
@testable import MythaiaKit

/// The transport-level handling in front of the subscription parsers, and the parsing itself.
final class SubscriptionFetcherTests: XCTestCase {

    /// RFC 1952 around Foundation's raw DEFLATE, written out field by field.
    private func gzip(_ body: Data) throws -> Data {
        let deflated = try (body as NSData).compressed(using: .zlib) as Data
        var out = Data([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF])
        out.append(deflated)
        let crc = Gzip.crc32(body)
        let size = UInt32(truncatingIfNeeded: body.count)
        for shift in stride(from: 0, to: 32, by: 8) { out.append(UInt8(truncatingIfNeeded: crc >> UInt32(shift))) }
        for shift in stride(from: 0, to: 32, by: 8) { out.append(UInt8(truncatingIfNeeded: size >> UInt32(shift))) }
        return out
    }

    private func isConnectFailed(_ error: Error) -> Bool {
        if case MythaiaError.connectFailed? = error as? MythaiaError { return true }
        return false
    }

    func testTheCrcIsTheStandardOne() {
        // The check value every CRC-32 catalogue lists for "123456789".
        XCTAssertEqual(Gzip.crc32(Data("123456789".utf8)), 0xCBF4_3926)
    }

    func testAGzippedBodyIsDecodedWhenTheHeaderSaysSo() throws {
        let plain = Data("vless://x@y:1#n\n".utf8)
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(gzip(plain), contentEncoding: "gzip"), plain)
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(gzip(plain), contentEncoding: " X-Gzip "), plain)
        // No header, or another encoding: the bytes are what they are.
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(plain, contentEncoding: nil), plain)
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(plain, contentEncoding: "identity"), plain)
    }

    func testABodyThatIsNotGzipUnderAGzipHeaderIsAFetchError() {
        XCTAssertThrowsError(try SubscriptionFetcher.gunzipIfNeeded(Data("not gzip".utf8), contentEncoding: "gzip")) { error in
            XCTAssertTrue(self.isConnectFailed(error), "\(error)")
        }
    }

    func testABodyIsReadWholeUpToTheCapAndRefusedPastIt() throws {
        let cap = 16 * 1024 * 1024
        let body = Data((0..<cap).map { UInt8($0 % 251) })
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(gzip(body), contentEncoding: "gzip"), body)
        XCTAssertEqual(try SubscriptionFetcher.gunzipIfNeeded(gzip(Data()), contentEncoding: "gzip"), Data())
        XCTAssertThrowsError(try SubscriptionFetcher.gunzipIfNeeded(gzip(Data(count: cap + 1)), contentEncoding: "gzip")) { error in
            XCTAssertTrue(self.isConnectFailed(error), "\(error)")
        }
    }

    func testOnlyHttpAndHttpsSubscriptionUrlsAreFetched() async {
        for url in ["file:///etc/hosts", "ftp://example.com/sub", "not a url"] {
            do {
                _ = try await SubscriptionFetcher.fetch(urlString: url)
                XCTFail("expected a refusal for \(url)")
            } catch {
                guard case MythaiaError.invalidConfiguration? = error as? MythaiaError else {
                    return XCTFail("expected invalidConfiguration for \(url), got \(error)")
                }
            }
        }
    }

    func testABase64ListBrokenIntoLinesDecodesInEitherAlphabet() throws {
        let links = (0..<300).map { "trojan://p%3F%3E\($0)@h\($0).example.com:443?sni=s\($0).example.com#node-\($0)" }
        let raw = Data(links.joined(separator: "\r\n").utf8)
        let mime = raw.base64EncodedString(options: [.lineLength76Characters, .endLineWithCarriageReturn, .endLineWithLineFeed])
        var urlSafe = raw.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while urlSafe.hasSuffix("=") { urlSafe.removeLast() }
        var chunked: [String] = []
        var rest = Substring(urlSafe)
        while !rest.isEmpty {
            chunked.append(String(rest.prefix(76)))
            rest = rest.dropFirst(76)
        }
        for encoded in [mime, chunked.joined(separator: "\n")] {
            XCTAssertEqual(SubscriptionFetcher.decodeBody(Data(encoded.utf8)), links.joined(separator: "\r\n"))
            XCTAssertEqual(try SubscriptionFetcher.parse(Data(encoded.utf8)).configurations.count, links.count)
        }
        // Text that is not base64, Cyrillic included, comes back as it was.
        let prose = "Подписка истекла\n"
        XCTAssertEqual(SubscriptionFetcher.decodeBody(Data(prose.utf8)), prose)
    }

    func testMetadataComesFromTheBodyAroundABase64List() throws {
        let links = [
            "trojan://secret@a.example.com:443?sni=a.example.com#A",
            "trojan://secret@b.example.com:443?sni=b.example.com#B",
        ]
        let title = Data("Мой VPN".utf8).base64EncodedString()
        let body = "#profile-title: base64:\(title)\n" +
            "#subscription-userinfo: upload=1; download=2; total=30; expire=1700000000\n" +
            "#announce: Hello\n" +
            "#new-url: https://elsewhere.example.com/sub\n" +
            Data(links.joined(separator: "\n").utf8).base64EncodedString()
        let result = try SubscriptionFetcher.parse(Data(body.utf8))
        XCTAssertEqual(result.configurations.map { $0.name }, ["A", "B"])
        XCTAssertEqual(result.name, "Мой VPN")
        XCTAssertEqual(result.upload, 1)
        XCTAssertEqual(result.total, 30)
        XCTAssertEqual(result.expire, 1_700_000_000_000)
        XCTAssertEqual(result.panel.announce, "Hello")
        // Not over verified TLS: anyone on the path could have written this one.
        XCTAssertNil(result.panel.newUrl)
    }

    func testAMetadataLinkIsNotTakenForAServer() throws {
        let body = "#support-url: https://t.me/help\n#profile-title: P\nhysteria2://pw@example.com:443#H\n"
        let result = try SubscriptionFetcher.parse(Data(body.utf8))
        XCTAssertEqual(result.configurations.count, 1)
        XCTAssertEqual(result.panel.supportUrl, "https://t.me/help")
    }

    func testABodyWithNoServersIsAParseError() {
        XCTAssertThrowsError(try SubscriptionFetcher.parse(Data("<html>maintenance</html>".utf8))) { error in
            guard case MythaiaError.parse? = error as? MythaiaError else { return XCTFail("\(error)") }
        }
    }

    // MARK: - The HTTP/1.1 reader the fronted client uses

    private final class ScriptedStream: ByteStream {
        private var chunks: [Data]
        private let lock = NSLock()

        init(_ chunks: [String]) {
            self.chunks = chunks.map { Data($0.utf8) }
        }

        func send(_ data: Data) async throws {}

        func receive() async throws -> Data? {
            lock.lock()
            defer { lock.unlock() }
            return chunks.isEmpty ? nil : chunks.removeFirst()
        }

        func close() {}
    }

    func testAChunkedResponseSplitAcrossRecordsIsJoined() async throws {
        let stream = ScriptedStream([
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n",
            "Profile-Title: P\r\n\r\n5\r\nhel",
            "lo\r\n6;ext=1\r\n world\r\n0\r\n\r\n",
        ])
        let response = try await FrontedHttpClient.readResponse(stream, maxBody: 1 << 20)
        XCTAssertEqual(response.status, 200)
        XCTAssertEqual(response.header("Profile-Title"), "P")
        XCTAssertEqual(response.header("content-encoding"), "gzip")
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), "hello world")
    }

    func testAContentLengthBodyStopsAtItsLength() async throws {
        let stream = ScriptedStream(["HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope and more"])
        let response = try await FrontedHttpClient.readResponse(stream, maxBody: 1 << 20)
        XCTAssertEqual(response.status, 404)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), "nope")
    }

    func testABodyWithNeitherRunsToTheClose() async throws {
        let stream = ScriptedStream(["HTTP/1.0 200 OK\r\n\r\nab", "cd"])
        let response = try await FrontedHttpClient.readResponse(stream, maxBody: 1 << 20)
        XCTAssertEqual(String(decoding: response.body, as: UTF8.self), "abcd")
    }

    func testABodyPastTheCapIsRefused() async {
        let stream = ScriptedStream(["HTTP/1.1 200 OK\r\n\r\n", String(repeating: "x", count: 100)])
        do {
            _ = try await FrontedHttpClient.readResponse(stream, maxBody: 10)
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue(isConnectFailed(error), "\(error)")
        }
    }

    func testAnUnfinishedChunkedBodyIsAnError() async {
        let stream = ScriptedStream(["HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"])
        do {
            _ = try await FrontedHttpClient.readResponse(stream, maxBody: 1 << 20)
            XCTFail("expected a refusal")
        } catch {
            XCTAssertTrue(isConnectFailed(error), "\(error)")
        }
    }

    func testTargetsSplitIntoHostAndPort() {
        XCTAssertTrue(FrontedHttpClient.splitTarget("cdn.example.net", defaultPort: 443) == ("cdn.example.net", 443))
        XCTAssertTrue(FrontedHttpClient.splitTarget("192.0.2.16:8443", defaultPort: 443) == ("192.0.2.16", 8443))
        XCTAssertTrue(FrontedHttpClient.splitTarget("[2001:db8::1]:444", defaultPort: 443) == ("2001:db8::1", 444))
        XCTAssertTrue(FrontedHttpClient.splitTarget("2001:db8::1", defaultPort: 443) == ("2001:db8::1", 443))
    }
}
