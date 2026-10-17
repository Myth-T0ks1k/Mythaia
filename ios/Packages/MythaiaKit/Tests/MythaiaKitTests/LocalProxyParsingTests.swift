import Foundation
import XCTest
@testable import MythaiaKit

final class LocalProxyParsingTests: XCTestCase {
    // MARK: - SOCKS5 greeting

    private func greeting(_ bytes: [UInt8]) -> InboundParse<SocksInbound.Greeting> {
        SocksInbound.parseGreeting(Data(bytes))
    }

    func testGreetingWithNoAuthentication() {
        guard case .complete(let value, let consumed) = greeting([0x05, 0x01, 0x00]) else {
            return XCTFail("expected a complete greeting")
        }
        XCTAssertEqual(value.methods, [0x00])
        XCTAssertEqual(consumed, 3)
    }

    func testGreetingLeavesTheRequestThatFollows() {
        guard case .complete(let value, let consumed) = greeting([0x05, 0x02, 0x00, 0x02, 0x05, 0x01]) else {
            return XCTFail("expected a complete greeting")
        }
        XCTAssertEqual(value.methods, [0x00, 0x02])
        XCTAssertEqual(consumed, 4)
    }

    func testGreetingNeedsAllItsMethods() {
        guard case .incomplete = greeting([]) else { return XCTFail("empty input is incomplete") }
        guard case .incomplete = greeting([0x05]) else { return XCTFail("version alone is incomplete") }
        guard case .incomplete = greeting([0x05, 0x02, 0x00]) else { return XCTFail("one of two methods is incomplete") }
    }

    func testGreetingOfAnotherVersionIsRefused() {
        guard case .invalid = greeting([0x04, 0x01, 0x00]) else { return XCTFail("SOCKS4 is not SOCKS5") }
    }

    func testGreetingWithoutMethodsOffersNoneAcceptable() {
        guard case .complete(let value, _) = greeting([0x05, 0x00]) else {
            return XCTFail("expected a complete greeting")
        }
        XCTAssertFalse(value.methods.contains(SocksInbound.methodNoAuth))
        XCTAssertEqual(SocksInbound.noAcceptableMethods, Data([0x05, 0xFF]))
        XCTAssertEqual(SocksInbound.noAuthSelected, Data([0x05, 0x00]))
    }

    // MARK: - SOCKS5 request

    private func request(_ bytes: [UInt8]) -> InboundParse<SocksInbound.Request> {
        SocksInbound.parseRequest(Data(bytes))
    }

    func testConnectToIPv4() {
        let bytes: [UInt8] = [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50]
        guard case .complete(let value, let consumed) = request(bytes) else {
            return XCTFail("expected a complete request")
        }
        XCTAssertEqual(value, SocksInbound.Request(command: 0x01, host: "93.184.216.34", port: 80))
        XCTAssertEqual(consumed, 10)
    }

    func testConnectToDomainWithTrailingData() {
        var bytes: [UInt8] = [0x05, 0x01, 0x00, 0x03, 11]
        bytes += Array("example.com".utf8)
        bytes += [0x01, 0xBB]
        bytes += [0x16, 0x03, 0x01]
        guard case .complete(let value, let consumed) = request(bytes) else {
            return XCTFail("expected a complete request")
        }
        XCTAssertEqual(value.host, "example.com")
        XCTAssertEqual(value.port, 443)
        XCTAssertEqual(value.command, SocksInbound.commandConnect)
        XCTAssertEqual(consumed, 5 + 11 + 2)
    }

    func testConnectToIPv6() {
        var bytes: [UInt8] = [0x05, 0x01, 0x00, 0x04]
        bytes += [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        bytes += [0x1F, 0x90]
        guard case .complete(let value, let consumed) = request(bytes) else {
            return XCTFail("expected a complete request")
        }
        XCTAssertEqual(value.host, "2001:db8::1")
        XCTAssertEqual(value.port, 8080)
        XCTAssertEqual(consumed, 22)
    }

    func testUdpAssociateIsParsedForTheRefusal() {
        let bytes: [UInt8] = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
        guard case .complete(let value, _) = request(bytes) else {
            return XCTFail("expected a complete request")
        }
        XCTAssertEqual(value.command, SocksInbound.commandUdpAssociate)
    }

    func testTruncatedRequestsAreIncomplete() {
        let full: [UInt8] = [0x05, 0x01, 0x00, 0x03, 3, 0x61, 0x62, 0x63, 0x00, 0x50]
        for length in 0..<full.count {
            guard case .incomplete = request(Array(full.prefix(length))) else {
                return XCTFail("\(length) bytes should be incomplete")
            }
        }
    }

    func testBadRequestsAreInvalid() {
        guard case .invalid = request([0x04, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80]) else {
            return XCTFail("wrong version")
        }
        guard case .invalid = request([0x05, 0x01, 0x00, 0x09, 1, 2, 3, 4, 0, 80]) else {
            return XCTFail("unknown address type")
        }
        guard case .invalid = request([0x05, 0x01, 0x00, 0x03, 0, 0, 80]) else {
            return XCTFail("empty domain")
        }
    }

    func testRepliesAreTenBytesWithAZeroAddress() {
        XCTAssertEqual(SocksInbound.reply(SocksInbound.replySuccess), Data([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(SocksInbound.reply(SocksInbound.replyNotAllowed), Data([5, 2, 0, 1, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(SocksInbound.reply(SocksInbound.replyHostUnreachable), Data([5, 4, 0, 1, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(SocksInbound.reply(SocksInbound.replyCommandNotSupported), Data([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]))
    }

    // MARK: - HTTP

    private func parse(_ text: String) -> HTTPInbound.Request? {
        HTTPInbound.parse(head: Data(text.utf8))
    }

    private func forwarded(_ request: HTTPInbound.Request?) -> (host: String, port: UInt16, head: String)? {
        guard case .forward(let host, let port, let head)? = request else { return nil }
        return (host: host, port: port, head: String(decoding: head, as: UTF8.self))
    }

    func testConnectWithPort() {
        let request = parse("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        XCTAssertEqual(request, .connect(host: "example.com", port: 443, version: "HTTP/1.1"))
    }

    func testConnectDefaultsAndBrackets() {
        XCTAssertEqual(parse("connect example.com HTTP/1.0\r\n\r\n"), .connect(host: "example.com", port: 443, version: "HTTP/1.0"))
        XCTAssertEqual(parse("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"), .connect(host: "2001:db8::1", port: 8443, version: "HTTP/1.1"))
        XCTAssertNil(parse("CONNECT example.com:99999 HTTP/1.1\r\n\r\n"))
        XCTAssertNil(parse("CONNECT :443 HTTP/1.1\r\n\r\n"))
    }

    func testAbsoluteFormIsRewrittenToOriginForm() {
        let head = "GET http://example.com/path?q=1 HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Proxy-Connection: keep-alive\r\n"
            + "Accept: */*\r\n"
            + "Connection: keep-alive\r\n"
            + "Keep-Alive: timeout=5\r\n"
            + "Proxy-Authorization: Basic eA==\r\n"
            + "\r\n"
        guard let result = forwarded(parse(head)) else { return XCTFail("expected a forward") }
        XCTAssertEqual(result.host, "example.com")
        XCTAssertEqual(result.port, 80)
        let expected = "GET /path?q=1 HTTP/1.1\r\n"
            + "Host: example.com\r\n"
            + "Accept: */*\r\n"
            + "Connection: close\r\n"
            + "\r\n"
        XCTAssertEqual(result.head, expected)
    }

    func testAbsoluteFormWithPortAndNoPathGetsAHostHeader() {
        guard let result = forwarded(parse("GET http://Example.com:8080 HTTP/1.1\r\n\r\n")) else {
            return XCTFail("expected a forward")
        }
        XCTAssertEqual(result.host, "Example.com")
        XCTAssertEqual(result.port, 8080)
        XCTAssertEqual(result.head, "GET / HTTP/1.1\r\nHost: Example.com:8080\r\nConnection: close\r\n\r\n")
    }

    func testAbsoluteFormWithQueryButNoPath() {
        guard let result = forwarded(parse("GET http://example.com?x=1 HTTP/1.1\r\n\r\n")) else {
            return XCTFail("expected a forward")
        }
        XCTAssertEqual(result.host, "example.com")
        XCTAssertTrue(result.head.hasPrefix("GET /?x=1 HTTP/1.1\r\n"))
    }

    func testOriginFormUsesTheHostHeader() {
        guard let result = forwarded(parse("POST /submit HTTP/1.1\r\nhost: api.example.org:8000\r\nContent-Length: 2\r\n\r\n")) else {
            return XCTFail("expected a forward")
        }
        XCTAssertEqual(result.host, "api.example.org")
        XCTAssertEqual(result.port, 8000)
        XCTAssertEqual(result.head, "POST /submit HTTP/1.1\r\nhost: api.example.org:8000\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
    }

    func testBadHeadsAreRefused() {
        XCTAssertNil(parse("GET /nohost HTTP/1.1\r\n\r\n"))
        XCTAssertNil(parse("GARBAGE\r\n\r\n"))
        XCTAssertNil(parse("\r\n\r\n"))
        XCTAssertNil(parse("GET http:// HTTP/1.1\r\n\r\n"))
    }

    private func assertSplit(
        _ text: String,
        _ defaultPort: UInt16,
        host: String,
        port: UInt16,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let result = HTTPInbound.splitHostPort(text, defaultPort: defaultPort) else {
            return XCTFail("\(text) did not parse", file: file, line: line)
        }
        XCTAssertEqual(result.host, host, file: file, line: line)
        XCTAssertEqual(result.port, port, file: file, line: line)
    }

    func testSplitHostPort() {
        assertSplit("example.com", 80, host: "example.com", port: 80)
        assertSplit("example.com:81", 80, host: "example.com", port: 81)
        assertSplit(" example.com:81 ", 80, host: "example.com", port: 81)
        assertSplit("[::1]", 443, host: "::1", port: 443)
        assertSplit("[::1]:9", 443, host: "::1", port: 9)
        assertSplit("::1", 443, host: "::1", port: 443)
        XCTAssertNil(HTTPInbound.splitHostPort("", defaultPort: 80))
        XCTAssertNil(HTTPInbound.splitHostPort("example.com:0", defaultPort: 80))
        XCTAssertNil(HTTPInbound.splitHostPort("example.com:http", defaultPort: 80))
        XCTAssertNil(HTTPInbound.splitHostPort("[::1", defaultPort: 80))
    }

    func testResponses() {
        XCTAssertEqual(
            String(decoding: HTTPInbound.connectEstablished(version: "HTTP/1.1"), as: UTF8.self),
            "HTTP/1.1 200 Connection established\r\n\r\n"
        )
        XCTAssertEqual(
            String(decoding: HTTPInbound.errorResponse(502, "Bad Gateway"), as: UTF8.self),
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    }

    // MARK: - First data

    func testFirstDataIsCompleteForNonTlsBytes() {
        XCTAssertFalse(InboundFirstData.isComplete(Data()))
        XCTAssertTrue(InboundFirstData.isComplete(Data("GET / HTTP/1.1\r\n".utf8)))
        XCTAssertTrue(InboundFirstData.isComplete(Data([0x53])))
    }

    func testFirstDataWaitsForAWholeTlsRecord() {
        // A handshake record announcing 5 bytes of body.
        let header: [UInt8] = [0x16, 0x03, 0x01, 0x00, 0x05]
        XCTAssertFalse(InboundFirstData.isComplete(Data([0x16, 0x03])))
        XCTAssertFalse(InboundFirstData.isComplete(Data(header)))
        XCTAssertFalse(InboundFirstData.isComplete(Data(header + [1, 2, 3, 4])))
        XCTAssertTrue(InboundFirstData.isComplete(Data(header + [1, 2, 3, 4, 5])))
        XCTAssertTrue(InboundFirstData.isComplete(Data(header + [1, 2, 3, 4, 5, 6])))
    }

    func testFirstDataOnASliceUsesItsOwnIndices() {
        let backing = Data([0xFF, 0xFF, 0x16, 0x03, 0x01, 0x00, 0x01, 0x42])
        let slice = backing.subdata(in: 2..<backing.count)
        XCTAssertTrue(InboundFirstData.isComplete(slice))
        let view = backing[2...]
        XCTAssertTrue(InboundFirstData.isComplete(view))
    }
}
