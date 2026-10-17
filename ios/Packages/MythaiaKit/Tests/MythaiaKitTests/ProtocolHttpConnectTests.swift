import Foundation
import XCTest
@testable import MythaiaKit

/// The HTTP/1.1 CONNECT tunnel of the `http11` outbound.
final class ProtocolHttpConnectTests: XCTestCase {
    func testRequestNamesTheDestinationAndCarriesBasicCredentials() {
        let request = NaiveHttp11Connection.connectRequest(destination: Endpoint(host: "example.com", port: 443),
                                                           username: "user", password: "pass")
        let text = String(decoding: request, as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        XCTAssertEqual(lines[0], "CONNECT example.com:443 HTTP/1.1")
        XCTAssertEqual(lines[1], "Host: example.com:443")
        XCTAssertTrue(lines.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"))
        XCTAssertTrue(text.hasSuffix("\r\n\r\n"))
    }

    func testIPv6DestinationIsBracketedAndNoCredentialsMeansNoHeader() {
        let request = NaiveHttp11Connection.connectRequest(destination: Endpoint(host: "2001:db8::1", port: 8443),
                                                           username: nil, password: "pass")
        let text = String(decoding: request, as: UTF8.self)
        XCTAssertTrue(text.hasPrefix("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n"))
        XCTAssertFalse(text.contains("Proxy-Authorization"))
    }

    func testOkOpensTheTunnelAndKeepsBytesBehindTheResponse() async throws {
        let proxy = ProtocolTestStreams.Scripted(reads: [
            Data("HTTP/1.1 200 Connection established\r\n".utf8),
            Data("Proxy-Agent: test\r\n\r\nSSH-2.0".utf8),
        ])
        let stream = try await NaiveHttp11Connection.openTunnel(over: proxy, destination: Endpoint(host: "example.com", port: 22),
                                                                username: nil, password: nil)
        XCTAssertEqual(proxy.writes.count, 1)
        let first = try await stream.receive()
        XCTAssertEqual(first, Data("SSH-2.0".utf8))
    }

    func testProxyAuthenticationRequiredIsReported() async {
        let proxy = ProtocolTestStreams.Scripted(reads: [Data("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".utf8)])
        do {
            _ = try await NaiveHttp11Connection.openTunnel(over: proxy, destination: Endpoint(host: "example.com", port: 443),
                                                           username: nil, password: nil)
            XCTFail("expected an error")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .http(407, "Proxy authentication required"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testMalformedStatusLineIsAnError() {
        XCTAssertThrowsError(try NaiveHttp11Connection.checkResponse(Data("garbage\r\n\r\n".utf8)))
        XCTAssertThrowsError(try NaiveHttp11Connection.checkResponse(Data("SPDY/3 200 OK\r\n\r\n".utf8)))
        XCTAssertNoThrow(try NaiveHttp11Connection.checkResponse(Data("HTTP/1.0 200 OK\r\n\r\n".utf8)))
    }
}
