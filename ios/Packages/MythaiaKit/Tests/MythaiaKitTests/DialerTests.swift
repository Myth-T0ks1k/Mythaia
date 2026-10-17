import Foundation
import XCTest
@testable import MythaiaKit

/// The dialer's choices, checked without a network: what it refuses before
/// dialling, which TLS and ALPN each hop gets, and how its deadline and
/// retries behave.
final class DialerTests: XCTestCase {
    private let target = Endpoint(host: "example.com", port: 443)

    private func server(_ outbound: OutboundProtocol) -> ProxyConfiguration {
        var configuration = ProxyConfiguration(
            name: "test",
            serverAddress: "192.0.2.1",
            serverPort: 443,
            uuid: UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811")!,
            encryption: "none"
        )
        configuration.outboundProtocol = outbound
        return configuration
    }

    private func expectError(_ expected: MythaiaError, file: StaticString = #filePath, line: UInt = #line,
                             _ body: () async throws -> Void) async {
        do {
            try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as MythaiaError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    // MARK: - Refused before dialling

    func testProtocolsThatNeedQuicOrAreNotPortedAreRefusedByName() async {
        for outbound in [OutboundProtocol.hysteria2, .tuic, .anytls, .wireguard, .sudoku, .nowhere, .naiveHttp2] {
            await expectError(.unsupported(outbound.displayName)) {
                _ = try await Dialer.connect(server(outbound), to: target, timeout: 2)
            }
        }
    }

    func testAnUnsupportedHopInTheChainIsRefusedToo() async {
        var exit = server(.trojan)
        exit.chain = [server(.hysteria2)]
        await expectError(.unsupported("Hysteria2")) {
            _ = try await Dialer.connect(exit, to: target, timeout: 2)
        }
    }

    func testVlessEncryptionIsRefusedRatherThanDowngraded() async {
        var configuration = server(.vless)
        configuration.encryption = "mlkem768x25519plus.native.0rtt.abc"
        await expectError(.unsupported("VLESS encryption")) {
            _ = try await Dialer.connect(configuration, to: target, timeout: 2)
        }
    }

    func testVisionOverWebSocketIsRefused() async {
        var configuration = server(.vless)
        configuration.flow = "xtls-rprx-vision"
        configuration.transport = "ws"
        configuration.security = "tls"
        configuration.tls = TlsConfiguration(serverName: "example.com")
        configuration.websocket = WebSocketConfiguration(host: "example.com")
        await expectError(.invalidConfiguration("Vision flow is not supported over WebSocket transport")) {
            _ = try await Dialer.connect(configuration, to: target, timeout: 2)
        }
    }

    func testVisionWithoutTlsIsRefusedBeforeTheUuidLeaves() async {
        var configuration = server(.vless)
        configuration.flow = "xtls-rprx-vision"
        await expectError(.invalidConfiguration("Vision requires outer TLS or REALITY transport")) {
            _ = try await Dialer.connect(configuration, to: target, timeout: 2)
        }
    }

    func testUdpIsRefusedWhereTheProtocolHasNone() async {
        await expectError(.unsupported("UDP through HTTPS")) {
            _ = try await Dialer.connectUDP(server(.naiveHttp11), to: target, timeout: 2)
        }
        var vision = server(.vless)
        vision.flow = "xtls-rprx-vision"
        vision.security = "tls"
        vision.tls = TlsConfiguration(serverName: "example.com")
        await expectError(.unsupported("UDP to port 443 through XTLS Vision")) {
            _ = try await Dialer.connectUDP(vision, to: Endpoint(host: "1.1.1.1", port: 443), timeout: 2)
        }
    }

    // MARK: - Choices per hop

    func testTransportAliases() {
        XCTAssertEqual(Dialer.transportName(""), "tcp")
        XCTAssertEqual(Dialer.transportName("raw"), "tcp")
        XCTAssertEqual(Dialer.transportName("WS"), "ws")
        XCTAssertEqual(Dialer.transportName("splithttp"), "xhttp")
    }

    func testAlpnPerTransport() {
        let tls = DialSecurity.tls(TlsConfiguration(serverName: "example.com", alpn: ["h2"]))
        XCTAssertEqual(Dialer.alpn(transport: "ws", security: tls), ["http/1.1"])
        XCTAssertEqual(Dialer.alpn(transport: "httpupgrade", security: tls), ["http/1.1"])
        XCTAssertEqual(Dialer.alpn(transport: "grpc", security: tls), ["h2"])
        XCTAssertEqual(Dialer.alpn(transport: "tcp", security: tls), ["h2"])
        XCTAssertEqual(Dialer.alpn(transport: "tcp", security: .tls(TlsConfiguration(serverName: "x"))), ["h2", "http/1.1"])
        let reality = DialSecurity.reality(RealityConfiguration(serverName: "x", publicKey: Data(count: 32), shortId: Data()))
        XCTAssertEqual(Dialer.alpn(transport: "grpc", security: reality), ["h2", "http/1.1"])
    }

    func testXhttpVersionFollowsTheAlpn() throws {
        XCTAssertEqual(try Dialer.xhttpVersion(.none), .http11)
        XCTAssertEqual(try Dialer.xhttpVersion(.tls(TlsConfiguration(serverName: "x"))), .http2)
        XCTAssertEqual(try Dialer.xhttpVersion(.tls(TlsConfiguration(serverName: "x", alpn: ["http/1.1"]))), .http11)
        XCTAssertThrowsError(try Dialer.xhttpVersion(.tls(TlsConfiguration(serverName: "x", alpn: ["h3"]))))
        XCTAssertEqual(Dialer.xhttpAlpn(.http2, security: .tls(TlsConfiguration(serverName: "x", alpn: ["h3", "h2"]))), ["h2"])
        XCTAssertEqual(Dialer.xhttpAlpn(.http2, security: .tls(TlsConfiguration(serverName: "x", alpn: ["http/1.1", "h3"]))), ["h2", "http/1.1"])
    }

    func testVlessSecurityFollowsTheSettings() throws {
        var configuration = server(.vless)
        guard case .none = try Dialer.vlessSecurity(configuration, transport: "tcp") else {
            return XCTFail("plain")
        }
        configuration.security = "reality"
        configuration.reality = RealityConfiguration(serverName: "x", publicKey: Data(count: 32), shortId: Data())
        guard case .reality = try Dialer.vlessSecurity(configuration, transport: "tcp") else {
            return XCTFail("reality")
        }
        XCTAssertThrowsError(try Dialer.vlessSecurity(configuration, transport: "ws"))
        configuration.security = "tls"
        configuration.reality = nil
        XCTAssertThrowsError(try Dialer.vlessSecurity(configuration, transport: "tcp"), "TLS selected with no settings")
    }

    func testTrojanFallsBackToTheSharedTlsSettings() throws {
        var configuration = server(.trojan)
        XCTAssertThrowsError(try Dialer.trojanTls(configuration))
        configuration.tls = TlsConfiguration(serverName: "shared")
        XCTAssertEqual(try Dialer.trojanTls(configuration).serverName, "shared")
        configuration.trojanTls = TlsConfiguration(serverName: "own")
        XCTAssertEqual(try Dialer.trojanTls(configuration).serverName, "own")
    }

    func testGrpcAuthority() {
        let hop = server(.vless)
        XCTAssertEqual(Dialer.grpcAuthority(GrpcConfiguration(authority: "a.example"), hop: hop, security: .none), "a.example")
        XCTAssertEqual(Dialer.grpcAuthority(GrpcConfiguration(), hop: hop, security: .tls(TlsConfiguration(serverName: "sni.example"))), "sni.example")
        XCTAssertEqual(Dialer.grpcAuthority(GrpcConfiguration(), hop: hop, security: .none), "192.0.2.1")
    }

    func testPinnedDigestsDecodeHexWithOrWithoutColons() {
        let hex = String(repeating: "ab", count: 32)
        let colons = (0..<32).map { _ in "AB" }.joined(separator: ":")
        XCTAssertEqual(Dialer.pinnedDigests([hex, colons, "nothex", "abcd"]), [Data(repeating: 0xAB, count: 32), Data(repeating: 0xAB, count: 32)])
        XCTAssertEqual(Dialer.pinnedDigests(nil), [])
    }

    // MARK: - Deadline and retries

    /// A dial stuck on a silent server is unblocked by closing what it
    /// opened, and fails with a timeout.
    func testDeadlineClosesWhatTheDialOpened() async {
        let (a, _) = ProtocolTestStreams.pair()
        let resources = DialResources()
        let started = Date()
        await expectError(.timeout("connecting")) {
            _ = try await Dialer.runDial(timeout: 0.2, what: "connecting", resources: resources) { () async throws -> ByteStream in
                resources.track(a)
                _ = try await a.receive()
                return a
            }
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testRetriesStopAtWhatCannotGetBetter() async {
        let resources = DialResources()
        var attempts = 0
        await expectError(.invalidConfiguration("bad")) {
            _ = try await Dialer.withRetries(5, resources: resources) { () async throws -> Int in
                attempts += 1
                throw MythaiaError.invalidConfiguration("bad")
            }
        }
        XCTAssertEqual(attempts, 1)

        attempts = 0
        let value = try? await Dialer.withRetries(3, resources: resources) { () async throws -> Int in
            attempts += 1
            if attempts < 3 { throw MythaiaError.connectFailed("refused") }
            return 7
        }
        XCTAssertEqual(value, 7)
        XCTAssertEqual(attempts, 3)
    }

    func testRetryableErrors() {
        XCTAssertTrue(Dialer.isRetryable(MythaiaError.connectFailed("x")))
        XCTAssertTrue(Dialer.isRetryable(MythaiaError.closed))
        XCTAssertFalse(Dialer.isRetryable(MythaiaError.unsupported("x")))
        XCTAssertFalse(Dialer.isRetryable(MythaiaError.tls("certificate is not trusted")))
        XCTAssertTrue(Dialer.isRetryable(MythaiaError.tls("handshake reset")))
        XCTAssertFalse(Dialer.isRetryable(CancellationError()))
    }
}
