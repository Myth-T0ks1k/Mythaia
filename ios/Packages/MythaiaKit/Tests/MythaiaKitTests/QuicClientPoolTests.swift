import Foundation
import XCTest
@testable import MythaiaKit

/// What a dial leaves in the Hysteria2/TUIC pool, and what a latency test's
/// release must not take from the tunnel.
///
/// A test across a subscription of thousands of servers would otherwise leave
/// one QUIC session per server — a socket and a keep-alive that never idles
/// out. Each release closes what carries no flow, and never what does: testing
/// the server in use must not cut its flows.
///
/// No network is needed: an obfuscation this build does not speak is refused
/// after the pool has filed the client but before any socket opens, which is
/// exactly the state a failed test leaves behind.
final class QuicClientPoolTests: XCTestCase {
    override func tearDown() {
        QuicClientPool.closeAll()
        super.tearDown()
    }

    /// A Hysteria2 server on the documentation range, unique per call so
    /// tests never share a pooled client.
    private func hysteria(obfuscation: String? = "not-an-obfuscation") -> ProxyConfiguration {
        return ProxyConfiguration(
            name: "pool test",
            serverAddress: "192.0.2.1",
            serverPort: 443,
            uuid: UUID(),
            encryption: "none",
            security: "tls",
            tls: TlsConfiguration(serverName: "example.com"),
            outboundProtocol: .hysteria2,
            password: "secret-\(UUID().uuidString)",
            obfuscation: obfuscation
        )
    }

    // MARK: - Keys

    func testADuplicateUnderAnotherIdSharesTheClient() {
        let live = hysteria()
        var duplicate = live
        duplicate.id = UUID()
        duplicate.name = "duplicate"
        XCTAssertTrue(QuicClientPool.hysteria(live) === QuicClientPool.hysteria(duplicate))
    }

    func testADifferentPasswordIsADifferentSession() {
        let first = hysteria()
        var second = first
        second.password = "other"
        XCTAssertFalse(QuicClientPool.hysteria(first) === QuicClientPool.hysteria(second))
    }

    func testTuicAndHysteriaOnOneAddressAreKeptApart() {
        let config = hysteria()
        var tuic = config
        tuic.outboundProtocol = .tuic
        XCTAssertNotEqual(QuicClientPool.key(config), QuicClientPool.key(tuic))
    }

    // MARK: - Release

    func testReleaseClosesAClientThatCarriesNothing() {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        QuicClientPool.releaseIdle(config)
        XCTAssertTrue(pooled.isClosed)
        XCTAssertFalse(QuicClientPool.isPooled(config))
        // The next dial gets a new client.
        XCTAssertFalse(pooled === QuicClientPool.hysteria(config))
    }

    func testReleaseLeavesAClientCarryingAFlowAlone() {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        pooled.core.flowOpened()
        QuicClientPool.releaseIdle(config)
        XCTAssertFalse(pooled.isClosed)
        XCTAssertTrue(pooled === QuicClientPool.hysteria(config))
        // Its flow ending does not close it either: the release was refused,
        // not deferred, because the session was in use.
        pooled.core.flowClosed()
        XCTAssertFalse(pooled.isClosed)
    }

    func testAReleaseDuringADialClosesTheClientWhenTheDialEnds() {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        pooled.core.beginDial()
        QuicClientPool.releaseIdle(config)
        XCTAssertFalse(pooled.isClosed, "a dial in flight keeps the client for now")
        pooled.core.endDial()
        XCTAssertTrue(pooled.isClosed)
        XCTAssertFalse(QuicClientPool.isPooled(config))
    }

    func testADialThatOpensAFlowCancelsTheDeferredRelease() {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        pooled.core.beginDial()
        QuicClientPool.releaseIdle(config)
        pooled.core.flowOpened()
        pooled.core.endDial()
        XCTAssertFalse(pooled.isClosed)
        XCTAssertTrue(pooled === QuicClientPool.hysteria(config))
    }

    func testCloseAllEmptiesThePool() {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        pooled.core.flowOpened()
        QuicClientPool.closeAll()
        XCTAssertTrue(pooled.isClosed)
        XCTAssertFalse(QuicClientPool.isPooled(config))
    }

    // MARK: - Through the dialer

    func testAnObfuscationThisBuildDoesNotSpeakIsRefusedByName() async {
        let config = hysteria()
        do {
            _ = try await Dialer.connect(config, to: Endpoint(host: "example.com", port: 80), timeout: 5)
            XCTFail("expected a refusal")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .unsupported("Hysteria2 obfuscation not-an-obfuscation"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testReleasingPooledSessionsAfterAFailedDialClosesTheClient() async {
        let config = hysteria()
        let pooled = QuicClientPool.hysteria(config)
        _ = try? await Dialer.connect(config, to: Endpoint(host: "example.com", port: 80), timeout: 5)
        Dialer.releasePooledSessions(config)
        XCTAssertTrue(pooled.isClosed)
        XCTAssertFalse(QuicClientPool.isPooled(config))
    }

    func testALatencyTestLeavesNothingPooled() async {
        let config = hysteria()
        _ = QuicClientPool.hysteria(config)
        let result = await LatencyTester.measure(config, kind: .handshake, timeout: 3)
        XCTAssertNil(result)
        XCTAssertFalse(QuicClientPool.isPooled(config))
    }

    func testAQuicServerBehindAnotherServerIsRefused() async {
        var config = hysteria(obfuscation: nil)
        config.chain = [
            ProxyConfiguration(name: "first", serverAddress: "192.0.2.2", serverPort: 1080,
                               uuid: UUID(), encryption: "none", outboundProtocol: .socks5),
        ]
        let stream = PassThroughStream()
        do {
            _ = try await Dialer.dialQuic(config, below: stream, target: Endpoint(host: "example.com", port: 80),
                                          initialData: nil, resources: DialResources())
            XCTFail("expected a refusal")
        } catch let error as MythaiaError {
            if case .unsupported = error {} else { XCTFail("unexpected \(error)") }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    // MARK: - Flow bookkeeping

    func testAFlowReportsItsEndOnceHoweverOftenItIsClosed() {
        var ended = 0
        let flow = QuicClientFlow(PassThroughStream()) { ended += 1 }
        flow.close()
        flow.close()
        XCTAssertEqual(ended, 1)
    }

    func testADroppedFlowStillReportsItsEnd() {
        var ended = 0
        do {
            _ = QuicClientFlow(PassThroughStream()) { ended += 1 }
        }
        XCTAssertEqual(ended, 1)
    }

    /// A stream that goes nowhere, for the bookkeeping above.
    private final class PassThroughStream: ByteStream, @unchecked Sendable {
        func send(_ data: Data) async throws {}
        func receive() async throws -> Data? { return nil }
        func close() {}
    }
}
