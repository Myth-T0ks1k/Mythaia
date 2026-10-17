import Foundation
import XCTest
@testable import MythaiaKit

final class EngineTunnelMessageTests: XCTestCase {
    // MARK: - Messages

    private func roundTrip(_ message: TunnelMessage) throws -> TunnelMessage {
        try TunnelMessage.decode(try message.encoded())
    }

    func testSimpleMessagesRoundTrip() throws {
        let stats = try roundTrip(.stats)
        guard case .stats = stats else { return XCTFail("stats") }
        let logTail = try roundTrip(.logTail)
        guard case .logTail = logTail else { return XCTFail("logTail") }
        let ping = try roundTrip(.ping)
        guard case .ping = ping else { return XCTFail("ping") }
        let reload = try roundTrip(.reload)
        guard case .reload = reload else { return XCTFail("reload") }
        let appActive = try roundTrip(.appActive(true))
        guard case .appActive(let active) = appActive else { return XCTFail("appActive") }
        XCTAssertTrue(active)
    }

    func testMessagesAreTaggedByType() throws {
        let data = try TunnelMessage.appActive(false).encoded()
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["type"] as? String, "appActive")
        XCTAssertEqual(object["active"] as? Bool, false)

        let ping = try TunnelMessage.decode(Data("{\"type\":\"ping\"}".utf8))
        guard case .ping = ping else { return XCTFail("ping from plain JSON") }
    }

    func testUnknownMessagesAreRefused() {
        XCTAssertThrowsError(try TunnelMessage.decode(Data("{\"type\":\"selfDestruct\"}".utf8)))
        XCTAssertThrowsError(try TunnelMessage.decode(Data("{}".utf8)))
        XCTAssertThrowsError(try TunnelMessage.decode(Data("{\"type\":\"switchConfiguration\"}".utf8)))
    }

    func testRepliesRoundTrip() throws {
        let id = UUID()
        let stats = TrafficStats(uploadBytes: 10, downloadBytes: 2048, uploadSpeed: 1, downloadSpeed: 512, connections: 3)
        let reply = TunnelReply(stats: stats, logLines: ["a", "b"], configurationId: id, configurationName: "Home", port: 1080)
        let decoded = try TunnelReply.decode(try reply.encoded())
        XCTAssertTrue(decoded.ok)
        XCTAssertNil(decoded.error)
        XCTAssertEqual(decoded.stats, stats)
        XCTAssertEqual(decoded.logLines, ["a", "b"])
        XCTAssertEqual(decoded.configurationId, id)
        XCTAssertEqual(decoded.configurationName, "Home")
        XCTAssertEqual(decoded.port, 1080)

        let failure = try TunnelReply.decode(try TunnelReply.failure("The tunnel is not running").encoded())
        XCTAssertFalse(failure.ok)
        XCTAssertEqual(failure.error, "The tunnel is not running")
    }

    // MARK: - Log ring

    func testLogRingKeepsTheNewestLinesInOrder() {
        let ring = LogRingBuffer(capacity: 3)
        XCTAssertTrue(ring.lines().isEmpty)
        for index in 1...5 {
            ring.append("line \(index)")
        }
        XCTAssertEqual(ring.lines(), ["line 3", "line 4", "line 5"])
        XCTAssertEqual(ring.lines(last: 2), ["line 4", "line 5"])
        XCTAssertEqual(ring.count, 3)
        ring.clear()
        XCTAssertTrue(ring.lines().isEmpty)
        ring.append("again")
        XCTAssertEqual(ring.lines(), ["again"])
    }

    func testLogRingCutsLongLinesAndStampsLevels() {
        let ring = LogRingBuffer(capacity: 2)
        ring.append(String(repeating: "x", count: LogRingBuffer.maxLineLength * 2))
        XCTAssertEqual(ring.lines().first?.count, LogRingBuffer.maxLineLength + 3)

        ring.append(level: .warning, message: "careful", date: Date(timeIntervalSince1970: 0))
        let last = ring.lines().last ?? ""
        XCTAssertTrue(last.hasSuffix(" W careful"), last)
    }

    // MARK: - Traffic

    func testTrafficSpeedIsComputedOverTheLastSample() {
        let counter = TrafficCounter()
        counter.connectionOpened()
        counter.connectionOpened()
        let first = counter.snapshot(now: 100)
        XCTAssertEqual(first.uploadSpeed, 0)
        XCTAssertEqual(first.connections, 2)

        counter.addUp(1000)
        counter.addDown(4000)
        let second = counter.snapshot(now: 102)
        XCTAssertEqual(second.uploadBytes, 1000)
        XCTAssertEqual(second.downloadBytes, 4000)
        XCTAssertEqual(second.uploadSpeed, 500)
        XCTAssertEqual(second.downloadSpeed, 2000)

        // Asked again too soon: the last speed stands.
        counter.addDown(100)
        let third = counter.snapshot(now: 102.1)
        XCTAssertEqual(third.downloadSpeed, 2000)
        XCTAssertEqual(third.downloadBytes, 4100)

        counter.connectionClosed()
        counter.connectionClosed()
        counter.connectionClosed()
        XCTAssertEqual(counter.snapshot(now: 110).connections, 0)
    }
}
