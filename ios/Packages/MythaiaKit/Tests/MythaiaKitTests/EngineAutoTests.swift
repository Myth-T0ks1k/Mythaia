import Foundation
import XCTest
@testable import MythaiaKit

final class EngineAutoTests: XCTestCase {
    // MARK: - Switching margin

    func testADeadLiveServerIsAlwaysLeft() {
        XCTAssertTrue(AutoPolicy.worthSwitching(liveMs: nil, candidateMs: 5000))
    }

    func testGainMustBeatBothTheFloorAndTheShare() {
        // 1000 ms live: 30 % is 300 ms, above the 150 ms floor.
        XCTAssertTrue(AutoPolicy.worthSwitching(liveMs: 1000, candidateMs: 700))
        XCTAssertFalse(AutoPolicy.worthSwitching(liveMs: 1000, candidateMs: 701))
        // 300 ms live: 30 % is 90 ms, so the 150 ms floor applies.
        XCTAssertFalse(AutoPolicy.worthSwitching(liveMs: 300, candidateMs: 200))
        XCTAssertTrue(AutoPolicy.worthSwitching(liveMs: 300, candidateMs: 150))
        // A slower candidate never wins.
        XCTAssertFalse(AutoPolicy.worthSwitching(liveMs: 300, candidateMs: 400))
    }

    func testPickMovesOnlyForAWorthwhileGain() {
        let live = UUID()
        let fast = UUID()
        let slow = UUID()

        let small = AutoPolicy.pick(results: [live: 400, fast: 300, slow: 900], liveId: live)
        XCTAssertEqual(small?.id, fast)
        XCTAssertEqual(small?.ms, 300)
        XCTAssertEqual(small?.shouldSwitch, false)

        let big = AutoPolicy.pick(results: [live: 900, fast: 300], liveId: live)
        XCTAssertEqual(big?.shouldSwitch, true)

        let liveFailed = AutoPolicy.pick(results: [fast: 1200], liveId: live)
        XCTAssertEqual(liveFailed?.id, fast)
        XCTAssertEqual(liveFailed?.shouldSwitch, true)

        let liveIsBest = AutoPolicy.pick(results: [live: 100, fast: 200], liveId: live)
        XCTAssertEqual(liveIsBest?.id, live)
        XCTAssertEqual(liveIsBest?.shouldSwitch, false)

        XCTAssertNil(AutoPolicy.pick(results: [:], liveId: live))
    }

    // MARK: - Rounds

    func testRoundDue() {
        XCTAssertTrue(AutoPolicy.roundDue(now: 5, lastRoundAt: nil))
        XCTAssertFalse(AutoPolicy.roundDue(now: 100, lastRoundAt: 0, interval: 600))
        XCTAssertTrue(AutoPolicy.roundDue(now: 600, lastRoundAt: 0, interval: 600))
    }

    func testASmallGroupIsMeasuredWhole() {
        let ids = (0..<AutoPolicy.maxRound).map { _ in UUID() }
        XCTAssertEqual(AutoPolicy.roundSample(ids, liveId: ids[3], known: [:]), ids)
    }

    func testABigGroupIsSampled() {
        let ids = (0..<200).map { _ in UUID() }
        let live = ids[150]
        var known: [UUID: Int] = [:]
        // Thirty servers answered lately; the faster half of the round's room
        // goes to the 24 fastest of them.
        for index in 0..<30 {
            known[ids[index * 5]] = 1000 - index * 10
        }
        let sample = AutoPolicy.roundSample(ids, liveId: live, known: known, shuffle: { $0 })

        XCTAssertEqual(sample.count, AutoPolicy.maxRound)
        XCTAssertEqual(Set(sample).count, sample.count, "no duplicates")
        XCTAssertEqual(sample.first, live)
        let fastest = known.sorted { $0.value < $1.value }.prefix(AutoPolicy.maxRound / 2).map { $0.key }
        for id in fastest {
            XCTAssertTrue(sample.contains(id))
        }
        let slowest = known.sorted { $0.value > $1.value }.first!.key
        let slowestIndex = ids.firstIndex(of: slowest)!
        XCTAssertEqual(slowestIndex, 0)
        // With an identity shuffle the rest is filled in list order, and the
        // slowest known server (index 0) is first in that order.
        XCTAssertTrue(sample.contains(slowest))
    }

    func testAMissingLiveServerIsNotAdded() {
        let ids = (0..<100).map { _ in UUID() }
        let sample = AutoPolicy.roundSample(ids, liveId: UUID(), known: [:], shuffle: { $0 })
        XCTAssertEqual(sample, Array(ids.prefix(AutoPolicy.maxRound)))
    }

    // MARK: - Reconnect bound

    func testUnattendedReconnectsAreBounded() {
        var attempts: [Double] = []
        for index in 0..<AutoPolicy.reconnectMax {
            let decision = AutoPolicy.admitReconnect(attempts: attempts, now: Double(index))
            XCTAssertTrue(decision.allowed)
            attempts = decision.attempts
        }
        let refused = AutoPolicy.admitReconnect(attempts: attempts, now: 10)
        XCTAssertFalse(refused.allowed)
        let later = AutoPolicy.admitReconnect(attempts: refused.attempts, now: AutoPolicy.reconnectWindowSeconds + 5)
        XCTAssertTrue(later.allowed)
        XCTAssertEqual(later.attempts.count, 1)
    }

    func testSelectorKeepsItsOwnClockAndRoundClaim() {
        let clock = TestClock()
        let selector = AutoSelector(recheckInterval: 600, measure: { _ in nil }, clock: { clock.now })
        XCTAssertTrue(selector.roundDue())
        selector.markRound()
        XCTAssertFalse(selector.roundDue())
        clock.now = 599
        XCTAssertFalse(selector.roundDue())
        clock.now = 600
        XCTAssertTrue(selector.roundDue())

        XCTAssertTrue(selector.beginRound())
        XCTAssertFalse(selector.beginRound())
        selector.endRound()
        XCTAssertTrue(selector.beginRound())
        selector.endRound()

        for _ in 0..<AutoPolicy.reconnectMax {
            XCTAssertTrue(selector.mayReconnect())
        }
        XCTAssertFalse(selector.mayReconnect())
        clock.now += AutoPolicy.reconnectWindowSeconds + 1
        XCTAssertTrue(selector.mayReconnect())
    }

    func testMeasuringNothingFindsNothing() async {
        let selector = AutoSelector(measure: { _ in 100 })
        let results = await selector.measure([])
        XCTAssertTrue(results.isEmpty)
        let round = await selector.runRound(candidates: [], liveId: nil)
        XCTAssertNil(round.best)
        XCTAssertFalse(round.shouldSwitch)
    }
}

private final class TestClock: @unchecked Sendable {
    var now: Double = 0
}
