import Foundation
import XCTest
@testable import MythaiaKit

/// Brutal has no wire format to check against, so the reference here is the
/// algorithm as Hysteria defines it: five one-second sample slots, a fifty
/// sample floor, a minimum ack rate of 0.8 (a loss rate capped at 0.2), a
/// window of `rate * rtt * 2 / ackRate`, and a flat 10240 bytes until an RTT
/// has been measured. The expected numbers below are worked out from those
/// constants and from RFC 6928's ten-packet initial window, not read back out
/// of the implementation.
///
/// Where a window is compared with a tolerance it is because the reference
/// truncates a floating-point byte count to a whole number; the differences
/// being tested are tens of thousands of bytes, so a byte either way proves
/// nothing on its own.
final class QuicBrutalCongestionControlTests: XCTestCase {

    /// One megabyte per second, which makes the arithmetic below readable.
    private let targetBps: Int64 = 1_000_000

    /// Hysteria's own initial max datagram size.
    private let mss = 1252

    private let rtt100ms: Int64 = 100_000_000

    /// `rate * rtt * 2` with no loss: 1 MB/s over 100 ms, doubled.
    private let windowWithoutLoss: Int64 = 200_000

    private func controller(bps: Int64? = nil) -> BrutalCongestionControl {
        return BrutalCongestionControl(initialBytesPerSecond: bps ?? targetBps)
    }

    private func record(_ cc: BrutalCongestionControl, acks: Int, losses: Int, at nowNanos: Int64) {
        for _ in 0..<acks {
            cc.onPacketAcked(nowNanos)
        }
        for _ in 0..<losses {
            cc.onPacketLost(nowNanos)
        }
    }

    private func window(
        _ cc: BrutalCongestionControl,
        at nowNanos: Int64 = 0,
        rtt: Int64? = nil,
        datagramSize: Int? = nil
    ) -> BrutalCongestionControl.Window? {
        return cc.window(
            nowNanos: nowNanos,
            smoothedRttNanos: rtt ?? rtt100ms,
            maxDatagramSize: datagramSize ?? mss
        )
    }

    private func cwnd(
        _ cc: BrutalCongestionControl,
        at nowNanos: Int64 = 0,
        rtt: Int64? = nil,
        datagramSize: Int? = nil
    ) throws -> Int64 {
        return try XCTUnwrap(window(cc, at: nowNanos, rtt: rtt, datagramSize: datagramSize)).cwndBytes
    }

    // MARK: - The constants

    func testTheConstantsAreHysteriasOwn() {
        XCTAssertEqual(BrutalCongestionControl.slotCount, 5)
        XCTAssertEqual(BrutalCongestionControl.minSampleCount, 50)
        XCTAssertEqual(BrutalCongestionControl.maxLossRate, 0.2)
        XCTAssertEqual(BrutalCongestionControl.congestionWindowMultiplier, 2.0)
        XCTAssertEqual(BrutalCongestionControl.minCwndPackets, 10)
        XCTAssertEqual(BrutalCongestionControl.initialCwndBytes, 10_240)
        XCTAssertEqual(BrutalCongestionControl.maxSendQuantumBytes, 65_536)
    }

    // MARK: - The window before an RTT exists

    func testBeforeTheFirstRttSampleTheWindowIsTheFlatSeed() throws {
        // Hysteria returns a flat 10240 bytes while the RTT is unknown rather
        // than evaluating its formula against a made-up round trip.
        XCTAssertEqual(try cwnd(controller(), rtt: 0, datagramSize: 500), 10_240)
    }

    func testTheFlatSeedIsStillLiftedToTenPackets() throws {
        // 10 * 1252 is larger than 10240, and RFC 6928's window wins.
        XCTAssertEqual(try cwnd(controller(), rtt: 0), 12_520)
    }

    func testLossCannotChangeTheWindowBeforeAnRttExists() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)
        XCTAssertEqual(try cwnd(cc, rtt: 0, datagramSize: 500), 10_240)
    }

    // MARK: - The formula

    func testWithNoLossTheWindowIsTwiceTheBandwidthDelayProduct() throws {
        XCTAssertEqual(try cwnd(controller()), windowWithoutLoss)
    }

    func testAcknowledgementsOnTheirOwnNeverInflateTheWindow() throws {
        let cc = controller()
        record(cc, acks: 200, losses: 0, at: 0)
        XCTAssertEqual(try cwnd(cc), windowWithoutLoss)
    }

    func testTheWindowScalesWithTheTargetRate() throws {
        let cc = controller()
        cc.targetBytesPerSecond = 2 * targetBps
        XCTAssertEqual(try cwnd(cc), 2 * windowWithoutLoss)
    }

    func testAnUnknownTargetRateProducesNoWindowAtAll() {
        // Nothing to say beats writing a zero window into a live connection.
        XCTAssertNil(window(controller(bps: 0)))
        XCTAssertNil(window(controller(bps: -1)))
    }

    // MARK: - The sample floor

    func testALossRateBelowTheSampleFloorIsIgnored() throws {
        let cc = controller()
        // Forty-nine samples: one short of the fifty Hysteria requires.
        record(cc, acks: 45, losses: 4, at: 0)
        XCTAssertEqual(cc.observedLossRate(0), 0.0)
        XCTAssertEqual(try cwnd(cc), windowWithoutLoss)
    }

    func testTheFiftiethSampleBringsTheLossRateIntoEffect() throws {
        let cc = controller()
        record(cc, acks: 46, losses: 4, at: 0)
        XCTAssertEqual(cc.observedLossRate(0), 0.08, accuracy: 1e-12)
        // 1 MB/s over 100 ms, doubled, divided by an ack rate of 0.92.
        let measured = try cwnd(cc)
        XCTAssertEqual(Double(measured), 217_391.0, accuracy: 2.0)
    }

    func testSamplesFromDifferentSecondsAddUpTowardsTheFloor() {
        let cc = controller()
        record(cc, acks: 0, losses: 30, at: 0)
        XCTAssertEqual(cc.observedLossRate(0), 0.0)

        record(cc, acks: 0, losses: 25, at: 1_000_000_000)
        // Fifty-five samples spread over two slots still clear the floor.
        XCTAssertEqual(cc.observedLossRate(1_000_000_000), 1.0)
    }

    // MARK: - The loss-rate cap

    func testTheLossRateIsCappedBeforeItReachesTheWindow() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)

        // The measurement itself is honest about a link dropping everything.
        XCTAssertEqual(cc.observedLossRate(0), 1.0)
        // The window uses Hysteria's minimum ack rate of 0.8 instead, which
        // inflates by a quarter and no further.
        let measured = try cwnd(cc)
        XCTAssertEqual(Double(measured), 250_000.0, accuracy: 2.0)
    }

    func testALossRateAtTheCapAndOneFarAboveItGiveTheSameWindow() throws {
        let atCap = controller()
        record(atCap, acks: 80, losses: 20, at: 0)
        XCTAssertEqual(atCap.observedLossRate(0), 0.2, accuracy: 1e-12)

        let wayOver = controller()
        record(wayOver, acks: 10, losses: 90, at: 0)

        XCTAssertEqual(try cwnd(atCap), try cwnd(wayOver))
    }

    func testALossRateUnderTheCapIsUsedAsMeasured() throws {
        let cc = controller()
        record(cc, acks: 90, losses: 10, at: 0)
        XCTAssertEqual(cc.observedLossRate(0), 0.1, accuracy: 1e-12)
        // Doubled bandwidth-delay product over an ack rate of 0.9.
        let measured = try cwnd(cc)
        XCTAssertEqual(Double(measured), 222_222.0, accuracy: 2.0)
    }

    // MARK: - The RFC 6928 floor

    func testTheWindowNeverDropsBelowTenPackets() throws {
        // A kilobyte per second over a millisecond asks for two bytes.
        let cc = controller(bps: 1000)
        XCTAssertEqual(try cwnd(cc, rtt: 1_000_000, datagramSize: 1200), 10 * 1200)
    }

    func testTheFloorSurvivesALossRateThatWouldOtherwiseRaiseTheWindow() throws {
        let cc = controller(bps: 1000)
        record(cc, acks: 0, losses: 100, at: 0)
        XCTAssertEqual(try cwnd(cc, rtt: 1_000_000, datagramSize: 1200), 10 * 1200)
    }

    func testADatagramSizeOfZeroStillLeavesAFloorOfTenPackets() throws {
        let cc = controller(bps: 1000)
        XCTAssertEqual(try cwnd(cc, rtt: 1_000_000, datagramSize: 0), 10)
    }

    // MARK: - Slots expiring

    func testSamplesSurviveToTheLastSecondOfTheWindow() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)

        // Four seconds on, second zero is still one of the five being counted.
        XCTAssertEqual(cc.observedLossRate(4_999_999_999), 1.0)
        let measured = try cwnd(cc, at: 4_999_999_999)
        XCTAssertEqual(Double(measured), 250_000.0, accuracy: 2.0)
    }

    func testSamplesFallOutOnceTheWindowHasMovedPastThem() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)

        // Five seconds on, the slot holding them is the one being reused.
        XCTAssertEqual(cc.observedLossRate(5_000_000_000), 0.0)
        XCTAssertEqual(try cwnd(cc, at: 5_000_000_000), windowWithoutLoss)
    }

    func testASlotReusedForALaterSecondDoesNotCarryTheOldCounts() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)
        // Second five lands on the slot second zero used.
        record(cc, acks: 60, losses: 0, at: 5_000_000_000)

        XCTAssertEqual(cc.observedLossRate(5_000_000_000), 0.0)
        XCTAssertEqual(try cwnd(cc, at: 5_000_000_000), windowWithoutLoss)
    }

    func testTheRateIsTakenFromExactlyTheSecondsStillInTheWindow() {
        let cc = controller()
        record(cc, acks: 60, losses: 0, at: 0)
        record(cc, acks: 0, losses: 60, at: 3_000_000_000)

        // Both seconds are in reach, so half of what was sent was lost.
        XCTAssertEqual(cc.observedLossRate(3_000_000_000), 0.5, accuracy: 1e-12)
        // Second zero is the fifth and last second visible from second four.
        XCTAssertEqual(cc.observedLossRate(4_000_000_000), 0.5, accuracy: 1e-12)
        // From second five only the losses remain.
        XCTAssertEqual(cc.observedLossRate(5_000_000_000), 1.0)
    }

    func testAClockReadingFromBeforeItsOwnOriginIsStillAccountedFor() {
        // A monotonic clock may hand out negative readings; the slot ring has
        // to take them without folding onto a negative index.
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: -3_500_000_000)

        XCTAssertEqual(cc.observedLossRate(-3_500_000_000), 1.0)
        XCTAssertEqual(cc.observedLossRate(1_500_000_000), 0.0)
    }

    func testAResetForgetsEverySample() throws {
        let cc = controller()
        record(cc, acks: 0, losses: 100, at: 0)
        cc.reset()

        XCTAssertEqual(cc.observedLossRate(0), 0.0)
        XCTAssertEqual(try cwnd(cc), windowWithoutLoss)
    }

    // MARK: - Pacing

    func testThePacingIntervalIsNanosecondsPerByteInNgtcp2FixedPoint() throws {
        // A megabyte per second is a microsecond per kilobyte, so 1000 ns per
        // byte; ngtcp2 carries that shifted left by ten.
        XCTAssertEqual(try XCTUnwrap(window(controller())).pacingIntervalM, 1000 * 1024)
        // Twice the rate is half the interval.
        XCTAssertEqual(try XCTUnwrap(window(controller(bps: 2_000_000))).pacingIntervalM, 500 * 1024)
    }

    func testLossShortensThePacingIntervalBecauseThePacedRateRises() throws {
        let cc = controller()
        let quiet = try XCTUnwrap(window(cc)).pacingIntervalM
        record(cc, acks: 0, losses: 100, at: 0)
        let lossy = try XCTUnwrap(window(cc)).pacingIntervalM

        // A capped loss rate of 0.2 paces at 1.25 MB/s, so 800 ns per byte.
        XCTAssertEqual(Double(lossy), 800.0 * 1024, accuracy: 2.0)
        XCTAssertLessThan(lossy, quiet)
    }

    // MARK: - Send quantum

    func testTheSendQuantumIsAMillisecondOfBytes() throws {
        // 20 MB/s is 20000 bytes per millisecond, between the floor and the cap.
        XCTAssertEqual(try XCTUnwrap(window(controller(bps: 20_000_000))).sendQuantumBytes, 20_000)
    }

    func testTheSendQuantumIsFlooredAtTenPackets() throws {
        // A megabyte per second is only 1000 bytes per millisecond.
        XCTAssertEqual(try XCTUnwrap(window(controller())).sendQuantumBytes, Int64(10 * mss))
    }

    func testTheSendQuantumIsCappedAt64KiB() throws {
        XCTAssertEqual(try XCTUnwrap(window(controller(bps: 1_000_000_000))).sendQuantumBytes, 65_536)
    }

    func testTheSendQuantumDoesNotDependOnTheRtt() throws {
        let cc = controller(bps: 20_000_000)
        XCTAssertEqual(
            try XCTUnwrap(window(cc, rtt: 0)).sendQuantumBytes,
            try XCTUnwrap(window(cc)).sendQuantumBytes
        )
    }
}
