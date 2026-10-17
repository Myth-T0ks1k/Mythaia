import Foundation
import XCTest
@testable import MythaiaKit

/// The identifiers are checked against RFC 9000 §18.2 written out by hand, and
/// the algorithm numbers against the vendored `ngtcp2.h`. Neither is derived
/// from the code under test: a table that only agrees with itself would let a
/// transposed identifier through, and a peer's response to a parameter it does
/// not recognise is to ignore it silently.
final class QuicTuningTests: XCTestCase {

    private let presets: [(name: String, tuning: QuicTuning)] = [
        ("naive", QuicTuning.naive),
        ("nowhere", QuicTuning.nowhere),
        ("hysteria/brutal", QuicTuning.hysteria(.brutal, uploadMbps: 100)),
        ("hysteria/bbr", QuicTuning.hysteria(.bbr, uploadMbps: 0)),
    ]

    private let mib: Int64 = 1024 * 1024

    /// The value advertised under `id`, failing the test when there is none.
    private func advertised(_ tuning: QuicTuning, _ id: Int, _ name: String) -> Int64? {
        guard let parameter = tuning.advertisedParameters.first(where: { $0.id == id }) else {
            XCTFail("\(name) does not advertise 0x\(String(id, radix: 16))")
            return nil
        }
        return parameter.value
    }

    /// The naive preset with one or two fields changed, through the same
    /// checking initialiser every preset goes through.
    private func naive(
        initialMaxStreamsBidi: Int64? = nil,
        disableActiveMigration: Bool = false
    ) throws -> QuicTuning {
        let base = QuicTuning.naive
        return try QuicTuning(
            congestionControl: base.congestionControl,
            maxStreamWindow: base.maxStreamWindow,
            maxWindow: base.maxWindow,
            initialMaxData: base.initialMaxData,
            initialMaxStreamDataBidiLocal: base.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: base.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: base.initialMaxStreamDataUni,
            initialMaxStreamsBidi: initialMaxStreamsBidi ?? base.initialMaxStreamsBidi,
            initialMaxStreamsUni: base.initialMaxStreamsUni,
            maxIdleTimeoutNanos: base.maxIdleTimeoutNanos,
            handshakeTimeoutNanos: base.handshakeTimeoutNanos,
            keepAliveTimeoutNanos: base.keepAliveTimeoutNanos,
            disableActiveMigration: disableActiveMigration
        )
    }

    /// The opening Brutal rate for a declared upload, in bytes per second.
    private func brutalRate(_ uploadMbps: Int) -> Int64? {
        let tuning = QuicTuning.hysteria(.brutal, uploadMbps: uploadMbps)
        if case .brutal(initialBytesPerSecond: let rate) = tuning.congestionControl {
            return rate
        }
        XCTFail("hysteria/brutal is not on Brutal")
        return nil
    }

    // MARK: - RFC 9000 §18.2

    func testTheTransportParameterIdentifiersAreTheOnesTheRfcAssigns() {
        XCTAssertEqual(QuicTransportParameterId.maxIdleTimeout, 0x01)
        XCTAssertEqual(QuicTransportParameterId.initialMaxData, 0x04)
        XCTAssertEqual(QuicTransportParameterId.initialMaxStreamDataBidiLocal, 0x05)
        XCTAssertEqual(QuicTransportParameterId.initialMaxStreamDataBidiRemote, 0x06)
        XCTAssertEqual(QuicTransportParameterId.initialMaxStreamDataUni, 0x07)
        XCTAssertEqual(QuicTransportParameterId.initialMaxStreamsBidi, 0x08)
        XCTAssertEqual(QuicTransportParameterId.initialMaxStreamsUni, 0x09)
        XCTAssertEqual(QuicTransportParameterId.disableActiveMigration, 0x0c)
    }

    func testEachFieldIsAdvertisedUnderItsOwnIdentifier() {
        // 0x00, 0x02, 0x03, 0x0a, 0x0b, 0x0d..0x10 exist in the registry but
        // are either server-only or left to ngtcp2's defaults, so they are not
        // expected here.
        for (name, tuning) in presets {
            XCTAssertEqual(advertised(tuning, 0x01, name), tuning.maxIdleTimeoutMillis, name)
            XCTAssertEqual(advertised(tuning, 0x04, name), tuning.initialMaxData, name)
            XCTAssertEqual(advertised(tuning, 0x05, name), tuning.initialMaxStreamDataBidiLocal, name)
            XCTAssertEqual(advertised(tuning, 0x06, name), tuning.initialMaxStreamDataBidiRemote, name)
            XCTAssertEqual(advertised(tuning, 0x07, name), tuning.initialMaxStreamDataUni, name)
            XCTAssertEqual(advertised(tuning, 0x08, name), tuning.initialMaxStreamsBidi, name)
            XCTAssertEqual(advertised(tuning, 0x09, name), tuning.initialMaxStreamsUni, name)
        }
    }

    func testMaxIdleTimeoutGoesOutInMillisecondsNotNgtcp2Nanoseconds() {
        // RFC 9000 §18.2 states the parameter in milliseconds; ngtcp2 keeps
        // every duration in nanoseconds. Every preset idles at 30 seconds.
        for (name, tuning) in presets {
            XCTAssertEqual(tuning.maxIdleTimeoutNanos, 30_000_000_000, name)
            XCTAssertEqual(advertised(tuning, 0x01, name), 30_000, name)
        }
    }

    func testDisableActiveMigrationIsAPresenceNotAValue() throws {
        // Zero-length per RFC 9000 §18.2, so it is either there or it is not.
        for (name, tuning) in presets {
            XCTAssertFalse(tuning.disableActiveMigration, name)
            XCTAssertFalse(tuning.advertisedParameters.contains(where: { $0.id == 0x0c }), name)
        }

        let pinned = try naive(disableActiveMigration: true)
        let flags = pinned.advertisedParameters.filter { $0.id == 0x0c }
        XCTAssertEqual(flags.count, 1)
        if let flag = flags.first {
            XCTAssertNil(flag.value)
        }
    }

    func testTheLocalSettingsHaveNoIdentifierBecauseTheyNeverGoOnTheWire() {
        // The auto-tuning ceilings and the two client-side timers are ngtcp2
        // settings. Advertising a ceiling would tell the peer something QUIC
        // has no way to express, and no registry entry exists for one.
        //
        // Asserted on identity rather than on value: two unrelated settings
        // can legitimately hold the same number — naive sets both
        // maxStreamWindow and initialMaxData to 64 MiB — and a
        // value-membership check reads that coincidence as a leak.
        let registered: Set<Int> = [
            QuicTransportParameterId.maxIdleTimeout,
            QuicTransportParameterId.initialMaxData,
            QuicTransportParameterId.initialMaxStreamDataBidiLocal,
            QuicTransportParameterId.initialMaxStreamDataBidiRemote,
            QuicTransportParameterId.initialMaxStreamDataUni,
            QuicTransportParameterId.initialMaxStreamsBidi,
            QuicTransportParameterId.initialMaxStreamsUni,
            QuicTransportParameterId.disableActiveMigration,
        ]
        for (name, tuning) in presets {
            for parameter in tuning.advertisedParameters {
                XCTAssertTrue(
                    registered.contains(parameter.id),
                    "\(name) advertises unregistered id 0x\(String(parameter.id, radix: 16))"
                )
            }
        }
    }

    func testEveryAdvertisedValueFitsTheVarintTheParameterIsWrittenAs() throws {
        for (name, tuning) in presets {
            for parameter in tuning.advertisedParameters {
                guard let value = parameter.value else { continue }
                XCTAssertTrue((0...QuicVarInt.max).contains(value), "\(name)/\(parameter.id)")
                // Round-trips through the encoding RFC 9000 §16 defines.
                let encoded = try QuicVarInt.encode(value)
                XCTAssertEqual(QuicVarInt.decode(encoded)?.value, value, "\(name)/\(parameter.id)")
            }
        }
    }

    func testTheStreamCapIsTheOneTheRfcDerivesFromTheStreamIdSpace() {
        // 2^60, because a stream ID is the count shifted left two places plus
        // two type bits and has to stay inside a 62-bit varint.
        XCTAssertEqual(QuicTuning.maxStreams, 1_152_921_504_606_846_976)
        XCTAssertEqual(QuicTuning.maxStreams * 4 - 1, QuicVarInt.max)
    }

    func testAStreamCountPastTheCapIsRefusedRatherThanTruncated() {
        XCTAssertThrowsError(try naive(initialMaxStreamsBidi: QuicTuning.maxStreams + 1))
        // The cap itself is still allowed.
        XCTAssertNoThrow(try naive(initialMaxStreamsBidi: QuicTuning.maxStreams))
    }

    // MARK: - ngtcp2 algorithm numbers

    func testTheCongestionControlNumbersAreNgtcp2sOwn() {
        // ngtcp2.h: NGTCP2_CC_ALGO_RENO 0x00, CUBIC 0x01, BBR 0x02.
        XCTAssertEqual(QuicCongestionControl.ngtcp2CcAlgoReno, 0x00)
        XCTAssertEqual(QuicCongestionControl.ngtcp2CcAlgoCubic, 0x01)
        XCTAssertEqual(QuicCongestionControl.ngtcp2CcAlgoBbr, 0x02)
        XCTAssertEqual(QuicCongestionControl.reno.ngtcp2Algorithm, 0x00)
        XCTAssertEqual(QuicCongestionControl.cubic.ngtcp2Algorithm, 0x01)
        XCTAssertEqual(QuicCongestionControl.bbr.ngtcp2Algorithm, 0x02)
    }

    func testBrutalStartsNgtcp2OnCubicBecauseItReplacesTheControllerLater() {
        let brutal = QuicCongestionControl.brutal(initialBytesPerSecond: 1)
        XCTAssertEqual(brutal.ngtcp2Algorithm, 0x01)
    }

    // MARK: - Presets

    func testNaiveAdvertisesTheValuesTheReferenceDoes() {
        let tuning = QuicTuning.naive
        XCTAssertEqual(tuning.congestionControl, QuicCongestionControl.cubic)
        XCTAssertEqual(tuning.maxStreamWindow, 64 * mib)
        XCTAssertEqual(tuning.maxWindow, 128 * mib)
        XCTAssertEqual(tuning.initialMaxData, 64 * mib)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiLocal, 16 * mib)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiRemote, 16 * mib)
        XCTAssertEqual(tuning.initialMaxStreamDataUni, 16 * mib)
        XCTAssertEqual(tuning.initialMaxStreamsBidi, 1024)
        XCTAssertEqual(tuning.initialMaxStreamsUni, 100)
        XCTAssertEqual(tuning.handshakeTimeoutNanos, 10_000_000_000)
        XCTAssertEqual(tuning.keepAliveTimeoutNanos, 15_000_000_000)
    }

    func testNowhereGrantsThePeerNoStreamsAtAll() {
        let tuning = QuicTuning.nowhere
        XCTAssertEqual(tuning.congestionControl, QuicCongestionControl.bbr)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiLocal, 4 * mib)
        // Nothing the peer could open, so nothing funded for it to open with.
        XCTAssertEqual(tuning.initialMaxStreamsBidi, 0)
        XCTAssertEqual(tuning.initialMaxStreamsUni, 0)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiRemote, 0)
        XCTAssertEqual(tuning.initialMaxStreamDataUni, 0)
    }

    func testHysteriaBbrAsksNgtcp2ForBbrAndLeavesTheWindowsRoomToGrow() {
        let tuning = QuicTuning.hysteria(.bbr, uploadMbps: 50)
        XCTAssertEqual(tuning.congestionControl, QuicCongestionControl.bbr)
        XCTAssertEqual(tuning.maxStreamWindow, 16 * mib)
        XCTAssertEqual(tuning.maxWindow, 32 * mib)
        XCTAssertEqual(tuning.initialMaxData, 8 * mib)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiLocal, 2 * mib)
        XCTAssertEqual(tuning.initialMaxStreamsBidi, 1024)
        XCTAssertEqual(tuning.initialMaxStreamsUni, 16)
    }

    func testHysteriaBrutalKeepsTheWindowsSmallAndPacesToTheDeclaredRate() {
        let tuning = QuicTuning.hysteria(.brutal, uploadMbps: 100)
        XCTAssertEqual(tuning.maxStreamWindow, 2 * mib)
        XCTAssertEqual(tuning.maxWindow, 4 * mib)
        XCTAssertEqual(tuning.initialMaxData, 4 * mib)
        XCTAssertEqual(tuning.initialMaxStreamDataBidiRemote, 2 * mib)
        XCTAssertEqual(tuning.initialMaxStreamsUni, 16)
    }

    func testMegabitsPerSecondBecomeBytesPerSecond() {
        // 100 Mb/s is 100_000_000 bits, which is 12_500_000 bytes.
        XCTAssertEqual(brutalRate(100), 12_500_000)
        XCTAssertEqual(brutalRate(1), 125_000)
        XCTAssertEqual(brutalRate(10_000), 1_250_000_000)
        // Absent or nonsensical bandwidth opens at zero rather than wrapping;
        // the server's Hysteria-CC-RX corrects it after authentication.
        XCTAssertEqual(brutalRate(0), 0)
        XCTAssertEqual(brutalRate(-1), 0)
        XCTAssertEqual(brutalRate(Int.min), 0)
    }

    // MARK: - Invariants that hold across every preset

    func testACeilingIsNeverBelowTheWindowItIsMeantToCap() {
        for (name, tuning) in presets {
            XCTAssertGreaterThanOrEqual(tuning.maxWindow, tuning.initialMaxData, name)
            XCTAssertGreaterThanOrEqual(tuning.maxStreamWindow, tuning.initialMaxStreamDataBidiLocal, name)
            XCTAssertGreaterThanOrEqual(tuning.maxStreamWindow, tuning.initialMaxStreamDataBidiRemote, name)
            XCTAssertGreaterThanOrEqual(tuning.maxStreamWindow, tuning.initialMaxStreamDataUni, name)
        }
    }

    func testTheConnectionWindowIsNeverSmallerThanASingleStreams() {
        // Otherwise a stream could never reach the limit it was granted.
        for (name, tuning) in presets {
            XCTAssertGreaterThanOrEqual(tuning.initialMaxData, tuning.initialMaxStreamDataBidiLocal, name)
            XCTAssertGreaterThanOrEqual(tuning.initialMaxData, tuning.initialMaxStreamDataBidiRemote, name)
            XCTAssertGreaterThanOrEqual(tuning.initialMaxData, tuning.initialMaxStreamDataUni, name)
            XCTAssertGreaterThanOrEqual(tuning.maxWindow, tuning.maxStreamWindow, name)
        }
    }

    func testTheKeepaliveFiresBeforeTheIdleTimeoutCanExpire() {
        for (name, tuning) in presets {
            XCTAssertLessThan(tuning.keepAliveTimeoutNanos, tuning.maxIdleTimeoutNanos, name)
            XCTAssertLessThan(tuning.handshakeTimeoutNanos, tuning.maxIdleTimeoutNanos, name)
        }
    }

    func testMigrationIsLeftAvailableOnEveryPreset() {
        // Advertising disable_active_migration would rule out surviving a
        // Wi-Fi to cellular handover.
        for (name, tuning) in presets {
            XCTAssertFalse(tuning.disableActiveMigration, name)
        }
    }

    // MARK: - The native settings array

    func testTheNativeArrayCarriesTheEngineSettingsAfterTheSevenLimits() {
        // The bridge reads these by index: the first seven are transport
        // parameters, then cc algorithm, the two window ceilings, and the two
        // timeouts. A short array would silently leave them at ngtcp2 defaults.
        let tuning = QuicTuning.naive
        let values = tuning.toNativeArray()
        XCTAssertEqual(values.count, 12)
        guard values.count == 12 else { return }
        XCTAssertEqual(values[0], tuning.initialMaxData)
        XCTAssertEqual(values[6], tuning.maxIdleTimeoutNanos)
        XCTAssertEqual(values[8], tuning.maxWindow)
        XCTAssertEqual(values[9], tuning.maxStreamWindow)
        XCTAssertEqual(values[10], tuning.handshakeTimeoutNanos)
        XCTAssertEqual(values[11], tuning.keepAliveTimeoutNanos)
    }

    func testCubicAndBbrPresetsReportTheirOwnAlgorithmToNgtcp2() {
        // CUBIC (0x01) for Naive, BBR (0x02) for the bulk tunnel.
        XCTAssertEqual(QuicTuning.naive.toNativeArray()[7], 0x01)
        XCTAssertEqual(QuicTuning.nowhere.toNativeArray()[7], 0x02)
    }

    func testBrutalIsStartedOnBbrBecauseItIsNotAnNgtcp2Algorithm() {
        // The Brutal controller still reports CUBIC (it replaces the
        // controller later); what ngtcp2 is created with is BBR, the nearest
        // rate-probing match.
        let brutal = QuicTuning.hysteria(.brutal, uploadMbps: 100)
        XCTAssertEqual(brutal.toNativeArray()[7], 0x02)
        XCTAssertEqual(brutal.nativeCongestionAlgorithm, QuicCongestionControl.ngtcp2CcAlgoBbr)
        let bbr = QuicTuning.hysteria(.bbr, uploadMbps: 0)
        XCTAssertEqual(bbr.toNativeArray()[7], 0x02)
    }
}
