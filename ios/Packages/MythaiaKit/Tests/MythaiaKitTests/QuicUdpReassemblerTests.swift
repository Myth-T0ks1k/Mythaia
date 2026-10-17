import Foundation
import XCTest
@testable import MythaiaKit

/// The fragment reassembler both Hysteria and TUIC share.
///
/// The invariants are not cosmetic. The key is `session << 16 | packetId` with
/// a 16-bit packet id, so a fragment of packet N and one of packet N+65536
/// collide on the same key; an orphaned fragment of the first must not be
/// glued onto the second. The guards below are the ones that catch it: a
/// partial whose fragment count no longer matches is replaced rather than
/// indexed into, a fragment out of range is dropped without emitting
/// anything, and a partial left waiting too long is forgotten.
final class QuicUdpReassemblerTests: XCTestCase {

    /// A clock the test moves by hand, in milliseconds.
    private final class ManualClock {
        var millis: Int64 = 0
    }

    private func reassembler(_ clock: ManualClock = ManualClock()) -> UdpReassembler {
        return UdpReassembler(clock: { clock.millis })
    }

    func testASingleFragmentMessagePassesStraightThrough() {
        let r = reassembler()
        XCTAssertEqual(r.add(packetKey: 7, fragmentId: 0, fragmentCount: 1, payload: [1, 2, 3]), [1, 2, 3])
    }

    func testFragmentsReassembleInIndexOrderRegardlessOfArrivalOrder() {
        let r = reassembler()
        XCTAssertNil(r.add(packetKey: 42, fragmentId: 1, fragmentCount: 2, payload: [3, 4]))
        XCTAssertEqual(r.add(packetKey: 42, fragmentId: 0, fragmentCount: 2, payload: [1, 2]), [1, 2, 3, 4])
    }

    func testAFragmentOutOfRangeIsDroppedNotStored() {
        let r = reassembler()
        XCTAssertNil(r.add(packetKey: 1, fragmentId: 3, fragmentCount: 2, payload: [9]))
    }

    func testADifferingFragmentCountOnTheSameKeyReplacesTheStalePartial() {
        let r = reassembler()
        // One fragment of a 3-piece packet arrives, then the key is reused by
        // a 2-piece packet (the packet id wrapped). The stale piece must not be
        // glued onto the new one.
        XCTAssertNil(r.add(packetKey: 5, fragmentId: 0, fragmentCount: 3, payload: [0xAA]))
        XCTAssertNil(r.add(packetKey: 5, fragmentId: 0, fragmentCount: 2, payload: [1]))
        XCTAssertEqual(r.add(packetKey: 5, fragmentId: 1, fragmentCount: 2, payload: [2]), [1, 2])
    }

    func testAPartialLeftWaitingPastTheStaleLimitIsForgotten() {
        // A key collision with the same fragment count is the case the count
        // check cannot see; only expiry keeps an orphaned piece from being
        // glued onto the packet that reuses its key.
        let clock = ManualClock()
        let r = reassembler(clock)
        XCTAssertNil(r.add(packetKey: 9, fragmentId: 0, fragmentCount: 2, payload: [0xAA]))

        clock.millis = UdpReassembler.staleMilliseconds + 1
        XCTAssertNil(r.add(packetKey: 9, fragmentId: 1, fragmentCount: 2, payload: [2]))
        XCTAssertEqual(r.add(packetKey: 9, fragmentId: 0, fragmentCount: 2, payload: [1]), [1, 2])
    }

    func testAPartialWithinTheStaleLimitIsStillCompleted() {
        let clock = ManualClock()
        let r = reassembler(clock)
        XCTAssertNil(r.add(packetKey: 9, fragmentId: 0, fragmentCount: 2, payload: [1]))

        clock.millis = UdpReassembler.staleMilliseconds
        XCTAssertEqual(r.add(packetKey: 9, fragmentId: 1, fragmentCount: 2, payload: [2]), [1, 2])
    }
}
