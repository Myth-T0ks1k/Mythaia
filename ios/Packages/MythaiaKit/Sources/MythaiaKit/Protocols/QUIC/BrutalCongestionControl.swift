import Foundation

/// Hysteria's "Brutal" congestion control.
///
/// Brutal is not congestion control in the usual sense: it never backs off.
/// The user states how fast the link is and the sender holds that rate
/// whatever the network thinks of it. Loss is read not as a signal to slow
/// down but as a tax — if a fifth of the packets are being dropped, the answer
/// is to push a quarter more through so that what survives still adds up to
/// the target.
///
/// That is the whole algorithm: measure the loss rate over the last few
/// seconds, divide the target rate by the fraction getting through, and size
/// the window for that. A loss rate taken from a handful of packets is noise,
/// so below a sample floor it counts as zero; and an honest loss rate near 1.0
/// would divide the rate by nearly nothing, so it is capped.
///
/// This class holds no connection state and touches no native code. A caller
/// reports acknowledgements and losses along with the time they happened, then
/// asks for a window given the current smoothed RTT. Time arrives as a
/// parameter rather than from a clock read inside, which is what makes the
/// second-by-second accounting testable. ngtcp2 is started on BBR for a
/// Brutal connection (see `QuicTuning`), so nothing feeds this live yet.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class BrutalCongestionControl: @unchecked Sendable {
    /// Everything the controller has to say about the next stretch of sending.
    struct Window: Equatable {
        /// The congestion window, in bytes.
        let cwndBytes: Int64
        /// The pacing rate in ngtcp2's fixed-point form: nanoseconds per byte
        /// shifted left by ten. Zero asks the library for its own default.
        let pacingIntervalM: Int64
        /// How much may leave in one burst, in bytes.
        let sendQuantumBytes: Int64
    }

    /// Seconds of per-second ack/loss slots the loss rate is measured over.
    static let slotCount = 5
    /// Below this many ack plus loss samples the loss rate is treated as zero.
    static let minSampleCount: Int64 = 50
    /// The loss-rate cap, the other face of Hysteria's minimum ack rate of 0.8.
    static let maxLossRate = 0.2
    /// Two round trips of data in flight.
    static let congestionWindowMultiplier = 2.0
    /// Ten MSS, the RFC 6928 initial window, used here as a floor.
    static let minCwndPackets: Int64 = 10
    /// The flat window used until the first RTT sample arrives.
    static let initialCwndBytes: Int64 = 10240
    /// One burst tops out at 64 KiB however fast the link is.
    static let maxSendQuantumBytes: Int64 = 64 * 1024

    private static let pacingIntervalScale = 1024.0
    private static let nanosPerSecond: Int64 = 1_000_000_000
    private static let millisPerSecond = 1000.0

    /// One second of ack/loss counts. A slot whose mark is not the second
    /// being asked about holds old counts and is ignored, so nothing has to be
    /// swept on a timer. `Int64.min` marks a slot never used: no nanosecond
    /// reading divides down to that second.
    private struct Slot {
        var secondMark = Int64.min
        var ackCount: Int64 = 0
        var lossCount: Int64 = 0

        mutating func restart(_ second: Int64) {
            secondMark = second
            ackCount = 0
            lossCount = 0
        }
    }

    private let lock = NSLock()
    private var slots = [Slot](repeating: Slot(), count: BrutalCongestionControl.slotCount)
    private var target: Int64

    init(initialBytesPerSecond: Int64) {
        target = initialBytesPerSecond
    }

    /// The rate to pace towards, in bytes per second. A session normally
    /// starts with a placeholder and learns the real figure from the server
    /// after authentication, so this changes underneath a running connection.
    var targetBytesPerSecond: Int64 {
        get {
            lock.lock()
            defer { lock.unlock() }
            return target
        }
        set {
            lock.lock()
            target = newValue
            lock.unlock()
        }
    }

    /// Records one acknowledged packet at `nowNanos`.
    func onPacketAcked(_ nowNanos: Int64) {
        lock.lock()
        let index = slotIndex(for: nowNanos)
        slots[index].ackCount += 1
        lock.unlock()
    }

    /// Records one declared-lost packet at `nowNanos`.
    func onPacketLost(_ nowNanos: Int64) {
        lock.lock()
        let index = slotIndex(for: nowNanos)
        slots[index].lossCount += 1
        lock.unlock()
    }

    /// Forgets every sample, as on a persistent-congestion event, where the
    /// measurements describe a path the connection is no longer on.
    func reset() {
        lock.lock()
        for index in 0..<slots.count {
            slots[index].restart(Int64.min)
        }
        lock.unlock()
    }

    /// The measured loss rate over the last `slotCount` seconds, or zero when
    /// too few packets have been seen for the figure to mean anything. The
    /// in-progress second is counted: excluding it would report no loss
    /// through the first second of a connection, exactly when a bursty start
    /// is losing packets. Uncapped: the cap belongs to the window.
    func observedLossRate(_ nowNanos: Int64) -> Double {
        lock.lock()
        defer { lock.unlock() }
        return lossRateLocked(nowNanos)
    }

    private func lossRateLocked(_ nowNanos: Int64) -> Double {
        let now = BrutalCongestionControl.secondOf(nowNanos)
        var acks: Int64 = 0
        var losses: Int64 = 0
        for age in 0..<BrutalCongestionControl.slotCount {
            let second = now - Int64(age)
            let slot = slots[BrutalCongestionControl.indexOf(second)]
            if slot.secondMark != second { continue }
            acks += slot.ackCount
            losses += slot.lossCount
        }
        let total = acks + losses
        if total < BrutalCongestionControl.minSampleCount { return 0 }
        return Double(losses) / Double(total)
    }

    /// Sizes the window for `smoothedRttNanos`, or nil when no target rate has
    /// been set: a caller wiring this into a QUIC stack should then leave the
    /// stack's own numbers alone rather than write a zero window and stall.
    /// `maxDatagramSize` is the sender's MSS; only the floors depend on it.
    func window(nowNanos: Int64, smoothedRttNanos: Int64, maxDatagramSize: Int) -> Window? {
        lock.lock()
        let rate = target
        let measured = lossRateLocked(nowNanos)
        lock.unlock()
        if rate <= 0 { return nil }

        let lossRate = min(max(measured, 0), BrutalCongestionControl.maxLossRate)
        // Pace at target / ackRate, so that the share of the paced rate that
        // survives comes back out at the target.
        let ackRate = 1.0 - lossRate
        let pacedBytesPerSecond = Double(rate) / ackRate

        // Ten packets is RFC 6928's initial window, and the floor for
        // everything below: a window under it cannot keep a single round trip
        // busy no matter what the arithmetic says.
        let mss = max(Int64(maxDatagramSize), 1)
        let minCwnd = BrutalCongestionControl.minCwndPackets * mss

        let cwnd: Int64
        if smoothedRttNanos <= 0 {
            // No RTT has been measured yet. Feeding the formula a synthetic
            // floor inflates the window to megabytes, which starts the
            // connection with a burst the path then drops.
            cwnd = max(BrutalCongestionControl.initialCwndBytes, minCwnd)
        } else {
            // Rate times RTT times two, on the raw RTT with no floor under it.
            let bandwidthDelay = pacedBytesPerSecond * BrutalCongestionControl.congestionWindowMultiplier *
                Double(smoothedRttNanos) / Double(BrutalCongestionControl.nanosPerSecond)
            // Clamped before the conversion, which would trap past Int64.
            cwnd = max(Int64(min(bandwidthDelay, Double(Int64.max / 2))), minCwnd)
        }

        let pacingIntervalM: Int64
        if pacedBytesPerSecond >= 1.0 {
            let nanosPerByte = Double(BrutalCongestionControl.nanosPerSecond) / pacedBytesPerSecond
            pacingIntervalM = Int64(nanosPerByte * BrutalCongestionControl.pacingIntervalScale)
        } else {
            pacingIntervalM = 0
        }

        // A millisecond of bytes, under the same ten-packet floor and capped so
        // one burst cannot swallow the whole window.
        let bytesPerMillisecond = pacedBytesPerSecond / BrutalCongestionControl.millisPerSecond
        let sendQuantum = max(
            Int64(min(bytesPerMillisecond, Double(BrutalCongestionControl.maxSendQuantumBytes))),
            minCwnd
        )
        return Window(cwndBytes: cwnd, pacingIntervalM: pacingIntervalM, sendQuantumBytes: sendQuantum)
    }

    /// The slot for `nowNanos`, recycled if it still holds an older second.
    private func slotIndex(for nowNanos: Int64) -> Int {
        let second = BrutalCongestionControl.secondOf(nowNanos)
        let index = BrutalCongestionControl.indexOf(second)
        if slots[index].secondMark != second {
            slots[index].restart(second)
        }
        return index
    }

    /// Floored rather than truncated, so a clock reading before its own
    /// origin still lands on the right second.
    private static func secondOf(_ nanos: Int64) -> Int64 {
        let quotient = nanos / nanosPerSecond
        return (nanos % nanosPerSecond < 0) ? quotient - 1 : quotient
    }

    /// Floored modulo, so a negative second still lands on a slot instead of
    /// a negative index.
    private static func indexOf(_ second: Int64) -> Int {
        let count = Int64(slotCount)
        let remainder = second % count
        return Int(remainder < 0 ? remainder + count : remainder)
    }
}
