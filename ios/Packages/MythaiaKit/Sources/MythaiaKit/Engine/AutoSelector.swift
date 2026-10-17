import Foundation

/// When Auto measures its group and when it moves the tunnel.
///
/// A move is not free: connections being relayed stay on the old server
/// while new ones go to the new, and a round is not free either: each server
/// in the group gets a fresh TLS connection. Measured on a phone in the
/// field, rounds of 35 servers every two minutes, day and night, and moves
/// on a 50 ms gain (well inside the noise of one handshake, which ran from
/// 0.4 to 1.7 s on the same server) kept the radio busy and the tunnel
/// hopping between servers.
public enum AutoPolicy {
    /// Between rounds while connected, unless the settings say otherwise.
    public static let recheckSeconds: Double = 10 * 60

    /// The least a move must gain, in milliseconds...
    public static let minGainMs = 150

    /// ...and as a share of the live server's time.
    public static let minGainShare = 0.3

    /// Between checks of `roundDue` in the loops; cheap, nothing goes out
    /// unless a round is due.
    public static let dueCheckSeconds: Double = 60

    /// After the device wakes, before measuring: the radio needs a moment.
    public static let wakeSettleSeconds: Double = 3

    /// The most servers one round measures. A bulk list of 10,000 servers
    /// measured whole, six at a time with a ten-second timeout, made a round
    /// of several hours; a recovery after a block waited for all of it.
    public static let maxRound = 48

    /// Tests running at the same time.
    public static let maxConcurrentTests = 6

    /// Per test, in seconds.
    public static let testTimeout: Double = 10

    /// Moves Auto makes on its own after failures, at most this many...
    public static let reconnectMax = 4

    /// ...within this window, so a dead network does not turn into a loop.
    public static let reconnectWindowSeconds: Double = 10 * 60

    /// Proxied dials failing in a row before Auto looks for another server.
    public static let failuresBeforeRecovery = 3

    /// Whether to leave the live server for one measured at `candidateMs`.
    /// `liveMs` is the live server's own time this round, or nil when it did
    /// not answer (or is not in the group), which is always reason to move.
    public static func worthSwitching(liveMs: Int?, candidateMs: Int) -> Bool {
        guard let liveMs else { return true }
        let needed = max(Double(minGainMs), Double(liveMs) * minGainShare)
        return Double(liveMs - candidateMs) >= needed
    }

    /// Whether a round is owed at `now` (seconds on a monotonic clock).
    public static func roundDue(now: Double, lastRoundAt: Double?, interval: Double = recheckSeconds) -> Bool {
        guard let lastRoundAt else { return true }
        return now - lastRoundAt >= interval
    }

    /// The most servers of one group the tunnel keeps for Auto. Its memory
    /// limit is about 50 MB, and a bulk list of thousands of servers decoded
    /// whole would take a good part of it; the app hands over a sample
    /// (`AutoSelector.groupForTunnel`) and measures the whole list itself.
    public static let tunnelGroupLimit = 256

    /// The servers one round measures out of `ids`. A group of up to
    /// `limit` is measured whole. A bigger one gets the live server, the
    /// half that answered fastest lately (`known`: id to the last successful
    /// time), and a random share of the rest: each round stays short, and
    /// over successive rounds every server gets its turn.
    public static func roundSample(
        _ ids: [UUID],
        liveId: UUID?,
        known: [UUID: Int],
        limit: Int = maxRound,
        shuffle: ([UUID]) -> [UUID] = { $0.shuffled() }
    ) -> [UUID] {
        let cap = max(1, limit)
        if ids.count <= cap { return ids }
        var picked: [UUID] = []
        var seen = Set<UUID>()
        if let liveId, ids.contains(liveId) {
            picked.append(liveId)
            seen.insert(liveId)
        }
        var fastest: [(index: Int, id: UUID, ms: Int)] = []
        for (index, id) in ids.enumerated() {
            if let ms = known[id] {
                fastest.append((index: index, id: id, ms: ms))
            }
        }
        fastest.sort { left, right in
            if left.ms != right.ms { return left.ms < right.ms }
            return left.index < right.index
        }
        for entry in fastest.prefix(cap / 2) where !seen.contains(entry.id) {
            picked.append(entry.id)
            seen.insert(entry.id)
        }
        let rest = ids.filter { !seen.contains($0) }
        for id in shuffle(rest) {
            if picked.count >= cap { break }
            if seen.contains(id) { continue }
            picked.append(id)
            seen.insert(id)
        }
        return picked
    }

    /// The fastest server of a round and whether to move to it.
    public struct Pick: Equatable {
        public var id: UUID
        public var ms: Int
        public var shouldSwitch: Bool
    }

    /// The fastest of `results` (id to milliseconds); nil when nothing
    /// answered. Moving is worth it when the fastest is not the live server
    /// and beats it by the margins above.
    public static func pick(results: [UUID: Int], liveId: UUID?) -> Pick? {
        var best: (id: UUID, ms: Int)?
        for (id, ms) in results {
            if let current = best {
                let faster = ms < current.ms
                let tieBroken = ms == current.ms && id.uuidString < current.id.uuidString
                if faster || tieBroken { best = (id: id, ms: ms) }
            } else {
                best = (id: id, ms: ms)
            }
        }
        guard let best else { return nil }
        var move = false
        if best.id != liveId {
            let liveMs: Int? = liveId.flatMap { results[$0] }
            move = worthSwitching(liveMs: liveMs, candidateMs: best.ms)
        }
        return Pick(id: best.id, ms: best.ms, shouldSwitch: move)
    }

    /// Records a reconnect attempt at `now` if fewer than `reconnectMax`
    /// happened within the window; returns whether it is allowed and the
    /// attempts to keep.
    public static func admitReconnect(attempts: [Double], now: Double) -> (allowed: Bool, attempts: [Double]) {
        var recent = attempts.filter { now - $0 <= reconnectWindowSeconds }
        guard recent.count < reconnectMax else { return (false, recent) }
        recent.append(now)
        return (true, recent)
    }
}

/// What one Auto round found.
public struct AutoRoundResult {
    /// Successful times, by server id.
    public var results: [UUID: Int]
    /// The fastest server, nil when nothing answered.
    public var best: ProxyConfiguration?
    public var bestMs: Int?
    /// The live server's time, nil when it failed or was not measured.
    public var liveMs: Int?
    /// Whether the tunnel should move to `best`.
    public var shouldSwitch: Bool
}

/// Auto for whoever drives it, the app while it is on screen or the tunnel
/// while it is not: measures a group, remembers the times, and says when to
/// move. It holds no timer; the caller checks `roundDue()` on its own
/// schedule (every `AutoPolicy.dueCheckSeconds`).
public final class AutoSelector: @unchecked Sendable {
    public typealias Measure = (ProxyConfiguration) async -> Int?
    public typealias Clock = () -> Double

    public let recheckInterval: Double
    private let maxConcurrent: Int
    private let measureOne: Measure
    private let clock: Clock

    private let lock = NSLock()
    private var lastKnown: [UUID: Int] = [:]
    private var lastRoundAt: Double?
    private var reconnectTimes: [Double] = []
    private var roundRunning = false

    /// - Parameters:
    ///   - measure: one server's time in milliseconds, nil on failure;
    ///     defaults to an HTTP test through it.
    ///   - clock: seconds on a monotonic clock; defaults to one that keeps
    ///     counting through sleep, so a round skipped overnight is owed in
    ///     the morning.
    public init(
        recheckInterval: Double = AutoPolicy.recheckSeconds,
        maxConcurrent: Int = AutoPolicy.maxConcurrentTests,
        measure: Measure? = nil,
        clock: Clock? = nil
    ) {
        self.recheckInterval = max(60, recheckInterval)
        self.maxConcurrent = max(1, maxConcurrent)
        if let measure {
            self.measureOne = measure
        } else {
            self.measureOne = AutoSelector.httpTime
        }
        if let clock {
            self.clock = clock
        } else {
            self.clock = EngineClock.seconds
        }
    }

    private static func httpTime(_ configuration: ProxyConfiguration) async -> Int? {
        await LatencyTester.measure(configuration, kind: .http, timeout: AutoPolicy.testTimeout)
    }

    /// The servers Auto may pick: everything with a per-flow dial.
    public static func dialable(_ configurations: [ProxyConfiguration]) -> [ProxyConfiguration] {
        configurations.filter { $0.outboundProtocol != .wireguard }
    }

    /// The part of a group the tunnel gets for Auto: all of it up to
    /// `AutoPolicy.tunnelGroupLimit` servers, else the live server, the
    /// fastest known ones and a random share of the rest.
    public static func groupForTunnel(
        _ group: [ProxyConfiguration],
        liveId: UUID?,
        known: [UUID: Int] = [:]
    ) -> [ProxyConfiguration] {
        let usable = dialable(group)
        if usable.count <= AutoPolicy.tunnelGroupLimit { return usable }
        let ids = AutoPolicy.roundSample(
            usable.map { $0.id },
            liveId: liveId,
            known: known,
            limit: AutoPolicy.tunnelGroupLimit
        )
        let byId = AutoSelector.index(usable)
        var kept: [ProxyConfiguration] = []
        kept.reserveCapacity(ids.count)
        for id in ids {
            if let configuration = byId[id] { kept.append(configuration) }
        }
        return kept
    }

    /// The last successful time per server, so a sampled round of a big
    /// group starts from the fast ones.
    public var knownTimes: [UUID: Int] {
        locked { lastKnown }
    }

    public func roundDue() -> Bool {
        let now = clock()
        return locked {
            AutoPolicy.roundDue(now: now, lastRoundAt: lastRoundAt, interval: recheckInterval)
        }
    }

    /// Starts the interval over, for a round that just ran elsewhere (the
    /// app measured the group before connecting).
    public func markRound() {
        let now = clock()
        locked { lastRoundAt = now }
    }

    /// Claims the round; false when one is already running, so a periodic
    /// round and a failure round never measure the same group at once.
    public func beginRound() -> Bool {
        locked {
            if roundRunning { return false }
            roundRunning = true
            return true
        }
    }

    public func endRound() {
        locked { roundRunning = false }
    }

    /// Records an unattended move after a failure, if the window allows one.
    public func mayReconnect() -> Bool {
        let now = clock()
        return locked {
            let decision = AutoPolicy.admitReconnect(attempts: reconnectTimes, now: now)
            reconnectTimes = decision.attempts
            return decision.allowed
        }
    }

    /// Measures `configurations`, `maxConcurrent` at a time, and remembers
    /// the times; a server that fails is forgotten.
    public func measure(_ configurations: [ProxyConfiguration]) async -> [UUID: Int] {
        let measureOne = self.measureOne
        let limit = maxConcurrent
        var results: [UUID: Int] = [:]
        var failed: [UUID] = []
        await withTaskGroup(of: (UUID, Int?).self) { group in
            var nextIndex = 0
            while nextIndex < configurations.count && nextIndex < limit {
                let configuration = configurations[nextIndex]
                group.addTask {
                    let ms = await measureOne(configuration)
                    return (configuration.id, ms)
                }
                nextIndex += 1
            }
            while let outcome = await group.next() {
                if let ms = outcome.1 {
                    results[outcome.0] = ms
                } else {
                    failed.append(outcome.0)
                }
                if nextIndex < configurations.count {
                    let configuration = configurations[nextIndex]
                    group.addTask {
                        let ms = await measureOne(configuration)
                        return (configuration.id, ms)
                    }
                    nextIndex += 1
                }
            }
        }
        remember(results: results, failed: failed)
        return results
    }

    /// One round over `candidates` (sampled when the group is big) with
    /// `liveId` on the wire. Marks the round.
    public func runRound(candidates: [ProxyConfiguration], liveId: UUID?) async -> AutoRoundResult {
        markRound()
        let usable = AutoSelector.dialable(candidates)
        let sample = sampled(usable, liveId: liveId)
        let results = await measure(sample)
        return decide(results: results, among: usable, liveId: liveId)
    }

    /// The live server (`failed`) stopped answering: measure the rest of the
    /// group and name the best. Nil when the reconnect window is used up or
    /// nothing answered.
    public func recoverAfterFailure(candidates: [ProxyConfiguration], failed: UUID?) async -> AutoRoundResult? {
        guard mayReconnect() else {
            Log.warning("Auto: not moving again, \(AutoPolicy.reconnectMax) moves in the last \(Int(AutoPolicy.reconnectWindowSeconds / 60)) min")
            return nil
        }
        markRound()
        let usable = AutoSelector.dialable(candidates).filter { $0.id != failed }
        let sample = sampled(usable, liveId: nil)
        let results = await measure(sample)
        let outcome = decide(results: results, among: usable, liveId: nil)
        return outcome.best == nil ? nil : outcome
    }

    private func sampled(_ usable: [ProxyConfiguration], liveId: UUID?) -> [ProxyConfiguration] {
        let ids = AutoPolicy.roundSample(usable.map { $0.id }, liveId: liveId, known: knownTimes)
        let byId = AutoSelector.index(usable)
        var sample: [ProxyConfiguration] = []
        sample.reserveCapacity(ids.count)
        for id in ids {
            if let configuration = byId[id] { sample.append(configuration) }
        }
        return sample
    }

    private func decide(results: [UUID: Int], among usable: [ProxyConfiguration], liveId: UUID?) -> AutoRoundResult {
        var outcome = AutoRoundResult(results: results, best: nil, bestMs: nil, liveMs: nil, shouldSwitch: false)
        if let liveId { outcome.liveMs = results[liveId] }
        guard let pick = AutoPolicy.pick(results: results, liveId: liveId) else { return outcome }
        let byId = AutoSelector.index(usable)
        guard let best = byId[pick.id] else { return outcome }
        outcome.best = best
        outcome.bestMs = pick.ms
        outcome.shouldSwitch = pick.shouldSwitch
        return outcome
    }

    private func remember(results: [UUID: Int], failed: [UUID]) {
        locked {
            for (id, ms) in results {
                lastKnown[id] = ms
            }
            for id in failed {
                lastKnown[id] = nil
            }
        }
    }

    private static func index(_ configurations: [ProxyConfiguration]) -> [UUID: ProxyConfiguration] {
        var byId: [UUID: ProxyConfiguration] = [:]
        for configuration in configurations where byId[configuration.id] == nil {
            byId[configuration.id] = configuration
        }
        return byId
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
