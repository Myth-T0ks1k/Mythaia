import Foundation

/**
 * Servers to fetch a subscription through when its panel cannot be reached
 * from this network. Shared by every caller so all of them pick alike.
 */
public enum WorkingServers {

    /// How many servers a fetch is tried through.
    public static let attempts = 4

    /// How many are checked, and for how long, to find them.
    private static let probes = 24
    private static let probeSeconds: Double = 10
    /// Checks run at once, as the latency tester's own cap.
    private static let maxConcurrent = 6

    /**
     * The servers worth checking, in order: the subscription's own first (its
     * provider's servers reach its panel more often than anyone's), and in
     * each part the ones that answered last time, then the untested, then
     * those that failed (every one is checked afresh anyway). Layer-3 servers
     * are left out: WireGuard dials no streams.
     *
     * `known` holds the last check of each server: milliseconds when it
     * answered, nil when it failed; a server missing from it is untested.
     */
    public static func candidates(
        _ configs: [ProxyConfiguration],
        subscriptionId: UUID,
        known: [UUID: Int?]
    ) -> [ProxyConfiguration] {
        let usable = configs.filter { !$0.outboundProtocol.isLayer3 }
        func rank(_ config: ProxyConfiguration) -> Int64 {
            guard let entry = known[config.id] else { return Int64(Int32.max) }
            guard let ms = entry else { return Int64.max }
            return Int64(ms)
        }
        // Sorted with the position as the tie-break, so equal ranks keep their order.
        func ordered(_ part: [ProxyConfiguration]) -> [ProxyConfiguration] {
            let ranked = part.enumerated().map { (offset: $0.offset, rank: rank($0.element), config: $0.element) }
            let sorted = ranked.sorted { a, b in
                a.rank != b.rank ? a.rank < b.rank : a.offset < b.offset
            }
            return sorted.map { $0.config }
        }
        let own = usable.filter { $0.subscriptionId == subscriptionId }
        let others = usable.filter { $0.subscriptionId != subscriptionId }
        return Array((ordered(own) + ordered(others)).prefix(probes))
    }

    private enum Probe: Sendable {
        case result(UUID, Int?)
        case deadline
    }

    /**
     * Up to `attempts` servers that answer a real request right now: `live`
     * first when the tunnel works, then the first of `candidates` to pass a
     * fresh check. `prepare` applies the app's settings to a server before
     * it is checked; `onResult` hears every check (milliseconds, nil for a
     * failure), for the ping column.
     */
    public static func find(
        live: ProxyConfiguration?,
        candidates: [ProxyConfiguration],
        prepare: @escaping (ProxyConfiguration) -> ProxyConfiguration = { $0 },
        onResult: (UUID, Int?) -> Void = { _, _ in }
    ) async -> [ProxyConfiguration] {
        var picked: [ProxyConfiguration] = []
        var pickedIds = Set<UUID>()
        if let live = live, !live.outboundProtocol.isLayer3 {
            picked.append(live)
            pickedIds.insert(live.id)
        }
        let toCheck = candidates.filter { !pickedIds.contains($0.id) }
        var byId: [UUID: ProxyConfiguration] = [:]
        for config in toCheck { byId[config.id] = config }
        let wanted = attempts - picked.count
        if wanted <= 0 || toCheck.isEmpty { return picked }

        let prepared = toCheck.map { prepare($0) }
        let seconds = probeSeconds
        var found = 0
        await withTaskGroup(of: Probe.self, returning: Void.self) { group in
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return .deadline
            }
            var next = 0
            var running = 0
            while next < prepared.count && running < maxConcurrent {
                let config = prepared[next]
                group.addTask {
                    .result(config.id, await LatencyTester.measure(config, kind: .http, timeout: seconds))
                }
                next += 1
                running += 1
            }
            while let probe = await group.next() {
                guard case .result(let id, let ms) = probe else {
                    group.cancelAll()
                    return
                }
                running -= 1
                onResult(id, ms)
                if ms != nil, let config = byId[id], !pickedIds.contains(id) {
                    picked.append(config)
                    pickedIds.insert(id)
                    found += 1
                    if found >= wanted {
                        group.cancelAll()
                        return
                    }
                }
                if next < prepared.count {
                    let config = prepared[next]
                    group.addTask {
                        .result(config.id, await LatencyTester.measure(config, kind: .http, timeout: seconds))
                    }
                    next += 1
                    running += 1
                } else if running == 0 {
                    group.cancelAll()
                    return
                }
            }
        }
        return picked
    }
}
