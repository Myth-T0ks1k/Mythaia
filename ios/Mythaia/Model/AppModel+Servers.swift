import Foundation
import MythaiaKit

extension AppModel {

    // MARK: Servers

    /// Adds servers to the Default group in one write.
    func addConfigurations(_ configs: [ProxyConfiguration]) {
        guard !configs.isEmpty else { return }
        let added = configs.map { CoreBridge.withIdentity($0, id: $0.id, subscriptionId: nil) }
        setConfigurations(configurations + added)
        recomputeSelection()
    }

    /// Deletes servers in one write. A subscription left with none goes with
    /// them, and a tunnel on a deleted server moves to what is selected now.
    func deleteConfigurations(_ configs: [ProxyConfiguration]) {
        let ids = Set(configs.map { $0.id })
        guard !ids.isEmpty else { return }
        let liveDeleted = liveConfigId.map { ids.contains($0) } ?? false
        let chainHit = selectedChain?.proxyIds.contains(where: { ids.contains($0) }) ?? false
        let wasLive = vpn.status == .connected && (liveDeleted || chainHit)

        setConfigurations(configurations.filter { !ids.contains($0.id) })
        latency = latency.filter { !ids.contains($0.key) }

        let remaining = Set(configurations.compactMap { $0.subscriptionId })
        let emptied = Set(configs.compactMap { $0.subscriptionId }).subtracting(remaining)
        if !emptied.isEmpty {
            setSubscriptions(subscriptions.filter { !emptied.contains($0.id) })
            if emptied.contains(where: { ProxyGroup.id(for: $0) == browsingGroupId }) {
                browsingGroupId = ProxyGroup.defaultId
            }
        }
        recomputeSelection()
        if wasLive {
            if let next = selectedConfiguration { switchTunnel(to: next) } else { disconnect() }
        }
    }

    /// The servers of a group that failed their last check.
    func failedIn(_ groupId: String) -> [ProxyConfiguration] {
        groupConfigs(groupId).filter { latency[$0.id] == .failed }
    }

    /// Removes the servers of `groupId` that failed their last check; returns how many went.
    func removeFailed(_ groupId: String) -> Int {
        let failed = failedIn(groupId)
        deleteConfigurations(failed)
        return failed.count
    }

    /// Servers of `groupId` that repeat an earlier one exactly.
    func duplicatesIn(_ groupId: String) -> [ProxyConfiguration] {
        var seen = Set<String>()
        var duplicates: [ProxyConfiguration] = []
        for config in groupConfigs(groupId) {
            if !seen.insert(CoreBridge.duplicateKey(config)).inserted {
                duplicates.append(config)
            }
        }
        return duplicates
    }

    /// Removes the repeats in `groupId`, keeping the first of each; returns how many went.
    func removeDuplicates(_ groupId: String) -> Int {
        let duplicates = duplicatesIn(groupId)
        deleteConfigurations(duplicates)
        return duplicates.count
    }

    /// Share links for `configs`, one per line; servers with no link form are left out.
    func exportLinks(_ configs: [ProxyConfiguration]) -> String {
        configs.compactMap { CoreBridge.shareLink($0) }.joined(separator: "\n")
    }

    // MARK: Latency

    func testLatency(_ config: ProxyConfiguration) {
        testLatencies([config], kind: latencyKindShown)
    }

    /// Measures `configs`. Switching the kind clears the old numbers: a TCP
    /// time next to a handshake time would not compare.
    func testLatencies(_ configs: [ProxyConfiguration], kind: LatencyKind) {
        guard !configs.isEmpty else { return }
        if latencyKindShown != kind {
            latencyKindShown = kind
            latency = [:]
        }
        markTesting(configs)
        Task { _ = await self.measure(configs, kind: kind, chunk: 12) }
    }

    func markTesting(_ configs: [ProxyConfiguration]) {
        var copy = latency
        for config in configs { copy[config.id] = .testing }
        latency = copy
    }

    /// The last successful time of every server measured so far, Auto's
    /// own record first.
    func knownLatencies() -> [UUID: Int] {
        var out = autoSelector.knownTimes
        for (id, result) in latency where out[id] == nil {
            if let ms = result.milliseconds { out[id] = ms }
        }
        return out
    }

    /// Measures `configs` a chunk at a time, publishing each chunk's results
    /// in one update; returns the times of those that answered.
    func measure(_ configs: [ProxyConfiguration], kind: LatencyKind, chunk: Int) async -> [UUID: Int] {
        var successes: [UUID: Int] = [:]
        var index = 0
        while index < configs.count {
            if Task.isCancelled { break }
            let end = min(index + chunk, configs.count)
            let slice = Array(configs[index..<end])
            index = end
            let results = await AppModel.measureChunk(slice, kind: kind)
            var copy = latency
            for (id, ms) in results {
                if let ms = ms {
                    copy[id] = .success(ms)
                    successes[id] = ms
                } else {
                    copy[id] = .failed
                }
            }
            latency = copy
        }
        if index < configs.count {
            // Cut short: the servers never reached stop spinning.
            var copy = latency
            for config in configs[index...] where copy[config.id] == .testing {
                copy.removeValue(forKey: config.id)
            }
            latency = copy
        }
        return successes
    }

    nonisolated static func measureChunk(_ configs: [ProxyConfiguration], kind: LatencyKind) async -> [(UUID, Int?)] {
        await withTaskGroup(of: (UUID, Int?).self, returning: [(UUID, Int?)].self) { group in
            for config in configs {
                group.addTask {
                    let ms = await LatencyTester.measure(config, kind: kind, timeout: 5)
                    return (config.id, ms)
                }
            }
            var out: [(UUID, Int?)] = []
            for await result in group {
                out.append(result)
            }
            return out
        }
    }

    // MARK: Auto

    var recheckInterval: TimeInterval {
        autoSelector.recheckInterval
    }

    func roundDue() -> Bool {
        autoSelector.roundDue()
    }

    /// Whether Auto's pick for `groupId` is recent enough to start on without a new round.
    func autoChoiceFresh(_ groupId: String) -> Bool {
        guard selection.autoChoices[groupId] != nil, let at = autoChoiceAt[groupId] else { return false }
        return Date().timeIntervalSince(at) < recheckInterval
    }

    /// Measures the group and records the fastest server as Auto's pick.
    /// When the group is the tunnel's and on Auto, a running tunnel moves to
    /// the pick if it is clearly faster than the live server. A round asked
    /// for while another runs follows it.
    @discardableResult
    func autoSelectFastest(_ groupId: String) async -> ProxyConfiguration? {
        if autoSelecting {
            pendingRoundGroupId = groupId
            return nil
        }
        let winner = await runRound(groupId)
        if let next = pendingRoundGroupId {
            pendingRoundGroupId = nil
            Task { await self.autoSelectFastest(next) }
        }
        return winner
    }

    private func runRound(_ groupId: String) async -> ProxyConfiguration? {
        let candidates = autoCandidates(groupId)
        guard !candidates.isEmpty, autoSelector.beginRound() else { return nil }
        autoSelecting = true
        defer {
            autoSelecting = false
            autoSelector.endRound()
        }
        if latencyKindShown != AppModel.autoKind {
            latencyKindShown = AppModel.autoKind
            latency = [:]
        }
        let tunnelsGroup = groupId == activeGroupId && vpn.status == .connected
        let liveId = tunnelsGroup ? liveConfigId : nil
        let outcome = await autoSelector.runRound(candidates: candidates, liveId: liveId)
        guard let winner = outcome.best, let ms = outcome.bestMs else { return nil }
        Log.info("Auto: \(winner.name) at \(ms) ms")

        selection.autoChoices[groupId] = winner.id
        autoChoiceAt[groupId] = Date()
        saveSelection()

        if groupId == activeGroupId && activeIsAuto {
            recomputeSelection()
            if vpn.status == .connected && liveConfigId != winner.id && outcome.shouldSwitch {
                switchTunnel(to: winner)
            }
        }
        return configsById[winner.id] ?? winner
    }

    /// One server's time for Auto, shown in the list as it comes in.
    func autoMeasure(_ config: ProxyConfiguration) async -> Int? {
        var copy = latency
        copy[config.id] = .testing
        latency = copy
        let ms = await LatencyTester.measure(config, kind: AppModel.autoKind, timeout: AutoPolicy.testTimeout)
        if latencyKindShown == AppModel.autoKind {
            var updated = latency
            updated[config.id] = ms.map { LatencyResult.success($0) } ?? .failed
            latency = updated
        }
        return ms
    }

    /// While the app is in front: a round for the active group whenever the
    /// last one is older than the recheck interval.
    func startAutoLoop() {
        autoLoop?.cancel()
        autoLoop = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(AutoPolicy.dueCheckSeconds * 1_000_000_000))
                if Task.isCancelled { return }
                guard let self = self else { return }
                let groupId = self.activeGroupId
                if self.activeIsAuto && self.roundDue() && !self.autoCandidates(groupId).isEmpty {
                    await self.autoSelectFastest(groupId)
                }
            }
        }
    }
}
