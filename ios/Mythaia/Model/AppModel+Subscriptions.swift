import Foundation
import MythaiaKit

extension AppModel {

    /// The `x-hwid` value for a panel at `url`: only the panels known to
    /// require the device identifier get it.
    func hwid(for url: String) -> String? {
        guard SubscriptionDomainHelper.shouldRequireRemnawaveHWID(url), !settings.hwid.isEmpty else { return nil }
        return settings.hwid
    }

    // MARK: Adding

    /// Adds a downloaded subscription and its servers. A first subscription
    /// on an empty app becomes the active group, on Auto.
    func addSubscription(_ configs: [ProxyConfiguration], _ subscription: Subscription) {
        setSubscriptions(subscriptions + [subscription])
        let tagged = configs.map { CoreBridge.withIdentity($0, id: $0.id, subscriptionId: subscription.id) }
        setConfigurations(configurations + tagged)
        if groupConfigs(activeGroupId).isEmpty && selection.selectedChainId == nil {
            selection.activeGroupId = ProxyGroup.id(for: subscription.id)
            saveSelection()
        }
        recomputeSelection()
    }

    /// Downloads `url` (fronting from the arguments, else from the link
    /// itself) and adds it as a subscription.
    @discardableResult
    func importSubscription(url: String, frontSni: String?, frontTargets: [String], name: String?) async throws -> Subscription {
        importingSubscription = true
        defer { importingSubscription = false }

        let link = SubscriptionLink.parse(url)
        let panelUrl = link?.url ?? url
        let sni = frontSni ?? link?.frontSni
        let targets = frontTargets.isEmpty ? (link?.frontTargets ?? []) : frontTargets
        let givenName = (name ?? link?.name)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let linkName = (givenName?.isEmpty ?? true) ? nil : givenName
        let fallbackName = URL(string: panelUrl)?.host ?? String(localized: "Subscription")
        let draft = CoreBridge.newSubscription(
            name: linkName ?? fallbackName,
            url: panelUrl,
            frontSni: sni,
            frontTargets: targets,
            nameCustomized: linkName != nil
        )

        let result = try await SubscriptionFetcher.fetch(draft, hwid: hwid(for: panelUrl), via: nil, timeout: nil)
        if result.configurations.isEmpty {
            throw MythaiaError.parse(String(localized: "The subscription has no servers."))
        }
        let subscription = CoreBridge.merging(fetched: result.subscription, into: draft)
        addSubscription(result.configurations, subscription)
        browsingGroupId = ProxyGroup.id(for: subscription.id)
        return subscription
    }

    // MARK: Editing and deleting

    func updateSubscriptionSettings(_ subscription: Subscription, draft: SubscriptionDraft) {
        guard let current = subscriptions.first(where: { $0.id == subscription.id }) else { return }
        replaceSubscription(CoreBridge.applying(draft, to: current))
    }

    func deleteSubscription(_ subscription: Subscription) {
        let groupId = ProxyGroup.id(for: subscription.id)
        let wasLive = vpn.status == .connected && selection.selectedChainId == nil && activeGroupId == groupId
        let removedIds = Set(configurations.filter { $0.subscriptionId == subscription.id }.map { $0.id })
        setConfigurations(configurations.filter { $0.subscriptionId != subscription.id })
        setSubscriptions(subscriptions.filter { $0.id != subscription.id })
        latency = latency.filter { !removedIds.contains($0.key) }
        selection.groupPins.removeValue(forKey: groupId)
        selection.autoChoices.removeValue(forKey: groupId)
        saveSelection()
        if browsingGroupId == groupId { browsingGroupId = ProxyGroup.defaultId }
        if notice?.subscriptionId == subscription.id { notice = nil }
        recomputeSelection()
        if wasLive {
            if let next = selectedConfiguration { switchTunnel(to: next) } else { disconnect() }
        }
    }

    // MARK: Refreshing

    /// Fetches `subscription` again and folds the result into the store,
    /// keeping the ids of servers already there. A failure is recorded with
    /// the subscription and thrown.
    func updateSubscription(_ subscription: Subscription, via: ProxyConfiguration?, timeout: Double?) async throws {
        let result: SubscriptionFetchResult
        do {
            result = try await SubscriptionFetcher.fetch(
                subscription, hwid: hwid(for: subscription.url), via: via,
                timeout: timeout
            )
        } catch {
            if let current = subscriptions.first(where: { $0.id == subscription.id }) {
                replaceSubscription(CoreBridge.markingFailure(current, message: AppModel.describe(error)))
            }
            throw error
        }
        // The fetch takes a while: a rename or a deletion made meanwhile wins.
        guard let current = subscriptions.first(where: { $0.id == subscription.id }) else { return }
        let old = configurations.filter { $0.subscriptionId == current.id }
        let merged = SubscriptionMerge.preserveIds(old: old, fetched: result.configurations, subscriptionId: current.id)
        replaceServers(of: current.id, with: merged)
        replaceSubscription(CoreBridge.merging(fetched: result.subscription, into: current))
        recomputeSelection()
    }

    /// Puts `servers` where the subscription's old ones were.
    private func replaceServers(of subscriptionId: UUID, with servers: [ProxyConfiguration]) {
        var out: [ProxyConfiguration] = []
        out.reserveCapacity(configurations.count + servers.count)
        var inserted = false
        for config in configurations {
            if config.subscriptionId == subscriptionId {
                if !inserted {
                    out.append(contentsOf: servers)
                    inserted = true
                }
            } else {
                out.append(config)
            }
        }
        if !inserted { out.append(contentsOf: servers) }
        let kept = Set(out.map { $0.id })
        setConfigurations(out)
        latency = latency.filter { kept.contains($0.key) }
    }

    /// A refresh started from the Proxies screen, with its spinner and its
    /// failure in the bar at the bottom.
    func refreshSubscription(_ subscription: Subscription) {
        guard updatingSubscriptionId == nil else { return }
        updatingSubscriptionId = subscription.id
        Task {
            do {
                try await self.updateSubscription(subscription, via: nil, timeout: nil)
                if self.notice?.subscriptionId == subscription.id { self.notice = nil }
            } catch {
                self.reportFailure(subscription, error)
            }
            self.updatingSubscriptionId = nil
        }
    }

    /// The same refresh, awaited, for pull to refresh.
    func refreshSubscriptionNow(_ subscription: Subscription) async {
        guard updatingSubscriptionId == nil else { return }
        updatingSubscriptionId = subscription.id
        do {
            try await updateSubscription(subscription, via: nil, timeout: nil)
            if notice?.subscriptionId == subscription.id { notice = nil }
        } catch {
            reportFailure(subscription, error)
        }
        updatingSubscriptionId = nil
    }

    func reportFailure(_ subscription: Subscription, _ error: Error) {
        notice = .failed(
            subscriptionId: subscription.id,
            name: subscription.name,
            message: AppModel.describe(error),
            canRetry: AppModel.worthRetryingElsewhere(error)
        )
    }

    /// A panel that answered with nothing usable would say the same through
    /// any server; only a failure to reach it is worth a detour.
    static func worthRetryingElsewhere(_ error: Error) -> Bool {
        guard let error = error as? MythaiaError else { return true }
        switch error {
        case .parse, .invalidConfiguration, .unsupported:
            return false
        default:
            return true
        }
    }

    func dismissNotice() {
        notice = nil
    }

    /// Fetches the subscription through a server that works, for a panel
    /// this network cannot reach: the live server first, then the first
    /// servers to pass a fresh check, the subscription's own before the rest.
    func refreshThroughWorkingServer(_ subscriptionId: UUID) {
        guard let subscription = subscriptions.first(where: { $0.id == subscriptionId }),
              updatingSubscriptionId == nil else { return }
        updatingSubscriptionId = subscriptionId
        notice = .retrying(subscriptionId: subscriptionId, name: subscription.name)
        Task {
            var lastError: Error?
            let servers = await self.serversThatWork(subscriptionId)
            for server in servers {
                do {
                    try await self.updateSubscription(subscription, via: server, timeout: 20)
                    self.notice = .updatedThrough(subscriptionId: subscriptionId, name: subscription.name, server: server.name)
                    self.updatingSubscriptionId = nil
                    return
                } catch {
                    lastError = error
                    // Reached and empty: another server will not change that.
                    if !AppModel.worthRetryingElsewhere(error) { break }
                }
            }
            let message: String
            if let lastError = lastError {
                let reason = AppModel.describe(lastError)
                message = String(localized: "Not through a working server either: \(reason)")
            } else {
                message = String(localized: "No server answered, so there is nothing to go through. Check your servers and try again.")
            }
            self.notice = .failed(subscriptionId: subscriptionId, name: subscription.name, message: message, canRetry: false)
            self.updatingSubscriptionId = nil
        }
    }

    /// Servers that answered a real request just now, to fetch through:
    /// the live server first, then the subscription's own, then the rest.
    private func serversThatWork(_ subscriptionId: UUID) async -> [ProxyConfiguration] {
        var live: ProxyConfiguration?
        if vpn.status == .connected, let id = liveConfigId {
            live = configsById[id]
        }
        var known: [UUID: Int?] = [:]
        for (id, result) in latency {
            switch result {
            case .success(let ms): known[id] = .some(ms)
            case .failed: known[id] = .some(nil)
            case .testing: break
            }
        }
        let candidates = WorkingServers.candidates(configurations, subscriptionId: subscriptionId, known: known)
        let checks = CheckLog()
        let found = await WorkingServers.find(
            live: live,
            candidates: candidates,
            onResult: { id, ms in checks.add(id, ms) }
        )
        if latencyKindShown == .http {
            var copy = latency
            for (id, ms) in checks.all() {
                copy[id] = ms.map { LatencyResult.success($0) } ?? .failed
            }
            latency = copy
        }
        return found
    }

    /// The app came up: refresh what asks to be refreshed on open or is due,
    /// then speak up for a subscription that keeps failing.
    func refreshSubscriptionsOnOpen() {
        let now = Date()
        if let last = lastOpenRefresh, now.timeIntervalSince(last) < 30 { return }
        lastOpenRefresh = now
        let due = subscriptions.filter { shouldRefreshOnOpen($0) }
        Task {
            for subscription in due {
                if self.updatingSubscriptionId != nil { continue }
                self.updatingSubscriptionId = subscription.id
                do {
                    try await self.updateSubscription(subscription, via: nil, timeout: nil)
                } catch {
                    Log.warning("Refresh on open failed for \(subscription.name): \(AppModel.describe(error))")
                }
                self.updatingSubscriptionId = nil
            }
            if self.notice != nil { return }
            let failing = self.subscriptions.first { $0.isFailing && !self.failuresShown.contains($0.id) }
            guard let failing = failing else { return }
            self.failuresShown.insert(failing.id)
            self.notice = .failed(
                subscriptionId: failing.id,
                name: failing.name,
                message: failing.lastFailureMessage ?? String(localized: "Unknown error"),
                canRetry: true
            )
        }
    }

    /// On every open when the panel asks for it; otherwise once the update
    /// interval (the panel's, or a day) has passed.
    private func shouldRefreshOnOpen(_ subscription: Subscription) -> Bool {
        subscription.updateOnOpen || isAutoUpdateDue(subscription)
    }
}

/// The checks a search for working servers made, gathered from wherever
/// they finish and handed to the main actor afterwards.
private final class CheckLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [(UUID, Int?)] = []

    func add(_ id: UUID, _ ms: Int?) {
        lock.lock()
        entries.append((id, ms))
        lock.unlock()
    }

    func all() -> [(UUID, Int?)] {
        lock.lock()
        defer { lock.unlock() }
        return entries
    }
}
