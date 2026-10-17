import Foundation
import MythaiaKit

/// Servers typed in or changed by hand, chains, and the advanced settings.
extension AppModel {

    // MARK: Server editor

    func openNewServer() {
        rootSheet = .editor(EditorRequest(mode: .new, configuration: nil))
    }

    func openEditor(for config: ProxyConfiguration) {
        rootSheet = .editor(EditorRequest(mode: .edit, configuration: config))
    }

    func openDuplicate(of config: ProxyConfiguration) {
        rootSheet = .editor(EditorRequest(mode: .duplicate, configuration: config))
    }

    /// Stores what the editor made: a change under the server's own id, or
    /// a new server in the Default group.
    func saveFromEditor(_ config: ProxyConfiguration, mode: EditorRequest.Mode) {
        switch mode {
        case .edit:
            updateConfiguration(config)
        case .new, .duplicate:
            let fresh = CoreBridge.withIdentity(config, id: UUID(), subscriptionId: nil)
            addConfigurations([fresh])
            browsingGroupId = ProxyGroup.defaultId
        }
    }

    /// Replaces a server in place. The tunnel follows when it runs on it,
    /// directly or as a hop of the chosen chain; otherwise it would keep
    /// dialling the old address under the new name.
    func updateConfiguration(_ config: ProxyConfiguration) {
        var list = configurations
        guard let index = list.firstIndex(where: { $0.id == config.id }) else { return }
        list[index] = config
        setConfigurations(list)
        latency.removeValue(forKey: config.id)
        recomputeSelection()
        guard vpn.status == .connected else { return }
        let inChain = selectedChain?.proxyIds.contains(config.id) ?? false
        if liveConfigId == config.id || inChain, let live = selectedConfiguration {
            switchTunnel(to: live)
        }
    }

    // MARK: Chains

    func setChains(_ value: [ProxyChain]) {
        chains = value
        store.saveChains(value)
    }

    /// Adds `chain`, or replaces the one with its id. A chain on the wire is
    /// handed to the tunnel again.
    func saveChain(_ chain: ProxyChain) {
        var list = chains
        if let index = list.firstIndex(where: { $0.id == chain.id }) {
            list[index] = chain
        } else {
            list.append(chain)
        }
        setChains(list)
        chainLatency.removeValue(forKey: chain.id)
        recomputeSelection()
        if selection.selectedChainId == chain.id, vpn.status == .connected, let resolved = resolve(chain) {
            switchTunnel(to: resolved)
        }
    }

    func deleteChain(_ chain: ProxyChain) {
        let wasLive = selection.selectedChainId == chain.id && vpn.status == .connected
        setChains(chains.filter { $0.id != chain.id })
        chainLatency.removeValue(forKey: chain.id)
        recomputeSelection()
        if wasLive {
            if let next = selectedConfiguration { switchTunnel(to: next) } else { disconnect() }
        }
    }

    /// A real ping through every hop of the chain.
    func testChainLatency(_ chain: ProxyChain) {
        guard let resolved = resolve(chain) else { return }
        chainLatency[chain.id] = .testing
        Task {
            let ms = await LatencyTester.measure(resolved, kind: .http, timeout: AutoPolicy.testTimeout)
            if let ms = ms {
                self.chainLatency[chain.id] = .success(ms)
            } else {
                self.chainLatency[chain.id] = .failed
            }
        }
    }

    // MARK: Advanced settings

    /// Saves the advanced settings, applies the certificate policy here, and
    /// hands everything to a running tunnel.
    func setAdvanced(_ value: AdvancedSettings) {
        guard value != advanced else { return }
        advanced = value
        AdvancedSettingsStore.save(value)
        value.applyCertificatePolicy()
        pushSettingsToTunnel()
    }

    func setFragment(_ fragment: FragmentSettings) {
        var copy = advanced
        copy.fragment = fragment
        setAdvanced(copy)
    }

    func setAllowInsecure(_ on: Bool) {
        var copy = advanced
        copy.allowInsecure = on
        setAdvanced(copy)
    }

    enum TrustResult {
        case added
        case invalid
        case alreadyTrusted
    }

    /// Adds a certificate fingerprint: 64 hex digits, colons and spaces
    /// allowed between them.
    func trustFingerprint(_ text: String) -> TrustResult {
        let hex = text.lowercased().filter { $0 != ":" && $0 != " " && !$0.isNewline }
        let digits = Set("0123456789abcdef")
        guard hex.count == 64, hex.allSatisfy({ digits.contains($0) }) else { return .invalid }
        guard !advanced.trustedFingerprints.contains(hex) else { return .alreadyTrusted }
        var copy = advanced
        copy.trustedFingerprints.append(hex)
        setAdvanced(copy)
        return .added
    }

    func removeTrustedFingerprints(at offsets: IndexSet) {
        var copy = advanced
        for index in offsets.sorted(by: >) where index < copy.trustedFingerprints.count {
            copy.trustedFingerprints.remove(at: index)
        }
        setAdvanced(copy)
    }

    func setRouteRules(_ rules: [RouteRule]) {
        var copy = advanced
        copy.routeRules = rules
        setAdvanced(copy)
    }
}
