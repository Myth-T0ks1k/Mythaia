import Foundation
import Combine
import MythaiaKit

/// The app's state: servers, subscriptions, chains, what the tunnel draws
/// from, and the settings, all kept in the App Group store the tunnel reads.
///
/// Selection works as on Android: the tunnel draws from one group (Default
/// or a subscription). A group is on Auto, the fastest server by real ping,
/// unless the user pinned a server in it. A chain, when chosen, overrides
/// the group.
@MainActor
final class AppModel: ObservableObject {
    @Published var configurations: [ProxyConfiguration] = []
    @Published var subscriptions: [Subscription] = []
    @Published var chains: [ProxyChain] = []
    @Published var groups: [ProxyGroup] = []
    @Published var selection: SelectionState
    @Published var settings: AppSettings
    /// The server the tunnel is (or would be) on: the pin, or Auto's pick.
    @Published var selectedConfigId: UUID?

    @Published var latency: [UUID: LatencyResult] = [:]
    /// What the numbers in `latency` measure.
    @Published var latencyKindShown: LatencyKind
    @Published var autoSelecting = false
    @Published var updatingSubscriptionId: UUID?
    @Published var importingSubscription = false
    @Published var notice: SubscriptionNotice?
    @Published var alert: AppAlert?
    /// The sheet over the whole app: Add, or the server editor.
    @Published var rootSheet: RootSheet?
    /// Chains' last latency checks.
    @Published var chainLatency: [UUID: LatencyResult] = [:]
    /// Certificate policy and routing rules, read by the tunnel too.
    @Published var advanced: AdvancedSettings
    @Published var selectedTab: AppTab = .home
    /// The group shown on the Proxies screen.
    @Published var browsingGroupId: String = ProxyGroup.defaultId

    let vpn: VPNController
    let countryCodes: [String]
    let store: MythaiaStore

    var configsById: [UUID: ProxyConfiguration] = [:]
    var autoChoiceAt: [String: Date] = [:]
    /// Auto while the app is on screen; the tunnel runs its own while it is not.
    var autoSelector: AutoSelector!
    /// A round asked for while another ran; it runs next.
    var pendingRoundGroupId: String?
    var autoLoop: Task<Void, Never>?
    var lastOpenRefresh: Date?
    var failuresShown = Set<UUID>()
    /// The server the tunnel was last started on or switched to.
    var liveConfigId: UUID?
    private var cancellables = Set<AnyCancellable>()

    init() {
        let store = MythaiaStore.shared
        self.store = store
        self.vpn = VPNController()
        self.selection = store.loadSelection()
        let settings = store.loadSettings()
        self.settings = settings
        self.latencyKindShown = settings.latencyKind
        self.countryCodes = CountryCatalog.supportedCountryCodes()
        self.configurations = store.loadConfigurations()
        self.subscriptions = store.loadSubscriptions()
        self.chains = store.loadChains()
        let advanced = AdvancedSettingsStore.load()
        self.advanced = advanced
        advanced.applyCertificatePolicy()
        rebuildIndex()
        autoSelector = AutoSelector(
            recheckInterval: Double(max(settings.autoRecheckMinutes, 1) * 60),
            measure: { [weak self] config in
                guard let self = self else { return nil }
                return await self.autoMeasure(config)
            }
        )
        applyFirstRunDefaults()
        browsingGroupId = selection.activeGroupId
        recomputeSelection()

        vpn.$status
            .removeDuplicates()
            .sink { [weak self] status in
                self?.vpnStatusChanged(status)
            }
            .store(in: &cancellables)
        vpn.errors
            .receive(on: DispatchQueue.main)
            .sink { [weak self] message in
                self?.alert = AppAlert(title: String(localized: "VPN Error"), message: message)
            }
            .store(in: &cancellables)
    }

    // MARK: Store

    func setConfigurations(_ value: [ProxyConfiguration]) {
        configurations = value
        rebuildIndex()
        store.saveConfigurations(value)
    }

    func setSubscriptions(_ value: [Subscription]) {
        subscriptions = value
        rebuildIndex()
        store.saveSubscriptions(value)
    }

    func replaceSubscription(_ subscription: Subscription) {
        var copy = subscriptions
        guard let index = copy.firstIndex(where: { $0.id == subscription.id }) else { return }
        copy[index] = subscription
        setSubscriptions(copy)
    }

    func saveSelection() {
        store.saveSelection(selection)
    }

    func saveSettings() {
        store.saveSettings(settings)
    }

    /// The id lookup and the groups, rebuilt in one pass over the servers.
    func rebuildIndex() {
        var byId: [UUID: ProxyConfiguration] = [:]
        byId.reserveCapacity(configurations.count)
        var bySubscription: [UUID: [ProxyConfiguration]] = [:]
        var defaults: [ProxyConfiguration] = []
        for config in configurations {
            byId[config.id] = config
            if let subscriptionId = config.subscriptionId {
                bySubscription[subscriptionId, default: []].append(config)
            } else {
                defaults.append(config)
            }
        }
        configsById = byId
        var result = [ProxyGroup(id: ProxyGroup.defaultId, name: "", subscriptionId: nil, configs: defaults)]
        for subscription in subscriptions {
            result.append(ProxyGroup(
                id: ProxyGroup.id(for: subscription.id),
                name: subscription.name,
                subscriptionId: subscription.id,
                configs: bySubscription[subscription.id] ?? []
            ))
        }
        groups = result
    }

    private func applyFirstRunDefaults() {
        let key = "firstRunDefaultsApplied"
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: key) else { return }
        defaults.set(true, forKey: key)
        if settings.bypassCountryCode == nil,
           let code = CountryCatalog.suggestedCountryCode(),
           countryCodes.contains(code) {
            settings.bypassCountryCode = code
            saveSettings()
        }
    }

    // MARK: Groups and selection

    var activeGroupId: String { selection.activeGroupId }

    /// Whether the tunnel follows Auto rather than a pin or a chain.
    var activeIsAuto: Bool {
        selection.selectedChainId == nil && selection.groupPins[selection.activeGroupId] == nil
    }

    func group(_ id: String) -> ProxyGroup? {
        groups.first { $0.id == id }
    }

    func groupConfigs(_ id: String) -> [ProxyConfiguration] {
        group(id)?.configs ?? []
    }

    /// Servers Auto may choose from: everything with a per-flow dial.
    func autoCandidates(_ id: String) -> [ProxyConfiguration] {
        AutoSelector.dialable(groupConfigs(id))
    }

    /// What Auto measures, here and in the tunnel.
    static let autoKind: LatencyKind = .http

    func subscription(forGroup id: String) -> Subscription? {
        subscriptions.first { ProxyGroup.id(for: $0.id) == id }
    }

    var selectedChain: ProxyChain? {
        guard let id = selection.selectedChainId else { return nil }
        return chains.first { $0.id == id }
    }

    /// What the tunnel runs on: the chosen chain resolved, or the selected server.
    var selectedConfiguration: ProxyConfiguration? {
        if let chain = selectedChain { return resolve(chain) }
        guard let id = selectedConfigId else { return nil }
        return configsById[id]
    }

    /// A chain as one configuration: the last server is the exit, the ones
    /// before it the hops. Nil when a server is missing or is layer 3.
    func resolve(_ chain: ProxyChain) -> ProxyConfiguration? {
        let configs = chain.proxyIds.compactMap { configsById[$0] }
        guard configs.count == chain.proxyIds.count, configs.count >= 2 else { return nil }
        if configs.contains(where: { CoreBridge.isLayer3($0) }) { return nil }
        let exit = configs[configs.count - 1]
        return CoreBridge.chained(exit: exit, name: chain.name, hops: Array(configs.dropLast()))
    }

    /// Makes `id` the group the tunnel draws from; a live tunnel follows.
    func selectGroup(_ id: String) {
        let changed = selection.activeGroupId != id || selection.selectedChainId != nil
        selection.selectedChainId = nil
        selection.activeGroupId = id
        saveSelection()
        recomputeSelection()
        if changed { applySelectionToTunnel(freshAuto: true) }
    }

    /// Pins the tunnel to one server; its group becomes the active one.
    func pin(_ config: ProxyConfiguration) {
        let groupId = ProxyGroup.id(for: config.subscriptionId)
        // Tapping the server already on the wire changes the pin, not the
        // tunnel: a switch would drop every open connection.
        let alreadyLive = vpn.status == .connected && selection.selectedChainId == nil && liveConfigId == config.id
        selection.selectedChainId = nil
        selection.groupPins[groupId] = config.id
        selection.activeGroupId = groupId
        saveSelection()
        recomputeSelection()
        if !alreadyLive { applySelectionToTunnel(freshAuto: false) }
    }

    /// Lets `groupId` follow Auto again and makes it the active group.
    func useAuto(_ groupId: String) {
        selection.selectedChainId = nil
        selection.groupPins.removeValue(forKey: groupId)
        selection.activeGroupId = groupId
        saveSelection()
        recomputeSelection()
        applySelectionToTunnel(freshAuto: true)
    }

    func selectChain(_ chain: ProxyChain) {
        guard let resolved = resolve(chain) else { return }
        selection.selectedChainId = chain.id
        saveSelection()
        if vpn.status == .connected { switchTunnel(to: resolved) }
    }

    /// Brings a running tunnel in line with the selection. Auto first moves
    /// to the group's current pick, then measures and moves again if a
    /// server is clearly faster.
    func applySelectionToTunnel(freshAuto: Bool) {
        guard vpn.status == .connected else { return }
        guard let config = selectedConfiguration else { return }
        if config.id != liveConfigId || selection.selectedChainId != nil {
            switchTunnel(to: config)
        }
        if activeIsAuto && freshAuto {
            let groupId = activeGroupId
            Task { await self.autoSelectFastest(groupId) }
        }
    }

    /// Derives the selected server from the group state: the pin if it still
    /// exists, else Auto's last pick, else the first usable server.
    func recomputeSelection() {
        var changed = false
        let livePins = selection.groupPins.filter { configsById[$0.value] != nil }
        if livePins.count != selection.groupPins.count {
            selection.groupPins = livePins
            changed = true
        }
        let liveAuto = selection.autoChoices.filter { configsById[$0.value] != nil }
        if liveAuto.count != selection.autoChoices.count {
            selection.autoChoices = liveAuto
            changed = true
        }
        let groupId = selection.activeGroupId
        if groupId != ProxyGroup.defaultId && subscription(forGroup: groupId) == nil {
            selection.activeGroupId = ProxyGroup.defaultId
            changed = true
        }
        if let chainId = selection.selectedChainId {
            let chain = chains.first { $0.id == chainId }
            if chain == nil || resolve(chain!) == nil {
                selection.selectedChainId = nil
                changed = true
            }
        }
        if changed { saveSelection() }

        let active = selection.activeGroupId
        let configs = groupConfigs(active)
        selectedConfigId = livePins[active]
            ?? liveAuto[active]
            ?? configs.first(where: { !CoreBridge.isLayer3($0) })?.id
            ?? configs.first?.id
    }

    // MARK: Tunnel

    func toggleConnection() {
        switch vpn.status {
        case .disconnected:
            connect()
        case .connected, .connecting, .reasserting:
            disconnect()
        case .disconnecting:
            break
        }
    }

    /// Starts on the current selection. On Auto the tunnel comes up at once
    /// on the last pick and a round of measurements runs behind it.
    func connect() {
        let groupId = activeGroupId
        if let config = selectedConfiguration {
            startTunnel(config)
            if activeIsAuto && !autoChoiceFresh(groupId) && autoCandidates(groupId).count > 1 {
                Task {
                    // Let the start land before the measurements compete with it.
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                    let status = self.vpn.status
                    if status == .connected || status == .connecting {
                        await self.autoSelectFastest(groupId)
                    }
                }
            }
            return
        }
        if activeIsAuto && !autoCandidates(groupId).isEmpty {
            Task {
                guard let chosen = await self.autoSelectFastest(groupId) else {
                    self.alert = AppAlert(title: String(localized: "VPN Error"),
                                          message: String(localized: "No server answered."))
                    return
                }
                self.startTunnel(chosen)
            }
            return
        }
        alert = AppAlert(title: String(localized: "VPN Error"), message: String(localized: "No server is selected."))
    }

    func disconnect() {
        vpn.stop()
    }

    /// The options the tunnel starts with. On Auto it gets the group, cut to
    /// a sample it can hold in its memory limit.
    func startOptions(for config: ProxyConfiguration) -> TunnelStartOptions {
        var group: [ProxyConfiguration] = []
        if activeIsAuto {
            group = AutoSelector.groupForTunnel(groupConfigs(activeGroupId), liveId: config.id, known: knownLatencies())
        }
        return CoreBridge.tunnelStartOptions(configuration: config, settings: settings, groupConfigurations: group)
    }

    func startTunnel(_ config: ProxyConfiguration) {
        liveConfigId = config.id
        let options = startOptions(for: config)
        Task { await self.vpn.start(options) }
    }

    func switchTunnel(to config: ProxyConfiguration) {
        liveConfigId = config.id
        let options = startOptions(for: config)
        Task { await self.vpn.reload(options) }
    }

    /// Settings the tunnel reads at start: saved, and handed to a running
    /// tunnel with the current server.
    func pushSettingsToTunnel() {
        guard vpn.status == .connected, let config = selectedConfiguration else { return }
        switchTunnel(to: config)
    }

    private func vpnStatusChanged(_ status: TunnelStatus) {
        switch status {
        case .connected:
            if liveConfigId == nil {
                liveConfigId = store.loadTunnelStart()?.configuration.id
            }
            WidgetBridge.publish(connected: true, server: selectedConfiguration?.name)
        case .disconnected:
            liveConfigId = nil
            WidgetBridge.publish(connected: false, server: selectedConfiguration?.name)
        default:
            break
        }
    }

    // MARK: Settings

    func setRoutingMode(_ mode: RoutingMode) {
        guard settings.routingMode != mode else { return }
        settings.routingMode = mode
        saveSettings()
        pushSettingsToTunnel()
    }

    /// Saved for the next connect: the running tunnel's interface was set
    /// up for the mode it started in.
    func setTunnelMode(_ mode: TunnelMode) {
        guard settings.tunnelMode != mode else { return }
        settings.tunnelMode = mode
        saveSettings()
    }

    func setBypassCountry(_ code: String?) {
        guard settings.bypassCountryCode != code else { return }
        settings.bypassCountryCode = code
        saveSettings()
        pushSettingsToTunnel()
    }

    func setThemeMode(_ mode: ThemeMode) {
        settings.themeMode = mode
        saveSettings()
    }

    func setLatencyKind(_ kind: LatencyKind) {
        settings.latencyKind = kind
        saveSettings()
    }

    /// Everything on the Settings screen back to how a new install starts.
    func resetSettings() {
        settings.routingMode = .rule
        settings.tunnelMode = .tun
        settings.bypassCountryCode = CountryCatalog.suggestedCountryCode().flatMap { countryCodes.contains($0) ? $0 : nil }
        settings.themeMode = .system
        settings.latencyKind = .handshake
        settings.autoRecheckMinutes = 10
        settings.localProxyPort = 0
        saveSettings()
        pushSettingsToTunnel()
    }

    // MARK: Links and app lifecycle

    func handle(_ url: URL) {
        guard let link = DeepLink.parse(url) else { return }
        switch link {
        case .connect:
            if vpn.status == .disconnected { connect() }
        case .disconnect:
            if vpn.status != .disconnected { disconnect() }
        case .toggle:
            toggleConnection()
        case .importText(let text):
            // Nothing is added until the user confirms in the Add sheet.
            selectedTab = .proxies
            rootSheet = .add(AddRequest(initialText: text))
        }
    }

    func openAddSheet() {
        rootSheet = .add(AddRequest(initialText: ""))
    }

    func sceneBecameActive() {
        vpn.setForeground(true)
        Task { await self.adoptTunnelServer() }
        startAutoLoop()
        refreshSubscriptionsOnOpen()
        let groupId = activeGroupId
        if activeIsAuto && roundDue() && !autoCandidates(groupId).isEmpty {
            Task { await self.autoSelectFastest(groupId) }
        }
    }

    func sceneWentToBackground() {
        vpn.setForeground(false)
        autoLoop?.cancel()
        autoLoop = nil
        scheduleBackgroundRefresh()
    }

    /// Auto in the tunnel may have moved to another server while the app was
    /// away; the app takes that server as the group's Auto pick.
    func adoptTunnelServer() async {
        guard let id = await vpn.fetchLiveConfigurationId(), let config = configsById[id] else { return }
        liveConfigId = id
        guard activeIsAuto, ProxyGroup.id(for: config.subscriptionId) == activeGroupId,
              selection.autoChoices[activeGroupId] != id else { return }
        selection.autoChoices[activeGroupId] = id
        saveSelection()
        recomputeSelection()
    }

    static func describe(_ error: Error) -> String {
        if let localized = (error as? LocalizedError)?.errorDescription { return localized }
        return error.localizedDescription
    }
}
