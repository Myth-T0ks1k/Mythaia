import Foundation
import MythaiaKit
import NetworkExtension

/// The tunnel, in one of two modes (`AppSettings.tunnelMode`):
///
/// - TUN (the default): the interface takes the default routes and DNS, and
///   `TunStack` (lwIP) terminates every TCP connection and UDP flow of the
///   device, as the Android VPN does.
/// - Proxy: no routes; the system proxy settings point at a local SOCKS5/HTTP
///   proxy on 127.0.0.1, so only what honours them goes through.
///
/// Either way each connection is routed and dialled through the selected
/// server. The extension has a hard memory limit of about 50 MB, so nothing
/// here holds more than a bounded amount: the log is a ring, the engines cap
/// their connections and buffers.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// The proxy-mode interface address, from the benchmarking range that no
    /// real network uses. TUN mode uses its own (TunNetworkSettings), away
    /// from the fake-IP pool.
    private static let proxyInterfaceAddress = "198.18.0.1"

    private let logBuffer = LogRingBuffer(capacity: 500)
    private let stateLock = NSLock()
    private var engine: TunnelEngine?
    private var options: TunnelStartOptions?
    private var rulesDatabase: RulesDatabase?
    private var autoSelector: AutoSelector?
    private var autoTask: Task<Void, Never>?
    private var asleep = false
    private var sleptAt: Double?
    private var appActive = false

    // MARK: - Lifecycle

    override func startTunnel(options startOptions: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let buffer = logBuffer
        Log.setSink { level, message in
            buffer.append(level: level, message: message)
        }

        // Options passed by the app are the freshest; an on-demand or system
        // start has none and uses what the app saved last.
        guard var start = TunnelStartOptions(startOptions: startOptions) ?? MythaiaStore.shared.loadTunnelStart() else {
            Log.error("No server to connect to")
            completionHandler(MythaiaError.invalidConfiguration("no server selected"))
            return
        }
        start.groupConfigurations = AutoSelector.groupForTunnel(start.groupConfigurations, liveId: start.configuration.id)
        // Certificate checks and ClientHello fragmentation as the user set
        // them: the app keeps them in the App Group for this process.
        AdvancedSettingsStore.load().applyCertificatePolicy()

        // WireGuard is a layer-3 interface: it replaces the packet stack and
        // the local proxy alike, whatever the tunnel mode says.
        if start.configuration.outboundProtocol.isLayer3 {
            startWireGuard(start, completionHandler: completionHandler)
            return
        }

        switch start.settings.tunnelMode {
        case .tun:
            startTunMode(start, completionHandler: completionHandler)
        case .proxy:
            startProxyMode(start, completionHandler: completionHandler)
        }
    }

    private func startProxyMode(_ start: TunnelStartOptions, completionHandler: @escaping (Error?) -> Void) {
        let summary = "\(start.configuration.name), \(start.settings.routingMode.rawValue) mode, proxy on 127.0.0.1:"
        let proxy = LocalProxyServer(router: makeRouter(start.settings), port: start.settings.localProxyPort)
        proxy.configuration = start.configuration
        let port: UInt16
        do {
            port = try proxy.start()
        } catch {
            Log.error("Local proxy did not start: \(error.localizedDescription)")
            completionHandler(error)
            return
        }
        proxy.onProxyFailures = { [weak self] count in
            self?.proxyFailing(count: count)
        }
        withState {
            engine = proxy
            options = start
        }
        setTunnelNetworkSettings(PacketTunnelProvider.proxyNetworkSettings(port: port)) { [weak self] error in
            if let error {
                Log.error("Tunnel settings were refused: \(error.localizedDescription)")
                proxy.stop()
                self?.withState { self?.engine = nil }
                completionHandler(error)
                return
            }
            Log.info("Connected through \(summary)\(port)")
            self?.startAuto()
            completionHandler(nil)
        }
    }

    private func startTunMode(_ start: TunnelStartOptions, completionHandler: @escaping (Error?) -> Void) {
        let router = makeRouter(start.settings)
        let configuration = start.configuration
        Task { [weak self] in
            guard let self else { return }
            // The servers' real addresses, while the system's DNS is still its
            // own: they are routed outside the tunnel.
            let servers = await TunNetworkSettings.resolveServers(of: configuration)
            let addresses = TunNetworkSettings.allAddresses(servers)
            let settings = TunNetworkSettings.make(
                remoteAddress: addresses.first ?? "127.0.0.1",
                serverAddresses: addresses
            )
            self.setTunnelNetworkSettings(settings) { error in
                if let error {
                    Log.error("Tunnel settings were refused: \(error.localizedDescription)")
                    completionHandler(error)
                    return
                }
                let stack = TunStack(packetFlow: self.packetFlow, router: router, stats: TrafficStats())
                stack.switchConfiguration(configuration)
                stack.seedServerAddresses(servers)
                stack.onProxyFailures = { [weak self] count in
                    self?.proxyFailing(count: count)
                }
                stack.start()
                self.withState {
                    self.engine = stack
                    self.options = start
                }
                Log.info("Connected through \(configuration.name), \(start.settings.routingMode.rawValue) mode, all traffic")
                self.startAuto()
                completionHandler(nil)
            }
        }
    }

    // MARK: - WireGuard

    /// WireGuard and AmneziaWG: the device's IP packets go straight into the
    /// interface, which runs instead of the packet stack or the local proxy
    /// whatever `tunnelMode` says. The profile's own addresses, DNS and MTU
    /// shape the interface and its `AllowedIPs` are the routes. Domain routing
    /// rules do not apply to a layer-3 profile — there are no flows to route,
    /// only packets — and neither does Auto, which picks among stream servers
    /// this interface cannot carry.
    private func startWireGuard(_ start: TunnelStartOptions, completionHandler: @escaping (Error?) -> Void) {
        var withoutAuto = start
        withoutAuto.groupConfigurations = []
        let wireGuardStart = withoutAuto
        let configuration = start.configuration
        Task { [weak self] in
            guard let self else { return }
            let plan: WireGuardEngine.Plan
            do {
                // The endpoint is resolved while the system's DNS is still its own.
                plan = try await WireGuardEngine.plan(for: configuration)
            } catch {
                Log.error("WireGuard profile \(configuration.name) is not usable: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            self.setTunnelNetworkSettings(plan.networkSettings) { error in
                if let error {
                    Log.error("Tunnel settings were refused: \(error.localizedDescription)")
                    completionHandler(error)
                    return
                }
                let wireGuard: WireGuardEngine
                do {
                    wireGuard = try WireGuardEngine(packetFlow: self.packetFlow, plan: plan)
                } catch {
                    Log.error("WireGuard could not start: \(error.localizedDescription)")
                    completionHandler(error)
                    return
                }
                // Left running, a tunnel whose peer never answers keeps the
                // routes while carrying nothing; stopping hands them back and
                // tells the user what happened.
                wireGuard.onFailure = { [weak self, weak wireGuard] reason in
                    guard let self, let wireGuard, self.currentEngine() === wireGuard else { return }
                    self.cancelTunnelWithError(MythaiaError.connectFailed("the WireGuard peer did not answer (\(reason))"))
                }
                wireGuard.onRestartNeeded = { [weak self] next in
                    self?.restartEngine(with: next)
                }
                wireGuard.start()
                self.withState {
                    self.engine = wireGuard
                    self.options = wireGuardStart
                }
                // Stops an Auto left from a previous server; with no group,
                // none starts.
                self.startAuto()
                Log.info("Connected through \(configuration.name) (WireGuard), routes from its AllowedIPs")
                completionHandler(nil)
            }
        }
    }

    /// Moves the running tunnel to `configuration` when either side of the
    /// switch is WireGuard. A layer-3 interface and the packet stack (or the
    /// proxy) need different network settings, and two WireGuard profiles
    /// different addresses and routes, so the engine and its settings are
    /// rebuilt rather than adjusted, as the Android service rebuilds its VPN.
    private func restartEngine(with configuration: ProxyConfiguration) {
        let (previous, saved) = withState { () -> (TunnelEngine?, TunnelStartOptions?) in
            let old = engine
            engine = nil
            options?.configuration = configuration
            return (old, options)
        }
        guard let start = saved else { return }
        Log.info("Rebuilding the tunnel for \(configuration.name)")
        reasserting = true
        let finish: (Error?) -> Void = { [weak self] error in
            self?.reasserting = false
            if let error {
                Log.error("The tunnel could not move to \(configuration.name): \(error.localizedDescription)")
                self?.cancelTunnelWithError(error)
            }
        }
        let begin: () -> Void = { [weak self] in
            guard let self else { return }
            if configuration.outboundProtocol.isLayer3 {
                self.startWireGuard(start, completionHandler: finish)
                return
            }
            switch start.settings.tunnelMode {
            case .tun:
                self.startTunMode(start, completionHandler: finish)
            case .proxy:
                self.startProxyMode(start, completionHandler: finish)
            }
        }
        if let previous {
            previous.shutdown(begin)
        } else {
            begin()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Log.info("Disconnecting (reason \(reason.rawValue))")
        var current: TunnelEngine?
        var task: Task<Void, Never>?
        withState {
            current = engine
            task = autoTask
            engine = nil
            autoTask = nil
            autoSelector = nil
        }
        task?.cancel()
        guard let current else {
            QuicClientPool.closeAll()
            completionHandler()
            return
        }
        // TUN mode resets its connections on lwIP's queue before it finishes;
        // the QUIC sessions go after the flows that used them.
        current.shutdown {
            QuicClientPool.closeAll()
            completionHandler()
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        withState {
            asleep = true
            sleptAt = Date().timeIntervalSince1970
        }
        completionHandler()
    }

    override func wake() {
        let slept: Double? = withState { () -> Double? in
            asleep = false
            return sleptAt
        }
        // Proxy connections rarely survive a long sleep: the stack drops
        // them so apps reconnect at once instead of waiting on dead sockets.
        if let slept, Date().timeIntervalSince1970 - slept >= TunConstants.wakeRestartThresholdSec,
           let stack = currentEngine() as? TunStack {
            stack.restart()
        }
        // A round skipped while the device slept runs now, after a moment
        // for the radio to wake.
        Task { [weak self] in
            let settle = UInt64(AutoPolicy.wakeSettleSeconds * 1_000_000_000)
            try? await Task.sleep(nanoseconds: settle)
            await self?.autoTick()
        }
    }

    // MARK: - App messages

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let reply: TunnelReply
        do {
            let message = try TunnelMessage.decode(messageData)
            reply = handle(message)
        } catch {
            reply = TunnelReply.failure("Unknown request: \(error.localizedDescription)")
        }
        completionHandler?(try? reply.encoded())
    }

    private func handle(_ message: TunnelMessage) -> TunnelReply {
        switch message {
        case .switchConfiguration(let configuration):
            guard let current = currentEngine() else { return TunnelReply.failure("The tunnel is not running") }
            // To WireGuard from the packet stack or the proxy, the interface
            // itself changes; WireGuardEngine asks for the same rebuild when
            // it is handed a stream server.
            if configuration.outboundProtocol.isLayer3 && !(current is WireGuardEngine) {
                restartEngine(with: configuration)
                return TunnelReply(configurationId: configuration.id, configurationName: configuration.name)
            }
            current.use(configuration)
            withState { options?.configuration = configuration }
            Log.info("Switched to \(configuration.name)")
            return statusReply(current)
        case .stats:
            guard let current = currentEngine() else { return TunnelReply.failure("The tunnel is not running") }
            return TunnelReply(stats: current.trafficStats)
        case .logTail:
            return TunnelReply(logLines: logBuffer.lines())
        case .ping:
            guard let current = currentEngine() else { return TunnelReply.failure("The tunnel is not running") }
            return statusReply(current)
        case .reload:
            return reload()
        case .appActive(let active):
            withState { appActive = active }
            return TunnelReply()
        }
    }

    private func statusReply(_ current: TunnelEngine) -> TunnelReply {
        let configuration = current.currentConfiguration
        return TunnelReply(
            configurationId: configuration?.id,
            configurationName: configuration?.name,
            port: current.listeningPort
        )
    }

    /// Applies what the app saved: server, routing and the Auto group. The
    /// mode and the proxy's port stay until the next connect, since the
    /// network settings name them.
    private func reload() -> TunnelReply {
        guard let current = currentEngine() else { return TunnelReply.failure("The tunnel is not running") }
        guard var start = MythaiaStore.shared.loadTunnelStart() else {
            return TunnelReply.failure("No saved server to switch to")
        }
        start.groupConfigurations = AutoSelector.groupForTunnel(start.groupConfigurations, liveId: start.configuration.id)
        AdvancedSettingsStore.load().applyCertificatePolicy()
        if start.configuration.outboundProtocol.isLayer3 && !(current is WireGuardEngine) {
            withState { options = start }
            restartEngine(with: start.configuration)
            return TunnelReply(configurationId: start.configuration.id, configurationName: start.configuration.name)
        }
        current.route(with: makeRouter(start.settings))
        current.use(start.configuration)
        withState { options = start }
        Log.info("Settings reloaded; server \(start.configuration.name), \(start.settings.routingMode.rawValue) mode")
        // A WireGuard profile is one interface, not a group: Auto would move
        // the user off it.
        if !start.configuration.outboundProtocol.isLayer3 {
            startAuto()
        }
        return statusReply(current)
    }

    // MARK: - Routing

    private func makeRouter(_ settings: AppSettings) -> Router {
        var database: RulesDatabase?
        if settings.routingMode == .rule && settings.normalizedBypassCountryCode != nil {
            database = withState { () -> RulesDatabase? in
                if rulesDatabase == nil { rulesDatabase = RulesDatabase.bundled() }
                return rulesDatabase
            }
        }
        // The user's own rules (Advanced settings) come first; they apply in
        // rule mode, as the router decides.
        let router = Router(settings: settings, database: database, rules: AdvancedSettingsStore.load().routeRules)
        if let code = settings.normalizedBypassCountryCode, settings.routingMode == .rule {
            Log.info("Bypass for \(code): \(router.bypassEntryCount) entries")
        }
        return router
    }

    /// No default route and no DNS: the system keeps its own paths and
    /// resolvers, and only what honours the proxy settings goes through the
    /// local proxy. Local names and private addresses are excepted so the
    /// LAN is reached the way it always is.
    private static func proxyNetworkSettings(port: UInt16) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: [proxyInterfaceAddress], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = []
        settings.ipv4Settings = ipv4

        let endpoint = NEProxyServer(address: "127.0.0.1", port: Int(port))
        let proxy = NEProxySettings()
        proxy.httpEnabled = true
        proxy.httpServer = endpoint
        proxy.httpsEnabled = true
        proxy.httpsServer = endpoint
        proxy.excludeSimpleHostnames = true
        proxy.matchDomains = [""]
        proxy.exceptionList = proxyExceptions()
        settings.proxySettings = proxy
        return settings
    }

    private static func proxyExceptions() -> [String] {
        var list = [
            "localhost",
            "*.localhost",
            "*.local",
            "*.lan",
            "*.home.arpa",
            "127.0.0.1",
            "::1",
            "10.*",
            "192.168.*",
            "169.254.*",
        ]
        for second in 16...31 {
            list.append("172.\(second).*")
        }
        return list
    }

    // MARK: - Auto

    /// Auto runs here when the app handed over a group: every
    /// `AutoPolicy.dueCheckSeconds` it checks whether a round is owed, and
    /// skips it while the device sleeps or the app is on screen (the app
    /// measures then).
    private func startAuto() {
        let group: [ProxyConfiguration] = withState { options?.groupConfigurations ?? [] }
        let minutes: Int = withState { options?.settings.autoRecheckMinutes ?? AppSettings.defaultAutoRecheckMinutes }
        var previous: Task<Void, Never>?
        withState {
            previous = autoTask
            autoTask = nil
            autoSelector = nil
        }
        previous?.cancel()
        guard !AutoSelector.dialable(group).isEmpty else { return }

        let selector = AutoSelector(recheckInterval: Double(max(1, minutes)) * 60)
        // The app measured the group when it connected; the first round is
        // owed one interval from now.
        selector.markRound()
        let task = Task { [weak self] in
            let pause = UInt64(AutoPolicy.dueCheckSeconds * 1_000_000_000)
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: pause)
                if Task.isCancelled { break }
                await self?.autoTick()
            }
        }
        withState {
            autoSelector = selector
            autoTask = task
        }
        Log.info("Auto: \(group.count) servers, a round every \(max(1, minutes)) min")
    }

    private func autoTick() async {
        let state = withState { () -> (AutoSelector?, Bool) in
            (autoSelector, asleep || appActive)
        }
        guard let selector = state.0, !state.1, selector.roundDue() else { return }
        guard selector.beginRound() else { return }
        defer { selector.endRound() }
        guard let current = currentEngine() else { return }
        let group: [ProxyConfiguration] = withState { options?.groupConfigurations ?? [] }
        let live = current.currentConfiguration?.id
        let result = await selector.runRound(candidates: group, liveId: live)
        guard let best = result.best else {
            Log.warning("Auto: no server in the group answered")
            return
        }
        if result.shouldSwitch {
            moveTo(best, ms: result.bestMs, reason: "faster")
        }
    }

    /// Dials through the live server keep failing: with Auto on, measure the
    /// rest of the group and move to what answers. Bounded by
    /// `AutoPolicy.reconnectMax`, so a dead network does not turn into a
    /// loop.
    private func proxyFailing(count: Int) {
        guard count == AutoPolicy.failuresBeforeRecovery else { return }
        let state = withState { () -> (AutoSelector?, Bool) in
            (autoSelector, appActive)
        }
        guard let selector = state.0, !state.1 else { return }
        Task { [weak self] in
            guard selector.beginRound() else { return }
            defer { selector.endRound() }
            guard let self, let current = self.currentEngine() else { return }
            let group: [ProxyConfiguration] = self.withState { self.options?.groupConfigurations ?? [] }
            let failed = current.currentConfiguration?.id
            Log.warning("Auto: \(count) connections in a row failed; measuring the group")
            guard let result = await selector.recoverAfterFailure(candidates: group, failed: failed),
                  let best = result.best else { return }
            self.moveTo(best, ms: result.bestMs, reason: "after failures")
        }
    }

    /// New connections go to `best`; the choice is saved so the app shows
    /// it and an on-demand restart comes back on it.
    private func moveTo(_ best: ProxyConfiguration, ms: Int?, reason: String) {
        guard let current = currentEngine() else { return }
        if current.currentConfiguration?.id == best.id { return }
        current.use(best)
        let updated: TunnelStartOptions? = withState { () -> TunnelStartOptions? in
            options?.configuration = best
            return options
        }
        let timing = ms.map { " (\($0) ms)" } ?? ""
        Log.info("Auto: switching to \(best.name)\(timing), \(reason)")

        let store = MythaiaStore.shared
        var selection = store.loadSelection()
        selection.autoChoices[selection.activeGroupId] = best.id
        store.saveSelection(selection)
        if let updated {
            store.saveTunnelStart(updated)
        }
    }

    // MARK: - State

    private func currentEngine() -> TunnelEngine? {
        withState { engine }
    }

    @discardableResult
    private func withState<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }
}

/// What the provider needs from either engine: the local proxy (proxy mode)
/// or the packet stack (TUN mode).
protocol TunnelEngine: AnyObject {
    var currentConfiguration: ProxyConfiguration? { get }
    var trafficStats: TrafficStats { get }
    /// The local proxy's port, nil in TUN mode.
    var listeningPort: UInt16? { get }
    /// New connections go through `configuration`.
    func use(_ configuration: ProxyConfiguration)
    func route(with router: Router)
    func shutdown(_ done: @escaping () -> Void)
}

extension LocalProxyServer: TunnelEngine {
    var currentConfiguration: ProxyConfiguration? { configuration }
    var trafficStats: TrafficStats { stats }
    var listeningPort: UInt16? { boundPort }

    func use(_ configuration: ProxyConfiguration) {
        self.configuration = configuration
    }

    func route(with router: Router) {
        self.router = router
    }

    func shutdown(_ done: @escaping () -> Void) {
        stop()
        done()
    }
}

extension TunStack: TunnelEngine {
    var currentConfiguration: ProxyConfiguration? { configuration }
    var trafficStats: TrafficStats { stats }
    var listeningPort: UInt16? { nil }

    func use(_ configuration: ProxyConfiguration) {
        switchConfiguration(configuration)
    }

    func route(with router: Router) {
        self.router = router
    }

    func shutdown(_ done: @escaping () -> Void) {
        stop(completion: done)
    }
}
