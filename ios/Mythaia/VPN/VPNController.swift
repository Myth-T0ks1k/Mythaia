import Foundation
import Combine
import NetworkExtension
import MythaiaKit

/// Where the tunnel is, in the app's words.
enum TunnelStatus: Equatable {
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting

    var isTransitioning: Bool {
        self == .connecting || self == .reasserting || self == .disconnecting
    }
}

/// Owns the one VPN configuration of the app and talks to the running tunnel.
///
/// The configuration is created on the first connect. Starting saves the
/// chosen server and the settings to the App Group container, where the
/// tunnel reads them; a running tunnel is asked to switch servers, report
/// traffic and hand over its log with provider messages.
@MainActor
final class VPNController: ObservableObject {
    @Published private(set) var status: TunnelStatus = .disconnected
    /// When the tunnel came up; nil while it is not up.
    @Published private(set) var connectedDate: Date?
    @Published private(set) var uploadBytes: Int64 = 0
    @Published private(set) var downloadBytes: Int64 = 0
    /// Bytes per second over the last poll.
    @Published private(set) var uploadSpeed: Int64 = 0
    @Published private(set) var downloadSpeed: Int64 = 0
    /// A start that ended before the tunnel came up; the home screen shows it
    /// for a few seconds and clears it.
    @Published var lastConnectFailed = false
    /// What went wrong, in words, for an alert.
    let errors = PassthroughSubject<String, Never>()

    enum SendResult {
        case reply(Data?)
        case failed
    }

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var statsTask: Task<Void, Never>?
    private var reachedConnected = false
    private var pendingRestart: TunnelStartOptions?
    private var isForeground = true

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] _ in
            guard let self = self else { return }
            Task { @MainActor in
                self.refreshStatus()
            }
        }
        Task { [weak self] in
            await self?.loadExisting()
        }
    }

    /// The bundle id of the packet tunnel extension.
    private var tunnelBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "com.mythaia") + ".Tunnel"
    }

    // MARK: Configuration

    /// Picks up a configuration saved earlier, so a tunnel started from the
    /// Settings app or before a relaunch shows as it is.
    func loadExisting() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = pick(managers)
        } catch {
            Log.warning("Could not read VPN configurations: \(error.localizedDescription)")
        }
        refreshStatus()
    }

    private func pick(_ managers: [NETunnelProviderManager]) -> NETunnelProviderManager? {
        let ours = managers.first { candidate in
            (candidate.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == tunnelBundleIdentifier
        }
        return ours ?? managers.first
    }

    /// The configuration, created or brought up to date and saved, then loaded
    /// again as the system requires before a start.
    private func preparedManager() async throws -> NETunnelProviderManager {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = pick(managers) ?? NETunnelProviderManager()
        let existing = manager.protocolConfiguration as? NETunnelProviderProtocol
        let upToDate = existing?.providerBundleIdentifier == tunnelBundleIdentifier &&
            existing?.serverAddress == "Mythaia" && manager.isEnabled
        if !upToDate {
            let proto = existing ?? NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleIdentifier
            proto.serverAddress = "Mythaia"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Mythaia Pro"
            manager.isEnabled = true
            try await manager.saveToPreferences()
        }
        try await manager.loadFromPreferences()
        self.manager = manager
        return manager
    }

    // MARK: Start and stop

    /// Saves `options` for the tunnel and starts it.
    func start(_ options: TunnelStartOptions) async {
        MythaiaStore.shared.saveTunnelStart(options)
        lastConnectFailed = false
        let manager: NETunnelProviderManager
        do {
            manager = try await preparedManager()
        } catch {
            errors.send(setupFailureMessage(error))
            refreshStatus()
            return
        }
        do {
            reachedConnected = false
            status = .connecting
            // The full options are in the store; the copy passed along leaves
            // the Auto group out, which can be large.
            var passed = options
            passed.groupConfigurations = []
            try manager.connection.startVPNTunnel(options: try? passed.startOptions())
        } catch {
            status = .disconnected
            lastConnectFailed = true
            errors.send(error.localizedDescription)
            updateStatsLoop()
        }
    }

    func stop() {
        pendingRestart = nil
        manager?.connection.stopVPNTunnel()
    }

    /// Hands a running tunnel new start options (another server, new
    /// routing settings, another Auto group): they are saved, so a restart by
    /// the system comes up the same way, and the tunnel is told to re-read
    /// them. A tunnel that does not take the message is restarted instead.
    func reload(_ options: TunnelStartOptions) async {
        MythaiaStore.shared.saveTunnelStart(options)
        guard status == .connected || status == .reasserting else { return }
        let reply = await request(.reload)
        if reply?.ok != true {
            if let message = reply?.error { Log.warning("The tunnel did not reload: \(message)") }
            restart(options)
        }
    }

    /// Stops the tunnel and starts it again with `options` once it is down.
    func restart(_ options: TunnelStartOptions) {
        guard let manager = manager, status != .disconnected else {
            Task { await self.start(options) }
            return
        }
        pendingRestart = options
        manager.connection.stopVPNTunnel()
    }

    // MARK: Status

    private func refreshStatus() {
        guard let connection = manager?.connection else {
            status = .disconnected
            connectedDate = nil
            updateStatsLoop()
            return
        }
        let previous = status
        let next = map(connection.status)
        status = next
        connectedDate = next == .connected ? connection.connectedDate : nil

        if next == .connected {
            reachedConnected = true
            lastConnectFailed = false
            if previous != .connected {
                // Who runs Auto: the app while it is on screen, the tunnel otherwise.
                let foreground = isForeground
                Task { _ = await self.send(.appActive(foreground)) }
            }
        }
        if next == .disconnected && previous != .disconnected {
            if let pending = pendingRestart {
                pendingRestart = nil
                Task { await self.start(pending) }
            } else if (previous == .connecting || previous == .reasserting) && !reachedConnected {
                lastConnectFailed = true
                fetchDisconnectReason(connection)
            }
            reachedConnected = false
            resetStats()
        }
        updateStatsLoop()
    }

    private func map(_ status: NEVPNStatus) -> TunnelStatus {
        switch status {
        case .connecting: return .connecting
        case .connected: return .connected
        case .reasserting: return .reasserting
        case .disconnecting: return .disconnecting
        case .invalid, .disconnected: return .disconnected
        @unknown default: return .disconnected
        }
    }

    /// Why the last start ended, as the system or the tunnel put it.
    private func fetchDisconnectReason(_ connection: NEVPNConnection) {
        let errors = self.errors
        connection.fetchLastDisconnectError { error in
            guard let error = error else { return }
            let message = error.localizedDescription
            DispatchQueue.main.async {
                errors.send(message)
            }
        }
    }

    private func setupFailureMessage(_ error: Error) -> String {
        let base = String(localized: "The VPN configuration could not be set up.")
        let hint = String(localized: "A build without the Network Extension entitlement (unsigned, or running in the simulator) cannot create one; the request may also have been declined.")
        return base + " " + hint + "\n\n" + error.localizedDescription
    }

    // MARK: Foreground and stats

    /// The app came to the front or left it. The tunnel runs Auto on its
    /// own while the app is away, and leaves it to the app while it is here.
    func setForeground(_ foreground: Bool) {
        isForeground = foreground
        if foreground {
            Task { await self.loadExisting() }
        }
        if status == .connected || status == .reasserting {
            Task { _ = await self.send(.appActive(foreground)) }
        }
        updateStatsLoop()
    }

    private func updateStatsLoop() {
        let wanted = isForeground && status == .connected
        if !wanted {
            statsTask?.cancel()
            statsTask = nil
            return
        }
        if statsTask != nil { return }
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { return }
                await self.fetchStats()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    private func fetchStats() async {
        guard let reply = await request(.stats), let stats = reply.stats else { return }
        uploadBytes = stats.uploadBytes
        downloadBytes = stats.downloadBytes
        uploadSpeed = stats.uploadSpeed
        downloadSpeed = stats.downloadSpeed
    }

    private func resetStats() {
        uploadBytes = 0
        downloadBytes = 0
        uploadSpeed = 0
        downloadSpeed = 0
    }

    /// The tunnel's recent log lines; nil when no tunnel answers.
    func fetchLogTail() async -> [String]? {
        guard status != .disconnected else { return nil }
        guard let reply = await request(.logTail) else { return nil }
        return reply.logLines ?? []
    }

    /// The server the running tunnel uses now (Auto in the tunnel may have
    /// moved it while the app was away); nil when no tunnel answers.
    func fetchLiveConfigurationId() async -> UUID? {
        guard status == .connected else { return nil }
        return await request(.ping)?.configurationId
    }

    // MARK: Provider messages

    /// Sends `message` and decodes the tunnel's reply; nil when the tunnel
    /// did not answer, or answered with something unreadable.
    func request(_ message: TunnelMessage) async -> TunnelReply? {
        let result = await send(message)
        guard case .reply(let maybeData) = result, let data = maybeData else { return nil }
        return try? TunnelReply.decode(data)
    }

    /// Sends `message` to the running tunnel. A tunnel that does not answer
    /// within five seconds counts as a failure.
    func send(_ message: TunnelMessage) async -> SendResult {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = try? message.encoded() else { return .failed }
        return await withCheckedContinuation { (continuation: CheckedContinuation<SendResult, Never>) in
            let once = ResumeOnce(continuation)
            do {
                try session.sendProviderMessage(data) { response in
                    once.resume(.reply(response))
                }
            } catch {
                once.resume(.failed)
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                once.resume(.failed)
            }
        }
    }
}

/// Resumes a continuation at most once, whichever of the reply and the
/// timeout comes first.
private final class ResumeOnce<T> {
    private var continuation: CheckedContinuation<T, Never>?
    private let lock = NSLock()

    init(_ continuation: CheckedContinuation<T, Never>) {
        self.continuation = continuation
    }

    func resume(_ value: T) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
    }
}
