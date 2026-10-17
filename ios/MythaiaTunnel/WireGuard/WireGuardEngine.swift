import Foundation
import MythaiaKit
import Network
import NetworkExtension

/// A WireGuard or AmneziaWG interface: the tunnel's packets on one side, one
/// peer over UDP on the other.
///
/// WireGuard is a layer-3 outbound, not a stream proxy: whole IP packets go in
/// and come back out, so this runs *instead of* the packet stack and the local
/// proxy rather than underneath them, whatever the tunnel mode says. The
/// profile's own `[Interface]` and `AllowedIPs` shape the interface, which is
/// also why domain routing rules and Auto do not apply to it.
///
/// The protocol's decisions (handshake, rekey, keepalive, cookie, junk) are
/// `WireGuardTunnel`'s; this owns what it cannot: the socket, the interface,
/// the timer, the network path. Everything mutable lives on one serial queue,
/// the socket's callbacks included. Memory is bounded, since the extension is
/// killed past about 50 MB: one batch of packets is read at a time and only
/// while the socket keeps up, and writes to the interface are capped.
final class WireGuardEngine: @unchecked Sendable {

    /// What starting needs, worked out before the tunnel's own settings are
    /// applied: once they are, the system's DNS may be the profile's, reached
    /// through a tunnel that is not up yet.
    struct Plan {
        let configuration: ProxyConfiguration
        let config: WireGuardConfig
        /// The address the socket is opened to.
        let endpointAddress: String
        /// Every address the endpoint resolved to; all are kept off the routes.
        let endpointAddresses: [String]
        let interface: WireGuardInterfaceSettings

        /// Addresses, routes (`AllowedIPs`, the endpoint excluded), DNS and
        /// MTU from the profile. Both families are always set, as other
        /// WireGuard clients for this system do: a family the profile routes
        /// but has no address for is still captured, rather than leaving
        /// beside the tunnel.
        var networkSettings: NEPacketTunnelNetworkSettings {
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: endpointAddress)

            let ipv4 = NEIPv4Settings(
                addresses: interface.ipv4Addresses.map { $0.address },
                subnetMasks: interface.ipv4Addresses.map { $0.subnetMask }
            )
            ipv4.includedRoutes = interface.ipv4Routes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnetMask)
            }
            ipv4.excludedRoutes = interface.ipv4ExcludedRoutes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: $0.subnetMask)
            }
            settings.ipv4Settings = ipv4

            let ipv6 = NEIPv6Settings(
                addresses: interface.ipv6Addresses.map { $0.address },
                networkPrefixLengths: interface.ipv6Addresses.map { NSNumber(value: $0.prefixLength) }
            )
            ipv6.includedRoutes = interface.ipv6Routes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength))
            }
            ipv6.excludedRoutes = interface.ipv6ExcludedRoutes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefixLength))
            }
            settings.ipv6Settings = ipv6

            if !interface.dnsServers.isEmpty {
                let dns = NEDNSSettings(servers: interface.dnsServers)
                dns.searchDomains = interface.searchDomains
                // Every name goes to the profile's resolvers, as wg-quick
                // makes them the system's.
                dns.matchDomains = [""]
                settings.dnsSettings = dns
            }

            settings.mtu = NSNumber(value: interface.mtu)
            return settings
        }
    }

    /// A system lookup that takes longer than this is abandoned for the
    /// public resolvers: on a restart the old settings' DNS may point into a
    /// stack that no longer answers.
    private static let resolveTimeout: Double = 4
    /// Packets decrypted for the interface and not yet written; past this
    /// they are dropped (TCP sends them again).
    private static let maxPendingWrites = 512
    /// Bytes handed to the socket and not yet sent above which no more
    /// packets are read from the interface, and below which reading resumes.
    private static let uplinkHighWater = 2 * 1024 * 1024
    private static let uplinkLowWater = 512 * 1024

    private static let protocolV4 = NSNumber(value: AF_INET)
    private static let protocolV6 = NSNumber(value: AF_INET6)

    private let queue = DispatchQueue(label: "com.mythaia.tunnel.wireguard", qos: .userInitiated)
    private let packetFlow: NEPacketTunnelFlow
    private let tunnel: WireGuardTunnel
    private let config: WireGuardConfig
    private let counter = TunTrafficCounter(startingFrom: TrafficStats())
    private let resolver = TunResolver()

    // Readable from any thread, behind `stateLock`.
    private let stateLock = NSLock()
    private var lockedConfiguration: ProxyConfiguration
    private var failureHandler: ((String) -> Void)?
    private var restartHandler: ((ProxyConfiguration) -> Void)?

    // Everything below is touched on `queue` only.
    private var running = false
    private var endpointAddress: String
    private var connection: NWConnection?
    private var socketGeneration = 0
    private var timer: DispatchSourceTimer?
    private var lastTickAt: Double = 0
    private var pathMonitor: NWPathMonitor?
    private var lastPathKey: String?
    private var pathSatisfied = true
    private var resolving = false

    private var readGeneration = 0
    private var readPending = false
    private var readPaused = false
    private var inFlightBytes = 0

    private var pendingWrites: [Data] = []
    private var pendingProtocols: [NSNumber] = []
    private var flushScheduled = false
    private var droppedWrites = 0
    private var lastDropLog: Double = 0

    init(packetFlow: NEPacketTunnelFlow, plan: Plan) throws {
        self.packetFlow = packetFlow
        self.config = plan.config
        self.tunnel = try WireGuardTunnel(config: plan.config)
        self.endpointAddress = plan.endpointAddress
        self.lockedConfiguration = plan.configuration
    }

    // MARK: - Planning

    /// Reads the profile from `configuration` and resolves its endpoint.
    /// Throws with a message for the user when the profile cannot be used.
    static func plan(for configuration: ProxyConfiguration) async throws -> Plan {
        guard let text = configuration.wireGuardConfig,
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw MythaiaError.invalidConfiguration("\(configuration.name) has no WireGuard configuration")
        }
        // A chain proxies a stream through each hop in turn; WireGuard takes
        // IP packets and has nowhere to put one. Dialling the peer anyway
        // would quietly skip every hop the user asked for.
        if let chain = configuration.chain, !chain.isEmpty {
            throw MythaiaError.unsupported("WireGuard as the exit of a proxy chain")
        }
        let config = try WireGuardConfig.parse(text)
        let host = config.peer.endpointHost
        let addresses = await resolve(host, resolver: TunResolver())
        guard let address = preferredAddress(addresses) else {
            throw MythaiaError.connectFailed("could not resolve the WireGuard endpoint \(host)")
        }
        let interface = try WireGuardInterfaceSettings.make(config, endpointAddresses: addresses)
        return Plan(
            configuration: configuration,
            config: config,
            endpointAddress: address,
            endpointAddresses: addresses,
            interface: interface
        )
    }

    /// The endpoint's addresses: the system resolver first (it knows the
    /// local network's view, split-horizon names included), then the public
    /// resolvers over direct UDP when it answers nothing in time.
    static func resolve(_ host: String, resolver: TunResolver) async -> [String] {
        if let bytes = TunAddress.parse(host), let text = TunAddress.text(bytes) {
            return [text]
        }
        var addresses = await systemResolve(host, timeout: resolveTimeout).filter { !FakeIpPool.isFakeIp($0) }
        if addresses.isEmpty {
            let v4 = await resolver.upstreamLookup(host, type: DnsMessage.typeA)
            let v6 = await resolver.upstreamLookup(host, type: DnsMessage.typeAAAA)
            addresses = v4 + v6
        }
        return addresses
    }

    /// IPv4 first: it is what most peers listen on, and on an IPv6-only
    /// network the system still reaches it through NAT64.
    static func preferredAddress(_ addresses: [String]) -> String? {
        addresses.first { TunAddress.parse($0)?.count == 4 } ?? addresses.first
    }

    private static func systemResolve(_ host: String, timeout: Double) async -> [String] {
        await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            let gate = ResolveGate(continuation)
            DispatchQueue.global(qos: .userInitiated).async {
                gate.finish(TunResolver.resolveWithSystem(host))
            }
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + timeout) {
                gate.finish([])
            }
        }
    }

    // MARK: - Callbacks

    /// Raised when the peer has not completed a handshake for too long. Left
    /// running, the tunnel would keep its routes while carrying nothing:
    /// every app times out with the system still showing it connected.
    var onFailure: ((String) -> Void)? {
        get { withState { failureHandler } }
        set { withState { failureHandler = newValue } }
    }

    /// Raised when the tunnel is asked to move to a server it cannot carry in
    /// place; the provider rebuilds the tunnel for it.
    var onRestartNeeded: ((ProxyConfiguration) -> Void)? {
        get { withState { restartHandler } }
        set { withState { restartHandler = newValue } }
    }

    // MARK: - Lifecycle

    /// Opens the socket and starts the timer and the reads. The first
    /// handshake goes out at once: waiting a tick would leave the user looking
    /// at a connected tunnel that carries nothing for a second.
    func start() {
        queue.async {
            guard !self.running else { return }
            self.running = true
            self.openSocket()
            self.startPathMonitor()
            self.startTimer()
            self.readGeneration += 1
            self.readPackets(generation: self.readGeneration)
            Log.info("[WG] Started, peer \(self.config.peer.endpointHost):\(self.config.peer.endpointPort) at \(self.endpointAddress), MTU \(self.config.mtu), AmneziaWG \(self.config.amnezia.isEnabled ? "on" : "off")")
            self.tick()
        }
    }

    /// Closes everything; `done` runs on the engine's queue once it has.
    func shutdown(_ done: @escaping () -> Void) {
        queue.async {
            if self.running {
                self.running = false
                self.timer?.cancel()
                self.timer = nil
                self.pathMonitor?.cancel()
                self.pathMonitor = nil
                self.closeSocket()
                self.readGeneration += 1
                self.pendingWrites.removeAll()
                self.pendingProtocols.removeAll()
                Log.info("[WG] Stopped")
            }
            done()
        }
    }

    // MARK: - Socket

    /// A UDP socket to the endpoint. The extension's own sockets never enter
    /// its tunnel, so the peer is reached over the physical network even
    /// when `AllowedIPs` covers its address.
    private func openSocket() {
        closeSocket()
        guard let port = NWEndpoint.Port(rawValue: UInt16(clamping: config.peer.endpointPort)) else { return }
        let parameters = NWParameters(dtls: nil, udp: NWProtocolUDP.Options())
        // The proxy-mode tunnel points the system proxy at a listener of its
        // own; nothing of this one should ever be sent that way.
        parameters.preferNoProxies = true
        let generation = socketGeneration
        let socket = NWConnection(host: NWEndpoint.Host(endpointAddress), port: port, using: parameters)
        socket.stateUpdateHandler = { [weak self] state in
            self?.socketStateChanged(state, generation: generation)
        }
        connection = socket
        socket.start(queue: queue)
        receive(on: socket, generation: generation)
        resumeReadsIfDrained()
    }

    private func closeSocket() {
        socketGeneration += 1
        inFlightBytes = 0
        if let old = connection {
            old.stateUpdateHandler = nil
            old.cancel()
        }
        connection = nil
    }

    private func socketStateChanged(_ state: NWConnection.State, generation: Int) {
        guard running, generation == socketGeneration else { return }
        switch state {
        case .ready:
            Log.debug("[WG] Socket ready")
        case .waiting(let error):
            // No path for now; sends wait for one, and the path monitor says
            // when it comes back.
            Log.debug("[WG] Socket waiting: \(error)")
        case .failed(let error):
            Log.warning("[WG] Socket failed: \(error); reopening")
            // After a moment, so a dead path does not turn into a spin.
            queue.asyncAfter(deadline: .now() + 1) { [weak self] in
                guard let self, self.running, generation == self.socketGeneration else { return }
                self.openSocket()
            }
        default:
            break
        }
    }

    private func receive(on socket: NWConnection, generation: Int) {
        socket.receiveMessage { [weak self] content, _, _, error in
            guard let self, self.running, generation == self.socketGeneration else { return }
            if let content, !content.isEmpty {
                self.handleDatagram(content)
            }
            if let error {
                // A connected UDP socket reports an ICMP error from the path
                // as a failed read without failing; keep reading after a
                // pause. A real failure reopens through the state handler,
                // which retires this generation.
                Log.debug("[WG] Socket read failed: \(error)")
                self.queue.asyncAfter(deadline: .now() + 0.2) { [weak self] in
                    guard let self, self.running, generation == self.socketGeneration else { return }
                    self.receive(on: socket, generation: generation)
                }
                return
            }
            self.receive(on: socket, generation: generation)
        }
    }

    private func send(_ datagrams: [Data]) {
        guard !datagrams.isEmpty, let socket = connection else { return }
        let generation = socketGeneration
        socket.batch {
            for datagram in datagrams {
                let size = datagram.count
                self.inFlightBytes += size
                socket.send(content: datagram, completion: .contentProcessed { [weak self] error in
                    self?.sendCompleted(size, generation: generation, error: error)
                })
            }
        }
    }

    private func sendCompleted(_ size: Int, generation: Int, error: NWError?) {
        guard generation == socketGeneration else { return }
        inFlightBytes = max(0, inFlightBytes - size)
        if let error, running {
            Log.debug("[WG] Send failed: \(error)")
        }
        resumeReadsIfDrained()
    }

    // MARK: - Packets

    private func handleDatagram(_ datagram: Data) {
        let inbound = tunnel.receive(datagram)
        send(inbound.datagrams)
        if inbound.established {
            Log.info("[WG] Session established with \(config.peer.endpointHost)")
        }
        if let packet = inbound.packet {
            enqueueWrite(packet)
        }
    }

    /// Reads one batch, seals it, hands it to the socket, and only then asks
    /// for the next — unless the socket is behind, in which case reading
    /// waits for it to drain.
    private func readPackets(generation: Int) {
        guard !readPending else { return }
        readPending = true
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.queue.async {
                self.readPending = false
                guard self.running, generation == self.readGeneration else { return }
                self.outbound(packets)
                if self.inFlightBytes >= WireGuardEngine.uplinkHighWater {
                    self.readPaused = true
                } else {
                    self.readPackets(generation: generation)
                }
            }
        }
    }

    private func resumeReadsIfDrained() {
        guard running, readPaused, inFlightBytes <= WireGuardEngine.uplinkLowWater else { return }
        readPaused = false
        readPackets(generation: readGeneration)
    }

    private func outbound(_ packets: [Data]) {
        var datagrams: [Data] = []
        datagrams.reserveCapacity(packets.count)
        var bytes = 0
        for packet in packets where !packet.isEmpty {
            // Without a session the packet is dropped: TCP sends it again,
            // and a queue here would only delay what follows the handshake.
            guard let sealed = tunnel.encapsulate(packet) else { continue }
            datagrams.append(sealed)
            bytes += packet.count
        }
        counter.addUp(bytes)
        send(datagrams)
    }

    private func enqueueWrite(_ packet: Data) {
        if pendingWrites.count >= WireGuardEngine.maxPendingWrites {
            droppedWrites += 1
            let now = TunClock.now()
            if now - lastDropLog > 5 {
                lastDropLog = now
                Log.warning("[WG] Interface write queue full; dropped \(droppedWrites) packets so far")
            }
            return
        }
        pendingWrites.append(packet)
        let version = packet.first.map { $0 >> 4 } ?? 4
        pendingProtocols.append(version == 6 ? WireGuardEngine.protocolV6 : WireGuardEngine.protocolV4)
        if !flushScheduled {
            flushScheduled = true
            queue.async { [weak self] in
                self?.flushWrites()
            }
        }
    }

    private func flushWrites() {
        flushScheduled = false
        guard running, !pendingWrites.isEmpty else { return }
        let packets = pendingWrites
        let protocols = pendingProtocols
        pendingWrites.removeAll(keepingCapacity: true)
        pendingProtocols.removeAll(keepingCapacity: true)
        var bytes = 0
        for packet in packets {
            bytes += packet.count
        }
        if packetFlow.writePackets(packets, withProtocols: protocols) {
            counter.addDown(bytes)
        } else {
            Log.debug("[WG] Interface refused \(packets.count) packets")
        }
    }

    // MARK: - Timer

    private func startTimer() {
        let source = DispatchSource.makeTimerSource(queue: queue)
        let interval = WireGuardTunnel.tickInterval
        source.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(250))
        source.setEventHandler { [weak self] in
            self?.tick()
        }
        source.resume()
        timer = source
        lastTickAt = TunClock.now()
    }

    private func tick() {
        guard running else { return }
        let now = TunClock.now()
        // The timer did not fire for a long while: the device slept, and the
        // socket and the session may both be gone with the radio's state.
        if now - lastTickAt >= TunConstants.wakeRestartThresholdSec {
            handleNetworkPathChange("device wake")
        }
        lastTickAt = now

        // With no network at all, an unanswered handshake says nothing about
        // the peer; the attempts resume, from scratch, when a path returns.
        guard pathSatisfied else { return }

        let result = tunnel.tick()
        send(result.datagrams)
        if result.resolveEndpoint {
            resolveEndpointAgain()
        }
        if let failure = result.failure {
            Log.error("[WG] Could not reach the peer: \(failure)")
            onFailure?(failure)
        }
    }

    // MARK: - Network changes

    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.pathChanged(path)
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private func pathChanged(_ path: Network.NWPath) {
        guard running else { return }
        let satisfied = path.status == .satisfied
        // The interface the extension's own traffic leaves by; the tunnel's
        // own interface is not one of those.
        let key = path.availableInterfaces.first { $0.type != .other && $0.type != .loopback }?.name ?? ""
        let previousKey = lastPathKey
        let wasSatisfied = pathSatisfied
        lastPathKey = key
        pathSatisfied = satisfied
        guard let previousKey else { return }

        if !satisfied {
            if wasSatisfied { handleNetworkPathChange("network path unavailable") }
            return
        }
        if !wasSatisfied {
            handleNetworkPathChange("network path restored")
            tick()
            return
        }
        if key != previousKey {
            handleNetworkPathChange("network interface change")
            tick()
        }
    }

    /// Re-establishes the tunnel after the network underneath it changed.
    ///
    /// The socket was bound on a path that no longer exists, and the name may
    /// resolve somewhere else on the new one, so both are replaced and the
    /// session dropped rather than waiting out a rekey that would go out of
    /// the wrong interface.
    private func handleNetworkPathChange(_ reason: String) {
        guard running else { return }
        Log.info("[WG] Network path changed (\(reason)), re-establishing")
        tunnel.networkChanged()
        openSocket()
        resolveEndpointAgain()
    }

    /// Looks the endpoint's name up again, and moves the socket if it now
    /// points elsewhere. The old address stays in use when nothing answers.
    private func resolveEndpointAgain() {
        let host = config.peer.endpointHost
        guard !resolving, !TunAddress.isLiteral(host) else { return }
        resolving = true
        let resolver = self.resolver
        Task { [weak self] in
            let addresses = await WireGuardEngine.resolve(host, resolver: resolver)
            guard let self else { return }
            self.queue.async {
                self.resolving = false
                guard self.running, let next = WireGuardEngine.preferredAddress(addresses), next != self.endpointAddress else {
                    return
                }
                Log.info("[WG] \(host) now resolves to \(next)")
                self.endpointAddress = next
                self.openSocket()
            }
        }
    }

    // MARK: - State

    @discardableResult
    private func withState<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }
}

extension WireGuardEngine: TunnelEngine {
    var currentConfiguration: ProxyConfiguration? {
        withState { lockedConfiguration }
    }

    var trafficStats: TrafficStats {
        counter.snapshot(now: TunClock.now())
    }

    var listeningPort: UInt16? { nil }

    /// The same profile again (renamed, or picked once more) changes nothing
    /// on the wire. Anything else — another WireGuard profile, with its own
    /// addresses and routes, or a stream server, which needs the packet
    /// stack — cannot be carried by this interface, so the provider rebuilds
    /// the tunnel for it, as the Android service rebuilds its VPN.
    func use(_ configuration: ProxyConfiguration) {
        let current = currentConfiguration
        if configuration.outboundProtocol.isLayer3,
           (configuration.chain ?? []).isEmpty,
           configuration.wireGuardConfig == current?.wireGuardConfig {
            withState { lockedConfiguration = configuration }
            return
        }
        guard let restart = onRestartNeeded else {
            Log.warning("[WG] \(configuration.name) cannot replace a running WireGuard interface; reconnect to use it")
            return
        }
        Log.info("[WG] Switching to \(configuration.name) rebuilds the tunnel")
        restart(configuration)
    }

    /// Routing rules decide per flow, and a layer-3 interface has no flows:
    /// the profile's `AllowedIPs` are its only split.
    func route(with router: Router) {}
}

/// Resumes a lookup exactly once, with the answer or with nothing at the
/// deadline, whichever comes first; a late answer is dropped.
private final class ResolveGate: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<[String], Never>?

    init(_ continuation: CheckedContinuation<[String], Never>) {
        self.continuation = continuation
    }

    func finish(_ addresses: [String]) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: addresses)
    }
}
