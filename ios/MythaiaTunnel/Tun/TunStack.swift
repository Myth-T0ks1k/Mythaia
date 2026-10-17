import Foundation
import MythaiaKit
import NetworkExtension

/// The knobs the stack reads on every packet; replaceable while it runs.
struct TunSettings {
    /// Answer AAAA queries with fake IPv6 addresses; otherwise NODATA keeps
    /// clients on IPv4, the range that is sure to be routed into the tunnel.
    var ipv6Dns: Bool
    /// Refuse UDP/443 with ICMP port unreachable, so HTTP/3 clients fall back
    /// to HTTP/2 over TCP, which the proxies carry better.
    var blockQuic: Bool
    /// When false, DDR (RFC 9462) discovery is refused, so the system cannot
    /// move its DNS to DoH or DoT and away from port 53.
    var encryptedDnsEnabled: Bool
    /// Names (lowercase) whose A/AAAA queries get their real addresses rather
    /// than fake IPs; the proxy servers are always treated so. For names that
    /// must never enter the tunnel.
    var realAnswerDomains: Set<String>
    /// The resolvers the tunnel asks itself, over direct UDP, when it needs a
    /// real address the system resolver will not give.
    var upstreamDnsServers: [String]

    init(
        ipv6Dns: Bool = false,
        blockQuic: Bool = true,
        encryptedDnsEnabled: Bool = false,
        realAnswerDomains: Set<String> = [],
        upstreamDnsServers: [String] = TunResolver.defaultUpstreamServers
    ) {
        self.ipv6Dns = ipv6Dns
        self.blockQuic = blockQuic
        self.encryptedDnsEnabled = encryptedDnsEnabled
        self.realAnswerDomains = realAnswerDomains
        self.upstreamDnsServers = upstreamDnsServers
    }
}

/// The packet-level tunnel: every TCP connection and UDP flow of the device
/// comes in through `NEPacketTunnelFlow`, lwIP reassembles the packets into
/// connections, and each one is routed by `Router` and dialled through
/// `Dialer` (the server, or straight to the destination). DNS on port 53 is
/// answered here from the fake-IP pool, so a connection arrives carrying a
/// domain name the router and the proxy can use.
///
/// lwIP is built with NO_SYS=1 and is not thread-safe: every lwIP call, every
/// lwIP callback and all of this class's flow state live on `lwipQueue`, one
/// serial queue for the whole process. The public methods may be called from
/// any thread; they hop onto it.
///
/// Memory is bounded throughout, since the extension is killed past about
/// 50 MB: packets are read one batch at a time, each connection's buffers
/// are capped and acknowledged only as they drain, and the stack keeps
/// budgets for the downlink backlog and the queued datagrams of all
/// connections together.
final class TunStack: @unchecked Sendable {

    /// The one queue every lwIP call runs on.
    static let lwipQueue = DispatchQueue(label: "com.mythaia.tunnel.lwip", qos: .userInitiated)

    /// The stack lwIP's callbacks are delivered to. The callbacks are C
    /// functions and cannot capture anything, so they find the stack here.
    /// Only read and written on `lwipQueue`.
    fileprivate static weak var current: TunStack?
    private static var callbacksInstalled = false

    private static let protocolV4 = NSNumber(value: AF_INET)
    private static let protocolV6 = NSNumber(value: AF_INET6)

    let queue: DispatchQueue
    let resolver = TunResolver()
    let fakeIpPool = FakeIpPool()

    private let packetFlow: NEPacketTunnelFlow
    private let counter: TunTrafficCounter

    // Readable from any thread, behind `stateLock`.
    private let stateLock = NSLock()
    private var lockedRouter: Router
    private var lockedConfiguration: ProxyConfiguration?
    private var lockedSettings = TunSettings()
    private var lockedRunning = false
    private var failureHandler: ((Int) -> Void)?
    private var consecutiveProxyFailures = 0

    // Everything below is touched on `queue` only.
    private var running = false
    /// True while the stack aborts every PCB on purpose (stop, switch,
    /// restart), so the aborts are not logged as failures.
    private(set) var isTearingDown = false
    private var tcpConnections: [Int: LwipTcpConnection] = [:]
    private var udpFlows: [String: LwipUdpFlow] = [:]
    private var nextConnId = 1
    /// Every proxy server address (names and resolved IPs), normalized;
    /// flows to them never go through the proxy.
    private var proxyServerAddresses: Set<String> = []

    private var tickTimer: DispatchSourceTimer?
    private var tickIntervalMs = 0
    private var lastUdpCleanup: Double = 0

    private var outputPackets: [Data] = []
    private var outputProtocols: [NSNumber] = []
    private var outputFlushScheduled = false
    private var outputWriteInFlight = false
    private var droppedOutputPackets = 0
    private var lastOutputDropLog: Double = 0

    private var downlinkBacklog = 0
    private var downlinkWaiters: [Int] = []
    private var downlinkWaiterSet = Set<Int>()
    private var udpQueuedBytes = 0
    private var realAnswersInFlight = 0
    private var readGeneration = 0
    private var lastTcpCapWarn: Double = 0

    /// `stats` is where the counters start, so switching from the
    /// proxy-settings tunnel to this one keeps the totals the app shows.
    /// Call `switchConfiguration(_:)` (or use the other initializer) before
    /// flows can be dialled: until there is a server, new connections are
    /// refused, though DNS is answered.
    init(packetFlow: NEPacketTunnelFlow, router: Router, stats: TrafficStats) {
        self.packetFlow = packetFlow
        self.queue = TunStack.lwipQueue
        self.lockedRouter = router
        self.counter = TunTrafficCounter(startingFrom: stats)
    }

    convenience init(
        packetFlow: NEPacketTunnelFlow,
        router: Router,
        stats: TrafficStats,
        configuration: ProxyConfiguration,
        settings: TunSettings = TunSettings()
    ) {
        self.init(packetFlow: packetFlow, router: router, stats: stats)
        lockedConfiguration = configuration
        lockedSettings = settings
        resolver.upstreamServers = settings.upstreamDnsServers
    }

    // MARK: - Public state

    /// The router new flows are decided by. Replacing it changes the route
    /// of new flows only; open ones finish as they were (`restart()` re-routes
    /// them too).
    var router: Router {
        get { withState { lockedRouter } }
        set { withState { lockedRouter = newValue } }
    }

    /// The server flows are dialled through.
    var configuration: ProxyConfiguration? {
        withState { lockedConfiguration }
    }

    var settings: TunSettings {
        withState { lockedSettings }
    }

    var isRunning: Bool {
        withState { lockedRunning }
    }

    /// Bytes through the interface (up: read from it, down: written to it),
    /// speeds, and the open TCP connections.
    var stats: TrafficStats {
        counter.snapshot(now: TunClock.now())
    }

    /// Called after each failed dial through the server with the number of
    /// failures in a row; a successful dial resets the count. Auto uses it to
    /// notice a server that stopped answering. Called off the lwIP queue.
    var onProxyFailures: ((Int) -> Void)? {
        get { withState { failureHandler } }
        set { withState { failureHandler = newValue } }
    }

    // MARK: - Lifecycle

    /// Brings lwIP up and starts reading packets. Any thread.
    func start() {
        queue.async {
            if self.running { return }
            self.running = true
            self.setRunningFlag(true)
            self.bringUp()
            self.readGeneration += 1
            self.readPackets(generation: self.readGeneration)
            let settings = self.settings
            let name = self.configuration?.name ?? "no server yet"
            Log.info("Packet tunnel started for \(name), ipv6Dns=\(settings.ipv6Dns), blockQuic=\(settings.blockQuic)")
        }
    }

    /// Tears everything down; every flow is closed and lwIP shut. Returns at
    /// once; `completion` runs on the lwIP queue when it is done, and the
    /// provider should finish stopping from there.
    func stop(completion: (() -> Void)? = nil) {
        queue.async {
            if self.running {
                self.running = false
                self.setRunningFlag(false)
                self.shutdownInternal()
                // The RSTs of the aborted connections, so apps notice at once.
                self.flushOutputPackets()
                Log.info("Packet tunnel stopped")
            }
            self.readGeneration += 1
            self.fakeIpPool.reset()
            self.resolver.clear()
            self.outputPackets.removeAll()
            self.outputProtocols.removeAll()
            self.outputFlushScheduled = false
            if TunStack.current === self {
                TunStack.current = nil
            }
            completion?()
        }
    }

    /// Switches the server; every open flow is re-established through it
    /// (its connection is reset, and apps reconnect).
    func switchConfiguration(_ configuration: ProxyConfiguration) {
        let previous: ProxyConfiguration? = withState { () -> ProxyConfiguration? in
            let old = lockedConfiguration
            lockedConfiguration = configuration
            consecutiveProxyFailures = 0
            return old
        }
        queue.async {
            guard self.running else { return }
            if previous == nil {
                // Nothing was dialled without a server; nothing to re-establish.
                self.seedProxyServerAddresses(configuration)
                return
            }
            Log.info("Switching to \(configuration.name); reconnecting active connections")
            self.shutdownInternal()
            self.bringUp()
            self.flushOutputPackets()
        }
    }

    /// Resets every flow so it is routed again under the current router and
    /// server: after a change of routing rules, or on wake after a long
    /// sleep (`TunConstants.wakeRestartThresholdSec`).
    func restart() {
        queue.async {
            guard self.running, let configuration = self.configuration else { return }
            Log.info("Reconnecting active connections through \(configuration.name)")
            self.shutdownInternal()
            self.bringUp()
            self.flushOutputPackets()
        }
    }

    /// New per-packet knobs; they apply from the next packet, no flow drops.
    func updateSettings(_ settings: TunSettings) {
        withState { lockedSettings = settings }
        resolver.upstreamServers = settings.upstreamDnsServers
    }

    /// Addresses of the servers resolved before the tunnel's DNS changed
    /// (`TunNetworkSettings.resolveServers`): answers for their names come
    /// from here, and flows to them never go through the proxy.
    func seedServerAddresses(_ servers: [String: [String]]) {
        for (name, addresses) in servers {
            resolver.seed(name, addresses: addresses)
        }
        queue.async {
            for (name, addresses) in servers {
                self.proxyServerAddresses.insert(TunStack.normalizedHost(name))
                for address in addresses {
                    self.proxyServerAddresses.insert(TunStack.normalizedHost(address))
                }
            }
        }
    }

    // MARK: - Bring-up and teardown (on the queue)

    private func bringUp() {
        TunStack.installCallbacks()
        TunStack.current = self
        if let configuration = configuration {
            seedProxyServerAddresses(configuration)
        }
        lwip_bridge_init()
        startTicking()
    }

    /// Closes every flow and shuts lwIP; leaves `running` alone.
    private func shutdownInternal() {
        stopTicking()
        outputFlushScheduled = false

        let flows = Array(udpFlows.values)
        udpFlows.removeAll()
        for flow in flows {
            flow.close()
        }

        // lwip_bridge_shutdown aborts every PCB; each abort fires the error
        // callback, which releases the proxy side, and sends the RST that
        // makes the app drop the old connection and retry.
        let tcpCount = tcpConnections.count
        isTearingDown = true
        lwip_bridge_shutdown()
        isTearingDown = false

        // Whatever lwIP did not report (nothing, normally) is released too.
        let remaining = Array(tcpConnections.values)
        tcpConnections.removeAll()
        for connection in remaining where !connection.closed {
            connection.handleError(-1)
        }
        downlinkBacklog = 0
        downlinkWaiters.removeAll()
        downlinkWaiterSet.removeAll()
        udpQueuedBytes = 0
        counter.setConnections(0)
        Log.debug("Packet stack shut down, closed \(flows.count) UDP flows and \(tcpCount) TCP connections")
    }

    // MARK: - Packets in

    /// Reads one batch, feeds it to lwIP on the queue, and only then asks for
    /// the next: the read side never holds more than one batch.
    private func readPackets(generation: Int) {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            self.queue.async {
                guard self.running, self.readGeneration == generation else { return }
                self.input(packets)
                self.readPackets(generation: generation)
            }
        }
    }

    private func input(_ packets: [Data]) {
        var bytes = 0
        for packet in packets {
            if packet.isEmpty { continue }
            bytes += packet.count
            // lwIP references this buffer only for the length of the call
            // (no reassembly, no out-of-order queue); the callbacks copy out.
            packet.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Void in
                guard let base = raw.baseAddress else { return }
                lwip_bridge_input(base, Int32(raw.count))
            }
        }
        counter.addUp(bytes)
        if !outputPackets.isEmpty {
            flushOutputPackets()
        }
    }

    // MARK: - Packets out

    fileprivate func onOutput(_ packet: Data, isIpv6: Bool) {
        enqueueOutput(packet, isIpv6: isIpv6)
    }

    private func enqueueOutput(_ packet: Data, isIpv6: Bool) {
        if outputPackets.count >= TunConstants.maxPendingOutputPackets {
            droppedOutputPackets += 1
            let now = TunClock.now()
            if now - lastOutputDropLog > 5 {
                lastOutputDropLog = now
                Log.warning("Interface write queue full; dropped \(droppedOutputPackets) packets so far")
            }
            return
        }
        outputPackets.append(packet)
        outputProtocols.append(isIpv6 ? TunStack.protocolV6 : TunStack.protocolV4)
        scheduleOutputFlush()
    }

    private func scheduleOutputFlush() {
        if outputFlushScheduled { return }
        outputFlushScheduled = true
        queue.async { [weak self] in
            self?.flushOutputPackets()
        }
    }

    /// Pushes pending packets to the interface now; called by connections
    /// right after they hand lwIP data, so the packets leave in the same pass.
    func flushOutputInline() {
        flushOutputPackets()
    }

    /// Writes at most `tunnelMaxPacketsPerWrite` packets as one batch and
    /// schedules the rest, so one long burst cannot hold the queue.
    private func flushOutputPackets() {
        outputFlushScheduled = false
        if outputPackets.isEmpty { return }
        if outputWriteInFlight {
            scheduleOutputFlush()
            return
        }
        outputWriteInFlight = true
        let count = min(outputPackets.count, TunConstants.tunnelMaxPacketsPerWrite)
        let packets = Array(outputPackets[0..<count])
        let protocols = Array(outputProtocols[0..<count])
        outputPackets.removeFirst(count)
        outputProtocols.removeFirst(count)
        var bytes = 0
        for packet in packets {
            bytes += packet.count
        }
        if packetFlow.writePackets(packets, withProtocols: protocols) {
            counter.addDown(bytes)
        } else {
            Log.debug("Interface refused \(count) packets")
        }
        outputWriteInFlight = false
        if !outputPackets.isEmpty {
            scheduleOutputFlush()
        }
    }

    // MARK: - lwIP callbacks

    /// Points lwIP's callbacks at whichever stack is current. Done once per
    /// process: the functions never change, only `current` does.
    private static func installCallbacks() {
        if callbacksInstalled { return }
        callbacksInstalled = true

        lwip_bridge_set_output_fn({ data, length, isIpv6 in
            guard let data = data, length > 0, let stack = TunStack.current else { return }
            // lwIP reuses its buffer once the callback returns.
            let packet = Data(bytes: data, count: Int(length))
            stack.onOutput(packet, isIpv6: isIpv6 != 0)
        })

        lwip_bridge_set_tcp_accept_fn({ srcIp, srcPort, dstIp, dstPort, isIpv6, pcb in
            guard let srcIp = srcIp, let dstIp = dstIp, let pcb = pcb else { return nil }
            guard let stack = TunStack.current else { return nil }
            let width = isIpv6 != 0 ? 16 : 4
            let source = TunAddress.bytes(srcIp, count: width)
            let destination = TunAddress.bytes(dstIp, count: width)
            let connId = stack.onTcpAccept(
                srcIp: source,
                srcPort: srcPort,
                dstIp: destination,
                dstPort: dstPort,
                isIpv6: isIpv6 != 0,
                pcb: pcb
            )
            if connId == 0 { return nil }
            // The connection's id, not a pointer: a late callback for a
            // connection that is gone finds nothing instead of freed memory.
            return UnsafeMutableRawPointer(bitPattern: connId)
        })

        lwip_bridge_set_tcp_recv_fn({ conn, data, length in
            guard let stack = TunStack.current else { return }
            let connId = Int(bitPattern: conn)
            if let data = data, length > 0 {
                stack.onTcpRecv(connId: connId, data: TunAddress.bytes(data, count: Int(length)))
            } else {
                stack.onTcpRecv(connId: connId, data: nil)
            }
        })

        lwip_bridge_set_tcp_sent_fn({ conn, length in
            guard let stack = TunStack.current else { return }
            stack.onTcpSent(connId: Int(bitPattern: conn), length: Int(length))
        })

        lwip_bridge_set_tcp_err_fn({ conn, err in
            guard let stack = TunStack.current else { return }
            stack.onTcpErr(connId: Int(bitPattern: conn), err: err)
        })

        lwip_bridge_set_udp_recv_fn({ srcIp, srcPort, dstIp, dstPort, isIpv6, data, length in
            guard let srcIp = srcIp, let dstIp = dstIp, let data = data, length > 0 else { return }
            guard let stack = TunStack.current else { return }
            let width = isIpv6 != 0 ? 16 : 4
            let source = TunAddress.bytes(srcIp, count: width)
            let destination = TunAddress.bytes(dstIp, count: width)
            let payload = TunAddress.bytes(data, count: Int(length))
            stack.onUdpRecv(
                srcIp: source,
                srcPort: srcPort,
                dstIp: destination,
                dstPort: dstPort,
                isIpv6: isIpv6 != 0,
                payload: payload
            )
        })
    }

    // MARK: - TCP

    /// A new connection from an app; returns its id, or 0 to refuse it (lwIP
    /// then answers with a RST).
    fileprivate func onTcpAccept(
        srcIp: [UInt8],
        srcPort: UInt16,
        dstIp: [UInt8],
        dstPort: UInt16,
        isIpv6: Bool,
        pcb: UnsafeMutableRawPointer
    ) -> Int {
        guard running, let defaultConfiguration = configuration else { return 0 }
        if tcpConnections.count >= TunConstants.maxTcpConnections {
            warnTcpCapReached()
            return 0
        }

        let dstIpString = TunAddress.text(dstIp) ?? "?"
        guard let decision = decide(dstIp: dstIpString, dstIpBytes: dstIp, dstPort: dstPort, udp: false) else {
            return 0
        }

        let connId = nextConnId
        nextConnId += 1
        let connection = LwipTcpConnection(
            connId: connId,
            pcb: pcb,
            dstHost: decision.host,
            dstPort: dstPort,
            configuration: defaultConfiguration,
            forceBypass: decision.direct,
            // Only a real IP is worth sniffing: a fake IP names the domain already.
            sniffSNI: decision.realIp,
            stack: self
        )
        tcpConnections[connId] = connection
        counter.setConnections(tcpConnections.count)
        adjustTickInterval()
        connection.start()
        return connId
    }

    fileprivate func onTcpRecv(connId: Int, data: [UInt8]?) {
        guard let connection = tcpConnections[connId] else { return }
        if let data = data, !data.isEmpty {
            connection.handleReceivedData(data)
        } else {
            connection.handleRemoteClose()
        }
    }

    fileprivate func onTcpSent(connId: Int, length: Int) {
        tcpConnections[connId]?.handleSent(length)
    }

    fileprivate func onTcpErr(connId: Int, err: Int32) {
        guard let connection = tcpConnections.removeValue(forKey: connId) else { return }
        counter.setConnections(tcpConnections.count)
        connection.handleError(err)
    }

    /// A connection closed or aborted itself.
    func removeConnection(_ connId: Int) {
        if tcpConnections.removeValue(forKey: connId) != nil {
            counter.setConnections(tcpConnections.count)
        }
        downlinkWaiterSet.remove(connId)
    }

    private func warnTcpCapReached() {
        let now = TunClock.now()
        if now - lastTcpCapWarn < TunConstants.tcpCapWarnIntervalSec { return }
        lastTcpCapWarn = now
        Log.warning("Connection cap (\(TunConstants.maxTcpConnections)) reached; refusing new connections")
    }

    // MARK: - UDP

    fileprivate func onUdpRecv(
        srcIp: [UInt8],
        srcPort: UInt16,
        dstIp: [UInt8],
        dstPort: UInt16,
        isIpv6: Bool,
        payload: [UInt8]
    ) {
        guard running else { return }
        if dstPort == 53 && handleDnsQuery(payload, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, isIpv6: isIpv6) {
            return
        }

        if settings.blockQuic && dstPort == 443 {
            sendIcmpPortUnreachable(srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, isIpv6: isIpv6, udpPayloadLength: payload.count)
            return
        }

        let srcHost = TunAddress.text(srcIp) ?? "?"
        let dstIpString = TunAddress.text(dstIp) ?? "?"

        // An existing flow keeps the domain it resolved to even if the pool
        // has since reused the entry: a long-lived flow must not lose packets.
        let flowKey = "\(srcHost):\(srcPort)-\(dstIpString):\(dstPort)"
        if let flow = udpFlows[flowKey] {
            flow.handleReceivedData(Data(payload))
            return
        }

        guard let defaultConfiguration = configuration else { return }
        guard let decision = decide(dstIp: dstIpString, dstIpBytes: dstIp, dstPort: dstPort, udp: true) else {
            sendIcmpPortUnreachable(srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, isIpv6: isIpv6, udpPayloadLength: payload.count)
            return
        }
        if udpFlows.count >= TunConstants.maxUdpFlows {
            Log.debug("UDP flow cap (\(TunConstants.maxUdpFlows)) reached, dropping \(flowKey)")
            return
        }

        let flow = LwipUdpFlow(
            flowKey: flowKey,
            srcHost: srcHost,
            srcPort: srcPort,
            dstHost: decision.host,
            dstPort: dstPort,
            srcIpBytes: srcIp,
            dstIpBytes: dstIp,
            isIpv6: isIpv6,
            configuration: defaultConfiguration,
            forceBypass: decision.direct,
            stack: self
        )
        udpFlows[flowKey] = flow
        adjustTickInterval()
        flow.handleReceivedData(Data(payload))
    }

    /// A flow closed itself. Removed only if it is still the one under its
    /// key: a newer flow may have taken the key since.
    func removeUdpFlow(_ flow: LwipUdpFlow) {
        if let existing = udpFlows[flow.flowKey], existing === flow {
            udpFlows.removeValue(forKey: flow.flowKey)
        }
    }

    /// Sends one datagram to an app through lwIP.
    func sendUdp(from source: [UInt8], fromPort: UInt16, to destination: [UInt8], toPort: UInt16, isIpv6: Bool, payload: Data) {
        guard running, !payload.isEmpty, payload.count <= 65_507 else { return }
        let ipv6Flag: Int32 = isIpv6 ? 1 : 0
        source.withUnsafeBytes { (sourceBytes: UnsafeRawBufferPointer) -> Void in
            destination.withUnsafeBytes { (destinationBytes: UnsafeRawBufferPointer) -> Void in
                payload.withUnsafeBytes { (body: UnsafeRawBufferPointer) -> Void in
                    lwip_bridge_udp_sendto(
                        sourceBytes.baseAddress,
                        fromPort,
                        destinationBytes.baseAddress,
                        toPort,
                        ipv6Flag,
                        body.baseAddress,
                        Int32(body.count)
                    )
                }
            }
        }
    }

    private func closeIdleUdpFlows(now: Double) {
        var stale: [LwipUdpFlow] = []
        for flow in udpFlows.values where now - flow.lastActivity > TunConstants.udpIdleTimeoutSec {
            stale.append(flow)
        }
        for flow in stale {
            flow.close()
            udpFlows.removeValue(forKey: flow.flowKey)
        }
    }

    // MARK: - Routing

    private struct Decision {
        let host: String
        let direct: Bool
        /// The app connected to a real address, not a fake IP.
        let realIp: Bool
    }

    /// Nil means refuse: the router blocks it, or it is a fake IP the pool no
    /// longer knows (an answer from before a restart).
    private func decide(dstIp: String, dstIpBytes: [UInt8], dstPort: UInt16, udp: Bool) -> Decision? {
        var target = dstIp
        var realIp = true
        if FakeIpPool.isFakeIp(dstIp) {
            guard let domain = fakeIpPool.lookup(addressBytes: dstIpBytes) else {
                Log.debug("Stale fake IP \(dstIp):\(dstPort) (no pool entry)")
                return nil
            }
            target = domain
            realIp = false
        }
        switch route(target) {
        case .block:
            Log.debug("\(udp ? "UDP" : "TCP") to \(target):\(dstPort) blocked by rule")
            return nil
        case .direct:
            return Decision(host: target, direct: true, realIp: realIp)
        case .proxy:
            return Decision(host: target, direct: false, realIp: realIp)
        }
    }

    /// The router's verdict for `host`, a domain name or an IP literal.
    func route(_ host: String) -> RouteTarget {
        router.decide(host)
    }

    /// Whether `host` is a proxy server's own address, which must never go
    /// through the proxy (the dial would loop back to the server).
    func shouldBypass(_ host: String) -> Bool {
        proxyServerAddresses.contains(TunStack.normalizedHost(host))
    }

    private func isRealAnswerDomain(_ domain: String) -> Bool {
        if settings.realAnswerDomains.contains(domain) { return true }
        return proxyServerAddresses.contains(domain) && !TunAddress.isLiteral(domain)
    }

    private func seedProxyServerAddresses(_ configuration: ProxyConfiguration) {
        var names: [String] = []
        TunStack.collectServerNames(configuration, into: &names)
        for name in names {
            proxyServerAddresses.insert(name)
        }
        // Their addresses too, so a client that already holds a server's IP
        // (the app's latency tests) is also kept off the proxy.
        let domains = names.filter { !TunAddress.isLiteral($0) }
        if domains.isEmpty { return }
        let resolver = self.resolver
        let queue = self.queue
        Task {
            var found: [String] = []
            for domain in domains {
                let addresses = await resolver.serverAddresses(domain)
                found.append(contentsOf: addresses)
            }
            let resolved = found
            if resolved.isEmpty { return }
            queue.async {
                for address in resolved {
                    self.proxyServerAddresses.insert(TunStack.normalizedHost(address))
                }
            }
        }
    }

    /// The server's name and resolved IP, and those of every chain hop.
    static func collectServerNames(_ configuration: ProxyConfiguration, into names: inout [String]) {
        let name = normalizedHost(configuration.serverAddress)
        if !name.isEmpty && !names.contains(name) {
            names.append(name)
        }
        let resolvedIP: String? = configuration.resolvedIP
        if let resolved = resolvedIP {
            let ip = normalizedHost(resolved)
            if !ip.isEmpty && !names.contains(ip) {
                names.append(ip)
            }
        }
        for hop in configuration.chain ?? [] {
            collectServerNames(hop, into: &names)
        }
    }

    /// Lowercase, without brackets or a trailing dot; IP literals in their
    /// canonical text form, so one address always compares equal.
    static func normalizedHost(_ host: String) -> String {
        var value = host.trimmingCharacters(in: .whitespaces).lowercased()
        while value.hasSuffix(".") {
            value.removeLast()
        }
        if let bytes = TunAddress.parse(value), let text = TunAddress.text(bytes) {
            return text
        }
        return value
    }

    // MARK: - DNS

    /// True when the query is answered here (fake IP, NODATA, or a real
    /// answer on its way); false to let it through as a normal flow.
    private func handleDnsQuery(_ payload: [UInt8], srcIp: [UInt8], srcPort: UInt16, dstIp: [UInt8], dstPort: UInt16, isIpv6: Bool) -> Bool {
        let current = settings
        if let parsed = PacketUtil.parseDnsQueryExt(payload), parsed.qtype == 1 || parsed.qtype == 28 {
            let domain = parsed.domain.lowercased()
            if isRealAnswerDomain(domain) {
                answerWithRealAddress(payload, domain: domain, qtype: parsed.qtype, srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, isIpv6: isIpv6)
                return true
            }
        }
        let answer = FakeIpDns.answer(payload, pool: fakeIpPool, ipv6Dns: current.ipv6Dns, encryptedDnsEnabled: current.encryptedDnsEnabled)
        switch answer {
        case .passThrough:
            return false
        case .reply(let response, let reason):
            sendUdp(from: dstIp, fromPort: dstPort, to: srcIp, toPort: srcPort, isIpv6: isIpv6, payload: Data(response))
            if let reason = reason {
                Log.debug("Refused a \(reason) query")
            }
            return true
        }
    }

    /// A proxy server's name (or another real-answer name) must resolve to
    /// where it really is: a fake answer would send the connection to it
    /// back into the tunnel. The lookup runs off the queue and the reply
    /// hops back.
    private func answerWithRealAddress(
        _ payload: [UInt8],
        domain: String,
        qtype: Int,
        srcIp: [UInt8],
        srcPort: UInt16,
        dstIp: [UInt8],
        dstPort: UInt16,
        isIpv6: Bool
    ) {
        if realAnswersInFlight >= 64 {
            // Lookups are backed up: NODATA now beats an answer that never comes.
            if let response = PacketUtil.generateDnsResponse(payload, address: nil, qtype: qtype) {
                sendUdp(from: dstIp, fromPort: dstPort, to: srcIp, toPort: srcPort, isIpv6: isIpv6, payload: Data(response))
            }
            return
        }
        realAnswersInFlight += 1
        let resolver = self.resolver
        let queue = self.queue
        Task {
            let addresses = await resolver.addressesForRealAnswer(domain, qtype: qtype)
            let width = qtype == 28 ? 16 : 4
            var chosen: [UInt8]? = nil
            for address in addresses {
                if let bytes = TunAddress.parse(address), bytes.count == width {
                    chosen = bytes
                    break
                }
            }
            let response = PacketUtil.generateDnsResponse(payload, address: chosen, qtype: qtype)
            queue.async {
                self.realAnswersInFlight -= 1
                guard self.running, let response = response else { return }
                self.sendUdp(from: dstIp, fromPort: dstPort, to: srcIp, toPort: srcPort, isIpv6: isIpv6, payload: Data(response))
                self.flushOutputPackets()
            }
        }
    }

    // MARK: - ICMP

    private func sendIcmpPortUnreachable(srcIp: [UInt8], srcPort: UInt16, dstIp: [UInt8], dstPort: UInt16, isIpv6: Bool, udpPayloadLength: Int) {
        let packet: [UInt8]?
        if isIpv6 {
            packet = IcmpPackets.portUnreachableV6(srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, udpPayloadLength: udpPayloadLength)
        } else {
            packet = IcmpPackets.portUnreachableV4(srcIp: srcIp, srcPort: srcPort, dstIp: dstIp, dstPort: dstPort, udpPayloadLength: udpPayloadLength)
        }
        guard let bytes = packet else { return }
        enqueueOutput(Data(bytes), isIpv6: isIpv6)
    }

    // MARK: - Timers

    /// One timer drives lwIP's timeouts and the UDP idle sweep. It ticks
    /// every 100 ms while anything is open and once a second otherwise.
    private func startTicking() {
        stopTicking()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { [weak self] in
            self?.tick()
        }
        tickTimer = timer
        tickIntervalMs = 0
        lastUdpCleanup = TunClock.now()
        applyTickInterval(TunConstants.lwipTimeoutIntervalMs)
        timer.resume()
    }

    private func stopTicking() {
        if let timer = tickTimer {
            timer.setEventHandler(handler: nil)
            timer.cancel()
        }
        tickTimer = nil
        tickIntervalMs = 0
    }

    private func applyTickInterval(_ milliseconds: Int) {
        guard let timer = tickTimer, milliseconds != tickIntervalMs else { return }
        tickIntervalMs = milliseconds
        let interval = DispatchTimeInterval.milliseconds(milliseconds)
        let leeway = DispatchTimeInterval.milliseconds(max(5, milliseconds / 10))
        timer.schedule(deadline: .now() + interval, repeating: interval, leeway: leeway)
    }

    private func adjustTickInterval() {
        let idle = tcpConnections.isEmpty && udpFlows.isEmpty
        let wanted = idle ? TunConstants.lwipIdleTimeoutIntervalMs : TunConstants.lwipTimeoutIntervalMs
        applyTickInterval(wanted)
    }

    private func tick() {
        guard running else { return }
        lwip_bridge_check_timeouts()
        let now = TunClock.now()
        if now - lastUdpCleanup >= TunConstants.udpCleanupIntervalSec {
            lastUdpCleanup = now
            closeIdleUdpFlows(now: now)
        }
        adjustTickInterval()
        if !outputPackets.isEmpty {
            flushOutputPackets()
        }
    }

    // MARK: - Budgets

    /// Whether a connection may read more from its server now. When the
    /// downlink backlog of all connections is over budget it may not, and is
    /// woken once the backlog falls below it again.
    func mayReadDownlink(_ connId: Int) -> Bool {
        if downlinkBacklog < TunConstants.downlinkBacklogBudget { return true }
        if downlinkWaiterSet.insert(connId).inserted {
            downlinkWaiters.append(connId)
        }
        return false
    }

    /// A connection's downlink backlog grew (positive) or drained (negative).
    func adjustDownlinkBacklog(_ delta: Int) {
        downlinkBacklog = max(0, downlinkBacklog + delta)
        if delta < 0 && !downlinkWaiters.isEmpty && downlinkBacklog < TunConstants.downlinkBacklogBudget {
            let waiting = downlinkWaiters
            downlinkWaiters.removeAll()
            downlinkWaiterSet.removeAll()
            // After the current pass: the caller is in the middle of a drain.
            queue.async { [weak self] in
                guard let self = self else { return }
                for connId in waiting {
                    self.tcpConnections[connId]?.tryArmReceive()
                }
            }
        }
    }

    /// Reserves room for `count` bytes of queued datagrams; false when all
    /// flows together are at `udpPendingBudget`.
    func reserveUdpBytes(_ count: Int) -> Bool {
        if udpQueuedBytes + count > TunConstants.udpPendingBudget { return false }
        udpQueuedBytes += count
        return true
    }

    func releaseUdpBytes(_ count: Int) {
        udpQueuedBytes = max(0, udpQueuedBytes - count)
    }

    // MARK: - Dial results

    func proxyDialSucceeded() {
        withState { consecutiveProxyFailures = 0 }
    }

    func proxyDialFailed() {
        let state = withState { () -> (Int, ((Int) -> Void)?) in
            consecutiveProxyFailures += 1
            return (consecutiveProxyFailures, failureHandler)
        }
        guard let handler = state.1 else { return }
        let count = state.0
        // Off the lwIP queue: the handler is the provider's.
        DispatchQueue.global(qos: .utility).async {
            handler(count)
        }
    }

    // MARK: - Locking

    private func setRunningFlag(_ value: Bool) {
        withState { lockedRunning = value }
    }

    @discardableResult
    private func withState<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }
}

/// The interface's byte counters and speeds, readable from any thread. Speed
/// is computed when someone asks, so no timer wakes the extension for it.
final class TunTrafficCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var up: Int64
    private var down: Int64
    private var open = 0
    private var sampleTime: Double = 0
    private var sampleUp: Int64 = 0
    private var sampleDown: Int64 = 0
    private var upSpeed: Int64 = 0
    private var downSpeed: Int64 = 0

    /// The shortest interval a speed is computed over; a read sooner than
    /// this after the last returns the last speed.
    private static let minimumSampleInterval: Double = 0.8

    init(startingFrom stats: TrafficStats) {
        up = max(0, stats.uploadBytes)
        down = max(0, stats.downloadBytes)
    }

    func addUp(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        up += Int64(count)
        lock.unlock()
    }

    func addDown(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        down += Int64(count)
        lock.unlock()
    }

    func setConnections(_ count: Int) {
        lock.lock()
        open = max(0, count)
        lock.unlock()
    }

    func snapshot(now: Double) -> TrafficStats {
        lock.lock()
        defer { lock.unlock() }
        if sampleTime == 0 {
            sampleTime = now
            sampleUp = up
            sampleDown = down
        } else {
            let elapsed = now - sampleTime
            if elapsed >= TunTrafficCounter.minimumSampleInterval {
                upSpeed = Int64(Double(max(0, up - sampleUp)) / elapsed)
                downSpeed = Int64(Double(max(0, down - sampleDown)) / elapsed)
                sampleTime = now
                sampleUp = up
                sampleDown = down
            }
        }
        return TrafficStats(
            uploadBytes: up,
            downloadBytes: down,
            uploadSpeed: upSpeed,
            downloadSpeed: downSpeed,
            connections: open
        )
    }
}
