import Foundation
import Network

/// The local inbound: SOCKS5 (CONNECT) and HTTP (CONNECT and plain
/// forwarding) on one port of 127.0.0.1, the first byte of a connection
/// saying which. The system's proxy settings point at it.
///
/// Every connection is routed by `router` and dialled direct or through
/// `configuration` with `Dialer`, then relayed. Switching servers or routers
/// applies to new connections; the ones being relayed finish on what they
/// were dialled with.
public final class LocalProxyServer: @unchecked Sendable {
    typealias ProxyDial = (ProxyConfiguration, Endpoint, Data?) async throws -> ByteStream
    typealias DirectDial = (Endpoint) async throws -> ByteStream

    /// From accept to a parsed request; a client that says nothing is
    /// closed after it.
    static let handshakeTimeout: Double = 15
    /// Long enough for an idle-but-alive connection (a WebSocket, an IMAP
    /// IDLE) to be left alone; a client that vanished without a FIN would
    /// otherwise hold its connection for good.
    static let idleTimeout: Double = 10 * 60
    static let idleCheckInterval: Double = 30
    /// Each open connection costs memory in a process with a hard limit, so
    /// there is a ceiling; refusals are logged, but not one per connection.
    static let maxConnections = 512
    static let refusalLogInterval: Double = 10
    static let maxHead = 64 * 1024
    static let maxSocksRequest = 1024
    static let proxyDialTimeout: Double = 15
    static let directDialTimeout: Double = 10
    static let maxListenerRestarts = 5

    private let requestedPort: UInt16
    private let dialProxy: ProxyDial
    private let dialDirect: DirectDial
    private let counter = TrafficCounter()
    private let listenerQueue = DispatchQueue(label: "com.mythaia.localproxy.listener")
    private let connectionQueue = DispatchQueue(label: "com.mythaia.localproxy.connections")

    private let lock = NSLock()
    private var currentRouter: Router
    private var currentConfiguration: ProxyConfiguration?
    private var failureHandler: ((Int) -> Void)?
    private var listener: NWListener?
    private var running = false
    private var port: UInt16 = 0
    private var flows: [Int: Flow] = [:]
    private var nextFlowId = 0
    private var idleTimer: DispatchSourceTimer?
    private var restartAttempts = 0
    private var consecutiveProxyFailures = 0
    private var lastRefusalLog: Double = 0

    /// `port` 0 lets the system pick a free port; `start()` returns the one
    /// bound.
    public convenience init(router: Router, port: UInt16) {
        self.init(
            router: router,
            port: port,
            dialProxy: LocalProxyServer.dialThroughServer,
            dialDirect: LocalProxyServer.dialDirectly
        )
    }

    init(router: Router, port: UInt16, dialProxy: @escaping ProxyDial, dialDirect: @escaping DirectDial) {
        self.currentRouter = router
        self.requestedPort = port
        self.dialProxy = dialProxy
        self.dialDirect = dialDirect
    }

    private static func dialThroughServer(
        _ configuration: ProxyConfiguration,
        _ target: Endpoint,
        _ initialData: Data?
    ) async throws -> ByteStream {
        try await Dialer.connect(configuration, to: target, initialData: initialData, timeout: proxyDialTimeout)
    }

    private static func dialDirectly(_ target: Endpoint) async throws -> ByteStream {
        try await Dialer.direct(to: target, timeout: directDialTimeout)
    }

    // MARK: - Public state

    /// The router new connections are decided by.
    public var router: Router {
        get { locked { currentRouter } }
        set { locked { currentRouter = newValue } }
    }

    /// The server new connections go through; nil fails every proxied
    /// connection (direct ones still work).
    public var configuration: ProxyConfiguration? {
        get { locked { currentConfiguration } }
        set {
            locked {
                currentConfiguration = newValue
                consecutiveProxyFailures = 0
            }
        }
    }

    /// Called after each failed dial through the server with the number of
    /// failures in a row; a successful dial resets the count. Auto uses it
    /// to notice a server that stopped answering.
    public var onProxyFailures: ((Int) -> Void)? {
        get { locked { failureHandler } }
        set { locked { failureHandler = newValue } }
    }

    public var isRunning: Bool { locked { running } }

    /// The bound port while running, else 0.
    public var boundPort: UInt16 { locked { running ? port : 0 } }

    public var stats: TrafficStats {
        counter.snapshot(now: EngineClock.seconds())
    }

    // MARK: - Start and stop

    /// Starts listening on 127.0.0.1 and returns the bound port. Throws when
    /// the port is taken or the listener does not come up within seconds.
    @discardableResult
    public func start() throws -> UInt16 {
        lock.lock()
        if running {
            let bound = port
            lock.unlock()
            return bound
        }
        lock.unlock()

        let created = try makeListener(port: requestedPort)
        let startup = ListenerStartup()
        lock.lock()
        listener = created
        running = true
        restartAttempts = 0
        consecutiveProxyFailures = 0
        lock.unlock()
        attachHandlers(created, startup: startup)
        created.start(queue: listenerQueue)

        let finished = startup.wait(seconds: 5)
        var failure: Error?
        if !finished {
            failure = MythaiaError.timeout("starting the local proxy")
        } else if let error = startup.error {
            failure = MythaiaError.connectFailed("cannot listen on 127.0.0.1:\(requestedPort): \(error)")
        } else if created.port == nil || created.port?.rawValue == 0 {
            failure = MythaiaError.connectFailed("the local proxy has no port")
        }
        if let failure {
            lock.lock()
            if listener === created { listener = nil }
            running = false
            lock.unlock()
            created.cancel()
            throw failure
        }

        let bound = created.port?.rawValue ?? requestedPort
        lock.lock()
        port = bound
        lock.unlock()
        counter.reset()
        startIdleTimer()
        Log.info("Local proxy listening on 127.0.0.1:\(bound)")
        return bound
    }

    /// Stops listening and closes every connection.
    public func stop() {
        lock.lock()
        guard running else {
            lock.unlock()
            return
        }
        running = false
        let current = listener
        listener = nil
        let open = Array(flows.values)
        flows.removeAll()
        let timer = idleTimer
        idleTimer = nil
        lock.unlock()

        current?.cancel()
        timer?.cancel()
        for flow in open {
            flow.close()
        }
        Log.info("Local proxy stopped")
    }

    /// Closes every connection being relayed, the listener staying up; for
    /// when the old server's connections should not outlive a switch.
    public func closeAllConnections() {
        lock.lock()
        let open = Array(flows.values)
        lock.unlock()
        for flow in open {
            flow.close()
        }
    }

    private func makeListener(port: UInt16) throws -> NWListener {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcp)
        parameters.allowLocalEndpointReuse = true
        parameters.acceptLocalOnly = true
        // The address and the port both come from the required local
        // endpoint (port `.any` for 0): loopback only, never the LAN.
        let localPort = NWEndpoint.Port(rawValue: port) ?? .any
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: localPort)
        return try NWListener(using: parameters)
    }

    private func attachHandlers(_ target: NWListener, startup: ListenerStartup?) {
        target.newConnectionHandler = { [weak self] connection in
            guard let self else {
                connection.cancel()
                return
            }
            self.accept(connection)
        }
        target.stateUpdateHandler = { [weak self, weak target] state in
            switch state {
            case .ready:
                if let startup, startup.finish(nil) { return }
                self?.listenerRecovered()
            case .failed(let error):
                if let startup, startup.finish(error) { return }
                if let self, let target {
                    self.listenerFailed(target, error: error)
                }
            case .waiting(let error):
                if let startup, startup.finish(error) { return }
            default:
                break
            }
        }
    }

    /// The listener can fail while the tunnel runs (the system reclaimed the
    /// socket); the proxy settings name its port, so it comes back on the
    /// same one, a few times with a growing pause.
    private func listenerFailed(_ failed: NWListener, error: NWError) {
        lock.lock()
        guard running, listener === failed else {
            lock.unlock()
            return
        }
        listener = nil
        restartAttempts += 1
        let attempt = restartAttempts
        let bound = port
        lock.unlock()
        failed.cancel()
        guard attempt <= LocalProxyServer.maxListenerRestarts else {
            Log.error("Local proxy listener failed (\(error)); giving up after \(attempt - 1) restarts")
            return
        }
        Log.error("Local proxy listener failed (\(error)); restarting")
        listenerQueue.asyncAfter(deadline: .now() + Double(attempt)) { [weak self] in
            self?.restartListener(port: bound)
        }
    }

    private func restartListener(port: UInt16) {
        guard isRunning else { return }
        do {
            let created = try makeListener(port: port)
            lock.lock()
            guard running else {
                lock.unlock()
                created.cancel()
                return
            }
            listener = created
            lock.unlock()
            attachHandlers(created, startup: nil)
            created.start(queue: listenerQueue)
        } catch {
            Log.error("Local proxy could not listen again: \(error.localizedDescription)")
        }
    }

    private func listenerRecovered() {
        lock.lock()
        let attempts = restartAttempts
        restartAttempts = 0
        lock.unlock()
        if attempts > 0 {
            Log.info("Local proxy listening again")
        }
    }

    private func startIdleTimer() {
        let timer = DispatchSource.makeTimerSource(queue: connectionQueue)
        let interval = LocalProxyServer.idleCheckInterval
        timer.schedule(deadline: .now() + interval, repeating: interval, leeway: .seconds(5))
        timer.setEventHandler { [weak self] in
            self?.closeIdleFlows()
        }
        lock.lock()
        idleTimer?.cancel()
        idleTimer = timer
        lock.unlock()
        timer.resume()
    }

    private func closeIdleFlows() {
        let now = EngineClock.seconds()
        lock.lock()
        let idle = flows.values.filter { $0.idleSeconds(now: now) >= LocalProxyServer.idleTimeout }
        lock.unlock()
        for flow in idle {
            Log.debug("Connection idle for \(Int(LocalProxyServer.idleTimeout / 60)) min; closing")
            flow.close()
        }
    }

    // MARK: - Connections

    private func accept(_ connection: NWConnection) {
        let inbound = InboundStream(connection, queue: connectionQueue)
        guard let flow = register(inbound) else {
            connection.cancel()
            return
        }
        inbound.start()
        counter.connectionOpened()
        Task.detached {
            await self.serve(flow)
            self.unregister(flow)
            self.counter.connectionClosed()
        }
    }

    private func register(_ inbound: InboundStream) -> Flow? {
        let now = EngineClock.seconds()
        lock.lock()
        guard running else {
            lock.unlock()
            return nil
        }
        if flows.count >= LocalProxyServer.maxConnections {
            let shouldLog = now - lastRefusalLog > LocalProxyServer.refusalLogInterval
            if shouldLog { lastRefusalLog = now }
            lock.unlock()
            if shouldLog {
                Log.warning("Refusing a connection: \(LocalProxyServer.maxConnections) are open")
            }
            return nil
        }
        nextFlowId += 1
        let flow = Flow(id: nextFlowId, inbound: inbound, now: now)
        flows[flow.id] = flow
        lock.unlock()
        return flow
    }

    private func unregister(_ flow: Flow) {
        lock.lock()
        flows[flow.id] = nil
        lock.unlock()
    }

    private func serve(_ flow: Flow) async {
        let inbound = flow.inbound
        let deadline = DispatchWorkItem { [weak inbound] in
            inbound?.close()
        }
        connectionQueue.asyncAfter(deadline: .now() + LocalProxyServer.handshakeTimeout, execute: deadline)
        let reader = StreamReader(inbound)
        do {
            let first = try await reader.readExactly(1)
            reader.unread(first)
            let leading = first[first.startIndex]
            if leading == SocksInbound.version {
                try await serveSocks(flow, reader: reader, deadline: deadline)
            } else if leading == 0x04 {
                Log.debug("SOCKS4 is not supported")
            } else {
                try await serveHTTP(flow, reader: reader, deadline: deadline)
            }
        } catch {
            Log.debug("Local connection: \(LocalProxyServer.describe(error))")
        }
        deadline.cancel()
        flow.close()
    }

    private func serveSocks(_ flow: Flow, reader: StreamReader, deadline: DispatchWorkItem) async throws {
        let inbound = flow.inbound
        let greeting = try await readParsed(reader, limit: LocalProxyServer.maxSocksRequest) { data in
            SocksInbound.parseGreeting(data)
        }
        guard greeting.methods.contains(SocksInbound.methodNoAuth) else {
            try await inbound.send(SocksInbound.noAcceptableMethods)
            return
        }
        try await inbound.send(SocksInbound.noAuthSelected)
        let request = try await readParsed(reader, limit: LocalProxyServer.maxSocksRequest) { data in
            SocksInbound.parseRequest(data)
        }
        deadline.cancel()

        guard request.command == SocksInbound.commandConnect else {
            // UDP ASSOCIATE and BIND: the system's proxy settings never ask
            // for them, and UDP would need a relay socket per client.
            try await inbound.send(SocksInbound.reply(SocksInbound.replyCommandNotSupported))
            return
        }
        let target = Endpoint(host: request.host, port: request.port)
        let route = router.decide(request.host)
        if route == .block {
            try await inbound.send(SocksInbound.reply(SocksInbound.replyNotAllowed))
            return
        }

        if wantsFirstData(route) {
            // Confirm first, as Xray's inbounds do, so the client sends its
            // first bytes and they go out with the request header. A dial
            // that then fails can only close the connection.
            try await inbound.send(SocksInbound.reply(SocksInbound.replySuccess))
            let firstData = await readFirstData(flow, already: reader.drain())
            let upstream: ByteStream
            do {
                upstream = try await openUpstream(route, target, initialData: firstData)
            } catch {
                Log.debug("Dial \(target) failed: \(LocalProxyServer.describe(error))")
                return
            }
            if let firstData { counter.addUp(firstData.count) }
            await pump(flow, upstream: upstream, prefix: Data())
            return
        }

        let upstream: ByteStream
        do {
            upstream = try await openUpstream(route, target, initialData: nil)
        } catch {
            Log.debug("Dial \(target) failed: \(LocalProxyServer.describe(error))")
            try await inbound.send(SocksInbound.reply(SocksInbound.replyHostUnreachable))
            return
        }
        do {
            try await inbound.send(SocksInbound.reply(SocksInbound.replySuccess))
        } catch {
            upstream.close()
            throw error
        }
        await pump(flow, upstream: upstream, prefix: reader.drain())
    }

    private func serveHTTP(_ flow: Flow, reader: StreamReader, deadline: DispatchWorkItem) async throws {
        let inbound = flow.inbound
        let head = try await reader.readThrough(HTTPInbound.headTerminator, limit: LocalProxyServer.maxHead)
        let remainder = reader.drain()
        guard let request = HTTPInbound.parse(head: head) else {
            try await inbound.send(HTTPInbound.errorResponse(400, "Bad Request"))
            return
        }
        deadline.cancel()

        switch request {
        case .connect(let host, let port, let version):
            let target = Endpoint(host: host, port: port)
            let route = router.decide(host)
            if route == .block {
                try await inbound.send(HTTPInbound.errorResponse(403, "Forbidden"))
                return
            }
            if wantsFirstData(route) {
                // As for SOCKS: confirm first, dial with the client's first bytes.
                try await inbound.send(HTTPInbound.connectEstablished(version: version))
                let firstData = await readFirstData(flow, already: remainder)
                let upstream: ByteStream
                do {
                    upstream = try await openUpstream(route, target, initialData: firstData)
                } catch {
                    Log.debug("Dial \(target) failed: \(LocalProxyServer.describe(error))")
                    return
                }
                if let firstData { counter.addUp(firstData.count) }
                await pump(flow, upstream: upstream, prefix: Data())
                return
            }
            let upstream: ByteStream
            do {
                upstream = try await openUpstream(route, target, initialData: nil)
            } catch {
                Log.debug("Dial \(target) failed: \(LocalProxyServer.describe(error))")
                try await inbound.send(HTTPInbound.errorResponse(502, "Bad Gateway"))
                return
            }
            do {
                try await inbound.send(HTTPInbound.connectEstablished(version: version))
            } catch {
                upstream.close()
                throw error
            }
            await pump(flow, upstream: upstream, prefix: remainder)

        case .forward(let host, let port, let forwardedHead):
            var initial = forwardedHead
            initial.append(remainder)
            let target = Endpoint(host: host, port: port)
            let route = router.decide(host)
            if route == .block {
                try await inbound.send(HTTPInbound.errorResponse(403, "Forbidden"))
                return
            }
            let upstream: ByteStream
            do {
                upstream = try await openUpstream(route, target, initialData: initial)
            } catch {
                Log.debug("Dial \(target) failed: \(LocalProxyServer.describe(error))")
                try await inbound.send(HTTPInbound.errorResponse(502, "Bad Gateway"))
                return
            }
            counter.addUp(initial.count)
            await pump(flow, upstream: upstream, prefix: Data())
        }
    }

    /// Reads until `parse` has a whole request; bytes after it stay in the
    /// reader.
    private func readParsed<Value>(
        _ reader: StreamReader,
        limit: Int,
        _ parse: (Data) -> InboundParse<Value>
    ) async throws -> Value {
        var buffer = Data()
        while true {
            switch parse(buffer) {
            case .complete(let value, let consumed):
                if consumed < buffer.count {
                    reader.unread(buffer.subdata(in: consumed..<buffer.count))
                }
                return value
            case .invalid(let reason):
                throw MythaiaError.protocolError(reason)
            case .incomplete:
                if buffer.count > limit { throw MythaiaError.parse("request too long") }
                guard let chunk = try await reader.readSome() else { throw MythaiaError.closed }
                buffer.append(chunk)
            }
        }
    }

    /// Whether a connection on `route` should hand the server the client's
    /// first bytes with its request: VLESS and VMess embed them in the
    /// handshake, and Trojan and Shadowsocks otherwise write a header that
    /// never leaves when the server speaks first (SSH, SMTP, IMAP).
    private func wantsFirstData(_ route: RouteTarget) -> Bool {
        guard route == .proxy, let configuration = self.configuration else { return false }
        return LocalProxyServer.handshakeCarriesInitialData(configuration)
    }

    static func handshakeCarriesInitialData(_ configuration: ProxyConfiguration) -> Bool {
        switch configuration.outboundProtocol {
        case .vless, .vmess, .trojan, .shadowsocks:
            return true
        default:
            return false
        }
    }

    /// The client's first bytes after the connection was confirmed, after
    /// `already` when some came with the request: read until they are whole
    /// (`InboundFirstData`), each read waiting at most
    /// `InboundFirstData.waitSeconds`. Nil when the client sent none in that
    /// time or closed.
    private func readFirstData(_ flow: Flow, already: Data) async -> Data? {
        var first = already
        while !InboundFirstData.isComplete(first) {
            let outcome = await flow.inbound.read(waitingAtMost: InboundFirstData.waitSeconds)
            guard case .data(let chunk) = outcome else { break }
            first.append(chunk)
        }
        return first.isEmpty ? nil : first
    }

    private func openUpstream(_ route: RouteTarget, _ target: Endpoint, initialData: Data?) async throws -> ByteStream {
        switch route {
        case .block:
            throw MythaiaError.connectFailed("\(target) is blocked by a rule")
        case .direct:
            let stream = try await dialDirect(target)
            if let initialData, !initialData.isEmpty {
                do {
                    try await stream.send(initialData)
                } catch {
                    stream.close()
                    throw error
                }
            }
            return stream
        case .proxy:
            guard let configuration = self.configuration else {
                throw MythaiaError.invalidConfiguration("no server selected")
            }
            do {
                let stream = try await dialProxy(configuration, target, initialData)
                proxyDialSucceeded()
                return stream
            } catch {
                proxyDialFailed()
                throw error
            }
        }
    }

    private func proxyDialSucceeded() {
        lock.lock()
        consecutiveProxyFailures = 0
        lock.unlock()
    }

    private func proxyDialFailed() {
        lock.lock()
        consecutiveProxyFailures += 1
        let count = consecutiveProxyFailures
        let handler = failureHandler
        lock.unlock()
        handler?(count)
    }

    /// Relays the client and `upstream` until either ends, counting both
    /// ways; `prefix` is client data already read, sent first.
    private func pump(_ flow: Flow, upstream: ByteStream, prefix: Data) async {
        guard flow.attach(upstream, now: EngineClock.seconds()) else {
            upstream.close()
            return
        }
        let client: ByteStream
        if prefix.isEmpty {
            client = flow.inbound
        } else {
            client = PrefixedStream(flow.inbound, prefix: prefix)
        }
        let counted = FlowCountingStream(client, counter: counter) { [weak flow] in
            flow?.touch(now: EngineClock.seconds())
        }
        await relay(counted, upstream)
    }

    static func describe(_ error: Error) -> String {
        if let localized = error as? LocalizedError, let text = localized.errorDescription {
            return text
        }
        return String(describing: error)
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: - Helpers

    /// One accepted connection: the client and, once dialled, the server.
    final class Flow: @unchecked Sendable {
        let id: Int
        let inbound: InboundStream
        private let lock = NSLock()
        private var upstream: ByteStream?
        private var lastActivity: Double
        private var closed = false

        init(id: Int, inbound: InboundStream, now: Double) {
            self.id = id
            self.inbound = inbound
            self.lastActivity = now
        }

        /// False when the flow was closed meanwhile (the proxy stopped).
        func attach(_ stream: ByteStream, now: Double) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            if closed { return false }
            upstream = stream
            lastActivity = now
            return true
        }

        func touch(now: Double) {
            lock.lock()
            lastActivity = now
            lock.unlock()
        }

        func idleSeconds(now: Double) -> Double {
            lock.lock()
            defer { lock.unlock() }
            return now - lastActivity
        }

        func close() {
            lock.lock()
            closed = true
            let stream = upstream
            upstream = nil
            lock.unlock()
            stream?.close()
            inbound.close()
        }
    }

    /// The first state a starting listener reaches, for `start()` to wait on.
    private final class ListenerStartup: @unchecked Sendable {
        private let semaphore = DispatchSemaphore(value: 0)
        private let lock = NSLock()
        private var done = false
        private var failure: Error?

        /// Records the outcome; true if this call was the one that finished
        /// the startup.
        func finish(_ error: Error?) -> Bool {
            lock.lock()
            if done {
                lock.unlock()
                return false
            }
            done = true
            failure = error
            lock.unlock()
            semaphore.signal()
            return true
        }

        func wait(seconds: Double) -> Bool {
            semaphore.wait(timeout: .now() + seconds) == .success
        }

        var error: Error? {
            lock.lock()
            defer { lock.unlock() }
            return failure
        }
    }
}
