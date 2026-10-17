import Foundation

/// One Hysteria2 / TUIC client per server, shared by every flow.
///
/// Both protocols multiplex everything onto one QUIC connection — that is
/// where their speed comes from — so a client per flow would be the worst of
/// both worlds: every TCP connection paying a full QUIC handshake (and, for
/// Hysteria2, HTTP/3 setup and authentication), and every connection left
/// open, holding a socket and a keep-alive until the server's idle timeout.
/// Clients bring their session back up on their own when it dies.
///
/// What ends them: `closeAll` when the tunnel stops or switches server;
/// `releaseIdle` after a one-off dial such as a latency test (through
/// `Dialer.releasePooledSessions`), which closes a client carrying no flow;
/// and the client itself once it has carried no flow for `idleTimeout`, so a
/// server the tunnel moved away from does not keep a session alive for good.
public enum QuicClientPool {
    /// How long a client with no flow keeps its session before closing it.
    static let idleTimeout: Double = 300

    private final class State: @unchecked Sendable {
        let lock = NSLock()
        var hysteria: [String: HysteriaClient] = [:]
        var tuic: [String: TuicClient] = [:]
    }

    private static let state = State()

    static func hysteria(_ configuration: ProxyConfiguration) -> HysteriaClient {
        let id = key(configuration)
        state.lock.lock()
        defer { state.lock.unlock() }
        if let existing = state.hysteria[id], !existing.isClosed {
            return existing
        }
        let client = HysteriaClient(configuration: configuration, key: id)
        client.core.onRelease = { [weak client] in
            guard let client = client else { return }
            QuicClientPool.remove(client)
        }
        state.hysteria[id] = client
        return client
    }

    static func tuic(_ configuration: ProxyConfiguration) -> TuicClient {
        let id = key(configuration)
        state.lock.lock()
        defer { state.lock.unlock() }
        if let existing = state.tuic[id], !existing.isClosed {
            return existing
        }
        let client = TuicClient(configuration: configuration, key: id)
        client.core.onRelease = { [weak client] in
            guard let client = client else { return }
            QuicClientPool.remove(client)
        }
        state.tuic[id] = client
        return client
    }

    /// Ends every pooled session. Safe to call any time; the next dial starts afresh.
    public static func closeAll() {
        state.lock.lock()
        let hysteria = Array(state.hysteria.values)
        let tuic = Array(state.tuic.values)
        state.hysteria.removeAll()
        state.tuic.removeAll()
        state.lock.unlock()
        hysteria.forEach { $0.close() }
        tuic.forEach { $0.close() }
    }

    /// Ends the session `configuration` reaches, if one is pooled, whatever
    /// it carries.
    static func evict(_ configuration: ProxyConfiguration) {
        let id = key(configuration)
        state.lock.lock()
        let hysteria = state.hysteria.removeValue(forKey: id)
        let tuic = state.tuic.removeValue(forKey: id)
        state.lock.unlock()
        hysteria?.close()
        tuic?.close()
    }

    /// Closes the session `configuration` reaches when it carries no flow, as
    /// after a latency test: pooled sessions outlive their dial on purpose,
    /// which is right for the server in use and wrong for a test across a
    /// subscription of thousands, each keeping a socket and a keep-alive.
    /// A session carrying flows — the tunnel's own — is left alone. One whose
    /// only use is a dial still in flight is closed when that dial ends
    /// without opening a flow.
    static func releaseIdle(_ configuration: ProxyConfiguration) {
        let id = key(configuration)
        state.lock.lock()
        let hysteria = state.hysteria[id]
        let tuic = state.tuic[id]
        state.lock.unlock()
        if let client = hysteria, client.core.releaseIfIdle() {
            remove(client)
        }
        if let client = tuic, client.core.releaseIfIdle() {
            remove(client)
        }
    }

    /// Whether a session is pooled for `configuration`; for tests.
    static func isPooled(_ configuration: ProxyConfiguration) -> Bool {
        let id = key(configuration)
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.hysteria[id] != nil || state.tuic[id] != nil
    }

    private static func remove(_ client: HysteriaClient) {
        state.lock.lock()
        if state.hysteria[client.key] === client {
            state.hysteria.removeValue(forKey: client.key)
        }
        state.lock.unlock()
        client.close()
    }

    private static func remove(_ client: TuicClient) {
        state.lock.lock()
        if state.tuic[client.key] === client {
            state.tuic.removeValue(forKey: client.key)
        }
        state.lock.unlock()
        client.close()
    }

    /// Everything that makes two configurations reach the same session, so
    /// duplicates of one server under different ids share it.
    static func key(_ c: ProxyConfiguration) -> String {
        func text(_ value: Any?) -> String {
            guard let value = value else { return "-" }
            return "\(value)"
        }
        let parts: [String] = [
            c.outboundProtocol.rawValue, c.serverAddress, String(c.serverPort), c.resolvedIP ?? "-",
            c.uuid.uuidString, text(c.password), text(c.trojanPassword),
            text(c.obfuscation), text(c.obfuscationPassword), text(c.hysteriaUpMbps), text(c.hysteriaDownMbps),
            text(c.tls?.serverName), text(c.tls?.allowInsecure), text(c.tls?.fingerprint.rawValue),
            text(c.tls?.alpn?.joined(separator: ",")), text(c.tls?.pinnedCertSha256?.joined(separator: ",")),
            text(c.tls?.verifyName),
        ]
        return parts.joined(separator: "|")
    }
}

/// A pooled session: the QUIC connection and whatever the protocol built on it.
protocol QuicPooledSession: AnyObject {
    var isUsable: Bool { get }
    func close()
}

/// The session lifecycle both QUIC clients share: one session at a time,
/// brought up by the first flow that needs it while later ones wait for the
/// same handshake, replaced when it dies; and the count of flows and dials
/// that decides when an unused session may be closed.
final class QuicClientCore<Session: QuicPooledSession>: @unchecked Sendable {
    private let name: String
    private let establishTimeout: Double
    private let lock = NSLock()
    private var active: Session?
    private var establishing = false
    private var waiters: [UInt64: CheckedContinuation<Session, Error>] = [:]
    private var nextWaiterId: UInt64 = 0
    private var closed = false
    private var flows = 0
    private var dials = 0
    private var releaseWanted = false
    private var idleGeneration: UInt64 = 0
    private var releaseHandler: (() -> Void)?

    init(name: String, establishTimeout: Double) {
        self.name = name
        self.establishTimeout = establishTimeout
    }

    /// Called once the core decides its session should go (idle, or released
    /// while a dial was in flight); the pool removes and closes the client.
    var onRelease: (() -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return releaseHandler
        }
        set {
            lock.lock()
            releaseHandler = newValue
            lock.unlock()
        }
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    /// The live session, if there is one; nothing is dialled.
    var currentSession: Session? {
        lock.lock()
        defer { lock.unlock() }
        if let current = active, current.isUsable { return current }
        return nil
    }

    /// The usable session, establishing one with `establish` when there is
    /// none. Every caller waiting meanwhile shares the one handshake. A
    /// cancelled caller stops waiting at once; the handshake goes on for the
    /// others, bounded by its own timeout.
    func session(_ establish: @escaping () async throws -> Session) async throws -> Session {
        lock.lock()
        if closed {
            lock.unlock()
            throw MythaiaError.connectFailed("\(name) session closed")
        }
        if let current = active, current.isUsable {
            lock.unlock()
            return current
        }
        nextWaiterId &+= 1
        let id = nextWaiterId
        lock.unlock()

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Session, Error>) in
                lock.lock()
                if closed {
                    lock.unlock()
                    continuation.resume(throwing: MythaiaError.connectFailed("\(name) session closed"))
                    return
                }
                if let current = active, current.isUsable {
                    lock.unlock()
                    continuation.resume(returning: current)
                    return
                }
                if Task.isCancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                    return
                }
                waiters[id] = continuation
                var stale: Session?
                let start = !establishing
                if start {
                    establishing = true
                    stale = active
                    active = nil
                }
                lock.unlock()
                // The old session is dead; closing it releases its socket.
                stale?.close()
                if start {
                    Task { await self.establishSession(establish) }
                }
            }
        } onCancel: {
            self.lock.lock()
            let continuation = self.waiters.removeValue(forKey: id)
            self.lock.unlock()
            continuation?.resume(throwing: CancellationError())
        }
    }

    private func establishSession(_ establish: @escaping () async throws -> Session) async {
        var outcome: Result<Session, Error>
        do {
            let made = try await withTimeout(establishTimeout, "\(name) handshake") {
                try await establish()
            }
            outcome = .success(made)
        } catch {
            outcome = .failure(error)
        }
        lock.lock()
        establishing = false
        let pending = waiters
        waiters.removeAll()
        var discard: Session?
        if case .success(let made) = outcome {
            if closed {
                discard = made
                outcome = .failure(MythaiaError.connectFailed("\(name) session closed"))
            } else {
                active = made
            }
        }
        lock.unlock()
        discard?.close()
        for continuation in pending.values {
            continuation.resume(with: outcome)
        }
        checkIdle()
    }

    // MARK: - Use

    /// A dial through this client began; it may become a flow.
    func beginDial() {
        lock.lock()
        dials += 1
        idleGeneration &+= 1
        lock.unlock()
    }

    func endDial() {
        lock.lock()
        dials = max(0, dials - 1)
        lock.unlock()
        checkIdle()
    }

    /// A flow (a proxied TCP stream or UDP session) now runs on the session.
    func flowOpened() {
        lock.lock()
        flows += 1
        // Somebody uses it: a release asked for earlier no longer applies.
        releaseWanted = false
        idleGeneration &+= 1
        lock.unlock()
    }

    func flowClosed() {
        lock.lock()
        flows = max(0, flows - 1)
        lock.unlock()
        checkIdle()
    }

    /// True when the client carries nothing and may be closed now. A dial
    /// still in flight with no flow — most likely the probe's own — marks
    /// the client to be closed when it ends; flows mean the session is in
    /// use, and it is left alone.
    func releaseIfIdle() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if closed { return false }
        if flows == 0 && dials == 0 { return true }
        if flows == 0 { releaseWanted = true }
        return false
    }

    /// Releases now when a release was asked for, else arms the idle timer.
    private func checkIdle() {
        lock.lock()
        if closed || flows > 0 || dials > 0 {
            lock.unlock()
            return
        }
        if releaseWanted {
            let handler = releaseHandler
            lock.unlock()
            handler?()
            return
        }
        idleGeneration &+= 1
        let generation = idleGeneration
        let hasSession = active != nil || establishing
        lock.unlock()
        if !hasSession { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + QuicClientPool.idleTimeout) { [weak self] in
            self?.idleTimerFired(generation)
        }
    }

    private func idleTimerFired(_ generation: UInt64) {
        lock.lock()
        let idle = !closed && flows == 0 && dials == 0 && generation == idleGeneration
        let handler = releaseHandler
        lock.unlock()
        if idle {
            Log.debug("[QUIC] \(name): no flow for \(Int(QuicClientPool.idleTimeout)) s, closing the session")
            handler?()
        }
    }

    /// Ends the session and refuses new ones; waiting callers fail.
    func close() {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        let current = active
        active = nil
        let pending = waiters
        waiters.removeAll()
        releaseHandler = nil
        lock.unlock()
        current?.close()
        for continuation in pending.values {
            continuation.resume(throwing: MythaiaError.connectFailed("\(name) session closed"))
        }
    }
}

/// A flow handed out by a pooled client: the stream, plus the bookkeeping
/// that tells the client when the flow is over, closed or simply dropped.
final class QuicClientFlow: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let onClose: () -> Void
    private let lock = NSLock()
    private var ended = false

    init(_ inner: ByteStream, onClose: @escaping () -> Void) {
        self.inner = inner
        self.onClose = onClose
    }

    deinit {
        if !ended { onClose() }
        inner.close()
    }

    func send(_ data: Data) async throws {
        try await inner.send(data)
    }

    func receive() async throws -> Data? {
        return try await inner.receive()
    }

    func close() {
        lock.lock()
        let first = !ended
        ended = true
        lock.unlock()
        inner.close()
        if first { onClose() }
    }
}

/// A UDP flow held without keeping it alive: a flow its owner dropped
/// releases its session id through its own deinit.
struct WeakQuicUdpFlow {
    weak var flow: QuicUdpFlow?
}
