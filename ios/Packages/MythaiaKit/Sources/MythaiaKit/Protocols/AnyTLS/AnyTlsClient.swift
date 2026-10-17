import Foundation

/// Dials AnyTLS, reusing sessions.
///
/// The protocol requires multiplexing rather than merely allowing it: a
/// server may refuse a client that opens a TLS connection per request,
/// because that pattern is exactly what the padding scheme exists to hide. So
/// sessions live in a pool keyed by profile, newest first — a fresh session is
/// only built when no idle one is available.
enum AnyTlsClient {
    /// Reported in the settings frame. The protocol asks third-party clients
    /// to give their real name and version rather than impersonate the
    /// reference one, so a server can tell implementations apart.
    static let clientName = "mythaia/1.0"

    /// A stream to `host`:`port` through `configuration`. `dialTls` opens a
    /// new TLS connection to the server when no idle session can be reused.
    /// With `pooled` false (a server behind a chain, whose connection lives
    /// as long as this one flow) the session is made for this stream alone
    /// and closes with it.
    static func openStream(_ configuration: ProxyConfiguration, host: String, port: UInt16, pooled: Bool,
                           dialTls: () async throws -> ByteStream) async throws -> AnyTlsStream {
        guard let password = configuration.password, !password.isEmpty else {
            throw MythaiaError.invalidConfiguration("AnyTLS password not set")
        }
        let pool = AnyTlsPool.of(configuration.id)

        // A session that is alive and idle is always preferable: it costs no
        // handshake and keeps the connection count down, which is itself part
        // of what the protocol is trying to look ordinary about.
        if pooled, let session = pool.takeIdle() {
            do {
                return try await session.openStream(host: host, port: port)
            } catch {
                session.close()
            }
        }

        let tls = try await dialTls()
        let scheme = pool.scheme
        let session = AnyTlsSession(tls: tls, padding: scheme, clientName: clientName, onPaddingScheme: { next in
            pool.scheme = next
        })
        do {
            // Authentication rides in the same write as packet 0's padding,
            // which the scheme sizes; it is the one packet that cannot be split.
            var paddingLength = 0
            if let first = scheme.recordSizes(0).first, first != AnyTlsPaddingScheme.check {
                paddingLength = first
            }
            try await tls.send(AnyTlsProtocol.authentication(password: password, paddingLength: paddingLength))
            try await session.start()
        } catch {
            session.close()
            throw error
        }

        if pooled {
            pool.register(session)
        } else {
            session.onIdle = { [weak session] in
                session?.close()
            }
        }

        do {
            return try await session.openStream(host: host, port: port)
        } catch {
            // The session owns the TLS connection by now, so closing it is
            // what releases the connection.
            session.close()
            throw error
        }
    }
}

/// The live sessions for one profile.
///
/// Also where the padding scheme lives: the server pushes it per client, and
/// it must outlast the session it arrived on — otherwise every new session
/// would announce the default digest again and be told to update again.
final class AnyTlsPool: @unchecked Sendable {
    /// How often the pool looks for sessions to retire.
    static let sweepInterval: TimeInterval = 30
    /// How long a session may sit idle before it is closed.
    static let idleTimeout: TimeInterval = 60
    /// Kept back from retirement so the next request skips a handshake.
    static let minIdleSessions = 2

    private static let poolsLock = NSLock()
    private static var pools: [UUID: AnyTlsPool] = [:]

    static func of(_ id: UUID) -> AnyTlsPool {
        poolsLock.lock()
        defer { poolsLock.unlock() }
        if let existing = pools[id] {
            return existing
        }
        let created = AnyTlsPool()
        pools[id] = created
        return created
    }

    /// Closes the sessions of profile `id` that carry no stream, after a
    /// one-off dial such as a latency test: nothing else would, as the pool's
    /// own sweep runs only when that profile dials again. Sessions with live
    /// streams are left alone, so testing the server in use never cuts its
    /// flows.
    static func releaseIdle(_ id: UUID) {
        poolsLock.lock()
        let pool = pools[id]
        poolsLock.unlock()
        guard let pool = pool else { return }
        if pool.closeIdleSessions() {
            poolsLock.lock()
            if pools[id] === pool {
                pools.removeValue(forKey: id)
            }
            poolsLock.unlock()
        }
    }

    /// Whether profile `id` has a pool; for tests.
    static func isPooled(_ id: UUID) -> Bool {
        poolsLock.lock()
        defer { poolsLock.unlock() }
        return pools[id] != nil
    }

    private let lock = NSLock()
    private var sessions: [AnyTlsSession] = []
    /// Idle sessions and when each became idle; the oldest retire first.
    private var idle: [ObjectIdentifier: (session: AnyTlsSession, since: Date)] = [:]
    private var lastSweep = Date.distantPast
    private var currentScheme = AnyTlsPaddingScheme.defaultScheme

    var scheme: AnyTlsPaddingScheme {
        get {
            lock.lock()
            defer { lock.unlock() }
            return currentScheme
        }
        set {
            lock.lock()
            currentScheme = newValue
            lock.unlock()
        }
    }

    func register(_ session: AnyTlsSession) {
        session.onIdle = { [weak self, weak session] in
            if let session = session {
                self?.markIdle(session)
            }
        }
        lock.lock()
        sessions.append(session)
        let stale = sweepLocked()
        lock.unlock()
        for retired in stale {
            retired.close()
        }
    }

    /// Claims the newest session with no streams on it.
    ///
    /// Newest first is the protocol's own advice: an older session has been
    /// visible for longer, so reusing the freshest leaves the oldest free to
    /// retire. The session is removed from the idle set rather than merely
    /// read, because two dials that both saw it idle would each believe they
    /// were opening its first stream.
    func takeIdle() -> AnyTlsSession? {
        lock.lock()
        sessions.removeAll { $0.isClosed }
        let stale = sweepLocked()
        var chosen: AnyTlsSession?
        var newest = Date.distantPast
        for (_, entry) in idle where !entry.session.isClosed && entry.session.activeStreams == 0 {
            if chosen == nil || entry.since >= newest {
                chosen = entry.session
                newest = entry.since
            }
        }
        if let session = chosen {
            idle.removeValue(forKey: ObjectIdentifier(session))
        }
        lock.unlock()
        for retired in stale {
            retired.close()
        }
        return chosen
    }

    private func markIdle(_ session: AnyTlsSession) {
        lock.lock()
        if !session.isClosed {
            idle[ObjectIdentifier(session)] = (session, Date())
        }
        lock.unlock()
    }

    /// Retires sessions idle too long, keeping a couple back so the next
    /// request does not pay for a handshake. A session is a live TLS
    /// connection: kept forever it is a socket held for nothing, and a
    /// long-lived flow for an observer to notice. Returns them to be closed
    /// outside the lock.
    private func sweepLocked() -> [AnyTlsSession] {
        let now = Date()
        if now.timeIntervalSince(lastSweep) < AnyTlsPool.sweepInterval { return [] }
        lastSweep = now

        let ordered = idle.values.sorted { $0.since < $1.since }
        let expired = ordered.filter { now.timeIntervalSince($0.since) > AnyTlsPool.idleTimeout }
        let keep = min(AnyTlsPool.minIdleSessions, idle.count)
        let retiring = Array(expired.dropLast(keep)).map { $0.session }
        for session in retiring {
            idle.removeValue(forKey: ObjectIdentifier(session))
            sessions.removeAll { $0 === session }
        }
        return retiring
    }

    /// Closes every session without a stream; true when none is left.
    func closeIdleSessions() -> Bool {
        lock.lock()
        let unused = sessions.filter { $0.isClosed || $0.activeStreams == 0 }
        sessions.removeAll { session in unused.contains { $0 === session } }
        for session in unused {
            idle.removeValue(forKey: ObjectIdentifier(session))
        }
        let empty = sessions.isEmpty
        lock.unlock()
        for session in unused {
            session.close()
        }
        return empty
    }
}
