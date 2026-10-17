import Foundation

/// NaiveProxy over HTTP/2: a CONNECT tunnel on a stream of an HTTP/2
/// connection to the proxy, with NaiveProxy's padding negotiated in the
/// request headers.
///
/// Connections to one server are pooled: every tunnel to it is one more
/// stream on a shared TLS connection, as Chrome (and so NaiveProxy) does it,
/// rather than a handshake per tunnel. Behind a chain the connection runs
/// over the chain's flow and lives as long as this one tunnel, so it is not
/// pooled.
enum NaiveClient {
    /// Opens a tunnel to `target` through the HTTP/2 proxy `hop`. `dialTls`
    /// opens a new TLS connection (ALPN h2) to the proxy when a connection
    /// has to be made.
    static func connectHttp2(_ hop: ProxyConfiguration, target: Endpoint, pooled: Bool,
                             dialTls: @escaping () async throws -> ByteStream) async throws -> ByteStream {
        let destination = target.description
        let session: Http2Session
        let stream: Http2Stream
        let entry: NaiveSessionPool.Entry?
        do {
            if pooled {
                let acquired = try await NaiveSessionPool.shared.acquire(key: NaiveSessionPool.key(for: hop), destination: destination, dial: dialTls)
                session = acquired.entry.session
                stream = acquired.stream
                entry = acquired.entry
            } else {
                session = Http2Session(profile: .naive, keepalive: false, dial: dialTls)
                entry = nil
                do {
                    stream = try await session.acquireStream(destination)
                } catch {
                    session.close()
                    throw error
                }
            }
        } catch {
            throw TransportErrors.map(error)
        }

        let headerBlock = HpackEncoder.encodeConnectRequest(
            authority: destination,
            extraHeaders: requestHeaders(username: hop.naiveUsername, password: hop.naivePassword)
        )
        do {
            try await stream.openTunnel(headerBlock: headerBlock)
        } catch {
            stream.close()
            if let entry = entry {
                NaiveSessionPool.shared.tunnelEnded(entry)
            } else {
                session.close()
            }
            throw TransportErrors.map(error)
        }

        let paddingType = NaivePaddingNegotiator.parseResponse(stream.responseHeaders ?? [])
        let onClose: () -> Void
        if let entry = entry {
            onClose = { NaiveSessionPool.shared.tunnelEnded(entry) }
        } else {
            onClose = { session.close() }
        }
        return NaiveProxyConnection(TransportErrorMappingStream(stream), paddingType: paddingType, onClose: onClose)
    }

    /// The CONNECT request's headers beyond `:method` and `:authority`, in
    /// the order NaiveProxy sends them.
    static func requestHeaders(username: String?, password: String?) -> [HpackHeader] {
        var headers = [HpackHeader]()
        if let auth = NaiveHttp11Connection.basicAuth(username: username, password: password) {
            headers.append(HpackHeader("proxy-authorization", "Basic \(auth)"))
        }
        headers.append(HpackHeader("user-agent", NaiveHttp11Connection.userAgent))
        headers.append(contentsOf: NaivePaddingNegotiator.requestHeaders())
        return headers
    }
}

/// HTTP/2 connections to NaiveProxy servers, shared by every tunnel to the
/// same server under the same TLS settings.
final class NaiveSessionPool: @unchecked Sendable {
    static let shared = NaiveSessionPool()

    /// What decides whether two tunnels may share a connection. The TLS
    /// settings are part of it: a server edited to pin its certificate, or
    /// to stop allowing an insecure one, must not reuse a connection made
    /// under the old rules.
    struct Key: Hashable {
        let host: String
        let port: UInt16
        let serverName: String
        let tls: TlsConfiguration?
    }

    static func key(for hop: ProxyConfiguration) -> Key {
        return Key(
            host: hop.serverAddress,
            port: hop.serverPort,
            serverName: hop.tls?.serverName ?? hop.serverAddress,
            tls: hop.tls
        )
    }

    /// One pooled connection and the tunnels open on it.
    final class Entry: @unchecked Sendable {
        let session: Http2Session
        let key: Key
        fileprivate var tunnels = 0

        init(session: Http2Session, key: Key) {
            self.session = session
            self.key = key
        }
    }

    private let lock = NSLock()
    private var entries: [Key: [Entry]] = [:]

    /// A new stream for `destination` on a connection to the server of
    /// `key`: one with room, else one still starting (joining its
    /// handshake), else a new one.
    func acquire(key: Key, destination: String, dial: @escaping () async throws -> ByteStream) async throws -> (entry: Entry, stream: Http2Stream) {
        while true {
            let choice = choose(key: key, dial: dial)
            switch choice {
            case .ready(let entry):
                // Atomic reservation; nil means another caller took the last
                // slot meanwhile, so look again.
                if let stream = entry.session.tryReserveStream(destination) {
                    return (entry, stream)
                }
                tunnelEnded(entry)
            case .starting(let entry), .created(let entry):
                do {
                    let stream = try await entry.session.acquireStream(destination)
                    return (entry, stream)
                } catch {
                    tunnelEnded(entry)
                    if case .created = choice {
                        entry.session.close()
                        throw error
                    }
                    // A connection someone else started failed: try our own.
                }
            }
        }
    }

    private enum Choice {
        case ready(Entry)
        case starting(Entry)
        case created(Entry)
    }

    /// Picks the connection and counts the tunnel on it, under the lock.
    private func choose(key: Key, dial: @escaping () async throws -> ByteStream) -> Choice {
        lock.lock()
        defer { lock.unlock() }
        var list = entries[key] ?? []
        list.removeAll { $0.session.isClosed }
        if let ready = list.first(where: { $0.session.hasCapacity }) {
            ready.tunnels += 1
            entries[key] = list
            return .ready(ready)
        }
        if let starting = list.first(where: { $0.session.isStarting }) {
            starting.tunnels += 1
            entries[key] = list
            return .starting(starting)
        }
        let session = Http2Session(profile: .naive, keepalive: true, dial: dial)
        let entry = Entry(session: session, key: key)
        entry.tunnels = 1
        session.onClose = { [weak self, weak entry] in
            if let entry = entry {
                self?.remove(entry)
            }
        }
        list.append(entry)
        entries[key] = list
        return .created(entry)
    }

    /// A tunnel on `entry` closed, or never opened.
    func tunnelEnded(_ entry: Entry) {
        lock.lock()
        if entry.tunnels > 0 {
            entry.tunnels -= 1
        }
        lock.unlock()
    }

    private func remove(_ entry: Entry) {
        lock.lock()
        if var list = entries[entry.key] {
            list.removeAll { $0 === entry }
            entries[entry.key] = list.isEmpty ? nil : list
        }
        lock.unlock()
    }

    /// Closes the connections to `key`'s server that carry no tunnel, after
    /// a one-off dial such as a latency test: nothing reaps an idle pooled
    /// connection otherwise, so every server a test across a subscription
    /// reached would keep one open. Connections with live tunnels are left
    /// alone.
    func releaseIdle(_ key: Key) {
        lock.lock()
        let list = entries[key] ?? []
        let idle = list.filter { $0.tunnels == 0 }
        let kept = list.filter { $0.tunnels > 0 }
        entries[key] = kept.isEmpty ? nil : kept
        lock.unlock()
        for entry in idle {
            entry.session.onClose = nil
            entry.session.close()
        }
    }

    /// Whether a connection to `key`'s server is pooled; for tests.
    func holds(_ key: Key) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return !(entries[key] ?? []).isEmpty
    }
}
