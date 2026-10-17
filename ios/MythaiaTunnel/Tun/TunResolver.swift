import Foundation
import MythaiaKit

/// Real addresses for the names the tunnel itself has to reach: the proxy
/// servers, and the domains that go direct.
///
/// Once the tunnel's DNS points at the stack, any lookup that reaches it is
/// answered with a fake IP, and a fake IP dialled from the extension (whose
/// own sockets never enter the tunnel) leads nowhere. So nothing here trusts
/// an answer in the fake range: the system resolver is asked first, and
/// when its answer is fake (it went through the tunnel's DNS) or missing,
/// the question goes straight to a public resolver over a direct UDP socket,
/// as the Kotlin core's `DnsCache` asks over protected sockets.
///
/// Answers given to apps for the proxy servers' own names never use the
/// system resolver: if its lookups do go through the tunnel, the question
/// would come straight back to the stack, which would ask again.
final class TunResolver: @unchecked Sendable {

    /// The resolvers asked directly; the app's DNS settings may replace them.
    var upstreamServers: [String] {
        get { withLock { servers } }
        set {
            let replacement = newValue.isEmpty ? TunResolver.defaultUpstreamServers : newValue
            withLock { servers = replacement }
        }
    }

    static let defaultUpstreamServers = ["1.1.1.1", "8.8.8.8"]

    private struct Entry {
        let addresses: [String]
        let expiry: Double
    }

    private let lock = NSLock()
    private var servers: [String] = TunResolver.defaultUpstreamServers
    private var cache: [String: Entry] = [:]
    private var directTargets: [String: Entry] = [:]
    private var systemLookupsQueued = 0
    private var upstreamLookupsInFlight = 0

    /// Blocking getaddrinfo calls run here, a few at a time; the rest wait
    /// in the queue without holding a thread.
    private let operations: OperationQueue = {
        let queue = OperationQueue()
        queue.name = "com.mythaia.tunnel.resolver"
        queue.maxConcurrentOperationCount = 4
        queue.qualityOfService = .userInitiated
        return queue
    }()

    private static let cacheTtl: Double = 120
    private static let maxCacheEntries = 512
    private static let maxSystemLookupsQueued = 64
    private static let maxUpstreamLookups = 64
    private static let upstreamTimeout: Double = 3

    // MARK: - Cache

    /// Addresses learned elsewhere (the provider resolves the servers before
    /// the tunnel's DNS changes); kept while the tunnel runs.
    func seed(_ name: String, addresses: [String]) {
        let key = TunResolver.key(name)
        let real = addresses.filter { !FakeIpPool.isFakeIp($0) && TunAddress.isLiteral($0) }
        guard !key.isEmpty, !real.isEmpty else { return }
        withLock {
            cache[key] = Entry(addresses: real, expiry: Double.greatestFiniteMagnitude)
        }
    }

    func cachedAddresses(_ name: String) -> [String]? {
        let key = TunResolver.key(name)
        let now = TunClock.now()
        return withLock { () -> [String]? in
            guard let entry = cache[key], entry.expiry > now else { return nil }
            return entry.addresses
        }
    }

    func clear() {
        withLock {
            cache.removeAll()
            directTargets.removeAll()
        }
    }

    // MARK: - Lookups

    /// What a direct dial to `name` should connect to: the name itself when
    /// the system resolver answers it for real (the dial then resolves it
    /// the usual way, with Happy Eyeballs), an address from a public
    /// resolver when the system's answer was a fake IP, or the name again
    /// when nothing answered, so the dial fails with its own error.
    func directTarget(_ name: String) async -> String {
        if TunAddress.isLiteral(name) { return name }
        let key = TunResolver.key(name)
        let now = TunClock.now()
        let cached: String? = withLock { () -> String? in
            guard let entry = directTargets[key], entry.expiry > now else { return nil }
            return entry.addresses.first
        }
        if let cached = cached { return cached }

        var target = name
        let system = await systemLookup(name)
        if let system = system, !system.isEmpty, !system.contains(where: { FakeIpPool.isFakeIp($0) }) {
            target = name
        } else {
            var addresses = await upstreamLookup(name, type: DnsMessage.typeA)
            if addresses.isEmpty {
                addresses = await upstreamLookup(name, type: DnsMessage.typeAAAA)
            }
            if let first = addresses.first {
                target = first
            }
        }
        remember(directTarget: target, for: key)
        return target
    }

    /// Real addresses for an answer the stack gives an app (the proxy
    /// servers' names and the other real-answer domains): the cache, then a
    /// public resolver, never the system resolver.
    func addressesForRealAnswer(_ name: String, qtype: Int) async -> [String] {
        if let cached = cachedAddresses(name) { return cached }
        let type = qtype == DnsMessage.typeAAAA ? DnsMessage.typeAAAA : DnsMessage.typeA
        let addresses = await upstreamLookup(name, type: type)
        if !addresses.isEmpty {
            store(addresses, for: TunResolver.key(name))
        }
        return addresses
    }

    /// Every real address of a proxy server, for keeping flows to it off the
    /// proxy: the cache, the system resolver, then a public resolver.
    func serverAddresses(_ name: String) async -> [String] {
        if TunAddress.isLiteral(name) { return [name] }
        if let cached = cachedAddresses(name) { return cached }
        var addresses: [String] = []
        if let system = await systemLookup(name) {
            addresses = system.filter { !FakeIpPool.isFakeIp($0) }
        }
        if addresses.isEmpty {
            addresses = await upstreamLookup(name, type: DnsMessage.typeA)
            let v6 = await upstreamLookup(name, type: DnsMessage.typeAAAA)
            addresses.append(contentsOf: v6)
        }
        if !addresses.isEmpty {
            store(addresses, for: TunResolver.key(name))
        }
        return addresses
    }

    /// getaddrinfo off the caller's thread; nil when too many lookups are
    /// already waiting.
    func systemLookup(_ name: String) async -> [String]? {
        let admitted: Bool = withLock { () -> Bool in
            if systemLookupsQueued >= TunResolver.maxSystemLookupsQueued { return false }
            systemLookupsQueued += 1
            return true
        }
        if !admitted { return nil }
        let queue = operations
        return await withCheckedContinuation { (continuation: CheckedContinuation<[String]?, Never>) in
            queue.addOperation {
                let addresses = TunResolver.resolveWithSystem(name)
                self.finishSystemLookup()
                continuation.resume(returning: addresses)
            }
        }
    }

    private func finishSystemLookup() {
        lock.lock()
        systemLookupsQueued -= 1
        lock.unlock()
    }

    /// One question to the public resolvers in turn, over direct UDP; the
    /// addresses of the first useful answer, or none.
    func upstreamLookup(_ name: String, type: Int) async -> [String] {
        let admitted: Bool = withLock { () -> Bool in
            if upstreamLookupsInFlight >= TunResolver.maxUpstreamLookups { return false }
            upstreamLookupsInFlight += 1
            return true
        }
        if !admitted { return [] }
        defer { withLock { upstreamLookupsInFlight -= 1 } }

        let candidates = upstreamServers
        for server in candidates {
            let id = Int.random(in: 0...0xFFFF)
            guard let query = DnsMessage.makeQuery(domain: name, type: type, id: id) else { return [] }
            if let addresses = await TunResolver.ask(server, query: query, id: id), !addresses.isEmpty {
                return addresses.filter { !FakeIpPool.isFakeIp($0) }
            }
        }
        return []
    }

    // MARK: - Internal

    private static func ask(_ server: String, query: [UInt8], id: Int) async -> [String]? {
        let stream: DatagramStream
        do {
            stream = try await Dialer.directUDP(to: Endpoint(host: server, port: 53))
        } catch {
            Log.debug("[DNS] Resolver \(server) unreachable: \(describeTunError(error))")
            return nil
        }
        defer { stream.close() }
        do {
            try await stream.send(Data(query))
            let addresses: [String] = try await withTimeout(upstreamTimeout, "DNS answer from \(server)") { () async throws -> [String] in
                while let reply = try await stream.receive() {
                    do {
                        return try DnsMessage.parseAddresses([UInt8](reply), expectedId: id)
                    } catch DnsMessage.ParseFailure.identifierMismatch {
                        continue
                    }
                }
                return []
            }
            return addresses
        } catch {
            Log.debug("[DNS] No answer from \(server): \(describeTunError(error))")
            return nil
        }
    }

    /// getaddrinfo, both families, as text; blocking.
    static func resolveWithSystem(_ name: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>? = nil
        let status = getaddrinfo(name, nil, &hints, &result)
        guard status == 0, let first = result else { return [] }
        defer { freeaddrinfo(first) }

        var out: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let info = cursor {
            if let address = info.pointee.ai_addr {
                var bytes: [UInt8] = []
                if info.pointee.ai_family == AF_INET {
                    bytes = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer -> [UInt8] in
                        var raw = pointer.pointee.sin_addr
                        return withUnsafeBytes(of: &raw) { [UInt8]($0) }
                    }
                } else if info.pointee.ai_family == AF_INET6 {
                    bytes = address.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { pointer -> [UInt8] in
                        var raw = pointer.pointee.sin6_addr
                        return withUnsafeBytes(of: &raw) { [UInt8]($0) }
                    }
                }
                if let text = TunAddress.text(bytes), !out.contains(text) {
                    out.append(text)
                }
            }
            cursor = info.pointee.ai_next
        }
        return out
    }

    private func store(_ addresses: [String], for key: String) {
        let expiry = TunClock.now() + TunResolver.cacheTtl
        withLock {
            if cache.count >= TunResolver.maxCacheEntries {
                TunResolver.pruneExpired(&cache)
                if cache.count >= TunResolver.maxCacheEntries {
                    // Keep the seeded servers; drop the rest.
                    cache = cache.filter { $0.value.expiry == Double.greatestFiniteMagnitude }
                }
            }
            cache[key] = Entry(addresses: addresses, expiry: expiry)
        }
    }

    private func remember(directTarget target: String, for key: String) {
        let expiry = TunClock.now() + TunResolver.cacheTtl
        withLock {
            if directTargets.count >= TunResolver.maxCacheEntries {
                TunResolver.pruneExpired(&directTargets)
                if directTargets.count >= TunResolver.maxCacheEntries {
                    directTargets.removeAll()
                }
            }
            directTargets[key] = Entry(addresses: [target], expiry: expiry)
        }
    }

    private static func pruneExpired(_ table: inout [String: Entry]) {
        let now = TunClock.now()
        table = table.filter { $0.value.expiry > now }
    }

    private static func key(_ name: String) -> String {
        var key = name.trimmingCharacters(in: .whitespaces).lowercased()
        while key.hasSuffix(".") {
            key.removeLast()
        }
        return key
    }

    @discardableResult
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
