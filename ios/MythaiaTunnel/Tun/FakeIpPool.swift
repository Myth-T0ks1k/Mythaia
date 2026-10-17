import Foundation

/// Synthetic ("fake") IP addresses handed out as DNS answers, each standing
/// for one domain name.
///
/// When an app resolves a name through the tunnel it gets a fake IP; when it
/// then connects to that IP, the pool gives the name back, so the router and
/// the proxy see the domain rather than an address. No route is stored here:
/// routing is decided when the connection arrives, so a change of rules
/// applies at once.
///
/// IPv4: 198.18.0.0/15, offsets 1...`poolSize`. IPv6: fc00:: plus the same
/// offset. Once every offset is taken, the least recently used one is
/// reused.
///
/// Every reader and writer takes the lock, so a read from outside the lwIP
/// queue (statistics, diagnostics) cannot tear the LRU list.
final class FakeIpPool: @unchecked Sendable {
    static let poolSize = TunConstants.fakeIPPoolSize
    private static let baseIPv4 = TunConstants.fakeIPPoolBaseIPv4

    private let lock = NSLock()
    private var domainToOffset: [String: Int] = [:]
    private var offsetToDomain: [Int: String] = [:]

    // LRU list over offsets, kept in two arrays indexed by offset (0 means
    // none): O(1) touch and evict without a node object per entry.
    private var lruPrevious: [Int32] = []
    private var lruNext: [Int32] = []
    private var lruHead = 0     // most recently used
    private var lruTail = 0     // least recently used
    private var nextOffset = 1

    /// The offset for `domain` (lowercase), allocated if it has none. Use
    /// `ipv4Bytes` or `ipv6Bytes` for the address.
    func allocate(_ domain: String) -> Int {
        lock.lock()
        defer { lock.unlock() }

        if let existing = domainToOffset[domain] {
            touch(existing)
            return existing
        }
        if lruNext.isEmpty {
            lruPrevious = [Int32](repeating: 0, count: FakeIpPool.poolSize + 1)
            lruNext = [Int32](repeating: 0, count: FakeIpPool.poolSize + 1)
        }

        let offset: Int
        if nextOffset <= FakeIpPool.poolSize {
            offset = nextOffset
            nextOffset += 1
        } else {
            offset = evictLeastRecent()
        }
        domainToOffset[domain] = offset
        offsetToDomain[offset] = domain
        insertAtHead(offset)
        return offset
    }

    /// The domain behind a fake IP in text form, or nil when the address is
    /// not one the pool handed out (or its entry was reused since).
    func lookup(_ ip: String) -> String? {
        guard let bytes = TunAddress.parse(ip) else { return nil }
        return lookup(addressBytes: bytes)
    }

    /// The same for an address as 4 or 16 raw bytes.
    func lookup(addressBytes bytes: [UInt8]) -> String? {
        guard let offset = FakeIpPool.offset(of: bytes) else { return nil }
        lock.lock()
        defer { lock.unlock() }
        guard let domain = offsetToDomain[offset] else { return nil }
        touch(offset)
        return domain
    }

    func reset() {
        lock.lock()
        defer { lock.unlock() }
        domainToOffset.removeAll()
        offsetToDomain.removeAll()
        lruPrevious = []
        lruNext = []
        lruHead = 0
        lruTail = 0
        nextOffset = 1
    }

    /// Entries currently allocated.
    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return domainToOffset.count
    }

    // MARK: - Addresses

    /// Whether `ip` (text form) lies in the fake ranges: 198.18.0.0/15, or
    /// fc00:: plus an offset.
    static func isFakeIp(_ ip: String) -> Bool {
        ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") || ip.hasPrefix("fc00::")
    }

    /// The 4-byte IPv4 address of `offset`.
    static func ipv4Bytes(_ offset: Int) -> [UInt8] {
        let value = baseIPv4 &+ UInt32(truncatingIfNeeded: offset)
        return [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    /// The 16-byte IPv6 address of `offset`: fc00:: plus the offset.
    static func ipv6Bytes(_ offset: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 16)
        out[0] = 0xFC
        out[12] = UInt8((offset >> 24) & 0xFF)
        out[13] = UInt8((offset >> 16) & 0xFF)
        out[14] = UInt8((offset >> 8) & 0xFF)
        out[15] = UInt8(offset & 0xFF)
        return out
    }

    /// The pool offset an address encodes, or nil outside the pool.
    static func offset(of bytes: [UInt8]) -> Int? {
        var offset = 0
        if bytes.count == 4 {
            var value: UInt32 = 0
            for byte in bytes {
                value = (value << 8) | UInt32(byte)
            }
            guard value > baseIPv4 else { return nil }
            offset = Int(value - baseIPv4)
        } else if bytes.count == 16 {
            if bytes[0] != 0xFC || bytes[1] != 0x00 { return nil }
            for index in 2...11 where bytes[index] != 0 {
                return nil
            }
            for index in 12...15 {
                offset = (offset << 8) | Int(bytes[index])
            }
        } else {
            return nil
        }
        if offset < 1 || offset > poolSize { return nil }
        return offset
    }

    // MARK: - LRU (lock held)

    private func touch(_ offset: Int) {
        if lruHead == offset { return }
        unlink(offset)
        insertAtHead(offset)
    }

    private func insertAtHead(_ offset: Int) {
        lruPrevious[offset] = 0
        lruNext[offset] = Int32(lruHead)
        if lruHead != 0 {
            lruPrevious[lruHead] = Int32(offset)
        }
        lruHead = offset
        if lruTail == 0 {
            lruTail = offset
        }
    }

    private func unlink(_ offset: Int) {
        let previous = Int(lruPrevious[offset])
        let next = Int(lruNext[offset])
        if previous != 0 {
            lruNext[previous] = Int32(next)
        } else if lruHead == offset {
            lruHead = next
        }
        if next != 0 {
            lruPrevious[next] = Int32(previous)
        } else if lruTail == offset {
            lruTail = previous
        }
        lruPrevious[offset] = 0
        lruNext[offset] = 0
    }

    private func evictLeastRecent() -> Int {
        // The pool is full, so the list cannot be empty; fall back to offset
        // 1 rather than crash if it somehow is.
        let offset = lruTail
        if offset == 0 { return 1 }
        unlink(offset)
        if let domain = offsetToDomain.removeValue(forKey: offset) {
            domainToOffset.removeValue(forKey: domain)
        }
        return offset
    }
}
