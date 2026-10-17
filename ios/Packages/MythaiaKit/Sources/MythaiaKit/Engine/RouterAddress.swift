import Foundation

/// IP literals as the router and the local proxy see them: parsed to bytes
/// with the system's own parser, so "1.2.3" or "example.com" are never taken
/// for addresses, and turned back into text for the logs and the dialer.
enum RouterAddress {
    /// The 4 or 16 bytes of an IPv4 or IPv6 literal (brackets and an IPv6
    /// zone allowed); nil for anything else, a host name included.
    static func parse(_ text: String) -> [UInt8]? {
        var literal = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if literal.hasPrefix("[") && literal.hasSuffix("]") && literal.count >= 2 {
            literal = String(literal.dropFirst().dropLast())
        }
        if literal.isEmpty { return nil }
        if literal.contains(":") {
            if let percent = literal.firstIndex(of: "%") {
                literal = String(literal[..<percent])
            }
            var address = in6_addr()
            guard inet_pton(AF_INET6, literal, &address) == 1 else { return nil }
            return withUnsafeBytes(of: &address) { Array($0) }
        }
        var address = in_addr()
        guard inet_pton(AF_INET, literal, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    static func isLiteral(_ text: String) -> Bool {
        parse(text) != nil
    }

    /// An IPv4-mapped IPv6 address (::ffff:a.b.c.d) as the IPv4 address it
    /// carries; every other address unchanged. A client may hand either
    /// form, and they are the same destination.
    static func unmapped(_ bytes: [UInt8]) -> [UInt8] {
        guard bytes.count == 16 else { return bytes }
        for index in 0..<10 where bytes[index] != 0 {
            return bytes
        }
        guard bytes[10] == 0xFF && bytes[11] == 0xFF else { return bytes }
        return Array(bytes[12..<16])
    }

    /// The text form of 4 or 16 address bytes.
    static func text(_ bytes: [UInt8]) -> String? {
        let family: Int32
        switch bytes.count {
        case 4: family = AF_INET
        case 16: family = AF_INET6
        default: return nil
        }
        var buffer = [CChar](repeating: 0, count: 64)
        let capacity = socklen_t(buffer.count)
        let converted: Bool = bytes.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return buffer.withUnsafeMutableBufferPointer { out -> Bool in
                guard let target = out.baseAddress else { return false }
                return inet_ntop(family, base, target, capacity) != nil
            }
        }
        guard converted else { return nil }
        let end = buffer.firstIndex(of: 0) ?? buffer.count
        let utf8 = buffer[..<end].map { UInt8(bitPattern: $0) }
        return String(decoding: utf8, as: UTF8.self)
    }

    /// A big-endian IPv4 address as a number, for range lookups.
    static func ipv4Value(_ bytes: [UInt8]) -> UInt32? {
        guard bytes.count == 4 else { return nil }
        var value: UInt32 = 0
        for byte in bytes {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    /// Addresses a proxy cannot reach for this device at all: loopback,
    /// private (RFC 1918 and IPv6 site-local), link-local, unspecified,
    /// multicast, carrier-grade NAT (100.64.0.0/10) and IPv6 unique local
    /// (fc00::/7). They go direct in every mode.
    static func isPrivate(_ address: [UInt8]) -> Bool {
        let bytes = unmapped(address)
        if bytes.count == 4 {
            let first = bytes[0]
            let second = bytes[1]
            if first == 127 || first == 10 { return true }
            if first == 172 && (second & 0xF0) == 16 { return true }
            if first == 192 && second == 168 { return true }
            if first == 169 && second == 254 { return true }
            if first == 100 && (second & 0xC0) == 64 { return true }
            if first >= 224 && first <= 239 { return true }
            if bytes == [0, 0, 0, 0] { return true }
            return false
        }
        guard bytes.count == 16 else { return false }
        var leadingZero = true
        for index in 0..<15 where bytes[index] != 0 {
            leadingZero = false
            break
        }
        if leadingZero && (bytes[15] == 0 || bytes[15] == 1) { return true }
        if bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80 { return true }
        if bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0xC0 { return true }
        if bytes[0] == 0xFF { return true }
        if (bytes[0] & 0xFE) == 0xFC { return true }
        return false
    }
}

/// One network in CIDR notation, IPv4 or IPv6.
struct IPNetwork: Hashable {
    let bytes: [UInt8]
    let prefix: Int

    /// "a.b.c.d/n", "v6::/n" or a bare address (a single host). Host names
    /// are refused: resolving one here would be a lookup per rule.
    static func parse(_ text: String) -> IPNetwork? {
        let parts = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first else { return nil }
        guard let parsed = RouterAddress.parse(String(first)) else { return nil }
        // A mapped IPv6 network is its IPv4 network.
        let bytes: [UInt8]
        var prefix: Int
        let width = parsed.count * 8
        if parts.count > 1 {
            guard let value = Int(parts[1].trimmingCharacters(in: .whitespaces)) else { return nil }
            prefix = value
        } else {
            prefix = width
        }
        guard prefix >= 0 && prefix <= width else { return nil }
        let unmapped = RouterAddress.unmapped(parsed)
        if unmapped.count == 4 && parsed.count == 16 {
            guard prefix >= 96 else { return nil }
            prefix -= 96
            bytes = unmapped
        } else {
            bytes = parsed
        }
        return IPNetwork(bytes: IPNetwork.masked(bytes, prefix: prefix), prefix: prefix)
    }

    init(bytes: [UInt8], prefix: Int) {
        self.bytes = bytes
        self.prefix = prefix
    }

    func contains(_ address: [UInt8]) -> Bool {
        guard address.count == bytes.count else { return false }
        var remaining = prefix
        for index in 0..<bytes.count {
            if remaining <= 0 { return true }
            let mask: UInt8 = remaining >= 8 ? 0xFF : UInt8(truncatingIfNeeded: 0xFF << (8 - remaining))
            if (address[index] & mask) != (bytes[index] & mask) { return false }
            remaining -= 8
        }
        return true
    }

    /// First and last address of an IPv4 network.
    var ipv4Range: (start: UInt32, end: UInt32)? {
        guard bytes.count == 4, let start = RouterAddress.ipv4Value(bytes) else { return nil }
        let hostBits = 32 - prefix
        let span: UInt32 = hostBits >= 32 ? UInt32.max : ((UInt32(1) << UInt32(hostBits)) &- 1)
        return (start, start | span)
    }

    private static func masked(_ bytes: [UInt8], prefix: Int) -> [UInt8] {
        var out = bytes
        var remaining = prefix
        for index in 0..<out.count {
            if remaining >= 8 {
                remaining -= 8
                continue
            }
            let mask: UInt8 = remaining <= 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - remaining))
            out[index] &= mask
            remaining = 0
        }
        return out
    }
}

/// IPv4 networks as sorted, merged ranges with a binary search: a country
/// list of over ten thousand networks is a lookup of about fourteen steps
/// instead of a scan.
struct IPv4RangeSet {
    private(set) var starts: [UInt32] = []
    private(set) var ends: [UInt32] = []

    init(_ networks: [IPNetwork]) {
        var ranges: [(start: UInt32, end: UInt32)] = []
        ranges.reserveCapacity(networks.count)
        for network in networks {
            if let range = network.ipv4Range { ranges.append(range) }
        }
        ranges.sort { left, right in
            if left.start != right.start { return left.start < right.start }
            return left.end < right.end
        }
        var mergedStarts: [UInt32] = []
        var mergedEnds: [UInt32] = []
        for range in ranges {
            if let lastEnd = mergedEnds.last {
                // Adjacent or overlapping: extend the last range.
                let touches = lastEnd == UInt32.max || range.start <= lastEnd + 1
                if touches {
                    if range.end > lastEnd { mergedEnds[mergedEnds.count - 1] = range.end }
                    continue
                }
            }
            mergedStarts.append(range.start)
            mergedEnds.append(range.end)
        }
        starts = mergedStarts
        ends = mergedEnds
    }

    var count: Int { starts.count }
    var isEmpty: Bool { starts.isEmpty }

    func contains(_ address: UInt32) -> Bool {
        var low = 0
        var high = starts.count - 1
        var candidate = -1
        while low <= high {
            let middle = (low + high) / 2
            if starts[middle] <= address {
                candidate = middle
                low = middle + 1
            } else {
                high = middle - 1
            }
        }
        guard candidate >= 0 else { return false }
        return address <= ends[candidate]
    }
}
