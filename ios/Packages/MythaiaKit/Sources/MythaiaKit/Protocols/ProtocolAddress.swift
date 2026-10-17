import Foundation

/// Literal-address recognition shared by the request headers of every
/// protocol here. A destination that is not a literal goes on the wire as a
/// name and is never resolved locally: the point of sending a name is that
/// the server resolves it on its own side.
enum ProtocolAddress {
    /// The four bytes of a dotted-quad IPv4 literal, or nil.
    static func ipv4(_ host: String) -> [UInt8]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(4)
        for part in parts {
            guard !part.isEmpty, part.count <= 3 else { return nil }
            guard part.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
            guard let value = Int(part), value <= 255 else { return nil }
            out.append(UInt8(value))
        }
        return out
    }

    /// The sixteen bytes of an IPv6 literal, brackets allowed, or nil.
    static func ipv6(_ host: String) -> [UInt8]? {
        var bare = host
        if bare.hasPrefix("[") && bare.hasSuffix("]") && bare.count >= 2 {
            bare = String(bare.dropFirst().dropLast())
        }
        guard bare.contains(":") else { return nil }
        var address = in6_addr()
        let result = bare.withCString { pointer in
            inet_pton(AF_INET6, pointer, &address)
        }
        guard result == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    /// Renders sixteen bytes as the compact lowercase hex groups Kotlin's
    /// decoders produce (no zero compression).
    static func ipv6Text(_ bytes: [UInt8]) -> String {
        var groups = [String]()
        var i = 0
        while i + 1 < bytes.count {
            let word = (Int(bytes[i]) << 8) | Int(bytes[i + 1])
            groups.append(String(word, radix: 16))
            i += 2
        }
        return groups.joined(separator: ":")
    }

    static func ipv4Text(_ bytes: [UInt8]) -> String {
        return bytes.map { String($0) }.joined(separator: ".")
    }

    /// Big-endian port bytes.
    static func portBytes(_ port: UInt16) -> [UInt8] {
        return [UInt8(truncatingIfNeeded: port >> 8), UInt8(truncatingIfNeeded: port)]
    }

    /// The SOCKS5-style address used by Trojan, Shadowsocks and SOCKS5:
    /// ATYP 0x01 IPv4, 0x03 domain (length-prefixed, at most 255 bytes),
    /// 0x04 IPv6, followed by the big-endian port.
    static func socksAddressPort(host: String, port: UInt16) -> [UInt8] {
        var out = socksAddress(host)
        out.append(contentsOf: portBytes(port))
        return out
    }

    static func socksAddress(_ host: String) -> [UInt8] {
        if let v4 = ipv4(host) {
            return [0x01] + v4
        }
        if let v6 = ipv6(host) {
            return [0x04] + v6
        }
        let name = Array(host.utf8.prefix(255))
        return [0x03, UInt8(name.count)] + name
    }
}
