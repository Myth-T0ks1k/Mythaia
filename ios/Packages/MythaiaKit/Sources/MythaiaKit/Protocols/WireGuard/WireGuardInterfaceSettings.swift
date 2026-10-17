import Foundation

/// The interface a WireGuard profile asks for, in the shape the system's tunnel
/// settings take: addresses with masks, routes as network addresses, and the
/// DNS servers apart from search domains.
///
/// Built from the profile's own `[Interface]` and `AllowedIPs` rather than the
/// app-wide layout: a WireGuard peer states exactly what it routes, and that
/// list is the split tunnel. An entry that cannot be used is skipped with a
/// warning rather than failing the whole tunnel; only a profile left with no
/// address or no route at all is refused.
public struct WireGuardInterfaceSettings: Equatable {
    public struct IPv4Entry: Equatable {
        public var address: String
        public var subnetMask: String

        public init(address: String, subnetMask: String) {
            self.address = address
            self.subnetMask = subnetMask
        }
    }

    public struct IPv6Entry: Equatable {
        public var address: String
        public var prefixLength: Int

        public init(address: String, prefixLength: Int) {
            self.address = address
            self.prefixLength = prefixLength
        }
    }

    public var ipv4Addresses: [IPv4Entry] = []
    public var ipv6Addresses: [IPv6Entry] = []
    /// `AllowedIPs`, host bits cleared.
    public var ipv4Routes: [IPv4Entry] = []
    public var ipv6Routes: [IPv6Entry] = []
    /// The peer's own addresses, kept out of the tunnel so the datagrams that
    /// carry it never loop back into it.
    public var ipv4ExcludedRoutes: [IPv4Entry] = []
    public var ipv6ExcludedRoutes: [IPv6Entry] = []
    public var dnsServers: [String] = []
    /// `DNS` entries that are names rather than addresses, which wg-quick
    /// treats as search domains.
    public var searchDomains: [String] = []
    public var mtu: Int = WireGuardConfig.defaultMtu

    public init() {}

    /// The settings for `config`, with `endpointAddresses` (the peer's
    /// resolved addresses) excluded from the routes.
    ///
    /// Throws `invalidConfiguration` when no address or no route is usable.
    public static func make(_ config: WireGuardConfig, endpointAddresses: [String]) throws -> WireGuardInterfaceSettings {
        var out = WireGuardInterfaceSettings()
        out.mtu = config.mtu

        for entry in config.addresses {
            guard let cidr = parseCidr(entry, clearHostBits: false), let text = RouterAddress.text(cidr.bytes) else {
                Log.warning("[WG] Address \(entry) is not usable; skipped")
                continue
            }
            if cidr.bytes.count == 4 {
                out.ipv4Addresses.append(IPv4Entry(address: text, subnetMask: subnetMask(cidr.prefix)))
            } else {
                out.ipv6Addresses.append(IPv6Entry(address: text, prefixLength: cidr.prefix))
            }
        }
        if out.ipv4Addresses.isEmpty && out.ipv6Addresses.isEmpty {
            throw MythaiaError.invalidConfiguration("the WireGuard profile has no usable [Interface] Address")
        }

        for entry in config.peer.allowedIps {
            // wg-quick accepts a route with host bits set; the system's
            // settings want the network, and refusing it would silently take
            // the whole subnet out of the tunnel.
            guard let cidr = parseCidr(entry, clearHostBits: true), let text = RouterAddress.text(cidr.bytes) else {
                Log.warning("[WG] AllowedIPs entry \(entry) is not usable; skipped")
                continue
            }
            if cidr.bytes.count == 4 {
                let route = IPv4Entry(address: text, subnetMask: subnetMask(cidr.prefix))
                if !out.ipv4Routes.contains(route) { out.ipv4Routes.append(route) }
            } else {
                let route = IPv6Entry(address: text, prefixLength: cidr.prefix)
                if !out.ipv6Routes.contains(route) { out.ipv6Routes.append(route) }
            }
        }
        if out.ipv4Routes.isEmpty && out.ipv6Routes.isEmpty {
            throw MythaiaError.invalidConfiguration("the WireGuard profile has no usable AllowedIPs")
        }

        for address in endpointAddresses {
            guard let bytes = RouterAddress.parse(address), let text = RouterAddress.text(bytes) else { continue }
            if bytes.count == 4 {
                let route = IPv4Entry(address: text, subnetMask: "255.255.255.255")
                if !out.ipv4ExcludedRoutes.contains(route) { out.ipv4ExcludedRoutes.append(route) }
            } else {
                let route = IPv6Entry(address: text, prefixLength: 128)
                if !out.ipv6ExcludedRoutes.contains(route) { out.ipv6ExcludedRoutes.append(route) }
            }
        }

        for entry in config.dnsServers {
            let trimmed = entry.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            if let bytes = RouterAddress.parse(trimmed), let text = RouterAddress.text(bytes) {
                if !out.dnsServers.contains(text) { out.dnsServers.append(text) }
            } else if !out.searchDomains.contains(trimmed) {
                out.searchDomains.append(trimmed)
            }
        }
        return out
    }

    /// `address/prefix` (a bare address is a single host) as its bytes and
    /// prefix length; nil for anything that is not an IP literal with a prefix
    /// in range.
    static func parseCidr(_ text: String, clearHostBits: Bool) -> (bytes: [UInt8], prefix: Int)? {
        let parts = text.trimmingCharacters(in: .whitespaces)
            .split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first, let bytes = RouterAddress.parse(String(first)) else { return nil }
        let width = bytes.count * 8
        var prefix = width
        if parts.count > 1 {
            guard let value = Int(parts[1].trimmingCharacters(in: .whitespaces)), value >= 0, value <= width else {
                return nil
            }
            prefix = value
        }
        guard clearHostBits else { return (bytes, prefix) }
        var network = bytes
        var remaining = prefix
        for index in 0..<network.count {
            if remaining >= 8 {
                remaining -= 8
                continue
            }
            let mask: UInt8 = remaining <= 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - remaining))
            network[index] &= mask
            remaining = 0
        }
        return (network, prefix)
    }

    /// A dotted IPv4 mask for `prefix` bits.
    static func subnetMask(_ prefix: Int) -> String {
        let bits = max(0, min(32, prefix))
        let value: UInt32 = bits == 0 ? 0 : UInt32.max << UInt32(32 - bits)
        return "\(value >> 24).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
    }
}
