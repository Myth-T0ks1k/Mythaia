import Foundation

/// The addresses and routes the packet tunnel's interface is given.
public struct TunnelSettings: Codable, Hashable {
    public var address: String
    public var prefixLength: Int
    public var gateway: String
    public var dnsServers: [String]
    public var mtu: Int
    public var ipv6Enabled: Bool
    public var ipv6Address: String
    public var ipv6PrefixLength: Int
    public var bypassRoutes: [String]

    public static let defaultBypassRoutes: [String] = [
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
    ]

    public init(
        address: String = "10.8.0.2",
        prefixLength: Int = 24,
        gateway: String = "10.8.0.1",
        dnsServers: [String] = ["1.1.1.1", "1.0.0.1"],
        mtu: Int = 1500,
        ipv6Enabled: Bool = false,
        ipv6Address: String = "fd00::2",
        ipv6PrefixLength: Int = 64,
        bypassRoutes: [String] = TunnelSettings.defaultBypassRoutes
    ) {
        self.address = address
        self.prefixLength = prefixLength
        self.gateway = gateway
        self.dnsServers = dnsServers
        self.mtu = mtu
        self.ipv6Enabled = ipv6Enabled
        self.ipv6Address = ipv6Address
        self.ipv6PrefixLength = ipv6PrefixLength
        self.bypassRoutes = bypassRoutes
    }

    private enum CodingKeys: String, CodingKey {
        case address, prefixLength, gateway, dnsServers, mtu, ipv6Enabled, ipv6Address, ipv6PrefixLength, bypassRoutes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        address = try c.decodeIfPresent(String.self, forKey: .address) ?? "10.8.0.2"
        prefixLength = try c.decodeIfPresent(Int.self, forKey: .prefixLength) ?? 24
        gateway = try c.decodeIfPresent(String.self, forKey: .gateway) ?? "10.8.0.1"
        dnsServers = try c.decodeIfPresent([String].self, forKey: .dnsServers) ?? ["1.1.1.1", "1.0.0.1"]
        mtu = try c.decodeIfPresent(Int.self, forKey: .mtu) ?? 1500
        ipv6Enabled = try c.decodeIfPresent(Bool.self, forKey: .ipv6Enabled) ?? false
        ipv6Address = try c.decodeIfPresent(String.self, forKey: .ipv6Address) ?? "fd00::2"
        ipv6PrefixLength = try c.decodeIfPresent(Int.self, forKey: .ipv6PrefixLength) ?? 64
        bypassRoutes = try c.decodeIfPresent([String].self, forKey: .bypassRoutes) ?? TunnelSettings.defaultBypassRoutes
    }
}
