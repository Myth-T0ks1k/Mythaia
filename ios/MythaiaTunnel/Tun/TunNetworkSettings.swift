import Foundation
import MythaiaKit
import NetworkExtension

/// The interface settings of the packet tunnel in TUN mode: every route goes
/// into the tunnel except the local networks and the proxy servers
/// themselves, and DNS goes to the stack's sentinel address, where it is
/// answered from the fake-IP pool.
enum TunNetworkSettings {

    /// The interface's own IPv4 address. Not 198.18.0.1: that is the first
    /// address the fake-IP pool hands out (offset 1), and the system treats
    /// connections to its own interface address as local, so the domain
    /// that received it would be unreachable. 198.19.0.1 lies in the fake
    /// range's other half, beyond every pool offset, and is never an answer.
    static let interfaceAddressV4 = "198.19.0.1"
    static let interfaceSubnetMaskV4 = "255.255.255.252"

    /// The IPv6 address, in fd00::/64 like the Android app's; the IPv6 DNS
    /// sentinel fd00::1 is on-link there.
    static let interfaceAddressV6 = "fd00::2"
    static let interfacePrefixLengthV6 = 64

    /// lwIP's interface MTU (lwip_bridge.c) and the Android app's.
    static let mtu = 1500

    /// The IPv4 networks the Android app keeps off its tunnel: loopback, the
    /// private ranges and carrier-grade NAT, and a few service ranges it
    /// excludes too. Multicast and the reserved range stay out as well,
    /// since Android never routes them in either.
    static let bypassedIPv4Networks: [(address: String, mask: String)] = [
        ("127.0.0.0", "255.0.0.0"),
        ("10.0.0.0", "255.0.0.0"),
        ("172.16.0.0", "255.240.0.0"),
        ("192.168.0.0", "255.255.0.0"),
        ("100.64.0.0", "255.192.0.0"),
        ("162.14.0.0", "255.255.0.0"),
        ("211.99.96.0", "255.255.224.0"),
        ("162.159.192.0", "255.255.255.0"),
        ("162.159.193.0", "255.255.255.0"),
        ("162.159.195.0", "255.255.255.0"),
        ("224.0.0.0", "240.0.0.0"),
        ("240.0.0.0", "240.0.0.0"),
    ]

    /// Settings for the TUN-mode tunnel.
    ///
    /// - Parameters:
    ///   - remoteAddress: shown by the system as the tunnel's server; the
    ///     first server address, or 127.0.0.1.
    ///   - serverAddresses: every IP the servers resolve to (see
    ///     `resolveServers(of:)`), kept off the tunnel so the app's own
    ///     probes reach them directly.
    ///   - ipv6Dns: also advertise the IPv6 DNS sentinel; pair with
    ///     `TunSettings.ipv6Dns`.
    static func make(remoteAddress: String = "127.0.0.1", serverAddresses: [String] = [], ipv6Dns: Bool = false) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        var excludedV4: [NEIPv4Route] = []
        for network in bypassedIPv4Networks {
            excludedV4.append(NEIPv4Route(destinationAddress: network.address, subnetMask: network.mask))
        }
        var excludedV6: [NEIPv6Route] = [
            NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: NSNumber(value: 10)),
            NEIPv6Route(destinationAddress: "ff00::", networkPrefixLength: NSNumber(value: 8)),
        ]
        for address in serverAddresses {
            guard let bytes = TunAddress.parse(address), let text = TunAddress.text(bytes) else { continue }
            if bytes.count == 4 {
                excludedV4.append(NEIPv4Route(destinationAddress: text, subnetMask: "255.255.255.255"))
            } else {
                excludedV6.append(NEIPv6Route(destinationAddress: text, networkPrefixLength: NSNumber(value: 128)))
            }
        }

        let ipv4 = NEIPv4Settings(addresses: [interfaceAddressV4], subnetMasks: [interfaceSubnetMaskV4])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv4.excludedRoutes = excludedV4
        settings.ipv4Settings = ipv4

        // IPv6 is captured too, even with fake IPv6 answers off: without a
        // route, IPv6 traffic would leave beside the tunnel.
        let prefix = NSNumber(value: interfacePrefixLengthV6)
        let ipv6 = NEIPv6Settings(addresses: [interfaceAddressV6], networkPrefixLengths: [prefix])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        ipv6.excludedRoutes = excludedV6
        settings.ipv6Settings = ipv6

        var dnsServers = [TunConstants.dnsSentinelV4]
        if ipv6Dns {
            dnsServers.append(TunConstants.dnsSentinelV6)
        }
        let dns = NEDNSSettings(servers: dnsServers)
        // Every name, not just some domains, is resolved through the tunnel.
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        settings.mtu = NSNumber(value: mtu)
        return settings
    }

    /// Every server name (the server and each chain hop, plus a resolved IP
    /// the configuration carries) with its addresses, from the system
    /// resolver. Call it before the TUN settings are applied: afterwards the
    /// system's DNS is the stack's.
    static func resolveServers(of configuration: ProxyConfiguration) async -> [String: [String]] {
        var names: [String] = []
        TunStack.collectServerNames(configuration, into: &names)
        var out: [String: [String]] = [:]
        for name in names {
            if TunAddress.isLiteral(name) {
                out[name] = [name]
                continue
            }
            let addresses = await systemResolve(name)
            out[name] = addresses.filter { !FakeIpPool.isFakeIp($0) }
        }
        return out
    }

    /// Every address in `servers`, once each, for `make(serverAddresses:)`.
    static func allAddresses(_ servers: [String: [String]]) -> [String] {
        var out: [String] = []
        for addresses in servers.values {
            for address in addresses where !out.contains(address) {
                out.append(address)
            }
        }
        return out
    }

    private static func systemResolve(_ name: String) async -> [String] {
        await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: TunResolver.resolveWithSystem(name))
            }
        }
    }
}
