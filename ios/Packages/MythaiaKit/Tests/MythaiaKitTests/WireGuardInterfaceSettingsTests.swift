import Foundation
import XCTest
@testable import MythaiaKit

/// The interface a WireGuard profile asks the system for: its own addresses,
/// DNS and MTU, its AllowedIPs as the routes, and its peer kept out of them.
final class WireGuardInterfaceSettingsTests: XCTestCase {
    private let privateKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8($0) }))
    private let peerKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))

    private func parse(interface: [String], peer: [String]) throws -> WireGuardConfig {
        var lines = ["[Interface]", "PrivateKey = \(privateKey)"]
        lines += interface
        lines += ["", "[Peer]", "PublicKey = \(peerKey)"]
        lines += peer
        return try WireGuardConfig.parse(lines.joined(separator: "\n"))
    }

    func testAnOrdinaryProfile() throws {
        let config = try parse(
            interface: ["Address = 10.8.0.2/24, fd00::2/64", "DNS = 192.0.2.53, 2001:db8::53, corp.example", "MTU = 1380"],
            peer: ["Endpoint = 192.0.2.7:51820", "AllowedIPs = 0.0.0.0/0, ::/0"]
        )
        let settings = try WireGuardInterfaceSettings.make(config, endpointAddresses: ["192.0.2.7"])

        XCTAssertEqual(settings.ipv4Addresses, [.init(address: "10.8.0.2", subnetMask: "255.255.255.0")])
        XCTAssertEqual(settings.ipv6Addresses, [.init(address: "fd00::2", prefixLength: 64)])
        XCTAssertEqual(settings.ipv4Routes, [.init(address: "0.0.0.0", subnetMask: "0.0.0.0")])
        XCTAssertEqual(settings.ipv6Routes, [.init(address: "::", prefixLength: 0)])
        // The peer's own address stays outside, or its datagrams would loop.
        XCTAssertEqual(settings.ipv4ExcludedRoutes, [.init(address: "192.0.2.7", subnetMask: "255.255.255.255")])
        XCTAssertTrue(settings.ipv6ExcludedRoutes.isEmpty)
        // A name in DNS is a search domain, as wg-quick reads it.
        XCTAssertEqual(settings.dnsServers, ["192.0.2.53", "2001:db8::53"])
        XCTAssertEqual(settings.searchDomains, ["corp.example"])
        XCTAssertEqual(settings.mtu, 1380)
    }

    func testRoutesWithHostBitsSetBecomeTheirNetwork() throws {
        // wg-quick takes 10.0.0.2/24; the system wants 10.0.0.0, and refusing
        // the entry would take the whole subnet out of the tunnel.
        let config = try parse(
            interface: ["Address = 10.0.0.2/32"],
            peer: ["Endpoint = 192.0.2.7:51820", "AllowedIPs = 10.0.0.2/24, 198.51.100.77/30, 2001:db8:1:2::5/48"]
        )
        let settings = try WireGuardInterfaceSettings.make(config, endpointAddresses: [])
        XCTAssertEqual(settings.ipv4Routes, [
            .init(address: "10.0.0.0", subnetMask: "255.255.255.0"),
            .init(address: "198.51.100.76", subnetMask: "255.255.255.252"),
        ])
        XCTAssertEqual(settings.ipv6Routes, [.init(address: "2001:db8:1::", prefixLength: 48)])
    }

    func testAnUnusableEntryIsSkippedNotFatal() throws {
        let config = try parse(
            interface: ["Address = 10.0.0.2/33, nonsense, 10.0.0.3"],
            peer: ["Endpoint = 192.0.2.7:51820", "AllowedIPs = 192.0.2.0/24, 300.1.1.1/8, ::/129"]
        )
        let settings = try WireGuardInterfaceSettings.make(config, endpointAddresses: [])
        // A bare address is a single host.
        XCTAssertEqual(settings.ipv4Addresses, [.init(address: "10.0.0.3", subnetMask: "255.255.255.255")])
        XCTAssertEqual(settings.ipv4Routes, [.init(address: "192.0.2.0", subnetMask: "255.255.255.0")])
        XCTAssertTrue(settings.ipv6Routes.isEmpty)
    }

    func testAProfileWithNoUsableAddressOrRouteIsRefused() throws {
        let noAddress = try parse(interface: [], peer: ["Endpoint = 192.0.2.7:51820"])
        XCTAssertThrowsError(try WireGuardInterfaceSettings.make(noAddress, endpointAddresses: []))

        let noRoute = try parse(interface: ["Address = 10.0.0.2/32"], peer: ["Endpoint = 192.0.2.7:51820", "AllowedIPs = bogus"])
        XCTAssertThrowsError(try WireGuardInterfaceSettings.make(noRoute, endpointAddresses: []))
    }

    func testEveryEndpointAddressIsExcludedOnce() throws {
        let config = try parse(interface: ["Address = 10.0.0.2/32"], peer: ["Endpoint = vpn.example.com:51820"])
        let settings = try WireGuardInterfaceSettings.make(
            config,
            endpointAddresses: ["192.0.2.7", "2001:db8::7", "192.0.2.7", "not-an-address"]
        )
        XCTAssertEqual(settings.ipv4ExcludedRoutes, [.init(address: "192.0.2.7", subnetMask: "255.255.255.255")])
        XCTAssertEqual(settings.ipv6ExcludedRoutes, [.init(address: "2001:db8::7", prefixLength: 128)])
    }

    func testSubnetMasks() {
        XCTAssertEqual(WireGuardInterfaceSettings.subnetMask(0), "0.0.0.0")
        XCTAssertEqual(WireGuardInterfaceSettings.subnetMask(1), "128.0.0.0")
        XCTAssertEqual(WireGuardInterfaceSettings.subnetMask(20), "255.255.240.0")
        XCTAssertEqual(WireGuardInterfaceSettings.subnetMask(31), "255.255.255.254")
        XCTAssertEqual(WireGuardInterfaceSettings.subnetMask(32), "255.255.255.255")
    }
}
