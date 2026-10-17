import Foundation
import XCTest
@testable import MythaiaKit

/// The wg-quick INI a user pastes in, and the AmneziaWG fields on top of it.
final class WireGuardConfigTests: XCTestCase {
    private let privateBytes = Data((0..<32).map { UInt8($0) })
    private let peerBytes = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) })
    private var privateKey: String { WireGuardConfig.encodeKey(privateBytes) }
    private var peerKey: String { WireGuardConfig.encodeKey(peerBytes) }

    private func config(extraInterface: String = "", extraPeer: String = "") -> String {
        """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.8.0.2/32, fd00::2/128
        DNS = 192.0.2.53, 192.0.2.54
        MTU = 1380
        \(extraInterface)

        [Peer]
        PublicKey = \(peerKey)
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        \(extraPeer)
        """
    }

    // MARK: - Basics

    func testParsesAnOrdinaryWgQuickConfig() throws {
        let parsed = try WireGuardConfig.parse(config())

        XCTAssertEqual(parsed.privateKey, privateBytes)
        XCTAssertEqual(parsed.addresses, ["10.8.0.2/32", "fd00::2/128"])
        XCTAssertEqual(parsed.dnsServers, ["192.0.2.53", "192.0.2.54"])
        XCTAssertEqual(parsed.mtu, 1380)

        XCTAssertEqual(parsed.peer.publicKey, peerBytes)
        XCTAssertEqual(parsed.peer.endpointHost, "vpn.example.com")
        XCTAssertEqual(parsed.peer.endpointPort, 51820)
        XCTAssertEqual(parsed.peer.allowedIps, ["0.0.0.0/0", "::/0"])
        XCTAssertEqual(parsed.peer.persistentKeepalive, 25)
        XCTAssertNil(parsed.peer.presharedKey)

        // A plain config is not AmneziaWG.
        XCTAssertFalse(parsed.amnezia.isEnabled)
    }

    func testThePublicKeyIsDerivedNotStored() throws {
        let parsed = try WireGuardConfig.parse(config())
        XCTAssertEqual([UInt8](parsed.publicKey), try WireGuardCrypto.publicKey([UInt8](parsed.privateKey)))
    }

    func testKeysAreMatchedCaseInsensitivelyAsWgQuickDoes() throws {
        let parsed = try WireGuardConfig.parse(
            "[Interface]\nprivatekey = \(privateKey)\nADDRESS = 10.8.0.2/32\n\n[PEER]\nPublicKey = \(peerKey)\nendpoint = example.com:1234\n"
        )
        XCTAssertEqual(parsed.peer.endpointHost, "example.com")
        XCTAssertEqual(parsed.addresses, ["10.8.0.2/32"])
    }

    func testCommentsAndBlankLinesAreIgnored() throws {
        let parsed = try WireGuardConfig.parse(
            "# a comment\n[Interface]\nPrivateKey = \(privateKey)   # trailing comment\n; another comment\n\n"
                + "[Peer]\nPublicKey = \(peerKey)\nEndpoint = example.com:1234\n"
        )
        XCTAssertEqual(parsed.privateKey, privateBytes)
        XCTAssertEqual(parsed.peer.endpointPort, 1234)
    }

    func testAnAbsentMtuFallsBackToWhatWgQuickUses() throws {
        let parsed = try WireGuardConfig.parse(
            "[Interface]\nPrivateKey = \(privateKey)\n\n[Peer]\nPublicKey = \(peerKey)\nEndpoint = example.com:1234\n"
        )
        XCTAssertEqual(parsed.mtu, WireGuardConfig.defaultMtu)
        // An absent AllowedIPs routes everything, which is the common case.
        XCTAssertEqual(parsed.peer.allowedIps, ["0.0.0.0/0", "::/0"])
    }

    func testAPresharedKeyIsReadWhenPresent() throws {
        let psk = WireGuardConfig.encodeKey(Data(repeating: 9, count: 32))
        let parsed = try WireGuardConfig.parse(config(extraPeer: "PresharedKey = \(psk)"))
        XCTAssertEqual(parsed.peer.presharedKey, Data(repeating: 9, count: 32))
    }

    // MARK: - Endpoints

    func testABracketedIPv6EndpointIsSplitCorrectly() throws {
        let parsed = try WireGuardConfig.parse(
            config().replacingOccurrences(of: "Endpoint = vpn.example.com:51820", with: "Endpoint = [2001:db8::1]:51820")
        )
        XCTAssertEqual(parsed.peer.endpointHost, "2001:db8::1")
        XCTAssertEqual(parsed.peer.endpointPort, 51820)
    }

    func testAnUnbracketedIPv6EndpointIsRefusedRatherThanTruncated() {
        // Splitting on the last colon would give "2001:db8:" and port 1.
        XCTAssertThrowsError(try WireGuardConfig.parse(
            config().replacingOccurrences(of: "Endpoint = vpn.example.com:51820", with: "Endpoint = 2001:db8::1:51820")
        ))
    }

    func testAnEndpointWithoutAUsablePortIsRefused() {
        for endpoint in ["example.com", "example.com:", "example.com:abc", "example.com:0", "example.com:70000", ":51820"] {
            XCTAssertThrowsError(try WireGuardConfig.parse(
                config().replacingOccurrences(of: "Endpoint = vpn.example.com:51820", with: "Endpoint = \(endpoint)")
            ), endpoint)
        }
    }

    // MARK: - Missing or bad fields

    func testAConfigMissingWhatItNeedsSaysSo() {
        XCTAssertThrowsError(try WireGuardConfig.parse("[Interface]\n\n[Peer]\nPublicKey = \(peerKey)\nEndpoint = a.b:1"), "no private key")
        XCTAssertThrowsError(try WireGuardConfig.parse("[Interface]\nPrivateKey = \(privateKey)"), "no peer")
        XCTAssertThrowsError(try WireGuardConfig.parse("[Interface]\nPrivateKey = \(privateKey)\n\n[Peer]\nEndpoint = a.b:1"), "no peer public key")
        XCTAssertThrowsError(try WireGuardConfig.parse("[Interface]\nPrivateKey = \(privateKey)\n\n[Peer]\nPublicKey = \(peerKey)"), "no endpoint")
    }

    func testAKeyOfTheWrongLengthIsRefusedNotSilentlyTruncated() {
        let short = Data(count: 16).base64EncodedString()
        XCTAssertThrowsError(try WireGuardConfig.parse(config().replacingOccurrences(of: privateKey, with: short)), "short private key")
        XCTAssertThrowsError(try WireGuardConfig.parse(config().replacingOccurrences(of: peerKey, with: short)), "short peer key")
    }

    func testOnlyTheFirstPeerIsUsed() throws {
        // Silently dialling a peer the user did not expect would be worse than
        // ignoring the extras.
        let otherKey = WireGuardConfig.encodeKey(Data(repeating: 5, count: 32))
        let parsed = try WireGuardConfig.parse(config() + "\n\n[Peer]\nPublicKey = \(otherKey)\nEndpoint = 192.0.2.99:9999")
        XCTAssertEqual(parsed.peer.endpointHost, "vpn.example.com")
        XCTAssertEqual(parsed.peer.publicKey, peerBytes)
    }

    // MARK: - AmneziaWG

    func testAmneziaWGParametersAreReadFromTheInterfaceSection() throws {
        let parsed = try WireGuardConfig.parse(config(extraInterface: [
            "Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 15", "S2 = 30",
            "H1 = 1234567", "H2 = 7654321", "H3 = 1122334", "H4 = 4433221",
        ].joined(separator: "\n")))

        let a = parsed.amnezia
        XCTAssertTrue(a.isEnabled)
        XCTAssertEqual(a.junkPacketCount, 4)
        XCTAssertEqual(a.junkPacketMinSize, 40)
        XCTAssertEqual(a.junkPacketMaxSize, 70)
        XCTAssertEqual(a.initPacketJunkSize, 15)
        XCTAssertEqual(a.responsePacketJunkSize, 30)
        XCTAssertEqual(a.initPacketMagicHeader, 1_234_567)
        XCTAssertEqual(a.transportPacketMagicHeader, 4_433_221)
        // The full 32-bit value reaches the wire, not just its low byte.
        XCTAssertEqual(a.transportType, 4_433_221)
        XCTAssertEqual(a.initiationType, 1_234_567)
    }

    func testAHeaderAbove2To31KeepsAllFourOctets() throws {
        // H values are drawn up to 2^32 - 1; a signed 32-bit detour would
        // still write the right octets, but a byte or a 16-bit one would not.
        let parsed = try WireGuardConfig.parse(config(extraInterface: "H4 = 4294967040"))
        XCTAssertEqual(parsed.amnezia.transportType, 0xFFFF_FF00)
        let transport = WireGuardTransport(
            sendKey: [UInt8](repeating: 1, count: 32), receiveKey: [UInt8](repeating: 2, count: 32),
            peerIndex: 1, localIndex: 2, transportType: parsed.amnezia.transportType
        )
        XCTAssertEqual([UInt8](try transport.encapsulate(Data()).prefix(4)), [0x00, 0xFF, 0xFF, 0xFF])
    }

    func testAKeyWrittenTwiceKeepsBothValues() throws {
        // wg-quick takes the union of repeated Address, DNS and AllowedIPs
        // lines. Dropping the first would send that whole family in the clear.
        let parsed = try WireGuardConfig.parse([
            "[Interface]", "PrivateKey = \(privateKey)", "Address = 10.0.0.2/32", "Address = fd00::2/128",
            "DNS = 192.0.2.53", "DNS = 192.0.2.54", "",
            "[Peer]", "PublicKey = \(peerKey)", "Endpoint = example.com:51820", "AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0",
        ].joined(separator: "\n"))

        XCTAssertEqual(parsed.addresses, ["10.0.0.2/32", "fd00::2/128"])
        XCTAssertEqual(parsed.dnsServers, ["192.0.2.53", "192.0.2.54"])
        XCTAssertEqual(parsed.peer.allowedIps, ["0.0.0.0/0", "::/0"])
    }

    func testARepeatedSingleValuedKeyTakesTheLastOne() throws {
        let parsed = try WireGuardConfig.parse([
            "[Interface]", "PrivateKey = \(privateKey)", "MTU = 1280", "MTU = 1420", "",
            "[Peer]", "PublicKey = \(peerKey)", "Endpoint = example.com:51820",
        ].joined(separator: "\n"))
        XCTAssertEqual(parsed.mtu, 1420)
    }

    func testTheAmneziaWGDefaultsArePlainWireGuard() {
        let a = AmneziaSettings()
        XCTAssertFalse(a.isEnabled)
        XCTAssertEqual(a.initPacketMagicHeader, 1)
        XCTAssertEqual(a.responsePacketMagicHeader, 2)
        XCTAssertEqual(a.underloadPacketMagicHeader, 3)
        XCTAssertEqual(a.transportPacketMagicHeader, 4)
        XCTAssertEqual(a.initiationType, WireGuardHandshake.messageInitiation)
        XCTAssertEqual(a.responseType, WireGuardHandshake.messageResponse)
        XCTAssertEqual(a.cookieType, WireGuardHandshake.messageCookie)
        XCTAssertEqual(a.transportType, WireGuardHandshake.messageTransport)
    }

    func testJunkSizesStayInsideTheConfiguredRange() {
        let settings = AmneziaSettings(junkPacketCount: 5, junkPacketMinSize: 40, junkPacketMaxSize: 70)
        for _ in 0..<200 {
            let size = settings.junkSize()
            XCTAssertTrue((40...70).contains(size), "size \(size) outside 40...70")
        }

        // A single-value range does not need a random draw at all.
        XCTAssertEqual(AmneziaSettings(junkPacketMinSize: 50, junkPacketMaxSize: 50).junkSize(), 50)

        // No junk configured means no junk packet.
        XCTAssertEqual(AmneziaSettings().junkSize(), 0)
    }

    func testAReversedJunkRangeDoesNotTrap() {
        // Typed the wrong way round in a config someone pasted; it must not
        // take the tunnel down.
        let settings = AmneziaSettings(junkPacketMinSize: 90, junkPacketMaxSize: 40)
        for _ in 0..<50 {
            XCTAssertGreaterThanOrEqual(settings.junkSize(), 0)
        }
    }
}
