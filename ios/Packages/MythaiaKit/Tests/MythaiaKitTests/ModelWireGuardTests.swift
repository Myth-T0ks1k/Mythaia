import XCTest
@testable import MythaiaKit

/**
 * WireGuard as `wireguard://` and `wg://` share links (as v2rayNG and Hiddify
 * write them), as a pasted `wg-quick` INI, and as the field-by-field form.
 */
final class ModelWireGuardTests: XCTestCase {

    private let privateBytes = Data((0..<32).map { UInt8($0 + 1) })
    // Chosen so the base64 has '+', '/' and '=' in it, which is what a link mangles.
    private let peerBytes = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 37 + 251) })
    private let pskBytes = Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 5) })

    private var privateKey: String { WireGuardConfig.encodeKey(privateBytes) }
    private var peerKey: String { WireGuardConfig.encodeKey(peerBytes) }
    private var psk: String { WireGuardConfig.encodeKey(pskBytes) }

    private func enc(_ s: String) -> String { LinkText.urlEncode(s) }

    private func ini(_ config: ProxyConfiguration, file: StaticString = #filePath, line: UInt = #line) throws -> WireGuardConfig {
        XCTAssertEqual(config.outboundProtocol, .wireguard, file: file, line: line)
        return try WireGuardConfig.parse(XCTUnwrap(config.wireGuardConfig))
    }

    // MARK: - Links

    func testAV2rayNGWireguardLinkBecomesTheIniItStandsFor() throws {
        let link = "wireguard://\(enc(privateKey))@192.0.2.162:2408" +
            "?publickey=\(enc(peerKey))&address=\(enc("172.16.0.2/32,2001:db8:110:8a36::2/128"))" +
            "&mtu=1280&reserved=1,2,3&presharedkey=\(enc(psk))#WARP%20DE"
        XCTAssertTrue(ProxyConfiguration.canParseUrl(link))

        let config = try ProxyConfiguration.fromUrl(link)
        XCTAssertEqual(config.name, "WARP DE")
        XCTAssertEqual(config.serverAddress, "192.0.2.162")
        XCTAssertEqual(config.serverPort, 2408)

        let parsed = try ini(config)
        XCTAssertEqual(parsed.privateKey, privateBytes)
        XCTAssertEqual(parsed.peer.publicKey, peerBytes)
        XCTAssertEqual(parsed.peer.presharedKey, pskBytes)
        XCTAssertEqual(parsed.addresses, ["172.16.0.2/32", "2001:db8:110:8a36::2/128"])
        XCTAssertEqual(parsed.mtu, 1280)
        XCTAssertEqual(parsed.reserved, Data([1, 2, 3]))
        XCTAssertEqual(parsed.peer.allowedIps, ["0.0.0.0/0", "::/0"])
    }

    func testAHiddifyWgLinkWithKeysInTheQueryParsesTheSame() throws {
        let link = "wg://wg.example.com:2408?pk=\(enc(privateKey))" +
            "&local_address=172.16.0.2/32,2001:db8:110:8a36::2/128&peer_pk=\(enc(peerKey))" +
            "&pre_shared_key=\(enc(psk))&reserved=AQID&mtu=1330&workers=2#Hiddify%20WARP"
        XCTAssertTrue(ProxyConfiguration.canParseUrl(link))

        let config = try ProxyConfiguration.fromUrl(link)
        XCTAssertEqual(config.name, "Hiddify WARP")
        XCTAssertEqual(config.serverAddress, "wg.example.com")

        let parsed = try ini(config)
        XCTAssertEqual(parsed.privateKey, privateBytes)
        XCTAssertEqual(parsed.peer.publicKey, peerBytes)
        XCTAssertEqual(parsed.peer.presharedKey, pskBytes)
        XCTAssertEqual(parsed.mtu, 1330)
        XCTAssertEqual(parsed.reserved, Data([1, 2, 3]))
        XCTAssertEqual(parsed.addresses.count, 2)
    }

    func testSpellingsCrossSchemesAndKeysSurviveTheShapesLinksPutThemIn() throws {
        // wg:// with the key as userinfo, v2rayNG's publickey, a URL-safe key
        // with its padding stripped, and an upper-case parameter name.
        var urlSafePeer = peerKey.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while urlSafePeer.hasSuffix("=") { urlSafePeer.removeLast() }
        let link = "wg://\(enc(privateKey))@10.0.0.1:51820?PublicKey=\(urlSafePeer)&address=10.9.0.2"
        let parsed = try ini(ProxyConfiguration.fromUrl(link))
        XCTAssertEqual(parsed.peer.publicKey, peerBytes)
        // A bare address gets the host prefix the INI wants.
        XCTAssertEqual(parsed.addresses, ["10.9.0.2/32"])
        XCTAssertNil(parsed.reserved)

        // Hex keys, as Xray also accepts them.
        let hexPrivate = privateBytes.map { String(format: "%02x", $0) }.joined()
        let hex = try ini(ProxyConfiguration.fromUrl("wireguard://\(hexPrivate)@10.0.0.1:51820?peer_pk=\(enc(peerKey))"))
        XCTAssertEqual(hex.privateKey, privateBytes)
    }

    func testAnIPv6EndpointStaysBracketedAndTheDefaultNameIsWireGuard() throws {
        let link = "wireguard://\(enc(privateKey))@[2001:db8:d0::a29f:c001]:2408?publickey=\(enc(peerKey))&address=172.16.0.2/32"
        let config = try ProxyConfiguration.fromUrl(link)
        XCTAssertEqual(config.serverAddress, "2001:db8:d0::a29f:c001")
        XCTAssertEqual(config.name, "WireGuard")
        XCTAssertEqual(try ini(config).peer.endpointHost, "2001:db8:d0::a29f:c001")
        XCTAssertTrue(config.wireGuardConfig?.contains("Endpoint = [2001:db8:d0::a29f:c001]:2408") == true)
    }

    func testALinkMissingAKeyIsRefusedWithAReason() {
        let links = [
            "wireguard://\(enc(privateKey))@192.0.2.4:51820?address=10.0.0.2/32",
            "wg://192.0.2.4:51820?peer_pk=\(enc(peerKey))",
            "wireguard://\(enc(privateKey))@192.0.2.4:51820?publickey=\(enc(peerKey))&reserved=1,2",
        ]
        for link in links {
            XCTAssertThrowsError(try ProxyConfiguration.fromUrl(link), link) { error in
                guard case MythaiaError.parse(let why)? = error as? MythaiaError else { return XCTFail("\(error)") }
                XCTAssertFalse(why.isEmpty)
            }
        }
    }

    func testASubscriptionListKeepsItsWireGuardLines() throws {
        let body = [
            "wireguard://\(enc(privateKey))@192.0.2.4:51820?publickey=\(enc(peerKey))&address=10.0.0.2/32#one",
            "wg://192.0.2.8:2408?pk=\(enc(privateKey))&peer_pk=\(enc(peerKey))&local_address=10.0.0.3/32#two",
        ].joined(separator: "\n")
        let result = try SubscriptionFetcher.parse(Data(body.utf8))
        XCTAssertEqual(result.configurations.map { $0.name }, ["one", "two"])
        XCTAssertTrue(result.configurations.allSatisfy { $0.outboundProtocol == .wireguard })
    }

    // MARK: - INI

    private func iniText(_ extra: String = "") -> String {
        let privateKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8($0) }))
        let peerKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))
        return """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.7.0.2/32
        DNS = 192.0.2.53
        \(extra)

        [Peer]
        PublicKey = \(peerKey)
        Endpoint = vpn.example.com:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        PersistentKeepalive = 25
        """
    }

    func testAWgQuickConfigIsRecognisedAndAShareLinkIsNot() {
        XCTAssertTrue(ProxyConfiguration.looksLikeWireGuardConfig(iniText()))
        XCTAssertFalse(ProxyConfiguration.looksLikeWireGuardConfig("vless://x@a.b:443#n"))
        XCTAssertFalse(ProxyConfiguration.looksLikeWireGuardConfig("https://example.com/sub"))
        // An INI missing its peer is not something that could be dialled.
        XCTAssertFalse(ProxyConfiguration.looksLikeWireGuardConfig("[Interface]\nPrivateKey = \(privateKey)"))
    }

    func testImportingKeepsTheTextAndPullsTheEndpointOutOfIt() throws {
        let config = try ProxyConfiguration.fromWireGuardConfig(iniText())
        XCTAssertEqual(config.outboundProtocol, .wireguard)
        XCTAssertEqual(config.serverAddress, "vpn.example.com")
        XCTAssertEqual(config.serverPort, 51820)
        // Verbatim, so a key this build does not know still survives a save.
        XCTAssertEqual(config.wireGuardConfig, iniText())
    }

    func testAnAmneziaWGConfigIsLabelledAsOne() throws {
        let plain = try ProxyConfiguration.fromWireGuardConfig(iniText())
        let amnezia = try ProxyConfiguration.fromWireGuardConfig(
            iniText("Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nH1 = 1234567\nH4 = 4433221")
        )
        XCTAssertEqual(plain.name, "WireGuard")
        XCTAssertEqual(amnezia.name, "AmneziaWG")
        let parsed = try WireGuardConfig.parse(XCTUnwrap(amnezia.wireGuardConfig))
        XCTAssertEqual(parsed.amnezia.junkPacketCount, 4)
        XCTAssertEqual(parsed.amnezia.initiationType, 1_234_567)
        XCTAssertTrue(parsed.amnezia.renumbersTypes)
    }

    func testAGivenNameWinsOverTheDerivedOne() throws {
        XCTAssertEqual(try ProxyConfiguration.fromWireGuardConfig(iniText(), name: "Home").name, "Home")
    }

    func testAConfigThatCannotBeParsedIsRefusedWithAReason() {
        XCTAssertThrowsError(try ProxyConfiguration.fromWireGuardConfig("[Interface]\nPrivateKey = nonsense\n\n[Peer]\n")) { error in
            guard case MythaiaError.parse(let why)? = error as? MythaiaError else { return XCTFail("\(error)") }
            XCTAssertTrue(why.contains("PrivateKey"))
        }
    }

    func testWireGuardExportsTheConfigItWasGiven() throws {
        let config = try ProxyConfiguration.fromWireGuardConfig(iniText())
        XCTAssertEqual(config.toUrl(), iniText())
    }

    func testReservedReadsBothSpellings() {
        XCTAssertEqual(WireGuardConfig.parseReserved("[78, 135, 76]"), Data([78, 135, 76]))
        XCTAssertEqual(WireGuardConfig.parseReserved("AQID"), Data([1, 2, 3]))
        XCTAssertNil(WireGuardConfig.parseReserved("1,2"))
        XCTAssertNil(WireGuardConfig.parseReserved("1,2,256"))
    }

    // MARK: - Form

    private var formIni: String {
        let key = WireGuardConfig.encodeKey(Data(repeating: 0x11, count: 32))
        let peer = WireGuardConfig.encodeKey(Data(repeating: 0x22, count: 32))
        let second = WireGuardConfig.encodeKey(Data(repeating: 0x33, count: 32))
        return """
        [Interface]
        # from the panel
        PrivateKey = \(key)
        Address = 10.77.0.2/32
        Address = fd00::2/128
        DNS = 192.0.2.53
        MTU = 1280
        Jc = 4
        Jmin = 40
        Jmax = 70
        H1 = 1234
        FwMark = 51820

        [Peer]
        PublicKey = \(peer)
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = example.com:51820
        PersistentKeepalive = 25

        [Peer]
        PublicKey = \(second)
        Endpoint = second.example.com:51820
        """
    }

    func testFormFieldsReadAndUnknownLinesSurviveARoundTrip() throws {
        let form = WireGuardForm.fromIni(formIni)
        XCTAssertEqual(form.addresses, "10.77.0.2/32, fd00::2/128")
        XCTAssertEqual(form.mtu, "1280")
        XCTAssertEqual(form.endpoint, "example.com:51820")
        XCTAssertTrue(form.isAmnezia)
        XCTAssertTrue(form.extraInterface.contains { $0.contains("FwMark") })
        XCTAssertTrue(form.extraInterface.contains { $0.contains("# from the panel") })
        var edited = form
        edited.mtu = "1420"
        let out = edited.toIni()
        XCTAssertTrue(out.contains("MTU = 1420"))
        XCTAssertTrue(out.contains("FwMark = 51820"))
        XCTAssertTrue(out.contains("second.example.com:51820"))
        // What the form writes is what the tunnel parses.
        let parsed = try WireGuardConfig.parse(out)
        XCTAssertEqual(parsed.peer.endpointHost, "example.com")
        XCTAssertEqual(parsed.mtu, 1420)
    }

    func testABlankProfileHasAValidKeyPair() throws {
        let form = WireGuardForm.blank()
        let pub = try XCTUnwrap(WireGuardForm.publicKeyOf(form.privateKey))
        XCTAssertEqual(pub.count, 44)
        XCTAssertEqual(form.keepalive, "25")
    }

    func testThePublicKeyIsTheX25519OneOfTheRfc7748Vector() throws {
        // RFC 7748 §6.1: Alice's private key and the public key it gives.
        let privateKey = try XCTUnwrap(LinkText.hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let expected = try XCTUnwrap(LinkText.hexDecode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        XCTAssertEqual(WireGuardForm.publicKeyOf(privateKey.base64EncodedString()), expected.base64EncodedString())
    }
}
