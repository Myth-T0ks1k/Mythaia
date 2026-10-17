import XCTest
@testable import MythaiaKit

/**
 * The `hysteria2://`, `hy2://` and `anytls://` share links, which a
 * subscription may carry alongside the other schemes, and the cross-scheme
 * rules (server names, insecure flags, pins).
 */
final class ModelShareLinkTests: XCTestCase {

    private let pin = "abababababababababababababababababababababababababababababababab"

    private func parse(_ link: String, _ naive: OutboundProtocol? = nil) throws -> ProxyConfiguration {
        try ProxyConfiguration.fromUrl(link, naiveProtocol: naive)
    }

    private func assertRefused(_ link: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try ProxyConfiguration.fromUrl(link), "expected a refusal for \(link)", file: file, line: line) { error in
            guard case MythaiaError.parse(let why)? = error as? MythaiaError else {
                return XCTFail("expected MythaiaError.parse, got \(error)", file: file, line: line)
            }
            XCTAssertFalse(why.isEmpty, file: file, line: line)
        }
    }

    // MARK: - Hysteria2

    func testParsesAFullHysteria2Link() throws {
        let config = try parse(
            "hysteria2://s3cr3t@example.com:8443" +
                "?sni=cdn.example.com&upmbps=100&downmbps=200" +
                "&obfs=salamander&obfs-password=shhh#Tokyo%20Edge"
        )
        XCTAssertEqual(config.outboundProtocol, .hysteria2)
        XCTAssertEqual(config.serverAddress, "example.com")
        XCTAssertEqual(config.serverPort, 8443)
        XCTAssertEqual(config.password, "s3cr3t")
        XCTAssertEqual(config.name, "Tokyo Edge")
        XCTAssertEqual(config.hysteriaUpMbps, 100)
        XCTAssertEqual(config.hysteriaDownMbps, 200)
        XCTAssertEqual(config.obfuscation, "salamander")
        XCTAssertEqual(config.obfuscationPassword, "shhh")
        XCTAssertEqual(config.security, "tls")
        XCTAssertEqual(config.tls?.serverName, "cdn.example.com")
    }

    func testHy2IsTheSameSchemeUnderAnotherName() throws {
        let long = try parse("hysteria2://p@example.com:443#N")
        let short = try parse("hy2://p@example.com:443#N")
        // Not contentEquals: `uuid` is a fresh random placeholder for every
        // password-authenticated protocol. Compare what the link carries.
        XCTAssertEqual(long.outboundProtocol, short.outboundProtocol)
        XCTAssertEqual(long.serverAddress, short.serverAddress)
        XCTAssertEqual(long.serverPort, short.serverPort)
        XCTAssertEqual(long.password, short.password)
        XCTAssertEqual(long.name, short.name)
        XCTAssertEqual(long.tls, short.tls)
    }

    func testAbsentBandwidthStaysAbsent() throws {
        // The pair is what selects Brutal congestion control over BBR, so a
        // default here would silently change how the connection behaves.
        let config = try parse("hysteria2://p@example.com:443#N")
        XCTAssertNil(config.hysteriaUpMbps)
        XCTAssertNil(config.hysteriaDownMbps)
        XCTAssertNil(config.obfuscation)
        XCTAssertNil(config.obfuscationPassword)
        XCTAssertEqual(config.tls?.serverName, "example.com")
        XCTAssertEqual(config.name, "N")
        XCTAssertEqual(try parse("hy2://p@example.com:443").name, "example.com")
    }

    func testAPasswordContainingAnAtSignSurvives() throws {
        let config = try parse("hysteria2://us%40er%3Apass@example.com:443#N")
        XCTAssertEqual(config.password, "us@er:pass")
        XCTAssertEqual(config.serverAddress, "example.com")
    }

    func testAnObfsOfNoneMeansNoObfuscation() throws {
        XCTAssertNil(try parse("hysteria2://p@example.com:443?obfs=none#N").obfuscation)
        XCTAssertNil(try parse("hysteria2://p@example.com:443?obfs=NONE#N").obfuscation)
        XCTAssertEqual(try parse("hysteria2://p@example.com:443?obfs=salamander#N").obfuscation, "salamander")
    }

    // MARK: - VMess

    private func vmessLink(_ fields: [(String, String)]) -> String {
        var json = ImportJSONObject()
        for (key, value) in fields { json.put(key, value) }
        return "vmess://" + Data(json.serialized().utf8).base64EncodedString()
    }

    func testVmessOverMultiModeGrpcRoundTripsThroughItsUrl() throws {
        let original = try parse(vmessLink([
            ("v", "2"), ("ps", "Grpc"), ("add", "example.com"), ("port", "2053"),
            ("id", "b1a2c3d4-0000-4000-8000-000000000001"), ("aid", "0"),
            ("net", "grpc"), ("type", "multi"), ("path", "svc"), ("tls", "tls"), ("sni", "g.example.com"),
        ]))
        XCTAssertEqual(original.transport, "grpc")
        XCTAssertEqual(original.grpc?.multiMode, true)
        XCTAssertEqual(original.grpc?.serviceName, "svc")

        // The exporter writes the mode into `type`, where v2rayN keeps it;
        // the parser must not read that as header obfuscation.
        let reparsed = try parse(original.toUrl())
        XCTAssertEqual(reparsed.uuid, original.uuid)
        XCTAssertEqual(reparsed.transport, "grpc")
        XCTAssertEqual(reparsed.grpc?.multiMode, true)
        XCTAssertEqual(reparsed.grpc?.serviceName, original.grpc?.serviceName)
        XCTAssertEqual(reparsed.tls?.serverName, original.tls?.serverName)
        XCTAssertEqual(reparsed.name, "Grpc")
    }

    func testVmessExportIsTheV2rayNJsonAPeerReads() throws {
        let config = try parse(vmessLink([
            ("add", "example.com"), ("port", "443"), ("id", "B1A2C3D4-0000-4000-8000-000000000001"),
            ("net", "ws"), ("path", "/w"), ("host", "h.example.com"), ("tls", "tls"), ("ps", "W"),
        ]))
        let link = config.toUrl()
        XCTAssertTrue(link.hasPrefix("vmess://"))
        // Decoded independently: the id lower-case, the port a string, aid 0.
        let payload = String(link.dropFirst("vmess://".count))
        let data = try XCTUnwrap(Data(base64Encoded: payload))
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(json["id"] as? String, "b1a2c3d4-0000-4000-8000-000000000001")
        XCTAssertEqual(json["port"] as? String, "443")
        XCTAssertEqual(json["aid"] as? String, "0")
        XCTAssertEqual(json["net"] as? String, "ws")
        XCTAssertEqual(json["path"] as? String, "/w")
        XCTAssertEqual(json["host"] as? String, "h.example.com")
        XCTAssertEqual(json["tls"] as? String, "tls")
    }

    func testVmessHttpHeaderObfuscationIsStillRefused() {
        for net in ["tcp", "grpc"] {
            assertRefused(vmessLink([
                ("add", "example.com"), ("port", "443"),
                ("id", "b1a2c3d4-0000-4000-8000-000000000001"), ("net", net), ("type", "http"),
            ]))
        }
    }

    func testVmessWithALegacyAlterIdIsRefused() {
        assertRefused(vmessLink([
            ("add", "example.com"), ("port", "443"), ("id", "b1a2c3d4-0000-4000-8000-000000000001"), ("aid", "64"),
        ]))
    }

    // MARK: - VLESS

    func testVlessTransportsWithoutADialerAreRefusedAtImport() throws {
        let base = "vless://b1a2c3d4-0000-4000-8000-000000000001@example.com:443"
        for query in ["type=kcp", "type=quic", "type=h2", "type=tcp&headerType=http"] {
            assertRefused("\(base)?\(query)#N")
        }
        XCTAssertEqual(try parse("\(base)?type=splithttp&security=tls#N").transport, "xhttp")
        XCTAssertEqual(try parse("\(base)?type=raw&headerType=none#N").transport, "tcp")
        XCTAssertEqual(try parse("\(base)?type=ws&path=%2Fws#N").transport, "ws")
    }

    func testVlessRealityLinkReadsItsKeysAndExportsThemBack() throws {
        // A 32-byte key of 0x00..0x1f, written unpadded URL-safe as links carry it.
        let key = Data((0..<32).map { UInt8($0) })
        let pbk = key.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let link = "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=reality&sni=www.example.com" +
            "&pbk=\(pbk)&sid=6ba85179e30d4fc2&fp=firefox&flow=xtls-rprx-vision#R"
        let config = try parse(link)
        XCTAssertEqual(config.reality?.publicKey, key)
        XCTAssertEqual(config.reality?.shortId, Data([0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]))
        XCTAssertEqual(config.reality?.fingerprint, .firefox148)
        XCTAssertEqual(config.flow, "xtls-rprx-vision")

        let exported = config.toUrl()
        XCTAssertTrue(exported.contains("pbk=\(pbk)"))
        XCTAssertTrue(exported.contains("sid=6ba85179e30d4fc2"))
        XCTAssertTrue(exported.hasPrefix("vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443/?"))
        XCTAssertEqual(try parse(exported).reality, config.reality)
    }

    func testABadRealityKeyIsRefused() {
        assertRefused("vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=reality&sni=a.example.com&pbk=short#R")
        assertRefused("vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=reality&pbk=AAAA#R")
    }

    func testAPlusInAPathStaysAPlus() throws {
        let config = try parse("vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&path=%2F%3Fed%3D2048+xray#W")
        XCTAssertEqual(config.websocket?.path, "/?ed=2048+xray")
    }

    func testAnIPv6ServerIsBracketedOnExportAndRefusedUnbracketed() throws {
        let config = try parse("trojan://pw@[2001:db8::1]:443#T")
        XCTAssertEqual(config.serverAddress, "2001:db8::1")
        XCTAssertTrue(config.toUrl().contains("@[2001:db8::1]:443"))
        assertRefused("trojan://pw@2001:db8::1:443#T")
    }

    // MARK: - Naive and SOCKS5

    func testAnHttpsProxyKeepsHttp11ThroughItsUrl() throws {
        let original = try parse("https://u:p@example.com:8443#Proxy", .naiveHttp11)
        XCTAssertEqual(original.outboundProtocol, .naiveHttp11)

        let reparsed = try parse(original.toUrl())
        XCTAssertEqual(reparsed.outboundProtocol, .naiveHttp11)
        XCTAssertEqual(reparsed.naiveProtocol, .http11)
        XCTAssertEqual(reparsed.naiveUsername, "u")
        XCTAssertEqual(reparsed.naivePassword, "p")
        XCTAssertEqual(reparsed.serverPort, 8443)
        XCTAssertEqual(reparsed.name, "Proxy")

        // Without the marker the scheme means HTTP/2, and an explicit choice wins over the marker.
        let http2 = try parse("https://u:p@example.com:8443#P")
        XCTAssertEqual(try parse(http2.toUrl()).outboundProtocol, .naiveHttp2)
        XCTAssertEqual(try parse(original.toUrl(), .naiveHttp2).outboundProtocol, .naiveHttp2)
    }

    func testALinkWithoutSniTakesItsNameFromTheTransportHost() throws {
        let id = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
        // A CDN given by IP, the domain only in host=: an IP is never sent as
        // SNI, so the name has to come from the Host or the CDN answers 421.
        let ws = try parse("vless://\(id)@192.0.2.16:443?security=tls&type=ws&host=site.example&path=%2Fws#W")
        XCTAssertEqual(ws.tls?.serverName, "site.example")
        let grpc = try parse("vless://\(id)@192.0.2.16:443?security=tls&type=grpc&authority=grpc.example&serviceName=s#G")
        XCTAssertEqual(grpc.tls?.serverName, "grpc.example")
        let trojan = try parse("trojan://pw@192.0.2.16:443?type=ws&host=t.example#T")
        XCTAssertEqual(trojan.trojanTls?.serverName, "t.example")
        // An explicit sni wins, and plain TCP keeps the address.
        XCTAssertEqual(
            try parse("vless://\(id)@192.0.2.16:443?security=tls&type=ws&host=site.example&sni=other.example#W").tls?.serverName,
            "other.example"
        )
        XCTAssertEqual(try parse("vless://\(id)@example.com:443?security=tls#V").tls?.serverName, "example.com")
    }

    func testAnSniEqualToTheAddressSurvivesTheRoundTripNextToADifferentHost() throws {
        let id = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
        let config = try parse("vless://\(id)@front.example:443?security=tls&type=ws&host=site.example&sni=front.example#W")
        XCTAssertEqual(config.tls?.serverName, "front.example")
        XCTAssertEqual(try parse(config.toUrl()).tls?.serverName, "front.example")
    }

    func testAStoredServerWithAnIpForItsNameDialsWithTheHost() throws {
        let id = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
        let parsed = try parse("vless://\(id)@192.0.2.16:443?security=tls&type=ws&host=site.example#W")
        // As saved by a build that still used the address.
        var stored = parsed
        stored.tls?.serverName = "192.0.2.16"
        XCTAssertEqual(stored.withTransportHostSni().tls?.serverName, "site.example")
        // A real name is left alone; so is a server with no Host to borrow.
        var named = parsed
        named.tls?.serverName = "front.example"
        XCTAssertEqual(named.withTransportHostSni().tls?.serverName, "front.example")
        let tcp = try parse("vless://\(id)@192.0.2.16:443?security=tls#V")
        XCTAssertEqual(tcp.withTransportHostSni().tls?.serverName, "192.0.2.16")
    }

    func testANaiveLinkCarriesAllowInsecureItsNameAndItsPinBothWays() throws {
        let link = "https://u:p@192.0.2.4:443?sni=proxy.example&insecure=1&pcs=\(pin)&vcn=cert.example#N"
        let config = try parse(link)
        let tls = try XCTUnwrap(config.tls)
        XCTAssertEqual(tls.serverName, "proxy.example")
        XCTAssertTrue(tls.allowInsecure)
        XCTAssertEqual(tls.pinnedCertSha256, [pin])
        XCTAssertEqual(tls.verifyName, "cert.example")

        let again = try XCTUnwrap(try parse(config.toUrl()).tls)
        XCTAssertEqual(again.serverName, tls.serverName)
        XCTAssertTrue(again.allowInsecure)
        XCTAssertEqual(again.pinnedCertSha256, tls.pinnedCertSha256)
        XCTAssertEqual(again.verifyName, tls.verifyName)

        // A plain link keeps no TLS settings of its own.
        XCTAssertNil(try parse("https://u:p@example.com:443#P").tls)
    }

    func testAPinMayBeColonHexOrBase64() throws {
        let colonHex = stride(from: 0, to: 64, by: 2).map { i -> String in
            let start = pin.index(pin.startIndex, offsetBy: i)
            return String(pin[start..<pin.index(start, offsetBy: 2)]).uppercased()
        }.joined(separator: ":")
        XCTAssertEqual(try parse("hysteria2://p@example.com:443?pcs=\(colonHex)#H").tls?.pinnedCertSha256, [pin])
        let bytes = Data(repeating: 0xAB, count: 32)
        let base64 = bytes.base64EncodedString().replacingOccurrences(of: "=", with: "")
        XCTAssertEqual(try parse("hysteria2://p@example.com:443?pinSHA256=\(base64)#H").tls?.pinnedCertSha256, [pin])
    }

    func testANowhereLinkCarriesAllowInsecureAndItsPinBothWays() throws {
        let config = try parse("nowhere://key@example.com:443?up=udp&down=udp&insecure=1&pcs=\(pin)#W")
        XCTAssertEqual(config.outboundProtocol, .nowhere)
        XCTAssertEqual(config.tls?.allowInsecure, true)
        XCTAssertEqual(config.tls?.pinnedCertSha256, [pin])
        let again = try parse(config.toUrl())
        XCTAssertEqual(again.tls?.allowInsecure, true)
        XCTAssertEqual(again.tls?.pinnedCertSha256, config.tls?.pinnedCertSha256)
        XCTAssertEqual(again.password, "key")
        XCTAssertEqual(again.nowhereUplink, "udp")
    }

    func testNowhereCarriersAndMux() throws {
        let tcp = try parse("nowhere://k@example.com:443?net=tcp&mux=1#N")
        XCTAssertEqual(tcp.nowhereUplink, "tcp")
        XCTAssertEqual(tcp.nowhereDownlink, "tcp")
        XCTAssertTrue(tcp.nowhereMultiplex)
        // mux only means something with a stream carrier to honour it.
        XCTAssertFalse(try parse("nowhere://k@example.com:443?mux=1#N").nowhereMultiplex)
        assertRefused("nowhere://k@example.com:443?up=sctp#N")
        assertRefused("nowhere://k@example.com:443?mux=2#N")
    }

    func testAServerIsMarkedInsecureOnlyWhenItsCertificateReallyGoesUnchecked() throws {
        let id = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
        XCTAssertTrue(try parse("vless://\(id)@example.com:443?security=tls&allowInsecure=1#V").skipsCertificateCheck)
        XCTAssertTrue(try parse("trojan://pw@example.com:443?allowInsecure=1#T").skipsCertificateCheck)
        XCTAssertTrue(try parse("hysteria2://pw@example.com:443?insecure=1#H").skipsCertificateCheck)
        XCTAssertTrue(try parse("https://u:p@example.com:443?insecure=1#N").skipsCertificateCheck)
        // A pin is checked whatever the flag says.
        XCTAssertFalse(try parse("hysteria2://pw@example.com:443?insecure=1&pcs=\(pin)#H").skipsCertificateCheck)
        // No TLS in use, nothing to skip.
        XCTAssertFalse(try parse("vless://\(id)@example.com:443?security=none&allowInsecure=1#V").skipsCertificateCheck)
        XCTAssertFalse(try parse("vless://\(id)@example.com:443?security=tls#V").skipsCertificateCheck)
    }

    func testANaiveLinkWithoutAPortTakes443AndAQueryIsNotPartOfThePort() throws {
        let config = try parse("https://u:p@example.com?x=1#P")
        XCTAssertEqual(config.serverPort, 443)
        XCTAssertEqual(config.serverAddress, "example.com")
        XCTAssertEqual(try parse("https://u:p@example.com:8443?x=1").serverPort, 8443)
    }

    func testASocks5LinkWithAQueryStillParsesItsPort() throws {
        let config = try parse("socks5://u:p@example.com:1080?udp=1#S")
        XCTAssertEqual(config.serverPort, 1080)
        XCTAssertEqual(config.socks5Username, "u")
        XCTAssertEqual(config.socks5Password, "p")
        XCTAssertEqual(config.name, "S")
        XCTAssertEqual(try parse("socks5://example.com:1080?udp=1").serverPort, 1080)
        XCTAssertEqual(try parse(config.toUrl()).socks5Password, "p")
    }

    // MARK: - Shadowsocks

    func testShadowsocksInEveryShape() throws {
        // SIP002 with base64 user info, URL-safe and unpadded.
        let userInfo = Data("aes-256-gcm:pa/ss+word".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let sip002 = try parse("ss://\(userInfo)@192.0.2.5:8388/#Node%201")
        XCTAssertEqual(sip002.ssMethod, "aes-256-gcm")
        XCTAssertEqual(sip002.ssPassword, "pa/ss+word")
        XCTAssertEqual(sip002.name, "Node 1")

        // Literal method:password.
        let plain = try parse("ss://chacha20-ietf-poly1305:p%40ss@192.0.2.5:8388#P")
        XCTAssertEqual(plain.ssPassword, "p@ss")

        // Legacy: everything base64.
        let legacy = Data("aes-128-gcm:secret@192.0.2.5:8388".utf8).base64EncodedString()
        let old = try parse("ss://\(legacy)#Old")
        XCTAssertEqual(old.serverAddress, "192.0.2.5")
        XCTAssertEqual(old.ssPassword, "secret")

        // The export is URL-safe base64 a peer decodes to method:password.
        let exported = sip002.toUrl()
        let encoded = String(exported.dropFirst("ss://".count).prefix { $0 != "@" })
        XCTAssertFalse(encoded.contains("/") || encoded.contains("+") || encoded.contains("="))
        XCTAssertEqual(try parse(exported).ssPassword, "pa/ss+word")
    }

    func testShadowsocksPluginsAndUnknownCiphersAreRefused() {
        let userInfo = Data("aes-256-gcm:pw".utf8).base64EncodedString()
        assertRefused("ss://\(userInfo)@192.0.2.5:8388/?plugin=obfs-local%3Bobfs%3Dhttp#P")
        assertRefused("ss://rc4-md5:pw@192.0.2.5:8388#P")
    }

    // MARK: - AnyTLS

    func testParsesAnAnytlsLink() throws {
        let config = try parse("anytls://pw@example.com:8443?sni=front.example&alpn=h2,http%2F1.1&fp=firefox_148&insecure=1#Node")
        XCTAssertEqual(config.outboundProtocol, .anytls)
        XCTAssertEqual(config.password, "pw")
        XCTAssertEqual(config.tls?.serverName, "front.example")
        XCTAssertEqual(config.tls?.alpn, ["h2", "http/1.1"])
        XCTAssertEqual(config.tls?.fingerprint, .firefox148)
        XCTAssertEqual(config.tls?.allowInsecure, true)
        XCTAssertEqual(config.name, "Node")
    }

    // MARK: - Round trip

    func testHysteria2RoundTripsThroughItsUrl() throws {
        let original = try parse(
            "hysteria2://s3cr3t@example.com:8443?sni=cdn.example.com&upmbps=100&downmbps=200" +
                "&obfs=salamander&obfs-password=shhh#Tokyo"
        )
        let reparsed = try parse(original.toUrl())
        XCTAssertEqual(reparsed.serverAddress, original.serverAddress)
        XCTAssertEqual(reparsed.serverPort, original.serverPort)
        XCTAssertEqual(reparsed.password, original.password)
        XCTAssertEqual(reparsed.name, original.name)
        XCTAssertEqual(reparsed.hysteriaUpMbps, original.hysteriaUpMbps)
        XCTAssertEqual(reparsed.hysteriaDownMbps, original.hysteriaDownMbps)
        XCTAssertEqual(reparsed.obfuscation, original.obfuscation)
        XCTAssertEqual(reparsed.obfuscationPassword, original.obfuscationPassword)
        XCTAssertEqual(reparsed.tls?.serverName, original.tls?.serverName)
    }

    func testHy2ExportsAsTheCanonicalScheme() throws {
        XCTAssertTrue(try parse("hy2://p@example.com:443#N").toUrl().hasPrefix("hysteria2://"))
    }

    func testAnytlsRoundTripsThroughItsUrl() throws {
        let original = try parse("anytls://pw@example.com:8443?sni=front.example&fp=firefox_148&insecure=1#Node")
        let reparsed = try parse(original.toUrl())
        XCTAssertEqual(reparsed.password, original.password)
        XCTAssertEqual(reparsed.tls?.serverName, original.tls?.serverName)
        XCTAssertEqual(reparsed.tls?.fingerprint, original.tls?.fingerprint)
        XCTAssertEqual(reparsed.tls?.allowInsecure, original.tls?.allowInsecure)
        XCTAssertEqual(reparsed.name, original.name)
    }

    func testAVlessLinkIsAFixedPointOfExport() throws {
        let link = try parse(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&type=xhttp&host=x.example.com" +
                "&path=%2Fp&mode=packet-up&alpn=h2&fp=safari&fragment=3,1,tlshello,2#X%20node"
        )
        let once = link.toUrl()
        XCTAssertEqual(try parse(once).toUrl(), once)
        XCTAssertTrue(try parse(once).contentEquals(link))
    }

    func testASudokuLinkIsAFixedPointOfExport() throws {
        var json = ImportJSONObject()
        json.put("h", "192.0.2.9")
        json.put("p", 8443)
        json.put("k", "secret-key")
        json.put("a", "ascii")
        json.put("e", "aes-128-gcm")
        json.put("n", "Sudoku")
        json.put("ts", ImportJSON.array([.string(" xpxvvpvv "), .string("vxpvxvvp")]))
        json.put("hm", "stream")
        let encoded = LinkText.base64UrlEncode(Array(json.serialized().utf8))
        let config = try parse("sudoku://\(encoded)")
        XCTAssertEqual(config.outboundProtocol, .sudoku)
        XCTAssertEqual(config.serverPort, 8443)
        XCTAssertEqual(config.sudokuAsciiMode, "prefer_ascii")
        XCTAssertEqual(config.sudokuCustomTables, ["xpxvvpvv", "vxpvxvvp"])
        XCTAssertEqual(config.sudokuHttpMaskMode, "stream")

        let exported = config.toUrl()
        XCTAssertEqual(try parse(exported).toUrl(), exported)
        // The payload a peer reads: sorted keys, the defaults left out.
        let payload = try XCTUnwrap(ProxyConfiguration.decodeBase64Text(String(exported.dropFirst("sudoku://".count))))
        XCTAssertEqual(
            payload,
            "{\"a\":\"ascii\",\"e\":\"aes-128-gcm\",\"h\":\"192.0.2.9\",\"hm\":\"stream\",\"k\":\"secret-key\"," +
                "\"n\":\"Sudoku\",\"p\":8443,\"ts\":[\"xpxvvpvv\",\"vxpvxvvp\"],\"x\":false}"
        )
    }

    // MARK: - Recognition

    func testCanParseUrlRecognisesTheSchemes() {
        for url in ["hysteria2://p@h:443", "hy2://p@h:443", "anytls://p@h:443", "tuic://u:p@h", "wg://h:1"] {
            XCTAssertTrue(ProxyConfiguration.canParseUrl(url), url)
        }
        XCTAssertFalse(ProxyConfiguration.canParseUrl("http://example.com/sub"))
    }

    func testALinkWithNoUserinfoIsRejectedNotHalfParsed() {
        for url in ["hysteria2://example.com:443", "anytls://example.com:443"] {
            assertRefused(url)
        }
    }

    func testEveryProtocolALinkCanNameIsDialable() {
        for value in OutboundProtocol.allCases {
            XCTAssertTrue(value.isImplemented, value.displayName)
        }
    }
}
