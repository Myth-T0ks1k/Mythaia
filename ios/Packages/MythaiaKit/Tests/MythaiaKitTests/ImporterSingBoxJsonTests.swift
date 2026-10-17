import XCTest
@testable import MythaiaKit

/// sing-box JSON the way Hiddify and sing-box subscriptions hand it out.
final class ImporterSingBoxJsonTests: XCTestCase {

    private let uuid = "11111111-2222-3333-4444-555555555555"
    private var privateKey: String { WireGuardConfig.encodeKey(Data((0..<32).map { UInt8($0) })) }
    private var peerKey: String { WireGuardConfig.encodeKey(Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) })) }

    /// A Hiddify-style generated config: tun + mixed inbounds, selector/urltest, every proxy kind, endpoints.
    private var config: String {
        """
        {
          "log": {"level": "warn", "timestamp": true},
          "dns": {
            "servers": [
              {"tag": "dns-remote", "address": "udp://192.0.2.53", "address_resolver": "dns-direct"},
              {"tag": "dns-direct", "address": "192.0.2.54", "detour": "direct"}
            ],
            "rules": [{"domain_suffix": [".example"], "server": "dns-direct"}],
            "final": "dns-remote"
          },
          "inbounds": [
            {"type": "tun", "tag": "tun-in", "mtu": 9000, "address": ["172.19.0.1/28"], "auto_route": true,
             "strict_route": true, "stack": "mixed"},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 12334}
          ],
          "outbounds": [
            {"type": "selector", "tag": "select",
             "outbounds": ["auto", "🇩🇪 vless-reality", "vless-ws", "vmess-grpc"], "default": "auto"},
            {"type": "urltest", "tag": "auto", "outbounds": ["🇩🇪 vless-reality", "vless-ws"],
             "url": "https://probe.example.com/generate_204", "interval": "10m0s", "tolerance": 1},
            {"type": "vless", "tag": "🇩🇪 vless-reality", "server": "203.0.113.1", "server_port": 443,
             "uuid": "\(uuid)", "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
             "tls": {"enabled": true, "server_name": "www.example.com",
               "utls": {"enabled": true, "fingerprint": "chrome"},
               "reality": {"enabled": true, "public_key": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", "short_id": "6ba85179e30d4fc2"}}},
            {"type": "vless", "tag": "vless-ws", "server": "cdn.example.com", "server_port": 443, "uuid": "\(uuid)",
             "tls": {"enabled": true, "server_name": "cdn.example.com", "insecure": false, "alpn": ["http/1.1"],
               "utls": {"enabled": true, "fingerprint": "firefox"}},
             "transport": {"type": "ws", "path": "/ws", "headers": {"Host": "cdn.example.com"},
               "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"},
             "tls_fragment": {"enabled": true, "size": "10-30", "sleep": "2-8"}},
            {"type": "vmess", "tag": "vmess-grpc", "server": "203.0.113.3", "server_port": 2053, "uuid": "\(uuid)",
             "security": "aes-128-gcm", "alter_id": 0,
             "tls": {"enabled": true, "server_name": "g.example.com"},
             "transport": {"type": "grpc", "service_name": "svc"}},
            {"type": "trojan", "tag": "trojan-hu", "server": "203.0.113.4", "server_port": 443, "password": "trojan-pw",
             "tls": {"enabled": true, "server_name": "t.example.com"},
             "transport": {"type": "httpupgrade", "host": "t.example.com", "path": "/up"}},
            {"type": "shadowsocks", "tag": "ss-2022", "server": "203.0.113.5", "server_port": 8388,
             "method": "2022-blake3-aes-128-gcm", "password": "AAECAwQFBgcICQoLDA0ODw=="},
            {"type": "hysteria2", "tag": "hy2", "server": "203.0.113.6", "server_port": 443,
             "up_mbps": 50, "down_mbps": 100, "password": "hy-pw",
             "obfs": {"type": "salamander", "password": "obfs-pw"},
             "tls": {"enabled": true, "server_name": "hy.example.com", "insecure": true, "alpn": ["h3"]}},
            {"type": "tuic", "tag": "tuic", "server": "203.0.113.7", "server_port": 443, "uuid": "\(uuid)",
             "password": "tuic-pw", "congestion_control": "bbr", "udp_relay_mode": "native",
             "tls": {"enabled": true, "server_name": "tuic.example.com", "alpn": ["h3"]}},
            {"type": "anytls", "tag": "anytls", "server": "203.0.113.8", "server_port": 443, "password": "any-pw",
             "tls": {"enabled": true, "server_name": "any.example.com", "utls": {"enabled": true, "fingerprint": "safari"}}},
            {"type": "socks", "tag": "socks", "server": "203.0.113.9", "server_port": 1080, "version": "5",
             "username": "u", "password": "p"},
            {"type": "http", "tag": "https-proxy", "server": "proxy.example.com", "server_port": 443,
             "username": "hu", "password": "hp", "tls": {"enabled": true, "server_name": "proxy.example.com"}},
            {"type": "http", "tag": "plain-http", "server": "203.0.113.10", "server_port": 8080},
            {"type": "wireguard", "tag": "warp-legacy", "server": "wg.example.com", "server_port": 2408,
             "local_address": ["172.16.0.2/32", "2001:db8:110:8a36::2/128"],
             "private_key": "\(privateKey)", "peer_public_key": "\(peerKey)", "reserved": [1, 2, 3], "mtu": 1280},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
          ],
          "endpoints": [
            {"type": "wireguard", "tag": "warp-endpoint", "system": false, "mtu": 1408,
             "address": ["172.16.0.2/32"], "private_key": "\(privateKey)",
             "peers": [{"address": "192.0.2.162", "port": 2408, "public_key": "\(peerKey)",
               "allowed_ips": ["0.0.0.0/0", "::/0"], "reserved": "AQID", "persistent_keepalive_interval": 30}]}
          ],
          "route": {
            "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"ip_is_private": true, "outbound": "direct"}],
            "final": "select", "auto_detect_interface": true
          }
        }
        """
    }

    private let expectedNames = [
        "🇩🇪 vless-reality", "vless-ws", "vmess-grpc", "trojan-hu", "ss-2022", "hy2", "tuic",
        "anytls", "socks", "https-proxy", "warp-legacy", "warp-endpoint",
    ]

    private func byName() throws -> [String: ProxyConfiguration] {
        var out: [String: ProxyConfiguration] = [:]
        for config in try SingBoxJsonImporter.parse(config) { out[config.name] = config }
        return out
    }

    func testSingBoxIsToldApartFromXrayByItsOutboundsNotByRouteRules() {
        XCTAssertTrue(SingBoxJsonImporter.looksLikeSingBox(config))
        XCTAssertFalse(SingBoxJsonImporter.looksLikeSingBox(
            #"{"outbounds":[{"protocol":"vless","tag":"x"}],"routing":{"rules":[{"type":"field"}]}}"#
        ))
        XCTAssertFalse(SingBoxJsonImporter.looksLikeSingBox("vless://x@y:1"))
        XCTAssertTrue(XrayJsonImporter.looksLikeJson(config))
    }

    func testEveryProxyImportsUnderItsTagAndTheRoutingOutboundsAreSkipped() throws {
        XCTAssertEqual(try SingBoxJsonImporter.parse(config).map { $0.name }, expectedNames)
    }

    func testTheSubscriptionPathAndTheXrayEntryPointBothReadSingBox() throws {
        XCTAssertEqual(try SubscriptionFetcher.parse(Data(config.utf8)).configurations.map { $0.name }, expectedNames)
        XCTAssertEqual(try XrayJsonImporter.parse(config).map { $0.name }, expectedNames)
    }

    func testVlessWithRealityAndVision() throws {
        let c = try XCTUnwrap(byName()["🇩🇪 vless-reality"])
        XCTAssertEqual(c.outboundProtocol, .vless)
        XCTAssertEqual(c.serverAddress, "203.0.113.1")
        XCTAssertEqual(c.flow, "xtls-rprx-vision")
        XCTAssertEqual(c.security, "reality")
        XCTAssertEqual(c.reality?.serverName, "www.example.com")
        XCTAssertEqual(c.reality?.publicKey.count, 32)
        XCTAssertEqual(c.reality?.shortId.count, 8)
        XCTAssertEqual(c.reality?.fingerprint, .chrome133)
    }

    func testVlessOverWebSocketWithEarlyDataUTlsAndHiddifysFragment() throws {
        let c = try XCTUnwrap(byName()["vless-ws"])
        XCTAssertEqual(c.transport, "ws")
        XCTAssertEqual(c.websocket?.path, "/ws")
        XCTAssertEqual(c.websocket?.host, "cdn.example.com")
        XCTAssertEqual(c.websocket?.maxEarlyData, 2048)
        XCTAssertEqual(c.security, "tls")
        XCTAssertEqual(c.tls?.alpn, ["http/1.1"])
        XCTAssertEqual(c.tls?.fingerprint, .firefox148)
        let fragment = try XCTUnwrap(c.tls?.fragment)
        XCTAssertEqual(fragment.lengthRange, 10...30)
        XCTAssertEqual(fragment.intervalRange, 2...8)
    }

    func testVmessOverGrpcAndTrojanOverHttpUpgrade() throws {
        let all = try byName()
        let vm = try XCTUnwrap(all["vmess-grpc"])
        XCTAssertEqual(vm.outboundProtocol, .vmess)
        XCTAssertEqual(vm.vmessSecurity, "aes-128-gcm")
        XCTAssertEqual(vm.transport, "grpc")
        XCTAssertEqual(vm.grpc?.serviceName, "svc")
        XCTAssertEqual(vm.tls?.serverName, "g.example.com")
        XCTAssertEqual(vm.serverPort, 2053)

        let tj = try XCTUnwrap(all["trojan-hu"])
        XCTAssertEqual(tj.outboundProtocol, .trojan)
        XCTAssertEqual(tj.trojanPassword, "trojan-pw")
        XCTAssertEqual(tj.transport, "httpupgrade")
        XCTAssertEqual(tj.httpUpgrade?.host, "t.example.com")
        XCTAssertEqual(tj.httpUpgrade?.path, "/up")
    }

    func testShadowsocksSocksAndAnHttpsProxy() throws {
        let all = try byName()
        let ss = try XCTUnwrap(all["ss-2022"])
        XCTAssertEqual(ss.ssMethod, "2022-blake3-aes-128-gcm")
        XCTAssertEqual(ss.ssPassword, "AAECAwQFBgcICQoLDA0ODw==")

        let socks = try XCTUnwrap(all["socks"])
        XCTAssertEqual(socks.outboundProtocol, .socks5)
        XCTAssertEqual(socks.socks5Username, "u")
        XCTAssertEqual(socks.socks5Password, "p")

        let https = try XCTUnwrap(all["https-proxy"])
        XCTAssertEqual(https.outboundProtocol, .naiveHttp11)
        XCTAssertEqual(https.naiveUsername, "hu")
        XCTAssertEqual(https.naivePassword, "hp")
    }

    func testHysteria2TuicAndAnytls() throws {
        let all = try byName()
        let hy = try XCTUnwrap(all["hy2"])
        XCTAssertEqual(hy.outboundProtocol, .hysteria2)
        XCTAssertEqual(hy.password, "hy-pw")
        XCTAssertEqual(hy.obfuscation, "salamander")
        XCTAssertEqual(hy.obfuscationPassword, "obfs-pw")
        XCTAssertEqual(hy.hysteriaUpMbps, 50)
        XCTAssertEqual(hy.hysteriaDownMbps, 100)
        XCTAssertEqual(hy.tls?.serverName, "hy.example.com")
        XCTAssertEqual(hy.tls?.allowInsecure, true)
        XCTAssertEqual(hy.tls?.alpn, ["h3"])

        let tuic = try XCTUnwrap(all["tuic"])
        XCTAssertEqual(tuic.outboundProtocol, .tuic)
        XCTAssertEqual(tuic.uuid.uuidString.lowercased(), uuid)
        XCTAssertEqual(tuic.password, "tuic-pw")
        XCTAssertEqual(tuic.tls?.serverName, "tuic.example.com")

        let any = try XCTUnwrap(all["anytls"])
        XCTAssertEqual(any.outboundProtocol, .anytls)
        XCTAssertEqual(any.password, "any-pw")
        XCTAssertEqual(any.tls?.fingerprint, .safari26)
    }

    func testWireGuardAsALegacyOutboundAndAsAnEndpointReservedInBoth() throws {
        let all = try byName()
        let legacy = try XCTUnwrap(all["warp-legacy"])
        XCTAssertEqual(legacy.outboundProtocol, .wireguard)
        XCTAssertEqual(legacy.serverAddress, "wg.example.com")
        let legacyIni = try WireGuardConfig.parse(XCTUnwrap(legacy.wireGuardConfig))
        XCTAssertEqual(legacyIni.reserved, Data([1, 2, 3]))
        XCTAssertEqual(legacyIni.mtu, 1280)
        XCTAssertEqual(legacyIni.addresses, ["172.16.0.2/32", "2001:db8:110:8a36::2/128"])
        XCTAssertEqual(legacyIni.peer.publicKey, Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))

        let endpoint = try XCTUnwrap(all["warp-endpoint"])
        XCTAssertEqual(endpoint.serverAddress, "192.0.2.162")
        XCTAssertEqual(endpoint.serverPort, 2408)
        let endpointIni = try WireGuardConfig.parse(XCTUnwrap(endpoint.wireGuardConfig))
        XCTAssertEqual(endpointIni.reserved, Data([1, 2, 3]))
        XCTAssertEqual(endpointIni.peer.persistentKeepalive, 30)
        XCTAssertEqual(endpointIni.mtu, 1408)
        XCTAssertEqual(endpointIni.privateKey, Data((0..<32).map { UInt8($0) }))
    }

    func testADetourToAnotherProxyBecomesAChainAndTheHopIsNotListed() throws {
        let json = """
        {"outbounds":[
          {"type":"trojan","tag":"exit","server":"exit.example.com","server_port":443,"password":"pw",
           "tls":{"enabled":true,"server_name":"exit.example.com"},"detour":"entry"},
          {"type":"shadowsocks","tag":"entry","server":"entry.example.com","server_port":8388,
           "method":"aes-256-gcm","password":"secret"},
          {"type":"direct","tag":"direct"}
        ]}
        """
        let configs = try SingBoxJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        let exit = configs[0]
        XCTAssertEqual(exit.name, "exit")
        let chain = try XCTUnwrap(exit.chain)
        XCTAssertEqual(chain.count, 1)
        XCTAssertEqual(chain[0].outboundProtocol, .shadowsocks)
        XCTAssertEqual(chain[0].ssPassword, "secret")
    }

    func testAnEchConfigInSingBoxsPemFormBecomesTheLinksEch() throws {
        // Arbitrary bytes standing in for an ECHConfigList; the '+', '/' and '=' are what a link must carry intact.
        let body = "AEX+DQBBpQAgACB/ZWNoLmV4YW1wbGUuY29tIGZvciB0ZXN0aW5nIG9ubHk="
        let json = """
        {"outbounds":[{"type":"vless","tag":"ech","server":"203.0.113.1","server_port":443,"uuid":"\(uuid)",
          "tls":{"enabled":true,"server_name":"secret.example.com",
            "ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","\(body)","-----END ECH CONFIGS-----"]}}}]}
        """
        let configs = try SingBoxJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        XCTAssertEqual(configs[0].tls?.echConfig, body)
    }

    func testASingleBareOutboundObjectImports() throws {
        let json = #"{"type":"trojan","server":"t.example.com","server_port":443,"password":"pw","tls":{"enabled":true}}"#
        XCTAssertTrue(SingBoxJsonImporter.looksLikeSingBox(json))
        let configs = try SingBoxJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        // No tag: the endpoint is the name.
        XCTAssertEqual(configs[0].name, "t.example.com:443")
        XCTAssertNil(configs[0].chain)
    }

    func testTransportsAndOutboundsWithNoDialerHereAreRefusedWithAReason() {
        let json = """
        {"outbounds":[
          {"type":"vless","tag":"h2","server":"a.example.com","server_port":443,"uuid":"\(uuid)",
           "tls":{"enabled":true},"transport":{"type":"http","host":["a.example.com"],"path":"/"}},
          {"type":"shadowtls","tag":"stls","server":"b.example.com","server_port":443},
          {"type":"direct","tag":"direct"}
        ]}
        """
        XCTAssertThrowsError(try SingBoxJsonImporter.parse(json)) { error in
            guard case MythaiaError.parse(let why)? = error as? MythaiaError else { return XCTFail("\(error)") }
            XCTAssertTrue(why.contains("HTTP/2"), why)
            XCTAssertTrue(why.contains("shadowtls"), why)
        }
    }
}
