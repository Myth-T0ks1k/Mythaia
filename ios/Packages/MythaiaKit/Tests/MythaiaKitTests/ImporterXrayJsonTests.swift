import XCTest
@testable import MythaiaKit

/// Xray JSON the way panels and v2rayNG hand it out.
final class ImporterXrayJsonTests: XCTestCase {

    private let realityKey = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"

    private var fullConfig: String {
        """
        {
          // exported by a panel
          "log": {"loglevel": "warning"},
          "inbounds": [{"port": 10808, "protocol": "socks"}],
          "outbounds": [
            {
              "tag": "proxy",
              "protocol": "vless",
              "settings": {"vnext": [{"address": "192.0.2.4", "port": 443,
                "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {"serverName": "www.example.com", "fingerprint": "chrome",
                  "publicKey": "\(realityKey)", "shortId": "6ba85179e30d4fc2", "spiderX": "/"},
                "sockopt": {"dialerProxy": "fragment"}
              },
              "mux": {"enabled": false},
            },
            {
              "tag": "fragment",
              "protocol": "freedom",
              "settings": {"fragment": {"packets": "tlshello", "length": "10-20", "interval": "10-20"}}
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
          ]
        }
        """
    }

    private func assertRefused(_ json: String, containing text: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try XrayJsonImporter.parse(json), file: file, line: line) { error in
            guard case MythaiaError.parse(let why)? = error as? MythaiaError else {
                return XCTFail("\(error)", file: file, line: line)
            }
            XCTAssertTrue(why.contains(text), why, file: file, line: line)
        }
    }

    func testAFullConfigWithCommentsAndTrailingCommasImportsItsProxyOutbound() throws {
        let configs = try XrayJsonImporter.parse(fullConfig)
        XCTAssertEqual(configs.count, 1)
        let c = configs[0]
        XCTAssertEqual(c.outboundProtocol, .vless)
        XCTAssertEqual(c.name, "proxy")
        XCTAssertEqual(c.serverAddress, "192.0.2.4")
        XCTAssertEqual(c.serverPort, 443)
        XCTAssertEqual(c.flow, "xtls-rprx-vision")
        XCTAssertEqual(c.security, "reality")
        XCTAssertEqual(c.reality?.serverName, "www.example.com")
        XCTAssertEqual(c.reality?.fingerprint, .chrome133)
        XCTAssertEqual(c.reality?.shortId.count, 8)
        XCTAssertEqual(c.muxEnabled, false)
        XCTAssertNil(c.chain)
    }

    func testFragmentThroughAFreedomDialerProxyLandsOnATlsServer() throws {
        let json = """
        {"outbounds":[
          {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"safari","alpn":["h2","http/1.1"],"allowInsecure":true},
             "wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"sockopt":{"dialerProxy":"frag"}}},
          {"tag":"frag","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"3","interval":"1"}}}
        ]}
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        let c = configs[0]
        XCTAssertEqual(c.transport, "ws")
        XCTAssertEqual(c.websocket?.path, "/ws")
        XCTAssertEqual(c.websocket?.host, "cdn.example.com")
        XCTAssertEqual(c.tls?.serverName, "cdn.example.com")
        XCTAssertEqual(c.tls?.fingerprint, .safari26)
        XCTAssertEqual(c.tls?.alpn, ["h2", "http/1.1"])
        XCTAssertEqual(c.tls?.allowInsecure, true)
        let fragment = try XCTUnwrap(c.tls?.fragment)
        XCTAssertEqual(fragment.lengthRange, 3...3)
        XCTAssertEqual(fragment.intervalRange, 1...1)
    }

    func testDialerProxyToAnotherProxyBecomesAChainAndTheHopIsNotListedTwice() throws {
        let json = """
        {"outbounds":[
          {"tag":"exit","protocol":"trojan","settings":{"servers":[{"address":"exit.example.com","port":443,"password":"pw"}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"exit.example.com"},"sockopt":{"dialerProxy":"entry"}}},
          {"tag":"entry","protocol":"shadowsocks","settings":{"servers":[{"address":"entry.example.com","port":8388,"method":"aes-256-gcm","password":"secret"}]}}
        ]}
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        let exit = configs[0]
        XCTAssertEqual(exit.outboundProtocol, .trojan)
        XCTAssertEqual(exit.trojanPassword, "pw")
        let chain = try XCTUnwrap(exit.chain)
        XCTAssertEqual(chain.count, 1)
        XCTAssertEqual(chain[0].outboundProtocol, .shadowsocks)
        XCTAssertEqual(chain[0].ssMethod, "aes-256-gcm")
        XCTAssertEqual(chain[0].ssPassword, "secret")
    }

    func testVmessOutboundOverGrpcAndABareArrayBothImport() throws {
        let json = """
        [{"protocol":"vmess","tag":"vm","settings":{"vnext":[{"address":"192.0.2.5","port":2053,"users":[{"id":"11111111-2222-3333-4444-555555555555","alterId":0,"security":"aes-128-gcm"}]}]},
          "streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"g.example.com"},"grpcSettings":{"serviceName":"svc","multiMode":true}}},
         {"protocol":"socks","tag":"sk","settings":{"servers":[{"address":"192.0.2.9","port":1080,"users":[{"user":"u","pass":"p"}]}]}}]
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 2)
        let vm = try XCTUnwrap(configs.first { $0.outboundProtocol == .vmess })
        XCTAssertEqual(vm.name, "vm")
        XCTAssertEqual(vm.vmessSecurity, "aes-128-gcm")
        XCTAssertEqual(vm.tls?.serverName, "g.example.com")
        let sk = try XCTUnwrap(configs.first { $0.outboundProtocol == .socks5 })
        XCTAssertEqual(sk.socks5Username, "u")
        XCTAssertEqual(sk.socks5Password, "p")
        XCTAssertEqual(sk.serverPort, 1080)
    }

    func testAVmessOutboundWithRealityIsRefusedRatherThanImportedAsPlaintext() {
        let json = """
        {"protocol":"vmess","tag":"r","settings":{"vnext":[{"address":"192.0.2.4","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
         "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com",
           "publicKey":"\(realityKey)","shortId":"6ba85179e30d4fc2"}}}
        """
        assertRefused(json, containing: "Reality")
    }

    func testTrailingCommasGoButACommaAndBraceInsideAStringStay() throws {
        let cleaned = XrayJsonImporter.stripComments(
            """
            {"a": [1, 2,], "pw": "x,}y", /* c */ "b": {"c": 1, // d
            },}
            """
        )
        let object = try JSONSerialization.jsonObject(with: Data(cleaned.utf8)) as? [String: Any]
        XCTAssertEqual(object?["pw"] as? String, "x,}y")
        XCTAssertEqual((object?["a"] as? [Any])?.count, 2)
        XCTAssertEqual((object?["b"] as? [String: Any])?["c"] as? Int, 1)
    }

    func testPinnedCertificatesAndAVerifyNameMapToPcsAndVcn() throws {
        let pin = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        let json = """
        {"outbounds":[
          {"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.4","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"front.example.com",
             "pinnedPeerCertSha256":"\(pin)","verifyPeerCertByName":"real.example.com"}}},
          {"tag":"b","protocol":"vmess","settings":{"vnext":[{"address":"192.0.2.5","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555"}]}]},
           "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"front.example.com",
             "pinnedPeerCertSha256":["\(pin)"]},"wsSettings":{"path":"/w"}}}
        ]}
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 2)
        XCTAssertEqual(configs[0].tls?.pinnedCertSha256, [pin])
        XCTAssertEqual(configs[0].tls?.verifyName, "real.example.com")
        XCTAssertEqual(configs[1].tls?.pinnedCertSha256, [pin])
    }

    func testAHysteria2OutboundWithServersAPasswordAndBandwidth() throws {
        let json = """
        {"protocol":"hysteria","tag":"hy","settings":{"version":2,"servers":[{"address":"hy.example.com","port":8443}],"password":"pw"},
         "streamSettings":{"network":"hysteria","security":"tls",
           "tlsSettings":{"serverName":"sni.example.com","alpn":["h3"],"allowInsecure":true,"fingerprint":"firefox"},
           "hysteriaSettings":{"version":2,"up":"50 mbps","down":200}}}
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        let c = configs[0]
        XCTAssertEqual(c.outboundProtocol, .hysteria2)
        XCTAssertEqual(c.name, "hy")
        XCTAssertEqual(c.serverAddress, "hy.example.com")
        XCTAssertEqual(c.serverPort, 8443)
        XCTAssertEqual(c.password, "pw")
        XCTAssertEqual(c.tls?.serverName, "sni.example.com")
        XCTAssertEqual(c.tls?.alpn, ["h3"])
        XCTAssertEqual(c.tls?.allowInsecure, true)
        XCTAssertEqual(c.hysteriaUpMbps, 50)
        XCTAssertEqual(c.hysteriaDownMbps, 200)
        XCTAssertNil(c.obfuscation)
    }

    func testHysteriaV1IsRefusedRatherThanDialledAsV2() {
        let json = """
        {"protocol":"hysteria","settings":{"version":1,"address":"192.0.2.4","port":443},
            "streamSettings":{"hysteriaSettings":{"version":1,"auth":"x"}}}
        """
        assertRefused(json, containing: "version 1")
    }

    func testBandwidthReadsHysteriaUnitsAndBareNumbersAsMbps() {
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.string("100 mbps")), 100)
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.string("100Mbps")), 100)
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.string("1 gbps")), 1000)
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.string("500 kbps")), 1)
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.number("30")), 30)
        XCTAssertEqual(XrayJsonImporter.bandwidthMbps(.string("30")), 30)
        XCTAssertNil(XrayJsonImporter.bandwidthMbps(.number("0")))
        XCTAssertNil(XrayJsonImporter.bandwidthMbps(.string("fast")))
        XCTAssertNil(XrayJsonImporter.bandwidthMbps(nil))
    }

    func testAWireGuardOutboundBecomesItsIniReservedIncluded() throws {
        let privateKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8($0) }))
        let peerKey = WireGuardConfig.encodeKey(Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))
        let json = """
        {"outbounds":[{"protocol":"wireguard","tag":"warp",
          "settings":{"secretKey":"\(privateKey)","address":["172.16.0.2","2001:db8:110:8a36::2/128"],
            "peers":[{"publicKey":"\(peerKey)","endpoint":"wg.example.com:2408","keepAlive":25,
              "allowedIPs":["0.0.0.0/0","::/0"]}],
            "mtu":1280,"reserved":[78,135,76]}}]}
        """
        let configs = try XrayJsonImporter.parse(json)
        XCTAssertEqual(configs.count, 1)
        let c = configs[0]
        XCTAssertEqual(c.outboundProtocol, .wireguard)
        XCTAssertEqual(c.name, "warp")
        XCTAssertEqual(c.serverAddress, "wg.example.com")
        XCTAssertEqual(c.serverPort, 2408)

        let ini = try WireGuardConfig.parse(XCTUnwrap(c.wireGuardConfig))
        XCTAssertEqual(ini.privateKey, Data((0..<32).map { UInt8($0) }))
        XCTAssertEqual(ini.peer.publicKey, Data((0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }))
        XCTAssertEqual(ini.addresses, ["172.16.0.2/32", "2001:db8:110:8a36::2/128"])
        XCTAssertEqual(ini.mtu, 1280)
        XCTAssertEqual(ini.peer.persistentKeepalive, 25)
        XCTAssertEqual(ini.reserved, Data([78, 135, 76]))
    }

    func testAnHttpsProxyImportsAndAServerNameItCannotCarryIsRefused() throws {
        let ok = """
        {"protocol":"http","tag":"h","settings":{"servers":[{"address":"proxy.example.com","port":443,
            "users":[{"user":"u","pass":"p"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"proxy.example.com"}}}
        """
        let configs = try XrayJsonImporter.parse(ok)
        XCTAssertEqual(configs.count, 1)
        XCTAssertEqual(configs[0].serverAddress, "proxy.example.com")
        XCTAssertEqual(configs[0].naiveUsername, "u")

        assertRefused(
            ok.replacingOccurrences(of: "\"serverName\":\"proxy.example.com\"", with: "\"serverName\":\"other.example.com\""),
            containing: "other.example.com"
        )
    }

    func testAConfigWithNoProxyOutboundIsRefusedWithAReason() {
        assertRefused(#"{"outbounds":[{"protocol":"freedom"}]}"#, containing: "No proxy outbound")
        XCTAssertTrue(XrayJsonImporter.looksLikeJson(fullConfig))
        XCTAssertTrue(XrayJsonImporter.looksLikeJson(" \n\t" + fullConfig))
        XCTAssertFalse(XrayJsonImporter.looksLikeJson("vless://x@y:1"))
        XCTAssertFalse(XrayJsonImporter.looksLikeJson("  \n"))
    }

    func testAnOutboundDialingThroughItsOwnTagIsStillReportedAsCircular() {
        let json = """
        {"outbounds":[{"tag":"loop","protocol":"socks","settings":{"servers":[{"address":"192.0.2.4","port":1080}]},
           "streamSettings":{"sockopt":{"dialerProxy":"loop"}}}]}
        """
        assertRefused(json, containing: "circular")
    }

    func testThousandsOfOutboundsWithChainsImportInLinearTime() throws {
        // Every outbound used to be checked against every other for being a
        // dialerProxy hop; a config this size froze the import.
        let count = 6_000
        var outbounds: [String] = []
        outbounds.reserveCapacity(count)
        for i in 0..<count {
            if i % 2 == 0 {
                outbounds.append("""
                {"tag":"exit-\(i)","protocol":"trojan","settings":{"servers":[{"address":"exit\(i).example.com","port":443,"password":"pw\(i)"}]},
                 "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"exit\(i).example.com"},
                 "sockopt":{"dialerProxy":"entry-\(i + 1)"}}}
                """)
            } else {
                outbounds.append("""
                {"tag":"entry-\(i)","protocol":"shadowsocks","settings":{"servers":[{"address":"entry\(i).example.com","port":8388,"method":"aes-256-gcm","password":"s\(i)"}]}}
                """)
            }
        }
        let json = "{\"outbounds\":[" + outbounds.joined(separator: ",") + ",{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}"
        let started = Date()
        let configs = try XrayJsonImporter.parse(json)
        let seconds = Date().timeIntervalSince(started)
        // Each entry hop is carried by its exit, not listed on its own.
        XCTAssertEqual(configs.count, count / 2)
        XCTAssertEqual(configs.first?.name, "exit-0")
        XCTAssertEqual(configs.first?.chain?.first?.serverAddress, "entry1.example.com")
        XCTAssertEqual(configs.last?.serverAddress, "exit\(count - 2).example.com")
        XCTAssertLessThan(seconds, 30, "took \(seconds) s")
    }
}
