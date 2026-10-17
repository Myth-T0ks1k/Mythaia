import XCTest
@testable import MythaiaKit

/**
 * A JSON subscription as a panel serves it: an array of whole Xray configs,
 * one per server, each named by its `remarks`, one of them a balancer over
 * several servers. The shapes — singular and plural FinalMask fields, the
 * new Hysteria2 outbound, balancer tags, observatory, mux with concurrency —
 * are kept as served; credentials, addresses and host names are placeholders.
 */
final class ImporterXrayJsonSubscriptionTests: XCTestCase {

    private let subscription = #"""
    [
      {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "inbounds": [
          {"tag": "socks", "port": 10808, "listen": "0.0.0.0", "protocol": "socks",
           "sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": false},
           "settings": {"auth": "noauth", "udp": true, "allowTransparent": false}}
        ],
        "outbounds": [
          {"protocol": "vless", "tag": "proxy-1",
           "settings": {"vnext": [{"address": "203.0.113.11", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "xhttp", "security": "tls",
             "tlsSettings": {"serverName": "d111.cdn.example.net", "fingerprint": "safari"},
             "xhttpSettings": {"mode": "auto", "path": "/", "host": "d111.cdn.example.net",
               "extra": {"scMaxEachPostBytes": "500000", "scMinPostsIntervalMs": "60", "xPaddingBytes": "100-1000",
                 "xmux": {"maxConnections": 16, "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "300-600", "hKeepAlivePeriod": 15}}},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "maxSplit": "2", "length": "3", "delay": "1"}}]},
             "sockopt": {"tcpKeepAliveIdle": 15, "tcpKeepAliveInterval": 10, "tcpUserTimeout": 20000}}},
          {"protocol": "vless", "tag": "proxy-2",
           "settings": {"vnext": [{"address": "203.0.113.12", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "ws", "security": "tls",
             "tlsSettings": {"serverName": "d222.cdn.example.net", "fingerprint": "safari"},
             "wsSettings": {"path": "/", "host": "d222.cdn.example.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3-3"], "delays": ["1-1"], "maxSplit": "2-2"}}]}},
           "mux": {"enabled": true, "concurrency": 8, "xudpProxyUDP443": "reject"}},
          {"protocol": "vless", "tag": "proxy-3",
           "settings": {"vnext": [{"address": "203.0.113.13", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "xhttp", "security": "tls",
             "tlsSettings": {"serverName": "d333.cdn.example.net", "fingerprint": "safari"},
             "xhttpSettings": {"mode": "auto", "path": "/", "host": "d333.cdn.example.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "maxSplit": "2", "length": "3", "delay": "1"}}]}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "dns": {"servers": ["192.0.2.53"]},
        "observatory": {"subjectSelector": ["proxy-"], "probeUrl": "https://probe.example.com/generate_204",
          "probeInterval": "60s", "enableConcurrency": true},
        "routing": {"domainStrategy": "AsIs",
          "rules": [{"type": "field", "network": "tcp,udp", "balancerTag": "balancer-main"}],
          "balancers": [{"tag": "balancer-main", "selector": ["proxy-1", "proxy-2", "proxy-3"],
            "strategy": {"type": "leastPing"}, "fallbackTag": "BLOCK"}]},
        "remarks": "Авто-выбор VIP",
        "meta": {"serverDescription": ""}
      },
      {
        "log": {"loglevel": "warning"},
        "policy": {"levels": {"0": {"handshake": 4}}},
        "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": true}}],
        "outbounds": [
          {"protocol": "hysteria", "tag": "proxy",
           "settings": {"version": 2, "address": "198.51.100.54", "port": 443},
           "streamSettings": {"network": "hysteria", "security": "tls",
             "tlsSettings": {"serverName": "hy.example.net"},
             "hysteriaSettings": {"version": 2, "auth": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
             "finalmask": {
               "udp": [{"type": "salamander", "settings": {"password": "obfs-secret"}}],
               "quicParams": {"congestion": "bbr", "bbrProfile": "standard", "keepAlivePeriod": 10, "maxIdleTimeout": 30,
                 "initStreamReceiveWindow": 8388608, "maxStreamReceiveWindow": 8388608,
                 "initConnectionReceiveWindow": 20971520, "maxConnectionReceiveWindow": 20971520,
                 "maxIncomingStreams": 1024}}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "routing": {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]},
        "remarks": "📴SOCIAL & VIDEO"
      },
      {
        "outbounds": [
          {"protocol": "vless", "tag": "proxy",
           "settings": {"vnext": [{"address": "203.0.113.20", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "ws", "security": "tls",
             "tlsSettings": {"serverName": "d444.cdn.example.net", "fingerprint": "safari"},
             "wsSettings": {"path": "/", "host": "d444.cdn.example.net"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3"], "delays": ["1"], "maxSplit": "2"}}]}},
           "mux": {"enabled": true, "concurrency": 8, "xudpProxyUDP443": "reject"}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "remarks": "🚀Edge - 4G+Wifi "
      },
      {
        "outbounds": [
          {"protocol": "vless", "tag": "proxy",
           "settings": {"vnext": [{"address": "192.0.2.30", "port": 443,
             "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
           "streamSettings": {"network": "grpc", "security": "tls",
             "tlsSettings": {"serverName": "la.example.org", "fingerprint": "edge"},
             "grpcSettings": {"idle_timeout": 60, "health_check_timeout": 20, "initial_windows_size": 35538,
               "serviceName": "fr.example.org", "authority": "la.example.org"},
             "finalmask": {"tcp": [{"type": "fragment",
               "settings": {"packets": "tlshello", "lengths": ["3"], "delays": ["1"], "maxSplit": "2"}}]}}},
          {"protocol": "freedom", "tag": "DIRECT"},
          {"protocol": "blackhole", "tag": "BLOCK"}
        ],
        "remarks": "🌩️🇳🇱Relay Upgraded"
      }
    ]
    """#

    private let expectedNames = [
        "Авто-выбор VIP · 1", "Авто-выбор VIP · 2", "Авто-выбор VIP · 3",
        "📴SOCIAL & VIDEO",
        "🚀Edge - 4G+Wifi",
        "🌩️🇳🇱Relay Upgraded",
    ]

    func testServersAreNamedByRemarksBalancerMembersByTheirPlace() throws {
        XCTAssertEqual(try XrayJsonImporter.parse(subscription).map { $0.name }, expectedNames)
    }

    func testFinalMaskFragmentationSurvivesInBothSpellings() throws {
        let vless = try XrayJsonImporter.parse(subscription).filter { $0.outboundProtocol == .vless }
        XCTAssertEqual(vless.count, 5)
        for c in vless {
            let fragment = try XCTUnwrap(c.tls?.fragment, "\(c.name) lost its fragment settings")
            XCTAssertEqual(fragment.lengthRanges, [3...3])
            XCTAssertEqual(fragment.delayRanges, [1...1])
            XCTAssertEqual(fragment.maxSplit, 2)
        }
    }

    func testTheNewHysteria2OutboundImportsWithSalamanderFromFinalMask() throws {
        let all = try XrayJsonImporter.parse(subscription).filter { $0.outboundProtocol == .hysteria2 }
        XCTAssertEqual(all.count, 1)
        let hy = all[0]
        XCTAssertEqual(hy.serverAddress, "198.51.100.54")
        XCTAssertEqual(hy.serverPort, 443)
        XCTAssertEqual(hy.password, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        XCTAssertEqual(hy.obfuscation, "salamander")
        XCTAssertEqual(hy.obfuscationPassword, "obfs-secret")
        XCTAssertEqual(hy.tls?.serverName, "hy.example.net")
        // No bandwidth was declared, so BBR stays in charge.
        XCTAssertNil(hy.hysteriaUpMbps)
    }

    func testTransportsAndFingerprintsComeThroughPerServer() throws {
        var byName: [String: ProxyConfiguration] = [:]
        for config in try XrayJsonImporter.parse(subscription) { byName[config.name] = config }

        let xhttp = try XCTUnwrap(byName["Авто-выбор VIP · 1"])
        XCTAssertEqual(xhttp.transport, "xhttp")
        XCTAssertEqual(xhttp.xhttp?.host, "d111.cdn.example.net")
        XCTAssertEqual(xhttp.xhttp?.scMaxEachPostBytes, 500_000)
        XCTAssertEqual(xhttp.tls?.fingerprint, .safari26)

        let ws = try XCTUnwrap(byName["Авто-выбор VIP · 2"])
        XCTAssertEqual(ws.transport, "ws")
        XCTAssertEqual(ws.websocket?.host, "d222.cdn.example.net")
        // mux enabled stays the default; only enabled:false turns it off.
        XCTAssertTrue(ws.muxEnabled)

        let grpc = try XCTUnwrap(byName["🌩️🇳🇱Relay Upgraded"])
        XCTAssertEqual(grpc.transport, "grpc")
        XCTAssertEqual(grpc.grpc?.serviceName, "fr.example.org")
        XCTAssertEqual(grpc.grpc?.authority, "la.example.org")
        XCTAssertEqual(grpc.tls?.fingerprint, .edge85)
    }

    func testASubscriptionBodyGivesTheSameServersPlainOrBase64() throws {
        let plain = try SubscriptionFetcher.parse(Data(subscription.utf8)).configurations
        XCTAssertEqual(plain.map { $0.name }, expectedNames)
        let encoded = Data(subscription.utf8).base64EncodedData()
        XCTAssertEqual(try SubscriptionFetcher.parse(encoded).configurations.map { $0.name }, expectedNames)
    }

    func testASingleFullConfigWithRemarksIsNamedByThem() throws {
        let root = try XCTUnwrap(try XrayJsonImporter.parseJson(subscription).arrayValue)
        let single = try XCTUnwrap(root[2].objectValue).serialized()
        XCTAssertEqual(try XrayJsonImporter.parse(single).map { $0.name }, ["🚀Edge - 4G+Wifi"])
    }
}
