import XCTest
@testable import MythaiaKit

/**
 * Stores written by older builds must keep loading: every field with a
 * default may be missing from the JSON, and the keys are the property names.
 */
final class ModelCodableTests: XCTestCase {

    private func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
        try JSONDecoder().decode(type, from: Data(json.utf8))
    }

    func testAMinimalServerDecodesWithEveryDefault() throws {
        let config = try decode(ProxyConfiguration.self, #"""
        {"name":"Old","serverAddress":"192.0.2.1","serverPort":443,
         "uuid":"11111111-2222-3333-4444-555555555555","encryption":"none"}
        """#)
        XCTAssertEqual(config.name, "Old")
        XCTAssertEqual(config.serverPort, 443)
        XCTAssertEqual(config.transport, "tcp")
        XCTAssertEqual(config.security, "none")
        XCTAssertEqual(config.outboundProtocol, .vless)
        XCTAssertEqual(config.testseed, [900, 500, 900, 256])
        XCTAssertTrue(config.muxEnabled)
        XCTAssertTrue(config.xudpEnabled)
        XCTAssertTrue(config.sudokuEnablePureDownlink)
        XCTAssertEqual(config.sudokuCustomTables, [])
        XCTAssertNil(config.chain)
    }

    func testNestedConfigurationsDecodeWithTheirDefaultsAndOldProtocolNames() throws {
        let config = try decode(ProxyConfiguration.self, #"""
        {"id":"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE","name":"N","serverAddress":"example.com","serverPort":8443,
         "uuid":"11111111-2222-3333-4444-555555555555","encryption":"none","outboundProtocol":"naive_http11",
         "tls":{"serverName":"example.com","fingerprint":"chrome","fragment":{"maxSplit":2}},
         "xhttp":{"host":"x.example.com","noGRPCHeader":true},
         "websocket":{"host":"w.example.com"},
         "grpc":{"serviceName":"svc"},
         "reality":{"serverName":"r.example.com","publicKey":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","shortId":"6ba8"},
         "chain":[{"name":"Hop","serverAddress":"192.0.2.2","serverPort":1080,
                   "uuid":"11111111-2222-3333-4444-555555555555","encryption":"none","outboundProtocol":"socks5"}]}
        """#)
        XCTAssertEqual(config.outboundProtocol, .naiveHttp11)
        XCTAssertEqual(config.tls?.fingerprint, .chrome133)
        XCTAssertEqual(config.tls?.allowInsecure, false)
        XCTAssertEqual(config.tls?.fragment?.isEnabled, true)
        XCTAssertEqual(config.tls?.fragment?.minLength, 100)
        XCTAssertEqual(config.tls?.fragment?.maxSplit, 2)
        XCTAssertEqual(config.xhttp?.noGrpcHeader, true)
        XCTAssertEqual(config.xhttp?.scMaxEachPostBytes, 1_000_000)
        XCTAssertEqual(config.xhttp?.xPaddingPlacement, .queryInHeader)
        XCTAssertEqual(config.websocket?.path, "/")
        XCTAssertEqual(config.websocket?.earlyDataHeaderName, "Sec-WebSocket-Protocol")
        XCTAssertEqual(config.grpc?.multiMode, false)
        XCTAssertEqual(config.reality?.publicKey, Data((0..<32).map { UInt8($0) }))
        XCTAssertEqual(config.reality?.shortId, Data([0x6b, 0xa8]))
        XCTAssertEqual(config.chain?.first?.outboundProtocol, .socks5)
    }

    func testAServerSurvivesAnEncodeDecodeRoundTrip() throws {
        let original = try ProxyConfiguration.fromUrl(
            "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=reality&sni=www.example.com" +
                "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=6ba85179e30d4fc2&type=grpc&serviceName=svc#R"
        )
        var chained = original
        let hop = try ProxyConfiguration.fromUrl("trojan://pw@example.com:443?fragment=3,1,tlshello#T")
        chained.chain = [hop]
        let data = try JSONEncoder().encode(chained)
        let decoded = try JSONDecoder().decode(ProxyConfiguration.self, from: data)
        XCTAssertEqual(decoded, chained)

        // The Reality key and short id are stored as the text forms links use.
        let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let reality = try XCTUnwrap(object["reality"] as? [String: Any])
        XCTAssertEqual(reality["publicKey"] as? String, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
        XCTAssertEqual(reality["shortId"] as? String, "6ba85179e30d4fc2")
        XCTAssertEqual(object["outboundProtocol"] as? String, "vless")
    }

    func testASubscriptionDecodesWithItsDefaults() throws {
        let subscription = try decode(Subscription.self, #"{"name":"S","url":"https://sub.example.com/x","subInfo":{"text":"Hi"}}"#)
        XCTAssertTrue(subscription.autoUpdate)
        XCTAssertFalse(subscription.updateOnOpen)
        XCTAssertFalse(subscription.collapsed)
        XCTAssertEqual(subscription.frontTargets, [])
        XCTAssertEqual(subscription.subInfo?.color, "blue")
        XCTAssertFalse(subscription.isFailing)
    }

    func testRulesChainsAndSettingsDecode() throws {
        let rules = try decode([DomainRule].self, #"[{"type":2,"value":"example.com"},{"type":"domainKeyword","value":"ads"},{"type":"ipCIDR","value":"192.0.2.0/24"}]"#)
        XCTAssertEqual(rules.map { $0.type }, [.domainSuffix, .domainKeyword, .ipCidr])
        XCTAssertEqual(String(data: try JSONEncoder().encode(rules[1]), encoding: .utf8)?.contains("\"type\":3"), true)

        let chain = try decode(ProxyChain.self, #"{"name":"C"}"#)
        XCTAssertEqual(chain.proxyIds, [])

        XCTAssertEqual(try decode([ThemeMode].self, #"["dark","sepia"]"#), [.dark, .system])
        XCTAssertEqual(try decode(TunnelSettings.self, "{}"), TunnelSettings())
    }

    func testAnUnknownProtocolIsRefusedRatherThanGuessed() {
        XCTAssertThrowsError(try decode([OutboundProtocol].self, #"["carrier-pigeon"]"#))
        XCTAssertEqual(try decode([OutboundProtocol].self, #"["amneziawg","hy2","http2"]"#), [.wireguard, .hysteria2, .naiveHttp2])
    }
}
