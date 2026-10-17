import XCTest
@testable import MythaiaKit

/// Clash (mihomo) configs: the YAML reader and the `proxies:` importer on top of it.
final class ImporterClashTests: XCTestCase {

    private let uuid = "11111111-2222-3333-4444-555555555555"

    private var document: String {
        """
        # A config the way panels generate it.
        mixed-port: 7890
        allow-lan: false
        mode: rule
        dns:
          enable: true
          nameserver:
            - 192.0.2.53
            - https://dns.example.com/dns-query
        x-base: &base
          udp: true
          skip-cert-verify: false
        proxies:
        - name: "VLESS Reality"
          type: vless
          server: 192.0.2.10
          port: 443
          uuid: \(uuid)
          network: tcp
          tls: true
          flow: xtls-rprx-vision
          servername: www.example.com   # the name in the hello
          client-fingerprint: chrome
          reality-opts:
            public-key: SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc
            short-id: 6ba85179e30d4fc2
        - {name: 'Flow SS', type: ss, server: 192.0.2.11, port: "8388", cipher: aes-256-gcm, password: "p#ss: word"}
        - name: WS VLESS
          <<: *base
          type: vless
          server: '[2001:db8::5]'
          port: 443
          uuid: \(uuid)
          network: ws
          tls: true
          alpn:
          - h2
          - http/1.1
          ws-opts:
            path: /ws?ed=2048
            headers:
              Host: cdn.example.com
            max-early-data: 2048
            early-data-header-name: Sec-WebSocket-Protocol
        - name: HU
          type: vless
          server: hu.example.com
          port: 443
          uuid: \(uuid)
          network: ws
          ws-opts: {path: /up, v2ray-http-upgrade: true, headers: {Host: h.example.com}}
        - name: Trojan
          type: trojan
          server: t.example.com
          port: 443
          password: >-
            folded
            secret
          sni: front.example.com
          alpn: [h2, "http/1.1"]
        - name: Hy2
          type: hysteria2
          server: 192.0.2.12
          port: 8443
          password: hy-pw
          up: 50 Mbps
          down: "1 gbps"
          obfs: salamander
          obfs-password: obfs-pw
        - name: Hy2 hopping
          type: hysteria2
          server: 192.0.2.13
          port: 8443
          ports: 20000-30000
          password: hy-pw
        - name: VMess
          type: vmess
          server: 192.0.2.14
          port: 443
          uuid: \(uuid)
          alterId: 0
          cipher: auto
          tls: true
          network: ws
          ws-opts:
            path: /v
            headers: {host: v.example.com}
        - name: Legacy VMess
          type: vmess
          server: 192.0.2.15
          port: 443
          uuid: \(uuid)
          alterId: 64
        - name: Socks
          type: socks5
          server: 192.0.2.16
          port: 1080
          user: u
          pass: p
        - name: Snell
          type: snell
          server: 192.0.2.17
          port: 443
        - name: Short id
          type: vless
          server: 192.0.2.18
          port: 443
          uuid: short-name
        proxy-groups:
          - name: Auto
            type: url-test
            proxies: [VLESS Reality, "Flow SS", WS VLESS]
            url: https://probe.example.com/generate_204
            interval: 300
        rule-providers:
          ads:
            type: http
            url: "https://rules.example.com/ads.yaml"
            interval: 86400
        rules:
          - DOMAIN-SUFFIX,example.com,Auto
          - MATCH,DIRECT
        script:
          code: |
            def main(ctx, md):
              # not a YAML comment, part of the script
              return "DIRECT"
        """
    }

    func testTheReaderBuildsTheTreeLibyamlWould() throws {
        let root = try XCTUnwrap(ClashYAML.parse(document)?.objectValue)
        XCTAssertEqual(root.optString("mixed-port"), "7890")
        XCTAssertEqual(root.optObject("dns")?.optArray("nameserver")?.optString(1), "https://dns.example.com/dns-query")
        let proxies = try XCTUnwrap(root.optArray("proxies"))
        XCTAssertEqual(proxies.count, 12)
        let group = try XCTUnwrap(root.optArray("proxy-groups")?.optObject(0))
        XCTAssertEqual(group.optArray("proxies")?.map { $0.text }, ["VLESS Reality", "Flow SS", "WS VLESS"])
        XCTAssertEqual(root.optObject("rule-providers")?.optObject("ads")?.optString("url"), "https://rules.example.com/ads.yaml")
        XCTAssertEqual(root.optArray("rules")?.optString(0), "DOMAIN-SUFFIX,example.com,Auto")
        XCTAssertEqual(
            root.optObject("script")?.optString("code"),
            "def main(ctx, md):\n  # not a YAML comment, part of the script\n  return \"DIRECT\"\n"
        )
        // A merge brings the anchored keys in; the item's own keys win.
        let ws = try XCTUnwrap(proxies.optObject(2))
        XCTAssertEqual(ws.optString("udp"), "true")
        XCTAssertEqual(ws.optString("type"), "vless")
        // Quoted text keeps what would otherwise start a comment or a key.
        XCTAssertEqual(proxies.optObject(1)?.optString("password"), "p#ss: word")
        XCTAssertEqual(proxies.optObject(4)?.optString("password"), "folded secret")
    }

    func testEverySupportedProxyImportsAndTheRestAreCounted() throws {
        let result = try ClashProxyParser.parse(document)
        XCTAssertEqual(result.configurations.map { $0.name }, [
            "VLESS Reality", "Flow SS", "WS VLESS", "HU", "Trojan", "Hy2", "VMess", "Socks", "Short id",
        ])
        // Port hopping, a legacy alterId and Snell have no dialer here.
        XCTAssertEqual(result.skippedCount, 3)
    }

    func testEachProxyCarriesItsSettings() throws {
        var byName: [String: ProxyConfiguration] = [:]
        for config in try ClashProxyParser.parse(document).configurations { byName[config.name] = config }

        let reality = try XCTUnwrap(byName["VLESS Reality"])
        XCTAssertEqual(reality.security, "reality")
        XCTAssertEqual(reality.reality?.serverName, "www.example.com")
        XCTAssertEqual(reality.reality?.shortId.count, 8)
        XCTAssertEqual(reality.flow, "xtls-rprx-vision")

        let ss = try XCTUnwrap(byName["Flow SS"])
        XCTAssertEqual(ss.outboundProtocol, .shadowsocks)
        XCTAssertEqual(ss.serverPort, 8388)
        XCTAssertEqual(ss.ssPassword, "p#ss: word")

        let ws = try XCTUnwrap(byName["WS VLESS"])
        XCTAssertEqual(ws.serverAddress, "2001:db8::5")
        XCTAssertEqual(ws.transport, "ws")
        XCTAssertEqual(ws.websocket?.host, "cdn.example.com")
        XCTAssertEqual(ws.websocket?.path, "/ws?ed=2048")
        XCTAssertEqual(ws.websocket?.maxEarlyData, 2048)
        XCTAssertEqual(ws.tls?.alpn, ["h2", "http/1.1"])

        let hu = try XCTUnwrap(byName["HU"])
        XCTAssertEqual(hu.transport, "httpupgrade")
        XCTAssertEqual(hu.httpUpgrade?.host, "h.example.com")
        XCTAssertEqual(hu.httpUpgrade?.path, "/up")
        XCTAssertEqual(hu.security, "none")

        let trojan = try XCTUnwrap(byName["Trojan"])
        XCTAssertEqual(trojan.trojanPassword, "folded secret")
        XCTAssertEqual(trojan.trojanTls?.serverName, "front.example.com")
        XCTAssertEqual(trojan.trojanTls?.alpn, ["h2", "http/1.1"])

        let hy = try XCTUnwrap(byName["Hy2"])
        XCTAssertEqual(hy.hysteriaUpMbps, 50)
        XCTAssertEqual(hy.hysteriaDownMbps, 1000)
        XCTAssertEqual(hy.obfuscation, "salamander")
        XCTAssertEqual(hy.obfuscationPassword, "obfs-pw")

        let vmess = try XCTUnwrap(byName["VMess"])
        XCTAssertEqual(vmess.websocket?.host, "v.example.com")
        XCTAssertEqual(vmess.tls?.serverName, "v.example.com")
        XCTAssertNil(vmess.vmessSecurity)

        let socks = try XCTUnwrap(byName["Socks"])
        XCTAssertEqual(socks.socks5Username, "u")
        XCTAssertEqual(socks.socks5Password, "p")
    }

    func testAShortIdIsDerivedAsXrayDerivesIt() throws {
        // Xray maps a 1-30 character id to SHA-1(16 zero bytes || id) with the
        // version-5 and variant bits set; the value below is that digest worked
        // out by hand from the first 16 bytes of the hash.
        let derived = try XCTUnwrap(ClashProxyParser.parseXrayUuid("short-name"))
        var input = Data(repeating: 0, count: 16)
        input.append(contentsOf: Array("short-name".utf8))
        var bytes = Array(ClashTestSHA1.hash(input).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x50
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        let expected = bytes.map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(derived.uuidString.replacingOccurrences(of: "-", with: "").lowercased(), expected)
        XCTAssertEqual(derived.uuidString.lowercased().dropFirst(14).first, "5")
        XCTAssertEqual(ClashProxyParser.parseXrayUuid(uuid)?.uuidString.lowercased(), uuid)
        XCTAssertEqual(
            ClashProxyParser.parseXrayUuid("11111111222233334444555555555555")?.uuidString.lowercased(),
            uuid
        )
    }

    func testADocumentWithoutProxiesIsRefused() {
        XCTAssertThrowsError(try ClashProxyParser.parse("proxy-providers:\n  p:\n    type: http\n")) { error in
            guard case MythaiaError.parse(let why)? = error as? MythaiaError else { return XCTFail("\(error)") }
            XCTAssertTrue(why.contains("proxies"), why)
        }
    }

    func testTheSubscriptionPathReadsClash() throws {
        let result = try SubscriptionFetcher.parse(Data(document.utf8))
        XCTAssertEqual(result.configurations.count, 9)
        // And the same document base64-encoded, as some panels serve it.
        let encoded = Data(document.utf8).base64EncodedData()
        XCTAssertEqual(try SubscriptionFetcher.parse(encoded).configurations.count, 9)
    }

    func testIndentedSequencesAndMultiLineFlowCollectionsRead() throws {
        let text = """
        proxies:
          - name: a
            type: socks5
            server: 192.0.2.20
            port: 1080
          - {
              name: b, type: socks5,
              server: 192.0.2.21, port: 1081
            }
        """
        let result = try ClashProxyParser.parse(text)
        XCTAssertEqual(result.configurations.map { $0.name }, ["a", "b"])
        XCTAssertEqual(result.configurations.last?.serverPort, 1081)
    }
}

/// SHA-1 for the derivation check, written out so the test does not lean on
/// the code under test; FIPS 180-4 §6.1.
private enum ClashTestSHA1 {
    static func hash(_ message: Data) -> [UInt8] {
        var h0: UInt32 = 0x6745_2301
        var h1: UInt32 = 0xEFCD_AB89
        var h2: UInt32 = 0x98BA_DCFE
        var h3: UInt32 = 0x1032_5476
        var h4: UInt32 = 0xC3D2_E1F0
        var bytes = [UInt8](message)
        let bitLength = UInt64(bytes.count) * 8
        bytes.append(0x80)
        while bytes.count % 64 != 56 { bytes.append(0) }
        for shift in stride(from: 56, through: 0, by: -8) { bytes.append(UInt8(truncatingIfNeeded: bitLength >> UInt64(shift))) }
        var w = [UInt32](repeating: 0, count: 80)
        for chunk in stride(from: 0, to: bytes.count, by: 64) {
            for i in 0..<16 {
                let b0 = UInt32(bytes[chunk + i * 4]) << 24
                let b1 = UInt32(bytes[chunk + i * 4 + 1]) << 16
                let b2 = UInt32(bytes[chunk + i * 4 + 2]) << 8
                let b3 = UInt32(bytes[chunk + i * 4 + 3])
                w[i] = b0 | b1 | b2 | b3
            }
            for i in 16..<80 {
                let x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w[i] = (x << 1) | (x >> 31)
            }
            var a = h0, b = h1, c = h2, d = h3, e = h4
            for i in 0..<80 {
                let f: UInt32
                let k: UInt32
                if i < 20 {
                    f = (b & c) | (~b & d)
                    k = 0x5A82_7999
                } else if i < 40 {
                    f = b ^ c ^ d
                    k = 0x6ED9_EBA1
                } else if i < 60 {
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1B_BCDC
                } else {
                    f = b ^ c ^ d
                    k = 0xCA62_C1D6
                }
                let rotated = (a << 5) | (a >> 27)
                let temp = rotated &+ f &+ e &+ k &+ w[i]
                e = d
                d = c
                c = (b << 30) | (b >> 2)
                b = a
                a = temp
            }
            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
        }
        var out: [UInt8] = []
        for h in [h0, h1, h2, h3, h4] {
            out.append(UInt8(truncatingIfNeeded: h >> 24))
            out.append(UInt8(truncatingIfNeeded: h >> 16))
            out.append(UInt8(truncatingIfNeeded: h >> 8))
            out.append(UInt8(truncatingIfNeeded: h))
        }
        return out
    }
}
