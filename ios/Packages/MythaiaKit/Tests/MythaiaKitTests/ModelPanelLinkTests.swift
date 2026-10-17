import XCTest
@testable import MythaiaKit

/**
 * Links the way a live panel writes them: string-valued xhttp `extra`,
 * FinalMask in `fm=`, and uTLS family names in `fp=`. Credentials and hosts
 * are placeholders; the shapes are verbatim.
 */
final class ModelPanelLinkTests: XCTestCase {

    private func q(_ s: String) -> String { LinkText.urlEncode(s) }

    private let extra = #"{"scMaxEachPostBytes":"500000","scMinPostsIntervalMs":"60","xPaddingBytes":"100-1000","xmux":{"maxConnections":16,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000"}}"#
    private let fm = #"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3"],"delays":["1"],"maxSplit":"2"}}]}"#

    func testXhttpExtraWithStringValuesIsApplied() throws {
        let url = "vless://11111111-2222-3333-4444-555555555555@203.0.113.20:443?encryption=none&security=tls&type=xhttp&headerType=none&path=%2F&host=d555.cdn.example.net&mode=auto&extra=\(q(extra))&fm=\(q(fm))&sni=d555.cdn.example.net&fp=safari#Gold"
        let config = try ProxyConfiguration.fromUrl(url)
        let xhttp = try XCTUnwrap(config.xhttp)
        XCTAssertEqual(xhttp.scMaxEachPostBytes, 500_000)
        XCTAssertEqual(xhttp.scMinPostsIntervalMs, 60)
        XCTAssertEqual(xhttp.xPaddingBytesFrom, 100)
        XCTAssertEqual(xhttp.xPaddingBytesTo, 1000)
        XCTAssertEqual(xhttp.host, "d555.cdn.example.net")
    }

    func testAnExtraEncodedTwiceIsStillRead() throws {
        let twice = q(q(#"{"scMaxEachPostBytes":250000,"noGRPCHeader":true}"#))
        let config = try ProxyConfiguration.fromUrl(
            "vless://11111111-2222-3333-4444-555555555555@192.0.2.1:443?security=tls&type=xhttp&extra=\(twice)#X"
        )
        XCTAssertEqual(config.xhttp?.scMaxEachPostBytes, 250_000)
        XCTAssertEqual(config.xhttp?.noGrpcHeader, true)
    }

    func testFmOnATlsLinkBecomesTheServersFragmentSettings() throws {
        let url = "vless://11111111-2222-3333-4444-555555555555@203.0.113.51:443?encryption=none&security=tls&type=ws&headerType=none&path=%2F&host=d666.cdn.example.net&fm=\(q(fm))&sni=d666.cdn.example.net&fp=safari#Edge"
        let config = try ProxyConfiguration.fromUrl(url)
        let fragment = try XCTUnwrap(config.tls?.fragment)
        XCTAssertEqual(fragment.lengthRanges, [3...3])
        XCTAssertEqual(fragment.delayRanges, [1...1])
        XCTAssertEqual(fragment.maxSplit, 2)
        XCTAssertEqual(config.tls?.fingerprint, .safari26)
    }

    func testFpFamilyNamesMapToTheNewestProfileOfTheFamily() {
        XCTAssertEqual(TlsFingerprint.fromRaw("edge"), .edge85)
        XCTAssertEqual(TlsFingerprint.fromRaw("chrome"), .chrome133)
        XCTAssertEqual(TlsFingerprint.fromRaw("firefox"), .firefox148)
        XCTAssertEqual(TlsFingerprint.fromRaw("randomized"), .random)
        XCTAssertEqual(TlsFingerprint.fromRaw("chrome_120"), .chrome120)
        XCTAssertEqual(TlsFingerprint.fromRaw("something new"), .chrome133)
    }

    func testFmSalamanderFillsHysteria2ObfuscationWhenObfsParamsAreAbsent() throws {
        let udp = #"{"udp":[{"type":"salamander","settings":{"password":"pw123"}}],"quicParams":{"congestion":"bbr"}}"#
        let config = try ProxyConfiguration.fromUrl("hysteria2://secret@198.51.100.54:443?fm=\(q(udp))&sni=grid.example.net#Social")
        XCTAssertEqual(config.obfuscation, "salamander")
        XCTAssertEqual(config.obfuscationPassword, "pw123")
    }

    func testFragmentSurvivesTheShareLinkRoundTrip() throws {
        let url = "vless://11111111-2222-3333-4444-555555555555@198.51.100.12:443?encryption=none&security=tls&type=grpc&serviceName=grpc.example.net&authority=front.example.net&mode=gun&fm=\(q(fm))&sni=front.example.net&fp=edge#Relay"
        let config = try ProxyConfiguration.fromUrl(url)
        let again = try ProxyConfiguration.fromUrl(config.toUrl())
        let fragment = try XCTUnwrap(again.tls?.fragment)
        XCTAssertEqual(fragment.lengthRange, 3...3)
        XCTAssertEqual(fragment.maxSplit, 2)
        XCTAssertTrue(config.toUrl().contains("fragment="))
    }

    func testSecurityNoneLinkCarriesNoFragmentEvenWithFm() throws {
        let url = "vless://11111111-2222-3333-4444-555555555555@192.0.2.86:80?encryption=none&security=none&type=xhttp&host=cdn.example.com&mode=stream-up&fm=\(q(fm))#Premium"
        let config = try ProxyConfiguration.fromUrl(url)
        XCTAssertNil(config.tls)
        XCTAssertEqual(config.xhttp?.mode, XHttpMode.fromRaw("stream-up"))
    }
}
