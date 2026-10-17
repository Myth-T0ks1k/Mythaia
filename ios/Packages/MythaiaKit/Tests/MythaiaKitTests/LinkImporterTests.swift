import XCTest
@testable import MythaiaKit

/// The paste box: whatever comes in, the servers and subscriptions in it come out.
final class LinkImporterTests: XCTestCase {

    func testAChatMessageGivesItsServersAndItsSubscription() throws {
        let text = """
        Your key: vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main.
        Backup: trojan://pw@192.0.2.4:443#Backup and the subscription https://sub.example.com/abc?token=1
        """
        let result = try LinkImporter.importFromString(text)
        XCTAssertEqual(result.configurations.map { $0.name }, ["Main", "Backup"])
        XCTAssertEqual(result.subscriptionUrls, ["https://sub.example.com/abc?token=1"])
        XCTAssertTrue(result.failures.isEmpty)
    }

    func testAnHttpsLinkIsAProxyOnlyWhenTheCallerSaysSo() throws {
        let asProxy = try LinkImporter.importFromString("https://u:p@proxy.example.com:443#P", naiveProtocol: .naiveHttp11)
        XCTAssertEqual(asProxy.configurations.first?.outboundProtocol, .naiveHttp11)
        XCTAssertTrue(asProxy.subscriptionUrls.isEmpty)
        // Fronting written into the link makes it a subscription whatever the caller said.
        let fronted = try LinkImporter.importFromString("https://sub.example.com/x#front=192.0.2.16", naiveProtocol: .naiveHttp11)
        XCTAssertEqual(fronted.subscriptionUrls, ["https://sub.example.com/x#front=192.0.2.16"])
    }

    func testABase64BodyJsonAndAnIniAreReadWhole() throws {
        let links = "trojan://pw@a.example.com:443#A\ntrojan://pw@b.example.com:443#B"
        XCTAssertEqual(try LinkImporter.importFromString(Data(links.utf8).base64EncodedString()).configurations.count, 2)

        let json = #"{"outbounds":[{"protocol":"socks","tag":"s","settings":{"servers":[{"address":"192.0.2.9","port":1080}]}}]}"#
        XCTAssertEqual(try LinkImporter.importFromString(json).configurations.first?.name, "s")

        let privateKey = WireGuardConfig.encodeKey(Data(repeating: 1, count: 32))
        let peerKey = WireGuardConfig.encodeKey(Data(repeating: 2, count: 32))
        let ini = "[Interface]\nPrivateKey = \(privateKey)\n\n[Peer]\nPublicKey = \(peerKey)\nEndpoint = vpn.example.com:51820\n"
        XCTAssertEqual(try LinkImporter.importFromString(ini).configurations.first?.outboundProtocol, .wireguard)
    }

    func testABadLinkIsReportedAndTheGoodOnesStillCome() throws {
        let result = try LinkImporter.importFromString("vless://not-a-uuid@example.com:443#X\ntrojan://pw@example.com:443#T")
        XCTAssertEqual(result.configurations.map { $0.name }, ["T"])
        XCTAssertEqual(result.failures.count, 1)
        XCTAssertThrowsError(try LinkImporter.importFromString("vless://not-a-uuid@example.com:443#X"))
        XCTAssertThrowsError(try LinkImporter.importFromString("   "))
    }
}
