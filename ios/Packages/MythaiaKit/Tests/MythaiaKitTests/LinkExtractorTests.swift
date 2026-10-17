import XCTest
@testable import MythaiaKit

final class LinkExtractorTests: XCTestCase {

    func testLinksComeOutOfAChatMessage() {
        let text = """
        Привет! Твой ключ: vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main.
        Запасной (на всякий): hysteria2://pass@192.0.2.4:443?sni=x.example.com#Backup, и подписка
        «https://sub.example.com/abc?token=1» — обновляй раз в день!
        """
        XCTAssertEqual(LinkExtractor.extract(text), [
            "vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main",
            "hysteria2://pass@192.0.2.4:443?sni=x.example.com#Backup",
            "https://sub.example.com/abc?token=1",
        ])
    }

    func testOtherClientsImportLinksAreUnwrapped() {
        XCTAssertEqual(LinkExtractor.extract("happ://add/https://sub.example.com/x"), ["https://sub.example.com/x"])
        XCTAssertEqual(
            LinkExtractor.extract("v2rayng://install-config?url=https%3A%2F%2Fsub.example.com%2Fa%3Fb%3Dc"),
            ["https://sub.example.com/a?b=c"]
        )
        XCTAssertEqual(
            LinkExtractor.extract("sing-box://import-remote-profile?url=https%3A%2F%2Fs.example.com%2Fp#name=My"),
            ["https://s.example.com/p"]
        )
    }

    func testALetterThatGrowsWhenLowercasedDoesNotShiftTheLink() {
        // "İ".lowercased() is two characters, so an offset found in a
        // lowercased copy of the text landed one character into every link after it.
        let link = "vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@example.com:443?security=tls#Main"
        XCTAssertEqual(LinkExtractor.extract("İşte: \(link)"), [link])
        XCTAssertEqual(LinkExtractor.extract("İİİ \(link) İİİ"), [link])
    }

    func testAVmessLinkIsNotMistakenForShadowsocksAndDuplicatesCollapse() {
        let vmess = "vmess://eyJhZGQiOiIxLjIuMy40In0="
        XCTAssertEqual(LinkExtractor.extract("\(vmess)\n\(vmess)"), [vmess])
        XCTAssertEqual(LinkExtractor.extract("(ss://YWVzOnBhc3M@192.0.2.4:8388#a)"), ["ss://YWVzOnBhc3M@192.0.2.4:8388#a"])
    }

    func testAnUnknownSchemeIsPassedOverAndTheCaseOfAKnownOneDoesNotMatter() {
        XCTAssertEqual(
            LinkExtractor.extract("see foo://bar and tg://x, then VLESS://id@h.example:443#a, or https://sub.example.com/x"),
            ["VLESS://id@h.example:443#a", "https://sub.example.com/x"]
        )
    }

    func testABracketTheLinkOpenedStaysWithIt() {
        XCTAssertEqual(
            LinkExtractor.extract("see https://example.com/wiki/Thing_(x)."),
            ["https://example.com/wiki/Thing_(x)"]
        )
    }

    func testTenThousandLinksComeOutInOrderAndQuickly() {
        // Searched for scheme by scheme, a paste this size never finished.
        let links: [String] = (0..<10_000).map { i -> String in
            switch i % 4 {
            case 0: return "vless://5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13@h\(i).example.com:443?security=tls&type=ws#n\(i)"
            case 1: return "trojan://pw\(i)@t\(i).example.com:443#t\(i)"
            case 2: return "hy2://pass\(i)@192.0.\(i / 256 % 256).\(i % 256):443?sni=x.example.com#h\(i)"
            default: return "ss://YWVzOnBhc3M@s\(i).example.com:8388#s\(i)"
            }
        }
        let text = links.enumerated().map { pair -> String in
            pair.offset % 3 == 0 ? "Server \(pair.offset): \(pair.element)." : pair.element
        }.joined(separator: "\n")
        let started = Date()
        let found = LinkExtractor.extract(text)
        let seconds = Date().timeIntervalSince(started)
        XCTAssertEqual(found, links)
        XCTAssertLessThan(seconds, 10, "took \(seconds) s")
    }
}
