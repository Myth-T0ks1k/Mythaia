import XCTest
@testable import MythaiaKit

final class SubscriptionLinkTests: XCTestCase {

    func testFrontingInTheFragmentIsReadAndTakenOffTheUrl() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse(
            "https://panel.example.com/sub/AbC+123?lang=ru#front=192.0.2.16,cdn.example.net:443&sni=www.example.org"
        ))
        XCTAssertEqual(link.url, "https://panel.example.com/sub/AbC+123?lang=ru")
        XCTAssertEqual(link.frontTargets, ["192.0.2.16", "cdn.example.net:443"])
        XCTAssertEqual(link.frontSni, "www.example.org")
        XCTAssertTrue(link.isFronted)
    }

    func testAUrlWithoutFrontingComesBackExactlyAsGiven() throws {
        for url in ["https://sub.example.com/abc?token=1", "https://sub.example.com/abc#My%20VPN"] {
            let link = try XCTUnwrap(SubscriptionLink.parse(url))
            XCTAssertEqual(link.url, url)
            XCTAssertFalse(link.isFronted)
            XCTAssertNil(link.frontSni)
        }
        XCTAssertNil(SubscriptionLink.parse("vless://id@example.com:443"))
        XCTAssertNil(SubscriptionLink.parse("not a link"))
    }

    func testANameAloneInTheFragmentNamesTheGroupAndLeavesTheUrlClean() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse("https://sub.example.com/abc?x=1#name=Home%20VPN"))
        XCTAssertEqual(link.url, "https://sub.example.com/abc?x=1")
        XCTAssertEqual(link.name, "Home VPN")
        XCTAssertFalse(link.isFronted)
        let app = try XCTUnwrap(SubscriptionLink.parse("mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fabc&name=Bulk"))
        XCTAssertEqual(SubscriptionLink.parse(app.toFragmentLink())?.url, "https://sub.example.com/abc")
        XCTAssertEqual(SubscriptionLink.parse(app.toFragmentLink())?.name, "Bulk")
    }

    func testAnSniAloneFrontsThePanelsOwnAddress() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse("https://panel.example.com:8443/sub/x#sni=allowed.example.org"))
        XCTAssertEqual(link.frontTargets, ["panel.example.com:8443"])
        XCTAssertEqual(link.frontSni, "allowed.example.org")
    }

    func testTheAppLinkCarriesTheEncodedUrlAndTheFronting() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse(
            "mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub%2FAbC%2B1%3Fa%3D1%26b%3D2" +
                "&front=192.0.2.16&front=203.0.113.10:443&sni=www.example.org&name=Family%20VPN"
        ))
        XCTAssertEqual(link.url, "https://panel.example.com/sub/AbC+1?a=1&b=2")
        XCTAssertEqual(link.frontTargets, ["192.0.2.16", "203.0.113.10:443"])
        XCTAssertEqual(link.frontSni, "www.example.org")
        XCTAssertEqual(link.name, "Family VPN")
    }

    func testAHandWrittenAppLinkKeepsThePanelsOwnQuery() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse(
            "mythaia://import?url=https://panel.example.com/sub?token=1&lang=ru&front=192.0.2.16&front-sni=www.example.org"
        ))
        XCTAssertEqual(link.url, "https://panel.example.com/sub?token=1&lang=ru")
        XCTAssertEqual(link.frontTargets, ["192.0.2.16"])
        XCTAssertEqual(link.frontSni, "www.example.org")
    }

    func testAHiddifyStyleNameAfterTheHashIsTheGroupName() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse("mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fx&front=192.0.2.4#Work"))
        XCTAssertEqual(link.url, "https://sub.example.com/x")
        XCTAssertEqual(link.name, "Work")
        XCTAssertEqual(link.frontTargets, ["192.0.2.4"])
    }

    func testBothFormsSurviveARoundTrip() {
        let original = SubscriptionLink(
            url: "https://panel.example.com/sub/AbC+1?a=1&b=2",
            frontSni: "www.example.org",
            frontTargets: ["192.0.2.16", "[2001:db8::1]:443"],
            name: "Семья & друзья"
        )
        XCTAssertEqual(SubscriptionLink.parse(original.toAppLink()), original)
        XCTAssertEqual(SubscriptionLink.parse(original.toFragmentLink()), original)
        XCTAssertTrue(original.toAppLink().hasPrefix("mythaia://import?url=https%3A%2F%2Fpanel.example.com"))
    }

    func testNoFrontingMeansThePlainUrlInBothForms() {
        let plain = SubscriptionLink(url: "https://sub.example.com/x")
        XCTAssertEqual(plain.toFragmentLink(), "https://sub.example.com/x")
        XCTAssertEqual(plain.toAppLink(), "mythaia://import?url=https%3A%2F%2Fsub.example.com%2Fx")
    }

    func testTheExtractorTurnsAnAppLinkIntoTheFragmentForm() {
        let text = "Подписка: mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub&front=192.0.2.16&sni=www.example.org — открой в Mythaia"
        XCTAssertEqual(LinkExtractor.extract(text), ["https://panel.example.com/sub#front=192.0.2.16&sni=www.example.org"])
        XCTAssertEqual(
            LinkExtractor.extract("https://panel.example.com/sub#front=192.0.2.16&sni=www.example.org"),
            ["https://panel.example.com/sub#front=192.0.2.16&sni=www.example.org"]
        )
    }

    func testHappsFormFrontsTheUrlsHostAndAsksForHost() throws {
        let link = try XCTUnwrap(SubscriptionLink.parse(
            "https://cdn.example.net/sub/TOKEN#My%20VPN?resolve-address=192.0.2.16&host=panel.example.com"
        ))
        XCTAssertEqual(link.url, "https://panel.example.com/sub/TOKEN")
        XCTAssertEqual(link.frontSni, "cdn.example.net")
        XCTAssertEqual(link.frontTargets, ["192.0.2.16"])
        XCTAssertEqual(link.name, "My VPN")

        // Without host the URL is the panel; resolve-address alone is where it is dialled.
        let dialOnly = try XCTUnwrap(SubscriptionLink.parse("https://panel.example.com/sub#?resolve-address=192.0.2.16"))
        XCTAssertEqual(dialOnly.url, "https://panel.example.com/sub")
        XCTAssertNil(dialOnly.frontSni)
        XCTAssertEqual(dialOnly.frontTargets, ["192.0.2.16"])

        // host alone: the front is dialled by its own name.
        let hostOnly = try XCTUnwrap(SubscriptionLink.parse("https://cdn.example.net:8443/sub#host=panel.example.com"))
        XCTAssertEqual(hostOnly.url, "https://panel.example.com:8443/sub")
        XCTAssertEqual(hostOnly.frontSni, "cdn.example.net")
        XCTAssertEqual(hostOnly.frontTargets, ["cdn.example.net:8443"])
    }

    func testTheRemnawaveHelperMatchesItsHostsOnly() {
        XCTAssertTrue(SubscriptionDomainHelper.shouldRequireRemnawaveHWID("https://sub.example.com/abc"))
        XCTAssertFalse(SubscriptionDomainHelper.shouldRequireRemnawaveHWID("https://sub.example.com.evil.example/abc"))
        XCTAssertTrue(SubscriptionDomainHelper.shouldDisableProxyEditing("https://sub.example.com/abc"))
    }
}
