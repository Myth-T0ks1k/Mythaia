import XCTest
@testable import MythaiaKit

final class SubscriptionMetadataTests: XCTestCase {

    private func read(headers: [String: String] = [:], body: String = "", secure: Bool = true) -> SubscriptionFetcher.PanelInfo {
        SubscriptionMetadata.read(header: { headers[$0] }, body: SubscriptionMetadata.bodyFields(body), secure: secure)
    }

    private func result(_ panel: SubscriptionFetcher.PanelInfo, name: String? = nil) -> SubscriptionFetcher.Result {
        SubscriptionFetcher.Result(configurations: [], name: name, upload: nil, download: nil, total: nil, expire: nil, panel: panel)
    }

    private let base = Subscription(name: "Panel", url: "https://panel.example.com:8443/sub/TOKEN?fmt=raw")

    func testBodyLinesAreReadAsHappWritesThem() {
        let announce = Data("Привет".utf8).base64EncodedString()
        let fields = SubscriptionMetadata.bodyFields("""
        #profile-title: My VPN
        # Announce :  base64:\(announce)
        #profile-title: second one loses
        #not a field
        vless://id@example.com:443#node
        """)
        XCTAssertEqual(fields["profile-title"], "My VPN")
        XCTAssertEqual(SubscriptionMetadata.decode(fields["announce"]), "Привет")
        XCTAssertEqual(Set(fields.keys), ["profile-title", "announce"])
    }

    func testAHeaderWinsOverTheSameKeyInTheBody() {
        let panel = read(headers: ["profile-title": "From header"], body: "#profile-title: From body\n#support-url: https://t.me/help\n")
        XCTAssertEqual(panel.title, "From header")
        XCTAssertEqual(panel.supportUrl, "https://t.me/help")
    }

    func testFlagsAreOnForTrueOr1Only() {
        XCTAssertEqual(read(body: "#subscription-auto-update-open-enable: 1").updateOnOpen, true)
        XCTAssertEqual(read(body: "#subscription-auto-update-open-enable: TRUE").updateOnOpen, true)
        XCTAssertEqual(read(body: "#subscription-auto-update-open-enable: yes please").updateOnOpen, false)
        XCTAssertNil(read().updateOnOpen)
        XCTAssertEqual(read(body: "#subscription-auto-update-enable: 0").autoUpdate, false)
        XCTAssertEqual(read(body: "#notification-subs-expire: 1").expireNotice, true)
    }

    func testKeysThatMoveTheSubscriptionNeedVerifiedTlsAndHttps() {
        let body = """
        #new-url: https://new.example.com/sub/T
        #new-domain: other.example.com
        #fallback-url: https://backup.example.com/sub/T
        #fronting-target: 192.0.2.16, cdn.example.net:443, bad host!
        #fronting-sni: www.example.org
        """
        let secure = read(body: body)
        XCTAssertEqual(secure.newUrl, "https://new.example.com/sub/T")
        XCTAssertEqual(secure.newDomain, "other.example.com")
        XCTAssertEqual(secure.fallbackUrl, "https://backup.example.com/sub/T")
        XCTAssertEqual(secure.frontTargets, ["192.0.2.16", "cdn.example.net:443"])
        XCTAssertEqual(secure.frontSni, "www.example.org")

        let plain = read(body: body, secure: false)
        XCTAssertNil(plain.newUrl)
        XCTAssertNil(plain.newDomain)
        XCTAssertNil(plain.fallbackUrl)
        XCTAssertNil(plain.frontTargets)
        XCTAssertNil(plain.frontSni)

        XCTAssertNil(read(body: "#new-url: http://new.example.com/sub").newUrl)
        XCTAssertNil(read(body: "#fallback-url: javascript:alert(1)").fallbackUrl)
    }

    func testSubInfoAndTheExpiryNotice() {
        let panel = read(body: """
        #sub-info-text: Pay by Friday
        #sub-info-color: GREEN
        #sub-info-button-text: Pay
        #sub-info-button-link: https://pay.example.com
        #sub-expire: 1
        #sub-expire-button-link: https://pay.example.com/renew
        """)
        XCTAssertEqual(panel.subInfo, Subscription.SubInfo(text: "Pay by Friday", color: "green", buttonText: "Pay", buttonLink: "https://pay.example.com"))
        XCTAssertEqual(panel.expireNotice, true)
        XCTAssertEqual(panel.expireButtonLink, "https://pay.example.com/renew")
        XCTAssertEqual(read(body: "#sub-info-text: x\n#sub-info-color: purple").subInfo?.color, "blue")
    }

    func testNewUrlMovesTheSubscriptionAndKeepsItsFronting() {
        var fronted = base
        fronted.frontSni = "www.example.org"
        fronted.frontTargets = ["192.0.2.16"]
        let moved = SubscriptionMetadata.applyTo(fronted, result: result(read(body: "#new-url: https://new.example.com/s/T")))
        XCTAssertEqual(moved.url, "https://new.example.com/s/T")
        XCTAssertEqual(moved.frontSni, "www.example.org")
        XCTAssertEqual(moved.frontTargets, ["192.0.2.16"])
    }

    func testNewUrlInHappsFrontedFormBringsItsOwnFronting() {
        let moved = SubscriptionMetadata.applyTo(
            base,
            result: result(read(body: "#new-url: https://cdn.example.net/s/T#Main?resolve-address=192.0.2.22&host=panel2.example.com"))
        )
        XCTAssertEqual(moved.url, "https://panel2.example.com/s/T")
        XCTAssertEqual(moved.frontSni, "cdn.example.net")
        XCTAssertEqual(moved.frontTargets, ["192.0.2.22"])
    }

    func testNewDomainKeepsThePathTheQueryAndThePort() {
        let moved = SubscriptionMetadata.applyTo(base, result: result(read(body: "#new-domain: Mirror.Example.com")))
        XCTAssertEqual(moved.url, "https://mirror.example.com:8443/sub/TOKEN?fmt=raw")
        let withPort = SubscriptionMetadata.applyTo(base, result: result(read(body: "#new-domain: mirror.example.com:443")))
        XCTAssertEqual(withPort.url, "https://mirror.example.com:443/sub/TOKEN?fmt=raw")
    }

    func testFrontingKeysSetChangeAndStopTheFronting() {
        let on = SubscriptionMetadata.applyTo(base, result: result(read(body: "#fronting-target: 192.0.2.16\n#fronting-sni: www.example.org")))
        XCTAssertEqual(on.frontTargets, ["192.0.2.16"])
        XCTAssertEqual(on.frontSni, "www.example.org")
        XCTAssertEqual(on.url, base.url)

        // An SNI alone dials the panel's own address, as in a link.
        let sniOnly = SubscriptionMetadata.applyTo(base, result: result(read(body: "#fronting-sni: www.example.org")))
        XCTAssertEqual(sniOnly.frontTargets, ["panel.example.com:8443"])

        let off = SubscriptionMetadata.applyTo(on, result: result(read(body: "#fronting-target: off")))
        XCTAssertTrue(off.frontTargets.isEmpty)
        XCTAssertNil(off.frontSni)

        // Saying nothing leaves the fronting as it was.
        XCTAssertEqual(SubscriptionMetadata.applyTo(on, result: result(read())).frontTargets, on.frontTargets)
    }

    func testHappsResolveAddressAndHostFrontTheUrlsOwnHostOnce() {
        let subscription = Subscription(name: "P", url: "https://cdn.example.net/sub/T")
        let panel = read(body: "#resolve-address: 192.0.2.33\n#host: panel.example.com")
        let once = SubscriptionMetadata.applyTo(subscription, result: result(panel))
        XCTAssertEqual(once.url, "https://panel.example.com/sub/T")
        XCTAssertEqual(once.frontSni, "cdn.example.net")
        XCTAssertEqual(once.frontTargets, ["192.0.2.33"])
        // The next refresh says the same and changes nothing.
        var again = SubscriptionMetadata.applyTo(once, result: result(panel))
        again.lastUpdate = once.lastUpdate
        XCTAssertEqual(again, once)
    }

    func testMessagesAreWithdrawnWhenThePanelStopsSendingThemTheRestIsKept() {
        var failing = base
        failing.lastFailure = 5
        failing.lastFailureMessage = "HTTP 502"
        let first = SubscriptionMetadata.applyTo(
            failing,
            result: result(read(body: "#announce: Maintenance\n#sub-info-text: Hi\n#support-url: https://t.me/x\n#profile-update-interval: 6"))
        )
        XCTAssertEqual(first.announce, "Maintenance")
        XCTAssertEqual(first.subInfo?.text, "Hi")
        XCTAssertNil(first.lastFailure)
        XCTAssertNil(first.lastFailureMessage)
        XCTAssertFalse(first.isFailing)

        let second = SubscriptionMetadata.applyTo(first, result: result(read()))
        XCTAssertNil(second.announce)
        XCTAssertNil(second.subInfo)
        XCTAssertEqual(second.supportUrl, "https://t.me/x")
        XCTAssertEqual(second.updateIntervalHours, 6)
    }

    func testACustomisedNameIsKept() {
        var renamed = base
        renamed.name = "Mine"
        renamed.isNameCustomized = true
        XCTAssertEqual(SubscriptionMetadata.applyTo(renamed, result: result(read(), name: "Panel name")).name, "Mine")
        XCTAssertEqual(SubscriptionMetadata.applyTo(base, result: result(read(), name: "Panel name")).name, "Panel name")
    }

    func testReplaceHostKeepsUserInfoAndHandlesIPv6() {
        XCTAssertEqual(SubscriptionMetadata.replaceHost("https://u:p@a.example/x", "b.example"), "https://u:p@b.example/x")
        XCTAssertEqual(SubscriptionMetadata.replaceHost("https://a.example:8443/x?y=1", "[2001:db8::1]"), "https://[2001:db8::1]:8443/x?y=1")
        XCTAssertEqual(SubscriptionMetadata.replaceHost("https://[2001:db8::1]:8443", "b.example:9000"), "https://b.example:9000")
    }

    func testTheExpiryWarningComesThreeDaysAhead() {
        let day: Int64 = 24 * 60 * 60 * 1000
        let now: Int64 = 1_000_000_000_000
        var sub = Subscription(name: "P", url: "https://p.example", expireNotice: true)
        sub.expire = now + 4 * day
        XCTAssertNil(sub.expiryWarning(now: now))
        sub.expire = now + 3 * day
        XCTAssertEqual(sub.expiryWarning(now: now), .soon(days: 3))
        // Whole days, as the usage card counts them.
        sub.expire = now + 2 * day + day / 4
        XCTAssertEqual(sub.expiryWarning(now: now), .soon(days: 2))
        sub.expire = now + 1
        XCTAssertEqual(sub.expiryWarning(now: now), .soon(days: 1))
        sub.expire = now
        XCTAssertEqual(sub.expiryWarning(now: now), .expired)
        // Only when the panel asked for it.
        sub.expireNotice = false
        XCTAssertNil(sub.expiryWarning(now: now))
    }
}
