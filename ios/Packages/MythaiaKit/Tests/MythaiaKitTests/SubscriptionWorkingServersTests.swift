import XCTest
@testable import MythaiaKit

final class SubscriptionWorkingServersTests: XCTestCase {

    private func server(_ name: String, _ subscription: UUID?) throws -> ProxyConfiguration {
        var config = try ProxyConfiguration.fromUrl("trojan://p@\(name).example.com:443?sni=\(name).example.com#\(name)")
        config.subscriptionId = subscription
        return config
    }

    func testTheSubscriptionsOwnServersComeFirstTheOnesThatAnsweredBeforeTheUntestedAndTheFailed() throws {
        let mine = UUID()
        let other = UUID()
        let ownSlow = try server("own-slow", mine)
        let ownUntested = try server("own-new", mine)
        let ownDead = try server("own-dead", mine)
        let ownFast = try server("own-fast", mine)
        let otherFast = try server("other-fast", other)
        let manual = try server("manual", nil)
        var wireGuard = try server("wg", mine)
        wireGuard.outboundProtocol = .wireguard
        let known: [UUID: Int?] = [
            ownSlow.id: 300,
            ownFast.id: 40,
            ownDead.id: nil,
            otherFast.id: 10,
        ]
        let order = WorkingServers.candidates(
            [manual, ownSlow, ownUntested, ownDead, otherFast, wireGuard, ownFast],
            subscriptionId: mine,
            known: known
        ).map { $0.name }
        XCTAssertEqual(order, ["own-fast", "own-slow", "own-new", "own-dead", "other-fast", "manual"])
    }

    func testAtMostTwentyFourAreChecked() throws {
        let mine = UUID()
        var configs: [ProxyConfiguration] = []
        for i in 0..<40 { configs.append(try server("s\(i)", mine)) }
        let picked = WorkingServers.candidates(configs, subscriptionId: mine, known: [:])
        XCTAssertEqual(picked.count, 24)
        // Equal ranks keep the order they came in.
        XCTAssertEqual(picked.map { $0.name }, (0..<24).map { "s\($0)" })
    }
}
