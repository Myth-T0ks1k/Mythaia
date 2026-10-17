import Foundation
import SQLite3
import XCTest
@testable import MythaiaKit

final class RouterTests: XCTestCase {
    private var temporaryDirectory: URL!

    override func setUpWithError() throws {
        temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("RouterTests-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    // MARK: - Private ranges and local names

    func testPrivateAddressesGoDirectInBothModes() {
        let privateHosts = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.10",
            "169.254.10.20",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.251",
            "::1",
            "[::1]",
            "::",
            "fe80::1",
            "fd12:3456::1",
            "ff02::fb",
            "::ffff:192.168.0.1",
        ]
        for mode in RoutingMode.allCases {
            let router = Router(mode: mode)
            for host in privateHosts {
                XCTAssertEqual(router.decide(host), .direct, "\(host) in \(mode.rawValue) mode")
            }
        }
    }

    func testPublicAddressesNextToPrivateRangesGoThroughTheProxy() {
        let router = Router(mode: .rule)
        let publicHosts = ["172.32.0.1", "172.15.255.255", "100.128.0.1", "100.63.255.255", "8.8.8.8", "2001:4860:4860::8888"]
        for host in publicHosts {
            XCTAssertEqual(router.decide(host), .proxy, host)
        }
    }

    func testLocalNamesGoDirect() {
        let router = Router(mode: .global)
        let names = ["localhost", "app.localhost", "printer.local", "PRINTER.LOCAL", "printer.local.", "nas.lan", "router.home.arpa"]
        for name in names {
            XCTAssertEqual(router.decide(name), .direct, name)
        }
        XCTAssertEqual(router.decide("example.com"), .proxy)
        XCTAssertEqual(router.decide("locallan.com"), .proxy)
    }

    func testEmptyHostIsBlocked() {
        let router = Router(mode: .rule)
        XCTAssertEqual(router.decide(""), .block)
        XCTAssertEqual(router.decide("  "), .block)
        XCTAssertEqual(router.decide("."), .block)
    }

    // MARK: - Country bypass

    private let bypass = [
        DomainRule(type: .domainSuffix, value: ".zz"),
        DomainRule(type: .ipCidr, value: "203.0.113.0/24"),
        DomainRule(type: .ipCidr, value: "198.51.100.128/25"),
        DomainRule(type: .ipCidr6, value: "2001:db8::/32"),
        DomainRule(type: .geoip, value: "ZZ"),
    ]

    func testCountryBypassAppliesInRuleMode() {
        let router = Router(mode: .rule, bypassRules: bypass)
        XCTAssertEqual(router.decide("shop.example.zz"), .direct)
        XCTAssertEqual(router.decide("zz"), .direct)
        XCTAssertEqual(router.decide("example.zz."), .direct)
        XCTAssertEqual(router.decide("notzz"), .proxy)
        XCTAssertEqual(router.decide("example.zz.com"), .proxy)
        XCTAssertEqual(router.decide("203.0.113.77"), .direct)
        XCTAssertEqual(router.decide("203.0.114.1"), .proxy)
        XCTAssertEqual(router.decide("198.51.100.200"), .direct)
        XCTAssertEqual(router.decide("198.51.100.127"), .proxy)
        XCTAssertEqual(router.decide("2001:db8:1::5"), .direct)
        XCTAssertEqual(router.decide("2001:db9::5"), .proxy)
        XCTAssertEqual(router.decide("::ffff:203.0.113.5"), .direct)
    }

    func testGlobalModeIgnoresTheCountryBypass() {
        let router = Router(mode: .global, bypassRules: bypass)
        XCTAssertEqual(router.bypassEntryCount, 0)
        XCTAssertEqual(router.decide("shop.example.zz"), .proxy)
        XCTAssertEqual(router.decide("203.0.113.77"), .proxy)
        XCTAssertEqual(router.decide("2001:db8::5"), .proxy)
        XCTAssertEqual(router.decide("192.168.0.1"), .direct)
    }

    func testTurkmenistanExtrasAreDirectInRuleModeOnly() {
        let extras = CountryBypassExtras.rulesFor("tm")
        XCTAssertEqual(extras.count, 14)
        XCTAssertTrue(CountryBypassExtras.rulesFor("RU").isEmpty)

        let settings = AppSettings(routingMode: .rule, bypassCountryCode: "TM", hwid: "test")
        let router = Router(settings: settings, database: nil)
        XCTAssertEqual(router.decide("177.93.143.10"), .direct)
        XCTAssertEqual(router.decide("95.85.100.1"), .direct)
        XCTAssertEqual(router.decide("2a05:2180::1"), .direct)
        XCTAssertEqual(router.decide("2a05:2188::1"), .proxy)
        XCTAssertEqual(router.decide("mail.example.tm"), .direct)

        var global = settings
        global.routingMode = .global
        let globalRouter = Router(settings: global, database: nil)
        XCTAssertEqual(globalRouter.decide("177.93.143.10"), .proxy)
        XCTAssertEqual(globalRouter.decide("mail.example.tm"), .proxy)
    }

    // MARK: - User rules

    func testUserRulesApplyInRuleModeOnly() {
        let rules = [
            RouteRule(type: .domainSuffix, value: "example.com", action: .direct),
            RouteRule(type: .domainKeyword, value: "ads", action: .block),
            RouteRule(type: .ipCidr, value: "198.51.100.0/24", action: .block),
            RouteRule(type: .ipCidr6, value: "2001:db8:aa::/48", action: .direct),
        ]
        let router = Router(mode: .rule, rules: rules)
        XCTAssertEqual(router.decide("example.com"), .direct)
        XCTAssertEqual(router.decide("www.EXAMPLE.com"), .direct)
        XCTAssertEqual(router.decide("badexample.com"), .proxy)
        XCTAssertEqual(router.decide("ads.tracker.net"), .block)
        XCTAssertEqual(router.decide("198.51.100.9"), .block)
        XCTAssertEqual(router.decide("2001:db8:aa::1"), .direct)
        XCTAssertEqual(router.decide("2001:db8:ab::1"), .proxy)

        let global = Router(mode: .global, rules: rules)
        XCTAssertEqual(global.decide("www.example.com"), .proxy)
        XCTAssertEqual(global.decide("ads.tracker.net"), .proxy)
        XCTAssertEqual(global.decide("198.51.100.9"), .proxy)
    }

    func testFirstMatchingUserRuleWins() {
        let rules = [
            RouteRule(type: .domainSuffix, value: "cdn.example.com", action: .block),
            RouteRule(type: .domainSuffix, value: "example.com", action: .direct),
        ]
        let router = Router(mode: .rule, rules: rules)
        XCTAssertEqual(router.decide("img.cdn.example.com"), .block)
        XCTAssertEqual(router.decide("www.example.com"), .direct)
    }

    // MARK: - Address helpers

    func testIPv4RangeSetMergesAndFinds() {
        let networks = ["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25", "192.0.2.7", "0.0.0.0/0"].compactMap { IPNetwork.parse($0) }
        let everything = IPv4RangeSet(networks)
        XCTAssertEqual(everything.count, 1)
        XCTAssertTrue(everything.contains(0))
        XCTAssertTrue(everything.contains(UInt32.max))

        let some = IPv4RangeSet(["10.0.0.0/24", "10.0.1.0/24", "192.0.2.7"].compactMap { IPNetwork.parse($0) })
        XCTAssertEqual(some.count, 2)
        XCTAssertTrue(some.contains(RouterAddress.ipv4Value([10, 0, 1, 255])!))
        XCTAssertFalse(some.contains(RouterAddress.ipv4Value([10, 0, 2, 0])!))
        XCTAssertTrue(some.contains(RouterAddress.ipv4Value([192, 0, 2, 7])!))
        XCTAssertFalse(some.contains(RouterAddress.ipv4Value([192, 0, 2, 8])!))
        XCTAssertFalse(some.contains(RouterAddress.ipv4Value([9, 255, 255, 255])!))
    }

    func testNetworkParsingRejectsNamesAndBadPrefixes() {
        XCTAssertNil(IPNetwork.parse("example.com/24"))
        XCTAssertNil(IPNetwork.parse("10.0.0.0/33"))
        XCTAssertNil(IPNetwork.parse("10.0.0.0/x"))
        XCTAssertNil(IPNetwork.parse("1.2.3/8"))
        XCTAssertEqual(IPNetwork.parse("10.1.2.3/8")?.bytes, [10, 0, 0, 0])
        XCTAssertEqual(IPNetwork.parse("2001:db8::1/32")?.prefix, 32)
    }

    func testAddressText() {
        XCTAssertEqual(RouterAddress.text([93, 184, 216, 34]), "93.184.216.34")
        var v6 = [UInt8](repeating: 0, count: 16)
        v6[0] = 0x20
        v6[1] = 0x01
        v6[2] = 0x0D
        v6[3] = 0xB8
        v6[15] = 0x01
        XCTAssertEqual(RouterAddress.text(v6), "2001:db8::1")
        XCTAssertNil(RouterAddress.text([1, 2, 3]))
        XCTAssertNil(RouterAddress.parse("example.com"))
        XCTAssertNil(RouterAddress.parse("1.2.3"))
        XCTAssertEqual(RouterAddress.parse("fe80::1%en0")?.count, 16)
    }

    // MARK: - Rules database

    func testBypassCountryFromRulesDatabase() throws {
        let url = temporaryDirectory.appendingPathComponent("Rules test.db")
        try makeRulesDatabase(at: url, rows: [
            ("ZZ", 2, ".zz"),
            ("ZZ", 0, "203.0.113.0/24"),
            ("ZZ", 1, "2001:db8::/32"),
            ("ZZ", 9, "from a newer build"),
            ("Telegram", 2, "t.me"),
        ], metadata: [
            ("supportedCountryCodes", "[\"ZZ\"]"),
            ("supportedServices", "[\"Telegram\"]"),
            ("languageToCountry", "{\"zz\": \"ZZ\"}"),
        ])

        let database = try RulesDatabase(url: url)
        let rules = database.loadRules(source: "ZZ")
        XCTAssertEqual(rules.count, 3, "the row of an unknown type is skipped")
        XCTAssertEqual(rules.first?.value, ".zz")
        XCTAssertEqual(database.supportedCountryCodes, ["ZZ"])
        XCTAssertEqual(database.supportedServices, ["Telegram"])
        XCTAssertEqual(database.suggestedCountryCode(languageCode: "zz"), "ZZ")
        XCTAssertNil(database.suggestedCountryCode(languageCode: "en"))
        XCTAssertNil(database.loadMetadata("missing"))
        XCTAssertTrue(database.loadRules(source: "nothing").isEmpty)
        XCTAssertEqual(database.countryBypassRules("zz").count, 3)

        let ruleSettings = AppSettings(routingMode: .rule, bypassCountryCode: "zz", hwid: "test")
        let router = Router(settings: ruleSettings, database: database)
        XCTAssertEqual(router.decide("bank.example.zz"), .direct)
        XCTAssertEqual(router.decide("203.0.113.9"), .direct)
        XCTAssertEqual(router.decide("2001:db8::9"), .direct)
        XCTAssertEqual(router.decide("t.me"), .proxy)
        XCTAssertEqual(router.decide("example.com"), .proxy)

        var globalSettings = ruleSettings
        globalSettings.routingMode = .global
        let globalRouter = Router(settings: globalSettings, database: database)
        XCTAssertEqual(globalRouter.decide("bank.example.zz"), .proxy)
        XCTAssertEqual(globalRouter.decide("203.0.113.9"), .proxy)

        let noCountry = Router(settings: AppSettings(routingMode: .rule, hwid: "test"), database: database)
        XCTAssertEqual(noCountry.decide("203.0.113.9"), .proxy)
    }

    func testMissingDatabaseFileThrows() {
        let url = temporaryDirectory.appendingPathComponent("absent.db")
        XCTAssertThrowsError(try RulesDatabase(url: url))
    }

    private func makeRulesDatabase(
        at url: URL,
        rows: [(String, Int, String)],
        metadata: [(String, String)]
    ) throws {
        var handle: OpaquePointer?
        guard sqlite3_open(url.path, &handle) == SQLITE_OK, let db = handle else {
            throw MythaiaError.parse("cannot create the test database")
        }
        defer { sqlite3_close(db) }
        let schema = "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            + "CREATE TABLE rules (source TEXT NOT NULL, type INTEGER NOT NULL, value TEXT NOT NULL);"
            + "CREATE INDEX idx_rules_source ON rules(source);"
        guard sqlite3_exec(db, schema, nil, nil, nil) == SQLITE_OK else {
            throw MythaiaError.parse("cannot create the tables")
        }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        for row in rows {
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(db, "INSERT INTO rules (source, type, value) VALUES (?, ?, ?)", -1, &statement, nil) == SQLITE_OK else {
                throw MythaiaError.parse("cannot prepare the insert")
            }
            sqlite3_bind_text(statement, 1, row.0, -1, transient)
            sqlite3_bind_int(statement, 2, Int32(row.1))
            sqlite3_bind_text(statement, 3, row.2, -1, transient)
            let status = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard status == SQLITE_DONE else { throw MythaiaError.parse("insert failed") }
        }
        for entry in metadata {
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(db, "INSERT INTO metadata (key, value) VALUES (?, ?)", -1, &statement, nil) == SQLITE_OK else {
                throw MythaiaError.parse("cannot prepare the insert")
            }
            sqlite3_bind_text(statement, 1, entry.0, -1, transient)
            sqlite3_bind_text(statement, 2, entry.1, -1, transient)
            let status = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard status == SQLITE_DONE else { throw MythaiaError.parse("insert failed") }
        }
    }
}
