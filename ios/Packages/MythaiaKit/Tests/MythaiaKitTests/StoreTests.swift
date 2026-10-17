import Foundation
import XCTest
@testable import MythaiaKit

final class StoreTests: XCTestCase {
    private var directory: URL!
    private var store: MythaiaStore!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("StoreTests-" + UUID().uuidString, isDirectory: true)
        store = MythaiaStore(directory: directory)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func write(_ text: String, to name: String) throws {
        try Data(text.utf8).write(to: directory.appendingPathComponent(name))
    }

    private func files() -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.sorted()
    }

    // MARK: - Settings

    func testSettingsDecodeEmptyObjectToDefaults() throws {
        let settings = try JSONDecoder().decode(AppSettings.self, from: Data("{}".utf8))
        XCTAssertEqual(settings.routingMode, .rule)
        XCTAssertNil(settings.bypassCountryCode)
        XCTAssertEqual(settings.themeMode, .system)
        XCTAssertEqual(settings.localProxyPort, 0)
        XCTAssertEqual(settings.autoRecheckMinutes, 10)
        XCTAssertEqual(settings.latencyKind, .handshake)
        XCTAssertFalse(settings.hwid.isEmpty)
    }

    func testSettingsKeepWhatIsThereAndDefaultTheRest() throws {
        let json = "{\"routingMode\":\"global\",\"localProxyPort\":1080,\"bypassCountryCode\":\"TM\",\"hwid\":\"abc\"}"
        let settings = try JSONDecoder().decode(AppSettings.self, from: Data(json.utf8))
        XCTAssertEqual(settings.routingMode, .global)
        XCTAssertEqual(settings.localProxyPort, 1080)
        XCTAssertEqual(settings.bypassCountryCode, "TM")
        XCTAssertEqual(settings.hwid, "abc")
        XCTAssertEqual(settings.autoRecheckMinutes, 10)
        XCTAssertEqual(settings.latencyKind, .handshake)
    }

    func testUnknownValuesFallBackToDefaults() throws {
        let json = "{\"routingMode\":\"sideways\",\"latencyKind\":\"psychic\",\"localProxyPort\":70000,\"autoRecheckMinutes\":0,\"bypassCountryCode\":\"\"}"
        let settings = try JSONDecoder().decode(AppSettings.self, from: Data(json.utf8))
        XCTAssertEqual(settings.routingMode, .rule)
        XCTAssertEqual(settings.latencyKind, .handshake)
        XCTAssertEqual(settings.localProxyPort, 0)
        XCTAssertEqual(settings.autoRecheckMinutes, 10)
        XCTAssertNil(settings.bypassCountryCode)
        XCTAssertNil(settings.normalizedBypassCountryCode)
    }

    func testSettingsRoundTripThroughTheStore() {
        var settings = AppSettings(hwid: "fixed-id")
        settings.routingMode = .global
        settings.bypassCountryCode = "tm"
        settings.localProxyPort = 8899
        settings.latencyKind = .tcp
        settings.autoRecheckMinutes = 25
        store.saveSettings(settings)
        let loaded = store.loadSettings()
        XCTAssertEqual(loaded, settings)
        XCTAssertEqual(loaded.normalizedBypassCountryCode, "TM")
    }

    func testFirstLoadKeepsTheGeneratedIdentifier() {
        let first = store.loadSettings()
        let second = store.loadSettings()
        XCTAssertEqual(first.hwid, second.hwid)
        let other = MythaiaStore(directory: directory)
        XCTAssertEqual(other.loadSettings().hwid, first.hwid)
    }

    func testSettingsWithoutIdentifierGetOneThatSticks() throws {
        try write("{\"routingMode\":\"global\"}", to: "settings.json")
        let first = store.loadSettings()
        XCTAssertEqual(first.routingMode, .global)
        XCTAssertEqual(store.loadSettings().hwid, first.hwid)
    }

    func testCorruptSettingsAreSetAsideAndDefaultsUsed() throws {
        try write("this is not json", to: "settings.json")
        let settings = store.loadSettings()
        XCTAssertEqual(settings.routingMode, .rule)
        XCTAssertTrue(files().contains { $0.hasPrefix("settings.json.corrupt-") })
        XCTAssertTrue(files().contains("settings.json"))
    }

    // MARK: - Selection

    func testSelectionDefaultsWhenMissing() throws {
        XCTAssertEqual(store.loadSelection(), SelectionState())
        let decoded = try JSONDecoder().decode(SelectionState.self, from: Data("{}".utf8))
        XCTAssertEqual(decoded.activeGroupId, "default")
        XCTAssertTrue(decoded.groupPins.isEmpty)
        XCTAssertTrue(decoded.autoChoices.isEmpty)
        XCTAssertNil(decoded.selectedChainId)
        XCTAssertTrue(decoded.isAuto("default"))
    }

    func testSelectionRoundTrip() {
        let pinned = UUID()
        let chosen = UUID()
        let chain = UUID()
        let subscriptionGroup = UUID().uuidString
        var selection = SelectionState(activeGroupId: subscriptionGroup)
        selection.groupPins["default"] = pinned
        selection.autoChoices[subscriptionGroup] = chosen
        store.saveSelection(selection)
        XCTAssertEqual(store.loadSelection(), selection)
        XCTAssertFalse(selection.isAuto("default"))
        XCTAssertTrue(selection.isAuto(subscriptionGroup))

        selection.selectedChainId = chain
        store.saveSelection(selection)
        let loaded = store.loadSelection()
        XCTAssertEqual(loaded.selectedChainId, chain)
        XCTAssertFalse(loaded.isAuto(subscriptionGroup))
    }

    // MARK: - Lists and files

    private struct Item: Codable, Equatable {
        var name: String
        var port: Int
    }

    func testListsAreEmptyWhenNothingWasSaved() {
        XCTAssertTrue(store.loadConfigurations().isEmpty)
        XCTAssertTrue(store.loadSubscriptions().isEmpty)
        XCTAssertTrue(store.loadChains().isEmpty)
        XCTAssertNil(store.loadTunnelStart())
    }

    func testListRoundTrip() {
        let items = [Item(name: "one", port: 1), Item(name: "two/three", port: 2)]
        store.saveList(items, to: "items.json")
        XCTAssertEqual(store.loadList(Item.self, from: "items.json"), items)
        let text = (try? String(contentsOf: directory.appendingPathComponent("items.json"), encoding: .utf8)) ?? ""
        XCTAssertTrue(text.contains("two/three"), "slashes are not escaped")
    }

    func testEntriesThatDoNotDecodeSurviveASave() throws {
        try write("[{\"name\":\"kept\",\"port\":1},{\"name\":\"future\",\"protocol\":\"warp-drive\"}]", to: "items.json")
        let loaded = store.loadList(Item.self, from: "items.json")
        XCTAssertEqual(loaded, [Item(name: "kept", port: 1)])

        store.saveList(loaded + [Item(name: "added", port: 3)], to: "items.json")
        let data = try Data(contentsOf: directory.appendingPathComponent("items.json"))
        let raw = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        XCTAssertEqual(raw.count, 3)
        XCTAssertTrue(raw.contains { ($0["protocol"] as? String) == "warp-drive" })
        XCTAssertEqual(store.loadList(Item.self, from: "items.json").count, 2)
    }

    func testAListThatIsNotJsonIsSetAside() throws {
        try write("{\"not\":\"a list\"}", to: "items.json")
        XCTAssertTrue(store.loadList(Item.self, from: "items.json").isEmpty)
        XCTAssertTrue(files().contains { $0.hasPrefix("items.json.corrupt-") })
    }

    func testAtomicWritesLeaveNoTemporaryFiles() {
        for index in 0..<5 {
            store.saveList([Item(name: "n\(index)", port: index)], to: "items.json")
            store.saveSettings(AppSettings(localProxyPort: UInt16(1000 + index), hwid: "x"))
        }
        XCTAssertEqual(files(), ["items.json", "settings.json"])
        XCTAssertEqual(store.loadSettings().localProxyPort, 1004)
    }

    func testConcurrentSavesAllLand() {
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "store-test", attributes: .concurrent)
        for index in 0..<20 {
            group.enter()
            queue.async {
                self.store.saveList([Item(name: "n\(index)", port: index)], to: "items.json")
                group.leave()
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
        XCTAssertEqual(store.loadList(Item.self, from: "items.json").count, 1)
        XCTAssertEqual(files(), ["items.json"])
    }

    func testStartOptionsDictionaryWithoutOptionsIsNil() {
        XCTAssertNil(TunnelStartOptions(startOptions: nil))
        XCTAssertNil(TunnelStartOptions(startOptions: ["other": NSNumber(value: 1)]))
        let garbage: [String: NSObject] = [TunnelStartOptions.startOptionsKey: Data("{}".utf8) as NSData]
        XCTAssertNil(TunnelStartOptions(startOptions: garbage))
    }

    func testGroupIdentifierFallsBackWithoutInfoPlistKey() {
        // The test runner's bundle has no MythaiaAppGroup key.
        XCTAssertEqual(AppGroup.identifier, AppGroup.defaultIdentifier)
    }
}
