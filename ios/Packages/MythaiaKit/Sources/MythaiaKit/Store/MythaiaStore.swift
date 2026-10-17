import Foundation

/// The app's persistent state as JSON files in one directory, normally the
/// App Group container, so the tunnel reads what the app wrote.
///
/// Reads go to disk every time: the app and the tunnel are two processes and
/// either may have written since. Writes replace a file atomically (see
/// `StoreFile.write`), so the other process never reads half a file. A list
/// entry this build cannot decode (a server of a protocol added by a newer
/// version) is kept aside and written back with the next save, so a
/// downgrade does not erase it.
public final class MythaiaStore: @unchecked Sendable {
    public static let shared = MythaiaStore(directory: AppGroup.containerURL)

    public let directory: URL

    private let lock = NSLock()
    /// Per file, the raw JSON entries that did not decode at the last load.
    private var undecodable: [String: [Any]] = [:]

    enum FileName {
        static let configurations = "configurations.json"
        static let subscriptions = "subscriptions.json"
        static let chains = "chains.json"
        static let settings = "settings.json"
        static let selection = "selection.json"
        static let tunnelStart = "tunnel-start.json"
    }

    public init(directory: URL) {
        self.directory = directory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    // MARK: - Lists

    public func loadConfigurations() -> [ProxyConfiguration] {
        loadList(ProxyConfiguration.self, from: FileName.configurations)
    }

    public func saveConfigurations(_ value: [ProxyConfiguration]) {
        saveList(value, to: FileName.configurations)
    }

    public func loadSubscriptions() -> [Subscription] {
        loadList(Subscription.self, from: FileName.subscriptions)
    }

    public func saveSubscriptions(_ value: [Subscription]) {
        saveList(value, to: FileName.subscriptions)
    }

    public func loadChains() -> [ProxyChain] {
        loadList(ProxyChain.self, from: FileName.chains)
    }

    public func saveChains(_ value: [ProxyChain]) {
        saveList(value, to: FileName.chains)
    }

    // MARK: - Single values

    /// The settings, with defaults for anything missing. A first load
    /// writes them straight back, so the generated `hwid` is the same on
    /// every later load and in the tunnel.
    public func loadSettings() -> AppSettings {
        let url = fileURL(FileName.settings)
        return locked {
            guard let data = StoreFile.read(url) else {
                let fresh = AppSettings()
                try? writeValueLocked(fresh, to: url)
                return fresh
            }
            do {
                let settings = try JSONDecoder().decode(AppSettings.self, from: data)
                if !MythaiaStore.containsKey("hwid", in: data) {
                    try? writeValueLocked(settings, to: url)
                }
                return settings
            } catch {
                Log.error("Settings could not be read (\(error.localizedDescription)); using defaults")
                StoreFile.quarantine(url)
                let fresh = AppSettings()
                try? writeValueLocked(fresh, to: url)
                return fresh
            }
        }
    }

    public func saveSettings(_ value: AppSettings) {
        saveValue(value, to: FileName.settings)
    }

    public func loadSelection() -> SelectionState {
        loadValue(SelectionState.self, from: FileName.selection) ?? SelectionState()
    }

    public func saveSelection(_ value: SelectionState) {
        saveValue(value, to: FileName.selection)
    }

    public func saveTunnelStart(_ value: TunnelStartOptions) {
        saveValue(value, to: FileName.tunnelStart)
    }

    /// What the app saved for the tunnel's last start; nil if it never did.
    public func loadTunnelStart() -> TunnelStartOptions? {
        loadValue(TunnelStartOptions.self, from: FileName.tunnelStart)
    }

    // MARK: - Generic I/O

    func fileURL(_ name: String) -> URL {
        directory.appendingPathComponent(name, isDirectory: false)
    }

    func loadValue<T: Decodable>(_ type: T.Type, from name: String) -> T? {
        let url = fileURL(name)
        return locked {
            guard let data = StoreFile.read(url) else { return nil }
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                Log.error("\(name) could not be read: \(error.localizedDescription)")
                StoreFile.quarantine(url)
                return nil
            }
        }
    }

    func saveValue<T: Encodable>(_ value: T, to name: String) {
        let url = fileURL(name)
        locked {
            do {
                try writeValueLocked(value, to: url)
            } catch {
                Log.error("Could not save \(name): \(error.localizedDescription)")
            }
        }
    }

    /// Decodes a JSON array entry by entry. The whole array is tried first,
    /// since that is the common case and the fast one for thousands of
    /// servers; only when it fails is each entry decoded on its own.
    func loadList<T: Decodable>(_ type: T.Type, from name: String) -> [T] {
        let url = fileURL(name)
        return locked {
            undecodable[name] = nil
            guard let data = StoreFile.read(url) else { return [] }
            let decoder = JSONDecoder()
            if let all = try? decoder.decode([T].self, from: data) {
                return all
            }
            guard let raw = (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) as? [Any] else {
                Log.error("\(name) is not a JSON list; set aside")
                StoreFile.quarantine(url)
                return []
            }
            var values: [T] = []
            var kept: [Any] = []
            for entry in raw {
                guard let entryData = try? JSONSerialization.data(withJSONObject: entry, options: [.fragmentsAllowed]),
                      let value = try? decoder.decode(T.self, from: entryData) else {
                    kept.append(entry)
                    continue
                }
                values.append(value)
            }
            if !kept.isEmpty {
                Log.warning("\(name): \(kept.count) entries this version cannot read are kept as they are")
                undecodable[name] = kept
            }
            return values
        }
    }

    func saveList<T: Encodable>(_ value: [T], to name: String) {
        let url = fileURL(name)
        locked {
            do {
                var data = try MythaiaStore.encoder().encode(value)
                if let kept = undecodable[name], !kept.isEmpty {
                    var merged = (try JSONSerialization.jsonObject(with: data, options: [])) as? [Any] ?? []
                    merged.append(contentsOf: kept)
                    data = try JSONSerialization.data(withJSONObject: merged, options: [])
                }
                try StoreFile.write(data, to: url)
            } catch {
                Log.error("Could not save \(name): \(error.localizedDescription)")
            }
        }
    }

    /// Caller holds `lock`.
    private func writeValueLocked<T: Encodable>(_ value: T, to url: URL) throws {
        let data = try MythaiaStore.encoder().encode(value)
        try StoreFile.write(data, to: url)
    }

    /// Compact output: pretty-printing made a store of thousands of servers
    /// several times larger to write, read and hold in memory.
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return encoder
    }

    /// Whether the top-level JSON object in `data` has `key`.
    static func containsKey(_ key: String, in data: Data) -> Bool {
        guard let object = (try? JSONSerialization.jsonObject(with: data, options: [])) as? [String: Any] else {
            return false
        }
        return object[key] != nil
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock()
        defer { lock.unlock() }
        return try body()
    }
}

/// File operations for the store.
enum StoreFile {
    static func read(_ url: URL) -> Data? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        return try? Data(contentsOf: url)
    }

    /// Writes `data` to a sibling temporary file with a unique name, flushes
    /// it to disk and renames it over `url`: a crash or a kill mid-write
    /// leaves the old file or the new one, never a half-written file the
    /// next launch cannot decode. The unique name keeps two writers (the app
    /// and the tunnel) from mixing their bytes in one temporary file.
    static func write(_ data: Data, to url: URL) throws {
        let fileManager = FileManager.default
        let folder = url.deletingLastPathComponent()
        try fileManager.createDirectory(at: folder, withIntermediateDirectories: true)
        let temp = folder.appendingPathComponent(url.lastPathComponent + "." + UUID().uuidString + ".tmp")
        do {
            #if os(iOS)
            // Readable after the first unlock, so an on-demand start of the
            // tunnel at boot can still load the server.
            try data.write(to: temp, options: [.completeFileProtectionUntilFirstUserAuthentication])
            #else
            try data.write(to: temp, options: [])
            #endif
            // The rename is only atomic against a power loss if the bytes are
            // on disk first; without the sync the name can be committed with
            // an empty file behind it.
            if let handle = try? FileHandle(forWritingTo: temp) {
                try? handle.synchronize()
                try? handle.close()
            }
            if rename(temp.path, url.path) != 0 {
                let code = errno
                throw CocoaError(.fileWriteUnknown, userInfo: [
                    NSFilePathErrorKey: url.path,
                    NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: Int(code)),
                ])
            }
        } catch {
            try? fileManager.removeItem(at: temp)
            throw error
        }
    }

    /// Moves an unreadable file aside as `name.corrupt-<millis>` so the next
    /// save does not overwrite what might still be recovered by hand.
    static func quarantine(_ url: URL) {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        let millis = Int64(Date().timeIntervalSince1970 * 1000)
        let target = url.deletingLastPathComponent()
            .appendingPathComponent(url.lastPathComponent + ".corrupt-" + String(millis))
        try? FileManager.default.moveItem(at: url, to: target)
    }
}
