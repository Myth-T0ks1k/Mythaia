import Foundation
import SQLite3

/// The bundled routing rules (Rules.db, the same file on every platform),
/// opened read-only.
///
/// Tables:
///  - `rules(source, type, value)`: domain and IP rules keyed by source
///    name, a country code or a service name; `type` is the raw value of
///    `DomainRuleType` (0 CIDR, 1 CIDR6, 2 domain suffix, 3 keyword, 4 geoip)
///  - `metadata(key, value)`: JSON lists and maps (`supportedServices`,
///    `supportedCountryCodes`, `languageToCountry`)
public final class RulesDatabase: @unchecked Sendable {
    public let url: URL

    private var handle: OpaquePointer?
    private let lock = NSLock()

    /// Opens the database at `url`. It is opened immutable: the file sits in
    /// a signed, read-only bundle, and SQLite then neither locks it nor
    /// looks for a journal beside it.
    public init(url: URL) throws {
        self.url = url
        var opened: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI | SQLITE_OPEN_NOMUTEX
        let status = sqlite3_open_v2(RulesDatabase.immutableURI(for: url), &opened, flags, nil)
        guard status == SQLITE_OK, let opened else {
            var reason = "error \(status)"
            if let opened, let message = sqlite3_errmsg(opened) {
                reason = String(cString: message)
            }
            if let opened { sqlite3_close(opened) }
            throw MythaiaError.parse("rules database \(url.lastPathComponent): \(reason)")
        }
        handle = opened
    }

    deinit {
        if let handle { sqlite3_close(handle) }
    }

    /// Rules.db from `bundle` (the app's or the tunnel's own); nil, with a
    /// log line, when it is missing or does not open. Routing then works
    /// without a country list.
    public static func bundled(in bundle: Bundle = .main) -> RulesDatabase? {
        guard let url = bundle.url(forResource: "Rules", withExtension: "db") else {
            Log.warning("Rules.db is not in the bundle; the country bypass is off")
            return nil
        }
        do {
            return try RulesDatabase(url: url)
        } catch {
            Log.error("Rules.db could not be opened: \(error.localizedDescription)")
            return nil
        }
    }

    /// The rules of one source; rows of a type this build does not know are
    /// skipped.
    public func loadRules(source: String) -> [DomainRule] {
        locked {
            guard let handle else { return [] }
            var statement: OpaquePointer?
            let sql = "SELECT type, value FROM rules WHERE source = ?"
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
                return []
            }
            defer { sqlite3_finalize(statement) }
            sqlite3_bind_text(statement, 1, source, -1, RulesDatabase.transient)
            var out: [DomainRule] = []
            while sqlite3_step(statement) == SQLITE_ROW {
                let raw = Int(sqlite3_column_int(statement, 0))
                guard let type = DomainRuleType(rawValue: raw),
                      let text = sqlite3_column_text(statement, 1) else { continue }
                out.append(DomainRule(type: type, value: String(cString: text)))
            }
            return out
        }
    }

    public func loadMetadata(_ key: String) -> String? {
        locked {
            guard let handle else { return nil }
            var statement: OpaquePointer?
            let sql = "SELECT value FROM metadata WHERE key = ?"
            guard sqlite3_prepare_v2(handle, sql, -1, &statement, nil) == SQLITE_OK, let statement else {
                return nil
            }
            defer { sqlite3_finalize(statement) }
            sqlite3_bind_text(statement, 1, key, -1, RulesDatabase.transient)
            guard sqlite3_step(statement) == SQLITE_ROW, let text = sqlite3_column_text(statement, 0) else {
                return nil
            }
            return String(cString: text)
        }
    }

    public func loadStringArray(_ key: String) -> [String] {
        guard let json = loadMetadata(key) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: Data(json.utf8))) ?? []
    }

    public func loadStringMap(_ key: String) -> [String: String] {
        guard let json = loadMetadata(key) else { return [:] }
        return (try? JSONDecoder().decode([String: String].self, from: Data(json.utf8))) ?? [:]
    }

    /// The built-in service rule sets (Telegram, YouTube, ...).
    public var supportedServices: [String] { loadStringArray("supportedServices") }

    /// The countries a bypass can be set for.
    public var supportedCountryCodes: [String] { loadStringArray("supportedCountryCodes") }

    /// Language code to the country a speaker of it most likely lives in.
    public var languageToCountry: [String: String] { loadStringMap("languageToCountry") }

    /// The bypass country to suggest for a language code such as "tk"; nil
    /// when there is none.
    public func suggestedCountryCode(languageCode: String?) -> String? {
        guard let language = languageCode?.lowercased(), !language.isEmpty else { return nil }
        return languageToCountry[language]
    }

    /// Everything that goes direct for a bypass country: its database rules
    /// and `CountryBypassExtras`.
    public func countryBypassRules(_ countryCode: String) -> [DomainRule] {
        let code = countryCode.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !code.isEmpty else { return [] }
        return loadRules(source: code) + CountryBypassExtras.rulesFor(code)
    }

    /// `file:` URI with the path escaped and `immutable=1`.
    static func immutableURI(for url: URL) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "?#%")
        let path = url.path.addingPercentEncoding(withAllowedCharacters: allowed) ?? url.path
        return "file:" + path + "?immutable=1"
    }

    /// SQLite copies a bound string at once with this destructor.
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
