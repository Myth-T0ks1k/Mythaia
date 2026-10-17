import Foundation

/// The App Group container the app and the packet tunnel share. Both read
/// the group's name from their own Info.plist, so the bundle identifiers and
/// the group can be changed in one build setting without touching code.
public enum AppGroup {
    /// The Info.plist key both targets carry; Xcode fills it from the
    /// `MYTHAIA_APP_GROUP` build setting.
    public static let infoPlistKey = "MythaiaAppGroup"

    /// Used when the key is missing or was never expanded, as in a test run.
    public static let defaultIdentifier = "group.com.mythaia.pro"

    public static var identifier: String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: infoPlistKey) as? String else {
            return defaultIdentifier
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // An unexpanded "$(MYTHAIA_APP_GROUP)" means the build setting is
        // missing; the default at least names a group the profile may have.
        if trimmed.isEmpty || trimmed.hasPrefix("$(") { return defaultIdentifier }
        return trimmed
    }

    /// The shared container, or a private directory when the process has no
    /// App Group entitlement (an unsigned build, the package's tests): the
    /// app then still works on its own, it just shares nothing with a tunnel.
    public static var containerURL: URL {
        let fileManager = FileManager.default
        if let url = fileManager.containerURL(forSecurityApplicationGroupIdentifier: identifier) {
            #if os(macOS)
            // macOS hands out a path even to a process that is not entitled
            // to it; only one that exists is really the group's.
            if fileManager.fileExists(atPath: url.path) { return url }
            #else
            return url
            #endif
        }
        return fallbackURL
    }

    /// Application Support/Mythaia, created on first use.
    static var fallbackURL: URL {
        let fileManager = FileManager.default
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        let url = base.appendingPathComponent("Mythaia", isDirectory: true)
        try? fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
