import Foundation

/// Which palette the app draws in.
public enum ThemeMode: String, Codable, CaseIterable, Hashable {
    /// Follow the device.
    case system = "system"
    case light = "light"
    case dark = "dark"

    public var raw: String { rawValue }

    public static func fromRaw(_ raw: String?) -> ThemeMode {
        guard let raw = raw else { return .system }
        return ThemeMode(rawValue: raw) ?? .system
    }

    public static let key = "themeMode"

    /// An unknown stored value means the device's palette, never a failed load.
    public init(from decoder: Decoder) throws {
        let raw = try? decoder.singleValueContainer().decode(String.self)
        self = ThemeMode.fromRaw(raw)
    }
}
