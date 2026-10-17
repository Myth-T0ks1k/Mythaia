import Foundation
import MythaiaKit

/// The countries the bypass can route directly, from the metadata of the
/// bundled rules database (Rules.db, the same file the Android app ships).
enum CountryCatalog {
    /// Used when the database is missing from the bundle.
    static let fallbackCodes = ["AE", "BY", "CN", "CU", "IR", "RU", "SA", "TM", "TR", "VN"]

    static func supportedCountryCodes() -> [String] {
        let codes = RulesDatabase.bundled()?.supportedCountryCodes ?? []
        return codes.isEmpty ? fallbackCodes : codes
    }

    /// The bypass a new install starts with: Turkmenistan for a device in
    /// Turkmen, nothing otherwise.
    static func suggestedCountryCode() -> String? {
        let language = Locale.preferredLanguages.first?.lowercased() ?? ""
        if language == "tk" || language.hasPrefix("tk-") || language.hasPrefix("tk_") { return "TM" }
        return nil
    }

    /// "🇹🇲 Turkmenistan": the flag and the country in the reader's language.
    static func displayName(_ code: String) -> String {
        let name = Locale.current.localizedString(forRegionCode: code) ?? code
        return flag(code) + " " + name
    }

    static func flag(_ code: String) -> String {
        var out = ""
        for scalar in code.uppercased().unicodeScalars {
            guard scalar.value >= 65 && scalar.value <= 90,
                  let indicator = UnicodeScalar(0x1F1E6 + scalar.value - 65) else { return "" }
            out.unicodeScalars.append(indicator)
        }
        return out
    }
}
