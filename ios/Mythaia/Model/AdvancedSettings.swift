import Foundation
import MythaiaKit

/// Settings the tunnel needs beside `AppSettings`: the global "allow
/// insecure", certificates the user trusts by fingerprint, and the user's
/// routing rules. Kept in a file of their own in the App Group container,
/// which the app writes and the tunnel reads at start and on `reload`.
///
/// Only Foundation and MythaiaKit are used here, so the tunnel target can
/// compile this file as it is.
struct AdvancedSettings: Codable, Equatable {
    /// No certificate is checked on any server (a pinned one still is).
    var allowInsecure: Bool
    /// SHA-256 of leaf certificates trusted without a certificate authority,
    /// lowercase hex.
    var trustedFingerprints: [String]
    /// The user's rules, first match wins; they apply in rule mode only.
    var routeRules: [RouteRule]

    init(allowInsecure: Bool = false, trustedFingerprints: [String] = [], routeRules: [RouteRule] = []) {
        self.allowInsecure = allowInsecure
        self.trustedFingerprints = trustedFingerprints
        self.routeRules = routeRules
    }

    private enum CodingKeys: String, CodingKey {
        case allowInsecure, trustedFingerprints, routeRules
    }

    /// A field this build cannot read costs that field, not the file.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        allowInsecure = (try? container.decodeIfPresent(Bool.self, forKey: .allowInsecure)) ?? false
        trustedFingerprints = ((try? container.decodeIfPresent([String].self, forKey: .trustedFingerprints)) ?? nil) ?? []
        routeRules = ((try? container.decodeIfPresent([RouteRule].self, forKey: .routeRules)) ?? nil) ?? []
    }

    /// Hands the certificate settings to the TLS code of this process.
    func applyCertificatePolicy() {
        CertificatePolicy.setAllowInsecure(allowInsecure)
        CertificatePolicy.setTrustedFingerprints(trustedFingerprints)
    }
}

/// Reads and writes `AdvancedSettings` in the App Group container.
enum AdvancedSettingsStore {
    static let fileName = "advanced-settings.json"

    static var url: URL {
        AppGroup.containerURL.appendingPathComponent(fileName, isDirectory: false)
    }

    static func load() -> AdvancedSettings {
        guard let data = try? Data(contentsOf: url),
              let value = try? JSONDecoder().decode(AdvancedSettings.self, from: data) else {
            return AdvancedSettings()
        }
        return value
    }

    static func save(_ value: AdvancedSettings) {
        do {
            let data = try JSONEncoder().encode(value)
            #if os(iOS)
            // Readable after the first unlock, like the rest of the store, so
            // an on-demand start at boot finds it.
            try data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            #else
            try data.write(to: url, options: [.atomic])
            #endif
        } catch {
            Log.error("Could not save the advanced settings: \(error.localizedDescription)")
        }
    }
}
