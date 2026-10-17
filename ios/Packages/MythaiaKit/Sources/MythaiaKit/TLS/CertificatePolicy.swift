import Foundation

/// The global certificate-validation policy. The TLS client reads it at
/// validation time, so a change in the settings applies to the next
/// handshake without rebuilding any configuration.
public enum CertificatePolicy {

    private final class State: @unchecked Sendable {
        let lock = NSLock()
        var allowInsecure = false
        var trustedFingerprints: [String] = []
    }

    private static let state = State()

    /// "Allow insecure" for every server: certificates are not checked at
    /// all. A server's pinned certificate still is.
    public static var allowInsecure: Bool {
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.allowInsecure
    }

    /// SHA-256 fingerprints (lowercase hex) of leaf certificates the user has
    /// explicitly trusted, accepted when the system does not vouch for them.
    public static var trustedFingerprints: [String] {
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.trustedFingerprints
    }

    public static func setAllowInsecure(_ value: Bool) {
        state.lock.lock()
        state.allowInsecure = value
        state.lock.unlock()
    }

    public static func setTrustedFingerprints(_ fingerprints: [String]) {
        let normalised = fingerprints.map { $0.lowercased() }
        state.lock.lock()
        state.trustedFingerprints = normalised
        state.lock.unlock()
    }
}
