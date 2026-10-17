import Foundation

/// The tunnel-wide ClientHello-fragmentation setting. The dialer reads it at
/// dial time, so a change in the settings applies to the next connection
/// without rebuilding any configuration. The app and the tunnel each set it
/// from the stored settings when they start and whenever the user changes it.
///
/// On by default, with Xray's popular 100-200 bytes, 10-20 ms: the product
/// ships to networks where the server name in the first packet is what a
/// filter reads, and the cost is a few dozen milliseconds once per
/// connection to the proxy server.
public enum FragmentPolicy {

    /// Keys the settings store may keep the tunnel-wide value under.
    public static let keyEnabled = "fragmentEnabled"
    public static let keyMinLength = "fragmentMinLength"
    public static let keyMaxLength = "fragmentMaxLength"
    public static let keyMinInterval = "fragmentMinInterval"
    public static let keyMaxInterval = "fragmentMaxInterval"

    private final class State: @unchecked Sendable {
        let lock = NSLock()
        var settings = FragmentSettings()
    }

    private static let state = State()

    /// The tunnel-wide default, used by any server whose link carried no
    /// `fragment=` (or `fm=`).
    public static var settings: FragmentSettings {
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.settings
    }

    /// Publishes a new tunnel-wide value; the next dial uses it.
    public static func set(_ settings: FragmentSettings) {
        state.lock.lock()
        state.settings = settings
        state.lock.unlock()
    }

    /// What applies to one server: its own setting when its link carried one
    /// (a server switched off stays off), the tunnel-wide default otherwise.
    /// Nil when the result is off.
    public static func effective(for configured: FragmentSettings?) -> FragmentSettings? {
        let chosen = configured ?? settings
        return chosen.isEnabled ? chosen : nil
    }
}
