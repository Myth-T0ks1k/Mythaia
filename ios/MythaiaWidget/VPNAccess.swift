import Foundation
import NetworkExtension

/// What the app last said about the connection, in the App Group's
/// defaults (the app writes it on every change; see WidgetBridge there).
enum SharedState {
    static let connectedKey = "widget.connected"
    static let serverKey = "widget.server"

    static var appGroup: String {
        let raw = Bundle.main.object(forInfoDictionaryKey: "MythaiaAppGroup") as? String ?? ""
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.isEmpty || value.hasPrefix("$(") { return "group.com.mythaia.pro" }
        return value
    }

    static func read() -> (connected: Bool, server: String?) {
        guard let defaults = UserDefaults(suiteName: appGroup) else { return (false, nil) }
        return (defaults.bool(forKey: connectedKey), defaults.string(forKey: serverKey))
    }

    static func write(connected: Bool) {
        UserDefaults(suiteName: appGroup)?.set(connected, forKey: connectedKey)
    }
}

enum VPNAccessError: Error, LocalizedError {
    case noConfiguration

    var errorDescription: String? {
        String(localized: "Open Mythaia Pro once to set up the VPN.")
    }
}

/// The app's VPN configuration, started and stopped from the widget. The
/// tunnel starts on the server the app saved last.
enum VPNAccess {
    static func manager() async -> NETunnelProviderManager? {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            return managers.first
        } catch {
            return nil
        }
    }

    /// The live state; nil when the configuration cannot be read from here.
    static func isConnected() async -> Bool? {
        guard let manager = await manager() else { return nil }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    static func setConnected(_ on: Bool) async throws {
        guard let manager = await manager() else { throw VPNAccessError.noConfiguration }
        if on {
            if !manager.isEnabled {
                manager.isEnabled = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }
            try manager.connection.startVPNTunnel()
        } else {
            manager.connection.stopVPNTunnel()
        }
        SharedState.write(connected: on)
    }

    static func toggle() async throws {
        let live = await isConnected()
        let connected = live ?? SharedState.read().connected
        try await setConnected(!connected)
    }
}
