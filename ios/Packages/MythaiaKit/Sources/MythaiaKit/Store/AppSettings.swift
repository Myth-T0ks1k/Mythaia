import Foundation

/// The settings the tunnel needs as well as the app. Every field decodes to
/// its default when it is missing or holds a value this build does not know,
/// so a settings file written by an older or newer build still loads.
public struct AppSettings: Codable, Hashable {
    /// Rule (the default) applies the country bypass and the routing rules;
    /// global sends everything through the server.
    public var routingMode: RoutingMode
    /// The country whose addresses go direct in rule mode, e.g. "TM"; nil
    /// for none.
    public var bypassCountryCode: String?
    public var themeMode: ThemeMode
    /// The local proxy's port; 0 lets the system pick a free one.
    public var localProxyPort: UInt16
    /// Between Auto's rounds while connected.
    public var autoRecheckMinutes: Int
    /// What the server list's ping button measures.
    public var latencyKind: LatencyKind
    /// This install's identifier, sent as `x-hwid` to the panels that ask
    /// for one. Generated once and kept.
    public var hwid: String
    /// Every app's traffic through the packet tunnel (the default), or only
    /// what honours the system proxy settings.
    public var tunnelMode: TunnelMode

    public static let defaultAutoRecheckMinutes = 10

    public init(
        routingMode: RoutingMode = .rule,
        bypassCountryCode: String? = nil,
        themeMode: ThemeMode = .system,
        localProxyPort: UInt16 = 0,
        autoRecheckMinutes: Int = AppSettings.defaultAutoRecheckMinutes,
        latencyKind: LatencyKind = .handshake,
        hwid: String = AppSettings.newHardwareId(),
        tunnelMode: TunnelMode = .tun
    ) {
        self.routingMode = routingMode
        self.bypassCountryCode = bypassCountryCode
        self.themeMode = themeMode
        self.localProxyPort = localProxyPort
        self.autoRecheckMinutes = autoRecheckMinutes
        self.latencyKind = latencyKind
        self.hwid = hwid
        self.tunnelMode = tunnelMode
    }

    /// A fresh identifier in the form the panels expect: a lowercase UUID.
    public static func newHardwareId() -> String {
        UUID().uuidString.lowercased()
    }

    /// The bypass country as the rules database keys it, or nil when none
    /// is set.
    public var normalizedBypassCountryCode: String? {
        guard let code = bypassCountryCode?.trimmingCharacters(in: .whitespacesAndNewlines),
              !code.isEmpty else { return nil }
        return code.uppercased()
    }

    enum CodingKeys: String, CodingKey {
        case routingMode
        case bypassCountryCode
        case themeMode
        case localProxyPort
        case autoRecheckMinutes
        case latencyKind
        case hwid
        case tunnelMode
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = AppSettings(hwid: "")
        // `try?` around each field: an unknown enum value or a wrong type in
        // one field costs that field, not the whole file.
        routingMode = (try? container.decodeIfPresent(RoutingMode.self, forKey: .routingMode)) ?? defaults.routingMode
        let code = (try? container.decodeIfPresent(String.self, forKey: .bypassCountryCode)) ?? nil
        // An empty string also means no country.
        if let code, !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            bypassCountryCode = code
        } else {
            bypassCountryCode = nil
        }
        themeMode = (try? container.decodeIfPresent(ThemeMode.self, forKey: .themeMode)) ?? defaults.themeMode
        localProxyPort = (try? container.decodeIfPresent(UInt16.self, forKey: .localProxyPort)) ?? defaults.localProxyPort
        let minutes = (try? container.decodeIfPresent(Int.self, forKey: .autoRecheckMinutes)) ?? nil
        if let minutes, minutes > 0 {
            autoRecheckMinutes = minutes
        } else {
            autoRecheckMinutes = defaults.autoRecheckMinutes
        }
        latencyKind = (try? container.decodeIfPresent(LatencyKind.self, forKey: .latencyKind)) ?? defaults.latencyKind
        let storedId = (try? container.decodeIfPresent(String.self, forKey: .hwid)) ?? nil
        if let storedId, !storedId.isEmpty {
            hwid = storedId
        } else {
            hwid = AppSettings.newHardwareId()
        }
        tunnelMode = (try? container.decodeIfPresent(TunnelMode.self, forKey: .tunnelMode)) ?? defaults.tunnelMode
    }
}

/// How the packet tunnel steers traffic.
public enum TunnelMode: String, Codable, CaseIterable {
    /// The interface takes the default routes and a userspace TCP/IP stack
    /// carries every connection, as Android's VPN does: Telegram and other
    /// apps with their own networking go through too.
    case tun
    /// No routes: the system proxy settings point at a local proxy, so only
    /// apps that honour them (Safari, most URLSession traffic) go through.
    case proxy
}

/// Which server the app has chosen, per group. A group with no pin is on
/// Auto, and `autoChoices` remembers what Auto picked there last, so the
/// home screen can show it before the next round.
public struct SelectionState: Codable, Hashable {
    public static let defaultGroupId = "default"

    /// "default" for the servers added by hand, or a subscription's UUID
    /// string.
    public var activeGroupId: String
    /// Group id to the pinned server; no entry means Auto.
    public var groupPins: [String: UUID]
    /// Group id to the server Auto chose last.
    public var autoChoices: [String: UUID]
    /// A chain selected instead of a single server; Auto is off while set.
    public var selectedChainId: UUID?

    public init(
        activeGroupId: String = SelectionState.defaultGroupId,
        groupPins: [String: UUID] = [:],
        autoChoices: [String: UUID] = [:],
        selectedChainId: UUID? = nil
    ) {
        self.activeGroupId = activeGroupId
        self.groupPins = groupPins
        self.autoChoices = autoChoices
        self.selectedChainId = selectedChainId
    }

    /// Whether Auto picks the server in `groupId`.
    public func isAuto(_ groupId: String) -> Bool {
        selectedChainId == nil && groupPins[groupId] == nil
    }

    enum CodingKeys: String, CodingKey {
        case activeGroupId
        case groupPins
        case autoChoices
        case selectedChainId
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let group = (try? container.decodeIfPresent(String.self, forKey: .activeGroupId)) ?? nil
        if let group, !group.isEmpty {
            activeGroupId = group
        } else {
            activeGroupId = SelectionState.defaultGroupId
        }
        groupPins = (try? container.decodeIfPresent([String: UUID].self, forKey: .groupPins)) ?? [:]
        autoChoices = (try? container.decodeIfPresent([String: UUID].self, forKey: .autoChoices)) ?? [:]
        selectedChainId = (try? container.decodeIfPresent(UUID.self, forKey: .selectedChainId)) ?? nil
    }
}

/// Everything the tunnel needs to come up without asking the app: written
/// by the app before it starts the tunnel, and read again by an on-demand
/// start that has no app behind it.
public struct TunnelStartOptions: Codable {
    /// The server to dial; a selected chain is already resolved into
    /// `configuration.chain`.
    public var configuration: ProxyConfiguration
    public var settings: AppSettings
    /// The active group, for Auto inside the tunnel; empty when a server is
    /// pinned or a chain is selected.
    public var groupConfigurations: [ProxyConfiguration]

    /// The key under which `startOptions()` puts the encoded options.
    public static let startOptionsKey = "mythaiaTunnelStart"

    public init(
        configuration: ProxyConfiguration,
        settings: AppSettings,
        groupConfigurations: [ProxyConfiguration] = []
    ) {
        self.configuration = configuration
        self.settings = settings
        self.groupConfigurations = groupConfigurations
    }

    enum CodingKeys: String, CodingKey {
        case configuration
        case settings
        case groupConfigurations
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        configuration = try container.decode(ProxyConfiguration.self, forKey: .configuration)
        settings = (try? container.decodeIfPresent(AppSettings.self, forKey: .settings)) ?? AppSettings()
        groupConfigurations = (try? container.decodeIfPresent([ProxyConfiguration].self, forKey: .groupConfigurations)) ?? []
    }

    /// The options as the dictionary `NETunnelProviderSession.startTunnel`
    /// takes. A big Auto group makes this large; the copy in the store is
    /// what the tunnel falls back to, so callers may pass a copy with the
    /// group left empty.
    public func startOptions() throws -> [String: NSObject] {
        let data = try JSONEncoder().encode(self)
        return [TunnelStartOptions.startOptionsKey: data as NSData]
    }

    /// Reads options passed by `startOptions()`; nil when there are none
    /// (an on-demand or system start) or they do not decode.
    public init?(startOptions: [String: NSObject]?) {
        guard let object = startOptions?[TunnelStartOptions.startOptionsKey] else { return nil }
        let data: Data
        if let bytes = object as? NSData {
            data = bytes as Data
        } else if let text = object as? NSString {
            data = Data((text as String).utf8)
        } else {
            return nil
        }
        guard let decoded = try? JSONDecoder().decode(TunnelStartOptions.self, from: data) else { return nil }
        self = decoded
    }
}
