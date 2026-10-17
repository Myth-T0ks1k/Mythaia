import Foundation
import MythaiaKit

/// The model edits the screens make, and the link parsing and export they
/// call, kept in one place so a change in MythaiaKit is fixed here.
enum CoreBridge {

    // MARK: Links

    /// Whether `text` is a whole document (Xray or sing-box JSON, Clash
    /// YAML, a WireGuard config) rather than links.
    static func looksLikeDocument(_ text: String) -> Bool {
        XrayJsonImporter.looksLikeJson(text) || SingBoxJsonImporter.looksLikeSingBox(text) ||
            ProxyConfiguration.looksLikeWireGuardConfig(text) || text.contains("proxies:")
    }

    /// Every server in pasted text: share links (in a message, a list or
    /// another client's import link), Xray or sing-box JSON, Clash YAML, or a
    /// WireGuard config. Links that do not parse are skipped.
    static func parseServers(_ text: String) -> [ProxyConfiguration] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return [] }
        if SingBoxJsonImporter.looksLikeSingBox(trimmed), let list = try? SingBoxJsonImporter.parse(trimmed), !list.isEmpty {
            return list
        }
        if XrayJsonImporter.looksLikeJson(trimmed) {
            return (try? XrayJsonImporter.parse(trimmed)) ?? []
        }
        if ProxyConfiguration.looksLikeWireGuardConfig(trimmed) {
            if let config = try? ProxyConfiguration.fromWireGuardConfig(trimmed) { return [config] }
            return []
        }
        if trimmed.contains("proxies:"), let result = try? ClashProxyParser.parse(trimmed) {
            return result.configurations
        }
        var out: [ProxyConfiguration] = []
        for link in LinkExtractor.extract(trimmed) where !LinkHelpers.isHttp(link) {
            if let config = try? ProxyConfiguration.fromUrl(link) {
                out.append(config)
            }
        }
        return out
    }

    /// The share link for one server.
    static func shareLink(_ configuration: ProxyConfiguration) -> String? {
        let link = configuration.toUrl()
        return link.isEmpty ? nil : link
    }

    // MARK: Servers

    /// The server with a new identity in the store.
    static func withIdentity(_ configuration: ProxyConfiguration, id: UUID, subscriptionId: UUID?) -> ProxyConfiguration {
        var copy = configuration
        copy.id = id
        copy.subscriptionId = subscriptionId
        return copy
    }

    /// A chain resolved into one configuration: the exit server, named after
    /// the chain, with the hops before it.
    static func chained(exit: ProxyConfiguration, name: String, hops: [ProxyConfiguration]) -> ProxyConfiguration {
        var copy = exit
        copy.name = name
        copy.chain = hops
        return copy
    }

    /// WireGuard carries packets, not streams: Auto and chains leave it out.
    static func isLayer3(_ configuration: ProxyConfiguration) -> Bool {
        configuration.outboundProtocol.isLayer3
    }

    /// The transport worth showing on a row (only VLESS and VMess use one).
    static func transportTag(_ configuration: ProxyConfiguration) -> String? {
        switch configuration.outboundProtocol {
        case .vless, .vmess:
            return configuration.transport == "tcp" ? nil : configuration.transport.uppercased()
        default:
            return nil
        }
    }

    static func securityTag(_ configuration: ProxyConfiguration) -> String? {
        let security = configuration.security.uppercased()
        return security == "NONE" || security.isEmpty ? nil : security
    }

    static func usesVision(_ configuration: ProxyConfiguration) -> Bool {
        configuration.flow?.lowercased().contains("vision") ?? false
    }

    static func skipsCertificateCheck(_ configuration: ProxyConfiguration) -> Bool {
        configuration.skipsCertificateCheck
    }

    /// What identifies a server across a subscription refresh, independent of
    /// its name; mirrors the Kotlin `SubscriptionUpdater.endpointKey`.
    static func endpointKey(_ configuration: ProxyConfiguration) -> String {
        let usesUuid: Bool
        switch configuration.outboundProtocol {
        case .vless, .vmess, .tuic: usesUuid = true
        default: usesUuid = false
        }
        return [
            configuration.outboundProtocol.rawValue,
            configuration.serverAddress.lowercased(),
            String(configuration.serverPort),
            usesUuid ? configuration.uuid.uuidString.lowercased() : "",
            configuration.password ?? "",
            configuration.ssPassword ?? "",
            configuration.trojanPassword ?? "",
            configuration.socks5Username ?? "",
            configuration.naiveUsername ?? "",
        ].joined(separator: "|")
    }

    /// Two servers with the same key reach the same place the same way.
    static func duplicateKey(_ configuration: ProxyConfiguration) -> String {
        [
            endpointKey(configuration),
            configuration.transport,
            configuration.security,
            configuration.flow ?? "",
        ].joined(separator: "|")
    }

    // MARK: Subscriptions

    static func newSubscription(name: String, url: String, frontSni: String?, frontTargets: [String],
                                nameCustomized: Bool) -> Subscription {
        Subscription(name: name, url: url, isNameCustomized: nameCustomized,
                     frontSni: frontSni, frontTargets: frontTargets)
    }

    /// The user's edits from the settings screen.
    static func applying(_ draft: SubscriptionDraft, to subscription: Subscription) -> Subscription {
        var copy = subscription
        let name = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !name.isEmpty && name != subscription.name {
            copy.name = name
            copy.isNameCustomized = true
        }
        let url = draft.url.trimmingCharacters(in: .whitespacesAndNewlines)
        if !url.isEmpty { copy.url = url }
        copy.autoUpdate = draft.autoUpdate
        copy.updateOnOpen = draft.updateOnOpen
        copy.updateIntervalHours = draft.updateIntervalHours
        let sni = draft.frontSni.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.frontSni = sni.isEmpty ? nil : sni
        copy.frontTargets = LinkHelpers.splitTargets(draft.frontTargets)
        return copy
    }

    /// A refresh that failed, kept with the subscription so the app can say
    /// so the next time it opens.
    static func markingFailure(_ subscription: Subscription, message: String) -> Subscription {
        var copy = subscription
        copy.lastFailure = nowMillis()
        copy.lastFailureMessage = String(message.prefix(300))
        return copy
    }

    /// The fetched record (the panel's metadata applied) folded onto the
    /// stored one, so a rename made during the fetch survives.
    static func merging(fetched: Subscription, into current: Subscription) -> Subscription {
        var copy = fetched
        copy.id = current.id
        if current.isNameCustomized {
            copy.name = current.name
            copy.isNameCustomized = true
        }
        copy.collapsed = current.collapsed
        copy.lastUpdate = nowMillis()
        return copy
    }

    static func isNameCustomized(_ subscription: Subscription) -> Bool {
        subscription.isNameCustomized
    }

    /// The `sub-expire` warning: whether the panel asked for one, and where
    /// its Renew button leads.
    static func expiryNoticeRequested(_ subscription: Subscription) -> Bool {
        subscription.expireNotice
    }

    static func expireButtonLink(_ subscription: Subscription) -> String? {
        subscription.expireButtonLink
    }

    /// The provider's coloured block (`sub-info-*`), if it sent one.
    static func providerInfo(_ subscription: Subscription) -> ProviderInfo? {
        guard let info = subscription.subInfo else { return nil }
        return ProviderInfo(text: info.text, color: info.color, buttonText: info.buttonText, buttonLink: info.buttonLink)
    }

    // MARK: Tunnel

    static func tunnelStartOptions(configuration: ProxyConfiguration, settings: AppSettings,
                                   groupConfigurations: [ProxyConfiguration]) -> TunnelStartOptions {
        TunnelStartOptions(configuration: configuration, settings: settings, groupConfigurations: groupConfigurations)
    }

    static func nowMillis() -> Int64 {
        Subscription.currentTimeMillis()
    }
}

/// The provider's coloured notice, independent of how MythaiaKit names it.
struct ProviderInfo: Hashable {
    var text: String
    /// "red", "blue" or "green".
    var color: String
    var buttonText: String?
    var buttonLink: String?
}

/// What the subscription settings screen edits.
struct SubscriptionDraft {
    var name: String
    var url: String
    var autoUpdate: Bool
    var updateOnOpen: Bool
    var updateIntervalHours: Int?
    var frontSni: String
    var frontTargets: String

    init(_ subscription: Subscription) {
        name = subscription.name
        url = subscription.url
        autoUpdate = subscription.autoUpdate
        updateOnOpen = subscription.updateOnOpen
        updateIntervalHours = subscription.updateIntervalHours
        frontSni = subscription.frontSni ?? ""
        frontTargets = subscription.frontTargets.joined(separator: "\n")
    }
}
