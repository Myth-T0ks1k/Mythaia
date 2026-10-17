import Foundation

/// How the tunnel routes: by rules, or everything through the server.
public enum RoutingMode: String, Codable, CaseIterable {
    /// The country bypass and the routing rules decide; the rest goes
    /// through the server.
    case rule
    /// Everything goes through the server, the home country included. Only
    /// the private ranges stay off it, since a proxy cannot reach them.
    case global
}

/// Where one connection goes.
public enum RouteTarget: String, Codable, CaseIterable {
    case proxy
    case direct
    case block
}

/// One user routing rule: a match and what to do with it.
public struct RouteRule: Codable, Hashable {
    public var type: DomainRuleType
    public var value: String
    public var action: RouteTarget

    public init(type: DomainRuleType, value: String, action: RouteTarget) {
        self.type = type
        self.value = value
        self.action = action
    }
}

/// Decides where one connection goes. Rule mode sends everything through the
/// proxy except what a rule, the private ranges or the country bypass send
/// direct; global mode sends everything through the proxy, the home country
/// included, and keeps only the private ranges off it, since those are
/// addresses a proxy cannot reach at all.
///
/// Immutable once built: a settings change builds a new router, and the
/// local proxy swaps it in for new connections.
public final class Router: @unchecked Sendable {
    public let mode: RoutingMode

    private struct SuffixRule {
        let suffix: String
        let action: RouteTarget
    }

    private struct KeywordRule {
        let keyword: String
        let action: RouteTarget
    }

    private struct NetworkRule {
        let network: IPNetwork
        let action: RouteTarget
    }

    private let suffixRules: [SuffixRule]
    private let keywordRules: [KeywordRule]
    private let networkRules: [NetworkRule]

    private let bypassSuffixes: Set<String>
    private let bypassKeywords: [String]
    private let bypassIPv4: IPv4RangeSet
    private let bypassIPv6: [IPNetwork]

    /// - Parameters:
    ///   - bypassRules: the country bypass (database rules and
    ///     `CountryBypassExtras`), all sent direct. Ignored in global mode.
    ///   - rules: user rules, first match wins. Ignored in global mode.
    ///
    /// `geoip` rules are skipped: there is no GeoIP database on this
    /// platform, and the country lists carry the networks themselves.
    public init(mode: RoutingMode, bypassRules: [DomainRule] = [], rules: [RouteRule] = []) {
        self.mode = mode
        let bypass: [DomainRule] = mode == .rule ? bypassRules : []

        var suffixes = Set<String>()
        var keywords: [String] = []
        var v4Networks: [IPNetwork] = []
        var v6Networks: [IPNetwork] = []
        for rule in bypass {
            switch rule.type {
            case .domainSuffix:
                let suffix = Router.normalizedSuffix(rule.value)
                if !suffix.isEmpty { suffixes.insert(suffix) }
            case .domainKeyword:
                let keyword = rule.value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if !keyword.isEmpty { keywords.append(keyword) }
            case .ipCidr, .ipCidr6:
                if let network = IPNetwork.parse(rule.value) {
                    if network.bytes.count == 4 {
                        v4Networks.append(network)
                    } else {
                        v6Networks.append(network)
                    }
                }
            default:
                continue
            }
        }
        bypassSuffixes = suffixes
        bypassKeywords = keywords
        bypassIPv4 = IPv4RangeSet(v4Networks)
        bypassIPv6 = v6Networks

        var userSuffixes: [SuffixRule] = []
        var userKeywords: [KeywordRule] = []
        var userNetworks: [NetworkRule] = []
        if mode == .rule {
            for rule in rules {
                switch rule.type {
                case .domainSuffix:
                    let suffix = Router.normalizedSuffix(rule.value)
                    if !suffix.isEmpty { userSuffixes.append(SuffixRule(suffix: suffix, action: rule.action)) }
                case .domainKeyword:
                    let keyword = rule.value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    if !keyword.isEmpty { userKeywords.append(KeywordRule(keyword: keyword, action: rule.action)) }
                case .ipCidr, .ipCidr6:
                    if let network = IPNetwork.parse(rule.value) {
                        userNetworks.append(NetworkRule(network: network, action: rule.action))
                    }
                default:
                    continue
                }
            }
        }
        suffixRules = userSuffixes
        keywordRules = userKeywords
        networkRules = userNetworks
    }

    /// The router for `settings`: in rule mode with a bypass country, that
    /// country's rules from the database plus `CountryBypassExtras`.
    public convenience init(settings: AppSettings, database: RulesDatabase?, rules: [RouteRule] = []) {
        var bypass: [DomainRule] = []
        if settings.routingMode == .rule, let code = settings.normalizedBypassCountryCode {
            if let database {
                bypass = database.countryBypassRules(code)
            } else {
                bypass = CountryBypassExtras.rulesFor(code)
            }
        }
        self.init(mode: settings.routingMode, bypassRules: bypass, rules: rules)
    }

    /// How many country-bypass entries are loaded, for the log.
    public var bypassEntryCount: Int {
        bypassSuffixes.count + bypassKeywords.count + bypassIPv4.count + bypassIPv6.count
    }

    /// `host` is a domain name or an IP literal, as the client gave it.
    public func decide(_ host: String) -> RouteTarget {
        let name = Router.normalizedHost(host)
        if name.isEmpty { return .block }
        if let address = RouterAddress.parse(name) {
            return decideAddress(RouterAddress.unmapped(address))
        }
        return decideDomain(name)
    }

    private func decideDomain(_ domain: String) -> RouteTarget {
        if Router.isLocalName(domain) { return .direct }
        if !bypassSuffixes.isEmpty && Router.matchesSuffix(domain, in: bypassSuffixes) { return .direct }
        for keyword in bypassKeywords where domain.contains(keyword) {
            return .direct
        }
        if mode == .rule {
            for rule in suffixRules where domain == rule.suffix || domain.hasSuffix("." + rule.suffix) {
                return rule.action
            }
            for rule in keywordRules where domain.contains(rule.keyword) {
                return rule.action
            }
        }
        return .proxy
    }

    private func decideAddress(_ address: [UInt8]) -> RouteTarget {
        if RouterAddress.isPrivate(address) { return .direct }
        if address.count == 4 {
            if !bypassIPv4.isEmpty, let value = RouterAddress.ipv4Value(address), bypassIPv4.contains(value) {
                return .direct
            }
        } else {
            for network in bypassIPv6 where network.contains(address) {
                return .direct
            }
        }
        if mode == .rule {
            for rule in networkRules where rule.network.contains(address) {
                return rule.action
            }
        }
        return .proxy
    }

    /// Lowercased, without surrounding space, brackets or trailing dots.
    static func normalizedHost(_ host: String) -> String {
        var text = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if text.hasPrefix("[") && text.hasSuffix("]") && text.count >= 2 {
            text = String(text.dropFirst().dropLast())
        }
        while text.hasSuffix(".") {
            text.removeLast()
        }
        return text
    }

    /// Names that never leave the local network.
    static func isLocalName(_ domain: String) -> Bool {
        if domain == "localhost" || domain.hasSuffix(".localhost") { return true }
        if domain.hasSuffix(".local") || domain.hasSuffix(".lan") { return true }
        return domain.hasSuffix(".home.arpa")
    }

    /// Whether `domain` is one of `suffixes` or under one, label-aligned:
    /// "shop.example.tm" matches "tm" and "example.tm", "notatm" matches
    /// neither.
    static func matchesSuffix(_ domain: String, in suffixes: Set<String>) -> Bool {
        var candidate = Substring(domain)
        while true {
            if suffixes.contains(String(candidate)) { return true }
            guard let dot = candidate.firstIndex(of: ".") else { return false }
            candidate = candidate[candidate.index(after: dot)...]
        }
    }

    private static func normalizedSuffix(_ value: String) -> String {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while text.hasPrefix(".") {
            text.removeFirst()
        }
        while text.hasSuffix(".") {
            text.removeLast()
        }
        return text
    }
}
