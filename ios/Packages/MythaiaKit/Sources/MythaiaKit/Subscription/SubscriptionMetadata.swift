import Foundation

/**
 * What a panel says about a subscription besides its servers.
 *
 * Every key is read from the response headers first and, failing that, from
 * a `#key: value` line in the body — the two places Happ reads them, so a
 * panel set up for Happ (Remnawave, Marzban, 3x-ui) works here unchanged.
 * Text values may be plain or `base64:`-prefixed; a flag is on for `true` or
 * `1` and off for any other value.
 *
 * | key | effect |
 * |---|---|
 * | `profile-title`, `subscription-userinfo` | name; traffic and expiry |
 * | `announce`, `support-url`, `profile-web-page-url` | the provider's message and links |
 * | `sub-info-text`, `-color`, `-button-text`, `-button-link` | a coloured block with a button |
 * | `sub-expire` (or `notification-subs-expire`), `sub-expire-button-link` | warn three days before expiry |
 * | `profile-update-interval` | background refresh, in hours |
 * | `subscription-auto-update-open-enable` | refresh whenever the app opens |
 * | `subscription-auto-update-enable` | `0` keeps the background refresh away |
 * | `subscription-request-timeout` | seconds to wait for the panel |
 * | `new-url` | the subscription moves there for good |
 * | `new-domain` | the same, keeping the path |
 * | `fallback-url` | fetched when the URL does not answer |
 * | `fronting-target` (or `resolve-address`) | hosts to dial instead of the panel; `off` stops fronting |
 * | `fronting-sni` | the name sent in the TLS handshake |
 * | `host` | with a target, Happ's name for the panel's real host |
 *
 * The keys that send the subscription elsewhere — `new-url`, `new-domain`,
 * `fallback-url` and the fronting ones — count only in a response that came
 * over verified TLS. From a plain-HTTP panel anyone on the path could move
 * the subscription for good.
 */
public enum SubscriptionMetadata {

    private static let offWords: Set<String> = ["off", "none", "disable", "disabled", "0", "false"]
    private static let maxUrl = 2048

    /// The `#key: value` lines of `body`, keys lower-cased; the first of a repeated key wins.
    public static func bodyFields(_ body: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in LinkText.lines(body) {
            guard LinkText.hasPrefix(LinkText.trimStart(line), "#") else { continue }
            guard let match = matchBodyLine(line) else { continue }
            let lower = match.0.lowercased()
            if out[lower] == nil { out[lower] = match.1 }
        }
        return out
    }

    /// Whether `line` is one of the metadata lines `bodyFields` reads.
    public static func isMetadataLine(_ line: String) -> Bool {
        matchBodyLine(line) != nil
    }

    private static func isRegexSpace(_ b: UInt8) -> Bool {
        b == 32 || b == 9 || b == 10 || b == 11 || b == 12 || b == 13
    }

    private static func isLetter(_ b: UInt8) -> Bool {
        (b >= 65 && b <= 90) || (b >= 97 && b <= 122)
    }

    private static func isDigit(_ b: UInt8) -> Bool {
        b >= 48 && b <= 57
    }

    /// `^\s*#\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*?)\s*$`: the key and the value.
    private static func matchBodyLine(_ line: String) -> (String, String)? {
        let bytes = Array(line.utf8)
        var i = 0
        while i < bytes.count && isRegexSpace(bytes[i]) { i += 1 }
        guard i < bytes.count, bytes[i] == UInt8(ascii: "#") else { return nil }
        i += 1
        while i < bytes.count && isRegexSpace(bytes[i]) { i += 1 }
        guard i < bytes.count, isLetter(bytes[i]) else { return nil }
        let keyStart = i
        while i < bytes.count && (isLetter(bytes[i]) || isDigit(bytes[i]) || bytes[i] == UInt8(ascii: "-")) { i += 1 }
        let key = LinkText.string(bytes[keyStart..<i])
        while i < bytes.count && isRegexSpace(bytes[i]) { i += 1 }
        guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else { return nil }
        i += 1
        while i < bytes.count && isRegexSpace(bytes[i]) { i += 1 }
        var end = bytes.count
        while end > i && isRegexSpace(bytes[end - 1]) { end -= 1 }
        return (key, LinkText.string(bytes[i..<end]))
    }

    /// `^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*\.?$`
    static func isHostName(_ text: String) -> Bool {
        var bytes = Array(text.utf8)
        if bytes.last == UInt8(ascii: ".") { bytes.removeLast() }
        if bytes.isEmpty { return false }
        var label: [UInt8] = []
        func labelIsValid(_ l: [UInt8]) -> Bool {
            guard let first = l.first, let last = l.last else { return false }
            let alnum: (UInt8) -> Bool = { isLetter($0) || isDigit($0) }
            return alnum(first) && alnum(last) && l.allSatisfy { alnum($0) || $0 == UInt8(ascii: "-") }
        }
        for b in bytes {
            if b == UInt8(ascii: ".") {
                if !labelIsValid(label) { return false }
                label = []
            } else {
                label.append(b)
            }
        }
        return labelIsValid(label)
    }

    /**
     * The panel's metadata, each key read through `header` and then `body`.
     * `secure` is whether the response arrived over verified TLS.
     */
    public static func read(header: (String) -> String?, body: [String: String], secure: Bool) -> SubscriptionFetcher.PanelInfo {
        func raw(_ name: String) -> String? {
            if let value = header(name) {
                let trimmed = LinkText.trim(value)
                if !trimmed.isEmpty { return trimmed }
            }
            if let value = body[name] {
                let trimmed = LinkText.trim(value)
                if !trimmed.isEmpty { return trimmed }
            }
            return nil
        }
        func text(_ name: String, _ limit: Int) -> String? {
            guard let decoded = decode(raw(name)) else { return nil }
            let trimmed = LinkText.trim(decoded)
            return trimmed.isEmpty ? nil : String(trimmed.prefix(limit))
        }
        func link(_ name: String) -> String? {
            guard let value = raw(name), value.utf16.count <= maxUrl, isLink(value) else { return nil }
            return value
        }
        func flag(_ name: String) -> Bool? {
            guard let value = raw(name)?.lowercased() else { return nil }
            return value == "true" || value == "1"
        }
        func httpsUrl(_ name: String) -> String? {
            guard secure, let value = raw(name), value.utf16.count <= maxUrl, isHttpsUrl(value) else { return nil }
            return value
        }

        let target: String? = secure ? (raw("fronting-target") ?? raw("resolve-address")) : nil
        let frontingOff = target.map { offWords.contains($0.lowercased()) } ?? false
        var targets: [String]? = nil
        if let target = target, !frontingOff {
            var seen = Set<String>()
            var list: [String] = []
            for piece in LinkText.split(target, UInt8(ascii: ",")) {
                let candidate = LinkText.trim(piece)
                if !isHostPort(candidate) || seen.contains(candidate) { continue }
                seen.insert(candidate)
                list.append(candidate)
                if list.count == 16 { break }
            }
            targets = list.isEmpty ? nil : list
        }

        var newDomain: String? = nil
        if secure, let value = raw("new-domain")?.lowercased(), isHostPort(value) { newDomain = value }
        var frontSni: String? = nil
        if secure && !frontingOff, let value = raw("fronting-sni")?.lowercased(), isHostName(value) { frontSni = value }
        var frontHost: String? = nil
        if targets != nil, let value = raw("host")?.lowercased(), isHostPort(value) { frontHost = value }

        var subInfo: Subscription.SubInfo? = nil
        if let infoText = text("sub-info-text", 500) {
            var color = "blue"
            if let value = raw("sub-info-color")?.lowercased(), ["red", "blue", "green"].contains(value) { color = value }
            subInfo = Subscription.SubInfo(
                text: infoText,
                color: color,
                buttonText: text("sub-info-button-text", 40),
                buttonLink: link("sub-info-button-link")
            )
        }

        var updateInterval: Int? = nil
        if let value = raw("profile-update-interval").flatMap({ Int($0) }), value >= 1 && value <= 720 { updateInterval = value }
        var requestTimeout: Int? = nil
        if let value = raw("subscription-request-timeout").flatMap({ Int($0) }), value >= 3 && value <= 60 { requestTimeout = value }

        return SubscriptionFetcher.PanelInfo(
            title: text("profile-title", 100),
            userInfo: raw("subscription-userinfo"),
            announce: text("announce", 1000),
            supportUrl: link("support-url"),
            webPageUrl: link("profile-web-page-url"),
            updateIntervalHours: updateInterval,
            updateOnOpen: flag("subscription-auto-update-open-enable"),
            autoUpdate: flag("subscription-auto-update-enable"),
            requestTimeoutSeconds: requestTimeout,
            newUrl: httpsUrl("new-url"),
            newDomain: newDomain,
            fallbackUrl: httpsUrl("fallback-url"),
            frontTargets: targets,
            frontingOff: frontingOff,
            frontSni: frontSni,
            frontHost: frontHost,
            subInfo: subInfo,
            expireNotice: flag("sub-expire") ?? flag("notification-subs-expire"),
            expireButtonLink: link("sub-expire-button-link")
        )
    }

    /**
     * `current` after a successful fetch: the servers' metadata folded in, and
     * the subscription moved where the panel says it now lives. A key the
     * panel leaves out keeps its old value, except the messages, which a panel
     * that stops sending them has withdrawn.
     */
    public static func applyTo(
        _ current: Subscription,
        result: SubscriptionFetcher.Result,
        now: Int64 = Subscription.currentTimeMillis()
    ) -> Subscription {
        let panel = result.panel

        // new-url may carry fronting of its own, in either link form.
        let newLink = panel.newUrl.flatMap { SubscriptionLink.parse($0) }
        var url = newLink?.url ?? panel.newDomain.flatMap { replaceHost(current.url, $0) } ?? current.url
        let newLinkFronted = newLink?.isFronted == true
        var sni: String? = newLinkFronted ? newLink?.frontSni : current.frontSni
        var targets: [String] = newLinkFronted ? (newLink?.frontTargets ?? []) : current.frontTargets

        if panel.frontingOff {
            sni = nil
            targets = []
        } else if let panelTargets = panel.frontTargets {
            targets = panelTargets
            // Happ's pair: `resolve-address` is dialled and `host` names the
            // panel, so the URL's own host is the front and goes in the SNI.
            if let frontHost = panel.frontHost, let front = hostPort(url),
               hostOnly(frontHost).lowercased() != hostOnly(front).lowercased() {
                if let moved = replaceHost(url, frontHost) {
                    url = moved
                    sni = hostOnly(front)
                }
            }
            if let panelSni = panel.frontSni { sni = panelSni }
        } else if let panelSni = panel.frontSni {
            sni = panelSni
            // An SNI on its own fronts the panel's own address, as in a link.
            if targets.isEmpty, let own = hostPort(url) { targets = [own] }
        }

        var updated = current
        updated.lastUpdate = now
        if !current.isNameCustomized {
            updated.name = result.name ?? newLink?.name ?? current.name
        }
        updated.upload = result.upload ?? current.upload
        updated.download = result.download ?? current.download
        updated.total = result.total ?? current.total
        updated.expire = result.expire ?? current.expire
        updated.announce = panel.announce
        updated.subInfo = panel.subInfo
        updated.supportUrl = panel.supportUrl ?? current.supportUrl
        updated.webPageUrl = panel.webPageUrl ?? current.webPageUrl
        updated.updateIntervalHours = panel.updateIntervalHours ?? current.updateIntervalHours
        updated.updateOnOpen = panel.updateOnOpen ?? current.updateOnOpen
        updated.autoUpdate = panel.autoUpdate ?? current.autoUpdate
        updated.requestTimeoutSeconds = panel.requestTimeoutSeconds ?? current.requestTimeoutSeconds
        updated.expireNotice = panel.expireNotice ?? current.expireNotice
        updated.expireButtonLink = panel.expireButtonLink ?? current.expireButtonLink
        updated.url = url
        let panelFallback = panel.fallbackUrl.flatMap { $0 == url ? nil : $0 }
        let currentFallback = current.fallbackUrl.flatMap { $0 == url ? nil : $0 }
        updated.fallbackUrl = panelFallback ?? currentFallback
        updated.frontSni = sni
        updated.frontTargets = targets
        updated.lastFailure = nil
        updated.lastFailureMessage = nil
        return updated
    }

    /**
     * `url` with its host replaced by `host` (`name` or `name:port`). The
     * path, query and user info stay; so does the port, unless `host` names one.
     */
    public static func replaceHost(_ url: String, _ host: String) -> String? {
        let bytes = Array(url.utf8)
        guard let schemeEnd = LinkText.indexOf(bytes, Array("://".utf8)), schemeEnd > 0, !host.isEmpty else { return nil }
        let rest = Array(bytes[(schemeEnd + 3)...])
        let authorityEnd = rest.firstIndex(where: { $0 == UInt8(ascii: "/") || $0 == UInt8(ascii: "?") || $0 == UInt8(ascii: "#") }) ?? rest.count
        let authority = Array(rest[..<authorityEnd])
        let at = authority.lastIndex(of: UInt8(ascii: "@"))
        let userInfo = at.map { LinkText.string(authority[..<$0]) } ?? ""
        let hostPart = at.map { LinkText.string(authority[($0 + 1)...]) } ?? LinkText.string(authority)
        let oldPort = portOf(hostPart)
        var newAuthority = ""
        if !userInfo.isEmpty { newAuthority += userInfo + "@" }
        newAuthority += host
        if portOf(host) == nil, let port = oldPort { newAuthority += ":" + port }
        return LinkText.string(bytes[..<(schemeEnd + 3)]) + newAuthority + LinkText.string(rest[authorityEnd...])
    }

    /// `host` or `host:port` of `url`, without user info.
    public static func hostPort(_ url: String) -> String? {
        let bytes = Array(url.utf8)
        guard let scheme = LinkText.indexOf(bytes, Array("://".utf8)) else { return nil }
        let rest = bytes[(scheme + 3)...]
        let end = rest.firstIndex(where: { $0 == UInt8(ascii: "/") || $0 == UInt8(ascii: "?") || $0 == UInt8(ascii: "#") }) ?? rest.endIndex
        var authority = Array(rest[rest.startIndex..<end])
        if let at = authority.lastIndex(of: UInt8(ascii: "@")) { authority = Array(authority[(at + 1)...]) }
        return authority.isEmpty ? nil : LinkText.string(authority)
    }

    /// `hostPort` without its port and IPv6 brackets.
    private static func hostOnly(_ hostPort: String) -> String {
        let bytes = Array(hostPort.utf8)
        if bytes.first == UInt8(ascii: "[") {
            let inner = bytes.dropFirst()
            let close = inner.firstIndex(of: UInt8(ascii: "]")) ?? inner.endIndex
            return LinkText.string(inner[inner.startIndex..<close])
        }
        let colon = bytes.firstIndex(of: UInt8(ascii: ":")) ?? bytes.count
        return LinkText.string(bytes[..<colon])
    }

    /// The port of `host:port` or `[v6]:port`; nil when there is none.
    private static func portOf(_ hostPort: String) -> String? {
        let bytes = Array(hostPort.utf8)
        var afterHost: [UInt8]
        if bytes.first == UInt8(ascii: "[") {
            if let close = bytes.firstIndex(of: UInt8(ascii: "]")) {
                afterHost = Array(bytes[(close + 1)...])
            } else {
                afterHost = []
            }
        } else {
            afterHost = bytes
        }
        let colons = afterHost.filter { $0 == UInt8(ascii: ":") }.count
        if afterHost.first != UInt8(ascii: ":") && colons != 1 { return nil }
        guard let last = afterHost.lastIndex(of: UInt8(ascii: ":")) else { return nil }
        let port = afterHost[(last + 1)...]
        guard !port.isEmpty, port.allSatisfy({ isDigit($0) }) else { return nil }
        return LinkText.string(port)
    }

    private static func isHostPort(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        if bytes.isEmpty || value.utf16.count > 255 { return false }
        if bytes.first == UInt8(ascii: "[") {
            guard let close = bytes.firstIndex(of: UInt8(ascii: "]")) else { return false }
            let v6 = bytes[1..<close]
            let rest = bytes[(close + 1)...]
            let v6Ok = !v6.isEmpty && v6.allSatisfy { isLetter($0) || isDigit($0) || $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: ".") }
            if !v6Ok { return false }
            if rest.isEmpty { return true }
            guard rest.first == UInt8(ascii: ":") else { return false }
            return validPort(LinkText.string(rest.dropFirst()))
        }
        let colon = bytes.firstIndex(of: UInt8(ascii: ":"))
        let host = LinkText.string(bytes[..<(colon ?? bytes.count)])
        let port = colon.map { LinkText.string(bytes[($0 + 1)...]) } ?? ""
        return isHostName(host) && (port.isEmpty || validPort(port))
    }

    private static func validPort(_ text: String) -> Bool {
        guard let port = Int(text) else { return false }
        return port >= 1 && port <= 65535
    }

    /// Plain text, or the UTF-8 behind a `base64:` prefix; nil for a blank result.
    public static func decode(_ value: String?) -> String? {
        guard let value = value else { return nil }
        let decoded: String?
        if LinkText.hasPrefix(value, "base64:") {
            decoded = LinkText.decodeBase64Lenient(LinkText.removePrefix(value, "base64:"), urlSafe: false).map { LinkText.utf8($0) }
        } else {
            decoded = value
        }
        guard let text = decoded, !LinkText.isBlank(text) else { return nil }
        return text
    }

    private static func isLink(_ value: String) -> Bool {
        LinkText.hasPrefix(value, "https://") || LinkText.hasPrefix(value, "http://") || LinkText.hasPrefix(value, "tg://")
    }

    private static func isHttpsUrl(_ value: String) -> Bool {
        guard LinkText.hasPrefix(value, "https://", ignoreCase: true), let authority = hostPort(value) else { return false }
        return isHostPort(authority)
    }
}
