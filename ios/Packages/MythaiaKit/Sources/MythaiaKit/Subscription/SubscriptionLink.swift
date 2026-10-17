import Foundation

/**
 * A subscription link that carries its own domain fronting, so a panel whose
 * domain is blocked is added in one step: paste or open the link and the
 * download already goes through the front, with nothing to fill in by hand.
 *
 * Two forms, read wherever a subscription is added:
 *
 * - the panel's URL with the settings in its fragment, which is never sent
 *   to the panel:
 *   `https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org`
 * - a link that opens the app, the panel's URL percent-encoded:
 *   `mythaia://import?url=https%3A%2F%2Fpanel.example.com%2Fsub%2FTOKEN&front=104.16.1.1&sni=www.example.org`
 *
 * `front` lists the hosts actually dialled (a host or IP, optionally `:port`;
 * comma-separated or repeated), `sni` the name sent in the TLS handshake
 * (`front-sni` is read too), `name` an optional name for the group. With
 * `sni` and no `front`, the panel's own host is dialled with that SNI.
 *
 * Happ's form is read too, where the URL names the front rather than the
 * panel: `https://cdn-front.example/sub/TOKEN#Name?resolve-address=104.16.1.1&host=panel.example.com`
 * dials `resolve-address` (the front's own address when absent), sends the
 * URL's host as the SNI and asks for `host`.
 */
public struct SubscriptionLink: Hashable {
    public var url: String
    public var frontSni: String?
    public var frontTargets: [String]
    public var name: String?

    public init(url: String, frontSni: String? = nil, frontTargets: [String] = [], name: String? = nil) {
        self.url = url
        self.frontSni = frontSni
        self.frontTargets = frontTargets
        self.name = name
    }

    /// Whether the download goes through a front rather than straight to `url`.
    public var isFronted: Bool { !frontTargets.isEmpty }

    /// The panel URL with the fronting in its fragment; `url` itself when there is none.
    public func toFragmentLink() -> String {
        let params = settingParams()
        return params.isEmpty ? url : url + "#" + params.joined(separator: "&")
    }

    /// A `mythaia://import` link that adds this subscription, fronting included, when opened.
    public func toAppLink() -> String {
        let parts = ["url=" + SubscriptionLink.encode(url, keep: "")] + settingParams()
        return SubscriptionLink.appPrefix + parts.joined(separator: "&")
    }

    private func settingParams() -> [String] {
        var out: [String] = []
        if !frontTargets.isEmpty {
            out.append("front=" + frontTargets.map { SubscriptionLink.encode($0) }.joined(separator: ","))
        }
        if let sni = frontSni { out.append("sni=" + SubscriptionLink.encode(sni)) }
        if let name = name { out.append("name=" + SubscriptionLink.encode(name)) }
        return out
    }

    private static let appPrefix = "mythaia://import?"
    private static let sniKeys: Set<String> = ["sni", "front-sni", "frontsni", "front_sni"]
    private static let frontKeys: Set<String> = ["front", "resolve-address"]
    private static let ownKeys: Set<String> = sniKeys.union(frontKeys).union(["name", "host"])

    private typealias Param = (key: String, value: String)

    /// Whether `link` is an http(s) URL or app import link that asks for fronting.
    public static func isFrontedLink(_ link: String) -> Bool {
        parse(link)?.isFronted == true
    }

    /**
     * Reads `link` in either form. Nil when it is neither an http(s) URL
     * nor a `mythaia://import` link; an http(s) URL whose fragment holds
     * none of the keys above comes back exactly as given.
     */
    public static func parse(_ link: String) -> SubscriptionLink? {
        let s = LinkText.trim(link)
        if LinkText.hasPrefix(s, appPrefix, ignoreCase: true) {
            return parseAppLink(LinkText.string(s.utf8.dropFirst(appPrefix.utf8.count)))
        }
        if !isHttp(s) { return nil }
        let bytes = Array(s.utf8)
        guard let hash = bytes.firstIndex(of: UInt8(ascii: "#")) else { return SubscriptionLink(url: s) }
        let params = fragmentParams(LinkText.string(bytes[(hash + 1)...]))
        // A name alone is read too: an import link with a name and no
        // fronting used to leave "#name=…" on the stored URL.
        if !params.contains(where: { ownKeys.contains($0.key) }) { return SubscriptionLink(url: s) }
        return fromParams(LinkText.string(bytes[..<hash]), params)
    }

    private static func parseAppLink(_ rest: String) -> SubscriptionLink? {
        let bytes = Array(rest.utf8)
        let hash = bytes.firstIndex(of: UInt8(ascii: "#"))
        let query = LinkText.string(hash.map { bytes[..<$0] } ?? bytes[...])
        let fragment = hash.map { LinkText.string(bytes[($0 + 1)...]) } ?? ""
        let parts = LinkText.split(query, UInt8(ascii: "&")).filter { !$0.isEmpty }
        guard let urlIndex = parts.firstIndex(where: { LinkText.hasPrefix($0, "url=", ignoreCase: true) }) else { return nil }
        var url = LinkText.trim(percentDecode(LinkText.string(parts[urlIndex].utf8.dropFirst(4))))
        if !isHttp(url) { return nil }

        // Our own links encode the URL. One written by hand may not, and the
        // panel's own query (…/sub?token=1&lang=ru) then lands beside ours:
        // whatever after `url=` is not ours goes back onto the URL.
        var own: [Param] = []
        for (i, part) in parts.enumerated() where i != urlIndex {
            let key = percentDecode(before(part, "=")).lowercased()
            if ownKeys.contains(key) {
                own.append((key: key, value: percentDecode(after(part, "=", missing: ""))))
            } else if i > urlIndex {
                url += (url.utf8.contains(UInt8(ascii: "?")) ? "&" : "?") + part
            }
        }
        // `#name` as Hiddify writes it, or settings put in the fragment.
        if !fragment.isEmpty {
            if fragment.utf8.contains(UInt8(ascii: "=")) {
                own.append(contentsOf: fragmentParams(fragment))
            } else {
                own.append((key: "name", value: percentDecode(fragment)))
            }
        }
        // A hand-written link may also carry the fragment form inside the URL.
        guard let inner = parse(url) else { return nil }
        let outer = fromParams(inner.url, own)
        return SubscriptionLink(
            url: inner.url,
            frontSni: outer.frontSni ?? inner.frontSni,
            frontTargets: outer.frontTargets.isEmpty ? inner.frontTargets : outer.frontTargets,
            name: outer.name ?? inner.name
        )
    }

    private static func fromParams(_ url: String, _ params: [Param]) -> SubscriptionLink {
        var panelUrl = url
        var sni = params.last(where: { sniKeys.contains($0.key) && !LinkText.isBlank($0.value) }).map { LinkText.trim($0.value) }
        var targets: [String] = []
        var seen = Set<String>()
        for param in params where frontKeys.contains(param.key) {
            for piece in LinkText.split(param.value, UInt8(ascii: ",")) {
                let target = LinkText.trim(piece)
                if target.isEmpty || seen.contains(target) { continue }
                seen.insert(target)
                targets.append(target)
            }
        }
        // Happ's `host`: the URL names the front, `host` the panel.
        let host = params.last(where: { $0.key == "host" && !LinkText.isBlank($0.value) }).map { LinkText.trim($0.value) }
        let front = hostAndPort(url)
        if let host = host, let front = front, !sameHost(host, front) {
            if let moved = SubscriptionMetadata.replaceHost(url, host) {
                panelUrl = moved
                if sni == nil { sni = hostOnly(front) }
                if targets.isEmpty { targets = [front] }
            }
        }
        // An SNI on its own fronts the panel's own address: the name in the
        // handshake is what a filter reads, wherever the packets go.
        if targets.isEmpty && sni != nil {
            if let own = hostAndPort(panelUrl) { targets = [own] }
        }
        let name = params.last(where: { $0.key == "name" && !LinkText.isBlank($0.value) }).map { LinkText.trim($0.value) }
        return SubscriptionLink(url: panelUrl, frontSni: sni, frontTargets: targets, name: name)
    }

    /**
     * A fragment's settings: `key=value&…`, or Happ's `Name?key=value&…`,
     * whose part before the `?` names the group.
     */
    private static func fragmentParams(_ fragment: String) -> [Param] {
        let bytes = Array(fragment.utf8)
        guard let q = bytes.firstIndex(of: UInt8(ascii: "?")), !bytes[..<q].contains(UInt8(ascii: "=")) else {
            return parseParams(fragment)
        }
        let name = LinkText.trim(percentDecode(LinkText.string(bytes[..<q])))
        let params = parseParams(LinkText.string(bytes[(q + 1)...]))
        if name.isEmpty || params.contains(where: { $0.key == "name" }) { return params }
        return params + [(key: "name", value: name)]
    }

    private static func before(_ s: String, _ delimiter: Character) -> String {
        guard let index = s.firstIndex(of: delimiter) else { return s }
        return String(s[..<index])
    }

    private static func after(_ s: String, _ delimiter: Character, missing: String) -> String {
        guard let index = s.firstIndex(of: delimiter) else { return missing }
        return String(s[s.index(after: index)...])
    }

    private static func hostOnly(_ hostPort: String) -> String {
        if LinkText.hasPrefix(hostPort, "[") {
            return before(LinkText.string(hostPort.utf8.dropFirst()), "]")
        }
        return before(hostPort, ":")
    }

    private static func sameHost(_ a: String, _ b: String) -> Bool {
        hostOnly(a).lowercased() == hostOnly(b).lowercased()
    }

    private static func parseParams(_ s: String) -> [Param] {
        LinkText.split(s, UInt8(ascii: "&")).filter { !$0.isEmpty }.map { part -> Param in
            (key: percentDecode(before(part, "=")).lowercased(), value: percentDecode(after(part, "=", missing: "")))
        }
    }

    private static func isHttp(_ s: String) -> Bool {
        LinkText.hasPrefix(s, "https://", ignoreCase: true) || LinkText.hasPrefix(s, "http://", ignoreCase: true)
    }

    private static func hostAndPort(_ url: String) -> String? {
        let bytes = Array(url.utf8)
        var start = 0
        if let scheme = LinkText.indexOf(bytes, Array("://".utf8)) { start = scheme + 3 }
        var end = bytes.count
        for (offset, b) in bytes[start...].enumerated() where b == UInt8(ascii: "/") || b == UInt8(ascii: "?") || b == UInt8(ascii: "#") {
            end = start + offset
            break
        }
        var authority = Array(bytes[start..<end])
        if let at = authority.lastIndex(of: UInt8(ascii: "@")) { authority = Array(authority[(at + 1)...]) }
        return authority.isEmpty ? nil : LinkText.string(authority)
    }

    /// Percent-encodes `s`, leaving the unreserved characters and those in `keep` as they are.
    private static func encode(_ s: String, keep: String = ":[]") -> String {
        let keepBytes = Set(keep.utf8)
        var out = ""
        for b in s.utf8 {
            let unreserved = (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57) ||
                b == 45 || b == 46 || b == 95 || b == 126
            if unreserved || keepBytes.contains(b) {
                out.unicodeScalars.append(Unicode.Scalar(b))
            } else {
                out += String(format: "%%%02X", b)
            }
        }
        return out
    }
}
