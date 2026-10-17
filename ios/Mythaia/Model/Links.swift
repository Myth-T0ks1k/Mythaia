import Foundation
import MythaiaKit

enum LinkHelpers {
    /// Hosts typed one per line, or separated by commas or semicolons.
    static func splitTargets(_ text: String) -> [String] {
        text.components(separatedBy: CharacterSet(charactersIn: "\n,;"))
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    static func isHttp(_ s: String) -> Bool {
        let lower = s.lowercased()
        return lower.hasPrefix("https://") || lower.hasPrefix("http://")
    }
}

/// What the app was opened with.
enum DeepLink: Equatable {
    /// Text for the Add sheet: a share link, or a subscription URL with its
    /// fronting in the fragment.
    case importText(String)
    case connect
    case disconnect
    case toggle

    static let shareSchemes: Set<String> = [
        "vless", "vmess", "trojan", "ss", "socks", "socks5", "hysteria2", "hy2", "tuic", "anytls",
    ]

    static func parse(_ url: URL) -> DeepLink? {
        parse(url.absoluteString)
    }

    static func parse(_ link: String) -> DeepLink? {
        let full = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let schemeEnd = full.range(of: "://") else { return nil }
        let scheme = full[..<schemeEnd.lowerBound].lowercased()
        if shareSchemes.contains(scheme) {
            return .importText(full)
        }
        guard scheme == "mythaia" else { return nil }
        let afterScheme = full[schemeEnd.upperBound...]
        let host = afterScheme.prefix { $0 != "?" && $0 != "/" && $0 != "#" }.lowercased()
        switch host {
        case "connect":
            return .connect
        case "disconnect":
            return .disconnect
        case "toggle":
            return .toggle
        case "import", "add-subscription":
            // `add-subscription` takes the same parameters as `import`; the
            // prefix is swapped so one parser reads both.
            guard let query = full.range(of: "?") else { return nil }
            let rewritten = "mythaia://import?" + String(full[query.upperBound...])
            guard let parsed = SubscriptionLink.parse(rewritten) else { return nil }
            return .importText(parsed.toFragmentLink())
        case "add-proxy":
            // Everything after `link=` is the share link, which may carry its
            // own `?` and `&`; it is taken whole.
            guard let marker = full.range(of: "?link=") ?? full.range(of: "&link=") else { return nil }
            let raw = String(full[marker.upperBound...])
            guard !raw.isEmpty else { return nil }
            return .importText(percentDecode(raw))
        default:
            return nil
        }
    }
}

/// Pasted text taken apart: subscription URLs to download, and the rest for
/// the server parser.
struct ImportText {
    var subscriptionLinks: [String]
    var serverText: String

    var isEmpty: Bool {
        subscriptionLinks.isEmpty && serverText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func split(_ text: String) -> ImportText {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // A whole document goes to the parser as it is.
        if CoreBridge.looksLikeDocument(trimmed) {
            return ImportText(subscriptionLinks: [], serverText: trimmed)
        }
        // A message, a list, or another client's import link: the links in it.
        let links = LinkExtractor.extract(trimmed)
        if links.isEmpty {
            return ImportText(subscriptionLinks: [], serverText: trimmed)
        }
        let subscriptions = links.filter { LinkHelpers.isHttp($0) }
        let servers = links.filter { !LinkHelpers.isHttp($0) }
        return ImportText(subscriptionLinks: subscriptions, serverText: servers.joined(separator: "\n"))
    }
}
