import Foundation

/**
 * Whatever a user pastes or scans, read into servers: a share link, a list of
 * them, a chat message with links in it, another client's import link, a
 * base64 subscription body, a Clash config, Xray or sing-box JSON, or a
 * WireGuard INI. The add screen's single entry point.
 *
 * Subscription URLs found in the text are handed back rather than fetched:
 * downloading is the caller's step (`SubscriptionFetcher.fetch(url:hwid:)`).
 */
public enum LinkImporter {

    public struct Result {
        /// The servers the text described, in order.
        public var configurations: [ProxyConfiguration]
        /// http(s) links found, as subscriptions to fetch (fronting in their fragment form).
        public var subscriptionUrls: [String]
        /// Links that looked like servers but were refused, each with the reason.
        public var failures: [String]

        public init(configurations: [ProxyConfiguration], subscriptionUrls: [String], failures: [String]) {
            self.configurations = configurations
            self.subscriptionUrls = subscriptionUrls
            self.failures = failures
        }
    }

    /**
     * Reads `text`. `naiveProtocol`, when given, says an `https://` link is an
     * HTTPS (or HTTP/2) proxy rather than a subscription.
     *
     * Throws `MythaiaError.parse` with the reason when nothing in the text is
     * usable.
     */
    public static func importFromString(_ text: String, naiveProtocol: OutboundProtocol? = nil) throws -> Result {
        let trimmed = LinkText.trim(text)
        if trimmed.isEmpty { throw MythaiaError.parse("Nothing to import") }

        // Xray / sing-box JSON: a whole config or one outbound. Every proxy
        // outbound in it is imported.
        if XrayJsonImporter.looksLikeJson(trimmed) {
            return Result(configurations: try XrayJsonImporter.parse(trimmed), subscriptionUrls: [], failures: [])
        }

        // A WireGuard peer hands out a wg-quick INI, not a link, so a paste is
        // recognised by its shape before any scheme matching happens.
        if ProxyConfiguration.looksLikeWireGuardConfig(trimmed) {
            return Result(configurations: [try ProxyConfiguration.fromWireGuardConfig(trimmed)], subscriptionUrls: [], failures: [])
        }

        // A Clash config carries URLs of its own (rule providers), so it is
        // read as a whole before links are looked for.
        if SubscriptionFetcher.looksLikeClash(trimmed) {
            let parsed = try ClashProxyParser.parse(trimmed)
            if parsed.configurations.isEmpty {
                throw MythaiaError.parse("No valid configurations found in subscription.")
            }
            return Result(configurations: parsed.configurations, subscriptionUrls: [], failures: [])
        }

        let links = LinkExtractor.extract(trimmed)
        if links.isEmpty {
            // No scheme anywhere: a subscription body pasted whole (base64).
            let parsed = try SubscriptionFetcher.parse(Data(trimmed.utf8))
            return Result(configurations: parsed.configurations, subscriptionUrls: [], failures: [])
        }

        var configurations: [ProxyConfiguration] = []
        var subscriptionUrls: [String] = []
        var failures: [String] = []
        for link in links {
            let isHttp = LinkText.hasPrefix(link, "http://", ignoreCase: true) || LinkText.hasPrefix(link, "https://", ignoreCase: true)
            // A link with fronting written in is a subscription whatever the caller says.
            if isHttp && (naiveProtocol == nil || SubscriptionLink.isFrontedLink(link) || !ProxyConfiguration.canParseUrl(link)) {
                subscriptionUrls.append(link)
                continue
            }
            do {
                configurations.append(try ProxyConfiguration.fromUrl(link, naiveProtocol: naiveProtocol))
            } catch {
                failures.append("\(link): \(ShareLinkParams.message(error))")
            }
        }
        if configurations.isEmpty && subscriptionUrls.isEmpty {
            throw MythaiaError.parse(failures.first ?? "No links found")
        }
        return Result(configurations: configurations, subscriptionUrls: subscriptionUrls, failures: failures)
    }
}
