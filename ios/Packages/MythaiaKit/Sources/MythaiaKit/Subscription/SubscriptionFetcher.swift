import Foundation

/// A fetched subscription: its servers, and the subscription with what the panel said folded in.
public struct SubscriptionFetchResult {
    public var configurations: [ProxyConfiguration]
    /// Metadata already applied (`SubscriptionMetadata.applyTo`).
    public var subscription: Subscription

    public init(configurations: [ProxyConfiguration], subscription: Subscription) {
        self.configurations = configurations
        self.subscription = subscription
    }
}

/**
 * Downloads and reads subscriptions.
 *
 * Errors: an unusable URL is `invalidConfiguration`, a body with no servers
 * in it is `parse`, and anything on the way — the connection, an HTTP status,
 * a front that did not answer — is `connectFailed` with the reason, which is
 * what moves a fetch on to the subscription's fallback URL.
 */
public enum SubscriptionFetcher {

    /**
     * What a panel says about the subscription besides the servers: the keys
     * Remnawave, Marzban and 3x-ui send and Happ reads, from the headers or
     * from `#key: value` lines in the body. `SubscriptionMetadata` reads them
     * and folds them into the stored subscription.
     */
    public struct PanelInfo: Hashable {
        public var title: String?
        public var userInfo: String?
        public var announce: String?
        public var supportUrl: String?
        public var webPageUrl: String?
        public var updateIntervalHours: Int?
        public var updateOnOpen: Bool?
        public var autoUpdate: Bool?
        public var requestTimeoutSeconds: Int?
        public var newUrl: String?
        public var newDomain: String?
        public var fallbackUrl: String?
        /// Hosts to dial instead of the panel; nil when the panel did not say.
        public var frontTargets: [String]?
        /// `fronting-target: off`: fetch straight from the panel again.
        public var frontingOff: Bool
        public var frontSni: String?
        /// Happ's `host`, beside a target: the panel's real host.
        public var frontHost: String?
        public var subInfo: Subscription.SubInfo?
        public var expireNotice: Bool?
        public var expireButtonLink: String?

        public init(
            title: String? = nil,
            userInfo: String? = nil,
            announce: String? = nil,
            supportUrl: String? = nil,
            webPageUrl: String? = nil,
            updateIntervalHours: Int? = nil,
            updateOnOpen: Bool? = nil,
            autoUpdate: Bool? = nil,
            requestTimeoutSeconds: Int? = nil,
            newUrl: String? = nil,
            newDomain: String? = nil,
            fallbackUrl: String? = nil,
            frontTargets: [String]? = nil,
            frontingOff: Bool = false,
            frontSni: String? = nil,
            frontHost: String? = nil,
            subInfo: Subscription.SubInfo? = nil,
            expireNotice: Bool? = nil,
            expireButtonLink: String? = nil
        ) {
            self.title = title
            self.userInfo = userInfo
            self.announce = announce
            self.supportUrl = supportUrl
            self.webPageUrl = webPageUrl
            self.updateIntervalHours = updateIntervalHours
            self.updateOnOpen = updateOnOpen
            self.autoUpdate = autoUpdate
            self.requestTimeoutSeconds = requestTimeoutSeconds
            self.newUrl = newUrl
            self.newDomain = newDomain
            self.fallbackUrl = fallbackUrl
            self.frontTargets = frontTargets
            self.frontingOff = frontingOff
            self.frontSni = frontSni
            self.frontHost = frontHost
            self.subInfo = subInfo
            self.expireNotice = expireNotice
            self.expireButtonLink = expireButtonLink
        }
    }

    public struct Result {
        public var configurations: [ProxyConfiguration]
        public var name: String?
        public var upload: Int64?
        public var download: Int64?
        public var total: Int64?
        /// Epoch milliseconds.
        public var expire: Int64?
        public var panel: PanelInfo

        public init(
            configurations: [ProxyConfiguration],
            name: String?,
            upload: Int64?,
            download: Int64?,
            total: Int64?,
            expire: Int64?,
            panel: PanelInfo = PanelInfo()
        ) {
            self.configurations = configurations
            self.name = name
            self.upload = upload
            self.download = download
            self.total = total
            self.expire = expire
            self.panel = panel
        }
    }

    public static let defaultTimeout: Double = 30

    /// How long the main URL gets when there is a fallback to try; Happ moves on after about nine seconds.
    static let fallbackAfter: Double = 10

    /// Panels do not serve lists this large; anything bigger is a misconfiguration, not a subscription.
    static let maxBodyBytes = 16 * 1024 * 1024

    private static func invalidUrl() -> MythaiaError {
        MythaiaError.invalidConfiguration("Invalid subscription URL.")
    }

    private static func noConfigurations() -> MythaiaError {
        MythaiaError.parse("No valid configurations found in subscription.")
    }

    /// The detail of a network error, the kind that sends a fetch to the fallback URL.
    private static func networkDetail(_ error: Error) -> String? {
        guard let mythaia = error as? MythaiaError else { return nil }
        switch mythaia {
        case .connectFailed(let detail): return detail
        case .timeout: return "timed out"
        case .tls(let why): return why
        case .closed: return "connection closed"
        default: return nil
        }
    }

    // MARK: - Public entry points

    /**
     * Refreshes `subscription` with its own fronting, timeout and fallback
     * URL, and folds what the panel said into it.
     *
     * - Parameters:
     *   - hwid: sent as `x-hwid` to panels that want the device identifier; nil sends none.
     *   - via: one of the user's servers to fetch through, for a panel that
     *     cannot be reached from here at all; nil to fetch directly.
     *   - timeout: seconds each URL gets; by default the panel's own
     *     `subscription-request-timeout`, shorter when a fallback URL waits.
     */
    public static func fetch(
        _ subscription: Subscription,
        hwid: String?,
        via: ProxyConfiguration?,
        timeout: Double?
    ) async throws -> SubscriptionFetchResult {
        let result = try await fetchResult(subscription, remnawaveHWID: hwid, via: via, timeout: timeout)
        let updated = SubscriptionMetadata.applyTo(subscription, result: result)
        return SubscriptionFetchResult(configurations: stamp(result.configurations, with: updated.id), subscription: updated)
    }

    /**
     * Adds a subscription from a URL in either link form (fronting and a
     * group name may ride along; see `SubscriptionLink`). The group is named
     * by the link, else by the panel, else by the host.
     */
    public static func fetch(url: String, hwid: String?) async throws -> SubscriptionFetchResult {
        let link = SubscriptionLink.parse(url)
        let panelUrl = link?.url ?? LinkText.trim(url)
        let frontTargets = link?.frontTargets ?? []
        let result = try await fetch(
            urlString: panelUrl,
            remnawaveHWID: hwid,
            frontSni: link?.frontSni,
            frontTargets: frontTargets
        )
        var linkName: String? = nil
        if let given = link?.name {
            let trimmed = LinkText.trim(given)
            if !trimmed.isEmpty { linkName = trimmed }
        }
        var hostName: String? = nil
        if let parsedUrl = makeURL(panelUrl) {
            let host = FrontedHttpClient.bareHost(parsedUrl)
            if !host.isEmpty { hostName = host }
        }
        let groupName = linkName ?? result.name ?? hostName ?? "Subscription"
        let base = Subscription(
            name: groupName,
            url: panelUrl,
            isNameCustomized: linkName != nil,
            frontSni: link?.frontSni,
            frontTargets: frontTargets
        )
        let subscription = SubscriptionMetadata.applyTo(base, result: result)
        return SubscriptionFetchResult(configurations: stamp(result.configurations, with: subscription.id), subscription: subscription)
    }

    /// The servers marked as this subscription's, chains included as they are.
    private static func stamp(_ configurations: [ProxyConfiguration], with id: UUID) -> [ProxyConfiguration] {
        configurations.map { config -> ProxyConfiguration in
            var copy = config
            copy.subscriptionId = id
            return copy
        }
    }

    /// The fetch behind `fetch(_:hwid:via:timeout:)`, before the metadata is folded in.
    public static func fetchResult(
        _ subscription: Subscription,
        remnawaveHWID: String? = nil,
        via: ProxyConfiguration? = nil,
        timeout: Double? = nil
    ) async throws -> Result {
        var fallback: SubscriptionLink? = nil
        if let fallbackUrl = subscription.fallbackUrl, fallbackUrl != subscription.url {
            fallback = SubscriptionLink.parse(fallbackUrl)
        }
        var mainTimeout: Double = fallback != nil ? fallbackAfter : defaultTimeout
        if let seconds = subscription.requestTimeoutSeconds { mainTimeout = Double(seconds) }
        if let explicit = timeout { mainTimeout = explicit }
        do {
            return try await fetch(
                urlString: subscription.url,
                remnawaveHWID: remnawaveHWID,
                frontSni: subscription.frontSni,
                frontTargets: subscription.frontTargets,
                via: via,
                timeout: mainTimeout
            )
        } catch {
            guard let detail = networkDetail(error), let fallback = fallback else { throw error }
            do {
                return try await fetch(
                    urlString: fallback.url,
                    remnawaveHWID: remnawaveHWID,
                    frontSni: fallback.frontSni,
                    frontTargets: fallback.frontTargets,
                    via: via,
                    timeout: timeout ?? defaultTimeout
                )
            } catch {
                if error is CancellationError { throw error }
                let why = networkDetail(error) ?? ShareLinkParams.message(error)
                throw MythaiaError.connectFailed("\(detail); fallback URL: \(why)")
            }
        }
    }

    /**
     * - Parameters:
     *   - allowInsecure: skip certificate checks. Never tied to the
     *     proxy-server "allow insecure" setting: that one is about the user's
     *     own self-signed server, whereas an unverified subscription download
     *     lets anyone on the path replace every server in the list.
     *   - via: see `fetch(_:hwid:via:timeout:)`.
     */
    public static func fetch(
        urlString: String,
        allowInsecure: Bool = false,
        remnawaveHWID: String? = nil,
        frontSni: String? = nil,
        frontTargets: [String] = [],
        via: ProxyConfiguration? = nil,
        timeout: Double = defaultTimeout
    ) async throws -> Result {
        guard let url = makeURL(urlString), let scheme = url.scheme?.lowercased() else { throw invalidUrl() }
        // Only http and https: file: and the like are not HTTP at all.
        let https = scheme == "https"
        if !https && scheme != "http" { throw invalidUrl() }
        let host = FrontedHttpClient.bareHost(url)
        if host.isEmpty { throw invalidUrl() }

        let targets = frontTargets.map { LinkText.trim($0) }.filter { !$0.isEmpty }
        if !targets.isEmpty && https {
            let sni = frontSni.map { LinkText.trim($0) }.flatMap { $0.isEmpty ? nil : $0 } ?? host
            return try await fetchFronted(url, sni: sni, targets: targets, allowInsecure: allowInsecure,
                                          remnawaveHWID: remnawaveHWID, via: via, timeout: timeout)
        }
        if let server = via {
            // The server dials the panel itself; nothing else changes.
            let bracketed = host.utf8.contains(UInt8(ascii: ":")) ? "[\(host)]" : host
            let target = url.port.map { "\(bracketed):\($0)" } ?? bracketed
            return try await fetchFronted(url, sni: host, targets: [target], allowInsecure: allowInsecure,
                                          remnawaveHWID: remnawaveHWID, via: server, timeout: timeout)
        }
        return try await fetchDirect(url, allowInsecure: allowInsecure, remnawaveHWID: remnawaveHWID, timeout: timeout)
    }

    /// `URL(string:)`, with characters a URL may not carry raw (spaces, non-ASCII) percent-encoded first.
    static func makeURL(_ text: String) -> URL? {
        let trimmed = LinkText.trim(text)
        if let url = URL(string: trimmed) { return url }
        let legal = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
        guard let encoded = trimmed.addingPercentEncoding(withAllowedCharacters: legal) else { return nil }
        return URL(string: encoded)
    }

    // MARK: - Transports

    private static func fetchDirect(_ url: URL, allowInsecure: Bool, remnawaveHWID: String?, timeout: Double) async throws -> Result {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        request.setValue("Mythaia", forHTTPHeaderField: "User-Agent")
        if let hwid = remnawaveHWID { request.setValue(hwid, forHTTPHeaderField: "x-hwid") }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = max(60, timeout * 4)
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let delegate: URLSessionDelegate? = allowInsecure ? SubscriptionTrustAllDelegate() : nil
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        let data: Data
        let response: URLResponse
        do {
            let pair = try await session.data(for: request)
            data = pair.0
            response = pair.1
        } catch let error as URLError {
            if error.code == .cancelled && Task.isCancelled { throw CancellationError() }
            throw MythaiaError.connectFailed(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw MythaiaError.connectFailed("Not an HTTP response")
        }
        if http.statusCode < 200 || http.statusCode > 299 {
            throw MythaiaError.connectFailed("HTTP \(http.statusCode)")
        }
        if data.count > maxBodyBytes {
            throw MythaiaError.connectFailed("Response larger than \(maxBodyBytes) bytes")
        }
        // URLSession inflates what it asked to be compressed and keeps the
        // header, so the body is only inflated here when it still is gzip.
        let encoding = http.value(forHTTPHeaderField: "Content-Encoding")
        var body = data
        if Gzip.looksCompressed(data) {
            body = try gunzipIfNeeded(data, contentEncoding: encoding)
        }

        // Secure is judged on the URL the answer came from: redirects are followed.
        let finalScheme = (http.url ?? url).scheme?.lowercased()
        return try parseBody(
            body,
            header: { http.value(forHTTPHeaderField: $0) },
            secure: !allowInsecure && finalScheme == "https"
        )
    }

    /**
     * Downloads through each front in turn until one answers.
     *
     * The response is parsed exactly as the direct path parses it; only the
     * transport differs. A target that fails moves on to the next; when all
     * fail, the error names the last one so the user can see which front is
     * dead rather than a generic "network error".
     */
    private static func fetchFronted(
        _ url: URL,
        sni: String,
        targets: [String],
        allowInsecure: Bool,
        remnawaveHWID: String?,
        via: ProxyConfiguration?,
        timeout: Double
    ) async throws -> Result {
        var extra: [(String, String)] = []
        if let hwid = remnawaveHWID { extra.append(("x-hwid", hwid)) }
        var lastError: String? = nil
        for target in targets {
            try Task.checkCancellation()
            let response: FrontedHttpClient.Response
            do {
                response = try await FrontedHttpClient.get(
                    url: url,
                    sni: sni,
                    target: target,
                    extraHeaders: extra,
                    allowInsecure: allowInsecure,
                    maxBody: maxBodyBytes,
                    via: via,
                    timeout: timeout
                )
            } catch {
                if Task.isCancelled { throw CancellationError() }
                lastError = FrontedHttpClient.describe(target, error)
                continue
            }
            if response.status < 200 || response.status > 299 {
                lastError = "\(target): HTTP \(response.status)"
                continue
            }
            let body = try gunzipIfNeeded(response.body, contentEncoding: response.header("content-encoding"))
            return try parseBody(
                body,
                header: { response.header($0) },
                secure: !allowInsecure && url.scheme?.lowercased() == "https"
            )
        }
        throw MythaiaError.connectFailed(lastError ?? "No front answered")
    }

    /**
     * `body` decompressed when `contentEncoding` says it is gzip.
     *
     * The fronted transport does not ask for compression, but some panels (and
     * the CDNs in front of them) gzip regardless. The decoded size is bounded
     * like the raw one.
     */
    static func gunzipIfNeeded(_ body: Data, contentEncoding: String?) throws -> Data {
        guard let encoding = contentEncoding.map({ LinkText.trim($0).lowercased() }) else { return body }
        if encoding != "gzip" && encoding != "x-gzip" { return body }
        return try Gzip.decompress(body, limit: maxBodyBytes)
    }

    // MARK: - Parsing

    /// Parses a subscription body already in hand (pasted text, a file), exactly as a fetch would.
    public static func parse(_ data: Data) throws -> Result {
        try parseBody(data, header: { _ in nil }, secure: false)
    }

    /**
     * The parsing shared by every transport. `header` reads the response
     * headers (case-insensitively); `secure` is whether they and the body
     * came over verified TLS.
     */
    private static func parseBody(_ data: Data, header: (String) -> String?, secure: Bool) throws -> Result {
        let decoded = decodeBodyText(data)
        let bodyString = decoded.text
        // Metadata lines may sit inside a base64 body or above it in plain text.
        var fields = SubscriptionMetadata.bodyFields(bodyString)
        if !decoded.same {
            let outer = SubscriptionMetadata.bodyFields(decoded.raw)
            for (key, value) in outer where fields[key] == nil { fields[key] = value }
        }
        let panel = SubscriptionMetadata.read(header: header, body: fields, secure: secure)
        let userInfo = parseUserInfoValue(panel.userInfo)

        func result(_ configurations: [ProxyConfiguration]) -> Result {
            Result(
                configurations: configurations,
                name: panel.title,
                upload: userInfo.upload,
                download: userInfo.download,
                total: userInfo.total,
                expire: userInfo.expire,
                panel: panel
            )
        }

        // Built at most once and shared by the checks and importers below,
        // which each parsed the body again: three trees for a JSON
        // subscription of thousands of outbounds.
        var parsedTree: ImportJSON? = nil
        var treeBuilt = false
        func tree() -> ImportJSON? {
            if !treeBuilt {
                treeBuilt = true
                parsedTree = try? XrayJsonImporter.parseJson(bodyString)
            }
            return parsedTree
        }

        // sing-box first: its configs have `outbounds` too, and only the
        // shape of each outbound tells the two apart.
        if SingBoxJsonImporter.looksLikeSingBox(bodyString, tree: tree) {
            var configurations: [ProxyConfiguration] = []
            if let root = tree(), let parsed = try? SingBoxJsonImporter.parse(root: root) { configurations = parsed }
            if configurations.isEmpty { throw noConfigurations() }
            return result(configurations)
        }

        if XrayJsonImporter.looksLikeJson(bodyString) {
            var configurations: [ProxyConfiguration] = []
            if let root = tree(), let parsed = try? XrayJsonImporter.parse(root: root) { configurations = parsed }
            if configurations.isEmpty { throw noConfigurations() }
            return result(configurations)
        }

        if looksLikeClash(bodyString) {
            let parsed = try ClashProxyParser.parse(bodyString)
            if parsed.configurations.isEmpty { throw noConfigurations() }
            return result(parsed.configurations)
        }

        let prefixes = ProxyConfiguration.parsableUrlPrefixes
        var configurations: [ProxyConfiguration] = []
        for rawLine in LinkText.lines(bodyString) {
            let line = LinkText.trim(rawLine)
            guard prefixes.contains(where: { LinkText.hasPrefix(line, $0) }) else { continue }
            if let config = try? ProxyConfiguration.fromUrl(line) { configurations.append(config) }
        }
        if configurations.isEmpty { throw noConfigurations() }
        return result(configurations)
    }

    /**
     * The body as text: base64 (either alphabet) when decoding yields
     * something that reads as a share-link list or a Clash document, raw
     * UTF-8 otherwise.
     */
    static func decodeBody(_ data: Data) -> String {
        decodeBodyText(data).text
    }

    /**
     * The body as received, and as the list to parse: without its metadata
     * lines, and decoded when it was base64. `same` when there was nothing to
     * take away.
     */
    private static func decodeBodyText(_ data: Data) -> (raw: String, text: String, same: Bool) {
        let raw = LinkText.utf8(data)
        let prefixes = ProxyConfiguration.parsableUrlPrefixes
        func recognisable(_ text: String) -> Bool {
            LinkText.containsAny(Array(text.utf8), prefixes) || looksLikeClash(text) || XrayJsonImporter.looksLikeJson(text)
        }

        // Metadata lines (`#key: value`) are not the list: their links would
        // pass for share links, and around base64 they break the decoding.
        let hasMetadata = LinkText.hasPrefix(LinkText.trimStart(raw), "#") || LinkText.contains(raw, "\n#")
        var payload = raw
        if hasMetadata {
            payload = LinkText.lines(raw).filter { !LinkText.hasPrefix(LinkText.trimStart($0), "#") }.joined(separator: "\n")
        }
        if recognisable(payload) { return (raw, payload, !hasMetadata) }

        for urlSafe in [false, true] {
            guard let bytes = LinkText.decodeBase64Lenient(payload, urlSafe: urlSafe) else { continue }
            let text = LinkText.utf8(bytes)
            if recognisable(text) { return (raw, text, false) }
        }
        return (raw, raw, true)
    }

    /// A Clash document has a top-level `proxies:` key, not merely the word somewhere.
    static func looksLikeClash(_ text: String) -> Bool {
        for line in LinkText.lines(text) {
            let t = LinkText.trimStart(line)
            if LinkText.hasPrefix(t, "proxies:") || LinkText.hasPrefix(t, "proxy-providers:") { return true }
        }
        return false
    }

    struct UserInfo {
        var upload: Int64? = nil
        var download: Int64? = nil
        var total: Int64? = nil
        var expire: Int64? = nil
    }

    /// `upload=1; download=2; total=3; expire=1700000000`, the expiry turned into milliseconds.
    static func parseUserInfoValue(_ value: String?) -> UserInfo {
        guard let value = value else { return UserInfo() }
        var info = UserInfo()
        for part in LinkText.split(value, UInt8(ascii: ";")) {
            let trimmed = LinkText.trim(part)
            let bytes = Array(trimmed.utf8)
            guard let eq = bytes.firstIndex(of: UInt8(ascii: "=")) else { continue }
            let key = LinkText.trim(LinkText.string(bytes[..<eq]))
            let number = Int64(LinkText.trim(LinkText.string(bytes[(eq + 1)...])))
            switch key {
            case "upload": info.upload = number
            case "download": info.download = number
            case "total": info.total = number
            case "expire": info.expire = number.map { $0 &* 1000 }
            default: break
            }
        }
        return info
    }
}

extension Gzip {
    /// Whether `data` starts with the gzip magic number.
    static func looksCompressed(_ data: Data) -> Bool {
        data.count >= 2 && data[data.startIndex] == 0x1F && data[data.startIndex + 1] == 0x8B
    }
}

/// Accepts any certificate; used only when a caller explicitly asks for an insecure download.
private final class SubscriptionTrustAllDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
