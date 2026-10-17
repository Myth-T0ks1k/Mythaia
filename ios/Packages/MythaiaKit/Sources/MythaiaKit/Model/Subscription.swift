import Foundation

public struct Subscription: Codable, Hashable, Identifiable {
    public var id: UUID
    public var name: String
    public var url: String
    public var lastUpdate: Int64?
    public var upload: Int64?
    public var download: Int64?
    public var total: Int64?
    /// Epoch milliseconds.
    public var expire: Int64?
    public var collapsed: Bool
    /// Whether the user manually renamed this subscription — prevents auto-overwrite on update.
    public var isNameCustomized: Bool
    /**
     * Domain fronting for the fetch itself.
     *
     * When `frontTargets` is not empty the subscription is downloaded by
     * connecting to each target in turn (a host or IP, optionally `:port`),
     * presenting `frontSni` in the TLS handshake (the URL's own host when
     * nil) and the URL's host in the HTTP `Host` header. This gets a panel
     * through a filter that blocks its domain but not the CDN in front of it.
     */
    public var frontSni: String?
    public var frontTargets: [String]
    /// The panel's `announce` header: a message from the provider, shown with the group.
    public var announce: String?
    /// `support-url`: where the provider takes questions.
    public var supportUrl: String?
    /// `profile-web-page-url`: the provider's page for this account.
    public var webPageUrl: String?
    /// `profile-update-interval`, in hours: how often the provider asks to be refreshed.
    public var updateIntervalHours: Int?
    /// `fallback-url`: where the subscription is fetched from when `url` does not answer.
    public var fallbackUrl: String?
    /// `sub-info-*`: a coloured block from the provider, with an optional button.
    public var subInfo: SubInfo?
    /// `sub-expire`: warn when `expire` is three days away or past.
    public var expireNotice: Bool
    /// `sub-expire-button-link`: where the expiry warning's Renew button leads.
    public var expireButtonLink: String?
    /// `subscription-auto-update-open-enable`: refresh each time the app opens.
    public var updateOnOpen: Bool
    /// `subscription-auto-update-enable: 0` keeps the background refresh away from this subscription.
    public var autoUpdate: Bool
    /// `subscription-request-timeout`, in seconds.
    public var requestTimeoutSeconds: Int?
    /// When the last refresh failed (epoch millis), and why; cleared by the next one that works.
    public var lastFailure: Int64?
    public var lastFailureMessage: String?

    public init(
        id: UUID = UUID(),
        name: String,
        url: String,
        lastUpdate: Int64? = nil,
        upload: Int64? = nil,
        download: Int64? = nil,
        total: Int64? = nil,
        expire: Int64? = nil,
        collapsed: Bool = false,
        isNameCustomized: Bool = false,
        frontSni: String? = nil,
        frontTargets: [String] = [],
        announce: String? = nil,
        supportUrl: String? = nil,
        webPageUrl: String? = nil,
        updateIntervalHours: Int? = nil,
        fallbackUrl: String? = nil,
        subInfo: SubInfo? = nil,
        expireNotice: Bool = false,
        expireButtonLink: String? = nil,
        updateOnOpen: Bool = false,
        autoUpdate: Bool = true,
        requestTimeoutSeconds: Int? = nil,
        lastFailure: Int64? = nil,
        lastFailureMessage: String? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdate = lastUpdate
        self.upload = upload
        self.download = download
        self.total = total
        self.expire = expire
        self.collapsed = collapsed
        self.isNameCustomized = isNameCustomized
        self.frontSni = frontSni
        self.frontTargets = frontTargets
        self.announce = announce
        self.supportUrl = supportUrl
        self.webPageUrl = webPageUrl
        self.updateIntervalHours = updateIntervalHours
        self.fallbackUrl = fallbackUrl
        self.subInfo = subInfo
        self.expireNotice = expireNotice
        self.expireButtonLink = expireButtonLink
        self.updateOnOpen = updateOnOpen
        self.autoUpdate = autoUpdate
        self.requestTimeoutSeconds = requestTimeoutSeconds
        self.lastFailure = lastFailure
        self.lastFailureMessage = lastFailureMessage
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, url, lastUpdate, upload, download, total, expire, collapsed, isNameCustomized
        case frontSni, frontTargets, announce, supportUrl, webPageUrl, updateIntervalHours, fallbackUrl
        case subInfo, expireNotice, expireButtonLink, updateOnOpen, autoUpdate, requestTimeoutSeconds
        case lastFailure, lastFailureMessage
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decode(String.self, forKey: .name)
        url = try c.decode(String.self, forKey: .url)
        lastUpdate = try c.decodeIfPresent(Int64.self, forKey: .lastUpdate)
        upload = try c.decodeIfPresent(Int64.self, forKey: .upload)
        download = try c.decodeIfPresent(Int64.self, forKey: .download)
        total = try c.decodeIfPresent(Int64.self, forKey: .total)
        expire = try c.decodeIfPresent(Int64.self, forKey: .expire)
        collapsed = try c.decodeIfPresent(Bool.self, forKey: .collapsed) ?? false
        isNameCustomized = try c.decodeIfPresent(Bool.self, forKey: .isNameCustomized) ?? false
        frontSni = try c.decodeIfPresent(String.self, forKey: .frontSni)
        frontTargets = try c.decodeIfPresent([String].self, forKey: .frontTargets) ?? []
        announce = try c.decodeIfPresent(String.self, forKey: .announce)
        supportUrl = try c.decodeIfPresent(String.self, forKey: .supportUrl)
        webPageUrl = try c.decodeIfPresent(String.self, forKey: .webPageUrl)
        updateIntervalHours = try c.decodeIfPresent(Int.self, forKey: .updateIntervalHours)
        fallbackUrl = try c.decodeIfPresent(String.self, forKey: .fallbackUrl)
        subInfo = try c.decodeIfPresent(SubInfo.self, forKey: .subInfo)
        expireNotice = try c.decodeIfPresent(Bool.self, forKey: .expireNotice) ?? false
        expireButtonLink = try c.decodeIfPresent(String.self, forKey: .expireButtonLink)
        updateOnOpen = try c.decodeIfPresent(Bool.self, forKey: .updateOnOpen) ?? false
        autoUpdate = try c.decodeIfPresent(Bool.self, forKey: .autoUpdate) ?? true
        requestTimeoutSeconds = try c.decodeIfPresent(Int.self, forKey: .requestTimeoutSeconds)
        lastFailure = try c.decodeIfPresent(Int64.self, forKey: .lastFailure)
        lastFailureMessage = try c.decodeIfPresent(String.self, forKey: .lastFailureMessage)
    }

    /// Whether the fetch goes through a front rather than straight to the URL.
    public var isFronted: Bool { !frontTargets.isEmpty }

    public struct SubInfo: Codable, Hashable {
        public var text: String
        /// `red`, `blue` or `green`.
        public var color: String
        public var buttonText: String?
        public var buttonLink: String?

        public init(text: String, color: String = "blue", buttonText: String? = nil, buttonLink: String? = nil) {
            self.text = text
            self.color = color
            self.buttonText = buttonText
            self.buttonLink = buttonLink
        }

        private enum CodingKeys: String, CodingKey {
            case text, color, buttonText, buttonLink
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            text = try c.decode(String.self, forKey: .text)
            color = try c.decodeIfPresent(String.self, forKey: .color) ?? "blue"
            buttonText = try c.decodeIfPresent(String.self, forKey: .buttonText)
            buttonLink = try c.decodeIfPresent(String.self, forKey: .buttonLink)
        }
    }

    /// Whether the last refresh failed, with no success since.
    public var isFailing: Bool {
        guard let failure = lastFailure else { return false }
        return failure > (lastUpdate ?? 0)
    }

    public enum ExpiryWarning: Hashable {
        case expired
        /// Expires within `days` days (1 to 3).
        case soon(days: Int)
    }

    private static let dayMs: Int64 = 24 * 60 * 60 * 1000
    private static let expiryWarningMs: Int64 = 3 * dayMs

    /// Now, in epoch milliseconds.
    public static func currentTimeMillis() -> Int64 {
        Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))
    }

    /// The `sub-expire` warning due at `now` (epoch millis), if any.
    public func expiryWarning(now: Int64 = Subscription.currentTimeMillis()) -> ExpiryWarning? {
        guard expireNotice, let at = expire, at > 0 else { return nil }
        if at <= now { return .expired }
        if at - now <= Subscription.expiryWarningMs {
            // Whole days left, as the usage card counts them: 2 days 5 hours is 2.
            let days = Int((at - now) / Subscription.dayMs)
            return .soon(days: max(1, days))
        }
        return nil
    }
}
