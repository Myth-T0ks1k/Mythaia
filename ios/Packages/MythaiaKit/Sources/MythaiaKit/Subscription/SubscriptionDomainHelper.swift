import Foundation

/**
 * Allow-lists of subscription domains that trigger special handling:
 *
 *  - `shouldDisableProxyEditing` locks individual proxies inside a subscription
 *    from being edited or deleted (users should re-subscribe instead).
 *  - `shouldRequireRemnawaveHWID` marks Remnawave-panel subscriptions whose
 *    endpoints require the device identifier as an `x-hwid` header.
 */
public enum SubscriptionDomainHelper {
    private static let domainsShouldDisableProxyEditing: [String] = [
        "sub.example.com",
        "sub.cdnjst.org",
    ]

    private static let domainsRequireRemnawaveHWID: [String] = [
        "sub.example.com",
        "sub.cdnjst.org",
    ]

    public static func shouldDisableProxyEditing(_ url: String) -> Bool {
        domainsShouldDisableProxyEditing.contains { LinkText.hasPrefix(url, "https://\($0)/") }
    }

    public static func shouldRequireRemnawaveHWID(_ url: String) -> Bool {
        domainsRequireRemnawaveHWID.contains { LinkText.hasPrefix(url, "https://\($0)/") }
    }
}
