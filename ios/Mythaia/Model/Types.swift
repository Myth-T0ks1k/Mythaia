import Foundation
import MythaiaKit

/// A set of servers the tunnel can point at as one thing: "Default" is every
/// server that came from no subscription, and every subscription is a group
/// of its own. A group is on Auto (the fastest server by real ping) unless
/// the user pinned one of its servers.
struct ProxyGroup: Identifiable {
    static let defaultId = SelectionState.defaultGroupId
    static let chainsId = "__chains__"

    let id: String
    let name: String
    let subscriptionId: UUID?
    let configs: [ProxyConfiguration]

    var isDefault: Bool { subscriptionId == nil }

    static func id(for subscriptionId: UUID?) -> String {
        subscriptionId.map { $0.uuidString.lowercased() } ?? defaultId
    }
}

/// The last latency check of one server.
enum LatencyResult: Equatable {
    case testing
    case success(Int)
    case failed

    var milliseconds: Int? {
        if case .success(let ms) = self { return ms }
        return nil
    }
}

/// What the bar at the bottom of the screen says about a subscription refresh.
enum SubscriptionNotice: Equatable {
    /// The refresh failed; `canRetry` offers the download through a server that works.
    case failed(subscriptionId: UUID, name: String, message: String, canRetry: Bool)
    /// Looking for a working server and fetching through it.
    case retrying(subscriptionId: UUID, name: String)
    /// Updated through `server`.
    case updatedThrough(subscriptionId: UUID, name: String, server: String)

    var subscriptionId: UUID {
        switch self {
        case .failed(let id, _, _, _), .retrying(let id, _), .updatedThrough(let id, _, _):
            return id
        }
    }
}

/// An alert the app shows over everything.
struct AppAlert: Identifiable {
    let id = UUID()
    let title: String
    let message: String
}

/// A request to open the Add sheet, with text to start from.
struct AddRequest: Identifiable {
    let id = UUID()
    var initialText: String
}

enum AppTab: Hashable {
    case home
    case proxies
    case settings
}
