import Foundation
import BackgroundTasks
import WidgetKit
import MythaiaKit

/// Subscriptions refreshed while the app is closed, through a background
/// app-refresh task. The system decides when it runs; the app only says
/// how soon the next subscription is due.
enum BackgroundRefresh {
    /// Listed in Info.plist under `BGTaskSchedulerPermittedIdentifiers`.
    static var identifier: String {
        (Bundle.main.bundleIdentifier ?? "com.mythaia") + ".refresh"
    }

    /// The model the task works on, set when the app starts, also when the
    /// system starts it in the background just for this task.
    @MainActor static weak var model: AppModel?

    @MainActor
    static func run() async {
        await model?.runBackgroundRefresh()
    }
}

extension AppModel {

    /// Whether `subscription` wants a refresh now: auto-update on, and its
    /// interval (the panel's, or a day) passed since the last one.
    func isAutoUpdateDue(_ subscription: Subscription, now: Date = Date()) -> Bool {
        guard subscription.autoUpdate else { return false }
        guard let last = subscription.lastUpdate else { return true }
        let hours = Double(max(subscription.updateIntervalHours ?? 24, 1))
        let lastDate = Date(timeIntervalSince1970: Double(last) / 1000)
        return now.timeIntervalSince(lastDate) >= hours * 3600
    }

    /// When the next subscription falls due; nil when none updates on its own.
    func nextAutoUpdateDate() -> Date? {
        let soonest = Date().addingTimeInterval(15 * 60)
        var earliest: Date?
        for subscription in subscriptions where subscription.autoUpdate {
            let hours = Double(max(subscription.updateIntervalHours ?? 24, 1))
            var next = soonest
            if let last = subscription.lastUpdate {
                next = Date(timeIntervalSince1970: Double(last) / 1000).addingTimeInterval(hours * 3600)
                if next < soonest { next = soonest }
            }
            if let current = earliest {
                if next < current { earliest = next }
            } else {
                earliest = next
            }
        }
        return earliest
    }

    /// Asks the system for a background run when the next subscription is due.
    func scheduleBackgroundRefresh() {
        let scheduler = BGTaskScheduler.shared
        scheduler.cancel(taskRequestWithIdentifier: BackgroundRefresh.identifier)
        guard let date = nextAutoUpdateDate() else { return }
        let request = BGAppRefreshTaskRequest(identifier: BackgroundRefresh.identifier)
        request.earliestBeginDate = date
        do {
            try scheduler.submit(request)
        } catch {
            // The simulator and builds without the capability say no.
            Log.warning("Background refresh not scheduled: \(error.localizedDescription)")
        }
    }

    /// The background task: every subscription that is due, one at a time,
    /// until the system takes the time back; then the next run is booked.
    func runBackgroundRefresh() async {
        let due = subscriptions.filter { isAutoUpdateDue($0) }
        for subscription in due {
            if Task.isCancelled { break }
            if updatingSubscriptionId != nil { continue }
            updatingSubscriptionId = subscription.id
            do {
                try await updateSubscription(subscription, via: nil, timeout: 25)
            } catch {
                Log.warning("Background refresh failed for \(subscription.name): \(AppModel.describe(error))")
            }
            updatingSubscriptionId = nil
        }
        scheduleBackgroundRefresh()
    }
}

/// The connection state the home-screen widget and the Control Center
/// control show, kept in the App Group's defaults. The widget extension
/// reads the same keys.
enum WidgetBridge {
    static let connectedKey = "widget.connected"
    static let serverKey = "widget.server"
    static let updatedKey = "widget.updated"

    static func publish(connected: Bool, server: String?) {
        if let defaults = UserDefaults(suiteName: AppGroup.identifier) {
            defaults.set(connected, forKey: connectedKey)
            defaults.set(server, forKey: serverKey)
            defaults.set(Date().timeIntervalSince1970, forKey: updatedKey)
        }
        WidgetCenter.shared.reloadAllTimelines()
        #if compiler(>=6.0)
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadAllControls()
        }
        #endif
    }
}
