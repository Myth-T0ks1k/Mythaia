import Foundation
import MythaiaKit

/// Folds a refreshed subscription's servers into the stored ones, keeping
/// the ids of servers already there: pins, Auto's picks and chains point at
/// them. Matched first by endpoint (a panel that renames a server keeps its
/// address), then by name, positionally within a set of duplicates.
enum SubscriptionMerge {
    private final class IndexQueue {
        var items: [Int] = []
        var head = 0

        var isEmpty: Bool { head >= items.count }

        func popFirst() -> Int? {
            guard head < items.count else { return nil }
            defer { head += 1 }
            return items[head]
        }
    }

    private final class EndpointGroup {
        var members: [Int] = []
        var next = 0
    }

    static func preserveIds(old: [ProxyConfiguration], fetched: [ProxyConfiguration],
                            subscriptionId: UUID) -> [ProxyConfiguration] {
        // Every set of equal old configs keeps the indices of its unclaimed
        // members in list order; claiming one takes the first of them.
        var equalSets: [ProxyConfiguration: IndexQueue] = [:]
        var unclaimedEqual: [IndexQueue] = []
        unclaimedEqual.reserveCapacity(old.count)
        for (index, config) in old.enumerated() {
            let queue: IndexQueue
            if let existing = equalSets[config] {
                queue = existing
            } else {
                queue = IndexQueue()
                equalSets[config] = queue
            }
            queue.items.append(index)
            unclaimedEqual.append(queue)
        }
        var claimed = [Bool](repeating: false, count: old.count)

        var byEndpoint: [String: EndpointGroup] = [:]
        for (index, config) in old.enumerated() {
            let key = CoreBridge.endpointKey(config)
            let group: EndpointGroup
            if let existing = byEndpoint[key] {
                group = existing
            } else {
                group = EndpointGroup()
                byEndpoint[key] = group
            }
            group.members.append(index)
        }

        // Pass 1: same endpoint.
        var assigned = [Int](repeating: -1, count: fetched.count)
        for (index, fresh) in fetched.enumerated() {
            guard let group = byEndpoint[CoreBridge.endpointKey(fresh)] else { continue }
            while group.next < group.members.count && unclaimedEqual[group.members[group.next]].isEmpty {
                group.next += 1
            }
            guard group.next < group.members.count else { continue }
            let match = group.members[group.next]
            if let first = unclaimedEqual[match].popFirst() {
                claimed[first] = true
            }
            assigned[index] = match
        }

        // Pass 2: same name, among whatever is still unclaimed.
        var byName: [String: IndexQueue] = [:]
        for index in old.indices where !claimed[index] {
            let name = old[index].name
            let queue: IndexQueue
            if let existing = byName[name] {
                queue = existing
            } else {
                queue = IndexQueue()
                byName[name] = queue
            }
            queue.items.append(index)
        }
        for (index, fresh) in fetched.enumerated() where assigned[index] < 0 {
            if let match = byName[fresh.name]?.popFirst() {
                assigned[index] = match
            }
        }

        var result: [ProxyConfiguration] = []
        result.reserveCapacity(fetched.count)
        for (index, fresh) in fetched.enumerated() {
            let match = assigned[index]
            let id = match >= 0 ? old[match].id : fresh.id
            result.append(CoreBridge.withIdentity(fresh, id: id, subscriptionId: subscriptionId))
        }
        return result
    }
}
