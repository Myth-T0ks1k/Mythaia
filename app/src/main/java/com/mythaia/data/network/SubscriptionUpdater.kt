package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.data.repository.SubscriptionRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Refreshes one subscription: fetches it, folds the new servers into the store
 * keeping the IDs of the ones already there, and records what the panel said.
 *
 * Extracted from the view model so the background refresh worker runs exactly
 * the same code path as the pull-to-refresh in the UI. Anything view-model
 * specific — reselecting a server that vanished, surfacing an error — stays
 * with the caller.
 */
object SubscriptionUpdater {

    /**
     * @param remnawaveHWID the `x-hwid` header value, or null not to send one.
     * @return the subscription as it should now be stored.
     */
    suspend fun update(
        subscription: Subscription,
        subscriptionRepository: SubscriptionRepository,
        configRepository: ConfigRepository,
        remnawaveHWID: String?
    ): Subscription {
        val result = SubscriptionFetcher.fetch(subscription, remnawaveHWID = remnawaveHWID)

        // The fetch can take a while; re-read the record so a rename, a
        // collapse or a deletion made meanwhile is not overwritten with the
        // snapshot the caller handed in.
        val current = subscriptionRepository.get(subscription.id)
            ?: throw SubscriptionFetcher.FetchError.NoConfigurations()

        // Off the caller's thread: the pull-to-refresh runs in the view
        // model's scope on the main thread, and the merge and the save behind
        // replaceBySubscription each walk every server, which for a list of
        // thousands froze the app once the download was done. The repository
        // is already written from the background worker's threads.
        withContext(Dispatchers.Default) {
            // Keep the IDs of servers already present: rule-set assignments,
            // chains and the saved selection all point at them. Matched first by
            // endpoint (a panel that renames a server keeps its address), then by
            // name, positionally within a group of duplicates.
            val oldConfigs = configRepository.getAll().filter { it.subscriptionId == current.id }
            val newConfigs = preserveIds(oldConfigs, result.configurations, current.id)

            // Atomically replace old configurations with new ones (single StateFlow emission)
            configRepository.replaceBySubscription(current.id, newConfigs)
        }

        // Preserve old metadata when new values are null and respect
        // user-customized names.
        val updated = current.copy(
            lastUpdate = System.currentTimeMillis(),
            name = if (current.isNameCustomized) current.name
                   else (result.name ?: current.name),
            upload = result.upload ?: current.upload,
            download = result.download ?: current.download,
            total = result.total ?: current.total,
            expire = result.expire ?: current.expire,
            // A panel that stops announcing has nothing to say any more.
            announce = result.panel.announce,
            supportUrl = result.panel.supportUrl ?: current.supportUrl,
            webPageUrl = result.panel.webPageUrl ?: current.webPageUrl,
            updateIntervalHours = result.panel.updateIntervalHours ?: current.updateIntervalHours
        )
        subscriptionRepository.update(updated)
        return updated
    }

    /** What identifies a server across a refresh, independent of its name. */
    internal fun endpointKey(config: ProxyConfiguration): String =
        listOf(
            config.outboundProtocol.name,
            config.serverAddress.lowercase(),
            config.serverPort.toString(),
            // Only the protocols that authenticate by uuid carry a real one;
            // the parsers fill in a fresh random placeholder for the rest, so
            // keying on it there would make every refresh look like a new
            // server and drop the ids a rename was meant to keep.
            when (config.outboundProtocol) {
                OutboundProtocol.VLESS, OutboundProtocol.VMESS, OutboundProtocol.TUIC -> config.uuid.toString()
                else -> ""
            },
            config.password ?: "",
            config.ssPassword ?: "",
            config.trojanPassword ?: "",
            config.socks5Username ?: "",
            config.naiveUsername ?: ""
        ).joinToString("|")

    internal fun preserveIds(
        oldConfigs: List<ProxyConfiguration>,
        fetched: List<ProxyConfiguration>,
        subscriptionId: java.util.UUID
    ): List<ProxyConfiguration> {
        // Old configs are tracked by their index. This used to keep a List of
        // the unclaimed ones and ask `in` and `remove` of it for every
        // server, comparing whole data classes each time: ~2x10^8 equals
        // calls for 10,000 servers, which froze the app after a refresh. The
        // maps below answer the same questions in constant time and pair
        // every server with exactly the old config the List did.
        //
        // `remove` took out the first config *equal* to the match, which for
        // two identical records need not be the match itself. So each set of
        // equal configs keeps the indices of its unclaimed members in list
        // order, and claiming one takes the first of them.
        val equalSets = HashMap<ProxyConfiguration, ArrayDeque<Int>>()
        val unclaimedEqual = Array(oldConfigs.size) { i ->
            equalSets.getOrPut(oldConfigs[i]) { ArrayDeque() }.apply { addLast(i) }
        }
        val claimed = BooleanArray(oldConfigs.size)

        val byEndpoint = HashMap<String, EndpointGroup>()
        oldConfigs.forEachIndexed { i, old -> byEndpoint.getOrPut(endpointKey(old)) { EndpointGroup() }.members += i }

        // Pass 1: same endpoint, the first member of the group that is still
        // unclaimed (or has an identical twin that is). Pass 1 only ever
        // claims, so a member that fails that test fails it for good and the
        // search can resume where it last stopped.
        val assigned = IntArray(fetched.size) { -1 }
        fetched.forEachIndexed { index, fresh ->
            val group = byEndpoint[endpointKey(fresh)] ?: return@forEachIndexed
            while (group.next < group.members.size && unclaimedEqual[group.members[group.next]].isEmpty()) group.next++
            val match = group.members.getOrNull(group.next) ?: return@forEachIndexed
            claimed[unclaimedEqual[match].removeFirst()] = true
            assigned[index] = match
        }

        // Pass 2: same name, among whatever is still unclaimed.
        val byName = HashMap<String, ArrayDeque<Int>>()
        for (i in oldConfigs.indices) {
            if (!claimed[i]) byName.getOrPut(oldConfigs[i].name) { ArrayDeque() }.addLast(i)
        }
        fetched.forEachIndexed { index, fresh ->
            if (assigned[index] >= 0) return@forEachIndexed
            assigned[index] = byName[fresh.name]?.removeFirstOrNull() ?: return@forEachIndexed
        }

        return fetched.mapIndexed { index, fresh ->
            val match = assigned[index]
            fresh.copy(id = if (match >= 0) oldConfigs[match].id else fresh.id, subscriptionId = subscriptionId)
        }
    }

    /** Old configs sharing an endpoint, in list order, and where pass 1 resumes. */
    private class EndpointGroup {
        val members = ArrayList<Int>()
        var next = 0
    }
}
