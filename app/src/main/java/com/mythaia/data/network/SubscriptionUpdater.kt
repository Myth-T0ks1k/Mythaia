package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.data.repository.SubscriptionRepository

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

        // Keep the IDs of servers already present: rule-set assignments,
        // chains and the saved selection all point at them. Matched first by
        // endpoint (a panel that renames a server keeps its address), then by
        // name, positionally within a group of duplicates.
        val oldConfigs = configRepository.getAll().filter { it.subscriptionId == current.id }
        val newConfigs = preserveIds(oldConfigs, result.configurations, current.id)

        // Atomically replace old configurations with new ones (single StateFlow emission)
        configRepository.replaceBySubscription(current.id, newConfigs)

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
    private fun endpointKey(config: ProxyConfiguration): String =
        listOf(
            config.outboundProtocol.name,
            config.serverAddress.lowercase(),
            config.serverPort.toString(),
            config.uuid.toString(),
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
        val unclaimed = oldConfigs.toMutableList()

        val byEndpoint = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (old in oldConfigs) byEndpoint.getOrPut(endpointKey(old)) { mutableListOf() }.add(old)

        // Pass 1: same endpoint.
        val assigned = arrayOfNulls<ProxyConfiguration>(fetched.size)
        fetched.forEachIndexed { index, fresh ->
            val group = byEndpoint[endpointKey(fresh)] ?: return@forEachIndexed
            val match = group.firstOrNull { it in unclaimed } ?: return@forEachIndexed
            unclaimed.remove(match)
            assigned[index] = match
        }

        // Pass 2: same name, among whatever is still unclaimed.
        val byName = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (old in unclaimed) byName.getOrPut(old.name) { mutableListOf() }.add(old)
        fetched.forEachIndexed { index, fresh ->
            if (assigned[index] != null) return@forEachIndexed
            val group = byName[fresh.name] ?: return@forEachIndexed
            if (group.isEmpty()) return@forEachIndexed
            val match = group.removeAt(0)
            unclaimed.remove(match)
            assigned[index] = match
        }

        return fetched.mapIndexed { index, fresh ->
            fresh.copy(id = assigned[index]?.id ?: fresh.id, subscriptionId = subscriptionId)
        }
    }
}
