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
        val result = SubscriptionFetcher.fetch(subscription.url, remnawaveHWID = remnawaveHWID)

        // Match new configurations against old ones by name to preserve IDs (and
        // routing rules). When several configs share a name, they are matched
        // positionally within that group.
        val oldConfigs = configRepository.getAll().filter { it.subscriptionId == subscription.id }

        val oldByName = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (old in oldConfigs) {
            oldByName.getOrPut(old.name) { mutableListOf() }.add(old)
        }
        val oldNameCursor = mutableMapOf<String, Int>()

        val newConfigs = result.configurations.map { newConfig ->
            val name = newConfig.name
            val cursor = oldNameCursor.getOrDefault(name, 0)
            val group = oldByName[name]
            val id = if (group != null && cursor < group.size) {
                oldNameCursor[name] = cursor + 1
                group[cursor].id
            } else {
                newConfig.id
            }
            newConfig.copy(id = id, subscriptionId = subscription.id)
        }

        // Atomically replace old configurations with new ones (single StateFlow emission)
        configRepository.replaceBySubscription(subscription.id, newConfigs)

        // Preserve old metadata when new values are null and respect
        // user-customized names.
        val updated = subscription.copy(
            lastUpdate = System.currentTimeMillis(),
            name = if (subscription.isNameCustomized) subscription.name
                   else (result.name ?: subscription.name),
            upload = result.upload ?: subscription.upload,
            download = result.download ?: subscription.download,
            total = result.total ?: subscription.total,
            expire = result.expire ?: subscription.expire
        )
        subscriptionRepository.update(updated)
        return updated
    }
}
