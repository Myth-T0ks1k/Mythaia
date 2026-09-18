package com.mythaia.data.repository

import android.content.Context
import com.mythaia.data.model.Subscription
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

class SubscriptionRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "subscriptions.json")

    private val _subscriptions = MutableStateFlow<List<Subscription>>(emptyList())
    val subscriptions: StateFlow<List<Subscription>> = _subscriptions.asStateFlow()

    init {
        _subscriptions.value = loadFromDisk()
    }

    fun getAll(): List<Subscription> = _subscriptions.value

    fun get(id: UUID): Subscription? = _subscriptions.value.find { it.id == id }

    fun add(subscription: Subscription) {
        _subscriptions.update { it + subscription }
        saveToDisk()
    }

    /** Replaces the stored record; a no-op if it was deleted meanwhile. */
    fun update(subscription: Subscription) {
        _subscriptions.update { list ->
            list.map { if (it.id == subscription.id) subscription else it }
        }
        saveToDisk()
    }

    fun delete(subscriptionId: UUID, configRepository: ConfigRepository) {
        configRepository.deleteBySubscription(subscriptionId)
        _subscriptions.update { list -> list.filter { it.id != subscriptionId } }
        saveToDisk()
    }

    private fun loadFromDisk(): List<Subscription> {
        if (!file.exists()) return emptyList()
        return runCatching {
            json.decodeFromString<List<Subscription>>(file.readText())
        }.getOrElse {
            com.mythaia.vpn.util.MythaiaLogger("SubscriptionStore")
                .error("Failed to load subscriptions: $it")
            file.quarantineCorrupt()
            emptyList()
        }
    }

    private fun saveToDisk() {
        val payload = json.encodeToString(_subscriptions.value)
        file.writeTextAsync(payload) {
            com.mythaia.vpn.util.MythaiaLogger("SubscriptionStore")
                .error("Failed to save subscriptions: $it")
        }
    }

    companion object {
        @Volatile
        private var instance: SubscriptionRepository? = null

        /**
         * The one instance for this process.
         *
         * The background refresh worker and the view model both mutate this
         * store. With an instance each they would hold two snapshots of the
         * same file and two independent StateFlows: whichever wrote last would
         * silently overwrite the other's edits, and the UI would not see what
         * the worker had written. Sharing one instance makes a background
         * refresh land in the running UI as well.
         */
        fun get(context: Context): SubscriptionRepository =
            instance ?: synchronized(this) {
                instance ?: SubscriptionRepository(context.applicationContext).also { instance = it }
            }
    }
}
