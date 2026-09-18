package com.mythaia.data.repository

import android.content.Context
import com.mythaia.data.model.ProxyConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import java.io.File
import java.util.UUID

private val logger = com.mythaia.vpn.util.MythaiaLogger("ConfigStore")

class ConfigRepository(context: Context) {
    private val json = Json { prettyPrint = true; ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "configurations.json")

    private val _configurations = MutableStateFlow<List<ProxyConfiguration>>(emptyList())
    val configurations: StateFlow<List<ProxyConfiguration>> = _configurations.asStateFlow()

    /**
     * Entries on disk this build could not decode — typically a server whose
     * protocol was added by a newer version. Carried through every save so a
     * downgrade does not erase them.
     */
    private var undecodable: List<JsonElement> = emptyList()

    init {
        _configurations.value = loadFromDisk()
    }

    fun getAll(): List<ProxyConfiguration> = _configurations.value

    fun get(id: UUID): ProxyConfiguration? = _configurations.value.find { it.id == id }

    // Every mutation goes through update {} (a CAS loop): the background
    // refresh worker and the UI both write here, and a plain read-then-assign
    // would let one of them drop the other's change.

    fun add(config: ProxyConfiguration) {
        _configurations.update { it + config }
        saveToDisk()
    }

    /** Adds many at once: one emission and one disk write instead of N. */
    fun addAll(configs: List<ProxyConfiguration>) {
        if (configs.isEmpty()) return
        _configurations.update { it + configs }
        saveToDisk()
    }

    fun update(config: ProxyConfiguration) {
        _configurations.update { list ->
            list.map { if (it.id == config.id) config else it }
        }
        saveToDisk()
    }

    fun delete(id: UUID) {
        _configurations.update { list -> list.filter { it.id != id } }
        saveToDisk()
    }

    fun deleteBySubscription(subscriptionId: UUID) {
        _configurations.update { list -> list.filter { it.subscriptionId != subscriptionId } }
        saveToDisk()
    }

    fun replaceBySubscription(subscriptionId: UUID, newConfigs: List<ProxyConfiguration>) {
        _configurations.update { list ->
            list.filter { it.subscriptionId != subscriptionId } + newConfigs
        }
        saveToDisk()
    }

    /**
     * Decodes the configuration list element-by-element, dropping entries that
     * fail to decode, so an unrecognized entry — e.g. a saved configuration
     * referencing a removed `outboundProtocol` — is skipped instead of
     * corrupting the entire list.
     */
    private fun loadFromDisk(): List<ProxyConfiguration> {
        if (!file.exists()) return emptyList()
        return runCatching {
            val array = json.parseToJsonElement(file.readText()).jsonArray
            val kept = mutableListOf<JsonElement>()
            val decoded = array.mapNotNull { element ->
                runCatching {
                    json.decodeFromJsonElement<ProxyConfiguration>(element)
                }.getOrElse {
                    logger.warning("Keeping an undecodable configuration entry: ${it.message ?: it}")
                    kept.add(element)
                    null
                }
            }
            undecodable = kept
            decoded
        }.getOrElse {
            // Not a JSON array at all. Set the file aside instead of letting
            // the next save replace whatever was in it with an empty list.
            logger.error("Failed to load configurations: $it")
            file.quarantineCorrupt()
            emptyList()
        }
    }

    private fun saveToDisk() {
        // Snapshot here so an in-flight write doesn't observe a later mutation.
        // Mirrors iOS `Task.detached { try data.write(to: url, options: .atomic) }`.
        val decoded = json.encodeToJsonElement(_configurations.value).jsonArray
        val payload = json.encodeToString(JsonArray.serializer(), JsonArray(decoded + undecodable))
        file.writeTextAsync(payload) {
            logger.error("Failed to save configurations: $it")
        }
    }

    companion object {
        @Volatile
        private var instance: ConfigRepository? = null

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
        fun get(context: Context): ConfigRepository =
            instance ?: synchronized(this) {
                instance ?: ConfigRepository(context.applicationContext).also { instance = it }
            }
    }
}
