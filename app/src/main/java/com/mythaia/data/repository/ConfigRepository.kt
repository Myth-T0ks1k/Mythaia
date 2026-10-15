package com.mythaia.data.repository

import android.content.Context
import com.mythaia.data.model.ProxyConfiguration
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.builtins.ListSerializer
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
    // Compact: pretty-printing made a 10,000-server store several times
    // larger to write, read and hold in memory. Older pretty files still load.
    private val json = Json { ignoreUnknownKeys = true }
    private val file = File(context.filesDir, "configurations.json")

    private val _configurations = MutableStateFlow<List<ProxyConfiguration>>(emptyList())
    val configurations: StateFlow<List<ProxyConfiguration>> = _configurations.asStateFlow()

    /**
     * Entries on disk this build could not decode — typically a server whose
     * protocol was added by a newer version. Carried through every save so a
     * downgrade does not erase them.
     */
    private var undecodable: List<JsonElement> = emptyList()

    /** Set by loadFromDisk when the file on disk is in the old pretty-printed form. */
    private var rewriteCompact = false

    /** Set while a save is queued; mutations meanwhile ride on it. */
    private val saveQueued = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * The list indexed by id, rebuilt only when the list changes: get() is
     * called per result and per frame, and a scan of thousands of servers
     * each time added up to seconds on the main thread.
     */
    @Volatile
    private var index: Pair<List<ProxyConfiguration>, Map<UUID, ProxyConfiguration>>? = null

    // After every field it uses: init may queue a save (see rewriteCompact),
    // and a field declared below this block would still be null then.
    init {
        _configurations.value = loadFromDisk()
        if (rewriteCompact) saveToDisk()
    }

    fun getAll(): List<ProxyConfiguration> = _configurations.value

    fun get(id: UUID): ProxyConfiguration? {
        val list = _configurations.value
        val cached = index
        val byId = if (cached != null && cached.first === list) cached.second
        else list.associateBy { it.id }.also { index = list to it }
        return byId[id]
    }

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

    /** Removes many at once: one emission and one disk write instead of N. */
    fun deleteAll(ids: Set<UUID>) {
        if (ids.isEmpty()) return
        _configurations.update { list -> list.filter { it.id !in ids } }
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
        val text = runCatching { file.readText() }.getOrElse {
            logger.error("Failed to read configurations: $it")
            return emptyList()
        }
        // One streaming pass when every entry decodes, which is nearly
        // always: building the JSON tree first and decoding each element
        // from it cost twice as much, and this runs while the app starts
        // (seconds with 10,000 servers). The slower path below is only for
        // a file holding entries this build cannot read.
        runCatching { json.decodeFromString(ListSerializer(ProxyConfiguration.serializer()), text) }
            .getOrNull()
            ?.let {
                undecodable = emptyList()
                // Written pretty by builds before 1.0.2: rewrite it compact once.
                rewriteCompact = text.length > 1 && text[1] == '\n'
                return it
            }
        return runCatching {
            val array = json.parseToJsonElement(text).jsonArray
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

    /**
     * Writes the store on the writer thread.
     *
     * Serialising thousands of servers takes seconds, and it used to run on
     * the caller's thread, usually the main one, once per change: a pasted
     * list of 5,000 links meant 5,000 full serialisations and froze the app.
     * A change now only queues a save; the save takes the latest snapshot
     * when it runs, so a burst of changes costs one serialisation. The
     * writer runs one job at a time, in order, so a newer snapshot is never
     * overwritten by an older one.
     */
    private fun saveToDisk() {
        if (!saveQueued.compareAndSet(false, true)) return
        launchOnRepositoryWriter {
            saveQueued.set(false)
            try {
                val decoded = json.encodeToJsonElement(_configurations.value).jsonArray
                val payload = json.encodeToString(JsonArray.serializer(), JsonArray(decoded + undecodable))
                file.writeTextAtomic(payload)
            } catch (e: Throwable) {
                logger.error("Failed to save configurations: $e")
            }
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
