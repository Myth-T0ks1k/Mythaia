package com.mythaia.data.repository

import android.content.Context
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.routing.GeoFileStore
import com.mythaia.data.routing.HappRouting
import com.mythaia.data.routing.RoutingProfile
import com.mythaia.data.routing.RoutingProfiles
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import java.io.File

/**
 * The Happ routing profiles: which there are, which one is in force, and
 * their geosite/geoip files under `files/geo`.
 *
 * Every change rewrites routing.json, which embeds the profile in force and
 * the paths of its files, so the running tunnel picks it up the way it picks
 * up any rule change. The transitions themselves are [RoutingProfiles]'.
 */
class RoutingProfileRepository private constructor(private val context: Context) {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = false }
    private val file = File(context.filesDir, "routing_profiles.json")
    val files = GeoFileStore(File(context.filesDir, "geo"))

    private val _state = MutableStateFlow(load())
    val state: StateFlow<RoutingProfiles> = _state.asStateFlow()

    /** The profile whose files are being fetched; null when none is. */
    private val _fetching = MutableStateFlow<String?>(null)
    val fetching: StateFlow<String?> = _fetching.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val fetchLock = Mutex()

    /** The servers to fetch files through when a direct fetch fails; set by the view model. */
    @Volatile
    var servers: (suspend () -> List<ProxyConfiguration>)? = null

    /** A link opened, pasted or sent by a subscription ([source]). */
    fun handle(command: HappRouting.Command, source: RoutingProfiles.Source? = null) {
        val now = System.currentTimeMillis()
        change { it.apply(command, now, files::ready, source) }
        if (command is HappRouting.Command.Add) fetchInBackground(command.profile.name, force = false)
    }

    fun activate(name: String) {
        change { it.activate(name, files::ready) }
        fetchInBackground(name, force = false)
    }

    fun off() = change { it.off() }

    fun remove(name: String) {
        change { it.remove(name) }
        files.prune(_state.value.fileUrls)
    }

    /** Forgets what a deleted subscription sent. */
    fun removeFrom(subscriptionId: String) {
        if (_state.value.entries.none { it.subscriptionId == subscriptionId }) return
        change { it.removeFrom(subscriptionId) }
        files.prune(_state.value.fileUrls)
    }

    /** Fetches [name]'s files now, even if they failed within the hour. */
    fun retry(name: String) = fetchInBackground(name, force = true)

    /** The profile in force with its files, for routing.json; null when none is. */
    fun activeRouting(): Triple<RoutingProfile, File?, File?>? {
        val entry = _state.value.activeEntry ?: return null
        return Triple(entry.profile, files.geosite(entry.profile), files.geoip(entry.profile))
    }

    /**
     * Fetches the files of every profile that is in force or waiting and due:
     * weekly, or sooner when its `LastUpdated` moved. For the background
     * refresh and the app's start.
     */
    suspend fun refreshDue() {
        val state = _state.value
        val now = System.currentTimeMillis()
        for (entry in listOfNotNull(state.activeEntry, state.pendingEntry)) {
            if (state.filesDue(entry, now)) fetch(entry.name, force = false)
        }
    }

    private fun fetchInBackground(name: String, force: Boolean) {
        scope.launch { fetch(name, force) }
    }

    private suspend fun fetch(name: String, force: Boolean) = fetchLock.withLock {
        val state = _state.value
        val entry = state.find(name) ?: return@withLock
        // Only what will be used: a profile merely added is fetched when turned on.
        val wanted = state.active.equals(entry.name, ignoreCase = true) || state.pending.equals(entry.name, ignoreCase = true)
        if (!wanted || !state.filesDue(entry, System.currentTimeMillis(), force)) return@withLock
        _fetching.value = entry.name
        try {
            val error = files.fetch(entry.profile) { servers?.invoke().orEmpty() }
            change { it.filesFetched(entry.name, System.currentTimeMillis(), error) }
            if (error == null) files.prune(_state.value.fileUrls)
            else logger.warning("[Routing] Files for ${entry.name}: $error")
        } finally {
            _fetching.value = null
        }
    }

    private fun change(transform: (RoutingProfiles) -> RoutingProfiles) {
        val before = _state.value
        _state.update(transform)
        val after = _state.value
        if (after == before) return
        save(after)
        // routing.json embeds the profile in force; files fetched for a
        // profile in force change what it matches too.
        if (before.activeEntry != after.activeEntry) syncRouting()
    }

    /** Rewrites routing.json, which also tells a running tunnel to reload. */
    fun syncRouting() {
        scope.launch {
            runCatching {
                RuleSetRepository(context).syncRoutingFile(ConfigRepository.get(context).getAll()) { host ->
                    DnsCache.resolveHost(host)
                }
            }.onFailure { logger.warning("[Routing] Routing sync failed: ${it.message ?: it}") }
        }
    }

    private fun load(): RoutingProfiles {
        if (!file.exists()) return RoutingProfiles()
        return runCatching { json.decodeFromString(RoutingProfiles.serializer(), file.readText()) }
            .getOrElse {
                logger.error("Failed to load routing profiles: $it")
                file.quarantineCorrupt()
                RoutingProfiles()
            }
    }

    private fun save(state: RoutingProfiles) {
        file.writeTextAsync(json.encodeToString(RoutingProfiles.serializer(), state)) {
            logger.error("Failed to save routing profiles: $it")
        }
    }

    companion object {
        private val logger = MythaiaLogger("Routing")

        @Volatile
        private var instance: RoutingProfileRepository? = null

        fun get(context: Context): RoutingProfileRepository =
            instance ?: synchronized(this) {
                instance ?: RoutingProfileRepository(context.applicationContext).also { instance = it }
            }
    }
}
