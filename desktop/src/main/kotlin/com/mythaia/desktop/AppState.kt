package com.mythaia.desktop

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.desktop.engine.LaunchAtLogin
import com.mythaia.desktop.engine.ProxyEngine
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.store.DesktopStore
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.DnsUpstream
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.GeoIpDatabase
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.util.UUID

/** What the connect button is doing. */
sealed class ConnectionState {
    /** The server in use, while connecting or connected. */
    abstract val configuration: ProxyConfiguration?

    data object Disconnected : ConnectionState() {
        override val configuration: ProxyConfiguration? get() = null
    }

    data class Connecting(override val configuration: ProxyConfiguration) : ConnectionState()
    data class Connected(override val configuration: ProxyConfiguration) : ConnectionState()

    data class Failed(val message: String) : ConnectionState() {
        override val configuration: ProxyConfiguration? get() = null
    }
}

/** One line of the in-app log. */
data class LogLine(val time: Long, val level: MythaiaLogger.Level, val text: String)

/** A server list: the manual servers, or one subscription. */
data class ServerGroup(val id: String, val name: String, val subscription: Subscription?)

/** Bytes per second in each direction, sampled once a second. */
data class Speed(val up: Long, val down: Long)

/**
 * The application state: the lists, the settings, the connection and Auto.
 * Compose reads the flows; every mutation goes through here and is saved.
 *
 * The persisted lists are changed only under [stateLock] with a
 * read-modify-write, so two subscription refreshes, or a refresh and a
 * delete, cannot lose each other's work.
 */
class AppState(private val store: DesktopStore, val nativeAvailable: Boolean) {
    private val logger = MythaiaLogger("App")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val stats = TrafficStats()
    val engine = ProxyEngine(stats)

    private val stateLock = Any()

    private val _settings = MutableStateFlow(store.loadSettings())
    val settings: StateFlow<DesktopSettings> = _settings.asStateFlow()

    private val _configurations = MutableStateFlow(store.loadConfigurations())
    val configurations: StateFlow<List<ProxyConfiguration>> = _configurations.asStateFlow()

    private val _subscriptions = MutableStateFlow(store.loadSubscriptions())
    val subscriptions: StateFlow<List<Subscription>> = _subscriptions.asStateFlow()

    private val _rules = MutableStateFlow(store.loadRules())
    val rules: StateFlow<List<RouteRule>> = _rules.asStateFlow()

    private val _chains = MutableStateFlow(store.loadChains())
    val chains: StateFlow<List<com.mythaia.data.model.ProxyChain>> = _chains.asStateFlow()

    private val _connection = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connection: StateFlow<ConnectionState> = _connection.asStateFlow()

    /** What the list shows: the last measurement of any kind. */
    private val _latencies = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val latencies: StateFlow<Map<UUID, LatencyResult>> = _latencies.asStateFlow()

    /** What Auto ranks by: real (HTTP) pings only, never a TCP number. */
    private val httpLatencies = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())

    private val _connectivityOk = MutableStateFlow(true)
    val connectivityOk: StateFlow<Boolean> = _connectivityOk.asStateFlow()

    private val _connectedSince = MutableStateFlow<Long?>(null)
    val connectedSince: StateFlow<Long?> = _connectedSince.asStateFlow()

    private val _updating = MutableStateFlow<Set<UUID>>(emptySet())
    val updating: StateFlow<Set<UUID>> = _updating.asStateFlow()

    private val _message = MutableStateFlow<String?>(null)
    val message: StateFlow<String?> = _message.asStateFlow()

    private val _logs = MutableStateFlow<List<LogLine>>(emptyList())
    val logs: StateFlow<List<LogLine>> = _logs.asStateFlow()

    private val _speed = MutableStateFlow(Speed(0, 0))
    val speed: StateFlow<Speed> = _speed.asStateFlow()

    /** True while a text field has focus, so window shortcuts leave typing alone. */
    val textFieldFocused = MutableStateFlow(false)

    /** Set when the window should come to the front (tray "show", second instance). */
    val windowVisible = MutableStateFlow(true)
    val bringToFront = MutableStateFlow(0L)

    private var autoJob: Job? = null
    private var probeJob: Job? = null
    private var pingJob: Job? = null
    private val connectLock = Mutex()
    private val autoRoundLock = Mutex()
    private var messageJob: Job? = null

    /** Set once Auto has measured the group at least once since the last connect. */
    @Volatile
    private var autoMeasuredOnce = false

    @Volatile
    private var probeFailures = 0

    init {
        MythaiaLogger.logSink = { text, level ->
            _logs.update { lines ->
                (lines + LogLine(System.currentTimeMillis(), level, text)).takeLast(MAX_LOG_LINES)
            }
        }
        applyPolicies(_settings.value)
        engine.updateRouting(_rules.value, _settings.value)
        GeoIpDatabase.load(AppPaths.geoIp)
        S.apply(_settings.value.language)
        // Sanity: a pin or an Auto choice may point at a server that is gone.
        pruneSelection()
        scope.launch { speedLoop() }
        scope.launch { subscriptionRefreshLoop() }
    }

    // ------------------------------------------------------------- groups

    fun groups(): List<ServerGroup> = buildList {
        add(ServerGroup(DEFAULT_GROUP, tr("group_default"), null))
        _subscriptions.value.forEach { add(ServerGroup(it.id.toString(), it.name, it)) }
    }

    fun groupIdOf(config: ProxyConfiguration): String = config.subscriptionId?.toString() ?: DEFAULT_GROUP

    fun groupConfigs(groupId: String): List<ProxyConfiguration> =
        _configurations.value.filter { groupIdOf(it) == groupId }

    val activeGroupId: String get() = _settings.value.activeGroupId

    fun isAuto(groupId: String): Boolean = _settings.value.groupPins[groupId] == null

    fun pinned(groupId: String): ProxyConfiguration? {
        val id = _settings.value.groupPins[groupId] ?: return null
        return _configurations.value.firstOrNull { it.id.toString() == id }
    }

    fun autoChoice(groupId: String): ProxyConfiguration? {
        val id = _settings.value.autoChoices[groupId] ?: return null
        return _configurations.value.firstOrNull { it.id.toString() == id && groupIdOf(it) == groupId }
    }

    /** The chain chosen as outbound, resolved to its exit with the hops before it; null when none or broken. */
    fun selectedChain(): ProxyConfiguration? {
        val id = _settings.value.selectedChainId ?: return null
        val chain = _chains.value.firstOrNull { it.id.toString() == id } ?: return null
        return resolveChain(chain)
    }

    fun resolveChain(chain: com.mythaia.data.model.ProxyChain): ProxyConfiguration? {
        val byId = _configurations.value.associateBy { it.id }
        val hops = chain.proxyIds.mapNotNull { byId[it] }
        if (hops.size != chain.proxyIds.size || hops.size < 2) return null
        if (!nativeAvailable && hops.any { it.outboundProtocol.needsNative() }) return null
        return hops.last().copy(name = chain.name, chain = hops.dropLast(1))
    }

    /** The server the group would connect with right now (a selected chain wins). */
    fun effectiveConfig(groupId: String): ProxyConfiguration? {
        selectedChain()?.let { return it }
        pinned(groupId)?.let { return it }
        val configs = dialable(groupConfigs(groupId))
        if (configs.isEmpty()) return null
        autoChoice(groupId)?.takeIf { it in configs }?.let { return it }
        return bestKnown(configs) ?: configs.first()
    }

    /** Without the native library the QUIC protocols cannot be dialled at all. */
    private fun dialable(configs: List<ProxyConfiguration>): List<ProxyConfiguration> =
        if (nativeAvailable) configs else configs.filterNot { it.outboundProtocol.needsNative() }

    private fun bestKnown(configs: List<ProxyConfiguration>): ProxyConfiguration? {
        val known = httpLatencies.value
        return configs.mapNotNull { c -> (known[c.id] as? LatencyResult.Success)?.let { c to it.ms } }
            .minByOrNull { it.second }?.first
    }

    fun selectGroup(groupId: String) {
        if (groupId == activeGroupId && _settings.value.selectedChainId == null) return
        mutateSettings { it.copy(activeGroupId = groupId, selectedChainId = null) }
        reconnectIfNeeded()
    }

    /** Pins one server for its group and makes that group active; a chosen chain is dropped. */
    fun pin(config: ProxyConfiguration) {
        val gid = groupIdOf(config)
        mutateSettings { it.copy(activeGroupId = gid, groupPins = it.groupPins + (gid to config.id.toString()), selectedChainId = null) }
        reconnectIfNeeded()
    }

    fun useAuto(groupId: String) {
        mutateSettings { it.copy(activeGroupId = groupId, groupPins = it.groupPins - groupId, selectedChainId = null) }
        reconnectIfNeeded()
    }

    // -------------------------------------------------------------- chains

    fun selectChain(chain: com.mythaia.data.model.ProxyChain?) {
        mutateSettings { it.copy(selectedChainId = chain?.id?.toString()) }
        reconnectIfNeeded()
    }

    fun saveChain(chain: com.mythaia.data.model.ProxyChain) {
        mutateChains { list -> if (list.any { it.id == chain.id }) list.map { if (it.id == chain.id) chain else it } else list + chain }
        if (_settings.value.selectedChainId == chain.id.toString()) reconnectIfNeeded()
    }

    fun deleteChain(id: UUID) {
        mutateChains { list -> list.filterNot { it.id == id } }
        if (_settings.value.selectedChainId == id.toString()) {
            mutateSettings { it.copy(selectedChainId = null) }
            reconnectIfNeeded()
        }
    }

    private fun mutateChains(transform: (List<com.mythaia.data.model.ProxyChain>) -> List<com.mythaia.data.model.ProxyChain>) {
        synchronized(stateLock) {
            val next = transform(_chains.value)
            _chains.value = next
            store.saveChains(next)
        }
    }

    // ----------------------------------------------------------- clipboard

    /** Imports whatever the clipboard holds: links, JSON or a subscription URL. */
    fun importFromClipboard() {
        val text = runCatching {
            java.awt.Toolkit.getDefaultToolkit().systemClipboard.getData(java.awt.datatransfer.DataFlavor.stringFlavor) as? String
        }.getOrNull()
        if (text.isNullOrBlank()) { notify(tr("clipboard_empty")); return }
        addText(text)
    }

    /** Reads every QR code on the screens and imports what they say. */
    fun importFromScreen() {
        scope.launch {
            val codes = runCatching { com.mythaia.desktop.util.Qr.scanScreens() }.getOrDefault(emptyList())
            if (codes.isEmpty()) notify(tr("no_qr_found")) else addText(codes.joinToString("\n"))
        }
    }

    fun copyToClipboard(text: String) {
        runCatching {
            java.awt.Toolkit.getDefaultToolkit().systemClipboard.setContents(java.awt.datatransfer.StringSelection(text), null)
        }
        notify(tr("copied"))
    }

    /** Links of [configs], one per line, for a subscription-style share. */
    fun linksOf(configs: List<ProxyConfiguration>): String =
        configs.mapNotNull { runCatching { it.toUrl() }.getOrNull() }.joinToString("\n")

    private fun reconnectIfNeeded() {
        if (!engine.isRunning) return
        scope.launch { startConnection() }
    }

    private fun pruneSelection() {
        val ids = _configurations.value.map { it.id.toString() }.toSet()
        val groupIds = groups().map { it.id }.toSet()
        val chainIds = _chains.value.map { it.id.toString() }.toSet()
        mutateSettings { s ->
            val pins = s.groupPins.filterValues { it in ids }
            val choices = s.autoChoices.filterValues { it in ids }
            val active = if (s.activeGroupId in groupIds) s.activeGroupId else DEFAULT_GROUP
            val chain = s.selectedChainId?.takeIf { it in chainIds }
            if (pins == s.groupPins && choices == s.autoChoices && active == s.activeGroupId && chain == s.selectedChainId) s
            else s.copy(groupPins = pins, autoChoices = choices, activeGroupId = active, selectedChainId = chain)
        }
    }

    // --------------------------------------------------------- connection

    fun toggle() {
        if (engine.isRunning || _connection.value is ConnectionState.Connecting) disconnect()
        else scope.launch { startConnection() }
    }

    fun connect() = scope.launch { startConnection() }

    private suspend fun startConnection() = connectLock.withLock {
        val gid = activeGroupId
        val previous = _connection.value
        val config = effectiveConfig(gid)
        if (config == null) {
            val reason = if (!nativeAvailable && groupConfigs(gid).isNotEmpty()) tr("native_missing") else tr("no_servers_hint")
            // A live connection is kept rather than replaced by nothing.
            if (engine.isRunning && previous is ConnectionState.Connected) {
                notify(reason)
                return@withLock
            }
            _connection.value = ConnectionState.Failed(tr("no_server"))
            notify(reason)
            return@withLock
        }
        if (!nativeAvailable && config.outboundProtocol.needsNative()) {
            if (engine.isRunning && previous is ConnectionState.Connected) {
                notify(tr("no_native_for", config.name))
                return@withLock
            }
            _connection.value = ConnectionState.Failed(tr("native_missing"))
            return@withLock
        }
        val wasRunning = engine.isRunning
        _connection.value = ConnectionState.Connecting(config)
        try {
            engine.updateRouting(_rules.value, _settings.value)
            engine.start(_settings.value, config)
        } catch (e: IOException) {
            logger.error("Start failed: ${e.message}")
            val port = _settings.value.socksPort
            _connection.value = ConnectionState.Failed(
                if (e is java.net.BindException) tr("port_in_use", port) else (e.message ?: tr("failed"))
            )
            engine.stop()
            return@withLock
        }
        if (!wasRunning) _connectedSince.value = System.currentTimeMillis()
        _connection.value = ConnectionState.Connected(config)
        _connectivityOk.value = true
        autoMeasuredOnce = false
        restartBackgroundJobs(gid)
    }

    /** Stops under the connect lock so a connect in flight cannot resurrect the listeners. */
    fun disconnect() {
        scope.launch { connectLock.withLock { disconnectLocked() } }
    }

    private fun disconnectLocked() {
        autoJob?.cancel(); autoJob = null
        probeJob?.cancel(); probeJob = null
        engine.stop()
        _connection.value = ConnectionState.Disconnected
        _connectedSince.value = null
        _connectivityOk.value = true
    }

    /** Called from the exit path: puts the system back the way it was. */
    fun shutdown() {
        runCatching {
            runBlocking {
                withTimeoutOrNull(5_000) { connectLock.withLock { disconnectLocked() } } ?: disconnectLocked()
            }
        }
        scope.cancel()
    }

    private fun restartBackgroundJobs(groupId: String) {
        autoJob?.cancel()
        probeJob?.cancel()
        autoJob = if (isAuto(groupId) && _settings.value.selectedChainId == null) scope.launch { autoLoop(groupId) } else null
        probeJob = scope.launch { probeLoop() }
    }

    /**
     * Auto: measure the group now and every two minutes, moving to the best
     * server as results come in on the first round, so the first good one is
     * used within seconds; later rounds only move away from a server that is
     * measured slower or failed.
     */
    private suspend fun autoLoop(groupId: String) {
        delay(AUTO_FIRST_ROUND_DELAY_MS)
        while (scope.isActive) {
            runAutoRound(groupId)
            delay(AUTO_RECHECK_MS)
        }
    }

    private suspend fun runAutoRound(groupId: String) {
        if (!autoRoundLock.tryLock()) return
        try {
            val configs = dialable(groupConfigs(groupId))
            if (configs.isEmpty()) return
            val firstRound = !autoMeasuredOnce
            _latencies.update { m -> m + configs.associate { it.id to LatencyResult.Testing } }
            var bestId: UUID? = null
            var bestMs = Int.MAX_VALUE
            val current = engine.configuration?.id
            var currentMs: Int? = null
            var currentFailed = false
            try {
                LatencyTester.testAll(configs, LatencyKind.HTTP).collect { (id, result) ->
                    _latencies.update { it + (id to result) }
                    httpLatencies.update { it + (id to result) }
                    if (id == current) {
                        currentMs = (result as? LatencyResult.Success)?.ms
                        currentFailed = result !is LatencyResult.Success
                    }
                    if (result is LatencyResult.Success && result.ms < bestMs) {
                        bestMs = result.ms
                        bestId = id
                    }
                    // Live switching: on the first round the current server is a
                    // guess, so the first good answer is worth moving to; later,
                    // only a current server known to have failed is left mid-round.
                    val best = bestId?.let { b -> configs.firstOrNull { it.id == b } }
                    if (best != null && best.id != engine.configuration?.id) {
                        val currentKnown = currentMs
                        val move = when {
                            currentFailed -> true
                            firstRound && currentKnown == null -> true
                            currentKnown != null -> bestMs + AUTO_SWITCH_MARGIN_MS < currentKnown
                            else -> false
                        }
                        if (move) switchAuto(groupId, best)
                    }
                }
            } catch (e: Throwable) {
                logger.warning("Auto round failed: ${e.message ?: e}")
                _latencies.update { m -> m + configs.filter { m[it.id] is LatencyResult.Testing }.associate { it.id to LatencyResult.Failed } }
            }
            autoMeasuredOnce = true
            val best = bestId?.let { b -> configs.firstOrNull { it.id == b } }
            if (best != null && engine.configuration?.id != best.id) {
                val currMs = (httpLatencies.value[engine.configuration?.id] as? LatencyResult.Success)?.ms
                if (currMs == null || bestMs + AUTO_SWITCH_MARGIN_MS < currMs) switchAuto(groupId, best)
            }
            if (best == null) {
                _connectivityOk.value = false
                logger.warning("Auto: no server in the group answered")
            }
        } finally {
            autoRoundLock.unlock()
        }
    }

    private fun switchAuto(groupId: String, config: ProxyConfiguration) {
        if (engine.configuration?.id == config.id) return
        engine.switchTo(config)
        _connection.value = ConnectionState.Connected(config)
        _connectivityOk.value = true
        probeFailures = 0
        mutateSettings { it.copy(autoChoices = it.autoChoices + (groupId to config.id.toString())) }
        notify(tr("auto_switching", config.name))
    }

    /** Checks the live server reaches the internet; failing that, Auto rechecks the group. */
    private suspend fun probeLoop() {
        delay(PROBE_FIRST_DELAY_MS)
        probeFailures = 0
        while (scope.isActive) {
            val config = engine.configuration
            if (config != null) {
                val result = safeTest(config, LatencyKind.HTTP)
                _latencies.update { it + (config.id to result) }
                httpLatencies.update { it + (config.id to result) }
                val ok = result is LatencyResult.Success
                if (engine.configuration?.id == config.id) _connectivityOk.value = ok
                if (!ok) {
                    probeFailures++
                    logger.warning("Probe failed for ${config.name} ($probeFailures)")
                    if (isAuto(activeGroupId)) runAutoRound(activeGroupId)
                } else {
                    probeFailures = 0
                }
            }
            delay(PROBE_INTERVAL_MS)
        }
    }

    /** A test that cannot throw: a missing native library reports Failed, not an Error. */
    private suspend fun safeTest(config: ProxyConfiguration, kind: LatencyKind): LatencyResult =
        try {
            if (!nativeAvailable && config.outboundProtocol.needsNative()) LatencyResult.Failed
            else LatencyTester.test(config, kind)
        } catch (e: Throwable) {
            logger.warning("Test of ${config.name} failed: ${e.message ?: e}")
            LatencyResult.Failed
        }

    // ---------------------------------------------------------- latency

    fun pingGroup(groupId: String, kind: LatencyKind) {
        val configs = groupConfigs(groupId)
        if (configs.isEmpty()) return
        pingJob?.cancel()
        pingJob = scope.launch {
            _latencies.update { m -> m + configs.associate { it.id to LatencyResult.Testing } }
            val (testable, skipped) = configs.partition { nativeAvailable || !it.outboundProtocol.needsNative() }
            _latencies.update { m -> m + skipped.associate { it.id to LatencyResult.Failed } }
            if (testable.isEmpty()) return@launch
            try {
                LatencyTester.testAll(testable, kind).collect { (id, result) ->
                    _latencies.update { it + (id to result) }
                    if (kind == LatencyKind.HTTP) httpLatencies.update { it + (id to result) }
                }
            } catch (e: Throwable) {
                logger.warning("Ping round failed: ${e.message ?: e}")
                _latencies.update { m -> m + testable.filter { m[it.id] is LatencyResult.Testing }.associate { it.id to LatencyResult.Failed } }
            }
        }
    }

    fun pingOne(config: ProxyConfiguration, kind: LatencyKind = LatencyKind.HTTP) {
        scope.launch {
            _latencies.update { it + (config.id to LatencyResult.Testing) }
            val result = safeTest(config, kind)
            _latencies.update { it + (config.id to result) }
            if (kind == LatencyKind.HTTP) httpLatencies.update { it + (config.id to result) }
        }
    }

    // ------------------------------------------------------------ servers

    /** Adds every link in [text]; an https:// line without credentials is a subscription; Xray JSON imports whole. */
    fun addText(text: String, subscriptionName: String? = null, frontSni: String? = null, frontTargets: List<String> = emptyList()) {
        if (com.mythaia.data.network.XrayJsonImporter.looksLikeJson(text)) {
            try {
                val imported = com.mythaia.data.network.XrayJsonImporter.parse(text).map { it.copy(subscriptionId = null) }
                mutateConfigurations { it + imported }
                notify(tr("added_n", imported.size))
            } catch (e: Exception) {
                notify(e.message ?: tr("nothing_parsed"))
            }
            return
        }
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val added = mutableListOf<ProxyConfiguration>()
        val subscriptionUrls = mutableListOf<String>()
        for (line in lines) {
            if (line.startsWith("https://", ignoreCase = true) || line.startsWith("http://", ignoreCase = true)) {
                val authority = line.substringAfter("://").substringBefore('/')
                if (!authority.contains('@')) {
                    subscriptionUrls += line
                    continue
                }
            }
            if (!ProxyConfiguration.canParseUrl(line)) continue
            runCatching { ProxyConfiguration.fromUrl(line) }
                .onSuccess { added += it.copy(subscriptionId = null) }
                .onFailure { logger.warning("Link rejected: ${it.message}") }
        }
        if (added.isNotEmpty()) {
            mutateConfigurations { it + added }
            notify(tr("added_n", added.size))
        }
        subscriptionUrls.forEach { addSubscription(it, subscriptionName, frontSni, frontTargets) }
        if (added.isEmpty() && subscriptionUrls.isEmpty()) notify(tr("nothing_parsed"))
    }

    /** Saves an edited or new server; a new one goes to the manual group. */
    fun saveConfiguration(config: ProxyConfiguration) {
        mutateConfigurations { list ->
            if (list.any { it.id == config.id }) list.map { if (it.id == config.id) config.copy(subscriptionId = it.subscriptionId) else it }
            else list + config.copy(subscriptionId = null)
        }
        if (engine.configuration?.id == config.id) reconnectIfNeeded()
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        mutateConfigurations { list -> list.filterNot { it.id == config.id } }
        pruneSelection()
        if (engine.configuration?.id == config.id) reconnectIfNeeded()
    }

    fun deleteConfigurations(ids: Set<UUID>) {
        mutateConfigurations { list -> list.filterNot { it.id in ids } }
        pruneSelection()
        if (engine.configuration?.id in ids) reconnectIfNeeded()
    }

    fun renameConfiguration(config: ProxyConfiguration, name: String) {
        mutateConfigurations { list -> list.map { if (it.id == config.id) it.copy(name = name.trim()) else it } }
    }

    /** Drops servers in [groupId] whose link repeats an earlier one. Returns how many went. */
    fun removeDuplicates(groupId: String): Int {
        var removed = 0
        mutateConfigurations { list ->
            val seen = HashSet<String>()
            list.filter { c ->
                if (groupIdOf(c) != groupId) true
                else {
                    val key = runCatching { c.toUrl().substringBefore('#') }.getOrDefault(c.id.toString())
                    if (seen.add(key)) true else { removed++; false }
                }
            }
        }
        pruneSelection()
        return removed
    }

    /** Drops servers in [groupId] whose last measurement failed. Returns how many went. */
    fun removeFailed(groupId: String): Int {
        val failed = groupConfigs(groupId).filter { _latencies.value[it.id] is LatencyResult.Failed }.map { it.id }.toSet()
        if (failed.isEmpty()) return 0
        deleteConfigurations(failed)
        return failed.size
    }

    fun addSubscription(url: String, name: String?, frontSni: String?, frontTargets: List<String>) {
        val subscription = Subscription(
            name = name?.trim()?.takeIf { it.isNotEmpty() } ?: url.substringAfter("://").substringBefore('/'),
            url = url.trim(),
            isNameCustomized = !name.isNullOrBlank(),
            frontSni = frontSni?.trim()?.takeIf { it.isNotEmpty() },
            frontTargets = frontTargets.map { it.trim() }.filter { it.isNotEmpty() }
        )
        mutateSubscriptions { it + subscription }
        updateSubscription(subscription.id, announceAdded = true)
    }

    fun updateSubscriptionSettings(id: UUID, name: String, frontSni: String?, frontTargets: List<String>) {
        mutateSubscriptions { list ->
            list.map {
                if (it.id == id) it.copy(
                    name = name.trim().ifEmpty { it.name },
                    isNameCustomized = name.trim().isNotEmpty(),
                    frontSni = frontSni?.trim()?.takeIf { s -> s.isNotEmpty() },
                    frontTargets = frontTargets.map { t -> t.trim() }.filter { t -> t.isNotEmpty() }
                ) else it
            }
        }
    }

    fun updateAllSubscriptions() {
        _subscriptions.value.forEach { updateSubscription(it.id) }
    }

    fun updateSubscription(id: UUID, announceAdded: Boolean = false) {
        val subscription = _subscriptions.value.firstOrNull { it.id == id } ?: return
        if (id in _updating.value) return
        _updating.update { it + id }
        scope.launch {
            try {
                val result = SubscriptionFetcher.fetch(subscription)
                // The same link twice in a feed is one server; ids of servers
                // that stayed are kept so pins and Auto choices survive.
                val fresh = result.configurations.distinctBy { runCatching { it.toUrl() }.getOrDefault(it.id.toString()) }
                mutateConfigurations { list ->
                    val previous = list.filter { it.subscriptionId == id }
                    val byLink = previous.associateBy { runCatching { it.toUrl() }.getOrNull() }.toMutableMap()
                    val merged = fresh.map { c ->
                        val link = runCatching { c.toUrl() }.getOrNull()
                        val old = link?.let { byLink.remove(it) }
                        c.copy(id = old?.id ?: c.id, subscriptionId = id)
                    }
                    list.filterNot { it.subscriptionId == id } + merged
                }
                mutateSubscriptions { list ->
                    list.map {
                        if (it.id == id) it.copy(
                            name = result.name.takeIf { n -> !it.isNameCustomized && !n.isNullOrBlank() } ?: it.name,
                            lastUpdate = System.currentTimeMillis(),
                            upload = result.upload, download = result.download,
                            total = result.total, expire = result.expire
                        ) else it
                    }
                }
                pruneSelection()
                val name = _subscriptions.value.firstOrNull { it.id == id }?.name ?: subscription.name
                notify(if (announceAdded) tr("subscription_added", name) else tr("subscription_updated", name, fresh.size))
                val live = engine.configuration
                if (live?.subscriptionId == id && _configurations.value.none { it.id == live.id }) reconnectIfNeeded()
            } catch (e: Exception) {
                logger.error("Subscription ${subscription.name}: ${e.message}")
                notify(tr("subscription_failed", e.message ?: e.javaClass.simpleName))
            } finally {
                _updating.update { it - id }
            }
        }
    }

    fun deleteSubscription(id: UUID) {
        mutateSubscriptions { list -> list.filterNot { it.id == id } }
        mutateConfigurations { list -> list.filterNot { it.subscriptionId == id } }
        pruneSelection()
        if (engine.configuration?.subscriptionId == id) reconnectIfNeeded()
    }

    /** Refreshes every subscription on the configured interval, and once on start when stale. */
    private suspend fun subscriptionRefreshLoop() {
        delay(20_000)
        while (scope.isActive) {
            val hours = _settings.value.subscriptionUpdateHours
            if (hours > 0) {
                val stale = System.currentTimeMillis() - hours * 3_600_000L
                _subscriptions.value.filter { (it.lastUpdate ?: 0L) < stale }.forEach { updateSubscription(it.id) }
            }
            delay(10 * 60_000L)
        }
    }

    // ------------------------------------------------------------ settings

    fun updateSettings(transform: (DesktopSettings) -> DesktopSettings) {
        var before: DesktopSettings? = null
        val after = mutateSettings { current -> before = current; transform(current) }
        val old = before ?: return
        if (after == old) return
        applyPolicies(after)
        engine.updateRouting(_rules.value, after)
        if (after.language != old.language) S.apply(after.language)
        if (after.launchAtLogin != old.launchAtLogin) {
            if (!LaunchAtLogin.set(after.launchAtLogin) && after.launchAtLogin) {
                mutateSettings { it.copy(launchAtLogin = false) }
            }
        }
        val portsChanged = after.socksPort != old.socksPort || after.httpPort != old.httpPort ||
            after.allowLan != old.allowLan || after.socksUdp != old.socksUdp
        if (engine.isRunning) {
            if (portsChanged) {
                scope.launch {
                    connectLock.withLock { engine.stop() }
                    startConnection()
                }
            } else if (after.setSystemProxy != old.setSystemProxy || after.proxyBypass != old.proxyBypass) {
                engine.setSystemProxy(after.setSystemProxy, after)
            }
        }
    }

    fun rememberWindowSize(width: Int, height: Int) {
        if (width < 600 || height < 400) return
        mutateSettings { if (it.windowWidth == width && it.windowHeight == height) it else it.copy(windowWidth = width, windowHeight = height) }
    }

    fun updateRules(rules: List<RouteRule>) {
        _rules.value = rules
        store.saveRules(rules)
        engine.updateRouting(rules, _settings.value)
    }

    fun importGeoIp(file: java.io.File, onDone: (Boolean) -> Unit) {
        scope.launch {
            val ok = runCatching { file.inputStream().use { GeoIpDatabase.importInto(AppPaths.geoIp, it) } }.getOrDefault(false)
            onDone(ok)
        }
    }

    fun clearGeoIp() = GeoIpDatabase.clear(AppPaths.geoIp)

    private fun applyPolicies(s: DesktopSettings) {
        FragmentPolicy.set(
            FragmentSettings(
                isEnabled = s.fragmentEnabled,
                minLength = s.fragmentMinLength, maxLength = s.fragmentMaxLength,
                minInterval = s.fragmentMinInterval, maxInterval = s.fragmentMaxInterval
            )
        )
        CertificatePolicy.setAllowInsecure(s.allowInsecure)
        EncryptedDnsPolicy.set(
            if (s.dohEnabled) (DnsUpstream.from("doh", s.dohUrl) ?: DnsUpstream.System) else DnsUpstream.System
        )
    }

    // ------------------------------------------------------------- persist

    private fun mutateSettings(transform: (DesktopSettings) -> DesktopSettings): DesktopSettings =
        synchronized(stateLock) {
            val next = transform(_settings.value)
            if (next != _settings.value) {
                _settings.value = next
                store.saveSettings(next)
            }
            next
        }

    private fun mutateConfigurations(transform: (List<ProxyConfiguration>) -> List<ProxyConfiguration>) {
        synchronized(stateLock) {
            val next = transform(_configurations.value)
            _configurations.value = next
            store.saveConfigurations(next)
        }
    }

    private fun mutateSubscriptions(transform: (List<Subscription>) -> List<Subscription>) {
        synchronized(stateLock) {
            val next = transform(_subscriptions.value)
            _subscriptions.value = next
            store.saveSubscriptions(next)
        }
    }

    // --------------------------------------------------------------- misc

    private suspend fun speedLoop() {
        var lastUp = stats.up.get()
        var lastDown = stats.down.get()
        while (scope.isActive) {
            delay(1000)
            val up = stats.up.get()
            val down = stats.down.get()
            _speed.value = Speed((up - lastUp).coerceAtLeast(0), (down - lastDown).coerceAtLeast(0))
            lastUp = up
            lastDown = down
        }
    }

    fun notify(text: String) {
        _message.value = text
        messageJob?.cancel()
        messageJob = scope.launch {
            delay(4_000)
            if (_message.value == text) _message.value = null
        }
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    companion object {
        const val DEFAULT_GROUP = "default"
        private const val MAX_LOG_LINES = 600
        private const val AUTO_FIRST_ROUND_DELAY_MS = 1_500L
        private const val AUTO_RECHECK_MS = 120_000L
        private const val AUTO_SWITCH_MARGIN_MS = 50
        private const val PROBE_FIRST_DELAY_MS = 2_500L
        private const val PROBE_INTERVAL_MS = 60_000L
    }
}

/** The protocols whose transport lives in the native library. */
internal fun OutboundProtocol.needsNative(): Boolean = when (this) {
    OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC, OutboundProtocol.NOWHERE -> true
    else -> false
}
