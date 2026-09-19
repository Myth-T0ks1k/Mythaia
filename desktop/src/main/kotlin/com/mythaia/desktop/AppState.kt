package com.mythaia.desktop

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.desktop.engine.LaunchAtLogin
import com.mythaia.desktop.engine.ProxyEngine
import com.mythaia.desktop.engine.SystemProxy
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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

/**
 * The application state: the lists, the settings, the connection and Auto.
 * Compose reads the flows; every mutation goes through here and is saved.
 */
class AppState(private val store: DesktopStore, val nativeAvailable: Boolean) {
    private val logger = MythaiaLogger("App")
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val stats = TrafficStats()
    val engine = ProxyEngine(stats)

    private val _settings = MutableStateFlow(store.loadSettings())
    val settings: StateFlow<DesktopSettings> = _settings.asStateFlow()

    private val _configurations = MutableStateFlow(store.loadConfigurations())
    val configurations: StateFlow<List<ProxyConfiguration>> = _configurations.asStateFlow()

    private val _subscriptions = MutableStateFlow(store.loadSubscriptions())
    val subscriptions: StateFlow<List<Subscription>> = _subscriptions.asStateFlow()

    private val _rules = MutableStateFlow(store.loadRules())
    val rules: StateFlow<List<RouteRule>> = _rules.asStateFlow()

    private val _connection = MutableStateFlow<ConnectionState>(ConnectionState.Disconnected)
    val connection: StateFlow<ConnectionState> = _connection.asStateFlow()

    private val _latencies = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val latencies: StateFlow<Map<UUID, LatencyResult>> = _latencies.asStateFlow()

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

    /** Set when the window should come to the front (tray "show"). */
    val windowVisible = MutableStateFlow(true)

    private var autoJob: Job? = null
    private var probeJob: Job? = null
    private var pingJob: Job? = null
    private val connectLock = Mutex()
    private var messageJob: Job? = null

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

    /** The server the group would connect with right now. */
    fun effectiveConfig(groupId: String): ProxyConfiguration? {
        pinned(groupId)?.let { return it }
        val configs = groupConfigs(groupId)
        if (configs.isEmpty()) return null
        autoChoice(groupId)?.let { return it }
        return bestKnown(configs) ?: configs.first()
    }

    private fun bestKnown(configs: List<ProxyConfiguration>): ProxyConfiguration? {
        val known = _latencies.value
        return configs.mapNotNull { c -> (known[c.id] as? LatencyResult.Success)?.let { c to it.ms } }
            .minByOrNull { it.second }?.first
    }

    fun selectGroup(groupId: String) {
        if (groupId == activeGroupId) return
        saveSettings(_settings.value.copy(activeGroupId = groupId))
        reconnectIfNeeded()
    }

    /** Pins one server for its group and makes that group active. */
    fun pin(config: ProxyConfiguration) {
        val gid = groupIdOf(config)
        val s = _settings.value
        saveSettings(s.copy(activeGroupId = gid, groupPins = s.groupPins + (gid to config.id.toString())))
        reconnectIfNeeded()
    }

    fun useAuto(groupId: String) {
        val s = _settings.value
        saveSettings(s.copy(activeGroupId = groupId, groupPins = s.groupPins - groupId))
        reconnectIfNeeded()
    }

    private fun reconnectIfNeeded() {
        if (_connection.value is ConnectionState.Disconnected || _connection.value is ConnectionState.Failed) return
        scope.launch { startConnection() }
    }

    private fun pruneSelection() {
        val ids = _configurations.value.map { it.id.toString() }.toSet()
        val s = _settings.value
        val pins = s.groupPins.filterValues { it in ids }
        val choices = s.autoChoices.filterValues { it in ids }
        val groupIds = groups().map { it.id }.toSet()
        val active = if (s.activeGroupId in groupIds) s.activeGroupId else DEFAULT_GROUP
        if (pins != s.groupPins || choices != s.autoChoices || active != s.activeGroupId) {
            saveSettings(s.copy(groupPins = pins, autoChoices = choices, activeGroupId = active))
        }
    }

    // --------------------------------------------------------- connection

    fun toggle() {
        when (_connection.value) {
            is ConnectionState.Disconnected, is ConnectionState.Failed -> scope.launch { startConnection() }
            else -> disconnect()
        }
    }

    fun connect() = scope.launch { startConnection() }

    private suspend fun startConnection() = connectLock.withLock {
        val gid = activeGroupId
        val config = effectiveConfig(gid)
        if (config == null) {
            _connection.value = ConnectionState.Failed(tr("no_server"))
            notify(tr("no_servers_hint"))
            return@withLock
        }
        if (!nativeAvailable && config.outboundProtocol.needsNative()) {
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
        restartBackgroundJobs(gid)
    }

    fun disconnect() {
        autoJob?.cancel(); autoJob = null
        probeJob?.cancel(); probeJob = null
        engine.stop()
        _connection.value = ConnectionState.Disconnected
        _connectedSince.value = null
        _connectivityOk.value = true
    }

    /** Called from the exit path: puts the system back the way it was. */
    fun shutdown() {
        runCatching { disconnect() }
        scope.cancel()
    }

    private fun restartBackgroundJobs(groupId: String) {
        autoJob?.cancel()
        probeJob?.cancel()
        autoJob = if (isAuto(groupId)) scope.launch { autoLoop(groupId) } else null
        probeJob = scope.launch { probeLoop() }
    }

    /**
     * Auto: measure the group now and every two minutes, moving to the best
     * server as results come in, so the first good one is used within
     * seconds rather than after the whole round.
     */
    private suspend fun autoLoop(groupId: String) {
        delay(AUTO_FIRST_ROUND_DELAY_MS)
        while (scope.isActive) {
            runAutoRound(groupId)
            delay(AUTO_RECHECK_MS)
        }
    }

    private suspend fun runAutoRound(groupId: String) {
        val configs = groupConfigs(groupId)
        if (configs.isEmpty()) return
        _latencies.update { m -> m + configs.associate { it.id to LatencyResult.Testing } }
        var bestId: UUID? = null
        var bestMs = Int.MAX_VALUE
        val current = engine.configuration?.id
        var currentMs: Int? = null
        LatencyTester.testAll(configs, LatencyKind.HTTP).collect { (id, result) ->
            _latencies.update { it + (id to result) }
            if (result is LatencyResult.Success) {
                if (id == current) currentMs = result.ms
                if (result.ms < bestMs) {
                    bestMs = result.ms
                    bestId = id
                    val config = configs.firstOrNull { it.id == id }
                    val currentKnown = currentMs
                    // Switch live when the current one is unmeasured-failed or
                    // clearly slower; a tie is not worth a new connection.
                    val currentFailed = _latencies.value[current] is LatencyResult.Failed
                    if (config != null && id != current &&
                        (currentFailed || currentKnown == null || result.ms + AUTO_SWITCH_MARGIN_MS < currentKnown)
                    ) {
                        switchAuto(groupId, config)
                    }
                }
            } else if (id == current && result is LatencyResult.Failed) {
                bestId?.let { b -> configs.firstOrNull { it.id == b }?.let { switchAuto(groupId, it) } }
            }
        }
        val best = bestId?.let { b -> configs.firstOrNull { it.id == b } }
        if (best != null && engine.configuration?.id != best.id) {
            val curr = engine.configuration?.id?.let { _latencies.value[it] }
            val currMs = (curr as? LatencyResult.Success)?.ms
            if (currMs == null || bestMs + AUTO_SWITCH_MARGIN_MS < currMs) switchAuto(groupId, best)
        }
        if (best == null) {
            _connectivityOk.value = false
            logger.warning("Auto: no server in the group answered")
        }
    }

    private fun switchAuto(groupId: String, config: ProxyConfiguration) {
        if (engine.configuration?.id == config.id) return
        engine.switchTo(config)
        _connection.value = ConnectionState.Connected(config)
        _connectivityOk.value = true
        val s = _settings.value
        saveSettings(s.copy(autoChoices = s.autoChoices + (groupId to config.id.toString())))
        notify(tr("auto_switching", config.name))
    }

    /** Checks the live server reaches the internet; failing that, Auto rechecks the group. */
    private suspend fun probeLoop() {
        delay(PROBE_FIRST_DELAY_MS)
        var failures = 0
        while (scope.isActive) {
            val config = engine.configuration
            if (config != null) {
                val result = LatencyTester.test(config, LatencyKind.HTTP)
                _latencies.update { it + (config.id to result) }
                val ok = result is LatencyResult.Success
                _connectivityOk.value = ok
                if (!ok) {
                    failures++
                    logger.warning("Probe failed for ${config.name} ($failures)")
                    val gid = activeGroupId
                    if (isAuto(gid) && failures <= MAX_AUTO_RECOVERIES) {
                        runAutoRound(gid)
                    }
                } else {
                    failures = 0
                }
            }
            delay(PROBE_INTERVAL_MS)
        }
    }

    // ---------------------------------------------------------- latency

    fun pingGroup(groupId: String, kind: LatencyKind) {
        val configs = groupConfigs(groupId)
        if (configs.isEmpty()) return
        pingJob?.cancel()
        pingJob = scope.launch {
            _latencies.update { m -> m + configs.associate { it.id to LatencyResult.Testing } }
            LatencyTester.testAll(configs, kind).collect { (id, result) ->
                _latencies.update { it + (id to result) }
            }
        }
    }

    fun pingOne(config: ProxyConfiguration, kind: LatencyKind = LatencyKind.HTTP) {
        scope.launch {
            _latencies.update { it + (config.id to LatencyResult.Testing) }
            val result = LatencyTester.test(config, kind)
            _latencies.update { it + (config.id to result) }
        }
    }

    // ------------------------------------------------------------ servers

    /** Adds every link in [text]; an https:// line without credentials is a subscription. */
    fun addText(text: String, subscriptionName: String? = null, frontSni: String? = null, frontTargets: List<String> = emptyList()) {
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
            saveConfigurations(_configurations.value + added)
            notify(tr("added_n", added.size))
        }
        subscriptionUrls.forEach { addSubscription(it, subscriptionName, frontSni, frontTargets) }
        if (added.isEmpty() && subscriptionUrls.isEmpty()) notify(tr("nothing_parsed"))
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        saveConfigurations(_configurations.value.filterNot { it.id == config.id })
        pruneSelection()
        if (engine.configuration?.id == config.id) reconnectIfNeeded()
    }

    fun renameConfiguration(config: ProxyConfiguration, name: String) {
        saveConfigurations(_configurations.value.map { if (it.id == config.id) it.copy(name = name.trim()) else it })
    }

    fun addSubscription(url: String, name: String?, frontSni: String?, frontTargets: List<String>) {
        val subscription = Subscription(
            name = name?.trim()?.takeIf { it.isNotEmpty() } ?: url.substringAfter("://").substringBefore('/'),
            url = url.trim(),
            isNameCustomized = !name.isNullOrBlank(),
            frontSni = frontSni?.trim()?.takeIf { it.isNotEmpty() },
            frontTargets = frontTargets.map { it.trim() }.filter { it.isNotEmpty() }
        )
        saveSubscriptions(_subscriptions.value + subscription)
        updateSubscription(subscription.id, announceAdded = true)
    }

    fun updateSubscriptionSettings(id: UUID, name: String, frontSni: String?, frontTargets: List<String>) {
        saveSubscriptions(_subscriptions.value.map {
            if (it.id == id) it.copy(
                name = name.trim().ifEmpty { it.name },
                isNameCustomized = name.trim().isNotEmpty(),
                frontSni = frontSni?.trim()?.takeIf { s -> s.isNotEmpty() },
                frontTargets = frontTargets.map { t -> t.trim() }.filter { t -> t.isNotEmpty() }
            ) else it
        })
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
                val previous = _configurations.value.filter { it.subscriptionId == id }
                val byLink = previous.associateBy { runCatching { it.toUrl() }.getOrNull() }
                val fresh = result.configurations.map { c ->
                    val link = runCatching { c.toUrl() }.getOrNull()
                    val old = link?.let { byLink[it] }
                    c.copy(id = old?.id ?: c.id, subscriptionId = id)
                }
                saveConfigurations(_configurations.value.filterNot { it.subscriptionId == id } + fresh)
                saveSubscriptions(_subscriptions.value.map {
                    if (it.id == id) it.copy(
                        name = result.name.takeIf { n -> !it.isNameCustomized && !n.isNullOrBlank() } ?: it.name,
                        lastUpdate = System.currentTimeMillis(),
                        upload = result.upload, download = result.download,
                        total = result.total, expire = result.expire
                    ) else it
                })
                pruneSelection()
                val name = _subscriptions.value.first { it.id == id }.name
                notify(if (announceAdded) tr("subscription_added", name) else tr("subscription_updated", name, fresh.size))
                if (engine.configuration?.subscriptionId == id && engine.configuration?.let { c -> fresh.none { it.id == c.id } } == true) {
                    reconnectIfNeeded()
                }
            } catch (e: Exception) {
                logger.error("Subscription ${subscription.name}: ${e.message}")
                notify(tr("subscription_failed", e.message ?: e.javaClass.simpleName))
            } finally {
                _updating.update { it - id }
            }
        }
    }

    fun deleteSubscription(id: UUID) {
        saveSubscriptions(_subscriptions.value.filterNot { it.id == id })
        saveConfigurations(_configurations.value.filterNot { it.subscriptionId == id })
        pruneSelection()
        if (engine.configuration?.subscriptionId == id) reconnectIfNeeded()
    }

    // ------------------------------------------------------------ settings

    fun updateSettings(transform: (DesktopSettings) -> DesktopSettings) {
        val before = _settings.value
        val after = transform(before)
        if (after == before) return
        saveSettings(after)
        applyPolicies(after)
        engine.updateRouting(_rules.value, after)
        if (after.language != before.language) S.apply(after.language)
        if (after.launchAtLogin != before.launchAtLogin) {
            if (!LaunchAtLogin.set(after.launchAtLogin) && after.launchAtLogin) {
                saveSettings(after.copy(launchAtLogin = false))
            }
        }
        val portsChanged = after.socksPort != before.socksPort || after.httpPort != before.httpPort ||
            after.allowLan != before.allowLan || after.socksUdp != before.socksUdp
        if (engine.isRunning) {
            if (portsChanged) {
                scope.launch {
                    engine.stop()
                    startConnection()
                }
            } else if (after.setSystemProxy != before.setSystemProxy || after.proxyBypass != before.proxyBypass) {
                if (after.setSystemProxy) SystemProxy.enable("127.0.0.1:${after.httpPort}", after.proxyBypass)
                else SystemProxy.restore()
            }
        }
    }

    fun updateRules(rules: List<RouteRule>) {
        _rules.value = rules
        store.saveRules(rules)
        engine.updateRouting(rules, _settings.value)
    }

    fun importGeoIp(file: java.io.File): Boolean {
        val ok = file.inputStream().use { GeoIpDatabase.importInto(AppPaths.geoIp, it) }
        return ok
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

    private fun saveSettings(settings: DesktopSettings) {
        _settings.value = settings
        store.saveSettings(settings)
    }

    private fun saveConfigurations(configs: List<ProxyConfiguration>) {
        _configurations.value = configs
        store.saveConfigurations(configs)
    }

    private fun saveSubscriptions(subs: List<Subscription>) {
        _subscriptions.value = subs
        store.saveSubscriptions(subs)
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
        private const val MAX_AUTO_RECOVERIES = 4
    }
}

/** The protocols whose transport lives in the native library. */
private fun com.mythaia.data.model.OutboundProtocol.needsNative(): Boolean = when (this) {
    com.mythaia.data.model.OutboundProtocol.HYSTERIA2,
    com.mythaia.data.model.OutboundProtocol.TUIC,
    com.mythaia.data.model.OutboundProtocol.NOWHERE -> true
    else -> false
}
