package com.mythaia.desktop

import com.mythaia.data.model.FragmentSettings
import com.mythaia.desktop.service.ServiceInstaller.Outcome as ServiceOutcome
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.data.network.SubscriptionMetadata
import com.mythaia.data.network.WorkingServers
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
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

/** What a link handed to the app would add, parsed but not stored: the window asks first. */
data class PendingImport(val text: String, val names: List<String>)

/** What the bar at the bottom of the window says, and the one thing it offers to do. */
class Notice(val text: String, val actionLabel: String? = null, val action: (() -> Unit)? = null)

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
    val tun = com.mythaia.desktop.tun.TunEngine(stats)

    /** True when TUN mode was asked for without administrator rights; the UI offers a relaunch. */
    val needsElevation = MutableStateFlow(false)

    /** The service is registered and answering, so TUN runs there without elevation. */
    val serviceAvailable = MutableStateFlow(false)
    val serviceInstalled = MutableStateFlow(false)

    /** The version the answering service reports; null before 1.1.2 or when it is not answering. */
    val serviceVersion = MutableStateFlow<String?>(null)

    /** The TUN tunnel the service is running for us, and its outbound. */
    @Volatile
    private var remoteTun: ProxyConfiguration? = null
    private var remoteLogSeq = 0L

    /** Whichever tunnel is up. */
    val isTunnelRunning: Boolean get() = engine.isRunning || tun.isRunning || remoteTun != null

    /** The outbound the live tunnel dials through, whichever mode. */
    val liveConfiguration: ProxyConfiguration? get() = remoteTun ?: if (tun.isRunning) tun.configuration else engine.configuration

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

    private val _message = MutableStateFlow<Notice?>(null)
    val message: StateFlow<Notice?> = _message.asStateFlow()

    private val _logs = MutableStateFlow<List<LogLine>>(emptyList())
    val logs: StateFlow<List<LogLine>> = _logs.asStateFlow()

    private val _speed = MutableStateFlow(Speed(0, 0))
    val speed: StateFlow<Speed> = _speed.asStateFlow()

    /** True while a text field has focus, so window shortcuts leave typing alone. */
    val textFieldFocused = MutableStateFlow(false)

    /** Set when the window should come to the front (tray "show", second instance). */
    val windowVisible = MutableStateFlow(true)
    val bringToFront = MutableStateFlow(0L)

    /** A URL-handler import waiting for the user's yes; see [requestImport]. */
    private val _pendingImport = MutableStateFlow<PendingImport?>(null)
    val pendingImport: StateFlow<PendingImport?> = _pendingImport.asStateFlow()

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
        scope.launch { refreshSubscriptionsOnOpen() }
        scope.launch { subscriptionRefreshLoop() }
        scope.launch { serviceWatchLoop() }
    }

    // ------------------------------------------------------------- service

    /** Keeps [serviceAvailable]/[serviceInstalled] fresh and, while the service runs our tunnel, mirrors its counters and log. */
    private suspend fun serviceWatchLoop() {
        // Status polls in a row that got no answer. The service answers one
        // request at a time, and a server switch (DNS, routes) keeps the pipe
        // busy for seconds, so a single silence is not a dead service: taking
        // it for one disconnected a working tunnel during Auto rounds.
        var unanswered = 0
        while (scope.isActive) {
            val installed = runCatching { com.mythaia.desktop.service.ServiceInstaller.isInstalled() }.getOrDefault(false)
            serviceInstalled.value = installed
            val remote = remoteTun
            if (remote != null) {
                val status = com.mythaia.desktop.service.ServiceClient.status(remoteLogSeq)
                if (status == null && ++unanswered < SERVICE_SILENCE_LIMIT) {
                    delay(1_000)
                    continue
                }
                if (status != null) unanswered = 0
                if (status == null || !status.running) {
                    unanswered = 0
                    // The service dropped the tunnel (stopped, crashed, or restarted).
                    logger.warning("Service tunnel is gone; disconnecting")
                    remoteTun = null
                    serviceAvailable.value = status != null
                    disconnect()
                } else {
                    serviceAvailable.value = true
                    serviceVersion.value = status.appVersion
                    stats.up.set(status.up)
                    stats.down.set(status.down)
                    stats.connections.set(status.connections)
                    status.logs.forEach { entry ->
                        remoteLogSeq = maxOf(remoteLogSeq, entry.seq)
                        val level = runCatching { MythaiaLogger.Level.valueOf(entry.level) }.getOrDefault(MythaiaLogger.Level.info)
                        _logs.update { lines -> (lines + LogLine(entry.time, level, "[service] ${entry.text}")).takeLast(MAX_LOG_LINES) }
                    }
                }
                delay(1_000)
            } else {
                val reply = if (installed) com.mythaia.desktop.service.ServiceClient.ping() else null
                serviceAvailable.value = reply != null
                serviceVersion.value = reply?.appVersion
                delay(5_000)
            }
        }
    }

    /**
     * Copies the app to Program Files and registers the service there (one
     * administrator prompt), or updates an installed one, then waits for it
     * to answer.
     */
    fun installService() {
        scope.launch {
            // Updating stops the service, and with it a tunnel it runs for us.
            if (remoteTun != null) disconnect()
            val outcome = com.mythaia.desktop.service.ServiceInstaller.install(onStarted = { notify(tr("service_installing")) })
            when (outcome) {
                ServiceOutcome.NO_LAUNCHER -> { notify(tr("service_needs_install")); return@launch }
                ServiceOutcome.DECLINED -> { notify(tr("service_prompt_declined")); return@launch }
                ServiceOutcome.FAILED -> { notify(tr("service_install_failed")); return@launch }
                ServiceOutcome.DONE -> Unit
            }
            serviceInstalled.value = true
            // The service is a JVM of its own; give it time to open its pipe.
            repeat(60) {
                val reply = com.mythaia.desktop.service.ServiceClient.ping()
                if (reply != null) {
                    serviceAvailable.value = true
                    serviceVersion.value = reply.appVersion
                    notify(tr("service_installed"))
                    return@launch
                }
                delay(500)
            }
            notify(tr("service_not_answering"))
        }
    }

    fun uninstallService() {
        scope.launch {
            if (remoteTun != null) disconnect()
            when (com.mythaia.desktop.service.ServiceInstaller.uninstall()) {
                ServiceOutcome.DONE -> {
                    serviceAvailable.value = false
                    serviceInstalled.value = false
                    notify(tr("service_removed"))
                }
                ServiceOutcome.DECLINED -> notify(tr("service_prompt_declined"))
                else -> notify(tr("service_remove_failed"))
            }
        }
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

    /**
     * Asks where to save the links of [configs] as a text file, one per line,
     * the form every client imports. A bulk list is too long to pass around
     * through the clipboard comfortably.
     */
    fun saveLinksToFile(configs: List<ProxyConfiguration>, groupName: String) {
        val text = linksOf(configs)
        if (text.isEmpty()) {
            notify(tr("nothing_parsed"))
            return
        }
        val dialog = java.awt.FileDialog(null as java.awt.Frame?, tr("save_links_file"), java.awt.FileDialog.SAVE)
        val safe = groupName.filter { it.isLetterOrDigit() || it in " ._-" }.trim().ifEmpty { "servers" }
        dialog.file = "$safe.txt"
        dialog.isVisible = true
        val dir = dialog.directory ?: return
        val name = dialog.file ?: return
        val file = java.io.File(dir, if (name.endsWith(".txt", ignoreCase = true)) name else "$name.txt")
        scope.launch(Dispatchers.IO) {
            runCatching { file.writeText(text) }
                .onSuccess { notify(tr("saved_n_links", text.count { it == '\n' } + 1)) }
                .onFailure { notify(it.message ?: tr("nothing_parsed")) }
        }
    }

    private fun reconnectIfNeeded() {
        if (!isTunnelRunning) return
        scope.launch { startConnection() }
    }

    /**
     * Hands the app to an elevated copy of itself for TUN mode and exits once
     * that copy has started. Off the UI thread: the UAC prompt can stay up for
     * as long as the user leaves it, and the window froze into "Not
     * responding" behind it.
     */
    fun relaunchElevated() {
        scope.launch(Dispatchers.IO) {
            if (com.mythaia.desktop.tun.TunEngine.relaunchElevated(listOf("--tun"))) {
                logger.info("Elevated instance launched; this one exits")
                kotlin.system.exitProcess(0)
            }
            notify(tr("tun_unavailable", com.mythaia.desktop.tun.Elevation.lastError ?: "?"))
        }
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
        if (isTunnelRunning || _connection.value is ConnectionState.Connecting) disconnect()
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
            if (isTunnelRunning && previous is ConnectionState.Connected) {
                notify(reason)
                return@withLock
            }
            _connection.value = ConnectionState.Failed(tr("no_server"))
            notify(reason)
            return@withLock
        }
        if (!nativeAvailable && config.outboundProtocol.needsNative()) {
            if (isTunnelRunning && previous is ConnectionState.Connected) {
                notify(tr("no_native_for", config.name))
                return@withLock
            }
            _connection.value = ConnectionState.Failed(tr("native_missing"))
            return@withLock
        }
        val settings = _settings.value
        val useTun = settings.tunnelMode == "tun"
        // The service runs the TUN tunnel when it is there; otherwise this
        // process must be elevated to do it itself.
        val viaService = useTun && (serviceAvailable.value || com.mythaia.desktop.service.ServiceClient.isAvailable())
        if (useTun && !viaService) {
            if (!com.mythaia.desktop.tun.TunEngine.isAvailable()) {
                _connection.value = ConnectionState.Failed(tr("tun_unavailable", "wintun.dll"))
                return@withLock
            }
            if (!com.mythaia.desktop.tun.TunEngine.isElevated()) {
                _connection.value = ConnectionState.Failed(tr("tun_needs_admin_short"))
                needsElevation.value = true
                return@withLock
            }
        }
        // Switching modes while up: the other tunnel comes down first.
        if (useTun && engine.isRunning) engine.stop()
        if (!useTun && tun.isRunning) tun.stop()
        if ((!useTun || !viaService) && remoteTun != null) { runCatching { com.mythaia.desktop.service.ServiceClient.stop() }; remoteTun = null }
        if (viaService && tun.isRunning) tun.stop()
        val wasRunning = isTunnelRunning
        _connection.value = ConnectionState.Connecting(config)
        try {
            when {
                viaService -> {
                    if (!wasRunning) stats.reset()
                    com.mythaia.desktop.service.ServiceClient.start(settings, config, _rules.value)
                    remoteTun = config
                    serviceAvailable.value = true
                }
                useTun -> {
                    tun.updateRouting(_rules.value, settings)
                    tun.start(settings, config)
                }
                else -> {
                    engine.updateRouting(_rules.value, settings)
                    engine.start(settings, config)
                }
            }
        } catch (e: Exception) {
            logger.error("Start failed: ${e.message}")
            val port = settings.socksPort
            _connection.value = ConnectionState.Failed(
                if (e is java.net.BindException) tr("port_in_use", port) else (e.message ?: tr("failed"))
            )
            runCatching {
                when {
                    viaService -> { com.mythaia.desktop.service.ServiceClient.stop(); remoteTun = null }
                    useTun -> tun.stop()
                    else -> engine.stop()
                }
            }
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
        if (remoteTun != null) {
            remoteTun = null
            runCatching { com.mythaia.desktop.service.ServiceClient.stop() }.onFailure { logger.error("Service stop: ${it.message}") }
        }
        if (tun.isRunning) runCatching { tun.stop() }.onFailure { logger.error("TUN stop: ${it.message}") }
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
            val current = liveConfiguration?.id
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
                    if (best != null && best.id != liveConfiguration?.id) {
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
                if (e is CancellationException && !currentCoroutineContext().isActive) {
                    // A reconnect, a pin, a group change or Disconnect stopped
                    // the round. Carrying on used to mark every unmeasured
                    // server Failed (which "Remove failed" then deleted), report
                    // that no server answered, and switch away from the server
                    // just pinned. What was not measured goes back to unmeasured.
                    _latencies.update { m -> m - configs.filter { m[it.id] is LatencyResult.Testing }.map { it.id }.toSet() }
                    throw e
                }
                logger.warning("Auto round failed: ${e.message ?: e}")
                _latencies.update { m -> m + configs.filter { m[it.id] is LatencyResult.Testing }.associate { it.id to LatencyResult.Failed } }
            }
            autoMeasuredOnce = true
            val best = bestId?.let { b -> configs.firstOrNull { it.id == b } }
            if (best != null && liveConfiguration?.id != best.id) {
                val currMs = (httpLatencies.value[liveConfiguration?.id] as? LatencyResult.Success)?.ms
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
        if (liveConfiguration?.id == config.id) return
        when {
            remoteTun != null -> {
                try {
                    com.mythaia.desktop.service.ServiceClient.switchTo(config)
                    remoteTun = config
                } catch (e: Exception) {
                    logger.error("Service switch: ${e.message}")
                    return
                }
            }
            tun.isRunning -> tun.switchTo(config)
            else -> engine.switchTo(config)
        }
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
            val config = liveConfiguration
            if (config != null) {
                val result = safeTest(config, LatencyKind.HTTP)
                _latencies.update { it + (config.id to result) }
                httpLatencies.update { it + (config.id to result) }
                val ok = result is LatencyResult.Success
                if (liveConfiguration?.id == config.id) _connectivityOk.value = ok
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

    /**
     * A test that cannot throw: a missing native library reports Failed, not
     * an Error. Cancellation of the caller is the exception — a probe stopped
     * by a reconnect or Disconnect did not find the server down.
     */
    private suspend fun safeTest(config: ProxyConfiguration, kind: LatencyKind): LatencyResult =
        try {
            if (!nativeAvailable && config.outboundProtocol.needsNative()) LatencyResult.Failed
            else LatencyTester.test(config, kind)
        } catch (e: Throwable) {
            if (e is CancellationException) currentCoroutineContext().ensureActive()
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
                // A newer round replaced this one and has marked the servers
                // Testing itself; overwriting them with Failed would undo that.
                if (e is CancellationException) currentCoroutineContext().ensureActive()
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

    /**
     * The URL-handler path into [addText]: any web page can open a
     * `mythaia://` or `vless://` link, so what one brings is shown — names
     * and hosts — and stored only on [confirmImport]. Pasting and QR
     * scanning from inside the app are the user's own doing and stay direct.
     */
    fun requestImport(text: String) {
        val names = describeImport(text)
        if (names.isEmpty()) {
            notify(tr("nothing_parsed"))
            return
        }
        _pendingImport.value = PendingImport(text, names)
        windowVisible.value = true
        bringToFront.value = System.currentTimeMillis()
    }

    fun confirmImport() {
        val pending = _pendingImport.value ?: return
        _pendingImport.value = null
        addText(pending.text)
    }

    fun dismissImport() {
        _pendingImport.value = null
    }

    /** What [addText] would make of [text]: one line per server (name and host) or subscription (host). */
    private fun describeImport(text: String): List<String> {
        if (com.mythaia.data.network.XrayJsonImporter.looksLikeJson(text)) {
            return runCatching { com.mythaia.data.network.XrayJsonImporter.parse(text) }.getOrDefault(emptyList())
                .map { "${it.name} · ${it.serverAddress}" }
        }
        val out = ArrayList<String>()
        for (line in text.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
            if (isSubscriptionUrl(line)) {
                out += line.substringAfter("://").substringBefore('/')
                continue
            }
            if (!ProxyConfiguration.canParseUrl(line)) continue
            runCatching { ProxyConfiguration.fromUrl(line) }.onSuccess { out += "${it.name} · ${it.serverAddress}" }
        }
        return out
    }

    /** An http(s):// line without credentials in its authority is a subscription, not a proxy link. */
    private fun isSubscriptionUrl(line: String): Boolean =
        (line.startsWith("https://", ignoreCase = true) || line.startsWith("http://", ignoreCase = true)) &&
            !line.substringAfter("://").substringBefore('/').contains('@')

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
        val subscriptionUrls = mutableListOf<com.mythaia.data.network.SubscriptionLink>()
        for (line in lines) {
            // A subscription, possibly with its fronting written in
            // (`…#front=…&sni=…` or mythaia://import?url=…&front=…).
            if (isSubscriptionUrl(line) || line.startsWith("mythaia://import?", ignoreCase = true)) {
                com.mythaia.data.network.SubscriptionLink.parse(line)
                    ?.takeIf { isSubscriptionUrl(it.url) }
                    ?.let { subscriptionUrls += it }
                continue
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
        // What the dialog's fields say wins; the link fills what they leave empty.
        subscriptionUrls.forEach { link ->
            addSubscription(
                url = link.url,
                name = subscriptionName?.takeIf { it.isNotBlank() } ?: link.name,
                frontSni = frontSni?.takeIf { it.isNotBlank() } ?: link.frontSni,
                frontTargets = frontTargets.ifEmpty { link.frontTargets }
            )
        }
        if (added.isEmpty() && subscriptionUrls.isEmpty()) notify(tr("nothing_parsed"))
    }

    /** Saves an edited or new server; a new one goes to the manual group. */
    fun saveConfiguration(config: ProxyConfiguration) {
        mutateConfigurations { list ->
            if (list.any { it.id == config.id }) list.map { if (it.id == config.id) config.copy(subscriptionId = it.subscriptionId) else it }
            else list + config.copy(subscriptionId = null)
        }
        if (liveConfiguration?.id == config.id) reconnectIfNeeded()
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        mutateConfigurations { list -> list.filterNot { it.id == config.id } }
        pruneSelection()
        if (liveConfiguration?.id == config.id) reconnectIfNeeded()
    }

    fun deleteConfigurations(ids: Set<UUID>) {
        mutateConfigurations { list -> list.filterNot { it.id in ids } }
        pruneSelection()
        if (liveConfiguration?.id in ids) reconnectIfNeeded()
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
        // Unreachable, or a certificate that does not verify: either way it does not work.
        val failed = groupConfigs(groupId).filter {
            val result = _latencies.value[it.id]
            result is LatencyResult.Failed || result is LatencyResult.Insecure
        }.map { it.id }.toSet()
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
                val count = fetchSubscription(subscription)
                val name = _subscriptions.value.firstOrNull { it.id == id }?.name ?: subscription.name
                notify(if (announceAdded) tr("subscription_added", name) else tr("subscription_updated", name, count))
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.error("Subscription ${subscription.name}: ${e.message}")
                notifySubscriptionFailure(subscription, e.message ?: e.javaClass.simpleName, canRetry = e.isWorthADetour())
            } finally {
                _updating.update { it - id }
            }
        }
    }

    /**
     * Downloads [subscription], folds its servers and what the panel said
     * into the store, and returns how many servers it has now. A failure is
     * recorded on the subscription before it is rethrown.
     */
    private suspend fun fetchSubscription(
        subscription: Subscription,
        via: ProxyConfiguration? = null,
        timeoutMs: Int? = null
    ): Int {
        val id = subscription.id
        val result = try {
            SubscriptionFetcher.fetch(subscription, via = via, timeoutMs = timeoutMs)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            mutateSubscriptions { list ->
                list.map {
                    if (it.id == id) it.copy(lastFailure = System.currentTimeMillis(), lastFailureMessage = e.message?.take(300))
                    else it
                }
            }
            throw e
        }
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
        // What the panel said, as the phone records it: a moved URL, fronting, messages.
        mutateSubscriptions { list -> list.map { if (it.id == id) SubscriptionMetadata.applyTo(it, result) else it } }
        pruneSelection()
        val live = liveConfiguration
        if (live?.subscriptionId == id && _configurations.value.none { it.id == live.id }) reconnectIfNeeded()
        return fresh.size
    }

    /** A panel that answered with nothing usable would say the same through any server. */
    private fun Exception.isWorthADetour(): Boolean =
        this !is SubscriptionFetcher.FetchError.NoConfigurations && this !is SubscriptionFetcher.FetchError.InvalidUrl

    private fun notifySubscriptionFailure(subscription: Subscription, reason: String, canRetry: Boolean) {
        val text = tr("subscription_failed_named", subscription.name, reason)
        if (canRetry) notify(text, tr("through_working_server")) { updateSubscriptionThroughServer(subscription.id) }
        else notify(text, long = true)
    }

    /**
     * Fetches [id] through a server that works, for a panel this network
     * cannot reach: the live server first, then the first servers to pass a
     * fresh check, the subscription's own before the rest.
     */
    fun updateSubscriptionThroughServer(id: UUID) {
        val subscription = _subscriptions.value.firstOrNull { it.id == id } ?: return
        if (id in _updating.value) return
        _updating.update { it + id }
        notify(tr("subscription_retrying", subscription.name), long = true)
        scope.launch {
            var lastError: Exception? = null
            try {
                for (server in serversThatWork(id)) {
                    try {
                        val count = fetchSubscription(subscription, via = server, timeoutMs = THROUGH_SERVER_TIMEOUT_MS)
                        logger.info("Subscription ${subscription.name} updated through ${server.name}")
                        val name = _subscriptions.value.firstOrNull { it.id == id }?.name ?: subscription.name
                        notify(tr("subscription_updated_through", name, server.name, count))
                        return@launch
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        throw e
                    } catch (e: SubscriptionFetcher.FetchError.NoConfigurations) {
                        lastError = e
                        break
                    } catch (e: Exception) {
                        logger.warning("Subscription ${subscription.name} through ${server.name}: ${e.message}")
                        lastError = e
                    }
                }
                notify(
                    lastError?.let { tr("subscription_failed_through", it.message ?: it.javaClass.simpleName) }
                        ?: tr("no_working_server"),
                    long = true
                )
            } finally {
                _updating.update { it - id }
            }
        }
    }

    /** Servers to fetch [subscriptionId] through, checked just now; see [WorkingServers]. */
    private suspend fun serversThatWork(subscriptionId: UUID): List<ProxyConfiguration> {
        val all = _configurations.value
        val live = if (isTunnelRunning && _connectivityOk.value) {
            liveConfiguration?.let { l -> all.firstOrNull { it.id == l.id } }
        } else null
        return WorkingServers.find(
            live = live,
            candidates = WorkingServers.candidates(all, subscriptionId, _latencies.value),
            onResult = { id, result -> _latencies.update { it + (id to result) } }
        )
    }

    /**
     * On start: refresh what the panel asked to have refreshed on every open
     * (`subscription-auto-update-open-enable`), and speak up for one that
     * kept failing last time.
     */
    private suspend fun refreshSubscriptionsOnOpen() {
        // Let the window come up first.
        delay(3_000)
        val subscriptions = _subscriptions.value
        subscriptions.filter { it.updateOnOpen }.forEach { updateSubscription(it.id) }
        val failing = subscriptions.firstOrNull { it.isFailing && !it.updateOnOpen } ?: return
        notifySubscriptionFailure(failing, failing.lastFailureMessage ?: tr("unknown_error"), canRetry = true)
    }

    fun deleteSubscription(id: UUID) {
        mutateSubscriptions { list -> list.filterNot { it.id == id } }
        mutateConfigurations { list -> list.filterNot { it.subscriptionId == id } }
        pruneSelection()
        if (liveConfiguration?.subscriptionId == id) reconnectIfNeeded()
    }

    /** Refreshes every subscription on the configured interval, and once on start when stale. */
    private suspend fun subscriptionRefreshLoop() {
        delay(20_000)
        while (scope.isActive) {
            val hours = _settings.value.subscriptionUpdateHours
            if (hours > 0) {
                val stale = System.currentTimeMillis() - hours * 3_600_000L
                // `subscription-auto-update-enable: 0`: the provider wants it refreshed by hand only.
                _subscriptions.value.filter { it.autoUpdate && (it.lastUpdate ?: 0L) < stale }.forEach { updateSubscription(it.id) }
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
        val modeChanged = after.tunnelMode != old.tunnelMode
        if (modeChanged) needsElevation.value = false
        if (isTunnelRunning) {
            val tunUp = tun.isRunning || remoteTun != null
            if (portsChanged || modeChanged || (tunUp && after.bypassTurkmenistan != old.bypassTurkmenistan)) {
                scope.launch {
                    connectLock.withLock {
                        if (remoteTun != null) { remoteTun = null; runCatching { com.mythaia.desktop.service.ServiceClient.stop() } }
                        if (tun.isRunning) runCatching { tun.stop() } else engine.stop()
                    }
                    startConnection()
                }
            } else if (engine.isRunning && (after.setSystemProxy != old.setSystemProxy || after.proxyBypass != old.proxyBypass)) {
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
        tun.updateRouting(rules, _settings.value)
        if (remoteTun != null) scope.launch { runCatching { com.mythaia.desktop.service.ServiceClient.updateRouting(_settings.value, rules) } }
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

    /**
     * A line at the bottom of the window that goes away on its own: after
     * four seconds, or twelve when it has an [actionLabel] to act on or is
     * [long] enough to need reading.
     */
    fun notify(text: String, actionLabel: String? = null, long: Boolean = false, action: (() -> Unit)? = null) {
        val notice = Notice(text, actionLabel?.takeIf { action != null }, action)
        _message.value = notice
        messageJob?.cancel()
        messageJob = scope.launch {
            delay(if (notice.actionLabel != null || long) 12_000 else 4_000)
            if (_message.value === notice) _message.value = null
        }
    }

    /** Runs the bar's action and takes the bar away. */
    fun actOnMessage(notice: Notice) {
        if (_message.value === notice) _message.value = null
        notice.action?.invoke()
    }

    fun dismissMessage() {
        _message.value = null
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    companion object {
        /** How long the panel gets through each server tried. */
        private const val THROUGH_SERVER_TIMEOUT_MS = 20_000

        const val DEFAULT_GROUP = "default"
        private const val MAX_LOG_LINES = 600
        private const val AUTO_FIRST_ROUND_DELAY_MS = 1_500L
        private const val AUTO_RECHECK_MS = 120_000L
        private const val AUTO_SWITCH_MARGIN_MS = 50
        private const val PROBE_FIRST_DELAY_MS = 2_500L
        private const val PROBE_INTERVAL_MS = 60_000L

        /** Unanswered service polls (one a second) before its tunnel counts as gone. */
        private const val SERVICE_SILENCE_LIMIT = 3
    }
}

/** The protocols whose transport lives in the native library. */
internal fun OutboundProtocol.needsNative(): Boolean = when (this) {
    OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC, OutboundProtocol.NOWHERE -> true
    else -> false
}
