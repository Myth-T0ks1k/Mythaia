package com.mythaia.viewmodel

import androidx.core.content.edit
import android.annotation.SuppressLint
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.SharedPreferences
import android.net.VpnService
import android.os.IBinder
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.mythaia.R
import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.ProxyChain
import com.mythaia.data.model.SplitTunnelSettings
import com.mythaia.data.model.Subscription
import com.mythaia.data.model.ThemeMode
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionDomainHelper
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.data.network.SubscriptionRefreshScheduler
import com.mythaia.data.network.SubscriptionUpdater
import com.mythaia.data.repository.CertificateRepository
import com.mythaia.data.repository.ChainRepository
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.data.repository.MitmRepository
import com.mythaia.data.repository.RuleSetRepository
import com.mythaia.data.repository.SubscriptionRepository
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.MythaiaVpnService
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.EncryptedDnsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload
import com.mythaia.vpn.protocol.tls.read
import com.mythaia.vpn.protocol.tls.write

enum class VpnStatus {
    DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, REASSERTING
}

/**
 * A set of servers the user can point the tunnel at as one thing.
 *
 * "Default" is every server that came from no subscription; every
 * subscription is a group of its own. A group is either on Auto — the
 * fastest server by handshake, re-measured while connected — or pinned to
 * one server the user tapped.
 */
data class ProxyGroup(
    val id: String,
    val name: String,
    val subscriptionId: UUID?,
    val configs: List<ProxyConfiguration>
) {
    val isDefault: Boolean get() = subscriptionId == null

    companion object {
        const val DEFAULT_ID = "default"
    }
}

private val logger = MythaiaLogger("VPNViewModel")

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    val configRepository = ConfigRepository.get(application)
    val subscriptionRepository = SubscriptionRepository.get(application)
    val ruleSetRepository = RuleSetRepository(application)
    val certificateRepository = CertificateRepository(application)
    val chainRepository = ChainRepository(application)
    val mitmRepository = MitmRepository(application)

    private val prefs: SharedPreferences =
        application.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    private val _vpnStatus = MutableStateFlow(VpnStatus.DISCONNECTED)
    val vpnStatus: StateFlow<VpnStatus> = _vpnStatus.asStateFlow()
    private var pendingReconnect = false

    private val _bytesIn = MutableStateFlow(0L)
    val bytesIn: StateFlow<Long> = _bytesIn.asStateFlow()

    private val _bytesOut = MutableStateFlow(0L)
    val bytesOut: StateFlow<Long> = _bytesOut.asStateFlow()

    /**
     * Throughput over the last poll, in bytes per second.
     *
     * Derived from the difference between two cumulative readings rather than
     * measured directly, so it is only as granular as the poll interval — which
     * is what a rate readout needs to be anyway.
     */
    private val _downloadSpeed = MutableStateFlow(0L)
    val downloadSpeed: StateFlow<Long> = _downloadSpeed.asStateFlow()

    private val _uploadSpeed = MutableStateFlow(0L)
    val uploadSpeed: StateFlow<Long> = _uploadSpeed.asStateFlow()

    /** How long the tunnel has been up, in seconds. 0 when it is not. */
    private val _uptimeSeconds = MutableStateFlow(0L)
    val uptimeSeconds: StateFlow<Long> = _uptimeSeconds.asStateFlow()

    /** The server the tunnel is (or would be) on: the pin, or Auto's pick. */
    private val _selectedConfigId = MutableStateFlow<UUID?>(null)
    val selectedConfigId: StateFlow<UUID?> = _selectedConfigId.asStateFlow()

    /** Which group the tunnel draws from; a chain selection overrides it. */
    private val _activeGroupId = MutableStateFlow(
        prefs.getString("activeGroupId", ProxyGroup.DEFAULT_ID) ?: ProxyGroup.DEFAULT_ID
    )
    val activeGroupId: StateFlow<String> = _activeGroupId.asStateFlow()

    /** Group id to the server pinned in it. A group with no pin is on Auto. */
    private val _pinnedByGroup = MutableStateFlow(loadPins())
    val pinnedByGroup: StateFlow<Map<String, UUID>> = _pinnedByGroup.asStateFlow()

    /** Group id to what Auto last chose, and when. Not persisted: it goes stale. */
    private val _autoChoice = MutableStateFlow<Map<String, UUID>>(emptyMap())
    val autoChoice: StateFlow<Map<String, UUID>> = _autoChoice.asStateFlow()
    private val autoChoiceAt = HashMap<String, Long>()

    /** What the numbers in [latencyResults] measure right now. */
    private val _latencyKind = MutableStateFlow(LatencyKind.HANDSHAKE)
    val latencyKind: StateFlow<LatencyKind> = _latencyKind.asStateFlow()

    private val _latencyResults = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val latencyResults: StateFlow<Map<UUID, LatencyResult>> = _latencyResults.asStateFlow()

    private val _startError = MutableStateFlow<String?>(null)
    val startError: StateFlow<String?> = _startError.asStateFlow()

    private val _orphanedRuleSetNames = MutableStateFlow<List<String>>(emptyList())
    val orphanedRuleSetNames: StateFlow<List<String>> = _orphanedRuleSetNames.asStateFlow()

    private val _selectedChainId = MutableStateFlow<UUID?>(null)
    val selectedChainId: StateFlow<UUID?> = _selectedChainId.asStateFlow()

    private val _chainLatencyResults = MutableStateFlow<Map<UUID, LatencyResult>>(emptyMap())
    val chainLatencyResults: StateFlow<Map<UUID, LatencyResult>> = _chainLatencyResults.asStateFlow()

    /**
     * Which palette to draw in.
     *
     * A flow rather than a plain preference read: the activity collects it, so
     * choosing a mode repaints immediately instead of at the next launch.
     */
    private val _themeMode = MutableStateFlow(
        ThemeMode.fromRaw(prefs.getString(ThemeMode.KEY, null))
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    fun setThemeMode(mode: ThemeMode) {
        if (_themeMode.value == mode) return
        prefs.edit { putString(ThemeMode.KEY, mode.raw) }
        _themeMode.value = mode
        applySystemNightMode(mode)
    }

    /**
     * Tells the platform too, so the system bars, the recents card and the
     * splash follow the choice — Compose alone only repaints its own tree.
     * Only available from API 31; below that the app's own surfaces still
     * follow the setting and the chrome follows the device.
     */
    private fun applySystemNightMode(mode: ThemeMode) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.S) return
        val manager = getApplication<Application>()
            .getSystemService(android.app.UiModeManager::class.java) ?: return
        runCatching {
            manager.setApplicationNightMode(
                when (mode) {
                    ThemeMode.SYSTEM -> android.app.UiModeManager.MODE_NIGHT_AUTO
                    ThemeMode.LIGHT -> android.app.UiModeManager.MODE_NIGHT_NO
                    ThemeMode.DARK -> android.app.UiModeManager.MODE_NIGHT_YES
                }
            )
        }
    }

    var onRequestVpnPermission: ((Intent) -> Unit)? = null

    /** Asks the activity to request POST_NOTIFICATIONS; a no-op below API 33. */
    var onRequestNotificationPermission: (() -> Unit)? = null

    /** The connect in flight, so a cancel can actually cancel it. */
    private var connectJob: Job? = null

    /**
     * Pending deep-link URL (vless://…, ss://…, socks5://…, or raw link from
     * mythaia://add-proxy?link=…). Consumed by ProxyListScreen to open the
     * Add Proxy sheet with the URL pre-filled.
     */
    private val _pendingDeepLinkUrl = MutableStateFlow<String?>(null)
    val pendingDeepLinkUrl: StateFlow<String?> = _pendingDeepLinkUrl.asStateFlow()

    fun onDeepLink(uri: android.net.Uri) {
        val scheme = uri.scheme?.lowercase() ?: return
        when (scheme) {
            "mythaia" -> {
                // mythaia://connect | disconnect | toggle: for launchers,
                // automation apps (Tasker, Shortcuts) and NFC tags.
                when (uri.host) {
                    "connect" -> { if (_vpnStatus.value == VpnStatus.DISCONNECTED) connect(); return }
                    "disconnect" -> { if (_vpnStatus.value != VpnStatus.DISCONNECTED) disconnect(); return }
                    "toggle" -> {
                        if (_vpnStatus.value == VpnStatus.DISCONNECTED) connect() else disconnect()
                        return
                    }
                }
                if (uri.host != "add-proxy") return
                val full = uri.toString()
                val marker = "?link="
                val idx = full.indexOf(marker)
                if (idx < 0) return
                val raw = full.substring(idx + marker.length)
                if (raw.isEmpty()) return
                _pendingDeepLinkUrl.value = runCatching {
                    com.mythaia.data.model.percentDecode(raw)
                }.getOrDefault(raw)
            }
            "vless", "trojan", "ss", "socks5", "socks", "vmess", "hysteria2", "hy2", "anytls",
            "tuic", "wireguard", "wg" -> {
                _pendingDeepLinkUrl.value = uri.toString()
            }
            else -> {}
        }
    }

    fun consumePendingDeepLink() {
        _pendingDeepLinkUrl.value = null
    }

    // A bound Service, not an Activity, and released in onServiceDisconnected
    // and again in onCleared — so it cannot outlive the binding.
    @SuppressLint("StaticFieldLeak")
    private var vpnService: MythaiaVpnService? = null
    private var serviceBound = false
    // True from bindService() until unbindService(). Unbinding must key off this
    // flag, not serviceBound: if disconnect()/onCleared() runs before the binder
    // callback arrives, the still-pending ServiceConnection would otherwise leak.
    private var bindRequested = false
    private var statsJob: Job? = null
    private var pendingConnectAfterPermission = false

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val localBinder = binder as? MythaiaVpnService.LocalBinder ?: return
            vpnService = localBinder.service
            serviceBound = true

            // The binder is delivered after `onStartCommand` has returned,
            // so `isRunning` reflects whether `startVpn` set up the TUN and
            // lwIP stack successfully.
            if (localBinder.service.isRunning) {
                _vpnStatus.value = VpnStatus.CONNECTED
                startStatsPolling()
                selectedConfiguration?.let { syncProxyServerAddresses(it) }
            } else if (!MythaiaVpnService.isActive) {
                // Bound to a service with no tunnel: whatever we expected, the
                // binding is useless now. Release it so the next connect gets
                // a fresh one — a stale binding never delivers a second
                // onServiceConnected, which left the button spinning forever.
                unbindFromService()
                if (_vpnStatus.value != VpnStatus.DISCONNECTED) {
                    _vpnStatus.value = VpnStatus.DISCONNECTED
                }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            serviceBound = false
            stopStatsPolling()
        }
    }

    val isButtonDisabled: Boolean
        get() = (selectedConfiguration == null) ||
            (_vpnStatus.value != VpnStatus.CONNECTED && _vpnStatus.value != VpnStatus.DISCONNECTED)

    /**
     * Mirrors the service's own idea of whether a tunnel is up.
     *
     * The service publishes this for the tile and the widget; the view model
     * listens too, so a stop that did not originate here — the notification's
     * Disconnect action, the system revoking the VPN, another VPN app taking
     * over, the peer never answering — reaches the power button at once
     * instead of at the next stats poll, or never.
     */
    private val serviceStateListener: () -> Unit = {
        val active = MythaiaVpnService.isActive
        viewModelScope.launch { onServiceActiveChanged(active) }
    }

    /**
     * A start that failed before the tunnel came up.
     *
     * Without this the service just stops itself and the UI flips back to
     * Disconnected with no word on why.
     */
    private val serviceFailureListener: (String) -> Unit = { message ->
        viewModelScope.launch { onServiceStartFailed(message) }
    }

    /** True from the user's own disconnect until the next connect: not a failure. */
    private var userStopped = true

    private fun onServiceActiveChanged(active: Boolean) {
        if (active) {
            if (_vpnStatus.value != VpnStatus.CONNECTED) {
                _vpnStatus.value = VpnStatus.CONNECTED
            }
            _lastConnectFailed.value = false
            autoReconnectTimes.clear()
            bindToService()
            startStatsPolling()
            startConnectivityProbe()
            updateAutoLoop()
            return
        }

        // Down. Whatever we thought we were doing, the tunnel is gone.
        val wasUp = _vpnStatus.value == VpnStatus.CONNECTED
        stopStatsPolling()
        stopConnectivityProbe()
        unbindFromService()
        updateAutoLoop()
        if (_vpnStatus.value != VpnStatus.DISCONNECTED) {
            _vpnStatus.value = VpnStatus.DISCONNECTED
        }
        if (pendingReconnect) {
            pendingReconnect = false
            connect()
            return
        }
        // A tunnel that fell over by itself — not stopped by the user — is
        // what Auto is for: try the group again on whatever answers now.
        if (wasUp && !userStopped) {
            _lastConnectFailed.value = true
            autoReconnectAfterFailure(_selectedConfigId.value)
        }
    }

    private fun onServiceStartFailed(message: String) {
        stopStatsPolling()
        stopConnectivityProbe()
        unbindFromService()
        updateAutoLoop()
        pendingReconnect = false
        _vpnStatus.value = VpnStatus.DISCONNECTED
        _startError.value = message
        _lastConnectFailed.value = true
        autoReconnectAfterFailure(_selectedConfigId.value)
    }

    /** True after a start failed or the tunnel dropped, until the next successful connect. */
    private val _lastConnectFailed = MutableStateFlow(false)
    val lastConnectFailed: StateFlow<Boolean> = _lastConnectFailed.asStateFlow()

    /**
     * Whether traffic actually gets through the live server.
     *
     * A tunnel can be "connected" — the TUN is up — while the proxy behind
     * it never answers. null until the first probe of a session reports.
     */
    private val _connectivityOk = MutableStateFlow<Boolean?>(null)
    val connectivityOk: StateFlow<Boolean?> = _connectivityOk.asStateFlow()

    private var probeJob: Job? = null

    /** Where the tunnel comes out — address and country — once a probe got through. */
    private val _exitInfo = MutableStateFlow<com.mythaia.data.network.ExitIpProbe.ExitInfo?>(null)
    val exitInfo: StateFlow<com.mythaia.data.network.ExitIpProbe.ExitInfo?> = _exitInfo.asStateFlow()
    private var exitInfoFor: UUID? = null

    /** Looks the exit up again, e.g. on a tap after the user changed something upstream. */
    fun refreshExitInfo() {
        val liveId = MythaiaVpnService.activeConfigId ?: return
        val live = configRepository.get(liveId) ?: selectedConfiguration ?: return
        exitInfoFor = live.id
        viewModelScope.launch { _exitInfo.value = lookupExit(live) }
    }

    private suspend fun lookupExit(live: ProxyConfiguration): com.mythaia.data.network.ExitIpProbe.ExitInfo? =
        com.mythaia.data.network.ExitIpProbe.throughServer(applyGlobalAllowInsecure(live))
            ?: com.mythaia.data.network.ExitIpProbe.throughDefaultRoute()

    /** A real request through the live server, shortly after connecting and then every minute. */
    private fun startConnectivityProbe() {
        probeJob?.cancel()
        probeJob = viewModelScope.launch {
            var delayMs = PROBE_FIRST_DELAY_MS
            while (true) {
                delay(delayMs)
                delayMs = PROBE_INTERVAL_MS
                if (_vpnStatus.value != VpnStatus.CONNECTED) break
                val liveId = MythaiaVpnService.activeConfigId ?: continue
                val live = configRepository.get(liveId) ?: selectedConfiguration ?: continue
                val result = LatencyTester.test(applyGlobalAllowInsecure(live), LatencyKind.HTTP)
                if (_vpnStatus.value != VpnStatus.CONNECTED) break
                _latencyResults.value = _latencyResults.value + (live.id to result)
                val ok = result is LatencyResult.Success
                _connectivityOk.value = ok
                // Once per server and session: where does this one come out?
                if (ok && exitInfoFor != live.id) {
                    exitInfoFor = live.id
                    _exitInfo.value = lookupExit(live)
                }
                // Dead on the wire while on Auto: find one that answers.
                if (!ok && activeIsAuto && !_autoSelecting.value) {
                    autoSelectFastest(_activeGroupId.value)
                }
            }
        }
    }

    private fun stopConnectivityProbe() {
        probeJob?.cancel()
        probeJob = null
        _connectivityOk.value = null
        _exitInfo.value = null
        exitInfoFor = null
    }

    fun clearLastConnectFailed() {
        _lastConnectFailed.value = false
    }

    init {
        com.mythaia.vpn.AutoSelectEngine.uiAlive = true
        MythaiaVpnService.addStateListener(serviceStateListener)
        MythaiaVpnService.addStartFailureListener(serviceFailureListener)

        // Picks the background engine made while no screen was open.
        prefs.getString("autoChoices", null)?.let { raw ->
            runCatching { json.decodeFromString<Map<String, String>>(raw) }.getOrNull()
                ?.mapNotNull { (k, v) -> runCatching { UUID.fromString(v) }.getOrNull()?.let { k to it } }
                ?.toMap()
                ?.let { _autoChoice.value = it }
        }

        val savedChainId = prefs.getString("selectedChainId", null)?.let {
            runCatching { UUID.fromString(it) }.getOrNull()
        }
        if (savedChainId != null && chainRepository.get(savedChainId) != null) {
            _selectedChainId.value = savedChainId
        }
        // A selection saved before groups existed becomes a pin in its group.
        prefs.getString("selectedConfigurationId", null)?.let { raw ->
            val id = runCatching { UUID.fromString(raw) }.getOrNull()
            val config = id?.let { configRepository.get(it) }
            if (config != null && !_pinnedByGroup.value.containsKey(groupIdOf(config))) {
                val gid = groupIdOf(config)
                _pinnedByGroup.value = _pinnedByGroup.value + (gid to config.id)
                _activeGroupId.value = gid
                savePins()
                prefs.edit { putString("activeGroupId", gid) }
            }
        }
        recomputeSelection()

        // The service outlives the Activity. Coming back to a tunnel that never
        // stopped has to restore CONNECTED and rebind — otherwise the power
        // button reads disconnected while traffic is still flowing, and the
        // next tap calls connect(), which tears the live stack down and
        // rebuilds it. Guarded by isActive so the binding never creates a
        // service that was not already running.
        if (MythaiaVpnService.isActive) {
            _vpnStatus.value = VpnStatus.CONNECTED
            bindToService()
        }

        // Prime CertificatePolicy with the current allowInsecure + trusted-certificate
        // values so TLS validation has a fresh snapshot before the first connection.
        CertificatePolicy.reload(application)
        FragmentPolicy.reload(application)
        EncryptedDnsPolicy.reload(application)
        // Reconcile the process-wide MITM store to what is on disk so the
        // interception hook sees any persisted CA and rule sets from the moment
        // the UI process starts. Idempotent and cheap when nothing is stored.
        viewModelScope.launch { mitmRepository.loadInto() }
        // Periodic work survives process death on its own; this only covers
        // a first run, or a reinstall that kept the preferences.
        SubscriptionRefreshScheduler.ensureScheduled(application)

        // React to trusted-certificate changes: update the singleton immediately and
        // notify the tunnel so live TLS connections tear down and reconnect under the
        // new policy.
        viewModelScope.launch {
            var first = true
            certificateRepository.fingerprints.collect { fingerprints ->
                CertificatePolicy.setTrustedFingerprints(fingerprints)
                if (first) { first = false; return@collect }
                signalCertificatePolicyChanged()
            }
        }
    }

    val selectedConfiguration: ProxyConfiguration?
        get() {
            val chainId = _selectedChainId.value
            if (chainId != null) {
                val chain = chainRepository.get(chainId) ?: return null
                return resolveChain(chain)
            }
            val id = _selectedConfigId.value ?: return null
            return configRepository.get(id)
        }

    // ---- Groups -------------------------------------------------------------

    fun groupIdOf(config: ProxyConfiguration): String =
        config.subscriptionId?.toString() ?: ProxyGroup.DEFAULT_ID

    /** Every group, Default first, in subscription order. Empty groups are kept. */
    fun groups(): List<ProxyGroup> {
        val all = configRepository.getAll()
        val default = ProxyGroup(
            id = ProxyGroup.DEFAULT_ID,
            name = "",
            subscriptionId = null,
            configs = all.filter { it.subscriptionId == null }
        )
        val subs = subscriptionRepository.getAll().map { sub ->
            ProxyGroup(sub.id.toString(), sub.name, sub.id, all.filter { it.subscriptionId == sub.id })
        }
        return listOf(default) + subs
    }

    fun groupConfigs(groupId: String): List<ProxyConfiguration> {
        val all = configRepository.getAll()
        return if (groupId == ProxyGroup.DEFAULT_ID) all.filter { it.subscriptionId == null }
        else all.filter { it.subscriptionId?.toString() == groupId }
    }

    /** Servers Auto may choose from: dialable, and not a layer-3 interface. */
    private fun autoCandidates(groupId: String): List<ProxyConfiguration> =
        groupConfigs(groupId).filter { it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3 }

    /** Whether [groupId] follows Auto (no pin). */
    fun isAuto(groupId: String): Boolean = _pinnedByGroup.value[groupId] == null

    /** Whether the tunnel is currently following Auto rather than a pin or a chain. */
    val activeIsAuto: Boolean
        get() = _selectedChainId.value == null && isAuto(_activeGroupId.value)

    /**
     * Makes [groupId] the group the tunnel draws from.
     *
     * On a live tunnel the switch is immediate: to the pin if the group has
     * one, otherwise to whatever Auto picks after a fresh round.
     */
    fun selectGroup(groupId: String) {
        val changedGroup = _activeGroupId.value != groupId || _selectedChainId.value != null
        _selectedChainId.value = null
        prefs.edit { remove("selectedChainId") }
        _activeGroupId.value = groupId
        prefs.edit { putString("activeGroupId", groupId) }
        recomputeSelection()
        if (!changedGroup) return
        applySelectionToTunnel(freshAuto = true)
    }

    /**
     * Pins the tunnel to one server: its group becomes active and stops
     * following Auto until [useAuto] is called for it.
     */
    fun pinConfiguration(config: ProxyConfiguration) {
        val gid = groupIdOf(config)
        _selectedChainId.value = null
        prefs.edit { remove("selectedChainId") }
        _pinnedByGroup.value = _pinnedByGroup.value + (gid to config.id)
        savePins()
        _activeGroupId.value = gid
        prefs.edit { putString("activeGroupId", gid) }
        recomputeSelection()
        applySelectionToTunnel(freshAuto = false)
    }

    /** Kept for callers that predate groups; a tap on a server pins it. */
    fun setSelectedConfiguration(config: ProxyConfiguration) = pinConfiguration(config)

    /** Lets [groupId] follow Auto again, and makes it the active group. */
    fun useAuto(groupId: String) {
        _selectedChainId.value = null
        prefs.edit { remove("selectedChainId") }
        _pinnedByGroup.value = _pinnedByGroup.value - groupId
        savePins()
        _activeGroupId.value = groupId
        prefs.edit { putString("activeGroupId", groupId) }
        recomputeSelection()
        applySelectionToTunnel(freshAuto = true)
    }

    /**
     * Brings the tunnel in line with the selection, if one is up. Auto runs a
     * measurement first when asked, so the switch lands on today's fastest
     * server rather than yesterday's.
     */
    private fun applySelectionToTunnel(freshAuto: Boolean) {
        updateAutoLoop()
        if (_vpnStatus.value != VpnStatus.CONNECTED) return
        if (activeIsAuto && freshAuto) {
            viewModelScope.launch { autoSelectFastest(_activeGroupId.value) }
            return
        }
        selectedConfiguration?.let { switchConfig(it) }
    }

    /**
     * Derives [selectedConfigId] from the group state: the pin if it still
     * exists, else Auto's last pick if it does, else the first candidate.
     */
    private fun recomputeSelection() {
        val gid = _activeGroupId.value
        val configs = groupConfigs(gid)

        // Drop pins and picks that point at servers that are gone.
        val livePins = _pinnedByGroup.value.filterValues { configRepository.get(it) != null }
        if (livePins.size != _pinnedByGroup.value.size) {
            _pinnedByGroup.value = livePins
            savePins()
        }
        val liveAuto = _autoChoice.value.filterValues { configRepository.get(it) != null }
        if (liveAuto.size != _autoChoice.value.size) _autoChoice.value = liveAuto

        // A group that vanished (subscription deleted) falls back to Default.
        if (gid != ProxyGroup.DEFAULT_ID && subscriptionRepository.getAll().none { it.id.toString() == gid }) {
            _activeGroupId.value = ProxyGroup.DEFAULT_ID
            prefs.edit { putString("activeGroupId", ProxyGroup.DEFAULT_ID) }
            recomputeSelection()
            return
        }

        val chosen = livePins[gid]
            ?: liveAuto[gid]
            ?: configs.firstOrNull { it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3 }?.id
            ?: configs.firstOrNull()?.id
        _selectedConfigId.value = chosen
        // Mirrors the selection for the tile, the widget and the watch, which
        // read it without a view model.
        prefs.edit { putString("selectedConfigurationId", chosen?.toString()) }
    }

    private fun loadPins(): Map<String, UUID> {
        val raw = prefs.getString("groupPins", null) ?: return emptyMap()
        return runCatching {
            json.decodeFromString<Map<String, String>>(raw)
                .mapNotNull { (k, v) -> runCatching { UUID.fromString(v) }.getOrNull()?.let { k to it } }
                .toMap()
        }.getOrDefault(emptyMap())
    }

    private fun savePins() {
        val raw = json.encodeToString(_pinnedByGroup.value.mapValues { it.value.toString() })
        prefs.edit { putString("groupPins", raw) }
    }

    fun toggleVPN() {
        when (_vpnStatus.value) {
            VpnStatus.DISCONNECTED -> connect()
            VpnStatus.CONNECTED, VpnStatus.CONNECTING -> disconnect()
            else -> {}
        }
    }

    /** True while [autoSelectFastest] is measuring. */
    private val _autoSelecting = MutableStateFlow(false)
    val autoSelecting: StateFlow<Boolean> = _autoSelecting.asStateFlow()

    /**
     * Measures every candidate in [groupId] by real ping (an HTTP round trip
     * through the proxy, as v2rayNG and Hiddify do) and records the fastest
     * as Auto's pick for that group.
     *
     * If the group is the active one, is on Auto, and a tunnel is up, the
     * tunnel moves to the pick when it differs from the server in use by more
     * than a small margin — enough to follow a real change, not enough to
     * flap between two servers a few milliseconds apart. It does not wait
     * for the whole round when the live server has already failed: the
     * first server that answers takes over at once.
     *
     * @return the pick, or null when nothing answered.
     */
    suspend fun autoSelectFastest(groupId: String = _activeGroupId.value): ProxyConfiguration? {
        if (_autoSelecting.value) return null
        val candidates = autoCandidates(groupId)
        if (candidates.isEmpty()) return null

        _autoSelecting.value = true
        try {
            _latencyKind.value = LatencyKind.HTTP
            syncProxyServerAddresses(candidates)
            candidates.forEach { config ->
                _latencyResults.value = _latencyResults.value + (config.id to LatencyResult.Testing)
            }

            val results = HashMap<UUID, Int>()
            // The server on the wire, and what we know about it so far. Kept
            // here rather than read back from the service on every result,
            // because a switch we just asked for takes a moment to land.
            var liveId: UUID? = MythaiaVpnService.activeConfigId
            var liveMs: Int? = null
            var liveFailed = _connectivityOk.value == false
            LatencyTester.testAll(candidates.map { applyGlobalAllowInsecure(it) }, LatencyKind.HTTP)
                .collect { (id, result) ->
                    _latencyResults.value = _latencyResults.value + (id to result)
                    if (result is LatencyResult.Success) results[id] = result.ms

                    if (id == liveId) {
                        if (result is LatencyResult.Success) { liveMs = result.ms; liveFailed = false }
                        else if (result !is LatencyResult.Testing) liveFailed = true
                    }

                    // Real-time: as soon as a server proves faster than the one
                    // on the wire (by the margin), or the wire is dead, move to
                    // it. Each move raises the bar for the next, so the tunnel
                    // only ever steps to something better, never sideways.
                    val canSwitch = groupId == _activeGroupId.value && activeIsAuto &&
                        _vpnStatus.value == VpnStatus.CONNECTED
                    if (canSwitch && result is LatencyResult.Success && id != liveId) {
                        val currentMs = liveMs
                        val better = liveFailed || liveId == null ||
                            (currentMs != null && currentMs - result.ms >= AUTO_SWITCH_MARGIN_MS)
                        if (better) {
                            configRepository.get(id)?.let { next ->
                                logger.info("[AutoSelect] ${next.name} at ${result.ms}ms beats the live server; switching")
                                switchConfig(next)
                                _autoChoice.value = _autoChoice.value + (groupId to next.id)
                                recomputeSelection()
                                liveId = next.id
                                liveMs = result.ms
                                liveFailed = false
                            }
                        }
                    }
                }

            val bestEntry = results.minByOrNull { it.value } ?: return null
            val winner = configRepository.get(bestEntry.key) ?: return null
            logger.info("[AutoSelect] ${groupLabel(groupId)}: ${winner.name} at ${bestEntry.value}ms")

            _autoChoice.value = _autoChoice.value + (groupId to winner.id)
            autoChoiceAt[groupId] = System.currentTimeMillis()
            prefs.edit {
                putString("autoChoices", json.encodeToString(_autoChoice.value.mapValues { it.value.toString() }))
            }

            if (groupId == _activeGroupId.value && activeIsAuto) {
                recomputeSelection()
                if (_vpnStatus.value == VpnStatus.CONNECTED) {
                    // Settle on the round's best, compared with whatever ended
                    // up on the wire (real-time moves included).
                    val live = liveId ?: MythaiaVpnService.activeConfigId
                    val liveNow = live?.let { results[it] }
                    val worthIt = live != winner.id &&
                        (liveNow == null || liveNow - bestEntry.value >= AUTO_SWITCH_MARGIN_MS)
                    if (worthIt) switchConfig(winner)
                }
            }
            return winner
        } finally {
            _autoSelecting.value = false
        }
    }

    private fun groupLabel(groupId: String): String =
        if (groupId == ProxyGroup.DEFAULT_ID) "Default" else
            subscriptionRepository.getAll().firstOrNull { it.id.toString() == groupId }?.name ?: groupId

    /** Whether Auto's pick for [groupId] is recent enough to connect to without a new round. */
    private fun autoChoiceFresh(groupId: String): Boolean {
        val at = autoChoiceAt[groupId] ?: return false
        return _autoChoice.value[groupId] != null &&
            System.currentTimeMillis() - at < AUTO_RECHECK_MS
    }

    /**
     * The continuous part of Auto: while a tunnel is up on an Auto group,
     * re-measure every two minutes and move to the best server.
     */
    private var autoLoopJob: Job? = null

    private fun updateAutoLoop() {
        val wanted = _vpnStatus.value == VpnStatus.CONNECTED && activeIsAuto
        if (!wanted) {
            autoLoopJob?.cancel()
            autoLoopJob = null
            return
        }
        if (autoLoopJob?.isActive == true) return
        autoLoopJob = viewModelScope.launch {
            while (true) {
                delay(AUTO_RECHECK_MS)
                if (_vpnStatus.value != VpnStatus.CONNECTED || !activeIsAuto) break
                autoSelectFastest(_activeGroupId.value)
            }
        }
    }

    /**
     * The tunnel went down on its own (a block, a dead server) while on Auto:
     * measure again and come back up on whatever answers. Bounded so a
     * network that is simply gone does not loop forever.
     */
    private var autoReconnectTimes = ArrayDeque<Long>()

    private fun autoReconnectAfterFailure(failed: UUID?) {
        if (!activeIsAuto) return
        val now = System.currentTimeMillis()
        while (autoReconnectTimes.isNotEmpty() && now - autoReconnectTimes.first() > AUTO_RECONNECT_WINDOW_MS) {
            autoReconnectTimes.removeFirst()
        }
        if (autoReconnectTimes.size >= AUTO_RECONNECT_MAX) {
            logger.warning("[AutoSelect] Not reconnecting: ${AUTO_RECONNECT_MAX} attempts in the window")
            return
        }
        autoReconnectTimes.addLast(now)
        failed?.let { _latencyResults.value = _latencyResults.value + (it to LatencyResult.Failed) }
        viewModelScope.launch {
            val gid = _activeGroupId.value
            // Forget the pick that just failed so the round can move on.
            if (failed != null && _autoChoice.value[gid] == failed) {
                _autoChoice.value = _autoChoice.value - gid
            }
            val chosen = autoSelectFastest(gid) ?: return@launch
            if (_vpnStatus.value == VpnStatus.DISCONNECTED) {
                logger.info("[AutoSelect] Reconnecting on ${chosen.name}")
                connect()
            }
        }
    }

    fun connect() {
        val context = getApplication<Application>()

        // Started elsewhere (tile, watch, always-on) while this screen thought
        // it was off: adopt it rather than tearing a live tunnel down to
        // rebuild the same one.
        if (MythaiaVpnService.isActive) {
            onServiceActiveChanged(active = true)
            return
        }

        // Android 13+ hides the tunnel notification (and its Disconnect
        // action) until the user allows notifications. Asked once, here,
        // where the reason is obvious; the connect goes ahead either way.
        if (!prefs.getBoolean("notificationsAsked", false)) {
            prefs.edit { putBoolean("notificationsAsked", true) }
            onRequestNotificationPermission?.invoke()
        }

        // The permission prompt comes first either way: asking for it after a
        // measurement round would leave the user staring at a spinner before
        // the dialog they actually have to answer.
        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            pendingConnectAfterPermission = true
            onRequestVpnPermission?.invoke(prepareIntent)
            return
        }

        userStopped = false
        connectWithSelection()
    }

    /**
     * Starts on the current selection.
     *
     * On an Auto group the tunnel comes up at once on the last pick (or the
     * first server), and the round of measurements runs behind it; the
     * tunnel moves to the winner when the round settles. Waiting for the
     * round first would leave the user staring at a spinner for the length
     * of the slowest timeout, which is what made the old flow feel broken.
     */
    private fun connectWithSelection() {
        val context = getApplication<Application>()
        val gid = _activeGroupId.value
        val config = selectedConfiguration

        if (config != null) {
            startVpnService(config)
            if (activeIsAuto && !autoChoiceFresh(gid) && autoCandidates(gid).size > 1) {
                viewModelScope.launch {
                    // Let the start land before the measurements compete
                    // with it for the radio.
                    delay(AUTO_FIRST_ROUND_DELAY_MS)
                    if (_vpnStatus.value == VpnStatus.CONNECTED || _vpnStatus.value == VpnStatus.CONNECTING) {
                        autoSelectFastest(gid)
                    }
                }
            }
            return
        }

        // Nothing to start on yet (an Auto group with no pick): measure first.
        if (activeIsAuto && autoCandidates(gid).isNotEmpty()) {
            _vpnStatus.value = VpnStatus.CONNECTING
            viewModelScope.launch {
                val chosen = autoSelectFastest(gid)
                if (chosen == null) {
                    _vpnStatus.value = VpnStatus.DISCONNECTED
                    _startError.value = context.getString(R.string.auto_select_none)
                    return@launch
                }
                if (_vpnStatus.value != VpnStatus.CONNECTING) return@launch
                startVpnService(chosen)
            }
        }
    }

    fun onVpnPermissionGranted() {
        if (!pendingConnectAfterPermission) return
        pendingConnectAfterPermission = false
        userStopped = false
        connectWithSelection()
    }

    fun onVpnPermissionDenied() {
        pendingConnectAfterPermission = false
        _startError.value = getApplication<Application>().getString(R.string.permission_denied)
    }

    /**
     * Applies the global allowInsecure setting to a proxy configuration's TLS config.
     * The global toggle overrides per-proxy setting when enabled.
     */
    private fun applyGlobalAllowInsecure(config: ProxyConfiguration): ProxyConfiguration {
        if (!allowInsecure) return config
        val tls = config.tls ?: return config
        if (tls.allowInsecure) return config  // already insecure
        val updatedTls = tls.copy(allowInsecure = true)
        val updatedChain = config.chain?.map { applyGlobalAllowInsecure(it) }
        return config.copy(tls = updatedTls, chain = updatedChain)
    }

    private fun startVpnService(config: ProxyConfiguration) {
        val context = getApplication<Application>()
        _vpnStatus.value = VpnStatus.CONNECTING
        // A binding left over from an earlier session would never deliver a
        // second onServiceConnected; start each connect from none.
        unbindFromService()

        connectJob?.cancel()
        connectJob = viewModelScope.launch {
            // Resolve server domain on IO thread (avoids NetworkOnMainThreadException)
            val resolvedConfig = withContext(Dispatchers.IO) {
                // Write routing.json (DNS + disk I/O) before the service starts
                // so it reads fresh rules.
                syncRoutingConfigurationBlocking()
                resolveServerAddress(applyGlobalAllowInsecure(config))
            }
            // The user may have tapped the button again while DNS was slow;
            // starting now would bring a tunnel up under a screen that says off.
            if (_vpnStatus.value != VpnStatus.CONNECTING) return@launch

            DnsCache.setActiveProxyDomain(resolvedConfig.serverAddress)
            syncProxyServerAddresses(resolvedConfig)

            val configJson = json.encodeToString(ProxyConfiguration.serializer(), resolvedConfig)
            val intent = Intent(context, MythaiaVpnService::class.java).apply {
                action = MythaiaVpnService.ACTION_START
                putExtra(MythaiaVpnService.EXTRA_CONFIG, configJson)
            }

            try {
                context.startForegroundService(intent)
                // Status stays at CONNECTING until the service binder confirms
                // the tunnel is up via [serviceConnection.onServiceConnected]
                // + `isRunning`, or the service reports active / failed.
                bindToService()
            } catch (e: Exception) {
                logger.warning("Failed to send configuration to tunnel: ${e.message}")
                _vpnStatus.value = VpnStatus.DISCONNECTED
                _startError.value = e.message
            }
        }
    }

    fun disconnect() {
        val context = getApplication<Application>()
        val wasActive = MythaiaVpnService.isActive
        userStopped = true
        autoLoopJob?.cancel()
        autoLoopJob = null
        _vpnStatus.value = VpnStatus.DISCONNECTING

        // A connect still resolving DNS must not go on to start the tunnel.
        connectJob?.cancel()
        connectJob = null
        stopStatsPolling()

        val intent = Intent(context, MythaiaVpnService::class.java).apply {
            action = MythaiaVpnService.ACTION_STOP
        }
        try {
            context.startService(intent)
        } catch (_: Exception) {}

        unbindFromService()

        if (wasActive) {
            // The service confirms through [serviceStateListener], which also
            // runs any pending reconnect. A watchdog covers the case where the
            // stop never lands, so the button cannot sit on the spinner.
            viewModelScope.launch {
                delay(DISCONNECT_WATCHDOG_MS)
                if (_vpnStatus.value == VpnStatus.DISCONNECTING) {
                    onServiceActiveChanged(active = false)
                }
            }
            return
        }

        // Nothing was up (a connect still in flight, or a stale state): there
        // is no confirmation to wait for.
        _vpnStatus.value = VpnStatus.DISCONNECTED
        if (pendingReconnect) {
            pendingReconnect = false
            connect()
        }
    }

    /**
     * Stops the VPN and automatically reconnects once disconnected.
     * Used when switching configurations while connected.
     */
    fun reconnect() {
        val status = _vpnStatus.value
        if (status != VpnStatus.CONNECTED && status != VpnStatus.CONNECTING) return
        pendingReconnect = true
        disconnect()
    }

    private fun switchConfig(config: ProxyConfiguration) {
        val context = getApplication<Application>()
        // A new server has yet to prove itself.
        _connectivityOk.value = null
        if (_vpnStatus.value == VpnStatus.CONNECTED) startConnectivityProbe()
        viewModelScope.launch {
            val resolvedConfig = withContext(Dispatchers.IO) {
                resolveServerAddress(applyGlobalAllowInsecure(config))
            }
            DnsCache.setActiveProxyDomain(resolvedConfig.serverAddress)
            syncProxyServerAddresses(resolvedConfig)
            val configJson = json.encodeToString(ProxyConfiguration.serializer(), resolvedConfig)
            val intent = Intent(context, MythaiaVpnService::class.java).apply {
                action = MythaiaVpnService.ACTION_SWITCH_CONFIG
                putExtra(MythaiaVpnService.EXTRA_CONFIG, configJson)
            }
            try {
                context.startService(intent)
            } catch (_: Exception) {}
        }
    }

    private fun bindToService() {
        if (bindRequested) return
        val context = getApplication<Application>()
        val intent = Intent(context, MythaiaVpnService::class.java)
        bindRequested = true
        context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
    }

    private fun unbindFromService() {
        if (!bindRequested) return
        val context = getApplication<Application>()
        try {
            // Legal even while the connection is still pending — this is what
            // releases a binding whose onServiceConnected never arrived.
            context.unbindService(serviceConnection)
        } catch (_: Exception) {}
        vpnService = null
        serviceBound = false
        bindRequested = false
    }

    private fun startStatsPolling() {
        if (statsJob != null) return
        statsJob = viewModelScope.launch {
            // Seeded from the first reading rather than zero: rebinding to a
            // tunnel that has been up for hours must not report all of its
            // traffic as one second's worth.
            var lastIn = -1L
            var lastOut = -1L

            while (true) {
                delay(STATS_POLL_MS)
                val service = vpnService
                if (service != null && service.isRunning) {
                    val (bytesIn, bytesOut) = service.getStats()

                    if (lastIn >= 0) {
                        val seconds = STATS_POLL_MS / 1000.0
                        // A counter that went backwards means the stack
                        // restarted; report nothing rather than a negative rate.
                        _downloadSpeed.value =
                            ((bytesIn - lastIn).coerceAtLeast(0L) / seconds).toLong()
                        _uploadSpeed.value =
                            ((bytesOut - lastOut).coerceAtLeast(0L) / seconds).toLong()
                    }
                    lastIn = bytesIn
                    lastOut = bytesOut

                    _bytesIn.value = bytesIn
                    _bytesOut.value = bytesOut
                    _uptimeSeconds.value = service.uptimeSeconds
                } else if (service != null && !service.isRunning &&
                    _vpnStatus.value == VpnStatus.CONNECTED) {
                    // Service is bound but no longer running — it actually died
                    _vpnStatus.value = VpnStatus.DISCONNECTED
                    resetStats()
                    unbindFromService()
                    statsJob = null
                    break
                }
                // If service is null, binding is still in progress — keep polling
            }
        }
    }

    /** Zeroes every live readout so a stale rate cannot linger on screen. */
    private fun resetStats() {
        _bytesIn.value = 0
        _bytesOut.value = 0
        _downloadSpeed.value = 0
        _uploadSpeed.value = 0
        _uptimeSeconds.value = 0
    }

    private fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
        resetStats()
    }

    /**
     * Resolves server address to IP before tunnel starts (avoids DNS-over-tunnel loop).
     * If already an IP, returns config as-is. If a domain, resolves via system DNS.
     */
    private fun resolveServerAddress(config: ProxyConfiguration): ProxyConfiguration {
        val resolvedConfig = resolveAddress(config)
        val resolvedChain = config.chain?.map { resolveAddress(it) }
        return if (resolvedChain != null) resolvedConfig.copy(chain = resolvedChain) else resolvedConfig
    }

    private fun resolveAddress(config: ProxyConfiguration): ProxyConfiguration {
        val resolved = resolveServerAddress(config.serverAddress) ?: return config
        return config.copy(resolvedIP = resolved)
    }

    private fun resolveServerAddress(address: String): String? {
        val bare = if (address.startsWith("[") && address.endsWith("]")) {
            address.substring(1, address.length - 1)
        } else {
            address
        }

        if (DnsCache.isIpAddress(bare)) return bare

        return try {
            val all = InetAddress.getAllByName(bare)
            val resolved = all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
            resolved?.hostAddress
        } catch (e: Exception) {
            logger.warning("Failed to resolve $bare: ${e.message ?: e}")
            null
        }
    }

    override fun onCleared() {
        super.onCleared()
        com.mythaia.vpn.AutoSelectEngine.uiAlive = false
        MythaiaVpnService.removeStateListener(serviceStateListener)
        MythaiaVpnService.removeStartFailureListener(serviceFailureListener)
        stopStatsPolling()
        unbindFromService()
    }

    fun clearStartError() {
        _startError.value = null
    }

    fun clearOrphanedRuleSetNames() {
        _orphanedRuleSetNames.value = emptyList()
    }

    fun addConfiguration(config: ProxyConfiguration) {
        configRepository.add(config)
        recomputeSelection()
    }

    fun updateConfiguration(config: ProxyConfiguration) {
        configRepository.update(config)
        // The server on the wire is this one: hand the tunnel the new
        // settings, or it keeps dialling the old address under the new name.
        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            val live = selectedConfiguration
            if (live != null && (live.id == config.id || live.chain?.any { it.id == config.id } == true)) {
                switchConfig(live)
            }
        }
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        val wasLive = _vpnStatus.value == VpnStatus.CONNECTED &&
            (_selectedConfigId.value == config.id ||
                selectedConfiguration?.chain?.any { it.id == config.id } == true)

        configRepository.delete(config.id)
        val chainId = _selectedChainId.value
        if (chainId != null) {
            val chain = chainRepository.get(chainId)
            if (chain == null || resolveChain(chain) == null) {
                _selectedChainId.value = null
                prefs.edit { remove("selectedChainId") }
            }
        }

        // The last server of a subscription takes the subscription with it:
        // a group with no members has no row to be renamed or deleted from,
        // yet the background refresh would keep repopulating it.
        config.subscriptionId?.let { subId ->
            if (configRepository.getAll().none { it.subscriptionId == subId }) {
                subscriptionRepository.get(subId)?.let {
                    subscriptionRepository.delete(subId, configRepository)
                }
            }
        }

        recomputeSelection()
        checkOrphanedRuleSets()

        // Traffic was going through the deleted server. Move it to whatever is
        // selected now, or stop rather than keep running a ghost.
        if (wasLive) {
            val next = selectedConfiguration
            if (next != null) switchConfig(next) else disconnect()
        }
    }

    fun configurations(forSubscription: Subscription): List<ProxyConfiguration> {
        return configRepository.getAll().filter { it.subscriptionId == forSubscription.id }
    }

    fun addSubscription(configurations: List<ProxyConfiguration>, subscription: Subscription) {
        subscriptionRepository.add(subscription)
        configRepository.addAll(configurations.map { it.copy(subscriptionId = subscription.id) })
        // A first subscription on an empty app becomes the active group, on Auto.
        if (groupConfigs(_activeGroupId.value).isEmpty() && _selectedChainId.value == null) {
            _activeGroupId.value = subscription.id.toString()
            prefs.edit { putString("activeGroupId", subscription.id.toString()) }
        }
        recomputeSelection()
    }

    /** Name and fronting in one save; the name counts as customised once changed. */
    fun updateSubscriptionSettings(
        subscription: Subscription,
        name: String,
        frontSni: String?,
        frontTargets: List<String>
    ) {
        val trimmedName = name.trim().ifEmpty { subscription.name }
        subscriptionRepository.update(
            subscription.copy(
                name = trimmedName,
                isNameCustomized = subscription.isNameCustomized || trimmedName != subscription.name,
                frontSni = frontSni?.trim()?.takeIf { it.isNotEmpty() },
                frontTargets = frontTargets.map { it.trim() }.filter { it.isNotEmpty() }
            )
        )
    }

    fun toggleSubscriptionCollapsed(subscription: Subscription) {
        subscriptionRepository.update(subscription.copy(collapsed = !subscription.collapsed))
    }

    fun renameSubscription(subscription: Subscription, newName: String) {
        subscriptionRepository.update(subscription.copy(name = newName, isNameCustomized = true))
    }

    fun deleteSubscription(subscription: Subscription) {
        val wasLive = _vpnStatus.value == VpnStatus.CONNECTED &&
            _selectedChainId.value == null &&
            _activeGroupId.value == subscription.id.toString()
        subscriptionRepository.delete(subscription.id, configRepository)
        _pinnedByGroup.value = _pinnedByGroup.value - subscription.id.toString()
        savePins()
        recomputeSelection()
        checkOrphanedRuleSets()
        if (wasLive) {
            val next = selectedConfiguration
            if (next != null) switchConfig(next) else disconnect()
        }
    }

    suspend fun updateSubscription(subscription: Subscription) {
        // Remnawave panels require the same x-hwid header on refresh as on the
        // initial import; without it the update fails or returns no configs.
        // Only sent when the user has opted in via the HWID setting.
        val hwid = if (remnawaveHWIDEnabled &&
            SubscriptionDomainHelper.shouldRequireRemnawaveHWID(subscription.url)
        ) deviceIdentifier else null

        SubscriptionUpdater.update(
            subscription = subscription,
            subscriptionRepository = subscriptionRepository,
            configRepository = configRepository,
            remnawaveHWID = hwid
        )

        recomputeSelection()
        // A panel that renames a server gives it a fresh id, which orphans any
        // rule set assigned to it. Without this the assignment points at a dead
        // id, the user is never told, and that rule set silently stops routing.
        checkOrphanedRuleSets()
        syncRoutingConfigurationToNE()
    }

    /**
     * How often subscriptions refresh on their own, in hours; 0 is off.
     *
     * Writing it reschedules the WorkManager job immediately, so the setting
     * takes effect without waiting for the next app start.
     */
    var subscriptionRefreshHours: Int
        get() = SubscriptionRefreshScheduler.intervalHours(getApplication())
        set(value) = SubscriptionRefreshScheduler.setIntervalHours(getApplication(), value)

    fun testLatency(forConfig: ProxyConfiguration, kind: LatencyKind = _latencyKind.value) {
        syncProxyServerAddresses(forConfig)
        _latencyKind.value = kind
        _latencyResults.value = _latencyResults.value + (forConfig.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(applyGlobalAllowInsecure(forConfig), kind)
            _latencyResults.value = _latencyResults.value + (forConfig.id to result)
        }
    }

    /**
     * Measures a set of servers. Switching the kind clears the old numbers:
     * a TCP time and a handshake time next to each other would not compare.
     */
    fun testLatencies(forConfigs: List<ProxyConfiguration>, kind: LatencyKind = _latencyKind.value) {
        if (forConfigs.isEmpty()) return
        syncProxyServerAddresses(forConfigs)
        if (_latencyKind.value != kind) {
            _latencyKind.value = kind
            _latencyResults.value = emptyMap()
        }
        forConfigs.forEach { config ->
            _latencyResults.value = _latencyResults.value + (config.id to LatencyResult.Testing)
        }
        viewModelScope.launch {
            LatencyTester.testAll(forConfigs.map { applyGlobalAllowInsecure(it) }, kind).collect { (id, result) ->
                _latencyResults.value = _latencyResults.value + (id to result)
            }
        }
    }

    fun addChain(chain: ProxyChain) {
        chainRepository.add(chain)
    }

    fun updateChain(chain: ProxyChain) {
        chainRepository.update(chain)
        if (_selectedChainId.value == chain.id) {
            val resolved = resolveChain(chain)
            if (resolved != null && _vpnStatus.value == VpnStatus.CONNECTED) {
                switchConfig(resolved)
            }
        }
    }

    fun deleteChain(chain: ProxyChain) {
        chainRepository.delete(chain.id)
        if (_selectedChainId.value == chain.id) {
            _selectedChainId.value = null
            prefs.edit { remove("selectedChainId") }
            recomputeSelection()
            updateAutoLoop()
        }
    }

    fun selectChain(chain: ProxyChain) {
        val resolved = resolveChain(chain) ?: return
        _selectedChainId.value = chain.id
        prefs.edit { putString("selectedChainId", chain.id.toString()) }
        updateAutoLoop()

        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            switchConfig(resolved)
        }
    }

    /**
     * Resolves a chain into a composite ProxyConfiguration.
     * The last proxy becomes the main config; preceding proxies fill the [chain] field.
     */
    fun resolveChain(chain: ProxyChain): ProxyConfiguration? {
        val configs = chain.proxyIds.mapNotNull { id -> configRepository.get(id) }
        if (configs.size != chain.proxyIds.size || configs.size < 2) return null
        // WireGuard carries IP packets, so it can be neither a hop nor the exit
        // of a chain. Resolving one anyway would dial the peer directly and
        // silently drop every hop the user put in front of it.
        if (configs.any { it.outboundProtocol.isLayer3 }) return null
        val exitProxy = configs.last()
        val chainProxies = configs.dropLast(1)
        return exitProxy.copy(
            name = chain.name,
            chain = chainProxies
        )
    }

    fun testChainLatency(chain: ProxyChain) {
        val resolved = resolveChain(chain) ?: return
        syncProxyServerAddresses(resolved)
        _chainLatencyResults.value = _chainLatencyResults.value + (chain.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(applyGlobalAllowInsecure(resolved))
            _chainLatencyResults.value = _chainLatencyResults.value + (chain.id to result)
        }
    }

    fun testAllChainLatencies() {
        val chains = chainRepository.getAll()
        // Give each resolved composite a fresh id: resolveChain copies the exit
        // proxy's id, so two chains ending in the same proxy would otherwise
        // collide in idMap and one chain would never receive its result.
        val resolvedChains = chains.mapNotNull { chain ->
            resolveChain(chain)?.let { chain.id to it.copy(id = UUID.randomUUID()) }
        }
        syncProxyServerAddresses(resolvedChains.map { it.second })
        resolvedChains.forEach { (chainId, _) ->
            _chainLatencyResults.value = _chainLatencyResults.value + (chainId to LatencyResult.Testing)
        }
        viewModelScope.launch {
            val configs = resolvedChains.map { applyGlobalAllowInsecure(it.second) }
            val idMap = resolvedChains.associate { (chainId, config) -> config.id to chainId }
            LatencyTester.testAll(configs).collect { (configId, result) ->
                val chainId = idMap[configId] ?: return@collect
                _chainLatencyResults.value = _chainLatencyResults.value + (chainId to result)
            }
        }
    }

    fun syncRoutingConfigurationToNE() {
        viewModelScope.launch(Dispatchers.IO) {
            syncRoutingConfigurationBlocking()
        }
    }

    /**
     * Writes routing.json. Must run off the main thread: the per-config address
     * resolver performs DNS lookups (NetworkOnMainThreadException on main) and
     * the routing file write is synchronous disk I/O.
     */
    private fun syncRoutingConfigurationBlocking() {
        ruleSetRepository.syncRoutingFile(
            configRepository.getAll()
        ) { address -> resolveServerAddress(address) }
        // Keyed on the service's own state: a tunnel the tile or the watch
        // started still has to reload its rules.
        if (MythaiaVpnService.isActive) {
            prefs.edit { putLong("routingChanged", System.currentTimeMillis()) }
        }
    }


    /**
     * Asks a running tunnel to reload its routing rules.
     *
     * For changes that alter how existing rules resolve rather than the rules
     * themselves — importing or removing the GeoIP database, say — where
     * rewriting routing.json would be beside the point.
     */
    fun signalRoutingChanged() {
        // Written unconditionally: LwipStack only listens while a tunnel is up,
        // so a stray write costs nothing, and gating on the view model own
        // status would drop the signal whenever that status is behind.
        prefs.edit { putLong("routingChanged", System.currentTimeMillis()) }
    }

    /** Collects all proxy server addresses (domains + resolved IPs) from all
     *  configurations and sends them to the VPN service. This prevents routing
     *  loops when proxy server domains match routing rules. */
    private fun syncProxyServerAddresses(configuration: ProxyConfiguration) {
        syncProxyServerAddresses(listOf(configuration))
    }

    private fun syncProxyServerAddresses(configurations: List<ProxyConfiguration>) {
        val addresses = linkedSetOf<String>()
        for (config in configurations) {
            collectProxyServerAddresses(config, addresses)
        }

        val persisted = addresses.toList()
        prefs.edit { putString("proxyServerAddresses", json.encodeToString(persisted)) }
        vpnService?.updateProxyServerAddresses(persisted)
    }

    private fun collectProxyServerAddresses(
        configuration: ProxyConfiguration,
        addresses: MutableSet<String>
    ) {
        addresses.add(configuration.serverAddress)
        configuration.resolvedIP?.let(addresses::add)
        DnsCache.cachedIPs(configuration.serverAddress)?.let(addresses::addAll)
        configuration.chain?.forEach { hop ->
            collectProxyServerAddresses(hop, addresses)
        }
    }

    /** "rule" (default) applies routing rules per-destination; "global" routes everything through the proxy. */
    var proxyMode: String
        get() = prefs.getString("proxyMode", "rule") ?: "rule"
        set(value) {
            prefs.edit { putString("proxyMode", value) }
            _isGlobalMode.value = value == "global"
        }

    /**
     * Whether everything is routed through the proxy.
     *
     * Home and Settings both offer this switch. A flow, so flipping it on one
     * screen is reflected on the other instead of each keeping the copy it
     * read when it first appeared.
     */
    private val _isGlobalMode = MutableStateFlow(prefs.getString("proxyMode", "rule") == "global")
    val isGlobalMode: StateFlow<Boolean> = _isGlobalMode.asStateFlow()

    var bypassCountryCode: String
        get() = prefs.getString("bypassCountryCode", "") ?: ""
        set(value) = prefs.edit { putString("bypassCountryCode", value) }

    /**
     * IPv6 DNS lookup toggle — a single knob that controls both IPv6 routes
     * in the TUN interface and fake-IPv6 answers for AAAA queries. When off,
     * IPv6 is effectively disabled.
     */
    var ipv6DnsEnabled: Boolean
        get() = prefs.getBoolean("ipv6DnsEnabled", false)
        set(value) = prefs.edit { putBoolean("ipv6DnsEnabled", value) }

    var encryptedDnsEnabled: Boolean
        get() = prefs.getBoolean("encryptedDnsEnabled", false)
        set(value) {
            prefs.edit { putBoolean("encryptedDnsEnabled", value) }
            EncryptedDnsPolicy.reload(getApplication())
        }

    var encryptedDnsProtocol: String
        get() = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        set(value) {
            prefs.edit { putString("encryptedDnsProtocol", value) }
            EncryptedDnsPolicy.reload(getApplication())
        }

    var encryptedDnsServer: String
        get() = prefs.getString("encryptedDnsServer", "") ?: ""
        set(value) {
            // Published straight away, like CertificatePolicy and
            // FragmentPolicy: without this the resolver keeps using the old
            // setting until the tunnel happens to reload.
            prefs.edit { putString("encryptedDnsServer", value) }
            EncryptedDnsPolicy.reload(getApplication())
        }

    /**
     * When true, drop UDP/443 traffic with ICMP port-unreachable so HTTP/3 clients
     * fall back to HTTP/2. Defaults to true.
     */
    var blockQuicEnabled: Boolean
        get() = prefs.getBoolean("blockQuicEnabled", true)
        set(value) = prefs.edit { putBoolean("blockQuicEnabled", value) }

    var allowInsecure: Boolean
        get() = prefs.getBoolean("allowInsecure", false)
        set(value) {
            if (value == allowInsecure) return
            prefs.edit { putBoolean("allowInsecure", value) }
            // Update the in-memory policy immediately so non-tunnel callers
            // (e.g. SubscriptionFetcher) observe the new value without waiting
            // for LwipStack to reload after a prefs listener fires.
            CertificatePolicy.setAllowInsecure(value)
            // Toggling allowInsecure tears down active TLS connections so the
            // new policy applies immediately.
            signalCertificatePolicyChanged()
        }

    /**
     * Tunnel-wide ClientHello fragmentation. A server whose share link carried
     * its own `fragment=` overrides this; every other server follows it.
     *
     * Reads and writes go through [FragmentPolicy] so the running tunnel sees a
     * change on its next dial without waiting for a stack reload.
     */
    var fragmentSettings: FragmentSettings
        get() = FragmentPolicy.read(prefs)
        set(value) = FragmentPolicy.write(prefs, value)

    /**
     * Which apps the tunnel carries. Writing it makes LwipStack re-establish the
     * TUN, since the selection is only expressible on VpnService.Builder.
     */
    var splitTunnelSettings: SplitTunnelSettings
        get() = SplitTunnelSettings.read(prefs)
        set(value) = SplitTunnelSettings.write(prefs, value)

    /** UI-only flag gating experimental features (e.g. custom rule set creation). */
    var experimentalEnabled: Boolean
        get() = prefs.getBoolean("experimentalEnabled", false)
        set(value) = prefs.edit { putBoolean("experimentalEnabled", value) }

    /**
     * Toggle for Remnawave-panel subscriptions that require an `x-hwid` header keyed
     * to this install. Off by default so the identifier is never sent unless the
     * user opts in.
     */
    var remnawaveHWIDEnabled: Boolean
        get() = prefs.getBoolean("remnawaveHWIDEnabled", false)
        set(value) = prefs.edit { putBoolean("remnawaveHWIDEnabled", value) }

    /**
     * Persistent per-install identifier used as the `x-hwid` header value for
     * Remnawave subscriptions. Generates a UUID on first read and reuses it
     * thereafter.
     */
    val deviceIdentifier: String
        get() {
            prefs.getString("identifier", null)?.let { return it }
            val generated = java.util.UUID.randomUUID().toString()
            prefs.edit { putString("identifier", generated) }
            return generated
        }

    /**
     * Signals a certificate policy change. LwipStack observes this key and
     * tears down active connections.
     */
    fun signalCertificatePolicyChanged() {
        prefs.edit { putLong("certificatePolicyChanged", System.currentTimeMillis()) }
    }

    val hasCompletedOnboarding: Boolean
        get() = prefs.getBoolean("hasCompletedOnboarding", false)

    fun completeOnboarding(bypassCountryCode: String, adBlockEnabled: Boolean) {
        if (bypassCountryCode.isNotEmpty()) {
            this.bypassCountryCode = bypassCountryCode
        }

        if (adBlockEnabled) {
            val adBlock = ruleSetRepository.ruleSets.value.find { it.id == "ADBlock" && !it.isCustom }
            if (adBlock != null) {
                ruleSetRepository.updateAssignment(adBlock, "REJECT")
            }
        }

        syncRoutingConfigurationToNE()

        prefs.edit { putBoolean("hasCompletedOnboarding", true) }
    }

    private fun checkOrphanedRuleSets() {
        val configIds = configRepository.getAll().map { it.id.toString() }.toSet()
        val orphaned = ruleSetRepository.clearOrphanedAssignments(configIds)
        if (orphaned.isNotEmpty()) {
            _orphanedRuleSetNames.value = orphaned
            syncRoutingConfigurationToNE()
        }
    }

    private companion object {
        /** One second: fast enough to read as live, slow enough to cost nothing. */
        const val STATS_POLL_MS = 1000L

        /** How long a stop may take to be confirmed before the UI gives up waiting. */
        const val DISCONNECT_WATCHDOG_MS = 3000L

        /** How often Auto re-measures a live group. */
        const val AUTO_RECHECK_MS = 2 * 60 * 1000L

        /** Head start the connect gets before the first measurement round. */
        const val AUTO_FIRST_ROUND_DELAY_MS = 1500L

        /** Connectivity probe: first check after the tunnel is up, then the cadence. */
        const val PROBE_FIRST_DELAY_MS = 2500L
        const val PROBE_INTERVAL_MS = 60 * 1000L

        /** A new best has to beat the current server by this much to be worth a switch. */
        const val AUTO_SWITCH_MARGIN_MS = 50

        /** At most this many unattended reconnects per window. */
        const val AUTO_RECONNECT_MAX = 4
        const val AUTO_RECONNECT_WINDOW_MS = 10 * 60 * 1000L
    }
}
