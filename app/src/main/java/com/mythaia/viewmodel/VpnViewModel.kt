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
import com.mythaia.data.network.WorkingServers
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import java.util.UUID
import kotlin.coroutines.coroutineContext
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload
import com.mythaia.vpn.util.file
import com.mythaia.vpn.util.load
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

    /**
     * The latency cache and the proxy server address list live apart from the
     * settings: with thousands of servers they made the settings file a
     * megabyte, rewritten (and waited for by the main thread) on every change
     * of any setting.
     */
    private val latencyPrefs: SharedPreferences =
        application.getSharedPreferences("mythaia_latency", Context.MODE_PRIVATE)
    private val addressPrefs: SharedPreferences =
        application.getSharedPreferences(com.mythaia.vpn.LwipStack.PROXY_ADDRESSES_PREFS, Context.MODE_PRIVATE)

    /** Stores the address list in order, off the main thread. */
    private val addressWriter = Dispatchers.Default.limitedParallelism(1)
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

    /**
     * Group id to the country its Auto keeps to (an ISO code), when the user
     * chose Auto on a country's section rather than on the whole group.
     */
    private val _autoCountry = MutableStateFlow(loadCountries())
    val autoCountry: StateFlow<Map<String, String>> = _autoCountry.asStateFlow()

    /** The server list in country sections; on unless the user turned it off. */
    private val _groupByCountry = MutableStateFlow(prefs.getBoolean(KEY_GROUP_BY_COUNTRY, true))
    val groupByCountry: StateFlow<Boolean> = _groupByCountry.asStateFlow()

    /** "groupId|code" of the country sections the user folded away. */
    private val _collapsedCountries = MutableStateFlow(prefs.getStringSet(KEY_COLLAPSED_COUNTRIES, null)?.toSet().orEmpty())
    val collapsedCountries: StateFlow<Set<String>> = _collapsedCountries.asStateFlow()

    /** Bumped once the GeoIP database is open, so the sections place what names alone could not. */
    private val _geoIpGeneration = MutableStateFlow(0)
    val geoIpGeneration: StateFlow<Int> = _geoIpGeneration.asStateFlow()

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

    /** The subscription being refreshed from the Proxies screen, for its spinner; null when none. */
    private val _updatingSubscriptionId = MutableStateFlow<UUID?>(null)
    val updatingSubscriptionId: StateFlow<UUID?> = _updatingSubscriptionId.asStateFlow()

    /** The bar at the bottom about a subscription refresh; null when there is nothing to say. */
    private val _subscriptionNotice = MutableStateFlow<SubscriptionNotice?>(null)
    val subscriptionNotice: StateFlow<SubscriptionNotice?> = _subscriptionNotice.asStateFlow()

    /** True while a subscription link is being downloaded for import. */
    private val _subscriptionImporting = MutableStateFlow(false)
    val subscriptionImporting: StateFlow<Boolean> = _subscriptionImporting.asStateFlow()

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
                // mythaia://import?url=…&front=…&sni=…: a subscription, its
                // fronting included, for the Add sheet to fill in.
                if (uri.host == "import") {
                    _pendingDeepLinkUrl.value =
                        com.mythaia.data.network.LinkExtractor.unwrap(uri.toString()) ?: return
                    return
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
        get() = when (_vpnStatus.value) {
            // A connect in flight stays tappable: the tap cancels it, and
            // that is the only way out of a DNS lookup or a measuring round
            // that takes half a minute to give up.
            VpnStatus.CONNECTING -> false
            VpnStatus.DISCONNECTING, VpnStatus.REASSERTING -> true
            else -> selectedConfiguration == null
        }

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
            // The reconnect window is deliberately not cleared here: a
            // server that comes up, stalls and drops over and over would
            // otherwise reset its own budget on every brief success.
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

    /**
     * The continuous part of Auto: while a tunnel is up on an Auto group,
     * re-measure every two minutes and move to the best server. Declared
     * ahead of `init`, which may start it: a property initialised after the
     * block would wipe the reference and leave the loop running unowned.
     */
    private var autoLoopJob: Job? = null

    /** The measuring round in flight, so a newer selection can cut it short. */
    private var autoRound: Job? = null

    /**
     * Whether the activity is on screen (between onStart and onStop). The view
     * model outlives a hidden activity, and its loops kept running behind it:
     * the per-second stats recomposed the home screen in the background, and
     * the per-minute probe and the Auto rounds woke the radio with the screen
     * off. They now do their work only while this is true; the service keeps
     * its own watch on the tunnel.
     */
    @Volatile
    private var uiVisible = true

    fun setUiVisible(visible: Boolean) {
        uiVisible = visible
        // Periodic Auto rounds belong to whoever can see the screen: this
        // view model while the activity shows, the service's engine otherwise.
        com.mythaia.vpn.AutoSelectEngine.uiVisible = visible
        if (visible) onBecameVisible()
    }

    /**
     * The screen just came up: what it shows must be current now, not after
     * the loops' next turn. Counters at once, a connectivity check at once
     * (it also finds the exit), and an Auto round if one is owed (one skipped
     * while hidden or with the screen off).
     */
    private fun onBecameVisible() {
        refreshSubscriptionsOnOpen()
        if (_vpnStatus.value != VpnStatus.CONNECTED) return
        if (statsJob != null && !statsTick()) stopStatsPolling()
        if (_vpnStatus.value != VpnStatus.CONNECTED) return
        startConnectivityProbe(firstDelayMs = 0L)
        val gid = _activeGroupId.value
        if (activeIsAuto && !_autoSelecting.value &&
            com.mythaia.vpn.AutoPolicy.roundDue(android.os.SystemClock.elapsedRealtime())
        ) {
            viewModelScope.launch { autoSelectFastest(gid) }
        }
    }

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
    private fun startConnectivityProbe(firstDelayMs: Long = PROBE_FIRST_DELAY_MS) {
        probeJob?.cancel()
        probeJob = viewModelScope.launch {
            var delayMs = firstDelayMs
            while (true) {
                delay(delayMs)
                delayMs = PROBE_INTERVAL_MS
                if (_vpnStatus.value != VpnStatus.CONNECTED) break
                if (!uiVisible) continue
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

    /**
     * Pings survive a restart for half an hour: the list opens with numbers
     * instead of blanks, and Auto has a first guess before it measures. Only
     * successes are kept; a failure from an hour ago says nothing now.
     */
    private fun restoreLatencyCache() {
        val raw = latencyPrefs.getString(LATENCY_CACHE_KEY, null)
            ?: prefs.getString(LATENCY_CACHE_KEY, null) // where it was before 1.0.2
            ?: return
        val now = System.currentTimeMillis()
        // One set, not a lookup per entry: that was a scan of the whole list
        // each, and with 10,000 cached servers the restore took seconds.
        val known = configRepository.getAll().mapTo(HashSet()) { it.id }
        val restored = raw.split(';').mapNotNull { entry ->
            val parts = entry.split(',')
            if (parts.size != 3) return@mapNotNull null
            val id = runCatching { UUID.fromString(parts[0]) }.getOrNull() ?: return@mapNotNull null
            val ms = parts[1].toIntOrNull() ?: return@mapNotNull null
            val at = parts[2].toLongOrNull() ?: return@mapNotNull null
            if (now - at > LATENCY_CACHE_TTL_MS || id !in known) null
            else id to (LatencyResult.Success(ms) as LatencyResult)
        }.toMap()
        if (restored.isNotEmpty()) _latencyResults.value = restored + _latencyResults.value
    }

    private fun startLatencyCachePersistence() {
        if (prefs.contains(LATENCY_CACHE_KEY)) prefs.edit { remove(LATENCY_CACHE_KEY) }
        // Off the main thread, and at most every few seconds: a run publishes
        // several times a second, and each write rebuilt the whole cache.
        viewModelScope.launch(Dispatchers.Default) {
            var stamps = HashMap<UUID, Pair<Int, Long>>()
            _latencyResults.collect { results ->
                val now = System.currentTimeMillis()
                val next = HashMap<UUID, Pair<Int, Long>>()
                for ((id, result) in results) {
                    if (result !is LatencyResult.Success) continue
                    val previous = stamps[id]
                    next[id] = if (previous != null && previous.first == result.ms) previous else result.ms to now
                }
                stamps = next
                latencyPrefs.edit {
                    putString(LATENCY_CACHE_KEY, next.entries.joinToString(";") { (id, v) -> "$id,${v.first},${v.second}" })
                }
                delay(LATENCY_CACHE_WRITE_MS)
            }
        }
    }

    /** Moves the address list out of the settings file, where builds before 1.0.2 kept it. */
    private fun migrateStoredAddresses() {
        val old = prefs.getString("proxyServerAddresses", null) ?: return
        if (!addressPrefs.contains("proxyServerAddresses")) {
            addressPrefs.edit { putString("proxyServerAddresses", old) }
        }
        prefs.edit { remove("proxyServerAddresses") }
    }

    init {
        migrateStoredAddresses()
        restoreLatencyCache()
        startLatencyCachePersistence()
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
        // service that was not already running. Adopted the same way
        // connect() adopts a tunnel started elsewhere: with the counters,
        // the probe and the Auto loop, and as a tunnel the user did not
        // stop — a status alone left Auto idle and a later drop unexplained.
        if (MythaiaVpnService.isActive) {
            userStopped = false
            onServiceActiveChanged(active = true)
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
        // The country sections place a server by its address when its name
        // says nothing; the tunnel opens the database only when it starts.
        viewModelScope.launch(Dispatchers.IO) {
            if (!com.mythaia.vpn.util.GeoIpDatabase.isLoaded && com.mythaia.vpn.util.GeoIpDatabase.file(application).exists()) {
                com.mythaia.vpn.util.GeoIpDatabase.load(application)
                if (com.mythaia.vpn.util.GeoIpDatabase.isLoaded) _geoIpGeneration.value++
            }
        }
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

    /**
     * Servers Auto may choose from: dialable, not a layer-3 interface, and in
     * the group's country when the user asked for Auto within one.
     */
    private fun autoCandidates(groupId: String): List<ProxyConfiguration> = com.mythaia.data.country.ServerCountry.keepTo(
        groupConfigs(groupId).filter { it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3 },
        _autoCountry.value[groupId]
    )

    /** Where [config] is, for the country sections; see [com.mythaia.data.country.ServerCountry]. */
    fun countryOf(config: ProxyConfiguration): String? = com.mythaia.data.country.ServerCountry.of(config)

    fun setGroupByCountry(enabled: Boolean) {
        prefs.edit { putBoolean(KEY_GROUP_BY_COUNTRY, enabled) }
        _groupByCountry.value = enabled
    }

    /** Folds or unfolds one country's section in one group; [code] null is the unplaced servers. */
    fun toggleCountryCollapsed(groupId: String, code: String?) {
        val key = countrySectionKey(groupId, code)
        val next = if (key in _collapsedCountries.value) _collapsedCountries.value - key else _collapsedCountries.value + key
        _collapsedCountries.value = next
        prefs.edit { putStringSet(KEY_COLLAPSED_COUNTRIES, next) }
    }

    fun countrySectionKey(groupId: String, code: String?): String = "$groupId|${code ?: "-"}"

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
        // Already the server on the wire — Auto's own pick, or the pinned row
        // tapped again: the pin still changes, the tunnel must not, since a
        // switch restarts the stack and drops every open connection. A chain
        // shares its exit's id, so a chain on the wire never counts as it.
        val alreadyLive = _vpnStatus.value == VpnStatus.CONNECTED &&
            _selectedChainId.value == null &&
            MythaiaVpnService.activeConfigId == config.id
        _selectedChainId.value = null
        prefs.edit { remove("selectedChainId") }
        _pinnedByGroup.value = _pinnedByGroup.value + (gid to config.id)
        savePins()
        _activeGroupId.value = gid
        prefs.edit { putString("activeGroupId", gid) }
        recomputeSelection()
        if (alreadyLive) updateAutoLoop() else applySelectionToTunnel(freshAuto = false)
    }

    /** Kept for callers that predate groups; a tap on a server pins it. */
    fun setSelectedConfiguration(config: ProxyConfiguration) = pinConfiguration(config)

    /** Lets [groupId] follow Auto again, over the whole group, and makes it the active group. */
    fun useAuto(groupId: String) {
        if (_autoCountry.value.containsKey(groupId)) {
            _autoCountry.value = _autoCountry.value - groupId
            saveCountries()
        }
        startAuto(groupId)
    }

    /**
     * Auto within one country of [groupId]: it measures and moves among that
     * country's servers only, until the user picks Auto for the whole group
     * (or a server) again.
     */
    fun useAutoIn(groupId: String, country: String) {
        _autoCountry.value = _autoCountry.value + (groupId to country)
        saveCountries()
        // A pick made over the whole group is most likely in another country.
        val previous = _autoChoice.value[groupId]?.let { configRepository.get(it) }
        if (previous != null && countryOf(previous) != country) _autoChoice.value = _autoChoice.value - groupId
        startAuto(groupId)
    }

    private fun startAuto(groupId: String) {
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
            startFreshAutoRound(_activeGroupId.value)
            return
        }
        selectedConfiguration?.let { switchConfig(it) }
    }

    /**
     * A round for a selection just made. The one in flight, if any, belongs
     * to the selection before it: it would block this one for its whole
     * length, and it moves the tunnel only while its own group is the active
     * one — so group B chosen during A's round sat on A's server until the
     * next due round. It is cut short, and waited for, so the new round
     * really starts (its flag clears only once it has unwound).
     */
    private fun startFreshAutoRound(groupId: String) {
        val previous = autoRound
        viewModelScope.launch {
            previous?.cancelAndJoin()
            autoSelectFastest(groupId)
        }
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
            ?: autoCandidates(gid).firstOrNull()?.id
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

    private fun loadCountries(): Map<String, String> {
        val raw = prefs.getString(com.mythaia.vpn.AutoPolicy.COUNTRIES_KEY, null) ?: return emptyMap()
        return runCatching { json.decodeFromString<Map<String, String>>(raw) }.getOrDefault(emptyMap())
    }

    private fun saveCountries() {
        prefs.edit { putString(com.mythaia.vpn.AutoPolicy.COUNTRIES_KEY, json.encodeToString(_autoCountry.value)) }
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
        // A big group is measured a sample at a time (see AutoPolicy.roundSample).
        val candidates = com.mythaia.vpn.AutoPolicy.roundSample(
            autoCandidates(groupId), MythaiaVpnService.activeConfigId, knownLatencies()
        )
        if (candidates.isEmpty()) return null

        _autoSelecting.value = true
        com.mythaia.vpn.AutoPolicy.markRound(android.os.SystemClock.elapsedRealtime())
        // The measuring is a job of its own rather than the caller's: a fresh
        // selection cancels it (see startFreshAutoRound), and that must not
        // take the caller — the Auto loop, the probe — down with it.
        val round = viewModelScope.async {
            try {
                measureGroup(groupId, candidates)
            } finally {
                _autoSelecting.value = false
                // Cut short, the servers never reached would spin for good.
                val ids = candidates.map { it.id }.toSet()
                _latencyResults.value = _latencyResults.value.filterNot { (id, result) ->
                    id in ids && result is LatencyResult.Testing
                }
            }
        }
        autoRound = round
        return try {
            round.await()
        } catch (e: CancellationException) {
            // The round was superseded; the caller itself goes on, with no pick.
            coroutineContext.ensureActive()
            null
        }
    }

    /** One round's measuring and moving; see [autoSelectFastest]. */
    private suspend fun measureGroup(groupId: String, candidates: List<ProxyConfiguration>): ProxyConfiguration? {
        _latencyKind.value = LatencyKind.HTTP
        syncProxyServerAddressesInBackground(candidates)
        markTesting(candidates)
        val published = LatencyBatch()

        val results = HashMap<UUID, Int>()
        // The server on the wire, and what we know about it so far. Kept
        // here rather than read back from the service on every result,
        // because a switch we just asked for takes a moment to land.
        var liveId: UUID? = MythaiaVpnService.activeConfigId
        var liveMs: Int? = null
        var liveFailed = _connectivityOk.value == false
        try {
            LatencyTester.testAll(candidates.map { applyGlobalAllowInsecure(it) }, LatencyKind.HTTP)
                .collect { (id, result) ->
                    published.add(id, result)
                    if (result is LatencyResult.Success) results[id] = result.ms

                    if (id == liveId) {
                        if (result is LatencyResult.Success) { liveMs = result.ms; liveFailed = false }
                        else if (result !is LatencyResult.Testing) liveFailed = true
                    }

                    // Real-time only when the wire is dead: move to the first
                    // server that answers. A live server that works waits for
                    // the end of the round, so a round moves the tunnel at
                    // most once (each move drops every open connection).
                    val canSwitch = groupId == _activeGroupId.value && activeIsAuto &&
                        _vpnStatus.value == VpnStatus.CONNECTED
                    if (canSwitch && result is LatencyResult.Success && id != liveId) {
                        val better = liveFailed || liveId == null
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
        } finally {
            published.flush()
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
                    com.mythaia.vpn.AutoPolicy.worthSwitching(liveNow, bestEntry.value)
                if (worthIt) switchConfig(winner)
            }
        }
        return winner
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
                delay(com.mythaia.vpn.AutoPolicy.DUE_CHECK_MS)
                if (_vpnStatus.value != VpnStatus.CONNECTED || !activeIsAuto) break
                // Hidden or screen off: the engine's turn, or nobody's.
                if (!uiVisible || !com.mythaia.vpn.AutoPolicy.mayMeasure(getApplication())) continue
                // A round from either side counts: see AutoPolicy.roundDue.
                if (!com.mythaia.vpn.AutoPolicy.roundDue(android.os.SystemClock.elapsedRealtime())) continue
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
        // rebuild the same one. The user asked for it, so it is theirs to
        // keep up — a drop from here on is a failure, not a stop.
        if (MythaiaVpnService.isActive) {
            userStopped = false
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

    /**
     * The previous counter reading, for the rates. -1 until there is one:
     * seeded from a first reading rather than zero, so rebinding to a tunnel
     * that has been up for hours does not report all of its traffic as one
     * second's worth, and reseeded whenever the screen was hidden.
     */
    private var statsLastIn = -1L
    private var statsLastOut = -1L

    private fun startStatsPolling() {
        if (statsJob != null) return
        statsJob = viewModelScope.launch {
            statsLastIn = -1L
            statsLastOut = -1L
            while (true) {
                delay(STATS_POLL_MS)
                if (!uiVisible) {
                    // Nobody is looking: skip the update (each one recomposes
                    // the home screen) and reseed, so the first reading back
                    // is not the whole hidden stretch counted as one second.
                    statsLastIn = -1L
                    statsLastOut = -1L
                    continue
                }
                if (!statsTick()) {
                    statsJob = null
                    break
                }
            }
        }
    }

    /**
     * One reading of the tunnel's counters into the live readouts. False when
     * the service turned out to have died, which ends the polling. Runs on the
     * main thread, from the loop and when the screen comes back.
     */
    private fun statsTick(): Boolean {
        val service = vpnService
        if (service != null && service.isRunning) {
            val (bytesIn, bytesOut) = service.getStats()

            if (statsLastIn >= 0) {
                val seconds = STATS_POLL_MS / 1000.0
                // A counter that went backwards means the stack
                // restarted; report nothing rather than a negative rate.
                _downloadSpeed.value =
                    ((bytesIn - statsLastIn).coerceAtLeast(0L) / seconds).toLong()
                _uploadSpeed.value =
                    ((bytesOut - statsLastOut).coerceAtLeast(0L) / seconds).toLong()
            } else {
                // No baseline yet (first reading, or back from hidden): the rate
                // from before is stale, so show none until the next tick.
                _downloadSpeed.value = 0
                _uploadSpeed.value = 0
            }
            statsLastIn = bytesIn
            statsLastOut = bytesOut

            _bytesIn.value = bytesIn
            _bytesOut.value = bytesOut
            _uptimeSeconds.value = service.uptimeSeconds
        } else if (service != null && !service.isRunning &&
            _vpnStatus.value == VpnStatus.CONNECTED) {
            // Service is bound but no longer running — it actually died
            _vpnStatus.value = VpnStatus.DISCONNECTED
            resetStats()
            unbindFromService()
            return false
        }
        // If service is null, binding is still in progress — keep polling
        return true
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
        com.mythaia.vpn.AutoSelectEngine.uiVisible = false
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

    /** Adds a pasted list in one go: one change of the store, one save. */
    fun addConfigurations(configs: List<ProxyConfiguration>) {
        if (configs.isEmpty()) return
        configRepository.addAll(configs)
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

    /**
     * The servers of [groupId] that did not work on their last check: no
     * answer, or a certificate that does not verify. A server never checked
     * is not among them.
     */
    fun failedIn(groupId: String): List<ProxyConfiguration> {
        val results = _latencyResults.value
        return groupConfigs(groupId).filter {
            val result = results[it.id]
            result is LatencyResult.Failed || result is LatencyResult.Insecure
        }
    }

    /** Removes the servers of [groupId] that failed their last check; returns how many went. */
    fun removeFailed(groupId: String): Int {
        val failed = failedIn(groupId)
        deleteConfigurations(failed)
        return failed.size
    }

    /**
     * Deletes several servers in one change of the store, with what
     * [deleteConfiguration] does for one: a chain left without a hop is
     * dropped, a subscription left empty goes with it, and a tunnel on a
     * deleted server moves to what is selected now.
     */
    fun deleteConfigurations(configs: List<ProxyConfiguration>) {
        if (configs.isEmpty()) return
        val ids = configs.mapTo(HashSet()) { it.id }
        val wasLive = _vpnStatus.value == VpnStatus.CONNECTED &&
            (_selectedConfigId.value in ids || selectedConfiguration?.chain?.any { it.id in ids } == true)

        configRepository.deleteAll(ids)
        _latencyResults.value = _latencyResults.value - ids
        val chainId = _selectedChainId.value
        if (chainId != null) {
            val chain = chainRepository.get(chainId)
            if (chain == null || resolveChain(chain) == null) {
                _selectedChainId.value = null
                prefs.edit { remove("selectedChainId") }
            }
        }
        val remaining = configRepository.getAll().mapNotNullTo(HashSet()) { it.subscriptionId }
        configs.mapNotNullTo(HashSet()) { it.subscriptionId }
            .filter { it !in remaining }
            .forEach { subId -> subscriptionRepository.get(subId)?.let { subscriptionRepository.delete(subId, configRepository) } }

        recomputeSelection()
        checkOrphanedRuleSets()
        if (wasLive) {
            val next = selectedConfiguration
            if (next != null) switchConfig(next) else disconnect()
        }
    }

    /**
     * [configs] as share links, one per line, in the form every client
     * imports. Returns the text and how many servers have no link form.
     */
    fun exportLinks(configs: List<ProxyConfiguration>): Pair<String, Int> {
        var skipped = 0
        val links = configs.mapNotNull { config ->
            runCatching { config.toUrl() }.getOrNull().also { if (it == null) skipped++ }
        }
        return links.joinToString("\n") to skipped
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

    /**
     * @param via a server to fetch through, for a panel this network cannot reach.
     * @param timeoutMs overrides how long the panel gets.
     */
    suspend fun updateSubscription(
        subscription: Subscription,
        via: ProxyConfiguration? = null,
        timeoutMs: Int? = null
    ) {
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
            remnawaveHWID = hwid,
            via = via,
            timeoutMs = timeoutMs
        )

        recomputeSelection()
        // A panel that renames a server gives it a fresh id, which orphans any
        // rule set assigned to it. Without this the assignment points at a dead
        // id, the user is never told, and that rule set silently stops routing.
        checkOrphanedRuleSets()
        syncRoutingConfigurationToNE()
    }

    /**
     * [updateSubscription] in this view model's own scope, with the spinner
     * and the failure as state. Launched from the screen it used to go down
     * with a tab switch, halfway and without a word.
     */
    fun refreshSubscription(subscription: Subscription) {
        if (_updatingSubscriptionId.value != null) return
        _updatingSubscriptionId.value = subscription.id
        viewModelScope.launch {
            try {
                updateSubscription(subscription)
                if (_subscriptionNotice.value?.subscriptionId == subscription.id) _subscriptionNotice.value = null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                reportSubscriptionFailure(subscription, e)
            } finally {
                _updatingSubscriptionId.value = null
            }
        }
    }

    private fun reportSubscriptionFailure(subscription: Subscription, e: Exception) {
        _subscriptionNotice.value = SubscriptionNotice.Failed(
            subscriptionId = subscription.id,
            name = subscription.name,
            message = e.message ?: getApplication<Application>().getString(R.string.unknown_error),
            // A panel that answered with nothing usable would say the same
            // through any server; only a failure to reach it is worth a detour.
            canRetry = e !is SubscriptionFetcher.FetchError.NoConfigurations &&
                e !is SubscriptionFetcher.FetchError.InvalidUrl
        )
    }

    fun dismissSubscriptionNotice() {
        _subscriptionNotice.value = null
    }

    /**
     * Fetches [subscriptionId] through a server that works, for a panel this
     * network cannot reach: the live server first, then the first servers to
     * pass a fresh check, the subscription's own before the rest.
     */
    fun refreshSubscriptionThroughServer(subscriptionId: UUID) {
        val subscription = subscriptionRepository.get(subscriptionId) ?: return
        if (_updatingSubscriptionId.value != null) return
        _updatingSubscriptionId.value = subscriptionId
        _subscriptionNotice.value = SubscriptionNotice.Retrying(subscriptionId, subscription.name)
        viewModelScope.launch {
            var lastError: Exception? = null
            try {
                for (server in serversThatWork(subscriptionId)) {
                    try {
                        updateSubscription(subscription, via = applyGlobalAllowInsecure(server), timeoutMs = THROUGH_SERVER_TIMEOUT_MS)
                        logger.info("[Sub] ${subscription.name} updated through ${server.name}")
                        _subscriptionNotice.value = SubscriptionNotice.UpdatedThrough(subscriptionId, subscription.name, server.name)
                        return@launch
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: SubscriptionFetcher.FetchError.NoConfigurations) {
                        // The panel was reached and had nothing; another server will not change that.
                        lastError = e
                        break
                    } catch (e: Exception) {
                        logger.warning("[Sub] ${subscription.name} through ${server.name} failed: ${e.message ?: e}")
                        lastError = e
                    }
                }
                val app = getApplication<Application>()
                _subscriptionNotice.value = SubscriptionNotice.Failed(
                    subscriptionId = subscriptionId,
                    name = subscription.name,
                    message = lastError?.let { app.getString(R.string.subscription_failed_through_servers, it.message ?: app.getString(R.string.unknown_error)) }
                        ?: app.getString(R.string.subscription_no_working_server),
                    canRetry = false
                )
            } finally {
                _updatingSubscriptionId.value = null
            }
        }
    }

    /** Servers to fetch [subscriptionId] through, checked just now; see [WorkingServers]. */
    private suspend fun serversThatWork(subscriptionId: UUID): List<ProxyConfiguration> {
        val all = configRepository.getAll()
        val live = if (_vpnStatus.value == VpnStatus.CONNECTED && _connectivityOk.value != false) {
            MythaiaVpnService.activeConfigId?.let { id -> all.firstOrNull { it.id == id } }
        } else null
        return WorkingServers.find(
            live = live,
            candidates = WorkingServers.candidates(all, subscriptionId, _latencyResults.value),
            prepare = { applyGlobalAllowInsecure(it) },
            onResult = { id, result -> _latencyResults.value = _latencyResults.value + (id to result) }
        )
    }

    /** Subscription ids whose failure the bar has already shown this session. */
    private val failuresShown = HashSet<UUID>()
    private var openRefreshAt = 0L

    /**
     * The app came up: refresh what the panel asked to have refreshed on
     * every open (`subscription-auto-update-open-enable`), then speak up for a
     * subscription that keeps failing, in the background or by hand.
     */
    private fun refreshSubscriptionsOnOpen() {
        val now = System.currentTimeMillis()
        // Back from a share sheet or the permission screen is not an open.
        if (now - openRefreshAt < OPEN_REFRESH_GAP_MS) return
        openRefreshAt = now
        viewModelScope.launch {
            for (subscription in subscriptionRepository.getAll().filter { it.updateOnOpen }) {
                if (_updatingSubscriptionId.value != null) continue
                _updatingSubscriptionId.value = subscription.id
                try {
                    updateSubscription(subscription)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    logger.warning("[Sub] Refresh on open failed for ${subscription.name}: ${e.message ?: e}")
                } finally {
                    _updatingSubscriptionId.value = null
                }
            }
            if (_subscriptionNotice.value != null) return@launch
            val failing = subscriptionRepository.getAll().firstOrNull { it.isFailing && it.id !in failuresShown }
                ?: return@launch
            failuresShown += failing.id
            _subscriptionNotice.value = SubscriptionNotice.Failed(
                subscriptionId = failing.id,
                name = failing.name,
                message = failing.lastFailureMessage ?: getApplication<Application>().getString(R.string.unknown_error),
                canRetry = true
            )
        }
    }

    /**
     * Downloads [url] and builds the subscription for it, then hands both to
     * [onImported] — or the reason to [onFailed] — on the main thread.
     *
     * Runs here rather than in the Add sheet's scope: importing a pasted list
     * closes the sheet on its first proxy link, and a download launched from
     * the sheet was cancelled with it, so the subscription was never added.
     */
    fun importSubscription(
        url: String,
        withRemnawaveHWID: Boolean,
        frontSni: String?,
        frontTargets: List<String>,
        onImported: (List<ProxyConfiguration>, Subscription) -> Unit,
        onFailed: (String) -> Unit,
        /** A name the link itself gave the group; it wins over the panel's. */
        name: String? = null
    ) {
        _subscriptionImporting.value = true
        viewModelScope.launch {
            try {
                val hwid = if (withRemnawaveHWID) deviceIdentifier else null
                val result = SubscriptionFetcher.fetch(
                    url, remnawaveHWID = hwid, frontSni = frontSni, frontTargets = frontTargets
                )
                val linkName = name?.trim()?.takeIf { it.isNotEmpty() }
                val groupName = linkName
                    ?: result.name
                    ?: runCatching { URL(url).host }.getOrNull()
                    ?: getApplication<Application>().getString(R.string.subscription)
                // Everything else the panel said, as a refresh would record it.
                val subscription = com.mythaia.data.network.SubscriptionMetadata.applyTo(
                    Subscription(
                        name = groupName,
                        url = url,
                        isNameCustomized = linkName != null,
                        frontSni = frontSni,
                        frontTargets = frontTargets
                    ),
                    result
                )
                onImported(result.configurations, subscription)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                onFailed(e.message ?: getApplication<Application>().getString(R.string.import_failed))
            } finally {
                _subscriptionImporting.value = false
            }
        }
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
        if (_latencyKind.value != kind) {
            _latencyKind.value = kind
            _latencyResults.value = emptyMap()
        }
        markTesting(forConfigs)
        viewModelScope.launch {
            // Before the first dial: the servers' names must get real answers.
            syncProxyServerAddressesInBackground(forConfigs)
            val published = LatencyBatch()
            try {
                LatencyTester.testAll(forConfigs.map { applyGlobalAllowInsecure(it) }, kind).collect { (id, result) ->
                    published.add(id, result)
                }
            } finally {
                published.flush()
            }
        }
    }

    /** Marks [configs] as being measured, in one update of the map rather than one per server. */
    private fun markTesting(configs: List<ProxyConfiguration>) {
        _latencyResults.value = _latencyResults.value + configs.associate { it.id to LatencyResult.Testing }
    }

    /** The last successful time of every server measured so far. */
    private fun knownLatencies(): Map<UUID, Int> =
        _latencyResults.value.mapNotNull { (id, result) -> (result as? LatencyResult.Success)?.let { id to it.ms } }.toMap()

    /**
     * Publishes the results of one measuring run in batches. Copying the
     * whole map once per result was quadratic work on the main thread: a
     * group of 10,000 servers froze the app into "not responding". Results
     * are gathered here and land at most every [LATENCY_FLUSH_MS], so the
     * list still fills in live.
     */
    private inner class LatencyBatch {
        private val pending = HashMap<UUID, LatencyResult>()
        private var flushedAt = 0L

        fun add(id: UUID, result: LatencyResult) {
            pending[id] = result
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - flushedAt >= LATENCY_FLUSH_MS) flush(now)
        }

        fun flush(now: Long = android.os.SystemClock.elapsedRealtime()) {
            flushedAt = now
            if (pending.isEmpty()) return
            _latencyResults.value = _latencyResults.value + pending
            pending.clear()
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
        val wasLive = _vpnStatus.value == VpnStatus.CONNECTED && _selectedChainId.value == chain.id
        chainRepository.delete(chain.id)
        if (_selectedChainId.value == chain.id) {
            _selectedChainId.value = null
            prefs.edit { remove("selectedChainId") }
            recomputeSelection()
            updateAutoLoop()
            // Traffic was going through the deleted chain: move it to what is
            // selected now, or stop, as deleting a server or a subscription does.
            if (wasLive) {
                val next = selectedConfiguration
                if (next != null) switchConfig(next) else disconnect()
            }
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
        publishProxyServerAddresses(allProxyServerAddresses(configurations))
    }

    /**
     * The same for a whole group, with the collecting off the main thread:
     * thousands of servers make it megabytes of work. Returns once the
     * service has the list, so the dials that follow resolve correctly.
     */
    private suspend fun syncProxyServerAddressesInBackground(configurations: List<ProxyConfiguration>) {
        publishProxyServerAddresses(withContext(Dispatchers.Default) { allProxyServerAddresses(configurations) })
    }

    private fun allProxyServerAddresses(configurations: List<ProxyConfiguration>): List<String> {
        val addresses = linkedSetOf<String>()
        for (config in configurations) {
            collectProxyServerAddresses(config, addresses)
        }
        return addresses.toList()
    }

    private fun publishProxyServerAddresses(addresses: List<String>) {
        vpnService?.updateProxyServerAddresses(addresses)
        viewModelScope.launch(addressWriter) {
            addressPrefs.edit { putString("proxyServerAddresses", json.encodeToString(addresses)) }
        }
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
        private const val KEY_GROUP_BY_COUNTRY = "groupByCountry"
        private const val KEY_COLLAPSED_COUNTRIES = "collapsedCountries"
        private const val LATENCY_CACHE_KEY = "latencyCache"
        private const val LATENCY_CACHE_WRITE_MS = 3_000L
        private const val LATENCY_FLUSH_MS = 250L
        private const val LATENCY_CACHE_TTL_MS = 30 * 60_000L

        /** One second: fast enough to read as live, slow enough to cost nothing. */
        const val STATS_POLL_MS = 1000L

        /** How long a stop may take to be confirmed before the UI gives up waiting. */
        const val DISCONNECT_WATCHDOG_MS = 3000L

        /** How often Auto re-measures a live group; see [com.mythaia.vpn.AutoPolicy]. */
        const val AUTO_RECHECK_MS = com.mythaia.vpn.AutoPolicy.RECHECK_MS

        /** Head start the connect gets before the first measurement round. */
        const val AUTO_FIRST_ROUND_DELAY_MS = 1500L

        /** Connectivity probe: first check after the tunnel is up, then the cadence. */
        const val PROBE_FIRST_DELAY_MS = 2500L
        const val PROBE_INTERVAL_MS = 60 * 1000L

        /** At most this many unattended reconnects per window. */
        const val AUTO_RECONNECT_MAX = 4
        const val AUTO_RECONNECT_WINDOW_MS = 10 * 60 * 1000L

        /** How long the panel gets through each server tried. */
        const val THROUGH_SERVER_TIMEOUT_MS = 20_000

        /** Coming back sooner than this is not opening the app (refresh on open). */
        const val OPEN_REFRESH_GAP_MS = 5 * 60 * 1000L
    }
}
