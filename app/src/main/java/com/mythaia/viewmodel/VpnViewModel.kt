package com.mythaia.viewmodel

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
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionDomainHelper
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.data.network.SubscriptionRefreshScheduler
import com.mythaia.data.network.SubscriptionUpdater
import com.mythaia.data.repository.CertificateRepository
import com.mythaia.data.repository.ChainRepository
import com.mythaia.data.repository.ConfigRepository
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

enum class VpnStatus {
    DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, REASSERTING
}

private val logger = MythaiaLogger("VPNViewModel")

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    val configRepository = ConfigRepository(application)
    val subscriptionRepository = SubscriptionRepository(application)
    val ruleSetRepository = RuleSetRepository(application)
    val certificateRepository = CertificateRepository(application)
    val chainRepository = ChainRepository(application)

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

    private val _selectedConfigId = MutableStateFlow<UUID?>(null)
    val selectedConfigId: StateFlow<UUID?> = _selectedConfigId.asStateFlow()

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

    var onRequestVpnPermission: ((Intent) -> Unit)? = null

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
            "vless", "trojan", "ss", "socks5", "socks", "hysteria2", "hy2", "anytls" -> {
                _pendingDeepLinkUrl.value = uri.toString()
            }
            else -> {}
        }
    }

    fun consumePendingDeepLink() {
        _pendingDeepLinkUrl.value = null
    }

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
            } else if (_vpnStatus.value == VpnStatus.CONNECTING) {
                // Service bound but tunnel setup failed (e.g. TUN establish
                // failed) — don't leave the UI stuck on the spinner.
                _vpnStatus.value = VpnStatus.DISCONNECTED
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

    init {
        val savedChainId = prefs.getString("selectedChainId", null)?.let {
            runCatching { UUID.fromString(it) }.getOrNull()
        }
        if (savedChainId != null && chainRepository.get(savedChainId) != null) {
            _selectedChainId.value = savedChainId
        } else {
            prefs.getString("selectedConfigurationId", null)?.let { id ->
                _selectedConfigId.value = runCatching { UUID.fromString(id) }.getOrNull()
            }
        }
        ensureValidSelection()

        // Prime CertificatePolicy with the current allowInsecure + trusted-certificate
        // values so TLS validation has a fresh snapshot before the first connection.
        CertificatePolicy.reload(application)
        FragmentPolicy.reload(application)
        EncryptedDnsPolicy.reload(application)
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

    fun setSelectedConfiguration(config: ProxyConfiguration) {
        _selectedChainId.value = null
        prefs.edit().remove("selectedChainId").apply()
        _selectedConfigId.value = config.id
        prefs.edit().putString("selectedConfigurationId", config.id.toString()).apply()

        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            switchConfig(config)
        }
    }

    fun toggleVPN() {
        when (_vpnStatus.value) {
            VpnStatus.DISCONNECTED -> connect()
            VpnStatus.CONNECTED, VpnStatus.CONNECTING -> disconnect()
            else -> {}
        }
    }

    fun connect() {
        val config = selectedConfiguration ?: return
        val context = getApplication<Application>()

        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            pendingConnectAfterPermission = true
            onRequestVpnPermission?.invoke(prepareIntent)
            return
        }

        startVpnService(config)
    }

    fun onVpnPermissionGranted() {
        if (pendingConnectAfterPermission) {
            pendingConnectAfterPermission = false
            val config = selectedConfiguration ?: return
            startVpnService(config)
        }
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

        viewModelScope.launch {
            // Resolve server domain on IO thread (avoids NetworkOnMainThreadException)
            val resolvedConfig = withContext(Dispatchers.IO) {
                // Write routing.json (DNS + disk I/O) before the service starts
                // so it reads fresh rules.
                syncRoutingConfigurationBlocking()
                resolveServerAddress(applyGlobalAllowInsecure(config))
            }
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
                // + `isRunning`.
                bindToService()
            } catch (e: Exception) {
                logger.warning("Failed to send configuration to tunnel: ${e.message}")
                _vpnStatus.value = VpnStatus.DISCONNECTED
                _startError.value = e.message
            }
        }
    }

    fun disconnect() {
        _vpnStatus.value = VpnStatus.DISCONNECTING
        val context = getApplication<Application>()

        stopStatsPolling()

        val intent = Intent(context, MythaiaVpnService::class.java).apply {
            action = MythaiaVpnService.ACTION_STOP
        }
        try {
            context.startService(intent)
        } catch (_: Exception) {}

        unbindFromService()
        _bytesIn.value = 0
        _bytesOut.value = 0
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
            while (true) {
                delay(1000)
                val service = vpnService
                if (service != null && service.isRunning) {
                    val (bytesIn, bytesOut) = service.getStats()
                    _bytesIn.value = bytesIn
                    _bytesOut.value = bytesOut
                } else if (service != null && !service.isRunning &&
                    _vpnStatus.value == VpnStatus.CONNECTED) {
                    // Service is bound but no longer running — it actually died
                    _vpnStatus.value = VpnStatus.DISCONNECTED
                    _bytesIn.value = 0
                    _bytesOut.value = 0
                    break
                }
                // If service is null, binding is still in progress — keep polling
            }
        }
    }

    private fun stopStatsPolling() {
        statsJob?.cancel()
        statsJob = null
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
        if (_selectedConfigId.value == null) {
            setSelectedConfiguration(config)
        }
    }

    fun updateConfiguration(config: ProxyConfiguration) {
        configRepository.update(config)
    }

    fun deleteConfiguration(config: ProxyConfiguration) {
        configRepository.delete(config.id)
        if (_selectedConfigId.value == config.id) {
            val remaining = configRepository.getAll()
            _selectedConfigId.value = remaining.firstOrNull()?.id
            prefs.edit().putString("selectedConfigurationId", _selectedConfigId.value?.toString()).apply()
        }
        val chainId = _selectedChainId.value
        if (chainId != null) {
            val chain = chainRepository.get(chainId)
            if (chain == null || resolveChain(chain) == null) {
                _selectedChainId.value = null
                prefs.edit().remove("selectedChainId").apply()
                ensureValidSelection()
            }
        }
        checkOrphanedRuleSets()
    }

    fun configurations(forSubscription: Subscription): List<ProxyConfiguration> {
        return configRepository.getAll().filter { it.subscriptionId == forSubscription.id }
    }

    fun addSubscription(configurations: List<ProxyConfiguration>, subscription: Subscription) {
        subscriptionRepository.add(subscription)
        configurations.forEach { config ->
            configRepository.add(config.copy(subscriptionId = subscription.id))
        }
        if (_selectedConfigId.value == null) {
            configurations.firstOrNull()?.let { setSelectedConfiguration(it) }
        }
    }

    fun toggleSubscriptionCollapsed(subscription: Subscription) {
        subscriptionRepository.update(subscription.copy(collapsed = !subscription.collapsed))
    }

    fun renameSubscription(subscription: Subscription, newName: String) {
        subscriptionRepository.update(subscription.copy(name = newName, isNameCustomized = true))
    }

    fun deleteSubscription(subscription: Subscription) {
        subscriptionRepository.delete(subscription.id, configRepository)
        ensureValidSelection()
        checkOrphanedRuleSets()
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

        ensureValidSelection()
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

    fun testLatency(forConfig: ProxyConfiguration) {
        syncProxyServerAddresses(forConfig)
        _latencyResults.value = _latencyResults.value + (forConfig.id to LatencyResult.Testing)
        viewModelScope.launch {
            val result = LatencyTester.test(applyGlobalAllowInsecure(forConfig))
            _latencyResults.value = _latencyResults.value + (forConfig.id to result)
        }
    }

    /** Tests latency for a specific set of configurations. The caller filters
     *  out collapsed subscriptions before invoking — we don't filter here. */
    fun testLatencies(forConfigs: List<ProxyConfiguration>) {
        if (forConfigs.isEmpty()) return
        syncProxyServerAddresses(forConfigs)
        forConfigs.forEach { config ->
            _latencyResults.value = _latencyResults.value + (config.id to LatencyResult.Testing)
        }
        viewModelScope.launch {
            LatencyTester.testAll(forConfigs.map { applyGlobalAllowInsecure(it) }).collect { (id, result) ->
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
            prefs.edit().remove("selectedChainId").apply()
            ensureValidSelection()
        }
    }

    fun selectChain(chain: ProxyChain) {
        val resolved = resolveChain(chain) ?: return
        _selectedChainId.value = chain.id
        prefs.edit()
            .putString("selectedChainId", chain.id.toString())
            .remove("selectedConfigurationId")
            .apply()
        _selectedConfigId.value = null

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
        if (_vpnStatus.value == VpnStatus.CONNECTED) {
            prefs.edit().putLong("routingChanged", System.currentTimeMillis()).apply()
        }
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
        prefs.edit().putString("proxyServerAddresses", json.encodeToString(persisted)).apply()
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
        set(value) = prefs.edit().putString("proxyMode", value).apply()

    var bypassCountryCode: String
        get() = prefs.getString("bypassCountryCode", "") ?: ""
        set(value) = prefs.edit().putString("bypassCountryCode", value).apply()

    /**
     * IPv6 DNS lookup toggle — a single knob that controls both IPv6 routes
     * in the TUN interface and fake-IPv6 answers for AAAA queries. When off,
     * IPv6 is effectively disabled.
     */
    var ipv6DnsEnabled: Boolean
        get() = prefs.getBoolean("ipv6DnsEnabled", false)
        set(value) = prefs.edit().putBoolean("ipv6DnsEnabled", value).apply()

    var encryptedDnsEnabled: Boolean
        get() = prefs.getBoolean("encryptedDnsEnabled", false)
        set(value) = prefs.edit().putBoolean("encryptedDnsEnabled", value).apply()

    var encryptedDnsProtocol: String
        get() = prefs.getString("encryptedDnsProtocol", "doh") ?: "doh"
        set(value) = prefs.edit().putString("encryptedDnsProtocol", value).apply()

    var encryptedDnsServer: String
        get() = prefs.getString("encryptedDnsServer", "") ?: ""
        set(value) = prefs.edit().putString("encryptedDnsServer", value).apply()

    /**
     * When true, drop UDP/443 traffic with ICMP port-unreachable so HTTP/3 clients
     * fall back to HTTP/2. Defaults to true.
     */
    var blockQuicEnabled: Boolean
        get() = prefs.getBoolean("blockQuicEnabled", true)
        set(value) = prefs.edit().putBoolean("blockQuicEnabled", value).apply()

    var allowInsecure: Boolean
        get() = prefs.getBoolean("allowInsecure", false)
        set(value) {
            if (value == allowInsecure) return
            prefs.edit().putBoolean("allowInsecure", value).apply()
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
        set(value) = prefs.edit().putBoolean("experimentalEnabled", value).apply()

    /**
     * Toggle for Remnawave-panel subscriptions that require an `x-hwid` header keyed
     * to this install. Off by default so the identifier is never sent unless the
     * user opts in.
     */
    var remnawaveHWIDEnabled: Boolean
        get() = prefs.getBoolean("remnawaveHWIDEnabled", false)
        set(value) = prefs.edit().putBoolean("remnawaveHWIDEnabled", value).apply()

    /**
     * Persistent per-install identifier used as the `x-hwid` header value for
     * Remnawave subscriptions. Generates a UUID on first read and reuses it
     * thereafter.
     */
    val deviceIdentifier: String
        get() {
            prefs.getString("identifier", null)?.let { return it }
            val generated = java.util.UUID.randomUUID().toString()
            prefs.edit().putString("identifier", generated).apply()
            return generated
        }

    /**
     * Signals a certificate policy change. LwipStack observes this key and
     * tears down active connections.
     */
    fun signalCertificatePolicyChanged() {
        prefs.edit().putLong("certificatePolicyChanged", System.currentTimeMillis()).apply()
    }

    val hasCompletedOnboarding: Boolean
        get() = prefs.getBoolean("hasCompletedOnboarding", false)

    fun completeOnboarding(bypassCountryCode: String, adBlockEnabled: Boolean) {
        if (bypassCountryCode.isNotEmpty()) {
            this.bypassCountryCode = bypassCountryCode
        }

        if (adBlockEnabled) {
            val adBlock = ruleSetRepository.ruleSets.value.find { it.name == "ADBlock" }
            if (adBlock != null) {
                ruleSetRepository.updateAssignment(adBlock, "REJECT")
            }
        }

        syncRoutingConfigurationToNE()

        prefs.edit().putBoolean("hasCompletedOnboarding", true).apply()
    }

    private fun ensureValidSelection() {
        val selectedId = _selectedConfigId.value
        if (selectedId == null || configRepository.get(selectedId) == null) {
            val newId = configRepository.getAll().firstOrNull()?.id
            _selectedConfigId.value = newId
            prefs.edit().putString("selectedConfigurationId", newId?.toString()).apply()
        }
    }

    private fun checkOrphanedRuleSets() {
        val configIds = configRepository.getAll().map { it.id.toString() }.toSet()
        val orphaned = ruleSetRepository.clearOrphanedAssignments(configIds)
        if (orphaned.isNotEmpty()) {
            _orphanedRuleSetNames.value = orphaned
            syncRoutingConfigurationToNE()
        }
    }
}
