package com.mythaia.vpn

import kotlinx.coroutines.launch
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.ParcelFileDescriptor
import com.mythaia.MainActivity
import com.mythaia.R
import com.mythaia.data.model.ProxyConfiguration
import android.content.pm.PackageManager
import com.mythaia.data.model.SplitTunnelMode
import com.mythaia.data.model.SplitTunnelSettings
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.LogBuffer
import kotlinx.serialization.json.Json
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload

/**
 * Android VPN service that creates a TUN interface, runs the lwIP TCP/IP stack,
 * and routes traffic through VLESS proxy connections.
 */
private val logger = MythaiaLogger("PacketTunnel")

class MythaiaVpnService : VpnService() {

    private var lwipStack: LwipStack? = null

    /**
     * The WireGuard interface, when the active profile is a layer-3 one.
     *
     * Exactly one of this and [lwipStack] is ever set: WireGuard carries whole
     * IP packets, so there is no lwIP stack under it to terminate flows.
     */
    private var wireGuardTunnel: com.mythaia.vpn.protocol.wireguard.WireGuardTunnel? = null

    /** The parsed profile behind [wireGuardTunnel], for rebuilding its TUN. */
    private var wireGuardSettings: com.mythaia.vpn.protocol.wireguard.WireGuardConfig? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var currentConfig: ProxyConfiguration? = null

    // Bumped on every startVpn(). A stopVpn() captures the current value and the
    // deferred finishStopVpn() (which runs later on the lwIP executor) compares it
    // so a stop scheduled for an OLD session can never tear down a session that
    // started after it (fast disconnect→connect toggle / reconnect()).
    @Volatile
    private var sessionGeneration = 0
    private val json = Json { ignoreUnknownKeys = true }

    // Tracks the most recent underlying (non-VPN) network so we can detect
    // path changes (e.g. Wi-Fi → Cellular) and restart the lwIP stack to
    // replace stale connections bound to the old interface.
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var lastUnderlyingNetwork: Network? = null
    private var lastUnderlyingTransports: Int = 0
    private var lastNetworkAvailable: Boolean = false

    // Screen on/off used to approximate device-level sleep — Android doesn't
    // expose sleep/wake callbacks on a foreground VpnService directly, so we
    // listen on `ACTION_SCREEN_OFF` / `ACTION_SCREEN_ON` (or `ACTION_USER_PRESENT`
    // on locked devices) and infer the duration the device spent in low-power
    // doze. Long sleeps (≥ wakeRestartThresholdSecs) trigger a stack restart so
    // stale connections bound to a NAT entry that has since timed out get
    // replaced instead of waiting for keep-alive failures.
    private var screenStateReceiver: BroadcastReceiver? = null
    private var sleepTimestampMillis: Long = 0L

    // Binder for activity communication
    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: MythaiaVpnService get() = this@MythaiaVpnService
    }

    override fun onBind(intent: Intent?): IBinder {
        return if (intent?.action == SERVICE_INTERFACE) {
            // System binding for VPN
            super.onBind(intent)!!
        } else {
            // Activity binding
            binder
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG)
                if (configJson == null) {
                    failStart(getString(R.string.tunnel_error_invalid_config))
                    return START_NOT_STICKY
                }

                val config = runCatching {
                    json.decodeFromString(ProxyConfiguration.serializer(), configJson)
                }.getOrNull()

                if (config == null) {
                    failStart(getString(R.string.tunnel_error_invalid_config))
                    return START_NOT_STICKY
                }

                SessionResume.setDesired(this, true)
                startVpn(config)
            }
            ACTION_STOP -> {
                // The user's own stop: a later restart by the system must not undo it.
                SessionResume.setDesired(this, false)
                stopVpn()
            }
            ACTION_SWITCH_CONFIG -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                val config = runCatching {
                    json.decodeFromString(ProxyConfiguration.serializer(), configJson)
                }.getOrNull() ?: return START_NOT_STICKY
                // A layer-3 profile has no lwIP stack to hand a new
                // configuration to, and a stream profile cannot be swapped into
                // a TUN shaped by someone else's AllowedIPs. Either way round,
                // the session has to be rebuilt rather than adjusted — an
                // in-place switch would leave the old tunnel carrying traffic
                // under the new server's name.
                if (config.outboundProtocol.isLayer3 ||
                    currentConfig?.outboundProtocol?.isLayer3 == true ||
                    wireGuardTunnel != null
                ) {
                    startVpn(config)
                } else {
                    currentConfig = config
                    activeServerName = config.name
                    activeConfigId = config.id
                    DnsCache.setActiveProxyDomain(config.serverAddress)
                    lwipStack?.switchConfiguration(config)
                    updateNotification(config.name)
                    MythaiaWidgetProvider.refresh(this)
                }
            }
            SERVICE_INTERFACE, null -> {
                // Always-on VPN (SERVICE_INTERFACE): the system starts us with
                // no configuration after a reboot or when the toggle goes on.
                // A null intent is the other case: the process was killed and
                // START_STICKY brought the service back — reconnect only if the
                // user had the tunnel on, and not when restarts keep failing.
                if (isRunning) return START_STICKY
                if (intent?.action == null) {
                    if (!SessionResume.isDesired(this)) {
                        stopSelf()
                        return START_NOT_STICKY
                    }
                    if (!SessionResume.allowRestart(this)) {
                        logger.warning("[VPN] Restarted three times in a minute; staying off")
                        SessionResume.setDesired(this, false)
                        stopSelf()
                        return START_NOT_STICKY
                    }
                    logger.info("[VPN] Restarted after the process was killed; reconnecting")
                } else {
                    SessionResume.setDesired(this, true)
                    logger.info("[VPN] Started by the system; connecting the selected server")
                }
                Thread({
                    val refusal = TunnelLauncher.startSelected(this)
                    if (refusal != null) {
                        android.os.Handler(mainLooper).post {
                            if (!isRunning) {
                                failStart(
                                    when (refusal) {
                                        TunnelLauncher.Refusal.NO_SELECTION -> getString(R.string.no_server_selected)
                                        TunnelLauncher.Refusal.NEEDS_CONSENT -> getString(R.string.permission_denied)
                                        TunnelLauncher.Refusal.FAILED -> getString(R.string.tunnel_error_establish)
                                    }
                                )
                            }
                        }
                    }
                }, "always-on-connect").apply { isDaemon = true }.start()
            }
            else -> {
                // Unknown action
                stopSelf()
            }
        }
        // Sticky while the user wants the tunnel: a killed process comes back.
        return if (SessionResume.isDesired(this)) START_STICKY else START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        // VPN permission revoked by user or system — another VPN took over, or
        // the user did it in Settings. Either way, not something to undo.
        logger.debug("[VPN] Permission revoked, stopping")
        SessionResume.setDesired(this, false)
        stopVpn()
    }

    /** Applies the global allowInsecure preference to a config's TLS settings. */
    private fun applyGlobalAllowInsecure(config: ProxyConfiguration): ProxyConfiguration {
        val prefs = getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("allowInsecure", false)) return config
        val tls = config.tls ?: return config
        if (tls.allowInsecure) return config
        val updatedTls = tls.copy(allowInsecure = true)
        val updatedChain = config.chain?.map { applyGlobalAllowInsecure(it) }
        return config.copy(tls = updatedTls, chain = updatedChain)
    }

    private fun startVpn(config: ProxyConfiguration) {
        // Invalidate any deferred finishStopVpn() from a previous stop so it
        // can't tear down the session we are about to start.
        sessionGeneration++

        // Foreground first. Everything below may wait up to ten seconds for a
        // previous session to drain, and Android kills a service started with
        // startForegroundService() that has not called startForeground() in time.
        enterForeground(config.name)

        // A stop from a moment ago may still be draining its lwIP executor;
        // nativeInit() before that nativeShutdown() completes trips the
        // single-netif assert and takes the process down.
        pendingStop?.let { latch ->
            try {
                latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
            } catch (_: InterruptedException) {}
            pendingStop = null
        }

        // Stop the existing stack before starting a new one. lwIP uses global
        // state (netif_default) and LWIP_SINGLE_NETIF asserts if netif_add() is
        // called while a netif is already registered. We must wait for
        // nativeShutdown() (which calls netif_remove → netif_default = NULL)
        // to complete before calling nativeInit() (which calls netif_add).
        wireGuardTunnel?.let { old ->
            wireGuardTunnel = null
            wireGuardSettings = null
            old.stop()
            tunFd?.close()
            tunFd = null
        }

        lwipStack?.let { oldStack ->
            lwipStack = null
            val latch = java.util.concurrent.CountDownLatch(1)
            oldStack.stop { latch.countDown() }
            try {
                latch.await(5, java.util.concurrent.TimeUnit.SECONDS)
            } catch (_: InterruptedException) {}
            tunFd?.close()
            tunFd = null
        }

        // Prime the cert-policy cache so the first TLS handshake uses the latest
        // prefs. The VPN service shares the app process on Android so VpnViewModel
        // would normally have already populated this cache, but a fresh process
        // (system-killed app + user-tapped reconnect) can race the first handshake.
        CertificatePolicy.reload(this)
        FragmentPolicy.reload(this)
        EncryptedDnsPolicy.reload(this)

        val effectiveConfig = applyGlobalAllowInsecure(config)
        logger.debug("[VPN] Starting tunnel to ${effectiveConfig.serverAddress}:${effectiveConfig.serverPort} " +
                "(connect: ${effectiveConfig.connectAddress}), security: ${effectiveConfig.security}, transport: ${effectiveConfig.transport}")

        currentConfig = effectiveConfig
        DnsCache.setActiveProxyDomain(effectiveConfig.serverAddress)

        // Create foreground notification. It reads "Connecting" until the
        // stack is actually up; claiming Connected before the TUN exists
        // would be a lie for the seconds a failure takes to show.
        enterForeground(effectiveConfig.name)

        if (effectiveConfig.outboundProtocol.isLayer3) {
            startWireGuard(effectiveConfig)
            return
        }

        // Build and establish TUN interface
        val fd = buildTunInterface(effectiveConfig) ?: run {
            failStart(getString(R.string.tunnel_error_establish))
            return
        }
        tunFd = fd

        // Start lwIP stack. The single `ipv6DNSEnabled` knob controls both IPv6
        // routes and AAAA fake-IP resolution.
        val prefs = getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        val ipv6Dns = prefs.getBoolean("ipv6DnsEnabled", false)

        // Register socket protector so protocol code can protect outbound sockets
        SocketProtector.setProtector(
            fdFn = ::protectSocket,
            socketFn = { protect(it) },
            datagramFn = { protect(it) }
        )

        // Set the underlying physical network for DnsCache so DNS resolution
        // bypasses the VPN tunnel.
        findUnderlyingNetwork()?.let { DnsCache.setUnderlyingNetwork(AndroidUnderlyingNetwork(it)) }

        val stack = LwipStack(this)
        lwipStack = stack
        // Stamped here rather than in the view model so the uptime survives the
        // UI going away and rebinding to a tunnel that never stopped.
        sessionStartedAt = android.os.SystemClock.elapsedRealtime()
        activeServerName = effectiveConfig.name
        activeConfigId = effectiveConfig.id
        setActive(true)
        MythaiaWidgetProvider.refresh(this)
        AutoSelectEngine.onTunnelUp(this)

        // Wire logger sink so logger.info/.warning/.error forward to the
        // user-facing log buffer.
        MythaiaLogger.logSink = { message, level ->
            LogBuffer.append(message, level)
        }

        stack.onTunnelSettingsNeedReapply = {
            reapplyTunnelSettings(effectiveConfig)
        }

        try {
            stack.start(fd, effectiveConfig, ipv6Dns)
        } catch (e: Exception) {
            logger.error("[VPN] lwIP stack could not start: ${e.message ?: e}")
            lwipStack = null
            sessionStartedAt = 0L
            activeServerName = null
            setActive(false)
            MythaiaWidgetProvider.refresh(this)
            try { fd.close() } catch (_: Exception) {}
            tunFd = null
            failStart(getString(R.string.tunnel_error_start, e.message ?: e.toString()))
            return
        }

        updateNotification(effectiveConfig.name)
        startStatsTicker()

        // Begin observing the underlying physical network so we can restart
        // the stack when the user roams between Wi-Fi and Cellular.
        startNetworkMonitoring()

        // Observe screen off/on as a proxy for device-level sleep so we can
        // proactively restart connections after long periods of inactivity
        // (NAT rebinds, server-side idle sweeps).
        startScreenStateMonitoring()
    }

    /**
     * A start that did not produce a tunnel.
     *
     * Logs, tells the UI why through [notifyStartFailure], drops the
     * foreground notification the start put up, and stops. Without this the
     * service simply vanished and the power button flipped back with no
     * explanation.
     */
    private fun failStart(message: String) {
        logger.error("[VPN] $message")
        currentConfig = null
        DnsCache.setActiveProxyDomain(null)
        SocketProtector.clearProtector()
        @Suppress("DEPRECATION")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
        notifyStartFailure(message)
        AutoSelectEngine.onTunnelFailed(this, null)
        stopSelf()
    }

    /** Set before a stopVpn() that the tunnel itself caused, not the user. */
    private var failureStop = false

    private fun stopVpn() {
        stopStatsTicker()
        stopNetworkMonitoring()
        stopScreenStateMonitoring()
        SocketProtector.clearProtector()
        DnsCache.setUnderlyingNetwork(null)

        wireGuardTunnel?.stop()
        wireGuardTunnel = null
        wireGuardSettings = null

        // AnyTLS keeps TLS connections pooled across dials, so they outlive any
        // one flow and have to be released with the tunnel rather than with it.
        kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).launch {
            runCatching { com.mythaia.vpn.protocol.anytls.AnyTlsClient.shutdown() }
        }

        val stack = lwipStack
        lwipStack = null
        sessionStartedAt = 0L
        activeServerName = null
        val stoppedConfigId = activeConfigId
        activeConfigId = null
        AutoSelectEngine.onTunnelDown()
        setActive(false)
        MythaiaWidgetProvider.refresh(this)
        if (failureStop) {
            failureStop = false
            AutoSelectEngine.onTunnelFailed(this, stoppedConfigId)
        }
        // Capture the fd now — a subsequent startVpn() assigns a fresh tunFd
        // and the deferred finishStopVpn() must never close that new one.
        val fdToClose = tunFd
        tunFd = null
        val generation = sessionGeneration

        if (stack != null) {
            // Use the completion callback so the TUN file descriptor is closed
            // AFTER the lwIP executor finishes draining — avoids racing with the
            // packet reader thread. startVpn() waits on the latch so a quick
            // reconnect cannot overlap the teardown.
            val done = java.util.concurrent.CountDownLatch(1)
            pendingStop = done
            stack.stop {
                try {
                    finishStopVpn(fdToClose, generation)
                } finally {
                    done.countDown()
                }
            }
        } else {
            finishStopVpn(fdToClose, generation)
        }
    }

    /** Counts down when the last lwIP teardown has finished on its executor. */
    @Volatile
    private var pendingStop: java.util.concurrent.CountDownLatch? = null

    private fun finishStopVpn(fdToClose: ParcelFileDescriptor?, generation: Int) {
        // Closing the captured old fd is always safe — it belongs to the session
        // this stop was scheduled for.
        try { fdToClose?.close() } catch (_: Exception) {}

        // A newer startVpn() has begun a fresh session since this stop was
        // scheduled — don't remove its notification or stop the service.
        if (generation != sessionGeneration) return

        MythaiaLogger.logSink = null

        currentConfig = null
        DnsCache.setActiveProxyDomain(null)

        @Suppress("DEPRECATION")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            stopForeground(true)
        }
        stopSelf()
    }

    // Bypass routes — IP ranges excluded from VPN tunnel (sent directly)
    private data class BypassRoute(val address: String, val prefixLength: Int)

    /**
     * Brings up a WireGuard or AmneziaWG interface.
     *
     * The TUN is built from the profile's own `[Interface]` and `AllowedIPs`
     * rather than the app-wide layout: a WireGuard peer states exactly what it
     * routes, and that list is the split tunnel. No lwIP stack is started —
     * whole IP packets go straight to the interface.
     */
    private fun startWireGuard(config: ProxyConfiguration) {
        val text = config.wireGuardConfig
        if (text.isNullOrBlank()) {
            logger.error("[VPN] ${config.name} has no WireGuard configuration")
            failStart(getString(R.string.tunnel_error_wireguard_empty))
            return
        }

        // A chain proxies a stream through each hop in turn; WireGuard takes
        // IP packets and has nowhere to put one. Dialling the peer anyway would
        // quietly skip every hop the user asked for.
        if (!config.chain.isNullOrEmpty()) {
            logger.error("[VPN] WireGuard cannot be the exit of a proxy chain")
            failStart(getString(R.string.tunnel_error_wireguard_chain))
            return
        }

        val parsed = try {
            com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse(text)
        } catch (e: Exception) {
            logger.error("[VPN] WireGuard configuration is not usable: ${e.message ?: e}")
            failStart(getString(R.string.tunnel_error_wireguard_invalid, e.message ?: e.toString()))
            return
        }

        val fd = buildWireGuardTun(parsed) ?: run {
            failStart(getString(R.string.tunnel_error_establish))
            return
        }
        tunFd = fd

        // The peer socket must sit outside the tunnel, or its own packets would
        // be routed back into it.
        SocketProtector.setProtector(
            fdFn = ::protectSocket,
            socketFn = { protect(it) },
            datagramFn = { protect(it) }
        )
        findUnderlyingNetwork()?.let { DnsCache.setUnderlyingNetwork(AndroidUnderlyingNetwork(it)) }
        DnsCache.setActiveProxyDomain(parsed.peer.endpointHost)

        MythaiaLogger.logSink = { message, level -> LogBuffer.append(message, level) }

        val tunnel = com.mythaia.vpn.protocol.wireguard.WireGuardTunnel(parsed)
        tunnel.onConnected = {
            logger.info("[VPN] WireGuard session established")
            android.os.Handler(mainLooper).post {
                if (wireGuardTunnel === tunnel) {
                    updateNotification(config.name)
                    startStatsTicker()
                }
            }
        }
        // Left running, the tunnel would keep the TUN's default route while
        // carrying nothing: every app times out with the UI still on Connected.
        // Stopping hands the routes back and lets the user see what happened.
        tunnel.onFailure = { reason ->
            logger.error("[VPN] WireGuard could not reach the peer: $reason")
            // Off the tunnel's own thread: stopVpn touches the service state.
            android.os.Handler(mainLooper).post {
                if (wireGuardTunnel === tunnel) {
                    failureStop = true
                    stopVpn()
                    notifyStartFailure(getString(R.string.tunnel_error_wireguard_peer, reason))
                }
            }
        }

        try {
            tunnel.start(fd)
        } catch (e: Exception) {
            logger.error("[VPN] WireGuard could not start: ${e.message ?: e}")
            try { fd.close() } catch (_: Exception) {}
            tunFd = null
            failStart(getString(R.string.tunnel_error_start, e.message ?: e.toString()))
            return
        }

        wireGuardTunnel = tunnel
        wireGuardSettings = parsed
        sessionStartedAt = android.os.SystemClock.elapsedRealtime()
        activeServerName = config.name
        activeConfigId = config.id
        setActive(true)
        MythaiaWidgetProvider.refresh(this)

        startNetworkMonitoring()
        startScreenStateMonitoring()
    }

    /**
     * The TUN for a WireGuard profile.
     *
     * Addresses, DNS and MTU come from `[Interface]`; the routes come from the
     * peer's `AllowedIPs`, which is what a WireGuard config uses to say what
     * belongs in the tunnel. An entry that Android refuses is skipped rather
     * than failing `establish()` and taking the whole tunnel down with it.
     */
    private fun buildWireGuardTun(
        config: com.mythaia.vpn.protocol.wireguard.WireGuardConfig
    ): ParcelFileDescriptor? {
        val builder = Builder()
            .setMtu(config.mtu)
            .setBlocking(true)
            .setSession("Mythaia VPN")

        var addressCount = 0
        for (entry in config.addresses) {
            val (address, prefix) = com.mythaia.vpn.util.Cidr.split(entry) ?: continue
            try {
                builder.addAddress(address, prefix)
                addressCount++
            } catch (e: Exception) {
                logger.warning("[VPN] WireGuard address $entry refused: ${e.message ?: e}")
            }
        }
        if (addressCount == 0) {
            logger.error("[VPN] WireGuard configuration has no usable [Interface] Address")
            return null
        }

        var routeCount = 0
        for (entry in config.peer.allowedIps) {
            val (address, prefix) = com.mythaia.vpn.util.Cidr.split(entry) ?: continue
            // wg-quick accepts a route with host bits set; addRoute rejects it
            // outright, so `AllowedIPs = 10.0.0.2/24` would silently take the
            // whole subnet out of the tunnel.
            val network = com.mythaia.vpn.util.Cidr.networkOf(address, prefix) ?: continue
            try {
                builder.addRoute(network, prefix)
                routeCount++
            } catch (e: Exception) {
                logger.warning("[VPN] WireGuard route $entry refused: ${e.message ?: e}")
            }
        }
        if (routeCount == 0) {
            logger.error("[VPN] WireGuard configuration has no usable AllowedIPs")
            return null
        }

        for (server in config.dnsServers) {
            try {
                builder.addDnsServer(server)
            } catch (e: Exception) {
                logger.warning("[VPN] WireGuard DNS $server refused: ${e.message ?: e}")
            }
        }

        applySplitTunnel(builder, getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE))

        return try {
            builder.establish()
        } catch (e: Exception) {
            logger.error("[VPN] Failed to set tunnel settings: ${e.message ?: e}")
            null
        }
    }

    private fun buildTunInterface(config: ProxyConfiguration): ParcelFileDescriptor? {
        val prefs = getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        // When enabled we add IPv6 address/routes/DNS.
        val ipv6Enabled = prefs.getBoolean("ipv6DnsEnabled", false)
        val remoteAddress = config.connectAddress

        val builder = Builder()
            // TUN IP
            .addAddress("10.8.0.2", 24)
            // DNS servers
            .addDnsServer("1.1.1.1")
            .addDnsServer("1.0.0.1")
            // MTU
            .setMtu(1500)
            // Block connections without VPN
            .setBlocking(true)

        // IPv6: add address, routes (excluding fc00::/7 and fe80::/10), and DNS servers.
        // Excluded ranges:
        //   fc00::/7  — unique-local (includes our fake IPv6 range fc00::x)
        //   fe80::/10 — link-local
        // Excluding fc00::/7 ensures fake IPv6 IPs fail fast (no route),
        // so apps fall back to IPv4 fake IPs which route through the tunnel.
        if (ipv6Enabled) {
            builder.addAddress("fd00::2", 64)
            // IPv6 routes: ::/0 minus fc00::/7 minus fe80::/10
            builder.addRoute("::", 1)          // 0000::-7fff::
            builder.addRoute("8000::", 2)      // 8000::-bfff::
            builder.addRoute("c000::", 3)      // c000::-dfff::
            builder.addRoute("e000::", 4)      // e000::-efff::
            builder.addRoute("f000::", 5)      // f000::-f7ff::
            builder.addRoute("f800::", 6)      // f800::-fbff::
            builder.addRoute("fe00::", 9)      // fe00::-fe7f::
            builder.addRoute("fec0::", 10)     // fec0::-feff::
            builder.addRoute("ff00::", 8)      // ff00::-ffff:: (multicast)
            // DNS servers (IPv6 DNS queries go through TUN → lwIP → local interception)
            builder.addDnsServer("2606:4700:4700::1111")
            builder.addDnsServer("2606:4700:4700::1001")
        }

        // Apply IPv4 bypass (exclude private/local ranges) via split routing.
        // Android has no addExcludedRoute API, so we replace the catch-all 0.0.0.0/0
        // with the complement routes that cover all public IP space. This allows
        // LAN devices (printers, NAS, local servers) to be reachable without
        // going through the VPN tunnel.
        //
        // The route list below covers 0.0.0.0/0 minus:
        //   10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        // (standard private / CGNAT / loopback ranges from BYPASS_IPV4_ROUTES).
        for (route in PUBLIC_IPV4_ROUTES) {
            builder.addRoute(route.address, route.prefixLength)
        }

        applySplitTunnel(builder, prefs)

        // Session name for system UI
        builder.setSession("Mythaia VPN")

        return try {
            builder.establish()
        } catch (e: Exception) {
            logger.error("[VPN] Failed to set tunnel settings: ${e.message ?: e}")
            null
        }
    }

    /**
     * Restricts the tunnel to (or excludes it from) the user's chosen apps.
     *
     * Each package is added on its own and a package that is no longer
     * installed is skipped: `addAllowedApplication` throws
     * `NameNotFoundException`, and letting that escape would fail
     * `establish()` outright, taking the whole tunnel down because the user
     * uninstalled one app from a list.
     *
     * If every selected package has gone away the selection is ignored rather
     * than applied empty — an allow-list that matched nothing would establish
     * a tunnel no app could use.
     */
    private fun applySplitTunnel(builder: Builder, prefs: android.content.SharedPreferences) {
        val settings = SplitTunnelSettings.read(prefs)
        if (!settings.isActive) return

        var applied = 0
        for (pkg in settings.packages) {
            try {
                when (settings.mode) {
                    SplitTunnelMode.ALLOW -> builder.addAllowedApplication(pkg)
                    SplitTunnelMode.DISALLOW -> builder.addDisallowedApplication(pkg)
                    SplitTunnelMode.OFF -> return
                }
                applied++
            } catch (e: PackageManager.NameNotFoundException) {
                logger.info("[VPN] Split tunnel: skipping uninstalled package $pkg")
            }
        }

        if (applied == 0) {
            logger.info("[VPN] Split tunnel: no selected package is still installed; carrying all apps")
        } else {
            logger.debug("[VPN] Split tunnel: ${settings.mode.raw} for $applied app(s)")
        }
    }

    /**
     * Re-applies tunnel settings when IPv6 toggle changes.
     *
     * Only rebuilds the TUN interface and swaps the fd. The lwIP stack restart
     * is handled by LwipStack.restartStack() which is called right after this
     * from handleSettingsChanged. This avoids a deadlock: this callback is
     * invoked on the lwipExecutor, and stack.stop() would block on the same thread.
     *
     * Only rebuilds the TUN interface without touching the lwIP stack.
     */
    private fun reapplyTunnelSettings(config: ProxyConfiguration) {
        val newFd = buildTunInterface(config)
        if (newFd != null) {
            val oldFd = tunFd
            tunFd = newFd
            // Swap the TUN fd in the stack — restartStack will handle the lwIP restart
            lwipStack?.swapTunFd(newFd)
            oldFd?.close()
            logger.info("[VPN] Tunnel settings reapplied")
        } else {
            logger.error("[VPN] Failed to reapply tunnel settings")
        }
    }

    /**
     * Protects a socket from VPN routing (prevents loop-back through TUN).
     * Must be called for all outbound sockets used by protocol connections.
     */
    fun protectSocket(fd: Int): Boolean {
        return protect(fd)
    }

    /**
     * Finds the underlying physical (non-VPN) network for DNS resolution.
     * Returns the first network that has internet capability and is not a VPN transport.
     * This allows DnsCache to resolve proxy server domains through the physical interface.
     */
    @Suppress("DEPRECATION")
    private fun findUnderlyingNetwork(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null

        // What the best-matching callback last reported is the system's own
        // answer; the guesses below are only for before it has spoken.
        bestUnderlyingNetwork?.let { best ->
            val caps = cm.getNetworkCapabilities(best)
            if (caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return best
        }

        // The active network first: it is the one traffic actually takes.
        // Scanning the list and returning whichever came first would pick an
        // idle interface as readily as the working one.
        cm.activeNetwork?.let { active ->
            val caps = cm.getNetworkCapabilities(active)
            if (caps != null &&
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            ) {
                return active
            }
        }

        // Falls back to a scan, which is what happens while our own VPN is the
        // active network. Prefer what the system would: validated, then
        // unmetered (Wi-Fi over a cellular link kept up in the background).
        @Suppress("DEPRECATION")
        return cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            var score = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 2
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) score += 1
            network to score
        }.maxByOrNull { it.second }?.first
    }

    /** The non-VPN network the system routes through, as its best-matching callback last said. */
    @Volatile
    private var bestUnderlyingNetwork: Network? = null

    /**
     * Begins observing the system's underlying (non-VPN) network so we can
     * detect interface switches (Wi-Fi ↔ Cellular) and trigger a stack restart.
     */
    private fun startNetworkMonitoring() {
        if (networkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return

        // Start from the network the tunnel was just brought up on, so the
        // callback's first report of that same network is not mistaken for a
        // change and does not restart every connection a second after connect.
        val initial = findUnderlyingNetwork()
        lastUnderlyingNetwork = initial
        lastUnderlyingTransports = initial?.let { cm.getNetworkCapabilities(it) }?.let(::transportBitmask) ?: 0
        lastNetworkAvailable = initial != null

        // The best network for "internet, not a VPN" — exactly the one the
        // system would put our protected sockets on. A listen on every network
        // filtered against activeNetwork never fired for a 4G -> Wi-Fi switch:
        // inside our own VPN, activeNetwork is the VPN. NetworkRequest.Builder
        // adds NOT_VPN by default; it is spelled out here because it matters.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                bestUnderlyingNetwork = network
                handlePathUpdate(network, available = true)
            }

            override fun onLost(network: Network) {
                if (bestUnderlyingNetwork == network) bestUnderlyingNetwork = null
                if (network == lastUnderlyingNetwork) {
                    handlePathUpdate(null, available = false)
                }
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                bestUnderlyingNetwork = network
                handlePathUpdate(network, available = true, caps = caps)
            }

            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                // Underlying interface DNS / route may have changed; refresh DnsCache
                // so subsequent resolutions go through the new interface.
                if (network == lastUnderlyingNetwork) {
                    DnsCache.setUnderlyingNetwork(network?.let { AndroidUnderlyingNetwork(it) })
                }
            }
        }

        try {
            // Best-matching (API 31+) and requestNetwork both follow the one
            // network the system picks for this request and move with it; a
            // request that the current default already satisfies brings up
            // nothing extra.
            val handler = android.os.Handler(mainLooper)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                cm.registerBestMatchingNetworkCallback(request, callback, handler)
            } else {
                cm.requestNetwork(request, callback, handler)
            }
            networkCallback = callback
        } catch (e: RuntimeException) {
            // SecurityException, or too many requests on an exotic ROM: the
            // old listen still beats knowing nothing.
            logger.debug("[VPN] Best-network callback refused (${e.message}); listening instead")
            runCatching { cm.registerNetworkCallback(request, callback) }.onSuccess { networkCallback = callback }
        }
    }

    private fun stopNetworkMonitoring() {
        val callback = networkCallback ?: return
        networkCallback = null
        bestUnderlyingNetwork = null
        lastUnderlyingNetwork = null
        lastUnderlyingTransports = 0
        lastNetworkAvailable = false
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // Already unregistered
        }
    }

    /**
     * Listens for screen on/off as a proxy for device-level sleep. Long sleeps
     * (≥ [WAKE_RESTART_THRESHOLD_SECS]) trigger a stack restart on resume to
     * defeat carrier NAT rebinds and server-side idle sweeps after the device
     * has been off for a while.
     */
    private fun startScreenStateMonitoring() {
        if (screenStateReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        sleepTimestampMillis = System.currentTimeMillis()
                    }
                    Intent.ACTION_SCREEN_ON, Intent.ACTION_USER_PRESENT -> {
                        if (sleepTimestampMillis == 0L) return
                        val sleepSecs = (System.currentTimeMillis() - sleepTimestampMillis) / 1000L
                        sleepTimestampMillis = 0L
                        logger.info("[VPN] Device woke up after ${sleepSecs}s")
                        if (sleepSecs >= WAKE_RESTART_THRESHOLD_SECS) {
                            logger.warning(
                                "[VPN] Long sleep detected (${sleepSecs}s); invalidating outbound state"
                            )
                            // Targeted abort of outbound proxy state instead of a
                            // full stack rebuild. The lwIP netif, listeners, FakeIP
                            // pool, and routing all survive sleep — only the
                            // kernel-killed outbound sockets need invalidating.
                            lwipStack?.handleWake()
                            wireGuardTunnel?.handleNetworkPathChange("device wake")
                        }
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        try {
            registerReceiver(receiver, filter)
            screenStateReceiver = receiver
        } catch (e: Throwable) {
            logger.debug("[VPN] Screen state receiver register failed: ${e.message}")
        }
    }

    private fun stopScreenStateMonitoring() {
        val r = screenStateReceiver ?: return
        screenStateReceiver = null
        sleepTimestampMillis = 0L
        try { unregisterReceiver(r) } catch (_: Throwable) {}
    }

    /**
     * Decides whether a network update represents a meaningful change that
     * requires restarting the lwIP stack. Compares the current snapshot to the
     * previous one and triggers a restart only when the underlying interface
     * (or its transport set) actually changed, or when connectivity is restored
     * after being lost.
     */
    private fun handlePathUpdate(network: Network?, available: Boolean, caps: NetworkCapabilities? = null) {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return

        if (!available || network == null) {
            if (lastNetworkAvailable) {
                // Wi-Fi gone with cellular already up (or the other way round):
                // one handoff, one restart — not "lost" and "restored" back to back.
                val next = findUnderlyingNetwork()?.takeIf { it != lastUnderlyingNetwork }
                if (next != null) {
                    handlePathUpdate(next, available = true)
                    return
                }
                logger.warning("[VPN] Network path unavailable; active connections interrupted")
                lastNetworkAvailable = false
                lastUnderlyingNetwork = null
                lastUnderlyingTransports = 0
                // Resolving through the network that just went away would
                // fail every new dial until another callback happened along.
                DnsCache.setUnderlyingNetwork(null)
                runCatching { setUnderlyingNetworks(null) }
                lwipStack?.handleNetworkPathChange("network path unavailable")
                wireGuardTunnel?.handleNetworkPathChange("network path unavailable")
            }
            return
        }

        val networkCaps = caps ?: cm.getNetworkCapabilities(network) ?: return
        if (networkCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
        if (!networkCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return

        // Only the system's best non-VPN network is acted on. The callback now
        // reports just that one; the check stays for the fallback listen,
        // which hears every network. (activeNetwork cannot be the test: inside
        // our own VPN it is the VPN, and every Wi-Fi handoff was ignored.)
        val best = bestUnderlyingNetwork
        if (best != null && best != network) return

        val transports = transportBitmask(networkCaps)
        val previousNetwork = lastUnderlyingNetwork
        val previousTransports = lastUnderlyingTransports
        val wasAvailable = lastNetworkAvailable

        lastUnderlyingNetwork = network
        lastUnderlyingTransports = transports
        lastNetworkAvailable = true

        // Refresh DnsCache so domain resolution always goes through the new
        // physical interface, and tell the system which network the tunnel
        // rides on — it uses that for metering and for the VPN's own
        // "has internet" state, which some ROMs gate traffic on.
        DnsCache.setUnderlyingNetwork(network?.let { AndroidUnderlyingNetwork(it) })
        runCatching { setUnderlyingNetworks(arrayOf(network)) }

        if (!wasAvailable) {
            logger.info("[VPN] Network path restored: ${transportSummary(transports)}; restarting connections")
            lwipStack?.handleNetworkPathChange("network path restored")
            wireGuardTunnel?.handleNetworkPathChange("network path restored")
            return
        }

        if (previousNetwork != network || previousTransports != transports) {
            logger.warning("[VPN] Network path changed to ${transportSummary(transports)}; restarting connections on new interface")
            lwipStack?.handleNetworkPathChange("network interface change")
            wireGuardTunnel?.handleNetworkPathChange("network interface change")
        }
    }

    private fun transportBitmask(caps: NetworkCapabilities): Int {
        var mask = 0
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) mask = mask or 0x1
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) mask = mask or 0x2
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) mask = mask or 0x4
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) mask = mask or 0x8
        return mask
    }

    private fun transportSummary(mask: Int): String {
        val parts = mutableListOf<String>()
        if (mask and 0x1 != 0) parts.add("Wi-Fi")
        if (mask and 0x2 != 0) parts.add("Cellular")
        if (mask and 0x4 != 0) parts.add("Ethernet")
        if (mask and 0x8 != 0) parts.add("Bluetooth")
        return if (parts.isEmpty()) "unknown" else parts.joinToString("+")
    }

    private fun buildNotification(
        configName: String? = null,
        connected: Boolean = true,
        /** Live line ("↓ 1.2 MB/s · ↑ 40 KB/s") and session totals, when the ticker has them. */
        speedLine: String? = null,
        totals: String? = null
    ): Notification {
        val channelId = "mythaia_vpn"
        val channel = NotificationChannel(
            channelId,
            getString(R.string.vpn_service),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_description)
            setShowBadge(false)
        }
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.createNotificationChannel(channel)

        val contentIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // Disconnect action
        val disconnectIntent = PendingIntent.getService(
            this, 1,
            Intent(this, MythaiaVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val disconnectAction = Notification.Action.Builder(
            null, getString(R.string.disconnect), disconnectIntent
        ).build()

        val state = getString(if (connected) R.string.connected else R.string.connecting)
        val stateLine = if (configName != null) "$state \u00B7 $configName" else state

        val builder = Notification.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_stat_wing)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(contentIntent)
            .addAction(disconnectAction)
        if (speedLine != null) {
            builder.setContentTitle(stateLine).setContentText(speedLine)
            totals?.let { builder.setSubText(it) }
        } else {
            builder.setContentTitle(getString(R.string.app_name)).setContentText(stateLine)
        }
        return builder.build()
    }

    /** Puts the service in the foreground with a "Connecting" notification. Safe to repeat. */
    private fun enterForeground(configName: String) {
        val connecting = buildNotification(configName, connected = false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, connecting, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, connecting)
        }
    }

    // MARK: - Live statistics and stall watch

    private val statsHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private var lastSample: LongArray? = null
    private val stallDetector = StallDetector()
    @Volatile private var stallCheckRunning = false

    private val statsTick = object : Runnable {
        override fun run() {
            onStatsTick()
            statsHandler.postDelayed(this, STATS_INTERVAL_MS)
        }
    }

    private fun startStatsTicker() {
        stopStatsTicker()
        lastSample = null
        stallDetector.reset()
        statsHandler.postDelayed(statsTick, STATS_INTERVAL_MS)
    }

    private fun stopStatsTicker() {
        statsHandler.removeCallbacks(statsTick)
        lastSample = null
    }

    /**
     * Every two seconds: the speed and totals in the notification (only while
     * the screen is on — nobody reads it in a pocket, and each update wakes
     * the system UI), and a reading for the stall detector.
     */
    private fun onStatsTick() {
        if (!isRunning) return
        val now = android.os.SystemClock.elapsedRealtime()
        val (down, up) = getStats()
        val previous = lastSample
        lastSample = longArrayOf(now, down, up)

        val interactive = getSystemService(android.os.PowerManager::class.java)?.isInteractive ?: true
        if (interactive && previous != null && now > previous[0]) {
            val seconds = (now - previous[0]) / 1000.0
            val downRate = ((down - previous[1]).coerceAtLeast(0) / seconds).toLong()
            val upRate = ((up - previous[2]).coerceAtLeast(0) / seconds).toLong()
            val speed = "\u2193 ${formatRate(downRate)}  \u2191 ${formatRate(upRate)}"
            val totals = "\u2193 ${formatAmount(down)} \u2191 ${formatAmount(up)}"
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, buildNotification(activeServerName, true, speed, totals))
        }

        if (stallDetector.sample(now, down, up)) onSuspectedStall()
    }

    /**
     * Sent a lot, heard nothing for half a minute. Confirm with a real request
     * through the tunnel's server before touching anything — a long upload
     * looks the same from the counters — and only then recover: under Auto,
     * move to a server that answers; on a pinned server, drop the outbound
     * sockets so every flow redials.
     */
    private fun onSuspectedStall() {
        val config = currentConfig ?: return
        if (stallCheckRunning || config.outboundProtocol.isLayer3) return
        stallCheckRunning = true
        Thread({
            try {
                val dead = (1..2).all {
                    kotlinx.coroutines.runBlocking {
                        com.mythaia.data.network.LatencyTester.test(config, com.mythaia.data.network.LatencyKind.HTTP)
                    } !is com.mythaia.data.network.LatencyResult.Success
                }
                if (!dead) return@Thread
                logger.warning("[VPN] ${config.name} stopped answering; recovering")
                android.os.Handler(mainLooper).post {
                    if (currentConfig?.id != config.id) return@post
                    lwipStack?.handleWake()
                    AutoSelectEngine.onTunnelFailed(this, config.id)
                }
            } finally {
                stallCheckRunning = false
            }
        }, "stall-check").apply { isDaemon = true }.start()
    }

    private fun formatAmount(bytes: Long): String = when {
        bytes >= 1L shl 30 -> String.format(java.util.Locale.US, "%.2f GB", bytes / 1073741824.0)
        bytes >= 1L shl 20 -> String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0)
        bytes >= 1L shl 10 -> String.format(java.util.Locale.US, "%.0f KB", bytes / 1024.0)
        else -> "$bytes B"
    }

    private fun formatRate(bytesPerSecond: Long): String = formatAmount(bytesPerSecond) + "/s"

    /** Updates the notification text (e.g., after config switch). */
    private fun updateNotification(configName: String) {
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, buildNotification(configName))
    }

    /** Returns current traffic statistics (bytes in/out). */
    fun getStats(): Pair<Long, Long> {
        wireGuardTunnel?.let { return it.bytesIn to it.bytesOut }
        val stack = lwipStack ?: return 0L to 0L
        return stack.totalBytesIn.get() to stack.totalBytesOut.get()
    }

    /** Updates proxy server addresses to prevent routing loops. */
    fun updateProxyServerAddresses(addresses: List<String>) {
        lwipStack?.updateProxyServerAddresses(addresses)
    }

    /** Returns whether the VPN is currently running. */
    val isRunning: Boolean get() = lwipStack != null || wireGuardTunnel != null

    /**
     * When the current session started, on the monotonic clock, or 0 when there
     * is none.
     *
     * elapsedRealtime rather than wall time: a clock adjustment or a timezone
     * change must not make the session look hours long or negative.
     */
    @Volatile
    var sessionStartedAt: Long = 0L
        private set

    /** How long the tunnel has been up, in seconds; 0 when it is not. */
    val uptimeSeconds: Long
        get() {
            val started = sessionStartedAt
            if (started == 0L || !isRunning) return 0L
            return (android.os.SystemClock.elapsedRealtime() - started) / 1000L
        }

    companion object {
        private const val TAG = "MythaiaVPN"
        private const val NOTIFICATION_ID = 1
        private const val STATS_INTERVAL_MS = 2_000L
        const val ACTION_START = "com.mythaia.START"
        const val ACTION_STOP = "com.mythaia.STOP"
        const val ACTION_SWITCH_CONFIG = "com.mythaia.SWITCH_CONFIG"
        const val EXTRA_CONFIG = "config"

        /**
         * Whether a tunnel is up, readable without binding to the service.
         *
         * The Quick Settings tile and the home-screen widget both need the
         * state and neither can hold a binding: a tile is created and destroyed
         * around each glance, and a widget update runs in a broadcast.
         */
        @Volatile
        var isActive: Boolean = false
            private set

        /** The server the tunnel is on, for the widget. Null when it is down. */
        @Volatile
        var activeServerName: String? = null
            private set

        /** The id of the server on the wire, for Auto to compare against. */
        @Volatile
        var activeConfigId: java.util.UUID? = null
            private set

        /** Callbacks fired when [isActive] changes, for the tile and widget. */
        private val stateListeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()

        fun addStateListener(listener: () -> Unit) {
            stateListeners.add(listener)
        }

        fun removeStateListener(listener: () -> Unit) {
            stateListeners.remove(listener)
        }

        /**
         * Callbacks for a start that failed, carrying a user-readable reason.
         *
         * Separate from [stateListeners]: a failed start never made the
         * tunnel active, so there is no state change to observe.
         */
        private val startFailureListeners =
            java.util.concurrent.CopyOnWriteArrayList<(String) -> Unit>()

        fun addStartFailureListener(listener: (String) -> Unit) {
            startFailureListeners.add(listener)
        }

        fun removeStartFailureListener(listener: (String) -> Unit) {
            startFailureListeners.remove(listener)
        }

        private fun notifyStartFailure(message: String) {
            for (listener in startFailureListeners) {
                runCatching { listener(message) }
            }
        }

        private fun setActive(active: Boolean) {
            if (isActive == active) return
            isActive = active
            // A listener that throws must not stop the others, nor take the
            // tunnel down with it.
            for (listener in stateListeners) {
                runCatching { listener() }
            }
        }

        /** Wake-from-sleep restart threshold. */
        private val WAKE_RESTART_THRESHOLD_SECS: Long = TunnelConstants.wakeRestartThresholdSec

        // Private/local IPv4 ranges excluded from the VPN tunnel.
        private val BYPASS_IPV4_ROUTES = listOf(
            BypassRoute("127.0.0.0", 8),      // loopback
            BypassRoute("10.0.0.0", 8),        // private
            BypassRoute("172.16.0.0", 12),     // private
            BypassRoute("192.168.0.0", 16),    // private
            BypassRoute("100.64.0.0", 10),     // CGNAT
            BypassRoute("162.14.0.0", 16),
            BypassRoute("211.99.96.0", 19),
            BypassRoute("162.159.192.0", 24),  // Cloudflare
            BypassRoute("162.159.193.0", 24),  // Cloudflare
            BypassRoute("162.159.195.0", 24),  // Cloudflare
        )

        private val BYPASS_IPV6_ROUTES = listOf(
            BypassRoute("fc00::", 7),   // unique-local
            BypassRoute("fe80::", 10),  // link-local
        )

        /**
         * Split routes covering 0.0.0.0/0 minus [BYPASS_IPV4_ROUTES], computed once
         * at class load. Android lacks `VpnService.Builder.addExcludedRoute()` below
         * API 33, so we feed `addRoute()` the explicit complement instead.
         *
         * Computed dynamically so adding entries to [BYPASS_IPV4_ROUTES] (e.g. the
         * Cloudflare and China Telecom ranges) automatically adjusts the routed
         * set without manually re-deriving the CIDRs.
         *
         * Note: 240.0.0.0/4 (reserved) and 224.0.0.0/4 (multicast) are intentionally
         * left out of [BYPASS_IPV4_ROUTES] but also not routed through the VPN —
         * they fall outside the public range we explicitly include below.
         */
        private val PUBLIC_IPV4_ROUTES: List<BypassRoute> by lazy {
            computeIPv4SplitRoutes(BYPASS_IPV4_ROUTES)
        }

        /**
         * Returns CIDR routes covering 0.0.0.0/0 with the given bypass routes
         * removed. Uses a longest-aligned-prefix decomposition: for each gap
         * between bypass ranges, emit the largest /N block aligned to the
         * current cursor that fits, then advance.
         */
        private fun computeIPv4SplitRoutes(bypass: List<BypassRoute>): List<BypassRoute> {
            // Sort bypass ranges by start address and merge overlaps.
            val ranges = bypass.map { it.toIpv4Range() }.sortedBy { it.first }
            val merged = mutableListOf<LongRange>()
            for (r in ranges) {
                val last = merged.lastOrNull()
                if (last != null && r.first <= last.last + 1) {
                    merged[merged.size - 1] = last.first..maxOf(last.last, r.last)
                } else {
                    merged.add(r)
                }
            }

            val routes = mutableListOf<BypassRoute>()
            var cursor = 0L
            // Stop one above the public unicast range — multicast (224/4) and
            // reserved (240/4) should not be routed through the tunnel.
            val publicEnd = 0xE0000000L  // 224.0.0.0
            for (r in merged) {
                if (r.first >= publicEnd) break
                if (r.first > cursor) {
                    appendIpv4CidrRange(cursor, r.first - 1, routes)
                }
                cursor = r.last + 1
            }
            if (cursor < publicEnd) {
                appendIpv4CidrRange(cursor, publicEnd - 1, routes)
            }
            return routes
        }

        private fun BypassRoute.toIpv4Range(): LongRange {
            val ip = ipv4ToLong(address)
            val size = 1L shl (32 - prefixLength)
            return ip until (ip + size)
        }

        private fun ipv4ToLong(addr: String): Long {
            val parts = addr.split(".").map { it.toLong() }
            require(parts.size == 4) { "Invalid IPv4: $addr" }
            return (parts[0] shl 24) or (parts[1] shl 16) or (parts[2] shl 8) or parts[3]
        }

        private fun longToIpv4(ip: Long): String =
            "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

        private fun appendIpv4CidrRange(
            startInclusive: Long,
            endInclusive: Long,
            out: MutableList<BypassRoute>
        ) {
            var s = startInclusive
            while (s <= endInclusive) {
                // Largest k such that s is 2^k-aligned and s + 2^k - 1 <= endInclusive.
                var k = 32
                while (k > 0) {
                    val size = 1L shl k
                    if ((s and (size - 1)) == 0L && s + size - 1 <= endInclusive) break
                    k--
                }
                out.add(BypassRoute(longToIpv4(s), 32 - k))
                s += if (k == 0) 1L else (1L shl k)
            }
        }
    }
}
