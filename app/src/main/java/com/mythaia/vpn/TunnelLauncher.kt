package com.mythaia.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.repository.ChainRepository
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.data.repository.RuleSetRepository
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.serialization.json.Json
import java.net.Inet4Address
import java.net.InetAddress
import java.util.UUID

private val logger = MythaiaLogger("TunnelLauncher")

/**
 * Starting and stopping the tunnel without a screen in front of it.
 *
 * The view model owns the *decision* to connect — the consent prompt,
 * auto-select, the status a user is watching. What is left once that is
 * settled is this: resolve the endpoint outside the tunnel, write the routing
 * file the service reads at startup, and hand the service a configuration.
 *
 * It lives apart from the view model because a watch, a tile or a widget has
 * no view model to ask, and a second copy of these three steps would be a
 * second copy that quietly drifts.
 */
object TunnelLauncher {

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Why a headless connect could not go ahead. */
    enum class Refusal {
        /** The user has never granted VPN consent, which needs an Activity. */
        NEEDS_CONSENT,

        /** Nothing is selected to connect to. */
        NO_SELECTION,

        /** The service refused to start. */
        FAILED
    }

    /**
     * Starts the tunnel with [config].
     *
     * Does the blocking work — a DNS lookup and a file write — on the calling
     * thread, so call it off the main thread.
     */
    fun start(context: Context, config: ProxyConfiguration): Refusal? {
        if (VpnService.prepare(context) != null) return Refusal.NEEDS_CONSENT

        val app = context.applicationContext
        val prepared = resolveServerAddress(applyGlobalAllowInsecure(app, config))

        RuleSetRepository(app).syncRoutingFile(ConfigRepository.get(app).getAll()) { address ->
            resolveHost(address)
        }

        DnsCache.setActiveProxyDomain(prepared.serverAddress)

        val intent = Intent(app, MythaiaVpnService::class.java).apply {
            action = MythaiaVpnService.ACTION_START
            putExtra(
                MythaiaVpnService.EXTRA_CONFIG,
                json.encodeToString(ProxyConfiguration.serializer(), prepared)
            )
        }

        return try {
            app.startForegroundService(intent)
            null
        } catch (e: Exception) {
            logger.warning("Could not start the tunnel: ${e.message ?: e}")
            Refusal.FAILED
        }
    }

    /**
     * Starts the tunnel with whatever the app has selected.
     *
     * Auto-select is deliberately not run here: it measures every server, which
     * is far too long to leave a watch or a tile waiting, and the choice it
     * makes belongs on the screen where the user can see it.
     */
    fun startSelected(context: Context): Refusal? {
        val config = selectedConfiguration(context) ?: return Refusal.NO_SELECTION
        return start(context, config)
    }

    fun stop(context: Context) {
        val app = context.applicationContext
        try {
            app.startService(
                Intent(app, MythaiaVpnService::class.java).apply {
                    action = MythaiaVpnService.ACTION_STOP
                }
            )
        } catch (e: Exception) {
            logger.warning("Could not stop the tunnel: ${e.message ?: e}")
        }
    }

    /** The configuration or chain the app currently has selected, if any. */
    fun selectedConfiguration(context: Context): ProxyConfiguration? {
        val app = context.applicationContext
        val prefs = app.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)

        val chainId = prefs.getString("selectedChainId", null)
            ?.let { runCatching { UUID.fromString(it) }.getOrNull() }
        if (chainId != null) {
            val chain = ChainRepository(app).get(chainId)
            if (chain != null) return resolveChain(app, chain)
        }

        val configId = prefs.getString("selectedConfigurationId", null)
            ?.let { runCatching { UUID.fromString(it) }.getOrNull() } ?: return null
        return ConfigRepository.get(app).get(configId)
    }

    /** The name shown for the current selection, for a status readout. */
    fun selectedName(context: Context): String? = selectedConfiguration(context)?.name

    // MARK: - Internal

    /** The exit proxy carries the hops in front of it, as the view model builds it. */
    private fun resolveChain(
        context: Context,
        chain: com.mythaia.data.model.ProxyChain
    ): ProxyConfiguration? {
        val repository = ConfigRepository.get(context)
        val hops = chain.proxyIds.mapNotNull { repository.get(it) }
        if (hops.size != chain.proxyIds.size || hops.size < 2) return null
        return hops.last().copy(name = chain.name, chain = hops.dropLast(1))
    }

    private fun applyGlobalAllowInsecure(
        context: Context,
        config: ProxyConfiguration
    ): ProxyConfiguration {
        val prefs = context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("allowInsecure", false)) return config
        val tls = config.tls ?: return config
        if (tls.allowInsecure) return config
        return config.copy(
            tls = tls.copy(allowInsecure = true),
            chain = config.chain?.map { applyGlobalAllowInsecure(context, it) }
        )
    }

    /**
     * Pins the endpoint to an address before the tunnel exists.
     *
     * Once the TUN is up a name lookup would go through it, and the tunnel it
     * is trying to reach is on the other side of that lookup.
     */
    private fun resolveServerAddress(config: ProxyConfiguration): ProxyConfiguration {
        val resolved = resolveOne(config)
        val chain = config.chain?.map { resolveOne(it) }
        return if (chain != null) resolved.copy(chain = chain) else resolved
    }

    private fun resolveOne(config: ProxyConfiguration): ProxyConfiguration {
        val resolved = resolveHost(config.serverAddress) ?: return config
        return config.copy(resolvedIP = resolved)
    }

    private fun resolveHost(address: String): String? {
        val bare = if (address.startsWith("[") && address.endsWith("]")) {
            address.substring(1, address.length - 1)
        } else {
            address
        }

        if (DnsCache.isIpAddress(bare)) return bare

        return try {
            val all = InetAddress.getAllByName(bare)
            (all.firstOrNull { it is Inet4Address } ?: all.firstOrNull())?.hostAddress
        } catch (e: Exception) {
            logger.warning("Failed to resolve $bare: ${e.message ?: e}")
            null
        }
    }
}
