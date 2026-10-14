package com.mythaia.vpn

import android.content.Context
import androidx.core.content.edit
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import java.util.UUID
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload

private val logger = MythaiaLogger("AutoSelect")

/**
 * Auto mode with no screen in front of it.
 *
 * The view model runs Auto while the app is open: it measures, switches and
 * shows the numbers. Once the activity is gone the view model is gone too,
 * but the tunnel is not, and a user who turned Auto on expects it to keep
 * following the fastest server. This does that, from the service's own
 * process, and steps aside whenever the view model is alive so the two never
 * measure the same group twice.
 *
 * Everything it needs is in preferences or in the shared repositories: the
 * active group, the pins, and the server on the wire.
 */
object AutoSelectEngine {

    /** The view model sets this while it exists; failure recovery is then its job. */
    @Volatile
    var uiAlive: Boolean = false

    /** The view model sets this while its activity is on screen; periodic rounds are then its job. */
    @Volatile
    var uiVisible: Boolean = false

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private var loop: Job? = null
    private val json = Json { ignoreUnknownKeys = true }

    /** Last successful time per server, so a sampled round of a big group starts from the fast ones. */
    private val lastKnown = java.util.concurrent.ConcurrentHashMap<UUID, Int>()

    private val reconnectTimes = ArrayDeque<Long>()

    /** Called when a tunnel comes up; checks every minute whether a round is owed ([AutoPolicy.roundDue]). */
    fun onTunnelUp(context: Context) {
        val app = context.applicationContext
        loop?.cancel()
        loop = scope.launch {
            while (isActive) {
                delay(AutoPolicy.DUE_CHECK_MS)
                runRoundIfDue(app)
            }
        }
    }

    fun onTunnelDown() {
        loop?.cancel()
        loop = null
    }

    /**
     * The screen just turned on: a round skipped while it was off runs now
     * (after a few seconds for the radio and the tunnel to wake), so what the
     * user meets is already the best server, not up to ten minutes later.
     */
    fun onScreenOn(context: Context) {
        val app = context.applicationContext
        scope.launch {
            delay(SCREEN_ON_SETTLE_MS)
            runRoundIfDue(app)
        }
    }

    @Volatile
    private var roundRunning = false

    private suspend fun runRoundIfDue(app: Context) {
        // Screen off: no rounds (a dead server is caught by onTunnelFailed and
        // the service's stall watch, not by measuring every server). The screen
        // on, with the app showing: the view model's turn.
        if (uiVisible || !MythaiaVpnService.isActive || !AutoPolicy.mayMeasure(app)) return
        if (roundRunning || !AutoPolicy.roundDue(android.os.SystemClock.elapsedRealtime())) return
        roundRunning = true
        try {
            AutoPolicy.markRound(android.os.SystemClock.elapsedRealtime())
            runCatching { tick(app) }
                .onFailure { logger.warning("Background tick failed: ${it.message ?: it}") }
        } finally {
            roundRunning = false
        }
    }

    /**
     * The tunnel fell over by itself (a peer that stopped answering, a start
     * that failed). With Auto on and no UI to do it, measure the group again
     * and come back up on what answers. Bounded, so a dead network does not
     * turn into a loop.
     */
    fun onTunnelFailed(context: Context, failed: UUID?) {
        if (uiAlive) return
        val app = context.applicationContext
        val prefs = prefs(app)
        if (!autoIsActive(prefs)) return

        val now = System.currentTimeMillis()
        while (reconnectTimes.isNotEmpty() && now - reconnectTimes.first() > RECONNECT_WINDOW_MS) {
            reconnectTimes.removeFirst()
        }
        if (reconnectTimes.size >= RECONNECT_MAX) {
            logger.warning("Not reconnecting: $RECONNECT_MAX attempts in the window")
            return
        }
        reconnectTimes.addLast(now)

        scope.launch {
            reloadPolicies(app)
            val gid = activeGroupId(prefs)
            val candidates = AutoPolicy.roundSample(
                candidates(app, gid).filter { it.id != failed }, liveId = null, known = lastKnown
            )
            val best = measure(candidates) ?: return@launch
            rememberChoice(prefs, gid, best.id)
            logger.info("Reconnecting on ${best.name} after a failure")
            TunnelLauncher.start(app, best)
        }
    }

    private suspend fun tick(app: Context) {
        val prefs = prefs(app)
        if (!autoIsActive(prefs)) return
        reloadPolicies(app)

        val gid = activeGroupId(prefs)
        val candidates = AutoPolicy.roundSample(candidates(app, gid), MythaiaVpnService.activeConfigId, lastKnown)
        if (candidates.isEmpty()) return

        val results = HashMap<UUID, Int>()
        LatencyTester.testAll(candidates, LatencyKind.HTTP).collect { (id, result) ->
            if (result is LatencyResult.Success) { results[id] = result.ms; lastKnown[id] = result.ms }
            else if (result !is LatencyResult.Testing) lastKnown.remove(id)
        }
        val bestEntry = results.minByOrNull { it.value } ?: return
        val best = candidates.firstOrNull { it.id == bestEntry.key } ?: return
        rememberChoice(prefs, gid, best.id)

        val live = MythaiaVpnService.activeConfigId
        val liveMs = live?.let { results[it] }
        val worthIt = live != best.id && AutoPolicy.worthSwitching(liveMs, bestEntry.value)
        if (worthIt) {
            logger.info("Switching to ${best.name} (${bestEntry.value}ms)")
            TunnelLauncher.switchTo(app, best)
        }
    }

    private suspend fun measure(candidates: List<ProxyConfiguration>): ProxyConfiguration? {
        if (candidates.isEmpty()) return null
        val results = HashMap<UUID, Int>()
        LatencyTester.testAll(candidates, LatencyKind.HTTP).collect { (id, result) ->
            if (result is LatencyResult.Success) { results[id] = result.ms; lastKnown[id] = result.ms }
            else if (result !is LatencyResult.Testing) lastKnown.remove(id)
        }
        val bestId = results.minByOrNull { it.value }?.key ?: return null
        return candidates.firstOrNull { it.id == bestId }
    }

    // ---- shared state, in the same preferences the view model uses -------

    private fun prefs(app: Context) = app.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)

    private fun activeGroupId(prefs: android.content.SharedPreferences): String =
        prefs.getString("activeGroupId", "default") ?: "default"

    /** Auto is active when no chain is selected and the active group has no pin. */
    private fun autoIsActive(prefs: android.content.SharedPreferences): Boolean {
        if (prefs.getString("selectedChainId", null) != null) return false
        val gid = activeGroupId(prefs)
        val pins = prefs.getString("groupPins", null) ?: return true
        val map = runCatching { json.decodeFromString<Map<String, String>>(pins) }.getOrDefault(emptyMap())
        return map[gid] == null
    }

    private fun candidates(app: Context, gid: String): List<ProxyConfiguration> {
        val all = ConfigRepository.get(app).getAll()
        val inGroup = if (gid == "default") all.filter { it.subscriptionId == null }
        else all.filter { it.subscriptionId?.toString() == gid }
        return inGroup.filter { it.outboundProtocol.isImplemented && !it.outboundProtocol.isLayer3 }
    }

    /** Auto's pick per group, so the UI can show it when it comes back. */
    private fun rememberChoice(prefs: android.content.SharedPreferences, gid: String, id: UUID) {
        val current = prefs.getString("autoChoices", null)?.let {
            runCatching { json.decodeFromString<Map<String, String>>(it) }.getOrNull()
        } ?: emptyMap()
        prefs.edit {
            putString("autoChoices", json.encodeToString(current + (gid to id.toString())))
            putString("selectedConfigurationId", id.toString())
        }
    }

    private fun reloadPolicies(app: Context) {
        CertificatePolicy.reload(app)
        FragmentPolicy.reload(app)
        EncryptedDnsPolicy.reload(app)
    }

    private const val RECONNECT_MAX = 4
    private const val RECONNECT_WINDOW_MS = 10 * 60 * 1000L

    /** After the screen turns on, before measuring: the radio and a slept tunnel need a moment. */
    private const val SCREEN_ON_SETTLE_MS = 3_000L
}
