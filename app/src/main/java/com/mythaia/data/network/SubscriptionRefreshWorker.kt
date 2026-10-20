package com.mythaia.data.network

import androidx.core.content.edit
import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.mythaia.data.repository.ConfigRepository
import com.mythaia.data.repository.SubscriptionRepository
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.EncryptedDnsPolicy
import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.TimeUnit
import com.mythaia.vpn.protocol.tls.reload
import com.mythaia.vpn.util.reload

private val logger = MythaiaLogger("Subscriptions")

/**
 * Refreshes every subscription in the background, on the interval the user
 * chose.
 *
 * Ports the iOS `SubscriptionFetcher`/`SubscriptionStore` refresh; on Android
 * the scheduling belongs to WorkManager so it survives process death and
 * reboots.
 */
class SubscriptionRefreshWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val context = applicationContext

        // A cold process started by WorkManager has no view model, so nothing
        // has loaded these yet; the fetch dials through the same TLS stack
        // the tunnel uses (fronting, fragments, encrypted DNS). Subscription
        // downloads always verify the certificate, whatever the proxy-server
        // "allow insecure" setting says.
        CertificatePolicy.reload(context)
        FragmentPolicy.reload(context)
        EncryptedDnsPolicy.reload(context)

        // The same instances the UI uses, so a refresh and a foreground edit
        // cannot overwrite one another, and the UI sees what lands.
        val subscriptionRepository = SubscriptionRepository.get(context)
        val configRepository = ConfigRepository.get(context)

        val subscriptions = subscriptionRepository.getAll()
        if (subscriptions.isEmpty()) return Result.success()

        val hwid = SubscriptionRefreshScheduler.remnawaveHWID(context)

        var failed = 0
        val now = System.currentTimeMillis()
        for (subscription in subscriptions) {
            // `subscription-auto-update-enable: 0`: the provider wants it refreshed by hand only.
            if (!subscription.autoUpdate) continue
            // A panel that asks for a longer interval than the user's gets it:
            // refreshing more often only adds load for the same list.
            val panelHours = subscription.updateIntervalHours
            val last = subscription.lastUpdate
            if (panelHours != null && last != null && now - last < panelHours * 3_600_000L * 9 / 10) continue
            try {
                SubscriptionUpdater.update(
                    subscription = subscription,
                    subscriptionRepository = subscriptionRepository,
                    configRepository = configRepository,
                    remnawaveHWID = if (SubscriptionDomainHelper
                            .shouldRequireRemnawaveHWID(subscription.url)
                    ) hwid else null,
                    context = context
                )
            } catch (e: Exception) {
                // One dead panel must not stop the others, and it must not
                // cost the whole periodic job its slot.
                failed++
                logger.warning("[Sub] Background refresh failed for ${subscription.name}: ${e.message ?: e}")
            }
        }

        logger.info("[Sub] Background refresh: ${subscriptions.size - failed}/${subscriptions.size} updated")

        // Routing profile files go stale weekly, or when a profile says it changed.
        runCatching { com.mythaia.data.repository.RoutingProfileRepository.get(context).refreshDue() }
            .onFailure { logger.warning("[Sub] Routing files refresh failed: ${it.message ?: it}") }

        // routing.json embeds the full server records, so a panel that moved a
        // server to a new address has to reach the running tunnel too.
        if (failed < subscriptions.size) {
            runCatching {
                com.mythaia.data.repository.RuleSetRepository(context)
                    .syncRoutingFile(configRepository.getAll()) { host ->
                        com.mythaia.vpn.util.DnsCache.resolveHost(host)
                    }
            }.onFailure { logger.warning("[Sub] Routing sync after refresh failed: ${it.message ?: it}") }
        }

        // Retry only when every one failed, which reads as "the network is not
        // really there" rather than "this panel is down".
        return if (failed == subscriptions.size) Result.retry() else Result.success()
    }

    companion object {
        const val WORK_NAME = "mythaia-subscription-refresh"
    }
}

/** Starts, restarts and stops the periodic refresh. */
object SubscriptionRefreshScheduler {

    const val KEY_INTERVAL_HOURS = "subscriptionRefreshHours"

    /** Off, and the intervals offered in the UI. */
    val INTERVAL_CHOICES = listOf(0, 6, 12, 24, 168)

    /**
     * WorkManager's own floor for a periodic job. A shorter choice would be
     * silently rounded up, so the UI does not offer one.
     */
    private const val MIN_INTERVAL_MINUTES = 15L

    fun intervalHours(context: Context): Int =
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
            .getInt(KEY_INTERVAL_HOURS, 0)

    fun setIntervalHours(context: Context, hours: Int) {
        context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
            .edit { putInt(KEY_INTERVAL_HOURS, hours) }
        apply(context)
    }

    /**
     * Makes sure the job exists, without disturbing one that is already
     * running.
     *
     * Called on app start. It has to use KEEP rather than UPDATE: UPDATE
     * restarts the period, so on a phone the user opens several times a day a
     * daily refresh would never come due.
     */
    fun ensureScheduled(context: Context) = schedule(context, replace = false)

    /** Brings the scheduled work in line with the stored interval. */
    fun apply(context: Context) = schedule(context, replace = true)

    private fun schedule(context: Context, replace: Boolean) {
        val manager = WorkManager.getInstance(context)
        val hours = intervalHours(context)

        if (hours <= 0) {
            manager.cancelUniqueWork(SubscriptionRefreshWorker.WORK_NAME)
            return
        }

        val minutes = maxOf(MIN_INTERVAL_MINUTES, hours * 60L)
        // Spread out: without it every device of a panel's users asks at the
        // same minute after an app update and the panel sees a spike.
        val flex = minOf(45L, minutes / 2).coerceAtLeast(5L)
        val request = PeriodicWorkRequestBuilder<SubscriptionRefreshWorker>(
            minutes, TimeUnit.MINUTES, flex, TimeUnit.MINUTES
        )
            .setInitialDelay((0L until minOf(60L, minutes)).random(), TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .build()

        manager.enqueueUniquePeriodicWork(
            SubscriptionRefreshWorker.WORK_NAME,
            if (replace) ExistingPeriodicWorkPolicy.UPDATE else ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }

    /**
     * The `x-hwid` value, or null when the user has not opted in.
     *
     * Read from prefs rather than the view model: the worker runs with no view
     * model alive, and the identifier is generated on first use by the app.
     */
    fun remnawaveHWID(context: Context): String? {
        val prefs = context.getSharedPreferences("mythaia_settings", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("remnawaveHWIDEnabled", false)) return null
        return prefs.getString("identifier", null)
    }
}
