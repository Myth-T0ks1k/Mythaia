package com.mythaia.data.network

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
import com.mythaia.vpn.util.MythaiaLogger
import java.util.concurrent.TimeUnit

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
        val subscriptionRepository = SubscriptionRepository(context)
        val configRepository = ConfigRepository(context)

        val subscriptions = subscriptionRepository.getAll()
        if (subscriptions.isEmpty()) return Result.success()

        val hwid = SubscriptionRefreshScheduler.remnawaveHWID(context)

        var failed = 0
        for (subscription in subscriptions) {
            try {
                SubscriptionUpdater.update(
                    subscription = subscription,
                    subscriptionRepository = subscriptionRepository,
                    configRepository = configRepository,
                    remnawaveHWID = if (SubscriptionDomainHelper
                            .shouldRequireRemnawaveHWID(subscription.url)
                    ) hwid else null
                )
            } catch (e: Exception) {
                // One dead panel must not stop the others, and it must not
                // cost the whole periodic job its slot.
                failed++
                logger.warning("[Sub] Background refresh failed for ${subscription.name}: ${e.message ?: e}")
            }
        }

        logger.info("[Sub] Background refresh: ${subscriptions.size - failed}/${subscriptions.size} updated")

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
            .edit().putInt(KEY_INTERVAL_HOURS, hours).apply()
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
        val request = PeriodicWorkRequestBuilder<SubscriptionRefreshWorker>(
            minutes, TimeUnit.MINUTES
        )
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
