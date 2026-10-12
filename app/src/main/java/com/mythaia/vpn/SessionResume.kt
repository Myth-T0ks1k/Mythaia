package com.mythaia.vpn

import android.content.Context

/**
 * Whether the user wants the tunnel up, kept across the process dying.
 *
 * Android kills an app's process under memory pressure, and aggressive OEM
 * battery managers do it on a schedule. Without this the VPN silently went
 * away until the user noticed. The service now returns START_STICKY, so the
 * system restarts it with a null intent — and that restart must reconnect only
 * when the user had the tunnel on, and give up when restarting is itself what
 * keeps crashing.
 *
 * Written with commit(), not apply(): the process may be killed right after,
 * which is the whole situation this exists for.
 */
internal object SessionResume {

    private const val PREFS = "mythaia_session"
    private const val KEY_DESIRED = "desired_on"
    private const val KEY_RESTARTS = "sticky_restarts"
    private const val MAX_RESTARTS = 3
    private const val WINDOW_MS = 60_000L

    fun setDesired(context: Context, on: Boolean) {
        prefs(context).edit().putBoolean(KEY_DESIRED, on).commit()
    }

    fun isDesired(context: Context): Boolean = prefs(context).getBoolean(KEY_DESIRED, false)

    /**
     * Records one system restart. False when there have already been
     * [MAX_RESTARTS] in the last minute: a tunnel that dies on every start
     * would otherwise restart forever, draining the battery behind the
     * user's back.
     */
    fun allowRestart(context: Context, now: Long = System.currentTimeMillis()): Boolean {
        val p = prefs(context)
        val recent = restartTimes(p.getString(KEY_RESTARTS, null), now)
        if (recent.size >= MAX_RESTARTS) return false
        p.edit().putString(KEY_RESTARTS, (recent + now).joinToString(",")).commit()
        return true
    }

    /** The restart stamps still inside the window. Pure, for the tests. */
    internal fun restartTimes(stored: String?, now: Long): List<Long> =
        stored.orEmpty().split(',').mapNotNull { it.trim().toLongOrNull() }.filter { now - it in 0 until WINDOW_MS }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}

/**
 * Notices a tunnel that sends but never hears back.
 *
 * Over the last [windowMs], at least [minUpBytes] went up and not one byte
 * came down: the classic shape of a server that stopped answering behind a
 * connection that still looks open. It is only a suspicion — a long upload
 * can look the same — so the service follows it with an active check through
 * the tunnel before doing anything. Costs nothing: it reads counters the
 * stack keeps anyway.
 */
internal class StallDetector(
    private val windowMs: Long = 30_000L,
    private val minUpBytes: Long = 16 * 1024L,
    private val cooldownMs: Long = 90_000L
) {
    private data class Sample(val at: Long, val down: Long, val up: Long)

    private val samples = ArrayDeque<Sample>()
    private var lastAlarm = Long.MIN_VALUE / 2

    fun reset() = samples.clear()

    /** Adds a reading; true when it completes a suspicious window. */
    fun sample(now: Long, bytesIn: Long, bytesOut: Long): Boolean {
        val last = samples.lastOrNull()
        // The stack zeroes its counters on a restart; a window spanning that is meaningless.
        if (last != null && (bytesIn < last.down || bytesOut < last.up)) samples.clear()
        samples.addLast(Sample(now, bytesIn, bytesOut))
        while (samples.size >= 2 && now - samples[1].at >= windowMs) samples.removeFirst()
        val first = samples.first()
        if (now - first.at < windowMs) return false
        val down = bytesIn - first.down
        val up = bytesOut - first.up
        if (down == 0L && up >= minUpBytes && now - lastAlarm >= cooldownMs) {
            lastAlarm = now
            samples.clear()
            return true
        }
        return false
    }
}
