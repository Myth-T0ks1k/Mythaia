package com.mythaia.vpn

import kotlin.math.max

/**
 * When Auto measures its group and when it moves the tunnel, for both the
 * screen ([com.mythaia.viewmodel.VpnViewModel]) and the background
 * [AutoSelectEngine].
 *
 * A move is not free: it restarts the tunnel, so every open connection drops,
 * a call or a download included. And a round is not free either: each server
 * in the group gets a fresh TLS connection. Measured on a phone in
 * the field, rounds of 35 servers every two minutes, day and night, and
 * moves on a 50 ms gain (well inside the noise of one handshake, which ran
 * from 0.4 to 1.7 s on the same server) kept the radio busy and the tunnel
 * hopping between servers.
 */
object AutoPolicy {

    /** Between rounds while connected, and only while the screen is on. */
    const val RECHECK_MS = 10 * 60 * 1000L

    /** The least a move must gain, in milliseconds... */
    const val MIN_GAIN_MS = 150

    /** ...and as a share of the live server's time. */
    const val MIN_GAIN_SHARE = 0.3

    /**
     * Whether to leave the live server for one measured at [candidateMs].
     * [liveMs] is the live server's own time this round, or null when it did
     * not answer (or is not in the group), which is always reason to move.
     */
    fun worthSwitching(liveMs: Int?, candidateMs: Int): Boolean {
        if (liveMs == null) return true
        val needed = max(MIN_GAIN_MS.toDouble(), liveMs * MIN_GAIN_SHARE)
        return liveMs - candidateMs >= needed
    }

    /** Rounds run only while someone can see the screen; a dead server is caught by the failure paths. */
    fun mayMeasure(context: android.content.Context): Boolean =
        context.getSystemService(android.os.PowerManager::class.java)?.isInteractive ?: true
}
