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

    /**
     * Preferences key: group id to the country its Auto keeps to, written by
     * the view model (Auto within one country) and read by the engine too.
     */
    const val COUNTRIES_KEY = "autoCountries"

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

    /**
     * When the last round started, by the screen or the background engine, on
     * `SystemClock.elapsedRealtime()`: it keeps counting through deep sleep, so
     * a phone picked up in the morning sees last night's round as old. Shared,
     * so opening the app right after a background round does not run another.
     */
    @Volatile
    private var lastRoundAt = 0L

    fun markRound(now: Long) {
        lastRoundAt = now
    }

    /**
     * Whether a round is owed at [now]. Checked every minute and the moment
     * the screen turns on or the app comes up, so a round skipped while the
     * screen was off runs as soon as anyone can see the result, not up to ten
     * minutes later.
     */
    fun roundDue(now: Long): Boolean = lastRoundAt == 0L || now - lastRoundAt >= RECHECK_MS

    /** Between checks of [roundDue] in the loops; cheap, nothing goes out unless a round is due. */
    const val DUE_CHECK_MS = 60 * 1000L

    /**
     * The most servers one round measures. A bulk list of 10,000 servers
     * measured whole, six at a time with a ten-second timeout, made a round
     * of several hours; a recovery after a block waited for all of it.
     */
    const val MAX_ROUND = 48

    /**
     * The servers one round measures out of [candidates]. A group of up to
     * [MAX_ROUND] is measured whole. A bigger one gets the live server
     * ([liveId]), the half that answered fastest lately ([known]: id to the
     * last successful time), and a random share of the rest: each round
     * stays short, and over successive rounds every server gets its turn.
     */
    fun roundSample(
        candidates: List<com.mythaia.data.model.ProxyConfiguration>,
        liveId: java.util.UUID?,
        known: Map<java.util.UUID, Int>,
        random: kotlin.random.Random = kotlin.random.Random.Default
    ): List<com.mythaia.data.model.ProxyConfiguration> {
        if (candidates.size <= MAX_ROUND) return candidates
        val picked = LinkedHashMap<java.util.UUID, com.mythaia.data.model.ProxyConfiguration>()
        if (liveId != null) candidates.firstOrNull { it.id == liveId }?.let { picked[it.id] = it }
        candidates.asSequence()
            .filter { it.id in known }
            .sortedBy { known.getValue(it.id) }
            .take(MAX_ROUND / 2)
            .forEach { picked.putIfAbsent(it.id, it) }
        for (config in candidates.filter { it.id !in picked }.shuffled(random)) {
            if (picked.size >= MAX_ROUND) break
            picked[config.id] = config
        }
        return picked.values.toList()
    }
}
