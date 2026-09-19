package com.mythaia.vpn.protocol.quic

/**
 * Hysteria's "Brutal" congestion control.
 *
 * Brutal is not congestion control in the usual sense: it never backs off. The
 * user states how fast the link is and the sender holds that rate whatever the
 * network thinks of it. Loss is read not as a signal to slow down but as a tax
 * — if a fifth of the packets are being dropped, the answer is to push a
 * quarter more through so that what survives still adds up to the target.
 *
 * That is the whole algorithm: measure the loss rate over the last few seconds,
 * divide the target rate by the fraction getting through, and size the window
 * for that. The guard rails carry as much weight as the formula. A loss rate
 * taken from a handful of packets is noise, so below a sample floor it counts
 * as zero; and an honest loss rate near 1.0 would divide the rate by nearly
 * nothing, so it is capped, because past that point the link is broken and
 * flooding it harder helps nobody.
 *
 * This class holds no connection state and touches no native code. A caller
 * reports acknowledgements and losses along with the time they happened, then
 * asks for a window given the current smoothed RTT; the numbers that come back
 * are what a QUIC stack's congestion-control hooks would write into its own
 * connection statistics. Time arrives as a parameter rather than from a clock
 * read inside, which is what makes the second-by-second accounting testable.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class BrutalCongestionControl(initialBytesPerSecond: Long) {

    /**
     * Everything the controller has to say about the next stretch of sending.
     *
     * The three values are computed together because they all fall out of the
     * same paced rate, and a sender that took the window without the quantum
     * would inherit whatever burst size its stack defaults to.
     */
    data class Window(
        /** The congestion window, in bytes. */
        val cwndBytes: Long,
        /**
         * The pacing rate in ngtcp2's fixed-point form: nanoseconds per byte
         * shifted left by ten. Zero asks the library for its own default.
         *
         * The unit is confirmed against the vendored source rather than taken
         * on trust: `ngtcp2_cc.c` computes `(rtt << 10) * 100 / 125 / cwnd`
         * and `ngtcp2_conn.c` shifts it back down by ten when spending it.
         * The `100 / 125` there is ngtcp2's own 1.25 pacing gain, derived from
         * a window; Brutal is handed a rate outright and paces at exactly that,
         * so no gain applies here.
         */
        val pacingIntervalM: Long,
        /** How much may leave in one burst, in bytes. */
        val sendQuantumBytes: Long
    )

    /**
     * The rate to pace towards, in bytes per second.
     *
     * A session normally starts with a placeholder and learns the real figure
     * from the server after authentication, so this changes underneath a
     * running connection. It is volatile rather than locked because it is one
     * independent value read once per window: a rate that lands a microsecond
     * late costs nothing, and holding the sample lock for it would only couple
     * the bandwidth update to the ack path.
     */
    @Volatile
    var targetBytesPerSecond: Long = initialBytesPerSecond

    /**
     * One second of ack/loss counts.
     *
     * [secondMark] is what makes the ring self-expiring: a slot whose mark is
     * not the second being asked about holds counts from five seconds ago and
     * is ignored, so nothing has to be swept on a timer.
     */
    private class Slot {
        /**
         * The second these counts belong to, or [Long.MIN_VALUE] for a slot
         * that has never been used. No nanosecond reading divides down to that
         * second, so an unused slot cannot be mistaken for a live one.
         */
        var secondMark = Long.MIN_VALUE
        var ackCount = 0L
        var lossCount = 0L

        /** Empties the slot and hands it to [second]. */
        fun restart(second: Long) {
            secondMark = second
            ackCount = 0
            lossCount = 0
        }

        /** Empties the slot and leaves it belonging to no second at all. */
        fun retire() = restart(Long.MIN_VALUE)
    }

    private val slots = Array(SLOT_COUNT) { Slot() }

    /** Records one acknowledged packet at [nowNanos]. */
    @Synchronized
    fun onPacketAcked(nowNanos: Long) {
        slotFor(nowNanos).ackCount++
    }

    /** Records one declared-lost packet at [nowNanos]. */
    @Synchronized
    fun onPacketLost(nowNanos: Long) {
        slotFor(nowNanos).lossCount++
    }

    /**
     * Forgets every sample.
     *
     * A QUIC stack calls this on a persistent-congestion event, where the
     * measurements describe a path the connection is no longer on.
     */
    @Synchronized
    fun reset() {
        for (slot in slots) slot.retire()
    }

    /**
     * The measured loss rate over the last [SLOT_COUNT] seconds, or zero when
     * too few packets have been seen for the figure to mean anything.
     *
     * The in-progress second is counted rather than held back until it closes.
     * Excluding it would report no loss at all through the first second of a
     * connection, which is exactly when a bursty start is losing packets and
     * the window most needs to react.
     *
     * This is the raw measurement, uncapped: the [MAX_LOSS_RATE] limit belongs
     * to the window calculation, not to what was observed.
     */
    @Synchronized
    fun observedLossRate(nowNanos: Long): Double {
        val now = secondOf(nowNanos)
        var acks = 0L
        var losses = 0L
        for (age in 0 until SLOT_COUNT) {
            val second = now - age
            val slot = slots[indexOf(second)]
            if (slot.secondMark != second) continue
            acks += slot.ackCount
            losses += slot.lossCount
        }

        val total = acks + losses
        if (total < MIN_SAMPLE_COUNT) return 0.0
        return losses.toDouble() / total.toDouble()
    }

    /**
     * Sizes the window for [smoothedRttNanos], or null when no target rate has
     * been set yet.
     *
     * Null means the controller has nothing to say — a caller wiring this into
     * a QUIC stack should leave that stack's own numbers alone rather than
     * writing a zero window and stalling the connection.
     *
     * [maxDatagramSize] is the sender's MSS, and only the floors depend on it.
     */
    fun window(nowNanos: Long, smoothedRttNanos: Long, maxDatagramSize: Int): Window? {
        val target = targetBytesPerSecond
        if (target <= 0) return null

        val lossRate = observedLossRate(nowNanos).coerceIn(0.0, MAX_LOSS_RATE)

        // Pace at target / ackRate, so that over time the share of the paced
        // rate that survives comes back out at the target.
        val ackRate = 1.0 - lossRate
        val pacedBytesPerSecond = target.toDouble() / ackRate

        // Ten packets is RFC 6928's initial window, and it is the floor for
        // everything below: a window under it cannot keep a single round trip
        // busy no matter what the arithmetic says.
        val mss = maxOf(maxDatagramSize.toLong(), 1L)
        val minCwnd = MIN_CWND_PACKETS * mss

        val cwnd = if (smoothedRttNanos <= 0) {
            // No RTT has been measured yet. The Brutal formula needs one, and
            // feeding it a synthetic floor inflates the window to several
            // megabytes, which starts the connection with a burst the path
            // then drops. A flat seed rides out the first round trip instead.
            maxOf(INITIAL_CWND_BYTES, minCwnd)
        } else {
            // Rate times RTT times two, on the raw RTT with no floor under it:
            // clamping to something like 50 ms would inflate the window five to
            // fifty-fold on a low-latency link.
            val bandwidthDelay = pacedBytesPerSecond * CONGESTION_WINDOW_MULTIPLIER *
                smoothedRttNanos.toDouble() / NANOS_PER_SECOND.toDouble()
            maxOf(bandwidthDelay.toLong(), minCwnd)
        }

        val pacingIntervalM = if (pacedBytesPerSecond >= 1.0) {
            val nanosPerByte = NANOS_PER_SECOND.toDouble() / pacedBytesPerSecond
            (nanosPerByte * PACING_INTERVAL_SCALE).toLong()
        } else {
            0L
        }

        // A millisecond of bytes, under the same ten-packet floor and capped so
        // one burst cannot swallow the whole window. Without this the sender
        // inherits a loss-based controller's static quantum of about ten
        // packets, which throttles a fast link on burst size alone.
        val bytesPerMillisecond = pacedBytesPerSecond / MILLIS_PER_SECOND
        val sendQuantum = maxOf(
            minOf(bytesPerMillisecond, MAX_SEND_QUANTUM_BYTES.toDouble()).toLong(),
            minCwnd
        )

        return Window(cwnd, pacingIntervalM, sendQuantum)
    }

    /**
     * The slot for [nowNanos], recycled if it still holds an older second.
     *
     * Recycling on write is what keeps the ring bounded: five slots cover five
     * seconds, and the sixth second lands back on the first slot and clears it.
     */
    private fun slotFor(nowNanos: Long): Slot {
        val second = secondOf(nowNanos)
        val slot = slots[indexOf(second)]
        if (slot.secondMark != second) slot.restart(second)
        return slot
    }

    private fun secondOf(nanos: Long) = Math.floorDiv(nanos, NANOS_PER_SECOND)

    /**
     * Floored rather than truncated so that a monotonic clock reading before
     * its own origin — which is allowed, and happens on some devices — still
     * lands on a slot instead of a negative index.
     */
    private fun indexOf(second: Long) = Math.floorMod(second, SLOT_COUNT.toLong()).toInt()

    companion object {
        /** Seconds of per-second ack/loss slots the loss rate is measured over. */
        const val SLOT_COUNT = 5

        /** Below this many ack plus loss samples the loss rate is treated as zero. */
        const val MIN_SAMPLE_COUNT = 50L

        /**
         * The loss-rate cap, the other face of Hysteria's minimum ack rate of
         * 0.8. Beyond it the window grows pathologically and floods the link.
         */
        const val MAX_LOSS_RATE = 0.2

        /** Two round trips of data in flight. */
        const val CONGESTION_WINDOW_MULTIPLIER = 2.0

        /** Ten MSS, the RFC 6928 initial window, used here as a floor. */
        const val MIN_CWND_PACKETS = 10L

        /** The flat window used until the first RTT sample arrives. */
        const val INITIAL_CWND_BYTES = 10240L

        /** One burst tops out at 64 KiB however fast the link is. */
        const val MAX_SEND_QUANTUM_BYTES = 64L * 1024

        /** ngtcp2 carries the pacing interval as nanoseconds per byte, shifted left by ten. */
        private const val PACING_INTERVAL_SCALE = 1024.0

        private const val NANOS_PER_SECOND = 1_000_000_000L
        private const val MILLIS_PER_SECOND = 1000.0
    }
}
