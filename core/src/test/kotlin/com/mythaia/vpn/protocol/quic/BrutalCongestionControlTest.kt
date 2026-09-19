package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Brutal has no wire format to check against, so the reference here is the
 * algorithm as Hysteria defines it: five one-second sample slots, a fifty
 * sample floor, a minimum ack rate of 0.8 (a loss rate capped at 0.2), a
 * window of `rate * rtt * 2 / ackRate`, and a flat 10240 bytes until an RTT
 * has been measured. The expected numbers below are worked out from those
 * constants and from RFC 6928's ten-packet initial window, not read back out
 * of the implementation.
 *
 * Where a window is compared with a tolerance it is because the reference
 * truncates a floating-point byte count to a whole number; the differences
 * being tested are tens of thousands of bytes, so a byte either way proves
 * nothing on its own.
 */
class BrutalCongestionControlTest {

    /** One megabyte per second, which makes the arithmetic below readable. */
    private val targetBps = 1_000_000L

    /** Hysteria's own initial max datagram size. */
    private val mss = 1252

    private val rtt100ms = 100_000_000L

    /** `rate * rtt * 2` with no loss: 1 MB/s over 100 ms, doubled. */
    private val windowWithoutLoss = 200_000L

    private fun controller(bps: Long = targetBps) = BrutalCongestionControl(bps)

    private fun BrutalCongestionControl.record(acks: Int, losses: Int, at: Long) {
        repeat(acks) { onPacketAcked(at) }
        repeat(losses) { onPacketLost(at) }
    }

    private fun BrutalCongestionControl.cwnd(
        at: Long = 0L,
        rtt: Long = rtt100ms,
        datagramSize: Int = mss
    ): Long = window(at, rtt, datagramSize)!!.cwndBytes

    // MARK: the window before an RTT exists

    @Test
    fun `before the first RTT sample the window is the flat seed`() {
        // Hysteria returns a flat 10240 bytes while the RTT is unknown rather
        // than evaluating its formula against a made-up round trip.
        assertEquals(10_240L, controller().cwnd(rtt = 0, datagramSize = 500))
    }

    @Test
    fun `the flat seed is still lifted to ten packets`() {
        // 10 * 1252 is larger than 10240, and RFC 6928's window wins.
        assertEquals(12_520L, controller().cwnd(rtt = 0))
    }

    @Test
    fun `loss cannot change the window before an RTT exists`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)
        assertEquals(10_240L, cc.cwnd(rtt = 0, datagramSize = 500))
    }

    // MARK: the formula

    @Test
    fun `with no loss the window is twice the bandwidth-delay product`() {
        assertEquals(windowWithoutLoss, controller().cwnd())
    }

    @Test
    fun `acknowledgements on their own never inflate the window`() {
        val cc = controller()
        cc.record(acks = 200, losses = 0, at = 0)
        assertEquals(windowWithoutLoss, cc.cwnd())
    }

    @Test
    fun `the window scales with the target rate`() {
        val cc = controller()
        cc.targetBytesPerSecond = 2 * targetBps
        assertEquals(2 * windowWithoutLoss, cc.cwnd())
    }

    @Test
    fun `an unknown target rate produces no window at all`() {
        // Nothing to say beats writing a zero window into a live connection.
        assertNull(controller(bps = 0).window(0, rtt100ms, mss))
        assertNull(controller(bps = -1).window(0, rtt100ms, mss))
    }

    // MARK: the sample floor

    @Test
    fun `a loss rate below the sample floor is ignored`() {
        val cc = controller()
        // Forty-nine samples: one short of the fifty Hysteria requires.
        cc.record(acks = 45, losses = 4, at = 0)
        assertEquals(0.0, cc.observedLossRate(0), 0.0)
        assertEquals(windowWithoutLoss, cc.cwnd())
    }

    @Test
    fun `the fiftieth sample brings the loss rate into effect`() {
        val cc = controller()
        cc.record(acks = 46, losses = 4, at = 0)
        assertEquals(0.08, cc.observedLossRate(0), 1e-12)
        // 1 MB/s over 100 ms, doubled, divided by an ack rate of 0.92.
        assertEquals(217_391.0, cc.cwnd().toDouble(), 2.0)
    }

    @Test
    fun `samples from different seconds add up towards the floor`() {
        val cc = controller()
        cc.record(acks = 0, losses = 30, at = 0)
        assertEquals(0.0, cc.observedLossRate(0), 0.0)

        cc.record(acks = 0, losses = 25, at = 1_000_000_000)
        // Fifty-five samples spread over two slots still clear the floor.
        assertEquals(1.0, cc.observedLossRate(1_000_000_000), 0.0)
    }

    // MARK: the loss-rate cap

    @Test
    fun `the loss rate is capped before it reaches the window`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)

        // The measurement itself is honest about a link dropping everything.
        assertEquals(1.0, cc.observedLossRate(0), 0.0)
        // The window uses Hysteria's minimum ack rate of 0.8 instead, which
        // inflates by a quarter and no further.
        assertEquals(250_000.0, cc.cwnd().toDouble(), 2.0)
    }

    @Test
    fun `a loss rate at the cap and one far above it give the same window`() {
        val atCap = controller()
        atCap.record(acks = 80, losses = 20, at = 0)
        assertEquals(0.2, atCap.observedLossRate(0), 1e-12)

        val wayOver = controller()
        wayOver.record(acks = 10, losses = 90, at = 0)

        assertEquals(atCap.cwnd(), wayOver.cwnd())
    }

    @Test
    fun `a loss rate under the cap is used as measured`() {
        val cc = controller()
        cc.record(acks = 90, losses = 10, at = 0)
        assertEquals(0.1, cc.observedLossRate(0), 1e-12)
        // Doubled bandwidth-delay product over an ack rate of 0.9.
        assertEquals(222_222.0, cc.cwnd().toDouble(), 2.0)
    }

    // MARK: the RFC 6928 floor

    @Test
    fun `the window never drops below ten packets`() {
        // A kilobyte per second over a millisecond asks for two bytes.
        val cc = controller(bps = 1000)
        assertEquals(10L * 1200, cc.cwnd(rtt = 1_000_000, datagramSize = 1200))
    }

    @Test
    fun `the floor survives a loss rate that would otherwise raise the window`() {
        val cc = controller(bps = 1000)
        cc.record(acks = 0, losses = 100, at = 0)
        assertEquals(10L * 1200, cc.cwnd(rtt = 1_000_000, datagramSize = 1200))
    }

    @Test
    fun `a datagram size of zero still leaves a floor of ten packets`() {
        val cc = controller(bps = 1000)
        assertEquals(10L, cc.cwnd(rtt = 1_000_000, datagramSize = 0))
    }

    // MARK: slots expiring

    @Test
    fun `samples survive to the last second of the window`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)

        // Four seconds on, second zero is still one of the five being counted.
        assertEquals(1.0, cc.observedLossRate(4_999_999_999), 0.0)
        assertEquals(250_000.0, cc.cwnd(at = 4_999_999_999).toDouble(), 2.0)
    }

    @Test
    fun `samples fall out once the window has moved past them`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)

        // Five seconds on, the slot holding them is the one being reused.
        assertEquals(0.0, cc.observedLossRate(5_000_000_000), 0.0)
        assertEquals(windowWithoutLoss, cc.cwnd(at = 5_000_000_000))
    }

    @Test
    fun `a slot reused for a later second does not carry the old counts`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)
        // Second five lands on the slot second zero used.
        cc.record(acks = 60, losses = 0, at = 5_000_000_000)

        assertEquals(0.0, cc.observedLossRate(5_000_000_000), 0.0)
        assertEquals(windowWithoutLoss, cc.cwnd(at = 5_000_000_000))
    }

    @Test
    fun `the rate is taken from exactly the seconds still in the window`() {
        val cc = controller()
        cc.record(acks = 60, losses = 0, at = 0)
        cc.record(acks = 0, losses = 60, at = 3_000_000_000)

        // Both seconds are in reach, so half of what was sent was lost.
        assertEquals(0.5, cc.observedLossRate(3_000_000_000), 1e-12)
        // Second zero is the fifth and last second visible from second four.
        assertEquals(0.5, cc.observedLossRate(4_000_000_000), 1e-12)
        // From second five only the losses remain.
        assertEquals(1.0, cc.observedLossRate(5_000_000_000), 0.0)
    }

    @Test
    fun `a clock reading from before its own origin is still accounted for`() {
        // A monotonic clock may hand out negative readings; the slot ring has
        // to take them without folding onto a negative index.
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = -3_500_000_000)

        assertEquals(1.0, cc.observedLossRate(-3_500_000_000), 0.0)
        assertEquals(0.0, cc.observedLossRate(1_500_000_000), 0.0)
    }

    @Test
    fun `a reset forgets every sample`() {
        val cc = controller()
        cc.record(acks = 0, losses = 100, at = 0)
        cc.reset()

        assertEquals(0.0, cc.observedLossRate(0), 0.0)
        assertEquals(windowWithoutLoss, cc.cwnd())
    }

    // MARK: pacing

    @Test
    fun `the pacing interval is nanoseconds per byte in ngtcp2 fixed point`() {
        // A megabyte per second is a microsecond per kilobyte, so 1000 ns per
        // byte; ngtcp2 carries that shifted left by ten.
        assertEquals(1000L * 1024, controller().window(0, rtt100ms, mss)!!.pacingIntervalM)
        // Twice the rate is half the interval.
        assertEquals(500L * 1024, controller(bps = 2_000_000).window(0, rtt100ms, mss)!!.pacingIntervalM)
    }

    @Test
    fun `loss shortens the pacing interval because the paced rate rises`() {
        val cc = controller()
        val quiet = cc.window(0, rtt100ms, mss)!!.pacingIntervalM
        cc.record(acks = 0, losses = 100, at = 0)
        val lossy = cc.window(0, rtt100ms, mss)!!.pacingIntervalM

        // A capped loss rate of 0.2 paces at 1.25 MB/s, so 800 ns per byte.
        assertEquals(800.0 * 1024, lossy.toDouble(), 2.0)
        assertTrue(lossy < quiet)
    }

    // MARK: send quantum

    @Test
    fun `the send quantum is a millisecond of bytes`() {
        // 20 MB/s is 20000 bytes per millisecond, between the floor and the cap.
        assertEquals(
            20_000L,
            controller(bps = 20_000_000).window(0, rtt100ms, mss)!!.sendQuantumBytes
        )
    }

    @Test
    fun `the send quantum is floored at ten packets`() {
        // A megabyte per second is only 1000 bytes per millisecond.
        assertEquals(10L * mss, controller().window(0, rtt100ms, mss)!!.sendQuantumBytes)
    }

    @Test
    fun `the send quantum is capped at 64 KiB`() {
        assertEquals(
            65_536L,
            controller(bps = 1_000_000_000).window(0, rtt100ms, mss)!!.sendQuantumBytes
        )
    }

    @Test
    fun `the send quantum does not depend on the RTT`() {
        val cc = controller(bps = 20_000_000)
        assertEquals(
            cc.window(0, 0, mss)!!.sendQuantumBytes,
            cc.window(0, rtt100ms, mss)!!.sendQuantumBytes
        )
    }
}
