package com.mythaia.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionResumeTest {

    @Test
    fun `only restarts inside the last minute count`() {
        val now = 1_000_000L
        val stored = listOf(now - 70_000, now - 50_000, now - 10_000, now + 5).joinToString(",")
        assertEquals(listOf(now - 50_000, now - 10_000), SessionResume.restartTimes(stored, now))
        assertEquals(emptyList<Long>(), SessionResume.restartTimes(null, now))
        assertEquals(emptyList<Long>(), SessionResume.restartTimes("garbage,,", now))
    }

    @Test
    fun `a stall is upload without any download for a full window`() {
        val d = StallDetector(windowMs = 30_000, minUpBytes = 16_000, cooldownMs = 90_000)
        var t = 0L
        var up = 0L
        assertFalse(d.sample(t, 5_000, up))
        repeat(14) { t += 2_000; up += 2_000; assertFalse(d.sample(t, 5_000, up)) }
        t += 2_000; up += 2_000
        assertTrue("30 s of uploads and no reply", d.sample(t, 5_000, up))
        // Cooldown: the same pattern right after does not fire again.
        repeat(16) { t += 2_000; up += 2_000; assertFalse(d.sample(t, 5_000, up)) }
    }

    @Test
    fun `any download, a quiet link or a counter reset is not a stall`() {
        val d = StallDetector(windowMs = 30_000, minUpBytes = 16_000)
        var t = 0L
        var down = 0L
        var up = 0L
        repeat(20) { t += 2_000; up += 2_000; down += 10; assertFalse(d.sample(t, down, up)) }

        val quiet = StallDetector(windowMs = 30_000, minUpBytes = 16_000)
        t = 0
        repeat(20) { t += 2_000; assertFalse(quiet.sample(t, 100, 100)) }

        val reset = StallDetector(windowMs = 30_000, minUpBytes = 16_000)
        t = 0; up = 100_000
        repeat(10) { t += 2_000; up += 2_000; assertFalse(reset.sample(t, 50_000, up)) }
        // Counters drop to zero (stack restart): the window starts again.
        t += 2_000
        assertFalse(reset.sample(t, 0, 0))
        repeat(5) { t += 2_000; assertFalse(reset.sample(t, 0, 4_000L * (it + 1))) }
    }
}
