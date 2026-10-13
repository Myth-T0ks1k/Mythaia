package com.mythaia.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoPolicyTest {

    @Test
    fun `a dead live server is always left`() {
        assertTrue(AutoPolicy.worthSwitching(liveMs = null, candidateMs = 2000))
    }

    @Test
    fun `noise is not a reason to move`() {
        // 50 ms and 120 ms gains: inside the spread of one handshake.
        assertFalse(AutoPolicy.worthSwitching(liveMs = 400, candidateMs = 350))
        assertFalse(AutoPolicy.worthSwitching(liveMs = 400, candidateMs = 280))
        // On a slow server the share decides: 30% of 2000 ms is 600 ms.
        assertFalse(AutoPolicy.worthSwitching(liveMs = 2000, candidateMs = 1500))
    }

    @Test
    fun `a round is owed at first and again after the recheck interval`() {
        AutoPolicy.markRound(0L)  // 0 reads as "never"
        assertTrue(AutoPolicy.roundDue(5_000L))
        AutoPolicy.markRound(1_000_000L)
        assertFalse(AutoPolicy.roundDue(1_000_000L + AutoPolicy.RECHECK_MS - 1))
        assertTrue(AutoPolicy.roundDue(1_000_000L + AutoPolicy.RECHECK_MS))
    }

    @Test
    fun `a clearly faster server is worth the move`() {
        assertTrue(AutoPolicy.worthSwitching(liveMs = 400, candidateMs = 240))
        assertTrue(AutoPolicy.worthSwitching(liveMs = 2000, candidateMs = 900))
    }
}
