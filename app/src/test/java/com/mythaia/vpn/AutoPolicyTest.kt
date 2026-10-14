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

    private fun servers(n: Int) = (0 until n).map {
        com.mythaia.data.model.ProxyConfiguration.fromUrl("socks5://10.0.${it / 250}.${it % 250 + 1}:1080#s$it")
    }

    @Test
    fun `a small group is measured whole`() {
        val group = servers(AutoPolicy.MAX_ROUND)
        org.junit.Assert.assertEquals(group, AutoPolicy.roundSample(group, liveId = null, known = emptyMap()))
    }

    @Test
    fun `a bulk group is sampled with the live server and the fast ones first`() {
        val group = servers(10_000)
        val live = group[7_000]
        val known = mapOf(group[10].id to 80, group[20].id to 40, group[9_999].id to 300)
        val round = AutoPolicy.roundSample(group, live.id, known, kotlin.random.Random(1))
        org.junit.Assert.assertEquals(AutoPolicy.MAX_ROUND, round.size)
        org.junit.Assert.assertEquals(round.size, round.map { it.id }.toSet().size)
        org.junit.Assert.assertEquals(live, round[0])
        org.junit.Assert.assertEquals(listOf(group[20], group[10], group[9_999]), round.subList(1, 4))
    }

    @Test
    fun `successive rounds reach servers the first one skipped`() {
        val group = servers(1_000)
        val seen = HashSet<java.util.UUID>()
        val random = kotlin.random.Random(2)
        repeat(40) { AutoPolicy.roundSample(group, null, emptyMap(), random).forEach { seen += it.id } }
        assertTrue("only ${seen.size} of 1000 reached", seen.size > 800)
    }
}
