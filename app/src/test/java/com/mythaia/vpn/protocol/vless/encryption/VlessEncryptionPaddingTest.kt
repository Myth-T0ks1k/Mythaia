package com.mythaia.vpn.protocol.vless.encryption

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

/**
 * The client-hello padding schedule grammar and its bounds.
 *
 * The rules are read straight from the reference: triples alternate
 * length/gap/length/gap by position, the first length rule is floored at 35 so a
 * decoy fragment can always cover the real prefix, and the summed maximum length
 * is capped at `18 + 65535`. The materialise roll is checked with a seeded
 * `Random` so its outputs can be bounded — each rule lands in `[lo, hi]` or is
 * dropped to zero — without pinning the specific draws, which are not part of
 * the contract.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptionPaddingTest {

    @Test
    fun `empty spec is the default schedule`() {
        val padding = VlessEncryptionPadding.parse("")
        assertEquals(VlessEncryptionPadding.DEFAULT, padding)
        assertEquals(listOf(Triple(100, 111, 1111), Triple(50, 0, 3333)), padding.lengths)
        assertEquals(listOf(Triple(75, 0, 111)), padding.gaps)
    }

    @Test
    fun `positions alternate length then gap`() {
        val padding = VlessEncryptionPadding.parse("100-111-1111.75-0-111.50-40-80")
        // Even positions are lengths, odd positions are gaps.
        assertEquals(listOf(Triple(100, 111, 1111), Triple(50, 40, 80)), padding.lengths)
        assertEquals(listOf(Triple(75, 0, 111)), padding.gaps)
    }

    @Test
    fun `the first length rule is floored at 35`() {
        // Below the floor, or below full probability, the reference refuses the
        // spec rather than risk under-covering the real prefix.
        assertThrows(VlessEncryptionError.Unsupported::class.java) {
            VlessEncryptionPadding.parse("100-34-1111")
        }
        assertThrows(VlessEncryptionError.Unsupported::class.java) {
            VlessEncryptionPadding.parse("99-111-1111")
        }
        // Exactly 35 at full probability is allowed.
        VlessEncryptionPadding.parse("100-35-35")
    }

    @Test
    fun `a non-numeric or short triple is rejected`() {
        assertThrows(VlessEncryptionError.Unsupported::class.java) {
            VlessEncryptionPadding.parse("100-111")
        }
        assertThrows(VlessEncryptionError.Unsupported::class.java) {
            VlessEncryptionPadding.parse("100-xx-1111")
        }
    }

    @Test
    fun `the summed maximum length is capped`() {
        // Two length rules whose maxima sum past 18 + 65535 must be rejected.
        assertThrows(VlessEncryptionError.Unsupported::class.java) {
            VlessEncryptionPadding.parse("100-111-40000.75-0-0.50-0-40000")
        }
    }

    @Test
    fun `materialize keeps each rule within its bounds`() {
        val padding = VlessEncryptionPadding.parse("100-40-80.75-0-111.50-100-200")
        // A fixed seed makes the roll reproducible so its bounds can be asserted.
        repeat(50) { seed ->
            val rolled = padding.materialize(Random(seed.toLong()))
            assertEquals(padding.lengths.size, rolled.lengths.size)
            assertEquals(padding.gaps.size, rolled.gapsMs.size)
            rolled.lengths.forEachIndexed { i, len ->
                val (_, lo, hi) = padding.lengths[i]
                assertTrue("length $len out of [$lo,$hi] or zero", len == 0 || (len in lo..maxOf(lo, hi)))
            }
            assertEquals(rolled.lengths.sum(), rolled.totalLength)
            rolled.gapsMs.forEach { assertTrue("gap $it negative", it >= 0L) }
        }
    }

    @Test
    fun `a full-probability rule always fires`() {
        // prob 100 means the length is drawn every time, never zero.
        val padding = VlessEncryptionPadding.parse("100-50-50")
        repeat(20) { seed ->
            val rolled = padding.materialize(Random(seed.toLong()))
            assertEquals(50, rolled.lengths[0])
        }
    }
}
