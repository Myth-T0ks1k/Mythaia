package com.mythaia.vpn.protocol.quic

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The fragment reassembler both Hysteria and TUIC share.
 *
 * The invariants are not cosmetic. The key is `session << 16 | packetId` with a
 * 16-bit packet id, so a fragment of packet N and one of packet N+65536 collide
 * on the same key; an orphaned fragment of the first must not be glued onto the
 * second. The guards below are the two that catch it: a partial whose fragment
 * count no longer matches is replaced rather than indexed into, and a fragment
 * out of range is dropped without emitting anything.
 *
 * Arguments are positional — `packetKey, fragmentId, fragmentCount, payload`.
 */
class UdpReassemblerTest {

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    @Test
    fun `a single-fragment message passes straight through`() {
        val r = UdpReassembler()
        assertArrayEquals(bytes(1, 2, 3), r.add(7L, 0, 1, bytes(1, 2, 3)))
    }

    @Test
    fun `fragments reassemble in index order regardless of arrival order`() {
        val r = UdpReassembler()
        assertNull(r.add(42L, 1, 2, bytes(3, 4)))
        assertArrayEquals(bytes(1, 2, 3, 4), r.add(42L, 0, 2, bytes(1, 2)))
    }

    @Test
    fun `a fragment out of range is dropped, not stored`() {
        val r = UdpReassembler()
        assertNull(r.add(1L, 3, 2, bytes(9)))
    }

    @Test
    fun `a differing fragment count on the same key replaces the stale partial`() {
        val r = UdpReassembler()
        // One fragment of a 3-piece packet arrives, then the key is reused by a
        // 2-piece packet (the packet id wrapped). The stale piece must not be
        // glued onto the new one.
        assertNull(r.add(5L, 0, 3, bytes(0xAA)))
        assertNull(r.add(5L, 0, 2, bytes(1)))
        assertArrayEquals(bytes(1, 2), r.add(5L, 1, 2, bytes(2)))
    }
}
