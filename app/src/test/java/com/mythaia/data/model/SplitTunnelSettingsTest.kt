package com.mythaia.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SplitTunnelSettingsTest {

    @Test
    fun `mode round-trips through its stored form`() {
        for (mode in SplitTunnelMode.entries) {
            assertEquals(mode, SplitTunnelMode.fromRaw(mode.raw))
        }
    }

    @Test
    fun `an unknown or missing stored mode falls back to off`() {
        // A value written by a newer build, or none at all, must not throw.
        assertEquals(SplitTunnelMode.OFF, SplitTunnelMode.fromRaw(null))
        assertEquals(SplitTunnelMode.OFF, SplitTunnelMode.fromRaw(""))
        assertEquals(SplitTunnelMode.OFF, SplitTunnelMode.fromRaw("something-else"))
        // The raw form is lowercase and matched exactly.
        assertEquals(SplitTunnelMode.OFF, SplitTunnelMode.fromRaw("ALLOW"))
    }

    @Test
    fun `an empty selection is never applied to the builder`() {
        // An allow-list matching nothing would establish a tunnel no app can
        // use; a disallow-list matching nothing is just the default. Both mean
        // "carry everything", and neither should reach VpnService.Builder.
        assertFalse(SplitTunnelSettings(SplitTunnelMode.ALLOW, emptySet()).isActive)
        assertFalse(SplitTunnelSettings(SplitTunnelMode.DISALLOW, emptySet()).isActive)
        assertFalse(SplitTunnelSettings(SplitTunnelMode.OFF, setOf("com.example")).isActive)
        assertFalse(SplitTunnelSettings().isActive)
    }

    @Test
    fun `a selection with a mode is applied`() {
        assertTrue(SplitTunnelSettings(SplitTunnelMode.ALLOW, setOf("com.example")).isActive)
        assertTrue(SplitTunnelSettings(SplitTunnelMode.DISALLOW, setOf("com.example")).isActive)
    }

    @Test
    fun `equality drives the change detection in LwipStack`() {
        // handleSettingsChanged compares two instances to decide whether to
        // re-establish the TUN, so value semantics have to hold for the set too.
        val a = SplitTunnelSettings(SplitTunnelMode.ALLOW, setOf("a", "b"))
        val b = SplitTunnelSettings(SplitTunnelMode.ALLOW, setOf("b", "a"))
        assertEquals(a, b)

        val c = SplitTunnelSettings(SplitTunnelMode.DISALLOW, setOf("a", "b"))
        assertTrue(a != c)
        assertTrue(a != SplitTunnelSettings(SplitTunnelMode.ALLOW, setOf("a")))
    }
}
