package com.mythaia.wear

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The line the phone sends.
 *
 * The two halves ship as separate APKs and a watch is often a version behind,
 * so what matters here is that an old reader survives a newer writer.
 */
class PhoneStatusTest {

    @Test
    fun `each state the phone can report is understood`() {
        assertEquals(PhoneStatus.State.ON, PhoneStatus.parse("on|Tokyo").state)
        assertEquals(PhoneStatus.State.OFF, PhoneStatus.parse("off|Tokyo").state)
        assertEquals(PhoneStatus.State.NEEDS_PHONE, PhoneStatus.parse("needs-phone|").state)
        assertEquals(PhoneStatus.State.NO_SERVER, PhoneStatus.parse("no-server|").state)
        assertEquals(PhoneStatus.State.FAILED, PhoneStatus.parse("failed|").state)
    }

    @Test
    fun `the server name comes through`() {
        assertEquals("Tokyo 01", PhoneStatus.parse("on|Tokyo 01").serverName)
        assertEquals("", PhoneStatus.parse("off|").serverName)
        assertEquals("", PhoneStatus.parse("off").serverName)
    }

    @Test
    fun `fields a newer phone adds are ignored, not fatal`() {
        val status = PhoneStatus.parse("on|Tokyo|4096|8192|something-else")
        assertEquals(PhoneStatus.State.ON, status.state)
        assertEquals("Tokyo", status.serverName)
    }

    @Test
    fun `a state this build does not know reads as unreachable`() {
        // Better to say the phone cannot be reached than to show a confident
        // "disconnected" while the tunnel is actually up.
        assertEquals(PhoneStatus.State.UNREACHABLE, PhoneStatus.parse("reconnecting|Tokyo").state)
        assertEquals(PhoneStatus.State.UNREACHABLE, PhoneStatus.parse("").state)
    }
}
