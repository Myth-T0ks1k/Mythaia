package com.mythaia.desktop.engine

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The dial-up, PPPoE and VPN connections' own proxy options: what is kept
 * to go back to, and the WinINet structures, checked by reading (never
 * writing) this PC's settings.
 */
class SystemProxyTest {
    private val ours = "127.0.0.1:10809"
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `each connection keeps what it had, and a new one is added once`() {
        val pppoe = PerConnectionProxy.Options(PerConnectionProxy.PROXY_TYPE_DIRECT or 0x8)
        val vpn = PerConnectionProxy.Options(PerConnectionProxy.PROXY_TYPE_DIRECT or PerConnectionProxy.PROXY_TYPE_PROXY, "corp:3128", "<local>")
        val lan = SystemProxy.Snapshot(enable = 0, server = "corp:3128", override = "<local>")
        val now = mapOf("PPPoE" to pppoe, "Work VPN" to vpn)

        val first = SystemProxy.withConnections(lan, listOf("PPPoE", "Work VPN"), ours) { now[it] }!!
        assertEquals(now, first.connections)
        assertEquals("corp:3128", first.server)

        // Later enables (a port change) find our proxy on them: the first record stays.
        val proxied = PerConnectionProxy.proxied(ours, "<local>")
        assertSame(first, SystemProxy.withConnections(first, listOf("PPPoE", "Work VPN"), ours) { proxied })

        // A connection created meanwhile gets its own record; one already ours goes back to none.
        val third = SystemProxy.withConnections(first, listOf("PPPoE", "Work VPN", "Dial-up"), ours) { proxied }!!
        assertEquals(PerConnectionProxy.Options(PerConnectionProxy.PROXY_TYPE_DIRECT), third.connections["Dial-up"])
        assertEquals(vpn, third.connections["Work VPN"])
    }

    @Test
    fun `a snapshot from an earlier version still reads`() {
        val old = json.decodeFromString(SystemProxy.Snapshot.serializer(), """{"enable":1,"server":"corp:3128","override":"<local>"}""")
        assertEquals(emptyMap<String, PerConnectionProxy.Options>(), old.connections)
        val withRas = old.copy(connections = mapOf("PPPoE" to PerConnectionProxy.Options(1, null, null)))
        val text = json.encodeToString(SystemProxy.Snapshot.serializer(), withRas)
        assertEquals(withRas, json.decodeFromString(SystemProxy.Snapshot.serializer(), text))
    }

    @Test
    fun `the WinINet and RAS structures are laid out right`() {
        assumeTrue(SystemProxy.isWindows)
        // Read only: the LAN always allows direct connections, and a wrong
        // layout makes WinINet refuse the call or return garbage.
        val lan = PerConnectionProxy.query(null)
        assertNotNull("WinINet refused the per-connection query", lan)
        assertTrue("flags ${lan!!.flags}", (lan.flags and PerConnectionProxy.PROXY_TYPE_DIRECT) != 0)
        assertTrue("flags ${lan.flags}", lan.flags in 1..0xFF)
        // RasEnumEntries checks the entry size it is given, even with no entries.
        assertNotNull("RasEnumEntries refused the entry size", PerConnectionProxy.connectionNames())
    }
}
