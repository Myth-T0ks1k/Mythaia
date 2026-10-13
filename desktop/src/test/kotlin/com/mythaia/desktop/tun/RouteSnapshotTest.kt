package com.mythaia.desktop.tun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The crash-recovery snapshot is read back by a process running as SYSTEM,
 * so it holds route data and nothing that could become a command: the
 * argv is rebuilt from fixed templates, and a file that is not exactly
 * what this version writes is thrown away whole.
 */
class RouteSnapshotTest {

    private val config = TunNetConfig(
        interfaceIndex = 27,
        physicalInterfaceIndex = 5,
        physicalGateway = "192.168.1.1",
        excludedHosts = listOf("203.0.113.10"),
        excludedNetworks = listOf("10.0.0.0/8")
    )

    @Test
    fun `delete commands come from fixed templates`() {
        assertEquals(
            "route delete 203.0.113.10 mask 255.255.255.255 192.168.1.1 if 5",
            RouteEntry.v4("203.0.113.10", 32, "192.168.1.1", 5).deleteCommand().toString()
        )
        assertEquals(
            "netsh interface ipv6 delete route 8000::/1 interface=27 store=active",
            RouteEntry.v6("8000::", 1, 27).deleteCommand().toString()
        )
        assertTrue(RoutePlan.teardownEntries(config).map { it.deleteCommand() }.none { it.essential })
    }

    @Test
    fun `the snapshot covers the adapter's IPv6 halves too`() {
        val entries = RoutePlan.teardownEntries(config)
        assertTrue(entries.contains(RouteEntry.v6("::", 1, 27)))
        assertTrue(entries.contains(RouteEntry.v6("8000::", 1, 27)))
        assertTrue(entries.contains(RouteEntry.v4("0.0.0.0", 1, "10.8.0.1", 27)))
        assertTrue(entries.contains(RouteEntry.v4("10.0.0.0", 8, "192.168.1.1", 5)))
        assertTrue(RoutePlan.teardownEntries(config.copy(ipv6Address = null)).none { it.kind == RouteEntry.IPV6 })
        // The command form of the same plan still deletes the IPv6 routes.
        assertTrue(RoutePlan.teardown(config).any { it.toString() == "netsh interface ipv6 delete route ::/1 interface=27 store=active" })
    }

    @Test
    fun `what was written is read back unchanged`() {
        val entries = RoutePlan.teardownEntries(config) + RoutePlan.includeHostEntry(config, "8.8.8.8")!!
        assertEquals(entries, WindowsRoutes.parseSnapshot(WindowsRoutes.encodeSnapshot(entries)))
    }

    @Test
    fun `the old format and other versions are rejected`() {
        assertNull(WindowsRoutes.parseSnapshot(null))
        assertNull(WindowsRoutes.parseSnapshot(""))
        assertNull(WindowsRoutes.parseSnapshot("""{"teardown":[["cmd","/c","calc"]]}"""))
        assertNull(WindowsRoutes.parseSnapshot("""{"version":1,"routes":[]}"""))
        assertNull(WindowsRoutes.parseSnapshot("""{"routes":[{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}]}"""))
        assertNotNull(WindowsRoutes.parseSnapshot("""{"version":2,"routes":[]}"""))
    }

    @Test
    fun `one bad entry rejects the whole file`() {
        fun snapshot(vararg entries: String) = """{"version":2,"routes":[${entries.joinToString(",")}]}"""
        val good = """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}"""
        assertEquals(1, WindowsRoutes.parseSnapshot(snapshot(good))?.size)
        val bad = listOf(
            """{"kind":"shell","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"evil.example","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4 && calc","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"999.1.1.1","prefix":32,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":33,"gateway":"192.168.1.1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"fe80::1","interfaceIndex":5}""",
            """{"kind":"route","destination":"1.2.3.4","prefix":32,"gateway":"192.168.1.1","interfaceIndex":0}""",
            """{"kind":"route6","destination":"8000::","prefix":129,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"8000:: /1","prefix":1,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"1.2.3.4","prefix":1,"interfaceIndex":27}""",
            """{"kind":"route6","destination":"8000::","prefix":1,"gateway":"192.168.1.1","interfaceIndex":27}"""
        )
        for (entry in bad) assertNull(entry, WindowsRoutes.parseSnapshot(snapshot(good, entry)))
    }
}
