package com.mythaia.desktop.tun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * The exact `netsh` / `route` lines TUN mode runs. They cannot be executed
 * without an adapter and administrator rights, so the text is pinned:
 * a typo here is a machine with no internet until reboot.
 */
class RoutePlanTest {

    private val config = TunNetConfig(
        interfaceIndex = 27,
        physicalInterfaceIndex = 5,
        physicalGateway = "192.168.1.1",
        excludedHosts = listOf("203.0.113.10", "1.1.1.1", "203.0.113.10"),
        excludedNetworks = listOf("10.0.0.0/8", "95.85.96.0/19")
    )

    private fun lines(commands: List<NetCommand>) = commands.map { it.toString() }

    @Test
    fun `setup addresses the adapter, takes the default route in halves and excludes the physical side`() {
        val setup = lines(RoutePlan.setup(config))
        assertEquals(
            "netsh interface ipv4 set address name=27 source=static address=10.8.0.2 mask=255.255.255.0 store=active",
            setup[0]
        )
        assertTrue(setup.contains("netsh interface ipv4 set dnsservers name=27 source=static address=1.1.1.1 register=none validate=no"))
        assertTrue(setup.contains("netsh interface ipv4 add dnsservers name=27 address=1.0.0.1 index=2 validate=no"))
        assertTrue(setup.contains("netsh interface ipv4 set interface interface=27 metric=1 store=active"))
        assertTrue(setup.contains("route add 0.0.0.0 mask 128.0.0.0 10.8.0.1 metric 1 if 27"))
        assertTrue(setup.contains("route add 128.0.0.0 mask 128.0.0.0 10.8.0.1 metric 1 if 27"))
        assertTrue(setup.contains("route add 10.0.0.0 mask 255.0.0.0 192.168.1.1 metric 1 if 5"))
        assertTrue(setup.contains("route add 95.85.96.0 mask 255.255.224.0 192.168.1.1 metric 1 if 5"))
        assertTrue(setup.contains("route add 203.0.113.10 mask 255.255.255.255 192.168.1.1 metric 1 if 5"))
        assertTrue(setup.contains("route add 1.1.1.1 mask 255.255.255.255 192.168.1.1 metric 1 if 5"))
        assertEquals(1, setup.count { it.startsWith("route add 203.0.113.10 ") })   // deduplicated
        assertTrue(setup.contains("netsh interface ipv6 add address interface=27 address=fd00:6d79:7468::2/64 store=active"))
        assertTrue(setup.contains("netsh interface ipv6 add route ::/1 interface=27 metric=1 store=active"))
        assertTrue(setup.contains("netsh interface ipv6 add route 8000::/1 interface=27 metric=1 store=active"))
        // The default route itself is never touched.
        assertFalse(setup.any { it.contains("0.0.0.0 mask 0.0.0.0") })
    }

    @Test
    fun `only the address and the two half routes are essential`() {
        val essential = RoutePlan.setup(config).filter { it.essential }.map { it.toString() }
        assertEquals(3, essential.size)
        assertTrue(essential[0].startsWith("netsh interface ipv4 set address"))
        assertTrue(essential[1].startsWith("route add 0.0.0.0 mask 128.0.0.0"))
        assertTrue(essential[2].startsWith("route add 128.0.0.0 mask 128.0.0.0"))
    }

    @Test
    fun `teardown deletes exactly what setup added on the physical side`() {
        val teardown = lines(RoutePlan.teardown(config))
        assertTrue(teardown.contains("route delete 0.0.0.0 mask 128.0.0.0 10.8.0.1 if 27"))
        assertTrue(teardown.contains("route delete 203.0.113.10 mask 255.255.255.255 192.168.1.1 if 5"))
        assertTrue(teardown.contains("route delete 1.1.1.1 mask 255.255.255.255 192.168.1.1 if 5"))
        assertTrue(teardown.contains("route delete 10.0.0.0 mask 255.0.0.0 192.168.1.1 if 5"))
        assertTrue(teardown.contains("route delete 95.85.96.0 mask 255.255.224.0 192.168.1.1 if 5"))
        assertTrue(RoutePlan.teardown(config).none { it.essential })
    }

    @Test
    fun `without a physical gateway nothing is routed around the tunnel`() {
        val onLink = config.copy(physicalGateway = null)
        assertTrue(RoutePlan.setup(onLink).none { it.argv[0] == "route" && it.argv.last() == "5" })
        assertNull(RoutePlan.excludeHost(onLink, "203.0.113.10"))
    }

    @Test
    fun `without an IPv6 address IPv6 is left alone`() {
        val v4Only = config.copy(ipv6Address = null)
        assertTrue(RoutePlan.setup(v4Only).none { it.argv.contains("ipv6") })
    }

    @Test
    fun `a host excluded later gets a matching add and delete`() {
        assertEquals("route add 8.8.8.8 mask 255.255.255.255 192.168.1.1 metric 1 if 5", RoutePlan.excludeHost(config, "8.8.8.8").toString())
        assertEquals("route delete 8.8.8.8 mask 255.255.255.255 192.168.1.1 if 5", RoutePlan.includeHost(config, "8.8.8.8").toString())
    }

    @Test
    fun `cidr and mask helpers`() {
        assertEquals("255.255.255.0", RoutePlan.maskOf(24))
        assertEquals("255.240.0.0", RoutePlan.maskOf(12))
        assertEquals("255.192.0.0", RoutePlan.maskOf(10))
        assertEquals("0.0.0.0", RoutePlan.maskOf(0))
        assertEquals("172.16.0.0" to 12, RoutePlan.splitCidr("172.16.0.0/12"))
        assertNull(RoutePlan.splitCidr("172.16.0.0"))
        assertNull(RoutePlan.splitCidr("fd00::/8"))
        assertNull(RoutePlan.splitCidr("10.0.0.0/33"))
    }

    @Test
    fun `physical path knows its own on-link hosts`() {
        val path = PhysicalPath(
            interfaceIndex = 5, gateway = "192.168.1.1",
            address = InetAddress.getByName("192.168.1.20"),
            networks = listOf(InetAddress.getByName("192.168.1.20") to 24),
            dnsServers = listOf("192.168.1.1")
        )
        assertTrue(path.isOnLink(InetAddress.getByName("192.168.1.1")))
        assertFalse(path.isOnLink(InetAddress.getByName("192.168.2.1")))
        assertFalse(path.isOnLink(InetAddress.getByName("1.1.1.1")))
    }

    @Test
    fun `GetBestRoute addresses are packed in memory order`() {
        assertEquals(0x0A08000A.toInt(), WindowsNet.packAddress(byteArrayOf(10, 0, 8, 10)))
        assertEquals("192.168.1.1", WindowsNet.unpackAddress(WindowsNet.packAddress(byteArrayOf(192.toByte(), 168.toByte(), 1, 1))))
    }

    @Test
    fun `relaunch quoting`() {
        assertEquals("'C:\\Program Files\\Mythaia Pro\\Mythaia Pro.exe'", Elevation.psQuote("C:\\Program Files\\Mythaia Pro\\Mythaia Pro.exe"))
        assertEquals("'it''s'", Elevation.psQuote("it's"))
        assertEquals("\"C:\\\\a\\\\b.jar\"", Elevation.argQuote("C:\\a\\b.jar"))
    }
}
