package com.mythaia.desktop.tun

import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.TunnelConstants
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * The exact `ifconfig`, `route` and `networksetup` lines TUN mode runs on
 * macOS. They need a Mac and root to execute, so the text is pinned: a typo
 * here is a Mac with no internet until the next restart.
 */
class MacRoutePlanTest {

    private val config = MacNetConfig(
        interfaceName = "utun5",
        ipv6Address = MacNetConfig.ADDRESS6,
        physicalInterface = "en0",
        physicalGateway = "192.168.1.1",
        excludedHosts = listOf("203.0.113.10", "1.1.1.1", "203.0.113.10"),
        excludedNetworks = listOf("10.0.0.0/8", "198.51.100.0/24"),
        services = listOf("Wi-Fi", "USB 10/100/1000 LAN")
    )

    private fun lines(steps: List<MacStep>) = steps.map { it.toString() }

    @Test
    fun `setup addresses the utun, keeps the physical side out, takes the default route and then DNS`() {
        val setup = lines(MacRoutePlan.setup(config))
        assertEquals("/sbin/ifconfig utun5 inet 198.19.255.1 198.19.255.2 netmask 255.255.255.255 mtu 1500 up", setup[0])
        assertEquals("/sbin/ifconfig utun5 inet6 fd00:6d79:7468::2 prefixlen 64 alias", setup[1])
        val expected = listOf(
            "/sbin/route -q -n add -net 10.0.0.0/8 192.168.1.1",
            "/sbin/route -q -n add -net 198.51.100.0/24 192.168.1.1",
            "/sbin/route -q -n add -host 203.0.113.10 192.168.1.1",
            "/sbin/route -q -n add -host 1.1.1.1 192.168.1.1",
            "/sbin/route -q -n add -net 0.0.0.0/1 -interface utun5",
            "/sbin/route -q -n add -net 128.0.0.0/1 -interface utun5",
            "/sbin/route -q -n add -inet6 ::/1 -interface utun5",
            "/sbin/route -q -n add -inet6 8000::/1 -interface utun5",
            "/usr/sbin/networksetup -setdnsservers Wi-Fi 198.18.0.0",
            "/usr/sbin/networksetup -setdnsservers USB 10/100/1000 LAN 198.18.0.0",
            "/usr/bin/dscacheutil -flushcache",
            "/usr/bin/killall -HUP mDNSResponder"
        )
        assertEquals(expected, setup.drop(2))
        assertEquals(1, setup.count { it.contains("-host 203.0.113.10 ") })   // deduplicated
        // A service name with spaces stays one argument; nothing goes through a shell.
        val dns = MacRoutePlan.setup(config).first { it.argv.contains("USB 10/100/1000 LAN") }
        assertEquals(listOf("/usr/sbin/networksetup", "-setdnsservers", "USB 10/100/1000 LAN", TunnelConstants.dnsSentinelV4), dns.argv)
    }

    @Test
    fun `only the address and the two half routes are essential`() {
        val essential = MacRoutePlan.setup(config).filter { it.essential }.map { it.toString() }
        assertEquals(3, essential.size)
        assertTrue(essential[0].startsWith("/sbin/ifconfig utun5 inet "))
        assertTrue(essential[1].endsWith("-net 0.0.0.0/1 -interface utun5"))
        assertTrue(essential[2].endsWith("-net 128.0.0.0/1 -interface utun5"))
    }

    @Test
    fun `every physical-side route can be undone and nothing on the utun is`() {
        val undo = MacRoutePlan.setup(config).mapNotNull { it.undo }
        assertEquals(4, undo.size)
        assertTrue(undo.none { it.interfaceName == "utun5" })
        assertEquals(
            listOf(
                "/sbin/route -q -n delete -net 10.0.0.0/8 192.168.1.1",
                "/sbin/route -q -n delete -net 198.51.100.0/24 192.168.1.1",
                "/sbin/route -q -n delete -host 203.0.113.10 192.168.1.1",
                "/sbin/route -q -n delete -host 1.1.1.1 192.168.1.1"
            ),
            undo.map { it.deleteCommand().joinToString(" ") }
        )
    }

    @Test
    fun `without a gateway the exclusions name the interface`() {
        val onLink = config.copy(physicalGateway = null)
        val setup = lines(MacRoutePlan.setup(onLink))
        assertTrue(setup.contains("/sbin/route -q -n add -host 203.0.113.10 -interface en0"))
        assertTrue(setup.contains("/sbin/route -q -n add -net 10.0.0.0/8 -interface en0"))
        assertEquals("/sbin/route -q -n delete -host 198.51.100.7 -interface en0",
            MacRoutePlan.hostEntry(onLink, "198.51.100.7")!!.deleteCommand().joinToString(" "))
    }

    @Test
    fun `IPv6 and DNS are left alone when not asked for`() {
        val plain = config.copy(ipv6Address = null, dnsServer = null)
        val setup = lines(MacRoutePlan.setup(plain))
        assertTrue(setup.none { it.contains("inet6") })
        assertTrue(setup.none { it.contains("networksetup") || it.contains("mDNSResponder") })
    }

    @Test
    fun `restoring DNS hands an empty list back to DHCP`() {
        assertEquals(listOf("/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "Empty"), MacRoutePlan.setDns("Wi-Fi", emptyList()))
        assertEquals(listOf("/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53", "192.0.2.54"),
            MacRoutePlan.setDns("Wi-Fi", listOf("192.0.2.53", "192.0.2.54")))
    }

    @Test
    fun `host entries take IPv4 literals only`() {
        assertNull(MacRoutePlan.hostEntry(config, "2001:db8::1"))
        assertNull(MacRoutePlan.hostEntry(config, "example.com"))
        assertNull(MacRoutePlan.hostEntry(config, "1.2.3.4; reboot"))
    }

    @Test
    fun `the utun's own addresses are outside the fake-IP pool`() {
        fun value(ip: String) = InetAddress.getByName(ip).address.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        val lastFake = InetAddress.getByAddress(FakeIpPool.ipv4Bytes(TunnelConstants.fakeIPPoolSize)).hostAddress
        assertTrue(value(MacNetConfig.ADDRESS) > value(lastFake))
        assertTrue(value(MacNetConfig.PEER) > value(lastFake))
        // ...but inside 198.18.0.0/15, which no LAN uses.
        assertTrue(MacNetConfig.ADDRESS.startsWith("198.19."))
        assertFalse(MacNetConfig.ADDRESS == TunnelConstants.dnsSentinelV4)
    }
}
