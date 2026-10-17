package com.mythaia.desktop.tun

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * What the macOS network setup remembers and undoes, with the system calls
 * replaced by a recorder: routes that already existed are not taken over,
 * every route is on record before it exists, DNS goes back as it was, and
 * a snapshot left by a crash is acted on only when it is exactly what this
 * version writes.
 */
class MacNetworkTest {

    private val file: File = File.createTempFile("mythaia-mac-net", ".json").also { it.delete() }

    @After
    fun cleanup() {
        file.delete()
    }

    /** Runs nothing; records the command lines and fails the ones [failing] matches. */
    private class Recorder(var failing: (String) -> String? = { null }) {
        val commands = ArrayList<String>()
        var onRun: (String) -> Unit = {}
        fun run(argv: List<String>): MacNet.Result {
            val line = argv.joinToString(" ")
            commands += line
            onRun(line)
            val error = failing(line)
            return if (error == null) MacNet.Result(0, "") else MacNet.Result(1, error)
        }
    }

    private val dns = mapOf(
        "Wi-Fi" to listOf("192.0.2.53"),
        "Ethernet" to emptyList(),
        "Thunderbolt Bridge" to null
    )

    private fun network(recorder: Recorder, trusted: Boolean = true) =
        MacNetwork(file, runner = recorder::run, readDns = { dns[it] }, trusted = { trusted })

    private val config = MacNetConfig(
        interfaceName = "utun5",
        physicalInterface = "en0",
        physicalGateway = "192.168.1.1",
        excludedHosts = listOf("203.0.113.10"),
        excludedNetworks = listOf("10.0.0.0/8", "172.16.0.0/12"),
        services = listOf("Wi-Fi", "Ethernet", "Thunderbolt Bridge")
    )

    private fun saved() = MacNetwork.parseSnapshot(file.readText())!!

    @Test
    fun `a route that already existed is not ours to delete`() {
        val recorder = Recorder(failing = { if (it.contains("-net 10.0.0.0/8 ")) "route: writing to routing socket: File exists" else null })
        val net = network(recorder)
        net.apply(config)

        val snapshot = saved()
        assertEquals(listOf("172.16.0.0", "203.0.113.10"), snapshot.routes.map { it.destination })
        assertEquals(listOf(ServiceDns("Wi-Fi", listOf("192.0.2.53")), ServiceDns("Ethernet", emptyList())), snapshot.dns)
        assertTrue(recorder.commands.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi 198.18.0.0"))

        recorder.commands.clear()
        net.restore()
        assertEquals(
            listOf(
                "/usr/sbin/networksetup -setdnsservers Wi-Fi 192.0.2.53",
                "/usr/sbin/networksetup -setdnsservers Ethernet Empty",
                "/usr/bin/dscacheutil -flushcache",
                "/usr/bin/killall -HUP mDNSResponder",
                "/sbin/route -q -n delete -host 203.0.113.10 192.168.1.1",
                "/sbin/route -q -n delete -net 172.16.0.0/12 192.168.1.1"
            ),
            recorder.commands
        )
        assertFalse(file.exists())
        assertNull(net.applied)
        recorder.commands.clear()
        net.restore()
        assertTrue("a second restore does nothing", recorder.commands.isEmpty())
    }

    @Test
    fun `every route is on record before it is added`() {
        val recorder = Recorder()
        recorder.onRun = { line ->
            if (line.startsWith("/sbin/route -q -n add -host 203.0.113.10")) {
                assertTrue(MacNetwork.parseSnapshot(file.readText())!!.routes.any { it.destination == "203.0.113.10" })
            }
            if (line.contains("-setdnsservers Wi-Fi 198.18.0.0")) {
                assertEquals(2, MacNetwork.parseSnapshot(file.readText())!!.dns.size)
            }
        }
        network(recorder).apply(config)
    }

    @Test
    fun `a host excluded later is added once and undone`() {
        val recorder = Recorder()
        val net = network(recorder)
        net.apply(config)
        net.excludeHost("198.51.100.7")
        net.excludeHost("198.51.100.7")
        net.excludeHost("203.0.113.10")
        assertEquals(1, recorder.commands.count { it == "/sbin/route -q -n add -host 198.51.100.7 192.168.1.1" })
        assertEquals(1, recorder.commands.count { it.startsWith("/sbin/route -q -n add -host 203.0.113.10") })
        assertTrue(saved().routes.any { it.destination == "198.51.100.7" })
        net.restore()
        assertTrue(recorder.commands.contains("/sbin/route -q -n delete -host 198.51.100.7 192.168.1.1"))
    }

    @Test
    fun `an essential failure rolls back and throws`() {
        val recorder = Recorder(failing = { if (it.contains("-net 128.0.0.0/1")) "route: bad address" else null })
        val net = network(recorder)
        try {
            net.apply(config)
            fail("expected the setup to fail")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("bad address"))
        }
        assertTrue(recorder.commands.contains("/sbin/route -q -n delete -host 203.0.113.10 192.168.1.1"))
        assertTrue(recorder.commands.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi 192.0.2.53"))
        assertTrue("DNS is never switched after a failure", recorder.commands.none { it.endsWith("198.18.0.0") })
        assertFalse(file.exists())
        assertNull(net.applied)
    }

    @Test
    fun `a crash is undone by the next start`() {
        network(Recorder()).apply(config)
        assertTrue(file.exists())

        val next = Recorder()
        network(next).cleanupLeftovers()
        assertTrue(next.commands.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi 192.0.2.53"))
        assertTrue(next.commands.contains("/usr/sbin/networksetup -setdnsservers Ethernet Empty"))
        assertTrue(next.commands.contains("/sbin/route -q -n delete -net 10.0.0.0/8 192.168.1.1"))
        assertTrue(next.commands.contains("/sbin/route -q -n delete -host 203.0.113.10 192.168.1.1"))
        assertFalse(file.exists())
    }

    @Test
    fun `DNS that could not be restored stays on record`() {
        network(Recorder()).apply(config)
        val failing = Recorder(failing = { if (it.contains("-setdnsservers Wi-Fi")) "networksetup: busy" else null })
        network(failing).cleanupLeftovers()
        assertTrue(file.exists())
        val left = saved()
        assertEquals(listOf(ServiceDns("Wi-Fi", listOf("192.0.2.53"))), left.dns)
        assertTrue(left.routes.isEmpty())

        val retry = Recorder()
        network(retry).cleanupLeftovers()
        assertEquals(1, retry.commands.count { it == "/usr/sbin/networksetup -setdnsservers Wi-Fi 192.0.2.53" })
        assertFalse(file.exists())
    }

    @Test
    fun `the sentinel left by a lost snapshot is not saved as the user's DNS`() {
        val recorder = Recorder()
        val net = MacNetwork(file, runner = recorder::run, readDns = { listOf("198.18.0.0") }, trusted = { true })
        net.apply(config.copy(services = listOf("Wi-Fi")))
        assertEquals(listOf(ServiceDns("Wi-Fi", emptyList())), saved().dns)
        net.restore()
        assertTrue(recorder.commands.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi Empty"))
    }

    @Test
    fun `an untrusted snapshot is discarded unread`() {
        network(Recorder()).apply(config)
        val recorder = Recorder()
        network(recorder, trusted = false).cleanupLeftovers()
        assertTrue(recorder.commands.isEmpty())
        assertFalse(file.exists())
    }

    @Test
    fun `a tampered snapshot is rejected whole`() {
        val good = MacRouteEntry(MacRouteEntry.HOST, "203.0.113.10", 32, "192.168.1.1")
        fun with(route: MacRouteEntry = good, dns: ServiceDns = ServiceDns("Wi-Fi", listOf("192.0.2.53"))) =
            MacNetwork.encodeSnapshot(listOf(good, route), listOf(dns))

        assertNotNull(MacNetwork.parseSnapshot(with()))
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(gateway = "192.168.1.1; reboot"))))
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(gateway = null, interfaceName = "en0 -x"))))
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(gateway = null))))                   // neither next hop nor interface
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(interfaceName = "en0"))))            // both
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(kind = "exec"))))
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(prefix = 24))))                      // a host is /32
        assertNull(MacNetwork.parseSnapshot(with(route = good.copy(destination = "example.com"))))
        assertNull(MacNetwork.parseSnapshot(with(dns = ServiceDns("-setairportpower", emptyList()))))
        assertNull(MacNetwork.parseSnapshot(with(dns = ServiceDns("Wi-Fi\nx", emptyList()))))
        assertNull(MacNetwork.parseSnapshot(with(dns = ServiceDns("Wi-Fi", listOf("resolver.example")))))
        assertNull(MacNetwork.parseSnapshot("""{"routes":[],"dns":[]}"""))                               // no version
        assertNull(MacNetwork.parseSnapshot("not json"))

        val parsed = MacNetwork.parseSnapshot(with(dns = ServiceDns("USB 10/100/1000 LAN", listOf("2001:DB8::53"))))!!
        assertEquals("2001:db8::53", parsed.dns.single().servers.single())
        assertEquals(MacRouteEntry(MacRouteEntry.NET, "10.0.0.0", 8, null, "en0"),
            MacNetwork.parseSnapshot(MacNetwork.encodeSnapshot(listOf(MacRouteEntry(MacRouteEntry.NET, "10.0.0.0", 8, null, "en0")), emptyList()))!!.routes.single())
    }

    @Test
    fun `route and resolver output is parsed`() {
        val route = MacNet.parseRouteGet(
            """
               route to: default
            destination: default
                   mask: default
                gateway: 192.168.1.1
              interface: en0
                  flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
             recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
                   0         0         0         0         0         0      1500         0
            """.trimIndent()
        )
        assertEquals(MacNet.RouteGet("192.168.1.1", "en0"), route)
        assertEquals(MacNet.RouteGet(null, "utun3"), MacNet.parseRouteGet("gateway: link#18\ninterface: utun3\n"))
        assertNull(MacNet.parseRouteGet("route: route has not been found\n"))

        val resolv = """
            #
            # macOS Notice
            #
            search example.lan
            nameserver 192.168.1.1
            nameserver fe80::1%en0
            nameserver 198.18.0.0
            nameserver 127.0.0.1
            nameserver 192.0.2.53
        """.trimIndent()
        assertEquals(listOf("192.168.1.1", "192.0.2.53"), MacNet.parseResolvConf(resolv))

        assertEquals(emptyList<String>(), MacNet.parseDnsServers("There aren't any DNS Servers set on Wi-Fi.\n"))
        assertEquals(listOf("192.0.2.53", "2001:db8::53"), MacNet.parseDnsServers("192.0.2.53\n2001:db8::53\n"))
    }
}
