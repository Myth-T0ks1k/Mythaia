package com.mythaia.desktop.tun

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.Platform
import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.TunnelConstants
import com.mythaia.vpn.tun.TunHost
import com.mythaia.vpn.tun.TunRoute
import com.mythaia.vpn.tun.TunSettings
import com.mythaia.vpn.tun.TunStack
import com.mythaia.vpn.util.DnsUpstream
import com.mythaia.vpn.util.DnsUpstreamClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * TUN mode on a real Mac, as root: a utun is created through the kernel
 * control and configured with the real `ifconfig` and `route` commands,
 * lwIP runs behind it with the interop lab's SOCKS5 server as the outbound,
 * and the lab's 4 MB file is downloaded through the tunnel and checked
 * against its SHA-256. A second test points every network service's DNS
 * elsewhere and checks it comes back, also from a snapshot left as if by a
 * crash.
 *
 * The default route is not taken. On a CI runner that would send the
 * runner's own connections, and the lab's Xray (another process, which the
 * app's socket binding does not cover), into the tunnel. Traffic to
 * 127.0.0.1 never enters a utun at all. So the fake-IP range 198.18.0.0/15
 * is routed into the utun instead — the addresses the stack's DNS hands
 * out — the stack's DNS is asked for `localhost` at the sentinel, and the
 * download goes to the fake address it answers. The stack turns that back
 * into the name for the SOCKS request, and Xray resolves it to the lab's
 * HTTP server. A host route for a documentation address through the real
 * gateway checks the physical side and its undo.
 *
 * Runs only with MYTHAIA_MAC_TUN_SMOKE=1; then everything else it needs
 * (macOS, root, the native library, the lab) must be there or it fails.
 * scripts/mac-tun-smoke.sh prepares all of it and runs only the test JVM as
 * root; see docs/TESTING.md.
 */
class MacTunSmoke {

    private lateinit var physical: PhysicalPath

    @Before
    fun gate() {
        assumeTrue("MYTHAIA_MAC_TUN_SMOKE not set", System.getenv("MYTHAIA_MAC_TUN_SMOKE") == "1")
        assertTrue("macOS only", Platform.isMac)
        assertTrue("must run as root (sudo)", MacUtun.isRoot())
        physical = MacNet.physicalPath() ?: throw AssertionError("no default route")
        println("physical: ${physical.interfaceName} ${physical.address.hostAddress} via ${physical.gateway ?: "on-link"}, DNS ${physical.dnsServers}, IPv6 ${physical.hasIpv6}")
    }

    @Test
    fun `a download through a utun matches the lab's file`() {
        assertTrue("native library not loaded (-Dmythaia.native.library)", NativeBridge.isLoaded)
        val lab = labDir()
        val lines = File(lab, "lab-links.txt").readLines()
        val (target, sha) = lines.first { it.startsWith("#http ") }.removePrefix("#http ").trim().split(Regex("\\s+"))
        val port = target.substringBefore('/').substringAfter(':').toInt()
        val path = "/" + target.substringAfter('/')
        val socks = lines.first { it.startsWith("socks5://") }.replace("@10.0.2.2:", "@127.0.0.1:")
        val config = ProxyConfiguration.fromUrl(socks)

        val snapshot = File.createTempFile("mythaia-tun-smoke", ".json").also { it.delete() }
        val network = MacNetwork(snapshot)
        val device = MacUtun.open()
        println("utun: ${device.name}")
        val down = AtomicLong()
        val up = AtomicLong()
        var stack: TunStack? = null
        var reader: Thread? = null
        val running = AtomicBoolean(true)
        try {
            network.apply(
                MacNetConfig(
                    interfaceName = device.name,
                    tunnelledNetworks = listOf("198.18.0.0/15"),
                    physicalInterface = physical.interfaceName!!,
                    physicalGateway = physical.gateway,
                    excludedHosts = listOf(EXCLUDED_HOST),
                    excludedNetworks = emptyList(),
                    dnsServer = null
                )
            )
            val routed = MacNet.run(listOf(MacNet.ROUTE, "-n", "get", "198.18.0.7")).output
            assertTrue("fake range not routed into ${device.name}:\n$routed", routed.contains("interface: ${device.name}"))
            val excluded = MacNet.run(listOf(MacNet.ROUTE, "-n", "get", EXCLUDED_HOST)).output
            assertTrue("no host route for $EXCLUDED_HOST:\n$excluded", excluded.contains("destination: $EXCLUDED_HOST"))
            assertEquals(listOf(EXCLUDED_HOST), MacNetwork.parseSnapshot(snapshot.readText())!!.routes.map { it.destination })

            val tunStack = TunStack(object : TunHost {
                override fun writePacket(packet: ByteArray, length: Int) {
                    if (device.send(packet, length)) down.addAndGet(length.toLong())
                }

                override fun route(host: String, port: Int, udp: Boolean): TunRoute = TunRoute.Proxy(config)
            })
            stack = tunStack
            tunStack.start(config, TunSettings())
            device.start()
            reader = thread(name = "utun-smoke-reader", isDaemon = true) {
                device.readLoop({ running.get() }) { batch ->
                    for (p in batch) up.addAndGet(p.size.toLong())
                    tunStack.input(batch)
                }
            }

            // UDP through the utun to the stack's own resolver.
            val answers = DnsUpstreamClient.resolve(
                "localhost", DnsUpstream.Plain(TunnelConstants.dnsSentinelV4), null, DnsUpstreamClient.Family.IPV4, timeoutMs = 5_000
            )
            val fake = answers.firstOrNull()
            assertNotNull("the stack's DNS did not answer through ${device.name}", fake)
            assertTrue("not a fake address: $fake", FakeIpPool.isFakeIp(fake!!))
            println("localhost -> $fake")

            // TCP through the utun, lwIP and the SOCKS5 server.
            val started = System.nanoTime()
            val connection = URL("http://$fake:$port$path").openConnection(Proxy.NO_PROXY) as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            assertEquals(200, connection.responseCode)
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            connection.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                    total += n
                }
            }
            val seconds = (System.nanoTime() - started) / 1e9
            println("downloaded $total bytes in ${"%.2f".format(seconds)} s through ${device.name}; utun up ${up.get()} B, down ${down.get()} B")
            assertEquals(sha, digest.digest().joinToString("") { "%02x".format(it) })
        } finally {
            running.set(false)
            stack?.let { s ->
                val done = CountDownLatch(1)
                s.stop { done.countDown() }
                done.await(5, TimeUnit.SECONDS)
            }
            device.stop()
            reader?.join(2_000)
            device.close()
            network.restore()
        }
        assertFalse("snapshot left behind", snapshot.exists())
        val after = MacNet.run(listOf(MacNet.ROUTE, "-n", "get", EXCLUDED_HOST)).output
        assertFalse("host route left behind:\n$after", after.contains("destination: $EXCLUDED_HOST"))
        assertFalse("${device.name} still exists", MacNet.run(listOf(MacNet.IFCONFIG, device.name)).ok)
    }

    @Test
    fun `every service's DNS is replaced and put back, also after a crash`() {
        val services = MacNet.services()
        assertTrue("no network services", services.isNotEmpty())
        val before = services.associateWith { MacNet.dnsServers(it) }
        println("DNS before: $before")
        val snapshot = File.createTempFile("mythaia-dns-smoke", ".json").also { it.delete() }
        val network = MacNetwork(snapshot)
        val device = MacUtun.open()
        try {
            network.apply(
                MacNetConfig(
                    interfaceName = device.name,
                    tunnelledNetworks = emptyList(),
                    physicalInterface = physical.interfaceName!!,
                    physicalGateway = physical.gateway,
                    excludedNetworks = emptyList(),
                    dnsServer = TEST_RESOLVER,
                    services = services
                )
            )
            for (service in services) assertEquals(service, listOf(TEST_RESOLVER), MacNet.dnsServers(service))
            assertTrue(MacNet.isTrusted(snapshot))

            // What the next start does after a crash: the snapshot alone puts DNS back.
            MacNetwork(snapshot).cleanupLeftovers()
            assertFalse(snapshot.exists())
            for (service in services) assertEquals(service, before[service], MacNet.dnsServers(service))
        } finally {
            network.restore()
            device.close()
        }
        for (service in services) assertEquals(service, before[service], MacNet.dnsServers(service))
    }

    private fun labDir(): File {
        val candidates = listOfNotNull(System.getenv("MYTHAIA_LAB_OUT"), "../scripts/lab/out", "scripts/lab/out").map(::File)
        return candidates.firstOrNull { File(it, "lab-links.txt").isFile }
            ?: throw AssertionError("lab not generated: run scripts/lab/ci-macos.sh (looked in $candidates)")
    }

    private companion object {
        /** A documentation address (RFC 5737): routed around the tunnel and back, never contacted. */
        const val EXCLUDED_HOST = "192.0.2.1"

        /** A public resolver that works on CI runners, set briefly in place of the services' own. */
        const val TEST_RESOLVER = "1.1.1.1"
    }
}
