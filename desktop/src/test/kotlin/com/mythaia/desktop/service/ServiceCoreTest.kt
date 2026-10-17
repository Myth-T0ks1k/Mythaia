package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlin.concurrent.thread

/** The service protocol end to end, with a fake tunnel behind the service, over each transport. */
class ServiceCoreTest {

    private class FakeControl : TunControl {
        override var isRunning = false
        override val statusName: String get() = if (isRunning) "RUNNING" else "STOPPED"
        override var configuration: ProxyConfiguration? = null
        override var lastError: String? = null
        override val stats = TrafficStats()
        var routingCalls = 0
        override fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings) { routingCalls++ }
        override fun start(settings: DesktopSettings, configuration: ProxyConfiguration) {
            if (configuration.name == "broken") throw IllegalStateException("adapter refused")
            this.configuration = configuration; isRunning = true; stats.up.addAndGet(10)
        }
        override fun switchTo(configuration: ProxyConfiguration) { this.configuration = configuration }
        override fun stop() { isRunning = false; configuration = null }
    }

    private fun config(name: String) = ProxyConfiguration.fromUrl(
        "vless://${UUID.randomUUID()}@1.2.3.4:443?security=tls&sni=x.example.com#$name"
    )

    @Test
    fun `requests are handled and status reflects the tunnel`() {
        val control = FakeControl()
        val core = ServiceCore(control)
        core.record(com.mythaia.vpn.util.MythaiaLogger.Level.info, "hello")

        val start = core.handle(ServiceProtocol.json.encodeToString(ServiceProtocol.Request.serializer(),
            ServiceProtocol.Request("start", DesktopSettings(), config("a"), emptyList())))
        val started = ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), start)
        assertTrue(started.ok)
        assertTrue(started.running)
        assertEquals(10L, started.up)
        assertEquals(1, started.logs.size)
        assertEquals(1, control.routingCalls)

        val broken = ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(),
            core.handle("""{"cmd":"start","settings":{},"configuration":${ServiceProtocol.json.encodeToString(ProxyConfiguration.serializer(), config("broken"))}}"""))
        assertFalse(broken.ok)
        assertEquals("adapter refused", broken.error)

        val stopped = ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), core.handle("""{"cmd":"stop"}"""))
        assertTrue(stopped.ok)
        assertFalse(stopped.running)

        val bad = ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), core.handle("not json"))
        assertFalse(bad.ok)
        assertNotNull(bad.error)
    }

    private fun decode(reply: String?): ServiceProtocol.Response {
        assertNotNull("no reply", reply)
        return ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), reply!!)
    }

    private fun encode(request: ServiceProtocol.Request) =
        ServiceProtocol.json.encodeToString(ServiceProtocol.Request.serializer(), request)

    /** Start, status, switch and stop through [transport], with [core] serving on another thread. */
    private fun conversation(transport: ServiceTransport, control: FakeControl) {
        val core = ServiceCore(control, transport)
        val server = thread(isDaemon = true) { core.serve() }
        try {
            var ping: String? = null
            for (attempt in 0 until 50) {
                ping = transport.exchange("""{"cmd":"ping"}""", 2_000)
                if (ping != null) break
                Thread.sleep(100)
            }
            assertTrue(decode(ping).ok)

            val started = decode(transport.exchange(encode(ServiceProtocol.Request("start", DesktopSettings(), config("a"), emptyList())), 5_000))
            assertTrue(started.ok)
            assertTrue(started.running)
            assertEquals(control.configuration?.id?.toString(), started.configurationId)

            val switched = decode(transport.exchange(encode(ServiceProtocol.Request("switch", configuration = config("b"))), 5_000))
            assertEquals("b", control.configuration?.name)
            assertTrue(switched.running)

            val failed = decode(transport.exchange(encode(ServiceProtocol.Request("start", DesktopSettings(), config("broken"), emptyList())), 5_000))
            assertFalse(failed.ok)
            assertEquals("adapter refused", failed.error)

            val stopped = decode(transport.exchange("""{"cmd":"stop"}""", 5_000))
            assertTrue(stopped.ok)
            assertFalse(stopped.running)
        } finally {
            core.stop()
            server.join(3_000)
        }
        assertFalse("serve() returns once stopped", server.isAlive)
    }

    @Test
    fun `the core is the same over any transport`() {
        conversation(MemoryTransport(), FakeControl())
    }

    @Test
    fun `a round trip over a Unix domain socket`() {
        // AF_UNIX paths are short and, on Windows, must be ASCII; the JDK's own socket directory is both.
        val base = System.getProperty("jdk.net.unixdomain.tmpdir") ?: System.getProperty("java.io.tmpdir")
        assumeTrue("no ASCII temp directory for the socket", base.all { it.code < 128 })
        val dir = File(base, "mythaia-sock-${UUID.randomUUID().toString().take(8)}")
        val path: Path = File(dir, "s.sock").toPath()
        try {
            val transport = UnixSocketTransport(path)
            assertEquals("nobody listens yet", null, transport.exchange("""{"cmd":"ping"}""", 500))
            // A socket file left by a run that died is replaced, not an obstacle.
            dir.mkdirs()
            Files.write(path, ByteArray(0))
            assertEquals("a stale file is not a listener", null, transport.exchange("""{"cmd":"ping"}""", 500))
            conversation(transport, FakeControl())
            assertFalse("the socket file goes with the service", Files.exists(path))
        } finally {
            Files.deleteIfExists(path)
            dir.delete()
        }
    }

    @Test
    fun `lines are read up to the newline, without the carriage return`() {
        val input = "{\"cmd\":\"ping\"}\r\nsecond\nlast".byteInputStream()
        assertEquals("{\"cmd\":\"ping\"}", UnixSocketTransport.readLineFrom(input))
        assertEquals("second", UnixSocketTransport.readLineFrom(input))
        assertEquals("last", UnixSocketTransport.readLineFrom(input))
        assertEquals(null, UnixSocketTransport.readLineFrom(input))
    }

    @Test
    fun `a round trip over a real named pipe works without privileges`() {
        assumeTrue("named pipes are Windows'", com.mythaia.desktop.Platform.isWindows)
        val control = FakeControl()
        val name = "\\\\.\\pipe\\MythaiaTest-${UUID.randomUUID()}"
        val core = ServiceCore(control, NamedPipeTransport(name))
        val server = thread(isDaemon = true) { core.serve() }
        try {
            var reply: String? = null
            for (attempt in 0 until 50) {
                reply = NamedPipe.exchange(name, """{"cmd":"ping"}""", 2_000)
                if (reply != null) break
                Thread.sleep(100)
            }
            assertNotNull("no reply from the pipe server", reply)
            val response = ServiceProtocol.json.decodeFromString(ServiceProtocol.Response.serializer(), reply!!)
            assertTrue(response.ok)
            assertEquals(ServiceProtocol.VERSION, response.version)

            val second = NamedPipe.exchange(name, """{"cmd":"status","logSince":0}""", 2_000)
            assertNotNull(second)
        } finally {
            core.stop()
            server.join(3_000)
        }
    }
}
