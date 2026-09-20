package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID
import kotlin.concurrent.thread

/** The pipe protocol end to end, with a fake tunnel behind the service. */
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

    @Test
    fun `a round trip over a real named pipe works without privileges`() {
        val control = FakeControl()
        val name = "\\\\.\\pipe\\MythaiaTest-${UUID.randomUUID()}"
        val core = ServiceCore(control, name)
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
