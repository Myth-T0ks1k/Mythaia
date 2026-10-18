package com.mythaia.desktop.service

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.engine.TrafficStats
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.util.UUID
import kotlin.concurrent.thread

/**
 * A start the service answers after the window stopped waiting: the
 * window asks for status and adopts the tunnel, or learns it failed,
 * instead of leaving a tunnel up that it knows nothing about.
 */
class ServiceClientLateStartTest {

    /** A tunnel that takes [startMs] to come up, and fails to when [failStart]. */
    private class SlowControl(private val startMs: Long, private val failStart: Boolean = false) : TunControl {
        @Volatile override var isRunning = false
        override val statusName: String get() = if (isRunning) "RUNNING" else "STOPPED"
        @Volatile override var configuration: ProxyConfiguration? = null
        @Volatile override var lastError: String? = null
        override val stats = TrafficStats()
        override fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings) = Unit
        override fun start(settings: DesktopSettings, configuration: ProxyConfiguration) {
            Thread.sleep(startMs)
            if (failStart) {
                lastError = "adapter refused"
                throw IllegalStateException("adapter refused")
            }
            this.configuration = configuration
            isRunning = true
        }
        override fun switchTo(configuration: ProxyConfiguration) { this.configuration = configuration }
        override fun stop() { isRunning = false; configuration = null }
    }

    private val pipe = "\\\\.\\pipe\\MythaiaTest-${UUID.randomUUID()}"
    private var core: ServiceCore? = null
    private var server: Thread? = null

    @Before
    fun pointClientAtTestPipe() {
        ServiceClient.pipeName = pipe
    }

    @After
    fun tearDown() {
        ServiceClient.pipeName = ServiceProtocol.PIPE_NAME
        core?.stop()
        server?.join(5_000)
    }

    private fun serve(control: TunControl) {
        val service = ServiceCore(control, pipe)
        core = service
        server = thread(isDaemon = true) { service.serve() }
        // Up once it answers.
        repeat(50) {
            if (ServiceClient.ping() != null) return
            Thread.sleep(100)
        }
        fail("the test service never answered")
    }

    private fun config(name: String) = ProxyConfiguration.fromUrl(
        "vless://${UUID.randomUUID()}@1.2.3.4:443?security=tls&sni=x.example.com#$name"
    )

    @Test
    fun `a start that answers late is adopted`() {
        val control = SlowControl(startMs = 1_500)
        serve(control)
        val wanted = config("slow")
        val response = ServiceClient.start(DesktopSettings(), wanted, emptyList(), timeoutMs = 300, settleMs = 15_000)
        assertTrue(response.running)
        assertEquals(wanted.id.toString(), response.configurationId)
        assertTrue(control.isRunning)
    }

    @Test
    fun `a start that fails late is reported as failed, not as no answer`() {
        serve(SlowControl(startMs = 1_500, failStart = true))
        try {
            ServiceClient.start(DesktopSettings(), config("broken"), emptyList(), timeoutMs = 300, settleMs = 15_000)
            fail("a failed start was taken for a running one")
        } catch (e: ServiceClient.NoAnswer) {
            fail("the service did answer the status request: ${e.message}")
        } catch (e: IOException) {
            assertEquals("adapter refused", e.message)
        }
    }

    @Test
    fun `no service at all is reported at once, without waiting for one`() {
        val began = System.nanoTime()
        try {
            ServiceClient.start(DesktopSettings(), config("none"), emptyList(), timeoutMs = 300, settleMs = 15_000)
            fail("started without a service")
        } catch (e: ServiceClient.NoAnswer) {
            val tookMs = (System.nanoTime() - began) / 1_000_000
            assertTrue("waited $tookMs ms for a service that is not there", tookMs < 5_000)
        }
    }

    @Test
    fun `a late status for another server is not adopted`() {
        val wanted = config("wanted")
        val other = ServiceProtocol.Response(ok = true, running = true, configurationId = UUID.randomUUID().toString())
        assertEquals(ServiceClient.LateStart.OTHER, ServiceClient.lateStartVerdict(other, wanted))
        val stopped = ServiceProtocol.Response(ok = true, running = false)
        assertEquals(ServiceClient.LateStart.FAILED, ServiceClient.lateStartVerdict(stopped, wanted))
        val ours = ServiceProtocol.Response(ok = true, running = true, configurationId = wanted.id.toString())
        assertEquals(ServiceClient.LateStart.ADOPT, ServiceClient.lateStartVerdict(ours, wanted))
    }
}
