package com.mythaia.desktop.service

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.desktop.model.DesktopSettings
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.HttpURLConnection
import java.net.URL

/**
 * Asks the installed service to bring TUN up on the subscription's
 * Hysteria2 server, fetches a page through it (every socket of this process
 * now goes through the adapter), and takes it down. Env-gated on
 * `MYTHAIA_SMOKE_SUBSCRIPTION` and on the service answering.
 */
class ServiceTunSmoke {
    @Test
    fun `tun through the service reaches the internet`() = runBlocking {
        val url = System.getenv("MYTHAIA_SMOKE_SUBSCRIPTION")
        assumeTrue("MYTHAIA_SMOKE_SUBSCRIPTION not set", !url.isNullOrBlank())
        assumeTrue("service not running", ServiceClient.isAvailable())
        val config = SubscriptionFetcher.fetch(url!!).configurations
            .firstOrNull { it.outboundProtocol == OutboundProtocol.HYSTERIA2 }
        assumeTrue("no hysteria2 server", config != null)

        val settings = DesktopSettings(tunnelMode = "tun", setSystemProxy = false)
        val started = ServiceClient.start(settings, config!!, emptyList())
        println("start: running=${started.running} status=${started.status} error=${started.error} lastError=${started.lastError}")
        started.logs.forEach { println("  service: ${it.text}") }
        try {
            assertTrue("service did not report running", started.running)
            Thread.sleep(2_000)
            val connection = URL("http://captive.apple.com/").openConnection() as HttpURLConnection
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000
            val code = connection.responseCode
            val body = connection.inputStream.bufferedReader().readText()
            println("through tun: $code ${body.take(60)}")
            val status = ServiceClient.status(0)
            println("status: up=${status?.up} down=${status?.down} connections=${status?.connections}")
            status?.logs?.forEach { println("  service: ${it.text}") }
            assertTrue(code == 200 && body.contains("Success"))
        } finally {
            val stopped = ServiceClient.stop()
            println("stop: running=${stopped?.running}")
            stopped?.logs?.forEach { println("  service: ${it.text}") }
        }
    }
}
