package com.mythaia.desktop.engine

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.desktop.model.DesktopSettings
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.URL

/**
 * The whole desktop path: local SOCKS5 listener → router → the subscription's
 * Hysteria2 server → the internet. Env-gated on `MYTHAIA_SMOKE_SUBSCRIPTION`;
 * the system proxy is left alone.
 */
class EngineSmoke {
    @Test
    fun `a request through the local proxy reaches the internet via hysteria2`() = runBlocking {
        val url = System.getenv("MYTHAIA_SMOKE_SUBSCRIPTION")
        assumeTrue("MYTHAIA_SMOKE_SUBSCRIPTION not set", !url.isNullOrBlank())
        val config = SubscriptionFetcher.fetch(url!!).configurations
            .firstOrNull { it.outboundProtocol == OutboundProtocol.HYSTERIA2 }
        assumeTrue("no hysteria2 server", config != null)

        val socks = ServerSocket(0).use { it.localPort }
        val http = ServerSocket(0).use { it.localPort }
        val engine = ProxyEngine(TrafficStats())
        val settings = DesktopSettings(socksPort = socks, httpPort = http, setSystemProxy = false)
        engine.updateRouting(emptyList(), settings)
        engine.start(settings, config!!)
        try {
            for ((name, proxy) in listOf(
                "socks5" to Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socks)),
                "http" to Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", http))
            )) {
                val connection = URL("http://captive.apple.com/").openConnection(proxy) as HttpURLConnection
                connection.connectTimeout = 15_000
                connection.readTimeout = 15_000
                val code = connection.responseCode
                val body = connection.inputStream.bufferedReader().readText()
                println("$name: $code ${body.take(60)}")
                assertTrue("$name gave $code", code == 200)
                assertTrue(body.contains("Success", ignoreCase = true))
            }
            println("traffic: up=${engine.stats.up.get()} down=${engine.stats.down.get()}")
        } finally {
            engine.stop()
        }
    }
}
