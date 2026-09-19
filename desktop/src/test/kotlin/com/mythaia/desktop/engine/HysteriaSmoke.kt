package com.mythaia.desktop.engine

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Dials the subscription's first Hysteria2 server with full tracing. Env-gated like the other smoke. */
class HysteriaSmoke {
    @Test
    fun `hysteria2 dial with trace`() = runBlocking {
        val url = System.getenv("MYTHAIA_SMOKE_SUBSCRIPTION")
        assumeTrue("MYTHAIA_SMOKE_SUBSCRIPTION not set", !url.isNullOrBlank())
        System.getenv("MYTHAIA_NATIVE")?.let { System.setProperty("mythaia.native.library", it) }
        MythaiaLogger.debugEnabled = true

        val result = SubscriptionFetcher.fetch(url!!)
        val config = result.configurations.firstOrNull { it.outboundProtocol == OutboundProtocol.HYSTERIA2 }
        assumeTrue("no hysteria2 server", config != null)
        config!!
        println("dialing ${config.name} ${config.serverAddress}:${config.serverPort} obfs=${config.obfuscation} up=${config.hysteriaUpMbps} down=${config.hysteriaDownMbps} sni=${config.tls?.serverName} alpn=${config.tls?.alpn} insecure=${config.tls?.allowInsecure}")
        val started = System.nanoTime()
        try {
            val connection = withTimeout(20_000) { ProxyClientFactory.connect(config, "captive.apple.com", 80, null) }
            println("connected in ${(System.nanoTime() - started) / 1_000_000} ms")
            connection.send("GET / HTTP/1.1\r\nHost: captive.apple.com\r\nConnection: close\r\n\r\n".toByteArray())
            val answer = withTimeout(15_000) { connection.receive() }
            println("answer: ${answer?.size} bytes: ${answer?.let { String(it, Charsets.ISO_8859_1).take(80) }}")
            connection.cancel()
        } catch (e: Throwable) {
            println("DIAL FAILED after ${(System.nanoTime() - started) / 1_000_000} ms: $e")
            e.printStackTrace(System.out)
            var cause = e.cause
            while (cause != null) { println("cause: $cause"); cause = cause.cause }
            throw e
        }
    }
}
