package com.mythaia.desktop.engine

import com.mythaia.data.model.FragmentSettings
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.tls.FragmentPolicy
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Every measurement kind against the servers at `MYTHAIA_SMOKE_SERVER`
 * (comma-separated addresses), each TLS server in three fragmentation
 * modes, then a traced dial. Env-gated.
 */
class ReachableServerSmoke {
    @Test
    fun `tcp handshake and http against addresses`() = runBlocking {
        val url = System.getenv("MYTHAIA_SMOKE_SUBSCRIPTION")
        val addresses = System.getenv("MYTHAIA_SMOKE_SERVER")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
        assumeTrue("env not set", !url.isNullOrBlank() && !addresses.isNullOrEmpty())
        System.getenv("MYTHAIA_NATIVE")?.let { System.setProperty("mythaia.native.library", it) }
        MythaiaLogger.debugEnabled = true

        val all = SubscriptionFetcher.fetch(url!!).configurations
        val configs = all.filter { it.serverAddress in addresses!! }.distinctBy { it.serverAddress + it.transport }
        assumeTrue("no server at $addresses", configs.isNotEmpty())
        for (base in configs) {
            val variants: List<Pair<String, ProxyConfiguration>> = if (base.tls != null) listOf(
                "as-sent" to base,
                "no-fragment" to base.copy(tls = base.tls!!.copy(fragment = FragmentSettings(isEnabled = false))),
                "default-100-200" to base.copy(tls = base.tls!!.copy(fragment = FragmentSettings()))
            ) else listOf("plain" to base)
            for ((label, config) in variants) {
                FragmentPolicy.set(if (label == "no-fragment") FragmentSettings(isEnabled = false) else FragmentSettings())
                println("== ${config.name} ${config.outboundProtocol} transport=${config.transport} security=${config.security} sni=${config.tls?.serverName} fp=${config.tls?.fingerprint} [$label]")
                for (kind in listOf(LatencyKind.HANDSHAKE, LatencyKind.HTTP)) {
                    val started = System.nanoTime()
                    val result = LatencyTester.test(config, kind)
                    println("   $kind -> $result in ${(System.nanoTime() - started) / 1_000_000} ms")
                }
                val started = System.nanoTime()
                try {
                    val connection = withTimeout(20_000) { ProxyClientFactory.connect(config, "captive.apple.com", 80, null) }
                    println("   dial ok in ${(System.nanoTime() - started) / 1_000_000} ms")
                    connection.send("GET / HTTP/1.1\r\nHost: captive.apple.com\r\nConnection: close\r\n\r\n".toByteArray())
                    val answer = withTimeout(15_000) { connection.receive() }
                    println("   answer: ${answer?.size} bytes: ${answer?.let { String(it, Charsets.ISO_8859_1).take(60).replace("\r\n", " ") }}")
                    connection.cancel()
                } catch (e: Throwable) {
                    println("   DIAL FAILED after ${(System.nanoTime() - started) / 1_000_000} ms: $e")
                    var cause = e.cause
                    while (cause != null) { println("   cause: $cause"); cause = cause.cause }
                }
            }
        }
    }
}
