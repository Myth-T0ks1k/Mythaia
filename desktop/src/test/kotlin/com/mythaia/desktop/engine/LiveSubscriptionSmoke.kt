package com.mythaia.desktop.engine

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.SubscriptionFetcher
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * A live check against the servers of a subscription named in the
 * `MYTHAIA_SMOKE_SUBSCRIPTION` environment variable: fetch, then a real HTTP
 * round trip through the first few servers of each protocol. Skipped when
 * the variable is not set, so the ordinary test run stays offline.
 */
class LiveSubscriptionSmoke {

    @Test
    fun `servers of the subscription answer a real ping`() = runBlocking {
        val url = System.getenv("MYTHAIA_SMOKE_SUBSCRIPTION")
        assumeTrue("MYTHAIA_SMOKE_SUBSCRIPTION not set", !url.isNullOrBlank())
        System.getenv("MYTHAIA_NATIVE")?.let { System.setProperty("mythaia.native.library", it) }
        MythaiaLogger.debugEnabled = true

        val result = SubscriptionFetcher.fetch(url!!)
        println("fetched ${result.configurations.size} servers, name=${result.name}")
        val byProtocol = result.configurations.groupBy { it.outboundProtocol }
        val report = StringBuilder()
        var successes = 0
        for ((protocol, configs) in byProtocol) {
            for (config in configs.take(3)) {
                val latency = LatencyTester.test(config, LatencyKind.HTTP)
                val line = "${protocol.displayName.padEnd(12)} ${config.name.take(28).padEnd(28)} ${config.transport.padEnd(10)} $latency"
                println(line)
                report.appendLine(line)
                if (latency is LatencyResult.Success) successes++
            }
        }
        println("successes: $successes")
        assert(successes > 0) { "no server answered:\n$report" }
        assumeTrue(OutboundProtocol.VLESS in byProtocol)
    }
}
