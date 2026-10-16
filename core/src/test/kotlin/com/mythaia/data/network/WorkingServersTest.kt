package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.UUID

class WorkingServersTest {

    private fun server(name: String, subscription: UUID?) =
        ProxyConfiguration.fromUrl("trojan://p@$name.example.com:443?sni=$name.example.com#$name").copy(subscriptionId = subscription)

    @Test
    fun `the subscription's own servers come first, the ones that answered before the untested and the failed`() {
        val mine = UUID.randomUUID()
        val other = UUID.randomUUID()
        val ownSlow = server("own-slow", mine)
        val ownUntested = server("own-new", mine)
        val ownDead = server("own-dead", mine)
        val ownFast = server("own-fast", mine)
        val otherFast = server("other-fast", other)
        val manual = server("manual", null)
        val wireGuard = server("wg", mine).copy(outboundProtocol = OutboundProtocol.WIREGUARD)
        val known = mapOf(
            ownSlow.id to LatencyResult.Success(300),
            ownFast.id to LatencyResult.Success(40),
            ownDead.id to LatencyResult.Failed,
            otherFast.id to LatencyResult.Success(10)
        )
        val order = WorkingServers.candidates(
            listOf(manual, ownSlow, ownUntested, ownDead, otherFast, wireGuard, ownFast), mine, known
        ).map { it.name }
        assertEquals(listOf("own-fast", "own-slow", "own-new", "own-dead", "other-fast", "manual"), order)
    }
}
