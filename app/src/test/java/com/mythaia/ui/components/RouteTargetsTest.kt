package com.mythaia.ui.components

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.Subscription
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class RouteTargetsTest {

    private val subA = Subscription(name = "Alpha", url = "https://a.example/sub")
    private val subB = Subscription(name = "Beta", url = "https://b.example/sub")

    private fun server(
        name: String,
        subscription: Subscription? = null,
        address: String = "203.0.113.1",
        protocol: OutboundProtocol = OutboundProtocol.VLESS,
        id: UUID = UUID.randomUUID()
    ) = ProxyConfiguration(
        id = id,
        name = name,
        serverAddress = address,
        serverPort = 443u,
        uuid = UUID.randomUUID(),
        encryption = "none",
        subscriptionId = subscription?.id,
        outboundProtocol = protocol
    )

    @Test
    fun `servers are grouped like the proxy list and found by id`() {
        val manual = server("Home")
        val a1 = server("Frankfurt", subA)
        val b1 = server("Tokyo", subB)
        val a2 = server("Paris", subA)
        val targets = RouteTargets.of(listOf(a1, manual, b1, a2), listOf(subA, subB))

        assertEquals(listOf(manual), targets.standalone)
        assertEquals(listOf(subA to listOf(a1, a2), subB to listOf(b1)), targets.groups)
        assertEquals(4, targets.size)
        assertSame(a2, targets[a2.id.toString()])
        assertNull(targets["DIRECT"])
    }

    @Test
    fun `a server of a deleted subscription is not offered`() {
        val orphan = server("Lost", Subscription(name = "Gone", url = "https://gone.example"))
        val targets = RouteTargets.of(listOf(orphan), listOf(subA))

        assertEquals(0, targets.size)
        assertTrue(targets.groups.isEmpty())
        assertNull(targets[orphan.id.toString()])
    }

    @Test
    fun `an id met twice is listed once, as its first copy`() {
        val id = UUID.randomUUID()
        val first = server("First", subA, id = id)
        val second = server("Second", subB, id = id)
        val targets = RouteTargets.of(listOf(first, second), listOf(subA, subB))

        assertEquals(1, targets.size)
        assertEquals(listOf(subA to listOf(first)), targets.groups)
        assertSame(first, targets[id.toString()])
    }

    @Test
    fun `search matches name, address and protocol and drops empty sections`() {
        val manual = server("Home", address = "home.example.net")
        val a1 = server("Frankfurt", subA, protocol = OutboundProtocol.HYSTERIA2)
        val b1 = server("Tokyo", subB)
        val targets = RouteTargets.of(listOf(manual, a1, b1), listOf(subA, subB))

        assertEquals(3, targets.sections("  ").size)

        val byName = targets.sections("frank")
        assertEquals(1, byName.size)
        assertSame(subA, byName[0].subscription)
        assertEquals(listOf(a1), byName[0].servers)

        val byAddress = targets.sections("EXAMPLE.NET")
        assertNull(byAddress.single().subscription)
        assertEquals(listOf(manual), byAddress.single().servers)

        assertEquals(listOf(a1), targets.sections("hysteria").single().servers)
        assertTrue(targets.sections("nothing like it").isEmpty())
    }
}
