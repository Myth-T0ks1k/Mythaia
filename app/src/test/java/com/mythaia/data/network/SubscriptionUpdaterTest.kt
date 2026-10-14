package com.mythaia.data.network

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID
import kotlin.random.Random

class SubscriptionUpdaterTest {

    private val subscriptionId = UUID.fromString("00000000-0000-0000-0000-00000000005b")

    private fun server(
        name: String,
        host: String,
        port: Int = 443,
        uuid: UUID = UUID.nameUUIDFromBytes(host.toByteArray()),
        protocol: OutboundProtocol = OutboundProtocol.VLESS,
        password: String? = null,
        id: UUID = UUID.randomUUID()
    ) = ProxyConfiguration(
        id = id, name = name, serverAddress = host, serverPort = port.toUShort(), uuid = uuid,
        encryption = "none", outboundProtocol = protocol, password = password, subscriptionId = subscriptionId
    )

    /**
     * The merge as it was before it was made linear: a List of unclaimed
     * configs searched and shrunk with data-class equals. Kept as the
     * reference the rewrite must agree with, duplicates and all.
     */
    private fun listMerge(old: List<ProxyConfiguration>, fetched: List<ProxyConfiguration>): List<UUID> {
        val unclaimed = old.toMutableList()
        val byEndpoint = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (o in old) byEndpoint.getOrPut(SubscriptionUpdater.endpointKey(o)) { mutableListOf() }.add(o)
        val assigned = arrayOfNulls<ProxyConfiguration>(fetched.size)
        fetched.forEachIndexed { index, fresh ->
            val group = byEndpoint[SubscriptionUpdater.endpointKey(fresh)] ?: return@forEachIndexed
            val match = group.firstOrNull { it in unclaimed } ?: return@forEachIndexed
            unclaimed.remove(match)
            assigned[index] = match
        }
        val byName = mutableMapOf<String, MutableList<ProxyConfiguration>>()
        for (o in unclaimed) byName.getOrPut(o.name) { mutableListOf() }.add(o)
        fetched.forEachIndexed { index, fresh ->
            if (assigned[index] != null) return@forEachIndexed
            val group = byName[fresh.name] ?: return@forEachIndexed
            if (group.isEmpty()) return@forEachIndexed
            val match = group.removeAt(0)
            unclaimed.remove(match)
            assigned[index] = match
        }
        return fetched.mapIndexed { index, fresh -> assigned[index]?.id ?: fresh.id }
    }

    @Test
    fun `ids follow the endpoint first, then the name, positionally among duplicates`() {
        val a = server("A", "a.example")
        val b = server("B", "b.example")
        val dup1 = server("dup", "d.example")
        val dup2 = server("dup", "d.example")
        val c = server("C", "c.example")
        val renamed = server("Renamed", "e.example")
        val x = server("X", "x.example")
        val old = listOf(a, b, dup1, dup2, c, renamed, x)

        val fetched = listOf(
            server("A", "a2.example"),          // moved: found by name
            server("B (new name)", "b.example"), // renamed: found by endpoint
            server("dup", "d.example"),
            server("dup", "d.example"),
            server("dup", "d.example"),          // a third copy: nothing left for it
            server("X", "y.example"),            // X's name, but X's endpoint is claimed below
            server("C", "c.example"),
            server("Brand new", "n.example"),
            server("Z", "x.example"),            // X's endpoint wins over X's name
            server("Renamed", "e2.example")
        )
        val merged = SubscriptionUpdater.preserveIds(old, fetched, subscriptionId)

        assertEquals(
            listOf(a.id, b.id, dup1.id, dup2.id, fetched[4].id, fetched[5].id, c.id, fetched[7].id, x.id, renamed.id),
            merged.map { it.id }
        )
        assertEquals(listMerge(old, fetched), merged.map { it.id })
        // Everything else comes from the fetch.
        assertEquals(fetched.map { it.name }, merged.map { it.name })
        assertTrue(merged.all { it.subscriptionId == subscriptionId })
    }

    @Test
    fun `identical records are claimed one at a time, as the list did`() {
        val same = server("same", "s.example")
        val other = server("same", "o.example")
        val old = listOf(same, other, same)
        val fetched = listOf(
            server("same", "s.example"), server("same", "s.example"), server("same", "s.example"),
            server("same", "z.example"), server("same", "z.example")
        )
        assertEquals(listMerge(old, fetched), SubscriptionUpdater.preserveIds(old, fetched, subscriptionId).map { it.id })
    }

    @Test
    fun `the merge agrees with the list version on random subscriptions`() {
        val random = Random(42)
        val names = listOf("Germany", "Finland", "Netherlands", "dup")
        val hosts = listOf("a.example", "b.example", "c.example")
        val uuids = List(2) { UUID.nameUUIDFromBytes(byteArrayOf(it.toByte())) }
        fun pick() = server(
            name = names.random(random), host = hosts.random(random), port = 443 + random.nextInt(2),
            uuid = uuids.random(random),
            protocol = if (random.nextInt(4) == 0) OutboundProtocol.HYSTERIA2 else OutboundProtocol.VLESS,
            password = if (random.nextBoolean()) "p" else null
        )
        repeat(3_000) {
            val old = ArrayList<ProxyConfiguration>()
            repeat(random.nextInt(0, 25)) {
                // Now and then the very same record twice, or a copy under another id.
                old += when {
                    old.isNotEmpty() && random.nextInt(8) == 0 -> old.random(random)
                    old.isNotEmpty() && random.nextInt(8) == 0 -> old.random(random).copy(id = UUID.randomUUID())
                    else -> pick()
                }
            }
            val fetched = List(random.nextInt(0, 25)) { pick() }
            assertEquals(listMerge(old, fetched), SubscriptionUpdater.preserveIds(old, fetched, subscriptionId).map { it.id })
        }
    }

    @Test
    fun `ten thousand servers merge quickly`() {
        // Ten thousand servers once took the list version ~2x10^8 equals
        // calls, on the main thread, and froze the app after a refresh.
        val old = List(10_000) { i -> server("node $i", "h$i.example", port = 1000 + i % 50) }
        val fetched = List(10_000) { i ->
            val j = (i * 7919) % 10_000
            when (i % 4) {
                0 -> server("node $j renamed", "h$j.example", port = 1000 + j % 50) // same endpoint
                1 -> server("node $j", "moved$j.example")                           // same name
                else -> server("node $j", "h$j.example", port = 1000 + j % 50)
            }
        }
        val started = System.nanoTime()
        val merged = SubscriptionUpdater.preserveIds(old, fetched, subscriptionId)
        val ms = (System.nanoTime() - started) / 1_000_000
        assertTrue("took $ms ms", ms < 2_000)
        assertEquals(old.map { it.id }.toSet(), merged.map { it.id }.toSet())
        // Spot check: fetched[1] is old[7919] under a new address.
        assertEquals(old[7919].id, merged[1].id)
    }
}
