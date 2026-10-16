package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID

/**
 * Servers to fetch a subscription through when its panel cannot be reached
 * from this network. Shared by the phone and the desktop so both pick alike.
 */
object WorkingServers {

    /** How many servers a fetch is tried through. */
    const val ATTEMPTS = 4

    /** How many are checked, and for how long, to find them. */
    private const val PROBES = 24
    private const val PROBE_MS = 10_000L

    /**
     * The servers worth checking, in order: the subscription's own first (its
     * provider's servers reach its panel more often than anyone's), and in
     * each part the ones that answered last time, then the untested, then
     * those that failed (every one is checked afresh anyway). Layer-3 servers
     * are left out: WireGuard dials no streams.
     */
    fun candidates(
        configs: List<ProxyConfiguration>,
        subscriptionId: UUID,
        known: Map<UUID, LatencyResult>
    ): List<ProxyConfiguration> {
        val usable = configs.filter { !it.outboundProtocol.isLayer3 }
        fun rank(config: ProxyConfiguration): Long = when (val result = known[config.id]) {
            is LatencyResult.Success -> result.ms.toLong()
            is LatencyResult.Failed -> Long.MAX_VALUE
            else -> Int.MAX_VALUE.toLong()
        }
        fun ordered(part: List<ProxyConfiguration>) = part.sortedBy { rank(it) }
        val (own, others) = usable.partition { it.subscriptionId == subscriptionId }
        return (ordered(own) + ordered(others)).take(PROBES)
    }

    /**
     * Up to [ATTEMPTS] servers that answer a real request right now: [live]
     * first when the tunnel works, then the first of [candidates] to pass a
     * fresh check. [prepare] applies the app's settings to a server before
     * it is checked; [onResult] hears every check, for the ping column.
     */
    suspend fun find(
        live: ProxyConfiguration?,
        candidates: List<ProxyConfiguration>,
        prepare: (ProxyConfiguration) -> ProxyConfiguration = { it },
        onResult: (UUID, LatencyResult) -> Unit = { _, _ -> }
    ): List<ProxyConfiguration> {
        val picked = LinkedHashMap<UUID, ProxyConfiguration>()
        live?.takeIf { !it.outboundProtocol.isLayer3 }?.let { picked[it.id] = it }
        val toCheck = candidates.filter { it.id !in picked }
        val byId = toCheck.associateBy { it.id }
        val wanted = ATTEMPTS - picked.size
        if (wanted > 0 && toCheck.isNotEmpty()) {
            withTimeoutOrNull(PROBE_MS) {
                LatencyTester.testAll(toCheck.map(prepare), LatencyKind.HTTP)
                    .onEach { (id, result) -> onResult(id, result) }
                    .filter { it.second is LatencyResult.Success }
                    .take(wanted)
                    .collect { (id, _) -> byId[id]?.let { picked.putIfAbsent(id, it) } }
            }
        }
        return picked.values.toList()
    }
}
