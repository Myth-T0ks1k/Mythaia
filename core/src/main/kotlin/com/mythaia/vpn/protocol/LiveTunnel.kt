package com.mythaia.vpn.protocol

import com.mythaia.data.model.ProxyConfiguration
import java.util.concurrent.ConcurrentHashMap

/**
 * The servers a running tunnel is carrying traffic through.
 *
 * Latency tests dial through the same per-server pools the tunnel does, and
 * [ProxyClientFactory.release] closes what a test left in them. The one
 * session that must survive a test is the one the tunnel's flows are riding,
 * and core cannot see the platform's tunnel, so each tunnel registers a way to
 * read its current server here: the Android `LwipStack`, the desktop
 * [com.mythaia.vpn.tun.TunStack] and the desktop local proxy.
 */
object LiveTunnel {

    private val tunnels = ConcurrentHashMap<Any, () -> ProxyConfiguration?>()

    /**
     * [owner] carries traffic through whatever [current] returns. It is read
     * at each release, so a server switch needs no call here. Keyed by owner
     * so that a stack which finishes stopping after its successor started
     * cannot unregister the successor.
     */
    fun register(owner: Any, current: () -> ProxyConfiguration?) {
        tunnels[owner] = current
    }

    fun unregister(owner: Any) {
        tunnels.remove(owner)
    }

    /** Every server a registered tunnel is dialling now, chain hops included. */
    internal fun servers(): List<ProxyConfiguration> =
        tunnels.values.mapNotNull { it() }.flatMap { it.chain.orEmpty() + it }
}
