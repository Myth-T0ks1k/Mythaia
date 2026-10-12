package com.mythaia.vpn

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.mux.MuxManager
import com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession
import java.util.concurrent.ScheduledExecutorService

/**
 * What a sniffed TLS SNI decides for a connection that arrived on a real IP.
 *
 * `null` from [LwipHost.routeDomain] means "no rule speaks about this name":
 * the connection keeps the route the destination IP gave it.
 */
sealed class LwipDomainRoute {
    data object Direct : LwipDomainRoute()
    data object Reject : LwipDomainRoute()

    /**
     * Send it through [configuration]; null when the rule named a proxy that
     * no longer exists, in which case the connection keeps its current one.
     */
    data class Proxy(val configuration: ProxyConfiguration?) : LwipDomainRoute()
}

/**
 * The stack a [LwipTcpConnection] or [LwipUdpFlow] lives in.
 *
 * The two flow classes drive lwIP PCBs and proxy connections; everything
 * they need from the surrounding stack — the executor, the routing verdicts,
 * the shared sessions and the bookkeeping of who is still open — comes
 * through this interface, so the same flow code serves the Android
 * `LwipStack` and the desktop TUN driver.
 *
 * Every member is called on [lwipExecutor] unless noted.
 */
interface LwipHost {
    /** The single thread every lwIP call runs on. */
    val lwipExecutor: ScheduledExecutorService

    /** True while the stack is deliberately aborting every PCB (shutdown, restart, wake). */
    val isTearingDown: Boolean

    /** The default outbound; the one flows compare against to decide whether the shared mux applies. */
    val configuration: ProxyConfiguration?

    /** The Vision mux for the default configuration, when one is active. */
    val muxManager: MuxManager?

    /** Whether [host] is a proxy server's own address, which must never go through the tunnel. */
    fun shouldBypass(host: String): Boolean

    /** The routing verdict for a domain learned from a TLS ClientHello; null when no rule matches. */
    fun routeDomain(domain: String): LwipDomainRoute?

    /**
     * The Shadowsocks UDP session for [config] and one local socket ([source],
     * "host:port"), or null when its credentials are unusable.
     *
     * One session per local socket, as Xray and sing-box keep: every flow of
     * that socket shares one upstream socket (and SS 2022 session id), which
     * keeps its NAT mapping full-cone. Replies are matched to flows by their
     * remote address, so two local sockets talking to the same server (two
     * QUIC connections to one host, two call streams to one relay) must not
     * share a session: the replies of both went to whichever came first.
     */
    fun shadowsocksUDPSession(config: ProxyConfiguration, source: String): ShadowsocksUdpSession?

    /** A flow let go of [session]; the host ends the session once no flow uses it. */
    fun releaseShadowsocksUDPSession(session: ShadowsocksUdpSession)

    /** A TCP connection closed or aborted itself. */
    fun removeConnection(connId: Long)

    /** A UDP flow closed itself. */
    fun removeUdpFlow(flowKey: String)

    /** Push pending output packets to the interface now, on the calling (lwIP) thread. */
    fun flushOutputInline()
}
