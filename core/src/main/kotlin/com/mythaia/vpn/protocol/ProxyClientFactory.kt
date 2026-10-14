package com.mythaia.vpn.protocol

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.naive.NaiveClient
import com.mythaia.vpn.protocol.shadowsocks.ShadowsocksClient
import com.mythaia.vpn.protocol.socks5.SocksClient
import com.mythaia.vpn.protocol.trojan.TrojanClient
import com.mythaia.vpn.protocol.vless.VlessClient
import com.mythaia.vpn.protocol.vmess.VmessClient

/** Factory for creating proxy connections based on protocol configuration. */
object ProxyClientFactory {

    suspend fun connect(
        configuration: ProxyConfiguration,
        host: String,
        port: Int,
        initialData: ByteArray? = null,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        val config = configuration.withTransportHostSni()
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SHADOWSOCKS -> ShadowsocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 ->
                NaiveClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.VMESS -> VmessClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.ANYTLS ->
                com.mythaia.vpn.protocol.anytls.AnyTlsClient(config, tunnel)
                    .connect(host, port, initialData)
            // One shared client per server: both multiplex every flow onto one
            // QUIC connection (see QuicClientPool).
            OutboundProtocol.HYSTERIA2 ->
                com.mythaia.vpn.protocol.quic.QuicClientPool.hysteria(config)
                    .connect(host, port, initialData)
            OutboundProtocol.TUIC ->
                com.mythaia.vpn.protocol.quic.QuicClientPool.tuic(config)
                    .connect(host, port, initialData)
            // Sudoku and Nowhere follow the Hysteria/TUIC convention: their
            // handshake does not carry the caller's first bytes, so the flow
            // layer forwards initialData after connect. connect still accepts it
            // for chain use, where the buffered bytes are handed straight on.
            OutboundProtocol.SUDOKU ->
                com.mythaia.vpn.protocol.sudoku.SudokuClient(config, config.toSudokuConfiguration(), tunnel)
                    .connect(host, port, initialData)
            OutboundProtocol.NOWHERE ->
                com.mythaia.vpn.protocol.nowhere.NowhereClient(config, tunnel)
                    .connect(host, port, initialData)
            // WireGuard is a layer-3 interface, not a stream proxy: it carries
            // whole IP packets and runs instead of the lwIP stack, so nothing
            // should ever reach the per-flow dial path with it.
            OutboundProtocol.WIREGUARD -> throw ProxyError.ProtocolError(
                "WireGuard carries IP packets and cannot be dialled per flow"
            )
        }
    }

    /**
     * Shadowsocks UDP is intentionally absent — it never reaches the chain
     * path because [com.mythaia.vpn.LwipUdpFlow] routes SS UDP
     * through the shared per-config session (see
     * [com.mythaia.vpn.protocol.shadowsocks.ShadowsocksUdpSession]).
     * NaiveProxy / HTTP doesn't carry UDP at all.
     */
    suspend fun connectUDP(
        configuration: ProxyConfiguration,
        host: String,
        port: Int,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        val config = configuration.withTransportHostSni()
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.VMESS -> VmessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.ANYTLS ->
                com.mythaia.vpn.protocol.anytls.AnyTlsClient(config, tunnel).connectUDP(host, port)
            // Sudoku frames UDP over its TCP carrier; Nowhere's own UDP path is
            // not wired to the flow layer yet and refuses with a message.
            OutboundProtocol.SUDOKU ->
                com.mythaia.vpn.protocol.sudoku.SudokuClient(config, config.toSudokuConfiguration(), tunnel)
                    .connectUDP(host, port)
            OutboundProtocol.NOWHERE ->
                com.mythaia.vpn.protocol.nowhere.NowhereClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.WIREGUARD -> throw ProxyError.ProtocolError(
                "WireGuard carries IP packets and cannot be dialled per flow"
            )
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> throw ProxyError.Dropped()
            OutboundProtocol.SHADOWSOCKS -> throw ProxyError.ProtocolError(
                "UDP not supported through TCP factory for Shadowsocks"
            )
            OutboundProtocol.HYSTERIA2 ->
                com.mythaia.vpn.protocol.quic.QuicClientPool.hysteria(config).connectUDP(host, port)
            OutboundProtocol.TUIC ->
                com.mythaia.vpn.protocol.quic.QuicClientPool.tuic(config).connectUDP(host, port)
        }
    }

    // MARK: - Pooled sessions

    /** One-off dials in flight per pooled session, between [retain] and [release]. Guarded by itself. */
    private val probes = HashMap<Any, Int>()

    /**
     * Holds the pooled sessions that dialling [configuration] reaches, its
     * chain hops' included, for a one-off dial such as a latency test, until
     * the matching [release].
     */
    fun retain(configuration: ProxyConfiguration) {
        synchronized(probes) {
            for (hop in configuration.chain.orEmpty() + configuration) {
                val key = poolKey(hop) ?: continue
                probes[key] = (probes[key] ?: 0) + 1
            }
        }
    }

    /**
     * Ends a [retain] and closes the per-server state the dial left pooled:
     * the Hysteria2/TUIC client, AnyTLS and Naive HTTP/2 sessions, the
     * Nowhere session.
     *
     * Each outlives its dial on purpose, which is right for the tunnel's
     * server and wrong for a latency test across a subscription of thousands:
     * every Hysteria2/TUIC server tested kept a socket and two threads alive
     * for good, until the app died of "pthread_create failed", OOM or EMFILE.
     *
     * A session is kept while another probe still holds it (duplicates of a
     * server share one QUIC client, and closing it under the other test would
     * fail that test), and while a tunnel carries traffic through it
     * ([LiveTunnel]): testing the server in use must never cut its flows.
     * Sessions are matched by pool key rather than profile id, because a
     * duplicate under another id shares the tunnel's session. Eviction runs
     * under the lock, so a probe retaining the same server meanwhile waits
     * and then dials afresh instead of having its session closed under it.
     *
     * Without a [retain], this closes whatever is neither probed nor live.
     */
    fun release(configuration: ProxyConfiguration) {
        synchronized(probes) {
            val live by lazy { LiveTunnel.servers().mapNotNullTo(HashSet()) { poolKey(it) } }
            for (hop in configuration.chain.orEmpty() + configuration) {
                val key = poolKey(hop) ?: continue
                val left = (probes[key] ?: 1) - 1
                if (left > 0) {
                    probes[key] = left
                } else {
                    probes.remove(key)
                    if (key !in live) evict(hop)
                }
            }
        }
    }

    /**
     * What [configuration]'s session is pooled under, or null when its
     * protocol dials afresh every time. Computed on the configuration
     * [connect] dials, so it is the key the pool filed the session under.
     */
    private fun poolKey(configuration: ProxyConfiguration): Any? {
        val config = configuration.withTransportHostSni()
        return when (config.outboundProtocol) {
            OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC ->
                "quic" to com.mythaia.vpn.protocol.quic.QuicClientPool.key(config)
            OutboundProtocol.ANYTLS -> "anytls" to config.id
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 ->
                NaiveClient.poolKey(config)?.let { "naive" to it }
            OutboundProtocol.NOWHERE ->
                "nowhere" to com.mythaia.vpn.protocol.nowhere.NowhereClient.poolKey(config)
            OutboundProtocol.VLESS, OutboundProtocol.TROJAN, OutboundProtocol.SHADOWSOCKS,
            OutboundProtocol.SOCKS5, OutboundProtocol.VMESS, OutboundProtocol.SUDOKU,
            OutboundProtocol.WIREGUARD -> null
        }
    }

    private fun evict(configuration: ProxyConfiguration) {
        val config = configuration.withTransportHostSni()
        when (config.outboundProtocol) {
            OutboundProtocol.HYSTERIA2, OutboundProtocol.TUIC ->
                com.mythaia.vpn.protocol.quic.QuicClientPool.evict(config)
            OutboundProtocol.ANYTLS -> com.mythaia.vpn.protocol.anytls.AnyTlsClient.release(config.id)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> NaiveClient.release(config)
            OutboundProtocol.NOWHERE -> com.mythaia.vpn.protocol.nowhere.NowhereClient.release(config)
            else -> Unit
        }
    }
}
