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
        config: ProxyConfiguration,
        host: String,
        port: Int,
        initialData: ByteArray? = null,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SHADOWSOCKS -> ShadowsocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 ->
                NaiveClient(config, tunnel).connect(host, port, initialData)
            OutboundProtocol.VMESS -> VmessClient(config, tunnel).connect(host, port, initialData)
            // Parsed, stored and exported, but not yet dialable — both wait on
            // the QUIC stack and the AnyTLS implementation. Failing here with
            // the protocol named beats a silent timeout.
            OutboundProtocol.HYSTERIA2, OutboundProtocol.ANYTLS -> throw ProxyError.ProtocolError(
                "${config.outboundProtocol.displayName} is not supported yet"
            )
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
        config: ProxyConfiguration,
        host: String,
        port: Int,
        tunnel: ProxyConnection? = null
    ): ProxyConnection {
        return when (config.outboundProtocol) {
            OutboundProtocol.VLESS -> VlessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.TROJAN -> TrojanClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.SOCKS5 -> SocksClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.VMESS -> VmessClient(config, tunnel).connectUDP(host, port)
            OutboundProtocol.WIREGUARD -> throw ProxyError.ProtocolError(
                "WireGuard carries IP packets and cannot be dialled per flow"
            )
            OutboundProtocol.NAIVE_HTTP11, OutboundProtocol.NAIVE_HTTP2 -> throw ProxyError.Dropped()
            OutboundProtocol.SHADOWSOCKS -> throw ProxyError.ProtocolError(
                "UDP not supported through TCP factory for Shadowsocks"
            )
            OutboundProtocol.HYSTERIA2, OutboundProtocol.ANYTLS -> throw ProxyError.ProtocolError(
                "${config.outboundProtocol.displayName} is not supported yet"
            )
        }
    }
}
