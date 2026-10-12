package com.mythaia.vpn.protocol.grpc

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.TlsConfiguration

/**
 * Helpers shared by gRPC transport callers. The actual connection establishment
 * lives inline in the outer protocol client (e.g. `VlessClient.connectWithGrpc`)
 * so gRPC retries/cleanup follow the same patterns as the other transports.
 */
object GrpcClient {

    /**
     * The link's TLS settings with ALPN forced to `h2` (gRPC requires HTTP/2).
     * A copy, not a rebuild: the fragment, ECH and pinned certificates are
     * part of how this server must be reached and have to survive.
     */
    fun sanitizedTlsConfiguration(base: TlsConfiguration): TlsConfiguration =
        base.copy(alpn = listOf("h2"))

    /**
     * Resolves the HTTP/2 `:authority` value from the proxy configuration, consulting
     * the gRPC override, the TLS SNI, the Reality server name, and finally the server
     * address.
     */
    fun resolveAuthority(
        grpc: GrpcConfiguration,
        configuration: ProxyConfiguration
    ): String = grpc.resolvedAuthority(
        tlsServerName = configuration.tls?.serverName,
        realityServerName = configuration.reality?.serverName,
        serverAddress = configuration.serverAddress
    )

    private val keyJson = kotlinx.serialization.json.Json { encodeDefaults = true }

    /**
     * What makes two tunnels able to share a [GrpcMux] connection: the same
     * server, reached the same way. Serialized rather than toString'd, so array
     * fields compare by content and an edited server never reuses the old
     * connection.
     */
    fun muxKey(configuration: ProxyConfiguration, grpc: GrpcConfiguration, authority: String): String =
        listOf(
            configuration.serverAddress,
            configuration.serverPort.toString(),
            configuration.tls?.let { keyJson.encodeToString(TlsConfiguration.serializer(), it) },
            configuration.reality?.let {
                keyJson.encodeToString(com.mythaia.data.model.RealityConfiguration.serializer(), it)
            },
            authority,
            grpc.userAgent
        ).joinToString("|")
}
