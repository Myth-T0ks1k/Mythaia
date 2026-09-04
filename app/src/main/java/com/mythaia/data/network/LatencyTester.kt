package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.DnsCache
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

sealed class LatencyResult {
    data object Testing : LatencyResult()
    data class Success(val ms: Int) : LatencyResult()
    data object Insecure : LatencyResult()
    data object Failed : LatencyResult()
}

/**
 * Tests full proxy round-trip latency by establishing a proxy connection
 * and sending a plain HTTP request through the proxy chain.
 *
 * Uses captive.apple.com:80 (plain HTTP) — no destination TLS handshake
 * needed, which avoids certificate issues and reduces test complexity.
 */
object LatencyTester {

    private val logger = MythaiaLogger("LatencyTester")
    private const val TIMEOUT_MS = 10_000L

    /** Latency test endpoint — plain HTTP. */
    private const val LATENCY_HOST = "captive.apple.com"
    private const val LATENCY_PORT = 80

    /** Maximum number of latency tests running at the same time. */
    private const val MAX_CONCURRENT_TESTS = 6

    /** How long to wait for a peer to answer a handshake initiation. */
    private const val HANDSHAKE_PROBE_MS = 5_000

    suspend fun test(config: ProxyConfiguration): LatencyResult = withContext(Dispatchers.IO) {
        // A layer-3 interface has no per-flow dial to time. Sending it through
        // the proxy factory would report Failed for a peer that is perfectly
        // reachable, so it gets the probe that actually applies to it.
        if (config.outboundProtocol.isLayer3) {
            return@withContext withTimeoutOrNull(TIMEOUT_MS) {
                try {
                    testWireGuard(config)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    logger.error("Latency test failed for ${config.name}: ${e.message}")
                    LatencyResult.Failed
                }
            } ?: LatencyResult.Failed
        }

        withTimeoutOrNull(TIMEOUT_MS) {
            try {
                performTest(resolveConfig(config))
            } catch (e: CancellationException) {
                throw e
            } catch (e: com.mythaia.vpn.protocol.tls.TlsError.CertificateValidationFailed) {
                logger.error("Latency test insecure for ${config.name}: ${e.message}")
                LatencyResult.Insecure
            } catch (e: Exception) {
                logger.error("Latency test failed for ${config.name}: ${e.message}")
                LatencyResult.Failed
            }
        } ?: LatencyResult.Failed
    }

    /**
     * Times a real WireGuard handshake against the peer.
     *
     * Nothing else would mean anything: the peer answers only a well-formed
     * initiation under the right key, so a reply is proof the endpoint is
     * reachable *and* that the profile is valid — which is more than the
     * stream-proxy probe establishes.
     */
    private fun testWireGuard(config: ProxyConfiguration): LatencyResult {
        val text = config.wireGuardConfig ?: return LatencyResult.Failed
        val parsed = com.mythaia.vpn.protocol.wireguard.WireGuardConfig.parse(text)
        val amnezia = parsed.amnezia

        val host = DnsCache.resolveHost(parsed.peer.endpointHost)
            ?: return LatencyResult.Failed
        val target = java.net.InetSocketAddress(
            java.net.InetAddress.getByName(host), parsed.peer.endpointPort
        )

        val handshake = com.mythaia.vpn.protocol.wireguard.WireGuardHandshake(
            localPrivateKey = parsed.privateKey,
            localPublicKey = parsed.publicKey,
            peerPublicKey = parsed.peer.publicKey,
            presharedKey = parsed.peer.presharedKey
                ?: ByteArray(com.mythaia.vpn.protocol.wireguard.WireGuardCrypto.KEY_SIZE),
            initiationType = amnezia.initiationType,
            responseType = amnezia.responseType,
            initiationJunkSize = amnezia.initPacketJunkSize,
            responseJunkSize = amnezia.responsePacketJunkSize
        )

        val socket = java.net.DatagramSocket()
        return try {
            com.mythaia.vpn.SocketProtector.protect(socket)
            socket.soTimeout = HANDSHAKE_PROBE_MS

            val initiation = handshake.buildInitiation()
            val started = System.nanoTime()
            socket.send(java.net.DatagramPacket(initiation, initiation.size, target))

            val buffer = ByteArray(2048)
            val reply = java.net.DatagramPacket(buffer, buffer.size)
            socket.receive(reply)
            val elapsed = ((System.nanoTime() - started) / 1_000_000L).toInt()

            // Only the peer that holds the key can produce a response this
            // parses, so anything else is a Failed rather than a fast answer.
            val message = buffer.copyOf(reply.length)
            handshake.consumeResponse(message)
            LatencyResult.Success(elapsed.coerceAtLeast(1))
        } catch (e: Exception) {
            logger.error("WireGuard probe failed for ${config.name}: ${e.message}")
            LatencyResult.Failed
        } finally {
            runCatching { socket.close() }
        }
    }

    fun testAll(configurations: List<ProxyConfiguration>): Flow<Pair<UUID, LatencyResult>> = channelFlow {
        // Pre-warm DNS cache for all hosts (including chain proxies)
        configurations.forEach { config ->
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }
        }

        // Cap concurrent tests to avoid overwhelming network/proxy.
        val semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        for (config in configurations) {
            launch(Dispatchers.IO) {
                semaphore.withPermit {
                    send(config.id to test(config))
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Resolve DNS before connecting to avoid DNS-over-tunnel loop when VPN is active.
     */
    private fun resolveConfig(config: ProxyConfiguration): ProxyConfiguration {
        val resolvedConfig = resolveAddress(config)
        val resolvedChain = config.chain?.map { resolveAddress(it) }
        return if (resolvedChain != null) resolvedConfig.copy(chain = resolvedChain) else resolvedConfig
    }

    private fun resolveAddress(config: ProxyConfiguration): ProxyConfiguration {
        if (config.resolvedIP != null) return config

        val address = config.serverAddress
        if (DnsCache.isIpAddress(address)) return config

        val resolved = DnsCache.resolveHost(address) ?: return config
        return config.copy(resolvedIP = resolved)
    }

    /**
     * Establishes a proxy connection and measures HTTP round-trip latency.
     *
     * Phase 1 (untimed): Establish proxy connection (TCP + TLS/Reality + VLESS/SS handshake).
     * Phase 2 (untimed): Warmup request — drains proxy-side buffers.
     * Phase 3 (untimed): Send the timed HTTP request.
     * Phase 4 (timed):   Wait for the response — measures actual network RTT.
     */
    private suspend fun performTest(config: ProxyConfiguration): LatencyResult = coroutineScope {
        val connections = mutableListOf<ProxyConnection>()

        // Cancellation watcher: closes connections when this scope is cancelled
        // (e.g., by withTimeoutOrNull). NioSocket.receive() uses suspendCoroutine
        // which is not cancellation-aware, so we must actively close the underlying
        // sockets to unblock pending I/O.
        val watcher = launch {
            try { awaitCancellation() } finally {
                connections.forEach { it.cancel() }
            }
        }

        try {
            DnsCache.prewarm(config.serverAddress)
            config.chain?.forEach { DnsCache.prewarm(it.serverAddress) }

            // Phase 1 (untimed): Establish proxy connection through chain.
            var tunnelConnection: ProxyConnection? = null

            val chain = config.chain
            if (!chain.isNullOrEmpty()) {
                for (i in chain.indices) {
                    val hopConfig = chain[i]
                    val nextConfig = if (i + 1 < chain.size) chain[i + 1] else config
                    tunnelConnection = ProxyClientFactory.connect(
                        hopConfig,
                        nextConfig.connectAddress,
                        nextConfig.serverPort.toInt(),
                        tunnel = tunnelConnection
                    )
                    connections.add(tunnelConnection)
                }
            }

            val proxyConnection = ProxyClientFactory.connect(
                config, LATENCY_HOST, LATENCY_PORT, tunnel = tunnelConnection
            )
            connections.add(proxyConnection)

            // Phase 2 (untimed warmup): Drain proxy-side buffers.
            val warmupRequest = "HEAD / HTTP/1.1\r\nHost: $LATENCY_HOST\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(warmupRequest)
            val warmupData = proxyConnection.receive()

            val warmupStatus = warmupData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (warmupStatus == null || !warmupStatus.contains("200")) {
                throw LatencyTestError("Unexpected warmup status: ${warmupStatus ?: "no response"}")
            }

            // Phase 3 (untimed): Send the timed HTTP request.
            val httpRequest = "HEAD / HTTP/1.1\r\nHost: $LATENCY_HOST\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(httpRequest)

            // Phase 4 (timed): Wait for the response.
            val startNs = System.nanoTime()
            val responseData = proxyConnection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            val statusLine = responseData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (statusLine == null || !statusLine.contains("200")) {
                throw LatencyTestError("Unexpected status: ${statusLine ?: "no response"}")
            }

            LatencyResult.Success(elapsedMs.toInt())
        } catch (e: CancellationException) {
            throw e
        } catch (e: com.mythaia.vpn.protocol.tls.TlsError.CertificateValidationFailed) {
            // Let certificate validation failures propagate so test() can map
            // them to LatencyResult.Insecure instead of a generic Failed.
            throw e
        } catch (e: Exception) {
            logger.error("Latency test failed for ${config.name}: ${e.message}")
            LatencyResult.Failed
        } finally {
            watcher.cancel()
            connections.forEach { it.cancel() }
        }
    }

    private class LatencyTestError(message: String) : Exception(message)
}
