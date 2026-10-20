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
 * What a measurement times.
 *
 * TCP is the cheapest and says only that the port answers; HANDSHAKE proves
 * the credentials and the protocol work and is what auto-select ranks by;
 * HTTP goes all the way through the proxy to the internet.
 */
enum class LatencyKind {
    /**
     * The quick reachability ping: the TCP connect for a server that listens
     * on TCP, and a QUIC probe ([QuicPing]) for one that listens on UDP only
     * (Hysteria2, TUIC, Nowhere over QUIC). A WireGuard peer gets its real
     * handshake, as for every kind. The name stays for stored settings.
     */
    TCP,

    /** Time to a finished proxy handshake (TCP + TLS/Reality + protocol). */
    HANDSHAKE,

    /** Time for an HTTP round trip through the proxy — the "real" ping. */
    HTTP
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

    /** Where the HTTP check goes: host, port, and the path asked for. */
    private class CheckTarget(val host: String, val port: Int, val path: String) {
        /** The Host header: the port only when it is not the default. */
        val hostHeader: String get() = if (port == 80) host else "$host:$port"
    }

    @Volatile
    private var target = CheckTarget(LATENCY_HOST, LATENCY_PORT, "/")

    /**
     * The page the check fetches through a server — a provider's
     * `check-url-via-proxy` — or null for the default. The request is plain
     * HTTP whatever the scheme: an `https://` URL is asked of the same host
     * on port 80, since the check times the round trip through the server and
     * a TLS handshake with the destination would only add noise to it.
     */
    var checkUrl: String? = null
        set(value) {
            field = value
            target = value?.let { parseTarget(it) } ?: CheckTarget(LATENCY_HOST, LATENCY_PORT, "/")
        }

    private fun parseTarget(url: String): CheckTarget? {
        val uri = runCatching { java.net.URI(url.trim()) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase() ?: return null
        val host = uri.host?.takeIf { it.isNotEmpty() && it.all { c -> c.isLetterOrDigit() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']' } } ?: return null
        val port = when {
            scheme == "http" && uri.port > 0 -> uri.port
            scheme == "http" || scheme == "https" -> 80
            else -> return null
        }
        val path = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
        if (path.any { it <= ' ' || it.code > 0x7E }) return null
        return CheckTarget(host.removePrefix("[").removeSuffix("]"), port, path)
    }

    /** Whether an HTTP status line is an answer: 2xx, or a redirect, which a captive check may give. */
    private fun answered(statusLine: String?): Boolean {
        val code = statusLine?.split(' ')?.getOrNull(1)?.toIntOrNull() ?: return false
        return code in 200..399
    }

    /** Maximum number of latency tests running at the same time. */
    private const val MAX_CONCURRENT_TESTS = 6

    /** How long to wait for a peer to answer a handshake initiation. */
    private const val HANDSHAKE_PROBE_MS = 5_000

    suspend fun test(
        config: ProxyConfiguration,
        kind: LatencyKind = LatencyKind.HTTP
    ): LatencyResult = withContext(Dispatchers.IO) {
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

        // The dial goes through the same per-server pools the tunnel uses, and
        // what it leaves there is closed once the test is over, however it
        // ended: a test across thousands of servers otherwise kept a QUIC
        // client or TLS session per server alive and crashed the app.
        ProxyClientFactory.retain(config)
        try {
            withTimeoutOrNull(TIMEOUT_MS) {
                try {
                    when (kind) {
                        LatencyKind.TCP -> performPingTest(resolveConfig(config))
                        LatencyKind.HANDSHAKE -> performHandshakeTest(resolveConfig(config))
                        LatencyKind.HTTP -> performTest(resolveConfig(config))
                    }
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
        } finally {
            ProxyClientFactory.release(config)
        }
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
            responseJunkSize = amnezia.responsePacketJunkSize,
            // WARP ignores an initiation without its client id, so the probe
            // would time out on a profile that connects fine.
            reserved = parsed.headerReserved
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

    fun testAll(
        configurations: List<ProxyConfiguration>,
        kind: LatencyKind = LatencyKind.HTTP
    ): Flow<Pair<UUID, LatencyResult>> = channelFlow {
        // Cap concurrent tests to avoid overwhelming network/proxy. Each test
        // resolves its own names under its own timeout, so a slow resolver
        // delays one result rather than all of them.
        val semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        for (config in configurations) {
            launch(Dispatchers.IO) {
                semaphore.withPermit {
                    send(config.id to test(config, kind))
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    /** Times the TCP connect alone, to the first hop of a chain or the server itself. */
    private suspend fun performPingTest(config: ProxyConfiguration): LatencyResult {
        val first = config.chain?.firstOrNull() ?: config
        if (listensOnUdp(first)) return pingUdp(first)
        val socket = com.mythaia.vpn.util.NioSocket()
        val started = System.nanoTime()
        try {
            socket.connect(first.connectAddress, first.serverPort.toInt())
        } finally {
            runCatching { socket.forceCancel() }
        }
        val elapsed = ((System.nanoTime() - started) / 1_000_000L).toInt()
        return LatencyResult.Success(elapsed.coerceAtLeast(1))
    }

    /** Whether [config]'s server takes its first packets over UDP (QUIC), where a TCP connect proves nothing. */
    internal fun listensOnUdp(config: ProxyConfiguration): Boolean = when (config.outboundProtocol) {
        com.mythaia.data.model.OutboundProtocol.HYSTERIA2,
        com.mythaia.data.model.OutboundProtocol.TUIC -> true
        com.mythaia.data.model.OutboundProtocol.NOWHERE ->
            (config.nowhereUplink ?: com.mythaia.vpn.protocol.nowhere.NowhereNetwork.UDP.wireName) ==
                com.mythaia.vpn.protocol.nowhere.NowhereNetwork.UDP.wireName
        else -> false
    }

    /** The UDP side of the ping: a QUIC probe, disguised the way a Hysteria2 server expects. */
    private fun pingUdp(config: ProxyConfiguration): LatencyResult {
        val host = DnsCache.resolveHost(config.connectAddress) ?: return LatencyResult.Failed
        val target = java.net.InetSocketAddress(java.net.InetAddress.getByName(host), config.serverPort.toInt())
        val obfuscator = if (config.outboundProtocol == com.mythaia.data.model.OutboundProtocol.HYSTERIA2) {
            com.mythaia.vpn.protocol.hysteria.HysteriaObfuscation
                .make(config.obfuscation, config.obfuscationPassword)
                ?.let { com.mythaia.vpn.protocol.hysteria.HysteriaObfuscator.of(it) }
        } else {
            null
        }
        val ms = QuicPing.ping(target, obfuscator) ?: return LatencyResult.Failed
        return LatencyResult.Success(ms)
    }

    /**
     * Times the whole dial: TCP, TLS or Reality, and the protocol's own
     * request, through every hop of a chain. Nothing is sent to the internet.
     */
    private suspend fun performHandshakeTest(config: ProxyConfiguration): LatencyResult = coroutineScope {
        val connections = mutableListOf<ProxyConnection>()
        val watcher = launch {
            try { awaitCancellation() } finally { connections.forEach { it.cancel() } }
        }
        try {
            val started = System.nanoTime()
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
            val check = target
            val proxyConnection = ProxyClientFactory.connect(
                config, check.host, check.port, tunnel = tunnelConnection
            )
            connections.add(proxyConnection)
            val elapsed = ((System.nanoTime() - started) / 1_000_000L).toInt()
            LatencyResult.Success(elapsed.coerceAtLeast(1))
        } finally {
            watcher.cancel()
            connections.forEach { runCatching { it.cancel() } }
        }
    }

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

            val check = target
            val proxyConnection = ProxyClientFactory.connect(
                config, check.host, check.port, tunnel = tunnelConnection
            )
            connections.add(proxyConnection)

            // Phase 2 (untimed warmup): Drain proxy-side buffers.
            val warmupRequest = "HEAD ${check.path} HTTP/1.1\r\nHost: ${check.hostHeader}\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(warmupRequest)
            val warmupData = proxyConnection.receive()

            val warmupStatus = warmupData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (!answered(warmupStatus)) {
                throw LatencyTestError("Unexpected warmup status: ${warmupStatus ?: "no response"}")
            }

            // Phase 3 (untimed): Send the timed HTTP request.
            val httpRequest = "HEAD ${check.path} HTTP/1.1\r\nHost: ${check.hostHeader}\r\nConnection: close\r\n\r\n"
                .toByteArray(Charsets.US_ASCII)
            proxyConnection.send(httpRequest)

            // Phase 4 (timed): Wait for the response.
            val startNs = System.nanoTime()
            val responseData = proxyConnection.receive()
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            val statusLine = responseData?.let { String(it, Charsets.US_ASCII) }
                ?.split("\r\n", limit = 2)?.firstOrNull()
            if (!answered(statusLine)) {

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
