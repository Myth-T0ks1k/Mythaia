package com.mythaia.desktop.engine

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.desktop.model.RouteRule
import com.mythaia.desktop.model.RouteTarget
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.DnsCache
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * The desktop "tunnel": a local proxy whose every connection is routed and
 * dialled through the selected server. Switching servers replaces the
 * outbound for new connections; the listeners stay up.
 */
class ProxyEngine(val stats: TrafficStats) : Dialer {
    private val logger = MythaiaLogger("Engine")
    private val server = LocalProxyServer(this, stats)

    @Volatile
    var configuration: ProxyConfiguration? = null
        private set

    @Volatile
    private var router: Router = Router(emptyList(), global = false, bypassCountries = listOf("TM"))

    @Volatile
    private var systemProxySet = false

    val isRunning: Boolean get() = server.isRunning

    fun updateRouting(rules: List<RouteRule>, settings: DesktopSettings) {
        router = Router.from(rules, settings)
    }

    /** Starts the listeners for [configuration]; throws when a port is taken or [configuration] is layer 3. */
    @Throws(IOException::class)
    fun start(settings: DesktopSettings, configuration: ProxyConfiguration) {
        if (configuration.outboundProtocol.isLayer3) {
            throw IOException("WireGuard and AmneziaWG need TUN mode")
        }
        if (server.isRunning) {
            switchTo(configuration)
        } else {
            this.configuration = configuration
            DnsCache.setActiveProxyDomain(configuration.serverAddress)
            stats.reset()
            server.start(settings.socksPort, settings.httpPort, settings.allowLan, settings.socksUdp)
            // Latency tests leave the pooled sessions of the server in use alone.
            // The property, not the parameter: it follows switchTo.
            com.mythaia.vpn.protocol.LiveTunnel.register(this) { this.configuration }
        }
        if (settings.setSystemProxy && !systemProxySet) setSystemProxy(true, settings)
        logger.info("Outbound: ${configuration.name} (${configuration.outboundProtocol.displayName})")
    }

    /**
     * New connections dial [configuration] from here on; the ones being
     * relayed finish through whatever they were dialled with. The pooled
     * sessions belong to the old server — a QUIC connection with its TUIC
     * heartbeat, HTTP/2 connections — and nothing would dial them again, so
     * they are closed now rather than at [stop].
     */
    fun switchTo(configuration: ProxyConfiguration) {
        if (configuration.outboundProtocol.isLayer3) {
            throw IllegalArgumentException("WireGuard and AmneziaWG need TUN mode")
        }
        val previous = this.configuration
        this.configuration = configuration
        DnsCache.setActiveProxyDomain(configuration.serverAddress)
        if (previous != configuration) closePooledSessions()
        logger.info("Switched to ${configuration.name}")
    }

    fun stop() {
        server.stop()
        com.mythaia.vpn.protocol.LiveTunnel.unregister(this)
        closePooledSessions()
        configuration = null
        DnsCache.setActiveProxyDomain(null)
        setSystemProxy(false, null)
    }

    private fun closePooledSessions() {
        com.mythaia.vpn.protocol.quic.QuicClientPool.closeAll()
        com.mythaia.vpn.protocol.naive.http2.Http2StreamPool.closeAll()
    }

    /**
     * Turns the Windows proxy on or off for the running listeners. The engine
     * owns the flag so a toggle while connected is undone on stop like any other.
     */
    fun setSystemProxy(enabled: Boolean, settings: DesktopSettings?) {
        if (enabled && settings != null) {
            SystemProxy.enable("127.0.0.1:${settings.httpPort}", settings.proxyBypass)
            systemProxySet = true
        } else if (systemProxySet || com.mythaia.desktop.AppPaths.proxySnapshot.isFile) {
            SystemProxy.restore()
            systemProxySet = false
        }
    }

    // ----------------------------------------------------------------- dialer

    override fun wantsFirstData(host: String): Boolean =
        configuration?.outboundProtocol?.handshakeCarriesInitialData == true &&
            router.decide(host) == RouteTarget.PROXY

    override suspend fun isThisHost(host: String): Boolean {
        if (Router.isThisHostLiteral(host)) return true
        // Only a direct route can get to this machine; a proxied name resolves at the server.
        if (DnsCache.isIpAddress(host) || router.decide(host) != RouteTarget.DIRECT) return false
        return withContext(Dispatchers.IO) { runCatching { DnsCache.resolveAll(host) }.getOrDefault(emptyList()) }
            .any { Router.isThisHostLiteral(it) }
    }

    override suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream? =
        when (router.decide(host)) {
            RouteTarget.BLOCK -> null
            RouteTarget.DIRECT -> DirectUpstream.connect(host, port, initialData)
            RouteTarget.PROXY -> {
                val config = configuration ?: throw IOException("no server selected")
                ProxyUpstream(connectThrough(config, host, port, initialData))
            }
        }

    override suspend fun dialUdp(host: String, port: Int): Upstream? =
        when (router.decide(host)) {
            RouteTarget.BLOCK -> null
            RouteTarget.DIRECT -> DirectUdpUpstream.connect(host, port)
            RouteTarget.PROXY -> {
                val config = configuration ?: throw IOException("no server selected")
                val tunnel = connectChain(config, config.chain)
                ProxyUpstream(ProxyClientFactory.connectUDP(config, host, port, tunnel))
            }
        }

    /** The exit's connection to [host]:[port], through the chain when there is one. */
    private suspend fun connectThrough(
        config: ProxyConfiguration,
        host: String,
        port: Int,
        initialData: ByteArray?
    ): ProxyConnection {
        val tunnel = connectChain(config, config.chain)
        return ProxyClientFactory.connect(config, host, port, initialData, tunnel)
    }

    /** Entry → … → last hop, each tunnelled through the previous; null without a chain. */
    private suspend fun connectChain(exit: ProxyConfiguration, chain: List<ProxyConfiguration>?): ProxyConnection? {
        if (chain.isNullOrEmpty()) return null
        var previous: ProxyConnection? = null
        for (i in chain.indices) {
            val hop = chain[i]
            val next = if (i + 1 < chain.size) chain[i + 1] else exit
            previous = ProxyClientFactory.connect(hop, next.serverAddress, next.serverPort.toInt(), null, previous)
        }
        return previous
    }
}

/**
 * Where the direct sockets block. Each direct connection holds a thread in
 * a blocking read for as long as it lives, and on Dispatchers.IO, which
 * stops at 64 threads, 64 of them starved everything else that waits there
 * — dials through the server, latency tests, subscription updates — so the
 * proxy stalled behind a rule that sends traffic direct. A view of IO with
 * its own, higher ceiling shares IO's threads without that limit.
 */
private val DirectIo = Dispatchers.IO.limitedParallelism(1024)

/** A server connection as the relay sees it. */
class ProxyUpstream(private val connection: ProxyConnection) : Upstream {
    override suspend fun send(data: ByteArray) = connection.send(data)
    override suspend fun receive(): ByteArray? = connection.receive()
    override fun close() = connection.cancel()
}

/** A plain TCP socket to the destination, resolved through the app's own cache. */
class DirectUpstream private constructor(private val socket: Socket) : Upstream {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val buffer = ByteArray(32 * 1024)

    override suspend fun send(data: ByteArray) = withContext(DirectIo) {
        output.write(data)
        output.flush()
    }

    override suspend fun receive(): ByteArray? = withContext(DirectIo) {
        val n = input.read(buffer)
        if (n < 0) null else buffer.copyOf(n)
    }

    override fun close() {
        runCatching { socket.close() }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 10_000

        suspend fun connect(host: String, port: Int, initialData: ByteArray?): DirectUpstream = withContext(DirectIo) {
            val address = if (DnsCache.isIpAddress(host)) host
            else DnsCache.resolveHost(host) ?: throw IOException("cannot resolve $host")
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                // A no-op in proxy mode; with the TUN up it keeps this socket off the tunnel.
                if (!com.mythaia.vpn.SocketProtector.protect(socket)) throw IOException("cannot protect the socket")
                socket.connect(InetSocketAddress(InetAddress.getByName(address), port), CONNECT_TIMEOUT_MS)
                if (initialData != null && initialData.isNotEmpty()) {
                    socket.getOutputStream().apply { write(initialData); flush() }
                }
            } catch (e: Exception) {
                runCatching { socket.close() }
                throw e
            }
            DirectUpstream(socket)
        }
    }
}

/** A datagram socket bound to one destination. */
class DirectUdpUpstream private constructor(private val socket: DatagramSocket, private val target: InetSocketAddress) : Upstream {
    private val buffer = ByteArray(65_535)

    override suspend fun send(data: ByteArray) = withContext(DirectIo) {
        socket.send(DatagramPacket(data, data.size, target))
    }

    override suspend fun receive(): ByteArray? = withContext(DirectIo) {
        val packet = DatagramPacket(buffer, buffer.size)
        socket.receive(packet)
        packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
    }

    override fun close() {
        runCatching { socket.close() }
    }

    companion object {
        suspend fun connect(host: String, port: Int): DirectUdpUpstream = withContext(DirectIo) {
            val address = if (DnsCache.isIpAddress(host)) host
            else DnsCache.resolveHost(host) ?: throw IOException("cannot resolve $host")
            val socket = DatagramSocket(null)
            if (!com.mythaia.vpn.SocketProtector.protect(socket)) throw IOException("cannot protect the socket")
            if (!socket.isBound) socket.bind(null)
            socket.soTimeout = 120_000
            DirectUdpUpstream(socket, InetSocketAddress(InetAddress.getByName(address), port))
        }
    }
}
