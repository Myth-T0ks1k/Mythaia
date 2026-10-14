package com.mythaia.vpn.protocol

import com.mythaia.data.model.NaiveProtocol
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyResult
import com.mythaia.data.network.LatencyTester
import com.mythaia.vpn.protocol.anytls.AnyTlsClient
import com.mythaia.vpn.protocol.naive.NaiveClient
import com.mythaia.vpn.protocol.naive.http2.Http2SessionPool
import com.mythaia.vpn.protocol.nowhere.NowhereClient
import com.mythaia.vpn.protocol.nowhere.NowhereSession
import com.mythaia.vpn.protocol.quic.QuicClientPool
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * What a latency test leaves in the per-server pools, and what it must not
 * take from the tunnel.
 *
 * A test across a subscription of thousands of servers used to leave one
 * Hysteria2/TUIC client — a socket and two threads that never idle out — or
 * one AnyTLS, Naive or Nowhere session per server, until the app crashed.
 * After the fix each test releases what it pooled, except the session the
 * running tunnel is using, which a test of that same server must not close.
 *
 * Real QUIC needs the native library, so the Hysteria2 configuration below
 * names an obfuscation this build does not speak: the client refuses it
 * before opening a socket, yet only after the pool has filed the client,
 * which is exactly the state a failed test leaves behind.
 */
class PoolEvictionTest {

    private val tunnel = Any()

    @After
    fun tearDown() {
        LiveTunnel.unregister(tunnel)
        QuicClientPool.closeAll()
        runBlocking { AnyTlsClient.shutdown() }
        Http2SessionPool.closeAll()
        NowhereClient.shutdown()
    }

    private fun base(protocol: OutboundProtocol, port: Int = 443) = ProxyConfiguration(
        name = protocol.name,
        serverAddress = "127.0.0.1",
        serverPort = port.toUShort(),
        uuid = UUID.randomUUID(),
        encryption = "none",
        outboundProtocol = protocol,
        password = "secret",
        tls = TlsConfiguration(serverName = "example.com")
    )

    private fun hysteria() = base(OutboundProtocol.HYSTERIA2).copy(obfuscation = "not-an-obfuscation")

    private fun test(config: ProxyConfiguration): LatencyResult =
        runBlocking { LatencyTester.test(config, LatencyKind.HANDSHAKE) }

    // MARK: - Hysteria2 through LatencyTester

    @Test
    fun `a latency test closes the Hysteria2 client it dialled through`() {
        val config = hysteria()
        val pooled = QuicClientPool.hysteria(config)

        assertEquals(LatencyResult.Failed, test(config))

        // The next dial gets a new client: the one the test used is gone.
        assertNotSame(pooled, QuicClientPool.hysteria(config))
    }

    @Test
    fun `testing the server the tunnel is using leaves its client alone`() {
        val config = hysteria()
        val pooled = QuicClientPool.hysteria(config)
        LiveTunnel.register(tunnel) { config }

        test(config)

        assertSame(pooled, QuicClientPool.hysteria(config))
    }

    @Test
    fun `a duplicate of the live server under another id shares its client and keeps it`() {
        val live = hysteria()
        val duplicate = live.copy(id = UUID.randomUUID(), name = "duplicate")
        val pooled = QuicClientPool.hysteria(live)
        LiveTunnel.register(tunnel) { live }

        test(duplicate)

        assertSame(pooled, QuicClientPool.hysteria(live))
    }

    @Test
    fun `a stopped tunnel no longer protects its server`() {
        val config = hysteria()
        val pooled = QuicClientPool.hysteria(config)
        LiveTunnel.register(tunnel) { null }

        test(config)

        assertNotSame(pooled, QuicClientPool.hysteria(config))
    }

    @Test
    fun `a client another test still holds survives until that test ends too`() {
        val config = hysteria()
        val pooled = QuicClientPool.hysteria(config)
        // A second test of the same server, still running.
        ProxyClientFactory.retain(config)

        test(config)
        assertSame(pooled, QuicClientPool.hysteria(config))

        ProxyClientFactory.release(config)
        assertNotSame(pooled, QuicClientPool.hysteria(config))
    }

    @Test
    fun `a chain hop is released with the test, unless the tunnel's chain uses it`() {
        val hop = hysteria()
        val exit = base(OutboundProtocol.VLESS).copy(chain = listOf(hop))

        val first = QuicClientPool.hysteria(hop)
        test(exit)
        assertNotSame(first, QuicClientPool.hysteria(hop))

        val second = QuicClientPool.hysteria(hop)
        LiveTunnel.register(tunnel) { exit }
        test(hop)
        assertSame(second, QuicClientPool.hysteria(hop))
    }

    // MARK: - The other pools

    @Test
    fun `releasing a TUIC server closes its client unless it is live`() {
        val config = base(OutboundProtocol.TUIC)

        val first = QuicClientPool.tuic(config)
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertNotSame(first, QuicClientPool.tuic(config))

        val second = QuicClientPool.tuic(config)
        LiveTunnel.register(tunnel) { config }
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertSame(second, QuicClientPool.tuic(config))
    }

    /** A carrier that ends at once, so an AnyTLS handshake fails without a network. */
    private class DeadTunnel : ProxyConnection() {
        override val isConnected: Boolean get() = false
        override suspend fun sendRaw(data: ByteArray) = Unit
        override fun sendRawAsync(data: ByteArray) = Unit
        override suspend fun receiveRaw(): ByteArray? = null
        override fun cancel() = Unit
    }

    private fun dialAnyTls(config: ProxyConfiguration) {
        // A failed dial still leaves the profile's pool behind, as a failed test does.
        runBlocking { runCatching { AnyTlsClient(config, DeadTunnel()).connect("example.com", 80) } }
        assertTrue(AnyTlsClient.isPooled(config.id))
    }

    @Test
    fun `releasing an AnyTLS server drops its session pool unless it is live`() {
        val config = base(OutboundProtocol.ANYTLS)

        dialAnyTls(config)
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertFalse(AnyTlsClient.isPooled(config.id))

        dialAnyTls(config)
        LiveTunnel.register(tunnel) { config }
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertTrue(AnyTlsClient.isPooled(config.id))
    }

    @Test
    fun `releasing a Naive HTTP2 server closes its pooled session unless it is live`() {
        assertFalse(naiveSessionSurvivesRelease(live = false))
        assertTrue(naiveSessionSurvivesRelease(live = true))
    }

    /**
     * Parks a pooled Naive session in its TLS handshake against a server that
     * never answers, releases the server, and reports whether the pool still
     * holds the session.
     */
    private fun naiveSessionSurvivesRelease(live: Boolean): Boolean {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val accepted = CompletableFuture<Socket>()
        thread(isDaemon = true) { runCatching { accepted.complete(server.accept()) } }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val config = base(OutboundProtocol.NAIVE_HTTP2, server.localPort)
                .copy(naiveProtocol = NaiveProtocol.HTTP2, naiveUsername = "u", naivePassword = "p")
            val naive = NaiveClient.naiveConfiguration(config, NaiveProtocol.HTTP2)
            val dial = scope.async { Http2SessionPool.acquireStream(naive, "example.com:80", scope) }
            // Connected, and waiting for a ServerHello that never comes.
            val connection = accepted.get(5, TimeUnit.SECONDS)
            assertTrue(Http2SessionPool.holds(naive.poolKey))

            if (live) LiveTunnel.register(tunnel) { config }
            ProxyClientFactory.retain(config)
            ProxyClientFactory.release(config)
            val survived = Http2SessionPool.holds(naive.poolKey)

            // Let the parked handshake finish so nothing outlives the test.
            Http2SessionPool.closeAll()
            connection.close()
            runBlocking { withTimeout(5_000) { runCatching { dial.await() } } }
            LiveTunnel.unregister(tunnel)
            return survived
        } finally {
            scope.cancel()
            server.close()
        }
    }

    @Test
    fun `releasing a Nowhere server closes its session unless it is live`() {
        val config = base(OutboundProtocol.NOWHERE)
        val settings = NowhereClient.settings(config, NowhereClient.Identity.of(config).sessionId)

        val first = NowhereSession.shared(settings)
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertTrue(first.isClosed)
        assertNotSame(first, NowhereSession.shared(settings))

        val second = NowhereSession.shared(settings)
        LiveTunnel.register(tunnel) { config }
        ProxyClientFactory.retain(config)
        ProxyClientFactory.release(config)
        assertFalse(second.isClosed)
        assertSame(second, NowhereSession.shared(settings))
    }
}
