package com.mythaia.vpn.protocol.tuic

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.UUID

/**
 * How the shared TUIC client brings its session up when it cannot; the same
 * cases as Hysteria2's, whose session code it mirrors.
 *
 * Unit tests run without the native QUIC library, so a dial to a dead port
 * fails on the first native call here and on the handshake timeout where the
 * library is loaded. The dial behind it must fail at once either way.
 */
class TuicClientSessionTest {

    private val clients = mutableListOf<TuicClient>()

    @After
    fun tearDown() {
        clients.forEach { it.close() }
    }

    private fun client(port: Int) = TuicClient(
        ProxyConfiguration(
            name = "tuic",
            serverAddress = "127.0.0.1",
            serverPort = port.toUShort(),
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.TUIC,
            password = "secret",
            tls = TlsConfiguration(serverName = "example.com")
        )
    ).also { clients += it }

    /** A local UDP port with nothing behind it. */
    private fun deadPort(): Int = DatagramSocket(0, InetAddress.getLoopbackAddress()).use { it.localPort }

    private fun failure(block: suspend () -> Unit): Throwable =
        runCatching { runBlocking { block() } }.exceptionOrNull()
            ?: throw AssertionError("expected the dial to fail")

    @Test
    fun `a dial to a dead port is not repeated by the dial behind it`() {
        val tuic = client(deadPort())

        val first = failure { tuic.connect("example.com", 80) }
        assertTrue(first.toString(), first.message?.contains("next in") != true)

        val started = System.nanoTime()
        val second = failure { tuic.connect("example.com", 80) }
        val tookMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue(second.toString(), second is ProxyError.ConnectionFailed)
        assertTrue(second.message, second.message!!.contains("next in"))
        assertTrue("the second dial took $tookMillis ms", tookMillis < 1_000)

        val udp = failure { tuic.connectUDP("example.com", 53) }
        assertTrue(udp.message, udp.message!!.contains("next in"))
    }

    @Test
    fun `a closed client refuses to dial`() {
        val tuic = client(deadPort())
        tuic.close()

        val started = System.nanoTime()
        val tcp = failure { tuic.connect("example.com", 80) }
        val tookMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue(tcp.toString(), tcp is ProxyError.ConnectionFailed)
        assertTrue(tcp.message, tcp.message!!.contains("client closed"))
        assertTrue("the refusal took $tookMillis ms", tookMillis < 1_000)

        val udp = failure { tuic.connectUDP("example.com", 53) }
        assertTrue(udp.message, udp.message!!.contains("client closed"))
    }
}
