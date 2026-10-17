package com.mythaia.vpn.protocol.hysteria

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
 * How the shared Hysteria2 client brings its session up when it cannot.
 *
 * When a server went dark, every queued dial ran its own 10 s handshake in
 * turn, so the n-th waited n × 10 s and the local proxy hit its connection cap;
 * and a client the pool had already closed still dialled, leaving a session
 * nobody would ever close. These tests need no server: a dial that cannot
 * succeed is all the backoff needs, and a closed client must refuse before it
 * gets that far.
 *
 * Real QUIC needs the native library, which unit tests run without. A dial to
 * a dead port therefore fails on the first native call here, and on the
 * handshake timeout where the library is loaded; the second dial must fail at
 * once either way.
 */
class HysteriaClientSessionTest {

    private val clients = mutableListOf<HysteriaClient>()

    @After
    fun tearDown() {
        clients.forEach { it.close() }
    }

    private fun client(port: Int, obfuscation: String? = null) = HysteriaClient(
        ProxyConfiguration(
            name = "hysteria",
            serverAddress = "127.0.0.1",
            serverPort = port.toUShort(),
            uuid = UUID.randomUUID(),
            encryption = "none",
            outboundProtocol = OutboundProtocol.HYSTERIA2,
            password = "secret",
            obfuscation = obfuscation,
            tls = TlsConfiguration(serverName = "example.com")
        )
    ).also { clients += it }

    /** A local UDP port with nothing behind it. */
    private fun deadPort(): Int = DatagramSocket(0, InetAddress.getLoopbackAddress()).use { it.localPort }

    private fun failure(block: suspend () -> Unit): Throwable =
        runCatching { runBlocking { block() } }.exceptionOrNull()
            ?: throw AssertionError("expected the dial to fail")

    @Test
    fun `a failed attempt makes the next dial fail at once with its reason`() {
        // An obfuscation this build does not speak fails the attempt before
        // any socket exists, which makes the first failure deterministic.
        val hysteria = client(443, obfuscation = "not-an-obfuscation")

        val first = failure { hysteria.connect("example.com", 80) }
        assertTrue(first.toString(), first is ProxyError.ProtocolError)

        val second = failure { hysteria.connect("example.com", 80) }
        assertTrue(second.toString(), second is ProxyError.ConnectionFailed)
        assertTrue(second.message, second.message!!.contains("next in"))
        assertTrue(second.message, second.message!!.contains("unsupported obfuscation"))
    }

    @Test
    fun `a dial to a dead port is not repeated by the dial behind it`() {
        val hysteria = client(deadPort())

        val first = failure { hysteria.connect("example.com", 80) }
        assertTrue(first.toString(), first.message?.contains("next in") != true)

        val started = System.nanoTime()
        val second = failure { hysteria.connect("example.com", 80) }
        val tookMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue(second.toString(), second is ProxyError.ConnectionFailed)
        assertTrue(second.message, second.message!!.contains("next in"))
        assertTrue("the second dial took $tookMillis ms", tookMillis < 1_000)

        // UDP dials wait on the same session, so they are refused the same way.
        val udp = failure { hysteria.connectUDP("example.com", 53) }
        assertTrue(udp.message, udp.message!!.contains("next in"))
    }

    @Test
    fun `a closed client refuses to dial`() {
        // Were it to try, the obfuscation would fail it with a different error.
        val hysteria = client(443, obfuscation = "not-an-obfuscation")
        hysteria.close()

        val tcp = failure { hysteria.connect("example.com", 80) }
        assertTrue(tcp.toString(), tcp is ProxyError.ConnectionFailed)
        assertTrue(tcp.message, tcp.message!!.contains("client closed"))

        val udp = failure { hysteria.connectUDP("example.com", 53) }
        assertTrue(udp.message, udp.message!!.contains("client closed"))
    }
}
