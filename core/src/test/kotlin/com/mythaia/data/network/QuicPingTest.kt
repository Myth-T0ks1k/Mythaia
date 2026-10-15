package com.mythaia.data.network

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.hysteria.SalamanderPacketObfuscator
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The UDP ping: a server that listens on UDP only (Hysteria2, TUIC) never
 * answered the TCP ping, so a reachable server always read as failed.
 */
class QuicPingTest {

    private val servers = mutableListOf<DatagramSocket>()

    @After
    fun closeServers() = servers.forEach { it.close() }

    /**
     * A stand-in QUIC endpoint: answers a probe of full size and unknown
     * version with Version Negotiation, as quic-go does. [unwrap] undoes the
     * client's obfuscation and [wrap] applies the server's to the reply.
     */
    private fun quicServer(
        unwrap: (ByteArray) -> ByteArray? = { it },
        wrap: (ByteArray) -> ByteArray = { it }
    ): InetSocketAddress {
        val socket = DatagramSocket(0, InetAddress.getLoopbackAddress())
        servers += socket
        Thread {
            val buffer = ByteArray(4096)
            while (!socket.isClosed) {
                val packet = DatagramPacket(buffer, buffer.size)
                runCatching { socket.receive(packet) }.onFailure { return@Thread }
                val data = unwrap(packet.data.copyOf(packet.length)) ?: continue
                if (data.size < QuicPing.PROBE_SIZE || (data[0].toInt() and 0x80) == 0) continue
                // Version 0, then the client's ids swapped, then one version we speak.
                val reply = byteArrayOf(0x80.toByte(), 0, 0, 0, 0, 8) + data.copyOfRange(15, 23) +
                    byteArrayOf(8) + data.copyOfRange(6, 14) + byteArrayOf(0, 0, 0, 1)
                val wrapped = wrap(reply)
                socket.send(DatagramPacket(wrapped, wrapped.size, packet.socketAddress))
            }
        }.apply { isDaemon = true }.start()
        return InetSocketAddress(InetAddress.getLoopbackAddress(), socket.localPort)
    }

    @Test
    fun `the probe is a full-size long-header packet of a reserved version`() {
        val probe = QuicPing.probe()
        assertEquals(QuicPing.PROBE_SIZE, probe.size)
        assertEquals(0xC0, probe[0].toInt() and 0xC0)
        val version = probe.copyOfRange(1, 5).fold(0) { acc, b -> (acc shl 8) or (b.toInt() and 0xFF) }
        assertEquals(0x0a0a0a0a, version and 0x0f0f0f0f)
        assertEquals(8, probe[5].toInt())
        assertEquals(8, probe[14].toInt())
        assertFalse(QuicPing.isVersionNegotiation(probe))
    }

    @Test
    fun `a QUIC server answers the probe`() {
        val ms = QuicPing.ping(quicServer())
        assertNotNull(ms)
        assertTrue(ms!! >= 1)
    }

    @Test
    fun `a salamander server answers the probe disguised for it`() {
        val server = SalamanderPacketObfuscator("correct horse battery")
        val ms = QuicPing.ping(
            quicServer(unwrap = { server.open(it) }, wrap = { server.seal(it).single() }),
            SalamanderPacketObfuscator("correct horse battery")
        )
        assertNotNull(ms)
    }

    @Test
    fun `a plain probe is lost on a salamander server`() {
        val server = SalamanderPacketObfuscator("correct horse battery")
        val target = quicServer(unwrap = { server.open(it) }, wrap = { server.seal(it).single() })
        assertNull(QuicPing.ping(target, obfuscator = null, attempts = 2, windowMs = 200))
    }

    @Test
    fun `silence is a failure within the time it was given`() {
        val silent = DatagramSocket(0, InetAddress.getLoopbackAddress()).also { servers += it }
        val started = System.nanoTime()
        assertNull(QuicPing.ping(InetSocketAddress(InetAddress.getLoopbackAddress(), silent.localPort), attempts = 2, windowMs = 200))
        assertTrue((System.nanoTime() - started) / 1_000_000 < 2_000)
    }

    @Test
    fun `the ping kind probes a Hysteria2 server over UDP`() = runBlocking {
        val target = quicServer()
        val config = ProxyConfiguration.fromUrl("hysteria2://secret@127.0.0.1:${target.port}?sni=example.com#h2")
        assertTrue(LatencyTester.listensOnUdp(config))
        val result = LatencyTester.test(config, LatencyKind.TCP)
        assertTrue("got $result", result is LatencyResult.Success)
    }

    @Test
    fun `TCP servers keep the TCP connect`() {
        assertFalse(LatencyTester.listensOnUdp(ProxyConfiguration.fromUrl("trojan://pw@example.com:443?security=tls#t")))
        assertTrue(LatencyTester.listensOnUdp(ProxyConfiguration.fromUrl("tuic://11111111-2222-3333-4444-555555555555:pw@example.com:443?sni=example.com#t")))
    }
}
