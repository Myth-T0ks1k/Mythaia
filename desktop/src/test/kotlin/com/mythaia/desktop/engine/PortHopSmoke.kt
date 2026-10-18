package com.mythaia.desktop.engine

import com.mythaia.data.network.ProtocolProbe
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.quic.QuicClientPool
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.util.LogBackend
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Hysteria2 port hopping against a real server: one TCP stream and one UDP
 * flow kept busy across several hops, on one QUIC session.
 *
 * `MYTHAIA_HOP_LINK` is a hopping link (the lab's "Hysteria2 port hopping",
 * with scripts/lab/hoprelay.py standing in for the server's DNAT; 10.0.2.2
 * becomes 127.0.0.1), `MYTHAIA_HOP_SECONDS` the length (default 30), and
 * `MYTHAIA_HOP_UDP` a UDP echo (default the lab's 127.0.0.1:9053). The TCP
 * echo runs here. Passes when every echo came back intact, the path hopped
 * at least every interval, and the session was never dialled again.
 */
class PortHopSmoke {
    @Test
    fun `one session carries a stream and a UDP flow across every hop`() = runBlocking {
        val link = System.getenv("MYTHAIA_HOP_LINK")
        assumeTrue("MYTHAIA_HOP_LINK not set", !link.isNullOrBlank())
        val seconds = System.getenv("MYTHAIA_HOP_SECONDS")?.toInt() ?: 30
        val (udpHost, udpPort) = (System.getenv("MYTHAIA_HOP_UDP") ?: "127.0.0.1:9053").split(':').let { it[0] to it[1].toInt() }
        val input = ProtocolProbe.readInput(link!!.replace("10.0.2.2", "127.0.0.1").toByteArray())
        CertificatePolicy.setAllowInsecure(true)
        val config = ProtocolProbe.configurationsOf("hop", input).first()
        val ports = config.hysteriaPortUnion
        assertTrue("not a hopping link: $link", ports != null)

        val hops = AtomicInteger()
        val handshakes = AtomicInteger()
        val hopPorts = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()
        MythaiaLogger.debugEnabled = true
        MythaiaLogger.backend = object : LogBackend {
            override fun log(level: MythaiaLogger.Level, category: String, message: String) = debug(category, message)
            override fun debug(category: String, message: String) {
                if (message.startsWith("[QUIC] Hopped to port")) {
                    hops.incrementAndGet()
                    hopPorts.add(message.removePrefix("[QUIC] Hopped to port ").substringBefore(' ').toInt())
                }
                if (message.startsWith("[QUIC] Handshake complete")) handshakes.incrementAndGet()
                println("LOG ${System.currentTimeMillis() % 100000} [$category] $message")
            }
        }

        val echo = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        thread(isDaemon = true) {
            while (!echo.isClosed) {
                val s = runCatching { echo.accept() }.getOrNull() ?: break
                thread(isDaemon = true) { s.use { it.getInputStream().copyTo(it.getOutputStream(), 4096) } }
            }
        }

        println("HOP ${config.name}: ports $ports every ${config.hysteriaHop} s for $seconds s")
        val stream = ProxyClientFactory.connect(config, "127.0.0.1", echo.localPort)
        val udp = ProxyClientFactory.connectUDP(config, udpHost, udpPort)
        val random = Random(42)
        var rounds = 0
        var udpAnswered = 0
        var udpSent = 0
        val deadline = System.currentTimeMillis() + seconds * 1000L
        try {
            while (System.currentTimeMillis() < deadline) {
                val payload = random.nextBytes(4096)
                stream.send(payload)
                val back = java.io.ByteArrayOutputStream()
                withTimeout(10_000) {
                    while (back.size() < payload.size) {
                        back.write(stream.receive() ?: error("stream closed after $rounds rounds"))
                    }
                }
                assertTrue("echo $rounds came back changed", payload.contentEquals(back.toByteArray()))
                rounds++

                val datagram = random.nextBytes(200)
                udp.send(datagram)
                udpSent++
                val answer = withTimeoutOrNull(1_000) { udp.receive() }
                if (answer != null && answer.contentEquals(datagram)) udpAnswered++
                Thread.sleep(250)
            }
        } finally {
            stream.cancel()
            udp.cancel()
            echo.close()
            QuicClientPool.closeAll()
        }

        val interval = config.hysteriaHop
        println("HOP RESULT rounds=$rounds udp=$udpAnswered/$udpSent hops=${hops.get()} ports=$hopPorts handshakes=${handshakes.get()}")
        assertEquals("one QUIC session for the whole run", 1, handshakes.get())
        assertTrue("hopped ${hops.get()} times in $seconds s", hops.get() >= seconds / interval.max - 1)
        assertTrue("hops reached more than one port: $hopPorts", hopPorts.size >= 2)
        // UDP may lose a datagram as the server moves to the new address; not more than that.
        assertTrue("UDP answered $udpAnswered of $udpSent", udpAnswered >= udpSent - hops.get() - 1)
    }
}
