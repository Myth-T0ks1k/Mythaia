package com.mythaia.desktop.engine

import com.mythaia.data.network.LatencyKind
import com.mythaia.data.network.LatencyTester
import com.mythaia.data.network.ProtocolProbe
import com.mythaia.vpn.protocol.LiveTunnel
import com.mythaia.vpn.protocol.ProxyClientFactory
import com.mythaia.vpn.protocol.quic.QuicClientPool
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * Hammers one QUIC server (Hysteria2, TUIC) the way a busy desktop session
 * does, to shake out crashes that only show under load: many parallel
 * downloads through the local SOCKS listener, downloads cut off half way,
 * slow readers, UDP flows opened and dropped, latency tests on the same
 * server, and the pool closed under the flows as a server switch does.
 *
 * `MYTHAIA_STRESS_LINK` is the share link (10.0.2.2 is rewritten to
 * `MYTHAIA_STRESS_HOST`, default 127.0.0.1); `MYTHAIA_STRESS_TARGET` is a
 * host:port serving `GET /blob` (the lab's helpers.py, default
 * 127.0.0.1:8099); `MYTHAIA_STRESS_UDP` an echo (default 127.0.0.1:9053);
 * `MYTHAIA_STRESS_SINK` a TCP sink for uploads (none by default; any
 * server that reads and discards, `MYTHAIA_STRESS_UPLOADERS` of them at
 * once, default 12); `MYTHAIA_STRESS_SECONDS` the length (default 180).
 *
 * Retransmissions are what found the native crash this was written for —
 * ngtcp2 re-reads sent stream data when a packet is lost — so run it with
 * uploads through a UDP relay that drops a few percent of packets, and
 * restart the server from outside to exercise expiry and reconnects. A
 * native crash ends the test JVM with an hs_err_pid file in desktop/.
 */
class QuicStressSmoke {
    @Test
    fun `parallel flows through one QUIC server survive churn`() = runBlocking {
        val link = System.getenv("MYTHAIA_STRESS_LINK")
        assumeTrue("MYTHAIA_STRESS_LINK not set", !link.isNullOrBlank())
        val host = System.getenv("MYTHAIA_STRESS_HOST") ?: "127.0.0.1"
        val input = ProtocolProbe.readInput(link!!.replace("10.0.2.2", host).toByteArray())
        CertificatePolicy.setAllowInsecure(true)
        val config = ProtocolProbe.configurationsOf("stress", input).first()
        val (targetHost, targetPort) = (System.getenv("MYTHAIA_STRESS_TARGET") ?: "127.0.0.1:8099").split(':').let { it[0] to it[1].toInt() }
        val (udpHost, udpPort) = (System.getenv("MYTHAIA_STRESS_UDP") ?: "127.0.0.1:9053").split(':').let { it[0] to it[1].toInt() }
        // A TCP sink for uploads (C:/gtmp/tcp_discard.py); none set, no upload workers.
        val sink = System.getenv("MYTHAIA_STRESS_SINK")?.split(':')?.let { it[0] to it[1].toInt() }
        val uploaders = System.getenv("MYTHAIA_STRESS_UPLOADERS")?.toInt() ?: 12
        val seconds = System.getenv("MYTHAIA_STRESS_SECONDS")?.toInt() ?: 180
        if (System.getenv("MYTHAIA_STRESS_LOG") != null) {
            com.mythaia.vpn.util.MythaiaLogger.debugEnabled = true
            com.mythaia.vpn.util.MythaiaLogger.backend = object : com.mythaia.vpn.util.LogBackend {
                override fun log(level: com.mythaia.vpn.util.MythaiaLogger.Level, category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} $level [$category] $message")
                override fun debug(category: String, message: String) =
                    println("LOG ${System.currentTimeMillis() % 100000} debug [$category] $message")
            }
        }

        // Always through the server: the engine's router keeps loopback targets direct.
        val dialer = object : Dialer {
            override suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream =
                ProxyUpstream(ProxyClientFactory.connect(config, host, port, initialData))
            override suspend fun dialUdp(host: String, port: Int): Upstream =
                ProxyUpstream(ProxyClientFactory.connectUDP(config, host, port))
        }
        val stats = TrafficStats()
        val server = LocalProxyServer(dialer, stats)
        val socks = ServerSocket(0).use { it.localPort }
        val http = ServerSocket(0).use { it.localPort }
        server.start(socks, http, allowLan = false, udp = true)
        LiveTunnel.register(this) { config }
        println("STRESS ${config.name} ${config.outboundProtocol} ${config.serverAddress}:${config.serverPort} for ${seconds}s")

        val deadline = System.currentTimeMillis() + seconds * 1000L
        val full = AtomicLong(); val cut = AtomicLong(); val failed = AtomicLong(); val udpOk = AtomicLong(); val udpFail = AtomicLong()
        val threads = mutableListOf<Thread>()

        fun worker(name: String, body: (Random) -> Unit) = Thread({
            val random = Random(name.hashCode())
            while (System.currentTimeMillis() < deadline) {
                try { body(random) } catch (_: Exception) { failed.incrementAndGet() }
            }
        }, name).also { it.isDaemon = true; threads += it; it.start() }

        repeat(40) { i ->
            worker("tcp-$i") { random ->
                Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socks))).use { s ->
                    s.soTimeout = 20_000
                    s.connect(InetSocketAddress.createUnresolved(targetHost, targetPort), 15_000)
                    s.getOutputStream().write("GET /blob HTTP/1.1\r\nHost: $targetHost\r\nConnection: close\r\n\r\n".toByteArray())
                    val mode = random.nextInt(10)
                    val limit = when (mode) { 0, 1, 2 -> random.nextInt(1, 600_000); else -> Int.MAX_VALUE }
                    val buffer = ByteArray(16 * 1024)
                    var total = 0
                    val stream = s.getInputStream()
                    while (total < limit) {
                        val n = stream.read(buffer)
                        if (n < 0) break
                        total += n
                        if (mode == 3) Thread.sleep(random.nextLong(1, 20)) // a slow reader
                    }
                    if (limit == Int.MAX_VALUE) full.incrementAndGet() else cut.incrementAndGet()
                }
            }
        }
        // Uploads: what a lost packet makes ngtcp2 retransmit is stream data the client sent.
        val up = AtomicLong()
        if (sink != null) repeat(uploaders) { i ->
            worker("up-$i") { random ->
                Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socks))).use { s ->
                    s.soTimeout = 20_000
                    s.connect(InetSocketAddress.createUnresolved(sink.first, sink.second), 15_000)
                    val out = s.getOutputStream()
                    val chunk = ByteArray(32 * 1024)
                    repeat(random.nextInt(8, 256)) {
                        random.nextBytes(chunk)
                        out.write(chunk)
                        up.addAndGet(chunk.size.toLong())
                    }
                }
            }
        }
        // Echoes: every byte that comes back must be the byte sent, retransmitted or not.
        val echo = System.getenv("MYTHAIA_STRESS_ECHO")?.split(':')?.let { it[0] to it[1].toInt() }
        val echoed = AtomicLong()
        val corrupted = AtomicLong()
        if (echo != null) repeat(8) { i ->
            worker("echo-$i") { random ->
                Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socks))).use { s ->
                    s.soTimeout = 30_000
                    s.connect(InetSocketAddress.createUnresolved(echo.first, echo.second), 15_000)
                    val sent = ByteArray(random.nextInt(16_384, 512 * 1024)).also { random.nextBytes(it) }
                    val writer = Thread({ runCatching { s.getOutputStream().write(sent) } }, "echo-writer-$i").apply { isDaemon = true; start() }
                    val back = s.getInputStream().readNBytes(sent.size)
                    writer.join(30_000)
                    if (back.size == sent.size) {
                        if (back.contentEquals(sent)) echoed.addAndGet(sent.size.toLong()) else corrupted.incrementAndGet()
                    }
                }
            }
        }
        repeat(8) { i ->
            worker("udp-$i") { random ->
                runBlocking {
                    val flow = ProxyClientFactory.connectUDP(config, udpHost, udpPort)
                    try {
                        repeat(random.nextInt(5, 200)) {
                            val payload = ByteArray(if (random.nextBoolean()) 64 else 1100).also { random.nextBytes(it) }
                            flow.send(payload)
                            if (withTimeoutOrNull(2_000) { flow.receive() } != null) udpOk.incrementAndGet() else udpFail.incrementAndGet()
                        }
                    } finally {
                        flow.cancel()
                    }
                }
            }
        }
        repeat(3) { i ->
            worker("ping-$i") { random ->
                runBlocking { LatencyTester.test(config, if (random.nextBoolean()) LatencyKind.HTTP else LatencyKind.TCP) }
                Thread.sleep(random.nextLong(200, 2_000))
            }
        }
        // A server switch: the pooled session goes while flows still use it
        // (MYTHAIA_STRESS_NOSWITCH=1 leaves it alone, for a clean integrity run).
        if (System.getenv("MYTHAIA_STRESS_NOSWITCH") == null) worker("switch") { random ->
            Thread.sleep(random.nextLong(2_000, 8_000))
            QuicClientPool.closeAll()
        }

        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(10_000)
            println("STRESS t=${(deadline - System.currentTimeMillis()) / 1000}s left full=$full cut=$cut failed=$failed udp=$udpOk/$udpFail down=${stats.down.get() / 1_000_000}MB up=${up.get() / 1_000_000}MB echoed=${echoed.get() / 1_000_000}MB corrupted=$corrupted threads=${Thread.activeCount()}")
        }
        // One minute for the workers to finish what they are in, all told:
        // the server stopping below ends whatever is still waiting.
        val joinBy = System.currentTimeMillis() + 60_000
        threads.forEach { it.join(maxOf(1, joinBy - System.currentTimeMillis())) }
        server.stop()
        LiveTunnel.unregister(this)
        QuicClientPool.closeAll()
        CertificatePolicy.setAllowInsecure(false)
        println("STRESS done full=$full cut=$cut failed=$failed udp=$udpOk/$udpFail echoed=${echoed.get() / 1_000_000}MB corrupted=$corrupted")
        org.junit.Assert.assertEquals("echoes that came back different", 0L, corrupted.get())
    }

    /**
     * Keep-alive connections that went quiet must not starve the session.
     *
     * `MYTHAIA_STRESS_IDLE` is a path on the target (a file a little under
     * 4 MiB, so each stream reads most of a credit batch and then stops);
     * eight connections fetch it and stay open, and a ninth must still
     * download `/blob` in full. While the connection window was credited per
     * stream, those eight held back more than Hysteria's whole 20 MiB window
     * and the ninth stalled at zero bytes.
     */
    @Test
    fun `idle keep-alive streams leave the session usable`() = runBlocking {
        val link = System.getenv("MYTHAIA_STRESS_LINK")
        // Without the leading slash is fine too: Git Bash rewrites "/name" into a Windows path.
        val idlePath = System.getenv("MYTHAIA_STRESS_IDLE")?.let { if (it.startsWith("/")) it else "/$it" }
        assumeTrue("MYTHAIA_STRESS_LINK / MYTHAIA_STRESS_IDLE not set", !link.isNullOrBlank() && !idlePath.isNullOrBlank())
        val host = System.getenv("MYTHAIA_STRESS_HOST") ?: "127.0.0.1"
        val input = ProtocolProbe.readInput(link!!.replace("10.0.2.2", host).toByteArray())
        CertificatePolicy.setAllowInsecure(true)
        val config = ProtocolProbe.configurationsOf("idle", input).first()
        val (targetHost, targetPort) = (System.getenv("MYTHAIA_STRESS_TARGET") ?: "127.0.0.1:8099").split(':').let { it[0] to it[1].toInt() }
        val dialer = object : Dialer {
            override suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream =
                ProxyUpstream(ProxyClientFactory.connect(config, host, port, initialData))
            override suspend fun dialUdp(host: String, port: Int): Upstream =
                ProxyUpstream(ProxyClientFactory.connectUDP(config, host, port))
        }
        val server = LocalProxyServer(dialer, TrafficStats())
        val socks = ServerSocket(0).use { it.localPort }
        val http = ServerSocket(0).use { it.localPort }
        server.start(socks, http, allowLan = false, udp = false)
        val idle = mutableListOf<Socket>()
        try {
            fun open(): Socket = Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socks))).apply {
                soTimeout = 20_000
                connect(InetSocketAddress.createUnresolved(targetHost, targetPort), 15_000)
            }
            /** Reads one keep-alive HTTP response whole; its body length. */
            fun fetch(s: Socket, path: String): Long {
                s.getOutputStream().write("GET $path HTTP/1.1\r\nHost: $targetHost\r\n\r\n".toByteArray())
                val inp = s.getInputStream()
                val head = StringBuilder()
                while (!head.endsWith("\r\n\r\n")) head.append(inp.read().also { check(it >= 0) { "closed in the headers" } }.toChar())
                val length = Regex("(?i)content-length: *(\\d+)").find(head)!!.groupValues[1].toLong()
                val buffer = ByteArray(64 * 1024)
                var left = length
                while (left > 0) {
                    val n = inp.read(buffer, 0, minOf(buffer.size.toLong(), left).toInt())
                    check(n >= 0) { "closed with $left bytes to go" }
                    left -= n
                }
                return length
            }
            repeat(8) { i ->
                val s = open()
                idle += s
                println("IDLE stream $i read ${fetch(s, idlePath!!)} bytes and stays open")
            }
            val started = System.currentTimeMillis()
            val length = open().use { fetch(it, "/blob") }
            println("IDLE fresh download: $length bytes in ${System.currentTimeMillis() - started} ms with ${idle.size} idle streams open")
        } finally {
            idle.forEach { runCatching { it.close() } }
            server.stop()
            QuicClientPool.closeAll()
            CertificatePolicy.setAllowInsecure(false)
        }
    }
}
