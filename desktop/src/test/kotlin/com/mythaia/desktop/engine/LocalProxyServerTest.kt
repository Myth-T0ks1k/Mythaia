package com.mythaia.desktop.engine

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import kotlin.concurrent.thread

/**
 * The local listeners against a tiny origin on loopback: what a browser does
 * through SOCKS5, through HTTP CONNECT, and with a plain proxied GET.
 */
class LocalProxyServerTest {

    private lateinit var origin: ServerSocket
    private lateinit var server: LocalProxyServer
    private var proxyPort = 0
    private var httpPort = 0
    private val stats = TrafficStats()

    private val directDialer = object : Dialer {
        override suspend fun dial(host: String, port: Int, initialData: ByteArray?): Upstream? =
            if (host == "blocked.test") null else DirectUpstream.connect(host, port, initialData)

        override suspend fun dialUdp(host: String, port: Int): Upstream? = DirectUdpUpstream.connect(host, port)
    }

    @Before
    fun start() {
        origin = ServerSocket(0, 8, InetSocketAddress("127.0.0.1", 0).address)
        thread(isDaemon = true) {
            while (!origin.isClosed) {
                val client = runCatching { origin.accept() }.getOrNull() ?: break
                thread(isDaemon = true) {
                    client.use { c ->
                        val input = c.getInputStream()
                        val head = ByteArrayOutputStream()
                        while (true) {
                            val b = input.read()
                            if (b < 0) break
                            head.write(b)
                            val bytes = head.toByteArray()
                            if (bytes.size >= 4 && bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) break
                        }
                        val request = String(head.toByteArray(), Charsets.ISO_8859_1)
                        val line = request.lineSequence().first()
                        val body = "echo:$line"
                        c.getOutputStream().write(
                            ("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body")
                                .toByteArray(Charsets.ISO_8859_1)
                        )
                        c.getOutputStream().flush()
                    }
                }
            }
        }
        proxyPort = freePort()
        httpPort = freePort()
        server = LocalProxyServer(directDialer, stats)
        server.start(proxyPort, httpPort, allowLan = false, udp = true)
    }

    @After
    fun stop() {
        server.stop()
        origin.close()
    }

    @Test
    fun `socks5 connect carries an http request and answer`() {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxyPort))
        val connection = URL("http://127.0.0.1:${origin.localPort}/via-socks").openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        val body = connection.inputStream.bufferedReader().readText()
        assertEquals("echo:GET /via-socks HTTP/1.1", body)
        assertTrue(stats.up.get() > 0 && stats.down.get() > 0)
    }

    @Test
    fun `http proxy forwards a plain request in origin form`() {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort))
        val connection = URL("http://127.0.0.1:${origin.localPort}/via-http?x=1").openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        val body = connection.inputStream.bufferedReader().readText()
        assertEquals("echo:GET /via-http?x=1 HTTP/1.1", body)
    }

    @Test
    fun `http connect opens a tunnel`() {
        Socket("127.0.0.1", httpPort).use { socket ->
            socket.soTimeout = 5000
            val out = socket.getOutputStream()
            out.write("CONNECT 127.0.0.1:${origin.localPort} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".toByteArray())
            out.flush()
            val input = socket.getInputStream()
            val reply = readUntilBlankLine(input)
            assertTrue(reply, reply.startsWith("HTTP/1.1 200"))
            out.write("GET /tunnelled HTTP/1.1\r\nHost: x\r\n\r\n".toByteArray())
            out.flush()
            val answer = input.readBytes().toString(Charsets.ISO_8859_1)
            assertTrue(answer, answer.endsWith("echo:GET /tunnelled HTTP/1.1"))
        }
    }

    @Test
    fun `either port speaks both protocols`() {
        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))
        val connection = URL("http://127.0.0.1:${origin.localPort}/mixed").openConnection(proxy) as HttpURLConnection
        connection.connectTimeout = 5000
        connection.readTimeout = 5000
        assertEquals("echo:GET /mixed HTTP/1.1", connection.inputStream.bufferedReader().readText())
    }

    @Test
    fun `a blocked destination is refused`() {
        Socket("127.0.0.1", httpPort).use { socket ->
            socket.soTimeout = 5000
            socket.getOutputStream().write("CONNECT blocked.test:443 HTTP/1.1\r\n\r\n".toByteArray())
            socket.getOutputStream().flush()
            val reply = readUntilBlankLine(socket.getInputStream())
            assertTrue(reply, reply.startsWith("HTTP/1.1 403"))
        }
    }

    @Test
    fun `rule mode keeps private and turkmen addresses direct`() = runBlocking {
        val router = Router(emptyList(), global = false, bypassCountries = listOf("TM"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.DIRECT, router.decide("192.168.1.10"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.DIRECT, router.decide("177.93.143.20"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.DIRECT, router.decide("gov.tm"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.PROXY, router.decide("example.com"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.PROXY, router.decide("8.8.8.8"))
    }

    @Test
    fun `global mode sends turkmen addresses through the proxy`() = runBlocking {
        val router = Router(emptyList(), global = true, bypassCountries = listOf("TM"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.DIRECT, router.decide("192.168.1.10"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.PROXY, router.decide("177.93.143.20"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.PROXY, router.decide("gov.tm"))
        assertEquals(com.mythaia.desktop.model.RouteTarget.PROXY, router.decide("example.com"))
    }

    @Test
    fun `this host is loopback, link-local and unspecified, not the LAN`() {
        for (host in listOf("127.0.0.1", "127.8.8.8", "::1", "[::1]", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "localhost", "LOCALHOST.", "api.localhost", "::ffff:127.0.0.1")) {
            assertTrue(host, Router.isThisHostLiteral(host))
        }
        for (host in listOf("192.168.1.10", "10.0.0.1", "172.16.5.5", "8.8.8.8", "example.com", "router.lan", "localhost.example.com")) {
            assertFalse(host, Router.isThisHostLiteral(host))
        }
    }

    @Test
    fun `socks5 udp associate relays a datagram and its answer`() {
        val echo = java.net.DatagramSocket(0, InetSocketAddress("127.0.0.1", 0).address)
        thread(isDaemon = true) {
            val buf = ByteArray(2048)
            while (!echo.isClosed) {
                val p = java.net.DatagramPacket(buf, buf.size)
                runCatching { echo.receive(p) }.getOrNull() ?: break
                val answer = ("echo:" + String(p.data, p.offset, p.length)).toByteArray()
                echo.send(java.net.DatagramPacket(answer, answer.size, p.socketAddress))
            }
        }
        try {
            Socket("127.0.0.1", proxyPort).use { control ->
                control.soTimeout = 5000
                val out = control.getOutputStream()
                val input = control.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00)); out.flush()
                assertEquals(0x05, input.read()); assertEquals(0x00, input.read())
                // UDP ASSOCIATE from 0.0.0.0:0, as RFC 1928 allows: the relay learns the port from the first datagram.
                out.write(byteArrayOf(0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0)); out.flush()
                val reply = ByteArray(10)
                var read = 0
                while (read < reply.size) read += input.read(reply, read, reply.size - read).also { assertTrue(it > 0) }
                assertEquals(0x00, reply[1].toInt())
                val relayPort = ((reply[8].toInt() and 0xFF) shl 8) or (reply[9].toInt() and 0xFF)

                java.net.DatagramSocket(0, InetSocketAddress("127.0.0.1", 0).address).use { client ->
                    client.soTimeout = 5000
                    val header = byteArrayOf(0, 0, 0, 0x01, 127, 0, 0, 1, (echo.localPort ushr 8).toByte(), (echo.localPort and 0xFF).toByte())
                    val payload = "ping".toByteArray()
                    val datagram = header + payload
                    client.send(java.net.DatagramPacket(datagram, datagram.size, InetSocketAddress("127.0.0.1", relayPort)))
                    val answer = java.net.DatagramPacket(ByteArray(2048), 2048)
                    client.receive(answer)
                    val body = String(answer.data, answer.offset + header.size, answer.length - header.size)
                    assertEquals("echo:ping", body)
                }
            }
        } finally {
            echo.close()
        }
    }

    @Test
    fun `proxy engine refuses layer-3 WireGuard profiles`() {
        val wg = com.mythaia.data.model.ProxyConfiguration.fromWireGuardConfig(SAMPLE_WG_CONF, "Lab WG")
        val proxyEngine = ProxyEngine(TrafficStats())
        val settings = com.mythaia.desktop.model.DesktopSettings(
            socksPort = freePort(),
            httpPort = freePort(),
            setSystemProxy = false
        )
        val thrown = runCatching { proxyEngine.start(settings, wg) }.exceptionOrNull()
        assertTrue("Expected IOException for WireGuard in ProxyEngine, got $thrown", thrown is java.io.IOException)
        assertFalse(proxyEngine.isRunning)
    }

    @Test
    fun `import chunks and QR round-trip wg-quick configs and wg links`() {
        val wgUrl = "wg://198.51.100.10:51820?pk=ADAS9brqmHVG11XeR2owXGOqZnYvZMvr4Zl2ZB24ImM%3D&local_address=10.77.0.2/32&peer_pk=8f8vrIkNUX7YeEmFFDOm40WjPrdFJx7FYrQxrH7kHUo%3D&mtu=1400#LabLink"
        val parsed = com.mythaia.desktop.parseImportChunks(listOf(SAMPLE_WG_CONF, wgUrl), name = "FromConf")
        assertEquals(2, parsed.configurations.size)
        assertEquals("FromConf", parsed.configurations[0].name)
        assertEquals(com.mythaia.data.model.OutboundProtocol.WIREGUARD, parsed.configurations[0].outboundProtocol)
        assertEquals("LabLink", parsed.configurations[1].name)
        assertEquals(com.mythaia.data.model.OutboundProtocol.WIREGUARD, parsed.configurations[1].outboundProtocol)
        assertEquals(listOf("WireGuard · 198.51.100.10"), com.mythaia.desktop.describeImportText(SAMPLE_WG_CONF))
    }

    @Test
    fun `WireGuard editor form round-trips AmneziaWG parameters`() {
        val form = com.mythaia.data.model.WireGuardForm.blank().copy(
            privateKey = "ADAS9brqmHVG11XeR2owXGOqZnYvZMvr4Zl2ZB24ImM=",
            addresses = "10.77.0.2/32, fd00:77::2/128",
            dns = "1.1.1.1, 1.0.0.1",
            mtu = "1380",
            publicKey = "8f8vrIkNUX7YeEmFFDOm40WjPrdFJx7FYrQxrH7kHUo=",
            endpoint = "198.51.100.10:51820",
            allowedIps = "0.0.0.0/0, ::/0",
            keepalive = "25",
            jc = "4",
            jmin = "40",
            jmax = "70",
            s1 = "15",
            s2 = "25",
            h1 = "100001",
            h2 = "100002",
            h3 = "100003",
            h4 = "100004"
        )
        val built = com.mythaia.data.model.ProxyConfiguration.fromWireGuardConfig(form.toIni(), "AWG Test")
        assertEquals("AWG Test", built.name)
        val reopened = com.mythaia.data.model.WireGuardForm.fromIni(built.wireGuardConfig.orEmpty())
        assertTrue(reopened.isAmnezia)
        assertEquals("4", reopened.jc)
        assertEquals("40", reopened.jmin)
        assertEquals("70", reopened.jmax)
        assertEquals("15", reopened.s1)
        assertEquals("25", reopened.s2)
        assertEquals("100001", reopened.h1)
        assertEquals("100004", reopened.h4)
    }

    private fun readUntilBlankLine(input: java.io.InputStream): String {
        val out = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b < 0) break
            out.write(b)
            val bytes = out.toByteArray()
            if (bytes.size >= 4 && bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) break
        }
        return String(out.toByteArray(), Charsets.ISO_8859_1)
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    companion object {
        private val SAMPLE_WG_CONF = """
            [Interface]
            PrivateKey = ADAS9brqmHVG11XeR2owXGOqZnYvZMvr4Zl2ZB24ImM=
            Address = 10.77.0.2/32
            DNS = 1.1.1.1
            MTU = 1400

            [Peer]
            PublicKey = 8f8vrIkNUX7YeEmFFDOm40WjPrdFJx7FYrQxrH7kHUo=
            Endpoint = 198.51.100.10:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
        """.trimIndent()
    }
}

