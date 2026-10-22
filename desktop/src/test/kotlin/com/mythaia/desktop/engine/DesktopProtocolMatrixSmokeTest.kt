package com.mythaia.desktop.engine

import com.mythaia.data.model.HttpTransportConfiguration
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.data.model.XHttpPlacement
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.model.DesktopSettings
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.nowhere.NowhereClient
import com.mythaia.vpn.protocol.sudoku.SudokuAeadMethod
import com.mythaia.vpn.protocol.sudoku.SudokuAsciiMode
import com.mythaia.vpn.protocol.sudoku.SudokuClient
import com.mythaia.vpn.protocol.sudoku.SudokuProtocol
import com.mythaia.vpn.protocol.sudoku.SudokuPureDecoder
import com.mythaia.vpn.protocol.sudoku.SudokuTablePair
import com.mythaia.vpn.protocol.sudoku.SudokuXorshift64Star
import com.mythaia.vpn.protocol.tls.TlsServer
import com.mythaia.vpn.protocol.vmess.VmessSecurity
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * End-to-end Desktop [ProxyEngine] + [LocalProxyServer] (SOCKS5 and HTTP proxy)
 * live smoke tests across the new protocol and transport matrix:
 * - Xray: VMess + XHTTP (plain HTTP, custom header/cookie placements, TLS H2 & HTTP/1.1,
 *   REALITY) across `auto`, `packet-up`, `stream-up`, `stream-one` modes and
 *   `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero` ciphers.
 * - Sing-box: VLESS/VMess/Trojan over `http` (HTTP/2 TLS and HTTP/1.1 plain) and
 *   `quic` transports, plus Hysteria2 (plain and Salamander).
 * - Loopback protocol servers: Sudoku (stream and native `KIP_OPEN_MUX`) and
 *   Nowhere (TLS 1.3 exporter-authenticated flow) through [ProxyEngine].
 *
 * Never touches the user's Windows system proxy (`setSystemProxy = false`) or `%APPDATA%`.
 */
class DesktopProtocolMatrixSmokeTest {

    companion object {
        val nativeLoaded: Boolean

        init {
            val candidates = listOfNotNull(
                System.getProperty("mythaia.native.library")?.takeIf { it.isNotBlank() }?.let(::File),
                File("desktop/native/out/mythaia_native.dll"),
                File("native/out/mythaia_native.dll"),
                File("../desktop/native/out/mythaia_native.dll")
            )
            val dll = candidates.firstOrNull { it.isFile }
            if (dll != null) {
                if (System.getProperty("mythaia.native.library").isNullOrBlank()) {
                    System.setProperty("mythaia.native.library", dll.absolutePath)
                }
                nativeLoaded = runCatching { System.load(dll.absolutePath); true }.getOrDefault(false)
            } else {
                nativeLoaded = false
            }
        }
    }

    private lateinit var tempDir: File
    private lateinit var originServer: ServerSocket
    private var originPort: Int = 0
    private lateinit var engine: ProxyEngine
    private var socksPort: Int = 0
    private var httpPort: Int = 0
    private lateinit var settings: DesktopSettings

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("mythaia-desktop-matrix-smoke-").toFile()
        AppPaths.overrideDataDir = tempDir

        originServer = ServerSocket(0, 64, InetAddress.getByName("127.0.0.1"))
        originPort = originServer.localPort
        thread(isDaemon = true, name = "matrix-origin-accept") {
            while (!originServer.isClosed) {
                val client = runCatching { originServer.accept() }.getOrNull() ?: break
                thread(isDaemon = true, name = "matrix-origin-worker") {
                    client.use { sock ->
                        sock.soTimeout = 10_000
                        val input = sock.getInputStream()
                        val head = ByteArrayOutputStream()
                        while (true) {
                            val b = input.read()
                            if (b < 0) return@use
                            head.write(b)
                            val arr = head.toByteArray()
                            val n = arr.size
                            if (n >= 4 &&
                                arr[n - 4] == 13.toByte() &&
                                arr[n - 3] == 10.toByte() &&
                                arr[n - 2] == 13.toByte() &&
                                arr[n - 1] == 10.toByte()
                            ) break
                        }
                        val headerText = String(head.toByteArray(), Charsets.ISO_8859_1)
                        val requestLine = headerText.lineSequence().firstOrNull().orEmpty()
                        val body = "origin-ok:$requestLine"
                        val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                        sock.getOutputStream().write(resp.toByteArray(Charsets.ISO_8859_1))
                        sock.getOutputStream().flush()
                    }
                }
            }
        }

        socksPort = freePort()
        httpPort = freePort()
        engine = ProxyEngine(TrafficStats())
        settings = DesktopSettings(
            socksPort = socksPort,
            httpPort = httpPort,
            setSystemProxy = false,
            tunnelMode = "proxy",
            routeMode = "global",
            bypassTurkmenistan = false
        )
        engine.updateRouting(emptyList(), settings)
    }

    @After
    fun tearDown() {
        runCatching { engine.stop() }
        runCatching { originServer.close() }
        SudokuClient.clearAllPools()
        NowhereClient.shutdown()
        AppPaths.overrideDataDir = null
        runCatching { tempDir.deleteRecursively() }
    }

    private fun freePort(): Int =
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    private fun waitForTcpPort(port: Int, timeoutMs: Long = 5_000L): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket("127.0.0.1", port).use { return true }
            } catch (_: Exception) {
                Thread.sleep(40)
            }
        }
        return false
    }

    private fun verifyEngineRoundTrip(config: ProxyConfiguration, label: String, concurrentCount: Int = 2) {
        val safeLabel = label.replace(Regex("[^A-Za-z0-9_.-]"), "_")
        val upBefore = engine.stats.up.get()
        val downBefore = engine.stats.down.get()

        engine.start(settings, config)
        assertTrue("Expected ProxyEngine to be running for $label", engine.isRunning)
        assertEquals(config, engine.configuration)

        val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
        val httpProxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", httpPort))

        // 1. SOCKS5 request through ProxyEngine -> outbound protocol -> origin
        val socksPath = "/socks/$safeLabel"
        val socksConn = URI("http://origin.example.com:$originPort$socksPath").toURL()
            .openConnection(socksProxy) as HttpURLConnection
        socksConn.connectTimeout = 10_000
        socksConn.readTimeout = 10_000
        assertEquals("SOCKS5 status for $label", 200, socksConn.responseCode)
        val socksBody = socksConn.inputStream.bufferedReader().readText()
        assertEquals("SOCKS5 body for $label", "origin-ok:GET $socksPath HTTP/1.1", socksBody)

        // 2. HTTP proxy request through ProxyEngine -> outbound protocol -> origin
        val httpPath = "/http/$safeLabel"
        val httpConn = URI("http://origin.example.com:$originPort$httpPath").toURL()
            .openConnection(httpProxy) as HttpURLConnection
        httpConn.connectTimeout = 10_000
        httpConn.readTimeout = 10_000
        assertEquals("HTTP proxy status for $label", 200, httpConn.responseCode)
        val httpBody = httpConn.inputStream.bufferedReader().readText()
        assertEquals("HTTP proxy body for $label", "origin-ok:GET $httpPath HTTP/1.1", httpBody)

        // 3. Concurrent requests across SOCKS5 & HTTP proxy listeners
        if (concurrentCount > 1) {
            val pool = Executors.newFixedThreadPool(concurrentCount)
            try {
                val tasks = (1..concurrentCount).map { idx ->
                    Callable {
                        val p = if (idx % 2 == 0) socksProxy else httpProxy
                        val path = "/conc/$safeLabel/$idx"
                        val conn = URI("http://origin.example.com:$originPort$path").toURL()
                            .openConnection(p) as HttpURLConnection
                        conn.connectTimeout = 10_000
                        conn.readTimeout = 10_000
                        val code = conn.responseCode
                        val text = conn.inputStream.bufferedReader().readText()
                        assertEquals("Concurrent[$idx] code for $label", 200, code)
                        assertEquals("Concurrent[$idx] body for $label", "origin-ok:GET $path HTTP/1.1", text)
                    }
                }
                pool.invokeAll(tasks).forEach { it.get(15, TimeUnit.SECONDS) }
            } finally {
                pool.shutdownNow()
            }
        }

        assertTrue("Expected stats.up to advance for $label", engine.stats.up.get() > upBefore)
        assertTrue("Expected stats.down to advance for $label", engine.stats.down.get() > downBefore)
    }

    @Test
    fun `Desktop ProxyEngine smoke test across Xray VMess XHTTP, TLS, REALITY, and VmessSecurity matrix`() {
        val xrayBin = listOfNotNull(
            System.getenv("MYTHAIA_XRAY")?.takeIf { it.isNotBlank() }?.let { File(it) },
            System.getenv("XRAY")?.takeIf { it.isNotBlank() }?.let { File(it) }
        ).firstOrNull { it.isFile }
        assumeTrue("No local xray binary found for live Desktop ProxyEngine test", xrayBin != null)
        val bin = xrayBin!!

        val certProc = ProcessBuilder(bin.absolutePath, "tls", "cert", "--domain=localhost")
            .redirectErrorStream(true)
            .start()
        val certOut = certProc.inputStream.bufferedReader().readText()
        certProc.waitFor(10, TimeUnit.SECONDS)
        val certObj = JSONObject(certOut.substring(certOut.indexOf('{')).trim())

        val userUuid = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val realityPrivateKey = "aLU54PDyo85Mn2JietGWthdOImxFonHn3jq7_hmPOUQ"
        val realityPublicKey = "YsP5Y9uw0OTS6d1DXoDZH33a2CBIfsVid9j_3DPZcxc"
        val realityShortId = "0123456789abcdef"

        val portPlain = freePort()
        val portPlacement = freePort()
        val portTls = freePort()
        val portReality = freePort()

        val configJson = JSONObject().apply {
            put("log", JSONObject().put("loglevel", "warning"))
            put(
                "inbounds",
                JSONArray()
                    .put(
                        JSONObject()
                            .put("tag", "in-plain")
                            .put("listen", "127.0.0.1")
                            .put("port", portPlain)
                            .put("protocol", "vmess")
                            .put("settings", JSONObject().put("clients", JSONArray().put(JSONObject().put("id", userUuid.toString()))))
                            .put(
                                "streamSettings",
                                JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "none")
                                    .put("xhttpSettings", JSONObject().put("path", "/xh").put("mode", "auto"))
                            )
                    )
                    .put(
                        JSONObject()
                            .put("tag", "in-placement")
                            .put("listen", "127.0.0.1")
                            .put("port", portPlacement)
                            .put("protocol", "vmess")
                            .put("settings", JSONObject().put("clients", JSONArray().put(JSONObject().put("id", userUuid.toString()))))
                            .put(
                                "streamSettings",
                                JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "none")
                                    .put(
                                        "xhttpSettings",
                                        JSONObject()
                                            .put("path", "/custom")
                                            .put("mode", "packet-up")
                                            .put(
                                                "extra",
                                                JSONObject()
                                                    .put("sessionIDPlacement", "header")
                                                    .put("sessionIDKey", "X-My-Session")
                                                    .put("seqPlacement", "cookie")
                                                    .put("seqKey", "my_seq")
                                                    .put("uplinkDataPlacement", "header")
                                                    .put("uplinkDataKey", "X-Up-Data")
                                                    .put("uplinkChunkSize", 256)
                                                    .put("serverMaxHeaderBytes", 65536)
                                                    .put("noSSEHeader", true)
                                            )
                                    )
                            )
                    )
                    .put(
                        JSONObject()
                            .put("tag", "in-tls")
                            .put("listen", "127.0.0.1")
                            .put("port", portTls)
                            .put("protocol", "vmess")
                            .put("settings", JSONObject().put("clients", JSONArray().put(JSONObject().put("id", userUuid.toString()))))
                            .put(
                                "streamSettings",
                                JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "tls")
                                    .put(
                                        "tlsSettings",
                                        JSONObject()
                                            .put("alpn", JSONArray().put("h2").put("http/1.1"))
                                            .put("certificates", JSONArray().put(certObj))
                                    )
                                    .put("xhttpSettings", JSONObject().put("path", "/tlsxh").put("mode", "auto"))
                            )
                    )
                    .put(
                        JSONObject()
                            .put("tag", "in-reality")
                            .put("listen", "127.0.0.1")
                            .put("port", portReality)
                            .put("protocol", "vmess")
                            .put("settings", JSONObject().put("clients", JSONArray().put(JSONObject().put("id", userUuid.toString()))))
                            .put(
                                "streamSettings",
                                JSONObject()
                                    .put("network", "xhttp")
                                    .put("security", "reality")
                                    .put(
                                        "realitySettings",
                                        JSONObject()
                                            .put("show", false)
                                            .put("dest", "127.0.0.1:$portTls")
                                            .put("serverNames", JSONArray().put("localhost"))
                                            .put("privateKey", realityPrivateKey)
                                            .put("shortIds", JSONArray().put(realityShortId))
                                    )
                                    .put("xhttpSettings", JSONObject().put("path", "/realityxh").put("mode", "auto"))
                            )
                    )
            )
            put(
                "outbounds",
                JSONArray().put(
                    JSONObject()
                        .put("protocol", "freedom")
                        .put("tag", "direct")
                        .put(
                            "settings",
                            JSONObject()
                                .put("redirect", "127.0.0.1:$originPort")
                                .put("finalRules", JSONArray().put(JSONObject().put("action", "allow")))
                        )
                )
            )
        }

        val tempConfig = File(tempDir, "xray-desktop-smoke.json")
        tempConfig.writeText(configJson.toString(2))
        val process = ProcessBuilder(bin.absolutePath, "run", "-c", tempConfig.absolutePath)
            .redirectErrorStream(true)
            .start()
        val xrayLog = StringBuffer()
        val logThread = thread(isDaemon = true) {
            runCatching {
                process.inputStream.bufferedReader().forEachLine { xrayLog.append(it).append('\n') }
            }
        }

        try {
            if (!waitForTcpPort(portPlain)) {
                fail("Xray failed to start on port $portPlain:\n$xrayLog")
            }

            val supportsNoneAndZero = bin.readBytes().let { bytes ->
                val pattern = byteArrayOf(0x04, 'N'.code.toByte(), 'O'.code.toByte(), 'N'.code.toByte(), 'E'.code.toByte(), 0x10, 0x05)
                bytes.indices.any { i ->
                    i + pattern.size <= bytes.size && pattern.indices.all { j -> bytes[i + j] == pattern[j] }
                }
            }

            // 1. Plain XHTTP across modes and ciphers
            val ciphers = buildList {
                add(VmessSecurity.AES_128_GCM)
                add(VmessSecurity.CHACHA20_POLY1305)
                add(VmessSecurity.AUTO)
                if (supportsNoneAndZero) {
                    add(VmessSecurity.NONE)
                    add(VmessSecurity.ZERO)
                }
            }
            for (mode in listOf(XHttpMode.PACKET_UP, XHttpMode.STREAM_UP, XHttpMode.STREAM_ONE, XHttpMode.AUTO)) {
                for (cipher in ciphers) {
                    val cfg = ProxyConfiguration(
                        name = "vmess-plain-$mode-${cipher.raw}",
                        serverAddress = "127.0.0.1",
                        serverPort = portPlain.toUShort(),
                        uuid = userUuid,
                        encryption = "none",
                        outboundProtocol = OutboundProtocol.VMESS,
                        transport = "xhttp",
                        security = "none",
                        vmessSecurity = cipher.raw,
                        xhttp = XHttpConfiguration(
                            host = "localhost",
                            path = "/xh",
                            mode = mode,
                            noGrpcHeader = mode == XHttpMode.STREAM_ONE
                        )
                    )
                    verifyEngineRoundTrip(cfg, "xray-plain-${mode.raw}-${cipher.raw}")
                }
            }

            // 2. Custom header/cookie placements
            val placementCfg = ProxyConfiguration(
                name = "vmess-placement",
                serverAddress = "127.0.0.1",
                serverPort = portPlacement.toUShort(),
                uuid = userUuid,
                encryption = "none",
                outboundProtocol = OutboundProtocol.VMESS,
                transport = "xhttp",
                security = "none",
                vmessSecurity = VmessSecurity.AES_128_GCM.raw,
                xhttp = XHttpConfiguration(
                    host = "localhost",
                    path = "/custom",
                    mode = XHttpMode.PACKET_UP,
                    sessionPlacement = XHttpPlacement.HEADER,
                    sessionKey = "X-My-Session",
                    seqPlacement = XHttpPlacement.COOKIE,
                    seqKey = "my_seq",
                    uplinkDataPlacement = XHttpPlacement.HEADER,
                    uplinkDataKey = "X-Up-Data",
                    uplinkChunkSize = 256,
                    noSseHeader = true
                )
            )
            verifyEngineRoundTrip(placementCfg, "xray-placement")

            // 3. TLS XHTTP (HTTP/2 and HTTP/1.1)
            for (alpn in listOf(listOf("h2"), listOf("http/1.1"))) {
                for (mode in listOf(XHttpMode.PACKET_UP, XHttpMode.STREAM_ONE, XHttpMode.AUTO)) {
                    val tlsCfg = ProxyConfiguration(
                        name = "vmess-tls-${alpn.first()}-${mode.raw}",
                        serverAddress = "127.0.0.1",
                        serverPort = portTls.toUShort(),
                        uuid = userUuid,
                        encryption = "none",
                        outboundProtocol = OutboundProtocol.VMESS,
                        transport = "xhttp",
                        security = "tls",
                        vmessSecurity = VmessSecurity.CHACHA20_POLY1305.raw,
                        tls = TlsConfiguration(
                            serverName = "localhost",
                            alpn = alpn,
                            allowInsecure = true
                        ),
                        xhttp = XHttpConfiguration(
                            host = "localhost",
                            path = "/tlsxh",
                            mode = mode
                        )
                    )
                    verifyEngineRoundTrip(tlsCfg, "xray-tls-${alpn.first()}-${mode.raw}")
                }
            }

            // 4. REALITY + XHTTP
            val realityCfg = ProxyConfiguration(
                name = "vmess-reality-xhttp",
                serverAddress = "127.0.0.1",
                serverPort = portReality.toUShort(),
                uuid = userUuid,
                encryption = "none",
                outboundProtocol = OutboundProtocol.VMESS,
                transport = "xhttp",
                security = "reality",
                vmessSecurity = VmessSecurity.AES_128_GCM.raw,
                reality = RealityConfiguration.parse(
                    mapOf(
                        "security" to "reality",
                        "sni" to "localhost",
                        "pbk" to realityPublicKey,
                        "sid" to realityShortId,
                        "fp" to "chrome_133"
                    )
                ),
                xhttp = XHttpConfiguration(
                    host = "localhost",
                    path = "/realityxh",
                    mode = XHttpMode.AUTO
                )
            )
            verifyEngineRoundTrip(realityCfg, "xray-reality-auto")
        } finally {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
            logThread.join(1000)
        }
    }

    @Test
    fun `Desktop ProxyEngine smoke test across Sing-box VLESS, VMess, Trojan HTTP2 and QUIC transports and Hysteria2`() {
        val labDir = System.getenv("MYTHAIA_LAB_DIR")?.takeIf { it.isNotBlank() }?.let(::File)
        val sbBin = System.getenv("MYTHAIA_SING_BOX")?.takeIf { it.isNotBlank() }?.let(::File)
            ?: labDir?.let { File(it, "sing-box.exe") }
        val crtFile = labDir?.let { File(it, "lab.crt") }
        val keyFile = labDir?.let { File(it, "lab.key") }
        assumeTrue(
            "MYTHAIA_LAB_DIR / MYTHAIA_SING_BOX not configured",
            sbBin != null && sbBin.isFile && crtFile != null && crtFile.isFile && keyFile != null && keyFile.isFile
        )

        val userUuid = UUID.fromString("5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13")
        val password = "lab-pass-123"
        val sni = "lab.mythaia.test"

        val portVlessH2 = freePort()
        val portVlessH1 = freePort()
        val portVmessH2 = freePort()
        val portTrojanH2 = freePort()
        val portVlessQuic = freePort()
        val portVmessQuic = freePort()
        val portTrojanQuic = freePort()
        val portHy2 = freePort()
        val portHy2Obfs = freePort()

        val sbTls = JSONObject()
            .put("enabled", true)
            .put("server_name", sni)
            .put("certificate_path", crtFile!!.absolutePath.replace("\\", "/"))
            .put("key_path", keyFile!!.absolutePath.replace("\\", "/"))

        val sbH2Transport = JSONObject()
            .put("type", "http")
            .put("host", JSONArray().put(sni))
            .put("path", "/h2")

        val inbounds = JSONArray()
            .put(
                JSONObject()
                    .put("type", "vless")
                    .put("tag", "vless-h2")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portVlessH2)
                    .put("users", JSONArray().put(JSONObject().put("uuid", userUuid.toString())))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject(sbH2Transport.toString()))
            )
            .put(
                JSONObject()
                    .put("type", "vless")
                    .put("tag", "vless-h1")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portVlessH1)
                    .put("users", JSONArray().put(JSONObject().put("uuid", userUuid.toString())))
                    .put("transport", JSONObject(sbH2Transport.toString()))
            )
            .put(
                JSONObject()
                    .put("type", "vmess")
                    .put("tag", "vmess-h2")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portVmessH2)
                    .put("users", JSONArray().put(JSONObject().put("uuid", userUuid.toString())))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject(sbH2Transport.toString()))
            )
            .put(
                JSONObject()
                    .put("type", "trojan")
                    .put("tag", "trojan-h2")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portTrojanH2)
                    .put("users", JSONArray().put(JSONObject().put("password", password)))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject(sbH2Transport.toString()))
            )
            .put(
                JSONObject()
                    .put("type", "vless")
                    .put("tag", "vless-quic")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portVlessQuic)
                    .put("users", JSONArray().put(JSONObject().put("uuid", userUuid.toString())))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject().put("type", "quic"))
            )
            .put(
                JSONObject()
                    .put("type", "vmess")
                    .put("tag", "vmess-quic")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portVmessQuic)
                    .put("users", JSONArray().put(JSONObject().put("uuid", userUuid.toString())))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject().put("type", "quic"))
            )
            .put(
                JSONObject()
                    .put("type", "trojan")
                    .put("tag", "trojan-quic")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portTrojanQuic)
                    .put("users", JSONArray().put(JSONObject().put("password", password)))
                    .put("tls", JSONObject(sbTls.toString()))
                    .put("transport", JSONObject().put("type", "quic"))
            )
            .put(
                JSONObject()
                    .put("type", "hysteria2")
                    .put("tag", "hy2")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portHy2)
                    .put("users", JSONArray().put(JSONObject().put("password", password)))
                    .put("tls", JSONObject(sbTls.toString()).put("alpn", JSONArray().put("h3")))
            )
            .put(
                JSONObject()
                    .put("type", "hysteria2")
                    .put("tag", "hy2-obfs")
                    .put("listen", "127.0.0.1")
                    .put("listen_port", portHy2Obfs)
                    .put("users", JSONArray().put(JSONObject().put("password", password)))
                    .put("obfs", JSONObject().put("type", "salamander").put("password", "salty"))
                    .put("tls", JSONObject(sbTls.toString()).put("alpn", JSONArray().put("h3")))
            )

        val sbConfig = JSONObject()
            .put("log", JSONObject().put("level", "warn"))
            .put("inbounds", inbounds)
            .put("outbounds", JSONArray().put(JSONObject().put("type", "direct").put("tag", "direct")))
            .put(
                "route",
                JSONObject().put(
                    "rules",
                    JSONArray().put(
                        JSONObject()
                            .put("port", JSONArray().put(originPort))
                            .put("action", "route-options")
                            .put("override_address", "127.0.0.1")
                    )
                )
            )

        val tempSbConfig = File(tempDir, "sb-desktop-smoke.json")
        tempSbConfig.writeText(sbConfig.toString(2))
        val process = ProcessBuilder(sbBin!!.absolutePath, "run", "-c", tempSbConfig.absolutePath)
            .redirectErrorStream(true)
            .start()
        val sbLog = StringBuffer()
        val logThread = thread(isDaemon = true) {
            runCatching {
                process.inputStream.bufferedReader().forEachLine { sbLog.append(it).append('\n') }
            }
        }

        try {
            if (!waitForTcpPort(portVlessH2)) {
                fail("sing-box failed to start on port $portVlessH2:\n$sbLog")
            }

            val tlsCfg = TlsConfiguration(serverName = sni, allowInsecure = true)
            val httpTransCfg = HttpTransportConfiguration(hosts = listOf(sni), path = "/h2")

            val cases = listOf(
                ProxyConfiguration(
                    name = "sb-vless-h2",
                    serverAddress = "127.0.0.1",
                    serverPort = portVlessH2.toUShort(),
                    uuid = userUuid,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VLESS,
                    transport = "http",
                    security = "tls",
                    tls = tlsCfg,
                    httpTransport = httpTransCfg
                ),
                ProxyConfiguration(
                    name = "sb-vless-h1-plain",
                    serverAddress = "127.0.0.1",
                    serverPort = portVlessH1.toUShort(),
                    uuid = userUuid,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VLESS,
                    transport = "http",
                    security = "none",
                    httpTransport = httpTransCfg
                ),
                ProxyConfiguration(
                    name = "sb-vmess-h2",
                    serverAddress = "127.0.0.1",
                    serverPort = portVmessH2.toUShort(),
                    uuid = userUuid,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VMESS,
                    transport = "http",
                    security = "tls",
                    tls = tlsCfg,
                    httpTransport = httpTransCfg
                ),
                ProxyConfiguration(
                    name = "sb-trojan-h2",
                    serverAddress = "127.0.0.1",
                    serverPort = portTrojanH2.toUShort(),
                    uuid = UUID(0, 0),
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.TROJAN,
                    trojanPassword = password,
                    transport = "http",
                    security = "tls",
                    tls = tlsCfg,
                    trojanTls = tlsCfg,
                    httpTransport = httpTransCfg
                ),
                ProxyConfiguration(
                    name = "sb-vless-quic",
                    serverAddress = "127.0.0.1",
                    serverPort = portVlessQuic.toUShort(),
                    uuid = userUuid,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VLESS,
                    transport = "quic",
                    security = "tls",
                    tls = tlsCfg
                ),
                ProxyConfiguration(
                    name = "sb-vmess-quic",
                    serverAddress = "127.0.0.1",
                    serverPort = portVmessQuic.toUShort(),
                    uuid = userUuid,
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.VMESS,
                    transport = "quic",
                    security = "tls",
                    tls = tlsCfg
                ),
                ProxyConfiguration(
                    name = "sb-trojan-quic",
                    serverAddress = "127.0.0.1",
                    serverPort = portTrojanQuic.toUShort(),
                    uuid = UUID(0, 0),
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.TROJAN,
                    trojanPassword = password,
                    transport = "quic",
                    security = "tls",
                    tls = tlsCfg,
                    trojanTls = tlsCfg
                ),
                ProxyConfiguration(
                    name = "sb-hy2",
                    serverAddress = "127.0.0.1",
                    serverPort = portHy2.toUShort(),
                    uuid = UUID(0, 0),
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.HYSTERIA2,
                    password = password,
                    tls = tlsCfg
                ),
                ProxyConfiguration(
                    name = "sb-hy2-salamander",
                    serverAddress = "127.0.0.1",
                    serverPort = portHy2Obfs.toUShort(),
                    uuid = UUID(0, 0),
                    encryption = "none",
                    outboundProtocol = OutboundProtocol.HYSTERIA2,
                    password = password,
                    obfuscation = "salamander",
                    obfuscationPassword = "salty",
                    tls = tlsCfg
                )
            )

            for (cfg in cases) {
                verifyEngineRoundTrip(cfg, cfg.name)
            }
        } catch (e: Throwable) {
            throw AssertionError("${e.message}\n--- sing-box log ---\n$sbLog", e)
        } finally {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
            logThread.join(1000)
        }
    }

    @Test
    fun `Desktop ProxyEngine smoke test for Sudoku and Nowhere over local loopback`() {
        assumeTrue("mythaia_native.dll not built", nativeLoaded)
        val sudokuPsk = "desktop-smoke-sudoku-key"
        val sudokuServer = ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"))
        val sudokuPort = sudokuServer.localPort

        thread(isDaemon = true, name = "sudoku-loopback-server") {
            while (!sudokuServer.isClosed) {
                val clientSock = runCatching { sudokuServer.accept() }.getOrNull() ?: break
                thread(isDaemon = true, name = "sudoku-loopback-worker") {
                    clientSock.use { sock ->
                        sock.soTimeout = 10_000
                        val input = sock.getInputStream()
                        val output = sock.getOutputStream()
                        val tables = SudokuTablePair(key = sudokuPsk, asciiMode = SudokuAsciiMode.PREFER_ENTROPY)
                        val pskBases = SudokuProtocol.pskBases(sudokuPsk)
                        val uplinkDecoder = SudokuPureDecoder(tables.uplink)
                        val downlinkRng = SudokuXorshift64Star(0x123456789ABCDEF0L)
                        val downlinkThreshold = downlinkRng.pickPaddingThreshold(0, 0)

                        var recvBase = pskBases.clientToServer
                        var sendBase = pskBases.serverToClient
                        var sendEpoch = 1L
                        var sendSeq = 1L

                        val wireBuffer = ByteArrayOutputStream()
                        val plainBuffer = ByteArrayOutputStream()

                        fun feed(obf: ByteArray, n: Int) {
                            val decoded = uplinkDecoder.decode(obf.copyOf(n), Int.MAX_VALUE)
                            if (decoded.isNotEmpty()) {
                                wireBuffer.write(decoded)
                                val bytes = wireBuffer.toByteArray()
                                var offset = 0
                                while (bytes.size - offset >= 2) {
                                    val bodyLen = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
                                    if (bytes.size - offset < 2 + bodyLen) break
                                    val body = bytes.copyOfRange(offset + 2, offset + 2 + bodyLen)
                                    val plain = SudokuProtocol.openRecord(SudokuAeadMethod.CHACHA20_POLY1305, recvBase, body)
                                    plainBuffer.write(plain)
                                    offset += 2 + bodyLen
                                }
                                if (offset > 0) {
                                    wireBuffer.reset()
                                    if (offset < bytes.size) wireBuffer.write(bytes, offset, bytes.size - offset)
                                }
                            }
                        }

                        fun readPlainExact(count: Int): ByteArray {
                            val buf = ByteArray(4096)
                            while (plainBuffer.size() < count) {
                                val n = input.read(buf)
                                if (n <= 0) throw IllegalStateException("EOF waiting for $count Sudoku plain bytes")
                                feed(buf, n)
                            }
                            val all = plainBuffer.toByteArray()
                            val out = all.copyOf(count)
                            plainBuffer.reset()
                            if (all.size > count) plainBuffer.write(all, count, all.size - count)
                            return out
                        }

                        fun sendPlain(plain: ByteArray) {
                            val frame = SudokuProtocol.sealRecord(SudokuAeadMethod.CHACHA20_POLY1305, sendBase, sendEpoch, sendSeq++, plain)
                            val obf = tables.downlink.encode(frame, downlinkRng, downlinkThreshold)
                            output.write(obf)
                            output.flush()
                        }

                        val x25519Cls = Class.forName("com.mythaia.vpn.X25519Crypto")
                        val x25519Inst = x25519Cls.getField("INSTANCE").get(null)
                        val genKp = x25519Cls.getMethod("generateKeyPair")
                        val keyAgree = x25519Cls.getMethod("keyAgreement", ByteArray::class.java, ByteArray::class.java)

                        // 1. KIP ClientHello (74 bytes)
                        val helloFrame = readPlainExact(74)
                        val payload = helloFrame.copyOfRange(6, 74)
                        val nonce = payload.copyOfRange(16, 32)
                        val clientPub = payload.copyOfRange(32, 64)
                        val serverKp = genKp.invoke(x25519Inst) as ByteArray
                        val serverPriv = serverKp.copyOf(32)
                        val serverPub = serverKp.copyOfRange(32, 64)
                        val serverHelloKip = byteArrayOf(0x6B, 0x69, 0x70, 0x02, 0x00, 0x34) + nonce + serverPub + byteArrayOf(0, 0, 0, 0)
                        sendPlain(serverHelloKip)

                        val shared = keyAgree.invoke(x25519Inst, serverPriv, clientPub) as ByteArray
                        val sessionBases = SudokuProtocol.sessionBases(sudokuPsk, shared, nonce)
                        recvBase = sessionBases.clientToServer
                        sendBase = sessionBases.serverToClient
                        sendEpoch = 1L
                        sendSeq = 1L

                        // 2. KIP_OPEN_TCP: "kip" (3B) + type 0x10 (1B) + len (2B) + addrPayload(len)
                        val openHdr = readPlainExact(6)
                        val addrLen = ((openHdr[4].toInt() and 0xFF) shl 8) or (openHdr[5].toInt() and 0xFF)
                        readPlainExact(addrLen) // consume destination address

                        // 3. Read HTTP request until \r\n\r\n, forward to originServer, return response
                        val reqBuf = ByteArrayOutputStream()
                        val tmp = ByteArray(4096)
                        while (true) {
                            val available = plainBuffer.toByteArray()
                            if (available.isNotEmpty()) {
                                plainBuffer.reset()
                                reqBuf.write(available)
                                val cur = reqBuf.toByteArray()
                                if (cur.size >= 4 &&
                                    cur[cur.size - 4] == 13.toByte() &&
                                    cur[cur.size - 3] == 10.toByte() &&
                                    cur[cur.size - 2] == 13.toByte() &&
                                    cur[cur.size - 1] == 10.toByte()
                                ) break
                            }
                            val n = input.read(tmp)
                            if (n <= 0) break
                            feed(tmp, n)
                        }
                        Socket("127.0.0.1", originPort).use { orig ->
                            orig.soTimeout = 5_000
                            orig.getOutputStream().write(reqBuf.toByteArray())
                            orig.getOutputStream().flush()
                            val respBytes = orig.getInputStream().readBytes()
                            sendPlain(respBytes)
                        }
                    }
                }
            }
        }

        val leafCerts = MitmLeafCertificates(MitmCertificateAuthority.generate())
        val nowhereServer = ServerSocket(0, 32, InetAddress.getByName("127.0.0.1"))
        val nowherePort = nowhereServer.localPort

        thread(isDaemon = true, name = "nowhere-loopback-server") {
            while (!nowhereServer.isClosed) {
                val clientSock = runCatching { nowhereServer.accept() }.getOrNull() ?: break
                thread(isDaemon = true, name = "nowhere-loopback-worker") {
                    clientSock.use { sock ->
                        sock.soTimeout = 10_000
                        val sockTransport = object : Transport {
                            override suspend fun send(data: ByteArray) {
                                sock.getOutputStream().write(data)
                                sock.getOutputStream().flush()
                            }
                            override fun sendAsync(data: ByteArray) {
                                sock.getOutputStream().write(data)
                                sock.getOutputStream().flush()
                            }
                            override suspend fun receive(): ByteArray? {
                                val buf = ByteArray(16384)
                                val n = sock.getInputStream().read(buf)
                                return if (n <= 0) null else buf.copyOf(n)
                            }
                            override fun forceCancel() {
                                runCatching { sock.close() }
                            }
                        }
                        runBlocking {
                            val tlsServer = TlsServer(
                                transport = sockTransport,
                                leafCertificates = leafCerts,
                                supportedAlpns = listOf("h3")
                            )
                            val record = tlsServer.handshake(ByteArray(0))
                            val buf = ByteArrayOutputStream()
                            while (true) {
                                val chunk = record.receive() ?: break
                                buf.write(chunk)
                                val bytes = buf.toByteArray()
                                // 32B auth + 1B flags + 4B flowId + 1B atyp(0x03) + 1B hostLen + host + 2B port + HTTP request ending in \r\n\r\n
                                if (bytes.size > 42 &&
                                    bytes[bytes.size - 4] == 13.toByte() &&
                                    bytes[bytes.size - 3] == 10.toByte() &&
                                    bytes[bytes.size - 2] == 13.toByte() &&
                                    bytes[bytes.size - 1] == 10.toByte()
                                ) break
                            }
                            val all = buf.toByteArray()
                            val hostLen = all[38].toInt() and 0xFF
                            val httpStart = 32 + 1 + 4 + 1 + 1 + hostLen + 2
                            val httpRequest = all.copyOfRange(httpStart, all.size)

                            Socket("127.0.0.1", originPort).use { orig ->
                                orig.soTimeout = 5_000
                                orig.getOutputStream().write(httpRequest)
                                orig.getOutputStream().flush()
                                val respBytes = orig.getInputStream().readBytes()
                                // Send READY (0x00) + HTTP response
                                record.send(byteArrayOf(0x00) + respBytes)
                            }
                        }
                    }
                }
            }
        }

        try {
            val sudokuCfg = ProxyConfiguration(
                name = "loopback-sudoku",
                serverAddress = "127.0.0.1",
                serverPort = sudokuPort.toUShort(),
                uuid = UUID(0, 0),
                encryption = "none",
                outboundProtocol = OutboundProtocol.SUDOKU,
                sudokuKey = sudokuPsk,
                sudokuAeadMethod = SudokuAeadMethod.CHACHA20_POLY1305.id,
                sudokuAsciiMode = SudokuAsciiMode.PREFER_ENTROPY.id,
                sudokuEnablePureDownlink = true,
                sudokuMultiplex = "off",
                sudokuHttpMaskDisable = true
            )
            verifyEngineRoundTrip(sudokuCfg, "loopback-sudoku")

            val nowhereCfg = ProxyConfiguration(
                name = "loopback-nowhere",
                serverAddress = "127.0.0.1",
                serverPort = nowherePort.toUShort(),
                uuid = UUID(0, 0),
                encryption = "none",
                outboundProtocol = OutboundProtocol.NOWHERE,
                password = "nowhere-desktop-secret",
                nowhereUplink = "tcp",
                nowhereDownlink = "tcp",
                nowhereMultiplex = false,
                tls = TlsConfiguration(
                    serverName = "portal.example.com",
                    alpn = listOf("h3"),
                    allowInsecure = true
                )
            )
            verifyEngineRoundTrip(nowhereCfg, "loopback-nowhere")
        } finally {
            runCatching { sudokuServer.close() }
            runCatching { nowhereServer.close() }
        }
    }
}
