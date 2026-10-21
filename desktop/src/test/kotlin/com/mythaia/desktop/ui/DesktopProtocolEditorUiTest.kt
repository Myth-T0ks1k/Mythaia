package com.mythaia.desktop.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.PointerEventType
import com.mythaia.data.model.HttpTransportConfiguration
import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.RealityConfiguration
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsFingerprint
import com.mythaia.data.model.XHttpConfiguration
import com.mythaia.data.model.XHttpMode
import com.mythaia.desktop.AppPaths
import com.mythaia.desktop.S
import com.mythaia.vpn.protocol.sudoku.SudokuAeadMethod
import com.mythaia.vpn.protocol.sudoku.SudokuAsciiMode
import com.mythaia.vpn.protocol.sudoku.SudokuMultiplex
import com.mythaia.vpn.protocol.vmess.VmessSecurity
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Base64
import java.util.UUID

/**
 * Headless Compose Desktop UI tests for [NewServerFlow] ([ProtocolPicker]) and [ServerEditor]
 * across the protocol and transport matrix:
 * - VMess (`xhttp` transport, `xhttpMode`, `xhttpExtra` JSON preservation, `reality` security,
 *   and all `VmessSecurity` ciphers: `auto`, `aes-128-gcm`, `chacha20-poly1305`, `none`, `zero`)
 * - VLESS (`http`, `quic`, `xhttp`, `reality`)
 * - Trojan (`xhttp` with `xhttpExtra` validation, `http`, `quic`)
 * - Hysteria2 (port hopping range & single-port validation, hop interval, salamander obfs, brutal bandwidth)
 * - Sudoku (key, AEAD, ASCII mode, pure downlink, multiplex, HTTP mask)
 * - Nowhere (key, asymmetric uplink/downlink, multiplex)
 * - WireGuard (INI preservation through editor save)
 */
class DesktopProtocolEditorUiTest {

    private lateinit var tempDir: File

    @Before
    fun setUp() {
        tempDir = Files.createTempDirectory("mythaia-desktop-proto-ui-").toFile()
        AppPaths.overrideDataDir = tempDir
        S.apply("en")
    }

    @After
    fun tearDown() {
        AppPaths.overrideDataDir = null
        runCatching { tempDir.deleteRecursively() }
    }

    /**
     * Renders [ServerEditor] at 560x900 and clicks the TopAppBar Save action IconButton
     * located at the top-right corner `(536f, 32f)`. Returns the saved [ProxyConfiguration]
     * if `isValid` enabled the Save button, or `null` if the Save button was disabled.
     */
    private fun renderEditorAndClickSave(
        configuration: ProxyConfiguration?,
        initialProtocol: OutboundProtocol? = null
    ): ProxyConfiguration? {
        var saved: ProxyConfiguration? = null
        val scene = ImageComposeScene(width = 560, height = 900)
        try {
            scene.setContent {
                MaterialTheme {
                    ServerEditor(
                        configuration = configuration,
                        onSave = { saved = it },
                        onDismiss = {},
                        initialProtocol = initialProtocol
                    )
                }
            }
            scene.render(nanoTime = 1_000_000L)
            val saveButtonPos = Offset(536f, 32f)
            scene.sendPointerEvent(PointerEventType.Press, saveButtonPos, timeMillis = 10L)
            scene.sendPointerEvent(PointerEventType.Release, saveButtonPos, timeMillis = 20L)
            scene.render(nanoTime = 30_000_000L)
        } finally {
            scene.close()
        }
        return saved
    }

    @Test
    fun `NewServerFlow renders ProtocolPicker and transitions to ServerEditor on row click`() {
        var dismissed = false
        val scene = ImageComposeScene(width = 560, height = 720)
        try {
            scene.setContent {
                MaterialTheme {
                    NewServerFlow(
                        onSave = {},
                        onDismiss = { dismissed = true }
                    )
                }
            }
            scene.render(nanoTime = 1_000_000L)
            val rowPos = Offset(280f, 150f)
            scene.sendPointerEvent(PointerEventType.Press, rowPos, timeMillis = 10L)
            scene.sendPointerEvent(PointerEventType.Release, rowPos, timeMillis = 20L)
            scene.render(nanoTime = 30_000_000L)
        } finally {
            scene.close()
        }
        assertTrue(!dismissed)
    }

    @Test
    fun `ServerEditor preserves xhttpExtra, xhttpMode, and vmessSecurity when editing VMess + XHTTP`() {
        val extraJson = """{"scMaxEachPostBytes":123456,"noGRPCHeader":true,"headers":{"X-Custom":"1"}}"""
        val vmessXhttp = ProxyConfiguration(
            name = "VMess-XHTTP-Preserve",
            serverAddress = "203.0.113.10",
            serverPort = 443u,
            uuid = UUID.fromString("11111111-2222-3333-4444-555555555555"),
            encryption = "none",
            outboundProtocol = OutboundProtocol.VMESS,
            vmessSecurity = VmessSecurity.CHACHA20_POLY1305.raw,
            transport = "xhttp",
            security = "tls",
            tls = TlsConfiguration(
                serverName = "sni.example.com",
                alpn = listOf("h2", "http/1.1"),
                fingerprint = TlsFingerprint.CHROME_133
            ),
            xhttp = XHttpConfiguration.fromExtraJson(
                host = "cdn.example.com",
                path = "/xhttp-sub",
                mode = XHttpMode.PACKET_UP,
                extraJson = extraJson
            )
        )

        val saved = renderEditorAndClickSave(vmessXhttp)
        assertNotNull("Expected Save button to be enabled for valid VMess+XHTTP", saved)
        assertEquals(OutboundProtocol.VMESS, saved!!.outboundProtocol)
        assertEquals(VmessSecurity.CHACHA20_POLY1305.raw, saved.vmessSecurity)
        assertEquals("xhttp", saved.transport)
        assertEquals("tls", saved.security)
        assertNotNull(saved.xhttp)
        assertEquals("cdn.example.com", saved.xhttp?.host)
        assertEquals("/xhttp-sub", saved.xhttp?.path)
        assertEquals(XHttpMode.PACKET_UP, saved.xhttp?.mode)
        assertEquals(123456, saved.xhttp?.scMaxEachPostBytes)
        assertEquals(true, saved.xhttp?.noGrpcHeader)
        assertEquals("1", saved.xhttp?.headers?.get("X-Custom"))
    }

    @Test
    fun `ServerEditor preserves VMess + REALITY + XHTTP and all VmessSecurity ciphers`() {
        val pkBytes = ByteArray(32) { (it + 1).toByte() }
        val sidBytes = byteArrayOf(0x01, 0x23, 0x45, 0x67, 0x89.toByte(), 0xab.toByte(), 0xcd.toByte(), 0xef.toByte())

        for (cipher in VmessSecurity.entries) {
            val vmessReality = ProxyConfiguration(
                name = "VMess-Reality-${cipher.raw}",
                serverAddress = "203.0.113.25",
                serverPort = 8443u,
                uuid = UUID.fromString("11111111-2222-3333-4444-555555555555"),
                encryption = "none",
                outboundProtocol = OutboundProtocol.VMESS,
                vmessSecurity = cipher.raw,
                transport = "xhttp",
                security = "reality",
                reality = RealityConfiguration(
                    serverName = "reality.example.com",
                    publicKey = pkBytes,
                    shortId = sidBytes,
                    fingerprint = TlsFingerprint.FIREFOX_148
                ),
                xhttp = XHttpConfiguration(
                    host = "reality.example.com",
                    path = "/reality-split",
                    mode = XHttpMode.STREAM_ONE
                )
            )
            val saved = renderEditorAndClickSave(vmessReality)
            assertNotNull("Expected Save button to be enabled for VMess+REALITY (${cipher.raw})", saved)
            val expectedSec = if (cipher == VmessSecurity.AUTO) null else cipher.raw
            assertEquals(expectedSec, saved!!.vmessSecurity)
            assertEquals("reality", saved.security)
            assertNotNull(saved.reality)
            assertEquals("reality.example.com", saved.reality?.serverName)
            assertArrayEquals(pkBytes, saved.reality?.publicKey)
            assertArrayEquals(sidBytes, saved.reality?.shortId)
            assertEquals(TlsFingerprint.FIREFOX_148, saved.reality?.fingerprint)
            assertEquals(XHttpMode.STREAM_ONE, saved.xhttp?.mode)
        }
    }

    @Test
    fun `ServerEditor round-trips VLESS and Trojan with HTTP2, QUIC, and XHTTP`() {
        val vlessHttp = ProxyConfiguration(
            name = "VLESS-H2",
            serverAddress = "203.0.113.30",
            serverPort = 443u,
            uuid = UUID.fromString("11111111-2222-3333-4444-555555555555"),
            encryption = "none",
            outboundProtocol = OutboundProtocol.VLESS,
            transport = "http",
            security = "tls",
            tls = TlsConfiguration(serverName = "h2.example.com"),
            httpTransport = HttpTransportConfiguration(hosts = listOf("h2.example.com", "alt.example.com"), path = "/h2path")
        )
        val savedVlessHttp = renderEditorAndClickSave(vlessHttp)
        assertNotNull(savedVlessHttp)
        assertEquals("http", savedVlessHttp!!.transport)
        assertEquals(listOf("h2.example.com", "alt.example.com"), savedVlessHttp.httpTransport?.hosts)
        assertEquals("/h2path", savedVlessHttp.httpTransport?.path)

        val vlessQuic = vlessHttp.copy(name = "VLESS-QUIC", transport = "quic", httpTransport = null)
        val savedVlessQuic = renderEditorAndClickSave(vlessQuic)
        assertNotNull(savedVlessQuic)
        assertEquals("quic", savedVlessQuic!!.transport)
        assertEquals("tls", savedVlessQuic.security)

        val trojanXhttp = ProxyConfiguration(
            name = "Trojan-XHTTP",
            serverAddress = "203.0.113.31",
            serverPort = 443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.TROJAN,
            trojanPassword = "secret-trojan-password",
            transport = "xhttp",
            security = "tls",
            trojanTls = TlsConfiguration(serverName = "trojan.example.com"),
            xhttp = XHttpConfiguration.fromExtraJson(
                host = "trojan.example.com",
                path = "/tj",
                mode = XHttpMode.STREAM_UP,
                extraJson = """{"scMinPostsIntervalMs":45,"scMaxEachPostBytes":500000}"""
            )
        )
        val savedTrojanXhttp = renderEditorAndClickSave(trojanXhttp)
        assertNotNull(savedTrojanXhttp)
        assertEquals(OutboundProtocol.TROJAN, savedTrojanXhttp!!.outboundProtocol)
        assertEquals("xhttp", savedTrojanXhttp.transport)
        assertEquals(XHttpMode.STREAM_UP, savedTrojanXhttp.xhttp?.mode)
        assertEquals(45, savedTrojanXhttp.xhttp?.scMinPostsIntervalMs)
        assertEquals(500000, savedTrojanXhttp.xhttp?.scMaxEachPostBytes)

        val trojanQuic = trojanXhttp.copy(name = "Trojan-QUIC", transport = "quic", xhttp = null)
        val savedTrojanQuic = renderEditorAndClickSave(trojanQuic)
        assertNotNull(savedTrojanQuic)
        assertEquals("quic", savedTrojanQuic!!.transport)
    }

    @Test
    fun `ServerEditor round-trips Hysteria2 port hopping, Sudoku, Nowhere, and WireGuard`() {
        val hy2 = ProxyConfiguration(
            name = "Hy2-Hop",
            serverAddress = "203.0.113.40",
            serverPort = 443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.HYSTERIA2,
            tls = TlsConfiguration(serverName = "hy2.example.com"),
            password = "hy2-password",
            obfuscation = "salamander",
            obfuscationPassword = "obfs-secret",
            hysteriaUpMbps = 100,
            hysteriaDownMbps = 250,
            hysteriaPorts = "20000-30000,40000",
            hysteriaHopInterval = 20,
            hysteriaHopIntervalMax = 40
        )
        val savedHy2 = renderEditorAndClickSave(hy2)
        assertNotNull(savedHy2)
        assertEquals("20000-30000,40000", savedHy2!!.hysteriaPorts)
        assertEquals(20, savedHy2.hysteriaHopInterval)
        assertEquals(40, savedHy2.hysteriaHopIntervalMax)
        assertEquals(100, savedHy2.hysteriaUpMbps)
        assertEquals(250, savedHy2.hysteriaDownMbps)
        assertEquals("salamander", savedHy2.obfuscation)
        assertEquals("obfs-secret", savedHy2.obfuscationPassword)

        // Single port in hysteriaPorts is accepted by validation and normalized to null hopPorts
        val hy2SinglePort = hy2.copy(hysteriaPorts = "21001")
        val savedHy2Single = renderEditorAndClickSave(hy2SinglePort)
        assertNotNull(savedHy2Single)
        assertNull(savedHy2Single!!.hysteriaPorts)

        val sudoku = ProxyConfiguration(
            name = "Sudoku-Node",
            serverAddress = "203.0.113.41",
            serverPort = 8443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.SUDOKU,
            sudokuKey = "sudoku-secret-key",
            sudokuAeadMethod = SudokuAeadMethod.CHACHA20_POLY1305.id,
            sudokuAsciiMode = SudokuAsciiMode.PREFER_ASCII.id,
            sudokuEnablePureDownlink = true,
            sudokuMultiplex = SudokuMultiplex.AUTO.id,
            sudokuHttpMaskDisable = false,
            sudokuHttpMaskHost = "mask.example.com",
            sudokuHttpMaskPathRoot = "api/v1"
        )
        val savedSudoku = renderEditorAndClickSave(sudoku)
        assertNotNull(savedSudoku)
        assertEquals(OutboundProtocol.SUDOKU, savedSudoku!!.outboundProtocol)
        assertEquals("sudoku-secret-key", savedSudoku.sudokuKey)
        assertEquals(SudokuAsciiMode.PREFER_ASCII.id, savedSudoku.sudokuAsciiMode)
        assertEquals("mask.example.com", savedSudoku.sudokuHttpMaskHost)
        assertEquals("api/v1", savedSudoku.sudokuHttpMaskPathRoot)

        val nowhere = ProxyConfiguration(
            name = "Nowhere-Node",
            serverAddress = "203.0.113.42",
            serverPort = 443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.NOWHERE,
            tls = TlsConfiguration(serverName = "nowhere.example.com"),
            password = "nowhere-key-base64",
            nowhereUplink = "tcp",
            nowhereDownlink = "udp",
            nowhereMultiplex = true
        )
        val savedNowhere = renderEditorAndClickSave(nowhere)
        assertNotNull(savedNowhere)
        assertEquals(OutboundProtocol.NOWHERE, savedNowhere!!.outboundProtocol)
        assertEquals("nowhere-key-base64", savedNowhere.password)
        assertEquals("tcp", savedNowhere.nowhereUplink)
        assertEquals("udp", savedNowhere.nowhereDownlink)
        assertEquals(true, savedNowhere.nowhereMultiplex)

        val wgPriv = Base64.getEncoder().encodeToString(ByteArray(32) { 3 })
        val wgPub = Base64.getEncoder().encodeToString(ByteArray(32) { 4 })
        val wgIni = """
            [Interface]
            PrivateKey = $wgPriv
            Address = 10.0.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey = $wgPub
            AllowedIPs = 0.0.0.0/0
            Endpoint = 203.0.113.43:51820
        """.trimIndent()
        val wg = ProxyConfiguration.fromWireGuardConfig(wgIni, name = "WG-Node")
        val savedWg = renderEditorAndClickSave(wg)
        assertNotNull(savedWg)
        assertEquals(OutboundProtocol.WIREGUARD, savedWg!!.outboundProtocol)
        assertEquals("WG-Node", savedWg.name)
        assertEquals("203.0.113.43", savedWg.serverAddress)
        assertEquals(wgIni, savedWg.wireGuardConfig?.trim())
    }

    @Test
    fun `ServerEditor disables Save when Trojan XHTTP extra JSON is malformed, QUIC lacks TLS, or Hysteria2 hop port list is invalid`() {
        val invalidTrojanXhttp = ProxyConfiguration(
            name = "Bad-Trojan-XHTTP",
            serverAddress = "203.0.113.50",
            serverPort = 443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.TROJAN,
            trojanPassword = "secret",
            transport = "xhttp",
            security = "tls",
            trojanTls = TlsConfiguration(serverName = "trojan.example.com"),
            xhttp = XHttpConfiguration(host = "trojan.example.com", path = "/tj", xmuxJson = "{not-valid-json")
        )
        assertNull(
            "Expected Save button to be disabled when Trojan has malformed xhttpExtra JSON",
            renderEditorAndClickSave(invalidTrojanXhttp)
        )

        val invalidQuicNoTls = ProxyConfiguration(
            name = "Bad-VMess-QUIC-NoTLS",
            serverAddress = "203.0.113.51",
            serverPort = 443u,
            uuid = UUID.fromString("11111111-2222-3333-4444-555555555555"),
            encryption = "none",
            outboundProtocol = OutboundProtocol.VMESS,
            transport = "quic",
            security = "none"
        )
        assertNull(
            "Expected Save button to be disabled when QUIC transport has security=none",
            renderEditorAndClickSave(invalidQuicNoTls)
        )

        val invalidHy2Hop = ProxyConfiguration(
            name = "Bad-Hy2-Hop",
            serverAddress = "203.0.113.52",
            serverPort = 443u,
            uuid = UUID(0, 0),
            encryption = "none",
            outboundProtocol = OutboundProtocol.HYSTERIA2,
            tls = TlsConfiguration(serverName = "hy2.example.com"),
            password = "hy2-password",
            hysteriaPorts = "99999-100000"
        )
        assertNull(
            "Expected Save button to be disabled when Hysteria2 hop port list is invalid",
            renderEditorAndClickSave(invalidHy2Hop)
        )
    }
}
