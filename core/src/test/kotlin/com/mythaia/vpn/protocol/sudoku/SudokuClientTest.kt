package com.mythaia.vpn.protocol.sudoku

import com.mythaia.data.model.OutboundProtocol
import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.data.model.ProxyError
import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion
import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.mitm.MitmCertificateAuthority
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.tls.TlsServer
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-end wire-format tests for [SudokuClient] across its carriers and
 * multiplexer:
 * - TLS carrier (`httpMask.tls = true`) over TLS 1.3 with ALPN `http/1.1`
 * - WebSocket camouflage (`httpMask.mode = ws`) upgrade headers, HMAC auth token,
 *   and masked binary WebSocket frames
 * - Split HTTP-mask tunnel (`stream`, `poll`, and `auto` fallback) with early KIP
 *   exchange on `GET <root>/session?ed=<base64url>&auth=<token>`, `/stream` pull,
 *   `/api/v1/upload?token=...&seq=...` push, and `&close=1` teardown
 * - Native multiplexer (`mux = on`) and [SudokuMuxPool] session sharing
 *   (`KIP_OPEN_MUX = 0x11`, `MUX_OPEN = 0x01`, `MUX_DATA = 0x02`, `MUX_CLOSE = 0x03`,
 *   `MUX_RESET = 0x04`, and `0x05` ping -> `0x06` pong control frames).
 */
class SudokuClientTest {

    @After
    fun tearDown() {
        SudokuClient.clearAllPools()
    }

    private val leafCertificates by lazy {
        MitmLeafCertificates(MitmCertificateAuthority.generate())
    }

    private fun ascii(text: String): ByteArray = text.toByteArray(Charsets.US_ASCII)

    private class InMemoryTransportPair {
        private val clientToServer = Channel<ByteArray>(Channel.UNLIMITED)
        private val serverToClient = Channel<ByteArray>(Channel.UNLIMITED)

        val clientSide: Transport = object : Transport {
            override suspend fun send(data: ByteArray) {
                if (data.isNotEmpty()) clientToServer.trySend(data.copyOf())
            }

            override fun sendAsync(data: ByteArray) {
                if (data.isNotEmpty()) clientToServer.trySend(data.copyOf())
            }

            override suspend fun receive(): ByteArray? = serverToClient.receiveCatching().getOrNull()

            override fun forceCancel() {
                clientToServer.close()
                serverToClient.close()
            }
        }

        val serverSide: Transport = object : Transport {
            override suspend fun send(data: ByteArray) {
                if (data.isNotEmpty()) serverToClient.trySend(data.copyOf())
            }

            override fun sendAsync(data: ByteArray) {
                if (data.isNotEmpty()) serverToClient.trySend(data.copyOf())
            }

            override suspend fun receive(): ByteArray? = clientToServer.receiveCatching().getOrNull()

            override fun forceCancel() {
                clientToServer.close()
                serverToClient.close()
            }
        }
    }

    /**
     * Server-side Sudoku peer helper that decodes the client's obfuscated uplink
     * using the shared [SudokuTablePair] and encodes the server's obfuscated downlink.
     */
    private class ServerSudokuPeer(
        val psk: String,
        val aeadMethod: SudokuAeadMethod = SudokuAeadMethod.CHACHA20_POLY1305,
        val asciiMode: SudokuAsciiMode = SudokuAsciiMode.PREFER_ENTROPY,
        val pureDownlink: Boolean = true
    ) {
        val tables = SudokuTablePair(key = psk, asciiMode = asciiMode)
        val pskBases = SudokuProtocol.pskBases(psk)
        private val uplinkDecoder = SudokuPureDecoder(tables.uplink)
        private val downlinkRng = SudokuXorshift64Star(0x123456789ABCDEF0L)
        private val downlinkThreshold = downlinkRng.pickPaddingThreshold(0, 0)

        var recvBase: ByteArray = pskBases.clientToServer
        var sendBase: ByteArray = pskBases.serverToClient
        var sendEpoch: Long = 1L
        var sendSeq: Long = 1L

        private val wireBuffer = ByteArrayOutputStream()
        private val plainBuffer = ByteArrayOutputStream()

        fun feedObfuscatedFromClient(obfuscated: ByteArray) {
            val decoded = uplinkDecoder.decode(obfuscated, Int.MAX_VALUE)
            if (decoded.isNotEmpty()) {
                if (aeadMethod == SudokuAeadMethod.NONE) {
                    plainBuffer.write(decoded)
                } else {
                    wireBuffer.write(decoded)
                    drainRecords()
                }
            }
        }

        private fun drainRecords() {
            val bytes = wireBuffer.toByteArray()
            var offset = 0
            while (bytes.size - offset >= 2) {
                val bodyLen = ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)
                if (bytes.size - offset < 2 + bodyLen) break
                val body = bytes.copyOfRange(offset + 2, offset + 2 + bodyLen)
                val plain = SudokuProtocol.openRecord(aeadMethod, recvBase, body)
                plainBuffer.write(plain)
                offset += 2 + bodyLen
            }
            if (offset > 0) {
                wireBuffer.reset()
                if (offset < bytes.size) {
                    wireBuffer.write(bytes, offset, bytes.size - offset)
                }
            }
        }

        fun takePlainBytes(count: Int): ByteArray? {
            val bytes = plainBuffer.toByteArray()
            if (bytes.size < count) return null
            val out = bytes.copyOf(count)
            plainBuffer.reset()
            if (count < bytes.size) {
                plainBuffer.write(bytes, count, bytes.size - count)
            }
            return out
        }

        fun takeAllPlainBytes(): ByteArray {
            val bytes = plainBuffer.toByteArray()
            plainBuffer.reset()
            return bytes
        }

        fun encodeServerPlaintextToObfuscated(plain: ByteArray): ByteArray {
            val wire = if (aeadMethod == SudokuAeadMethod.NONE) {
                plain
            } else {
                val frame = SudokuProtocol.sealRecord(aeadMethod, sendBase, sendEpoch, sendSeq, plain)
                sendSeq += 1
                frame
            }
            return tables.downlink.encode(wire, downlinkRng, downlinkThreshold)
        }

        /**
         * Reads the 74-byte KIP client hello (`"kip" || 0x01 || 0x0044 || payload(68)`),
         * verifies the key fingerprint, builds the 58-byte KIP server hello
         * (`"kip" || 0x02 || 0x0034 || nonce(16) || serverPub(32) || flags(4)`),
         * encodes it under PSK, and switches [recvBase]/[sendBase] to the derived
         * session keys.
         */
        fun completeKipServerHello(clientHelloFrame: ByteArray): ByteArray {
            // KIP header: 'k' 'i' 'p' (3B) + type 0x01 (1B) + length 68 = 0x0044 (2B)
            assertEquals(0x6B.toByte(), clientHelloFrame[0])
            assertEquals(0x69.toByte(), clientHelloFrame[1])
            assertEquals(0x70.toByte(), clientHelloFrame[2])
            assertEquals(0x01.toByte(), clientHelloFrame[3])
            assertEquals(0x00.toByte(), clientHelloFrame[4])
            assertEquals(0x44.toByte(), clientHelloFrame[5])

            val payload = clientHelloFrame.copyOfRange(6, 74)
            val expectedFp = MessageDigest.getInstance("SHA-256")
                .digest(psk.toByteArray(Charsets.UTF_8))
                .copyOfRange(0, 8)
            assertArrayEquals(expectedFp, payload.copyOfRange(8, 16))

            val nonce = payload.copyOfRange(16, 32)
            val clientPub = payload.copyOfRange(32, 64)
            // Feature flags = 0x0000001F
            assertArrayEquals(byteArrayOf(0x00, 0x00, 0x00, 0x1F), payload.copyOfRange(64, 68))

            val serverKp = X25519Crypto.generateKeyPair()
            val serverPriv = serverKp.copyOf(32)
            val serverPub = serverKp.copyOfRange(32, 64)

            val serverHelloPayload = nonce + serverPub + byteArrayOf(0, 0, 0, 0)
            val serverHelloKip = byteArrayOf(0x6B, 0x69, 0x70, 0x02, 0x00, 0x34) + serverHelloPayload
            val obfuscatedReply = encodeServerPlaintextToObfuscated(serverHelloKip)

            val shared = X25519Crypto.keyAgreement(serverPriv, clientPub)
            val sessionBases = SudokuProtocol.sessionBases(psk, shared, nonce)
            recvBase = sessionBases.clientToServer
            sendBase = sessionBases.serverToClient
            sendEpoch = 1L
            sendSeq = 1L
            return obfuscatedReply
        }
    }

    private fun verifyIndependentHttpMaskAuthToken(
        key: String,
        mode: String,
        method: String,
        path: String,
        token: String
    ) {
        val raw = Base64.getUrlDecoder().decode(token)
        assertEquals(24, raw.size)
        val tsBytes = raw.copyOf(8)
        val sig = raw.copyOfRange(8, 24)

        val authKey = MessageDigest.getInstance("SHA-256")
            .digest("sudoku-httpmask-auth-v1:$key".toByteArray(Charsets.UTF_8))
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(authKey, "HmacSHA256"))
        mac.update(mode.toByteArray(Charsets.UTF_8))
        mac.update(0.toByte())
        mac.update(method.toByteArray(Charsets.UTF_8))
        mac.update(0.toByte())
        mac.update(path.toByteArray(Charsets.UTF_8))
        mac.update(0.toByte())
        mac.update(tsBytes)
        val expectedSig = mac.doFinal().copyOf(16)
        assertArrayEquals(expectedSig, sig)
    }

    // MARK: - 1. TLS Carrier

    @Test
    fun `TLS carrier performs TLS 1_3 handshake with http1_1 ALPN and carries obfuscated KIP and TCP flow`() = runBlocking {
        withTimeout(15_000L) {
            val pair = InMemoryTransportPair()
            val psk = "tls-carrier-secret"
            val sudoku = SudokuConfiguration(
                key = psk,
                httpMask = SudokuHttpMaskConfiguration(
                    disable = false,
                    mode = SudokuHttpMaskMode.LEGACY,
                    tls = true,
                    host = "cdn.example.com",
                    pathRoot = "edge"
                )
            )
            val config = ProxyConfiguration(
                name = "sudoku-tls",
                serverAddress = "198.51.100.20",
                serverPort = 443u,
                uuid = UUID.randomUUID(),
                encryption = "none",
                outboundProtocol = OutboundProtocol.SUDOKU,
                sudokuKey = psk,
                sudokuHttpMaskTls = true,
                sudokuHttpMaskHost = "cdn.example.com",
                sudokuHttpMaskPathRoot = "edge",
                tls = TlsConfiguration(
                    serverName = "cdn.example.com",
                    allowInsecure = true
                )
            )

            val serverJob = async {
                val tlsServer = TlsServer(
                    transport = pair.serverSide,
                    leafCertificates = leafCertificates,
                    supportedAlpns = listOf("http/1.1")
                )
                val tlsConn = tlsServer.handshake(ByteArray(0))
                assertEquals("http/1.1", tlsConn.negotiatedAlpn)

                val peer = ServerSudokuPeer(psk = psk)

                // First plaintext inside TLS is the legacy HTTP decoy header:
                // POST /edge/api HTTP/1.1\r\nHost: cdn.example.com\r\n...
                val headerBuf = ByteArrayOutputStream()
                var afterHeader = ByteArray(0)
                while (true) {
                    val chunk = tlsConn.receive() ?: error("EOF before legacy header")
                    headerBuf.write(chunk)
                    val all = headerBuf.toByteArray()
                    val text = String(all, Charsets.ISO_8859_1)
                    val idx = text.indexOf("\r\n\r\n")
                    if (idx >= 0) {
                        val headerStr = text.substring(0, idx)
                        assertTrue(headerStr.startsWith("POST /edge/api HTTP/1.1\r\n"))
                        assertTrue(headerStr.contains("Host: cdn.example.com\r\n"))
                        afterHeader = all.copyOfRange(idx + 4, all.size)
                        break
                    }
                }

                peer.feedObfuscatedFromClient(afterHeader)
                while (true) {
                    val helloFrame = peer.takePlainBytes(74)
                    if (helloFrame != null) {
                        val reply = peer.completeKipServerHello(helloFrame)
                        tlsConn.send(reply)
                        break
                    }
                    val chunk = tlsConn.receive() ?: error("EOF waiting for KIP client hello")
                    peer.feedObfuscatedFromClient(chunk)
                }

                // Next is KIP_CONNECT_TCP (0x10): "kip" (3B) + 0x10 (1B) + len 15 (0x000F) +
                // ATYP_DOMAIN(0x03) + 11 + "example.com" + 0x01BB (21 bytes) + initialData "hello-tls" (9 bytes) = 30 bytes.
                var connectAndInit: ByteArray?
                while (true) {
                    connectAndInit = peer.takePlainBytes(30)
                    if (connectAndInit != null) break
                    val chunk = tlsConn.receive() ?: error("EOF waiting for KIP_CONNECT_TCP")
                    peer.feedObfuscatedFromClient(chunk)
                }

                val expectedConnect = byteArrayOf(
                    0x6B, 0x69, 0x70, 0x10, 0x00, 0x0F,
                    0x03, 0x0B,
                    'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(),
                    'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(), '.'.code.toByte(),
                    'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
                    0x01, 0xBB.toByte()
                ) + ascii("hello-tls")
                assertArrayEquals(expectedConnect, connectAndInit)

                tlsConn.send(peer.encodeServerPlaintextToObfuscated(ascii("world-tls")))
            }

            val client = SudokuClient(config, sudoku, rawTransportFactory = { pair.clientSide })
            val conn = client.connect("example.com", 443, ascii("hello-tls"))
            assertEquals(TlsVersion.TLS13, conn.outerTlsVersion)
            assertArrayEquals(ascii("world-tls"), conn.receiveRaw())
            conn.cancel()
            serverJob.await()
        }
    }

    // MARK: - 2. WebSocket Camouflage Carrier (mode=ws)

    @Test
    fun `WebSocket mask carrier sends authenticated upgrade headers and carries Sudoku over masked WS binary frames`() = runBlocking {
        withTimeout(15_000L) {
            val pair = InMemoryTransportPair()
            val psk = "ws-carrier-secret"
            val sudoku = SudokuConfiguration(
                key = psk,
                httpMask = SudokuHttpMaskConfiguration(
                    disable = false,
                    mode = SudokuHttpMaskMode.WS,
                    tls = false,
                    host = "cdn.example.com",
                    pathRoot = "cdn"
                )
            )
            val config = ProxyConfiguration(
                name = "sudoku-ws",
                serverAddress = "198.51.100.21",
                serverPort = 8080u,
                uuid = UUID.randomUUID(),
                encryption = "none",
                outboundProtocol = OutboundProtocol.SUDOKU,
                sudokuKey = psk,
                sudokuHttpMaskMode = "ws",
                sudokuHttpMaskHost = "cdn.example.com",
                sudokuHttpMaskPathRoot = "cdn"
            )

            val serverJob = async {
                // Read HTTP/1.1 WebSocket upgrade request
                val reqBuf = ByteArrayOutputStream()
                while (true) {
                    val chunk = pair.serverSide.receive() ?: error("EOF reading WS upgrade")
                    reqBuf.write(chunk)
                    val bytes = reqBuf.toByteArray()
                    val headerText = String(bytes, Charsets.US_ASCII)
                    val endIdx = headerText.indexOf("\r\n\r\n")
                    if (endIdx >= 0) {
                        val lines = headerText.substring(0, endIdx).split("\r\n")
                        val requestLine = lines[0]
                        assertTrue(requestLine.startsWith("GET /cdn/ws?auth=") && requestLine.endsWith(" HTTP/1.1"))
                        val queryAuth = requestLine.substringAfter("GET /cdn/ws?auth=").substringBefore(" HTTP/1.1")

                        val headers = lines.drop(1).associate { line ->
                            val idx = line.indexOf(':')
                            line.substring(0, idx).trim().lowercase() to line.substring(idx + 1).trim()
                        }
                        assertEquals("cdn.example.com:8080", headers["host"])
                        assertEquals("ws", headers["x-sudoku-tunnel"])
                        assertEquals("Bearer $queryAuth", headers["authorization"])
                        verifyIndependentHttpMaskAuthToken(psk, "ws", "GET", "/ws", queryAuth)

                        val wsKey = headers["sec-websocket-key"] ?: error("Missing Sec-WebSocket-Key")
                        val acceptSeed = wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                        val acceptHash = MessageDigest.getInstance("SHA-1").digest(acceptSeed.toByteArray(Charsets.US_ASCII))
                        val accept = Base64.getEncoder().encodeToString(acceptHash)

                        val upgradeResp = "HTTP/1.1 101 Switching Protocols\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Sec-WebSocket-Accept: $accept\r\n\r\n"
                        pair.serverSide.send(ascii(upgradeResp))
                        break
                    }
                }

                // Helper to read one client-masked WebSocket binary frame
                val wsRawBuffer = ByteArrayOutputStream()
                suspend fun readClientWsFrame(): ByteArray {
                    while (true) {
                        val buf = wsRawBuffer.toByteArray()
                        if (buf.size >= 2) {
                            val b0 = buf[0].toInt() and 0xFF
                            val b1 = buf[1].toInt() and 0xFF
                            assertEquals(0x82, b0) // FIN + binary opcode (0x02)
                            assertTrue("Client WS frame must be masked", (b1 and 0x80) != 0)
                            val len7 = b1 and 0x7F
                            var offset = 2
                            var payloadLen = len7
                            if (len7 == 126) {
                                if (buf.size < 4) {
                                    wsRawBuffer.write(pair.serverSide.receive() ?: error("EOF in WS length"))
                                    continue
                                }
                                payloadLen = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
                                offset = 4
                            }
                            if (buf.size >= offset + 4 + payloadLen) {
                                val mask = buf.copyOfRange(offset, offset + 4)
                                val masked = buf.copyOfRange(offset + 4, offset + 4 + payloadLen)
                                val unmasked = ByteArray(payloadLen) { i ->
                                    (masked[i].toInt() xor mask[i % 4].toInt()).toByte()
                                }
                                val totalConsumed = offset + 4 + payloadLen
                                wsRawBuffer.reset()
                                if (totalConsumed < buf.size) {
                                    wsRawBuffer.write(buf, totalConsumed, buf.size - totalConsumed)
                                }
                                return unmasked
                            }
                        }
                        wsRawBuffer.write(pair.serverSide.receive() ?: error("EOF reading WS frame"))
                    }
                }

                fun encodeServerWsFrame(payload: ByteArray): ByteArray {
                    val out = ByteArrayOutputStream()
                    out.write(0x82) // FIN + binary
                    if (payload.size < 126) {
                        out.write(payload.size)
                    } else {
                        out.write(126)
                        out.write((payload.size ushr 8) and 0xFF)
                        out.write(payload.size and 0xFF)
                    }
                    out.write(payload)
                    return out.toByteArray()
                }

                val peer = ServerSudokuPeer(psk = psk)
                while (true) {
                    peer.feedObfuscatedFromClient(readClientWsFrame())
                    val hello = peer.takePlainBytes(74)
                    if (hello != null) {
                        val reply = peer.completeKipServerHello(hello)
                        pair.serverSide.send(encodeServerWsFrame(reply))
                        break
                    }
                }

                // Read KIP_OPEN_UDP_OVER_TCP (0x12, empty payload -> 6 bytes) + UoT datagram
                // UoT datagram to 192.0.2.53:53 with payload "dns-q" (5 bytes):
                // addr = 0x01 + 192.0.2.53 + 0x0035 (7 bytes)
                // UoT header = 0x0007 + 0x0005 (4 bytes)
                // Total = 6 + 4 + 7 + 5 = 22 bytes.
                var uotStream: ByteArray?
                while (true) {
                    uotStream = peer.takePlainBytes(22)
                    if (uotStream != null) break
                    peer.feedObfuscatedFromClient(readClientWsFrame())
                }
                val expectedUot = byteArrayOf(
                    0x6B, 0x69, 0x70, 0x12, 0x00, 0x00, // KIP_OPEN_UDP_OVER_TCP
                    0x00, 0x07, 0x00, 0x05, // addrLen=7, payloadLen=5
                    0x01, 192.toByte(), 0, 2, 53, 0x00, 0x35 // 192.0.2.53:53
                ) + ascii("dns-q")
                assertArrayEquals(expectedUot, uotStream)

                // Send back UoT response frame
                val serverUot = byteArrayOf(
                    0x00, 0x07, 0x00, 0x05,
                    0x01, 192.toByte(), 0, 2, 53, 0x00, 0x35
                ) + ascii("dns-a")
                pair.serverSide.send(encodeServerWsFrame(peer.encodeServerPlaintextToObfuscated(serverUot)))
            }

            val client = SudokuClient(config, sudoku, rawTransportFactory = { pair.clientSide })
            val udp = client.connectUDP("192.0.2.53", 53)
            udp.sendRaw(ascii("dns-q"))
            assertArrayEquals(ascii("dns-a"), udp.receiveRaw())
            udp.cancel()
            serverJob.await()
        }
    }

    // MARK: - 3. Split HTTP-Mask Tunnel (stream, poll, auto)

    @Test
    fun `HTTP-mask stream and auto fallback perform early KIP on session endpoint and frame stream and poll bodies`() = runBlocking {
        withTimeout(15_000L) {
            val psk = "http-mask-auto-secret"
            val sudoku = SudokuConfiguration(
                key = psk,
                httpMask = SudokuHttpMaskConfiguration(
                    disable = false,
                    mode = SudokuHttpMaskMode.AUTO,
                    tls = false,
                    host = "cdn.example.com",
                    pathRoot = "tunnel"
                )
            )
            val config = ProxyConfiguration(
                name = "sudoku-http-auto",
                serverAddress = "198.51.100.22",
                serverPort = 80u,
                uuid = UUID.randomUUID(),
                encryption = "none",
                outboundProtocol = OutboundProtocol.SUDOKU,
                sudokuKey = psk,
                sudokuHttpMaskMode = "auto",
                sudokuHttpMaskHost = "cdn.example.com",
                sudokuHttpMaskPathRoot = "tunnel"
            )

            val peer = ServerSudokuPeer(psk = psk)
            val seenPaths = CopyOnWriteArrayList<String>()
            val legCounter = AtomicInteger(0)
            val closeReceived = Channel<String>(1)
            val pullServerSide = Channel<Transport>(1)

            val legFactory: suspend () -> Transport = {
                val legId = legCounter.incrementAndGet()
                val pair = InMemoryTransportPair()
                kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.IO).async {
                    val reqBuf = ByteArrayOutputStream()
                    while (true) {
                        val chunk = pair.serverSide.receive() ?: break
                        reqBuf.write(chunk)
                        val bytes = reqBuf.toByteArray()
                        val text = String(bytes, Charsets.US_ASCII)
                        val headerEnd = text.indexOf("\r\n\r\n")
                        if (headerEnd < 0) continue

                        val headerPart = text.substring(0, headerEnd)
                        val lines = headerPart.split("\r\n")
                        val requestLine = lines[0]
                        val headers = lines.drop(1).associate { line ->
                            val idx = line.indexOf(':')
                            line.substring(0, idx).trim().lowercase() to line.substring(idx + 1).trim()
                        }
                        val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                        if (bytes.size < headerEnd + 4 + contentLength) continue

                        val bodyBytes = bytes.copyOfRange(headerEnd + 4, headerEnd + 4 + contentLength)
                        val methodAndPath = requestLine.removeSuffix(" HTTP/1.1")
                        seenPaths.add(methodAndPath)

                        assertEquals("cdn.example.com", headers["host"])
                        assertEquals("1", headers["x-sudoku-version"])

                        when (legId) {
                            1 -> {
                                // Leg 1: AUTO tries STREAM first on GET /tunnel/session?ed=...&auth=...
                                assertEquals("stream", headers["x-sudoku-tunnel"])
                                assertTrue(methodAndPath.startsWith("GET /tunnel/session?ed="))
                                val auth = methodAndPath.substringAfter("&auth=")
                                verifyIndependentHttpMaskAuthToken(psk, "stream", "GET", "/session", auth)
                                // Refuse STREAM with 403 so AUTO falls back to POLL!
                                pair.serverSide.send(
                                    ascii("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                )
                                pair.serverSide.forceCancel()
                            }
                            2 -> {
                                // Leg 2: AUTO falls back to POLL on GET /tunnel/session?ed=...&auth=...
                                assertEquals("poll", headers["x-sudoku-tunnel"])
                                assertTrue(methodAndPath.startsWith("GET /tunnel/session?ed="))
                                val edParam = methodAndPath.substringAfter("?ed=").substringBefore("&auth=")
                                val auth = methodAndPath.substringAfter("&auth=")
                                verifyIndependentHttpMaskAuthToken(psk, "poll", "GET", "/session", auth)

                                val clientEarlyObfs = Base64.getUrlDecoder().decode(edParam)
                                peer.feedObfuscatedFromClient(clientEarlyObfs)
                                val helloFrame = peer.takePlainBytes(74)
                                assertNotNull("Early KIP client hello must decode from ed=", helloFrame)
                                val serverHelloObfs = peer.completeKipServerHello(helloFrame!!)
                                val serverEd = Base64.getUrlEncoder().withoutPadding().encodeToString(serverHelloObfs)

                                val respBody = ascii("token=tok_poll_99\ned=$serverEd\n")
                                val respHeader = "HTTP/1.1 200 OK\r\n" +
                                    "Content-Type: text/plain\r\n" +
                                    "Content-Length: ${respBody.size}\r\n" +
                                    "Connection: close\r\n\r\n"
                                pair.serverSide.send(ascii(respHeader) + respBody)
                                pair.serverSide.forceCancel()
                            }
                            3 -> {
                                // Leg 3: POLL downlink GET /tunnel/stream?token=tok_poll_99&auth=...
                                assertEquals("poll", headers["x-sudoku-tunnel"])
                                assertTrue(methodAndPath.startsWith("GET /tunnel/stream?token=tok_poll_99&auth="))
                                val auth = methodAndPath.substringAfter("&auth=")
                                verifyIndependentHttpMaskAuthToken(psk, "poll", "GET", "/stream", auth)

                                pair.serverSide.send(
                                    ascii("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
                                )
                                pullServerSide.trySend(pair.serverSide)
                            }
                            4 -> {
                                // Leg 4: POLL uplink seq=1 POST /tunnel/api/v1/upload?token=tok_poll_99&seq=1&auth=...
                                assertEquals("poll", headers["x-sudoku-tunnel"])
                                assertEquals("text/plain", headers["content-type"])
                                assertTrue(methodAndPath.startsWith("POST /tunnel/api/v1/upload?token=tok_poll_99&seq=1&auth="))
                                val auth = methodAndPath.substringAfter("&auth=")
                                verifyIndependentHttpMaskAuthToken(psk, "poll", "POST", "/api/v1/upload", auth)

                                // Body in POLL mode is standard Base64 + "\n"
                                val bodyText = String(bodyBytes, Charsets.US_ASCII)
                                assertTrue(bodyText.endsWith("\n"))
                                val uploadedObfs = Base64.getDecoder().decode(bodyText.trim())
                                peer.feedObfuscatedFromClient(uploadedObfs)

                                // Because early KIP already rekeyed the session on Leg 2, this first upload
                                // is decrypted with the session key and contains KIP_CONNECT_TCP!
                                val plain = peer.takeAllPlainBytes()
                                val expectedConnect = byteArrayOf(
                                    0x6B, 0x69, 0x70, 0x10, 0x00, 0x07,
                                    0x01, 203.toByte(), 0, 113, 8, 0x00, 0x50 // 203.0.113.8:80
                                )
                                assertArrayEquals(expectedConnect, plain)

                                pair.serverSide.send(
                                    ascii("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                )
                                pair.serverSide.forceCancel()
                            }
                            5 -> {
                                // Leg 5: POLL uplink seq=2 (initialData "GET /")
                                assertEquals("poll", headers["x-sudoku-tunnel"])
                                assertEquals("text/plain", headers["content-type"])
                                assertTrue(methodAndPath.startsWith("POST /tunnel/api/v1/upload?token=tok_poll_99&seq=2&auth="))
                                val bodyText = String(bodyBytes, Charsets.US_ASCII)
                                assertTrue(bodyText.endsWith("\n"))
                                val uploadedObfs = Base64.getDecoder().decode(bodyText.trim())
                                peer.feedObfuscatedFromClient(uploadedObfs)
                                assertArrayEquals(ascii("GET /"), peer.takeAllPlainBytes())

                                pair.serverSide.send(
                                    ascii("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                )
                                pair.serverSide.forceCancel()

                                // Push downlink reply over Leg 3 (/stream) as a chunked Base64 line
                                val pullConn = pullServerSide.receive()
                                val serverObfs = peer.encodeServerPlaintextToObfuscated(ascii("HTTP/1.1 200 OK"))
                                val pollLine = (Base64.getEncoder().encodeToString(serverObfs) + "\n").toByteArray(Charsets.US_ASCII)
                                val chunkedFrame = ascii("${pollLine.size.toString(16)}\r\n") + pollLine + ascii("\r\n0\r\n\r\n")
                                pullConn.send(chunkedFrame)
                            }
                            6 -> {
                                // Leg 6: Close notification POST /tunnel/api/v1/upload?token=tok_poll_99&close=1&auth=...
                                assertTrue(methodAndPath.startsWith("POST /tunnel/api/v1/upload?token=tok_poll_99&close=1&auth="))
                                closeReceived.trySend(methodAndPath)
                                pair.serverSide.send(
                                    ascii("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                )
                                pair.serverSide.forceCancel()
                            }
                        }
                        break
                    }
                }
                pair.clientSide
            }

            val client = SudokuClient(config, sudoku, rawTransportFactory = legFactory)
            val conn = client.connect("203.0.113.8", 80, ascii("GET /"))
            assertArrayEquals(ascii("HTTP/1.1 200 OK"), conn.receiveRaw())
            conn.cancel()

            val closePath = closeReceived.receive()
            assertTrue(closePath.contains("token=tok_poll_99&close=1"))
            assertEquals(6, seenPaths.size)
        }
    }

    // MARK: - 4. Native Multiplexer & Session Pool (mux=on)

    @Test
    fun `native multiplexer pools a single KIP_OPEN_MUX session across concurrent TCP dials and handles data, close, reset, and ping`() = runBlocking {
        withTimeout(15_000L) {
            val psk = "mux-pool-secret"
            val sudoku = SudokuConfiguration(
                key = psk,
                multiplex = SudokuMultiplex.ON,
                httpMask = SudokuHttpMaskConfiguration(disable = true)
            )
            val config = ProxyConfiguration(
                name = "sudoku-mux",
                serverAddress = "198.51.100.25",
                serverPort = 9443u,
                uuid = UUID.randomUUID(),
                encryption = "none",
                outboundProtocol = OutboundProtocol.SUDOKU,
                sudokuKey = psk,
                sudokuMultiplex = "on",
                sudokuHttpMaskDisable = true
            )

            val transportConnections = AtomicInteger(0)
            val pair = InMemoryTransportPair()

            val serverJob = async {
                val peer = ServerSudokuPeer(psk = psk)

                suspend fun readPlainExact(count: Int): ByteArray {
                    while (true) {
                        peer.takePlainBytes(count)?.let { return it }
                        val chunk = pair.serverSide.receive() ?: error("EOF waiting for $count plain bytes")
                        peer.feedObfuscatedFromClient(chunk)
                    }
                }

                // 1. Complete KIP handshake
                val helloFrame = readPlainExact(74)
                pair.serverSide.send(peer.completeKipServerHello(helloFrame))

                // 2. Expect KIP_OPEN_MUX: "kip" || 0x11 || 0x0000 (6 bytes)
                val openMux = readPlainExact(6)
                assertArrayEquals(byteArrayOf(0x6B, 0x69, 0x70, 0x11, 0x00, 0x00), openMux)

                // 3. Read stream 1 MUX_OPEN (type=0x01, streamId=1, len=7, IPv4 192.0.2.10:80)
                //    + stream 1 MUX_DATA (type=0x02, streamId=1, len=4, "one!")
                val s1Open = readPlainExact(9 + 7)
                assertArrayEquals(
                    byteArrayOf(
                        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07,
                        0x01, 192.toByte(), 0, 2, 10, 0x00, 0x50
                    ),
                    s1Open
                )
                val s1Data = readPlainExact(9 + 4)
                assertArrayEquals(
                    byteArrayOf(0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04) + ascii("one!"),
                    s1Data
                )

                // 4. Read stream 2 MUX_OPEN (type=0x01, streamId=2, len=7, IPv4 192.0.2.20:443)
                //    + stream 2 MUX_DATA (type=0x02, streamId=2, len=4, "two!")
                val s2Open = readPlainExact(9 + 7)
                assertArrayEquals(
                    byteArrayOf(
                        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07,
                        0x01, 192.toByte(), 0, 2, 20, 0x01, 0xBB.toByte()
                    ),
                    s2Open
                )
                val s2Data = readPlainExact(9 + 4)
                assertArrayEquals(
                    byteArrayOf(0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04) + ascii("two!"),
                    s2Data
                )

                // 5. Server sends MUX_CONTROL_PING (0x05 on stream 0, length 0)
                //    + MUX_DATA for stream 1 ("reply-1")
                //    + MUX_CLOSE (0x03) for stream 1
                //    + MUX_RESET (0x04) for stream 2 with reason "upstream refused"
                val pingFrame = byteArrayOf(0x05, 0, 0, 0, 0, 0, 0, 0, 0)
                val s1Reply = byteArrayOf(0x02, 0, 0, 0, 1, 0, 0, 0, 7) + ascii("reply-1")
                val s1Close = byteArrayOf(0x03, 0, 0, 0, 1, 0, 0, 0, 0)
                val reason = ascii("upstream refused")
                val s2Reset = byteArrayOf(0x04, 0, 0, 0, 2, 0, 0, 0, reason.size.toByte()) + reason

                pair.serverSide.send(
                    peer.encodeServerPlaintextToObfuscated(pingFrame + s1Reply + s1Close + s2Reset)
                )

                // 6. Expect client to answer MUX_CONTROL_PING with MUX_CONTROL_PONG (0x06 on stream 0, length 0)
                val pongFrame = readPlainExact(9)
                assertArrayEquals(byteArrayOf(0x06, 0, 0, 0, 0, 0, 0, 0, 0), pongFrame)
            }

            val factory: suspend () -> Transport = {
                transportConnections.incrementAndGet()
                pair.clientSide
            }

            val client1 = SudokuClient(config, sudoku, rawTransportFactory = factory)
            val stream1 = client1.connect("192.0.2.10", 80, ascii("one!"))

            val client2 = SudokuClient(config, sudoku, rawTransportFactory = factory)
            val stream2 = client2.connect("192.0.2.20", 443, ascii("two!"))

            // Both streams share the single pooled SudokuSession!
            assertEquals(1, transportConnections.get())
            assertNotNull(SudokuClient.poolKey(config))

            assertArrayEquals(ascii("reply-1"), stream1.receiveRaw())
            assertNull(stream1.receiveRaw()) // MUX_CLOSE -> clean EOF

            try {
                stream2.receiveRaw()
                fail("Expected stream2 to throw on MUX_RESET")
            } catch (e: ProxyError.ProtocolError) {
                assertTrue(e.message!!.contains("upstream refused"))
            }

            serverJob.await()
            stream1.cancel()
            stream2.cancel()
        }
    }
}
