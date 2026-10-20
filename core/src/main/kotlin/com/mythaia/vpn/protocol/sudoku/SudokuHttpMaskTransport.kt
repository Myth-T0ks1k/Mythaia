package com.mythaia.vpn.protocol.sudoku

import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.protocol.Transport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Split HTTP-tunnel transport for Sudoku (`stream`, `poll`, and `auto` mask modes).
 *
 * Unlike the `legacy` mode (which writes a single decoy POST header and then streams
 * obfuscated Sudoku records directly) or `ws` mode (which upgrades to WebSocket),
 * the split HTTP tunnel maps a Sudoku session onto three HTTP/1.1 endpoints:
 *
 * 1. `GET <root>/session?ed=<base64url>&auth=<token>` — authorises a tunnel session,
 *    optionally carrying the obfuscated KIP client hello in `ed` and receiving both
 *    `token=<sessionToken>` and the server's obfuscated KIP server hello `ed=<base64url>`
 *    in the `200 OK` body so the session rekeys immediately without an extra round trip.
 * 2. `GET <root>/stream?token=<token>&auth=<token>` — long-lived downlink stream:
 *    delivers raw obfuscated bytes in `stream` mode or newline-delimited Base64
 *    frames in `poll` mode.
 * 3. `POST <root>/api/v1/upload?token=<token>&seq=<seq>&auth=<token>` — sequenced
 *    uplink batches (`application/octet-stream` in `stream` mode, Base64 + `\n`
 *    `text/plain` in `poll` mode), terminated by `&close=1` on teardown.
 *
 * In `auto` mode, the client attempts `stream` first and falls back to `poll` if
 * establishing the `stream` tunnel fails.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuHttpMaskTransport(
    private val settings: SudokuConnectionSettings,
    private val enableEarlyHandshake: Boolean = true,
    private val connectionFactory: suspend () -> Transport
) : Transport {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private val closed = AtomicBoolean(false)

    @Volatile
    var selectedMode: SudokuHttpMaskMode = settings.httpMask.mode
        private set

    @Volatile
    var sessionToken: String = ""
        private set

    /**
     * Session record keys derived during the `/session?ed=...` early KIP exchange,
     * or null when the server did not answer with `ed=` (in which case
     * [SudokuSession] performs the KIP exchange in-band over the tunnel).
     */
    @Volatile
    var earlySessionBases: SudokuProtocol.DirectionKeys? = null
        private set

    @Volatile
    private var pullConnection: Transport? = null

    @Volatile
    private var pushConnection: Transport? = null

    private val pushMutex = Mutex()
    private var uploadSequence = 0L

    private val receiveChannel = Channel<ByteArray>(Channel.UNLIMITED)
    private val receiveMutex = Mutex()
    private var leftover = ByteArray(0)
    private var leftoverOffset = 0
    private var receiveEof = false

    /**
     * Authorises the HTTP-mask session, opens the `/stream` downlink leg, and
     * starts the background pull loop.
     */
    suspend fun connect() {
        when (settings.httpMask.mode) {
            SudokuHttpMaskMode.STREAM -> connectWithMode(SudokuHttpMaskMode.STREAM)
            SudokuHttpMaskMode.POLL -> connectWithMode(SudokuHttpMaskMode.POLL)
            SudokuHttpMaskMode.AUTO -> {
                try {
                    connectWithMode(SudokuHttpMaskMode.STREAM)
                } catch (_: Exception) {
                    connectWithMode(SudokuHttpMaskMode.POLL)
                }
            }
            else -> throw SudokuError.InvalidConfiguration(
                "unsupported HTTP tunnel mode: ${settings.httpMask.mode.id}"
            )
        }
    }

    private suspend fun connectWithMode(mode: SudokuHttpMaskMode) {
        val authResult = authorize(mode)
        val pull = openPullConnection(mode, authResult.token)
        selectedMode = mode
        sessionToken = authResult.token
        earlySessionBases = authResult.earlyBases
        pullConnection = pull.transport
        scope.launch {
            runPullLoop(pull.transport, mode, pull.header, pull.initialBody)
        }
    }

    override suspend fun send(data: ByteArray) {
        if (data.isEmpty()) return
        if (closed.get()) throw SudokuError.HttpMaskFailed("HTTP mask tunnel closed")
        val maxBatch = if (selectedMode == SudokuHttpMaskMode.POLL) MAX_POLL_BATCH_BYTES else MAX_STREAM_BATCH_BYTES
        pushMutex.withLock {
            var offset = 0
            while (offset < data.size) {
                if (closed.get()) throw SudokuError.HttpMaskFailed("HTTP mask tunnel closed")
                val count = minOf(maxBatch, data.size - offset)
                val chunk = data.copyOfRange(offset, offset + count)
                uploadSequence += 1
                uploadBatch(chunk, uploadSequence)
                offset += count
            }
        }
    }

    override fun sendAsync(data: ByteArray) {
        if (data.isEmpty() || closed.get()) return
        scope.launch {
            runCatching { send(data) }
        }
    }

    override suspend fun receive(): ByteArray? = receive(DEFAULT_RECEIVE_MAX)

    suspend fun receive(maxBytes: Int): ByteArray? {
        if (maxBytes <= 0) return ByteArray(0)
        return receiveMutex.withLock {
            takeLeftover(maxBytes)?.let { return@withLock it }
            if (receiveEof) return@withLock null
            val next = receiveChannel.receiveCatching().getOrNull() ?: run {
                receiveEof = true
                return@withLock null
            }
            if (next.size <= maxBytes) return@withLock next
            leftover = next
            leftoverOffset = maxBytes
            next.copyOf(maxBytes)
        }
    }

    override fun forceCancel() {
        if (!closed.compareAndSet(false, true)) return
        receiveChannel.close()
        val pull = pullConnection
        pullConnection = null
        runCatching { pull?.forceCancel() }

        val token = sessionToken
        val mode = selectedMode
        val existingPush = pushConnection
        pushConnection = null

        scope.launch {
            withContext(NonCancellable) {
                runCatching {
                    if (token.isNotEmpty()) {
                        sendCloseNotification(mode, token, existingPush)
                    } else {
                        existingPush?.forceCancel()
                    }
                }
            }
            scope.cancel()
        }
    }

    private fun takeLeftover(maxBytes: Int): ByteArray? {
        val available = leftover.size - leftoverOffset
        if (available <= 0) return null
        val count = minOf(maxBytes, available)
        val slice = leftover.copyOfRange(leftoverOffset, leftoverOffset + count)
        leftoverOffset += count
        if (leftoverOffset >= leftover.size) {
            leftover = ByteArray(0)
            leftoverOffset = 0
        }
        return slice
    }

    // MARK: - Session authorisation & early KIP

    private class AuthorizeResult(
        val token: String,
        val earlyBases: SudokuProtocol.DirectionKeys?
    )

    private class EarlyClientHandshake(
        val queryPayload: String,
        val finish: (ByteArray) -> SudokuProtocol.DirectionKeys
    )

    private suspend fun authorize(mode: SudokuHttpMaskMode): AuthorizeResult {
        val early = if (enableEarlyHandshake) makeEarlyHandshake() else null
        val conn = connectionFactory()
        try {
            val basePath = SudokuProtocol.applyPathRoot(settings.httpMask.pathRoot, "/session")
            val unixSeconds = System.currentTimeMillis() / 1000L
            val auth = SudokuProtocol.httpMaskAuthToken(settings.psk, mode.id, "GET", "/session", unixSeconds)
            val pathWithEd = if (early != null && early.queryPayload.isNotEmpty()) {
                val sep = if (basePath.contains('?')) "&" else "?"
                "$basePath${sep}ed=${early.queryPayload}"
            } else {
                basePath
            }
            val path = SudokuProtocol.appendAuth(pathWithEd, auth)
            val request = buildHttpRequest(
                method = "GET",
                path = path,
                mode = mode,
                auth = auth,
                contentType = null,
                body = ByteArray(0)
            )
            conn.send(request)
            val response = readHttpResponse(conn, MAX_CONTROL_BODY_BYTES)
            if (response.header.statusCode != 200) {
                throw SudokuError.HttpMaskFailed("HTTP mask session failed: HTTP ${response.header.statusCode}")
            }
            return parseSessionResponse(response.body, early)
        } finally {
            runCatching { conn.forceCancel() }
        }
    }

    private fun makeEarlyHandshake(): EarlyClientHandshake {
        val keyPair = X25519Crypto.generateKeyPair()
        val privateKey = keyPair.copyOf(32)
        val publicKey = keyPair.copyOfRange(32, 64)
        val nonce = ByteArray(SudokuProtocol.KIP_NONCE_SIZE).also { random.nextBytes(it) }
        val unixSeconds = System.currentTimeMillis() / 1000L
        val tableHint = if (settings.sendsTableHint) settings.tablePair.hint else null

        val helloFrame = SudokuHandshake.clientHelloFrame(
            keyFingerprintSource = settings.keyFingerprintSource,
            unixSeconds = unixSeconds,
            clientPublicKey = publicKey,
            nonce = nonce,
            tableHint = tableHint
        )

        val pskBases = SudokuProtocol.pskBases(settings.psk)
        val recordWire = if (settings.aeadMethod == SudokuAeadMethod.NONE) {
            helloFrame
        } else {
            val epoch = randomNonZeroUInt32()
            val seq = randomNonZeroUInt64()
            SudokuProtocol.sealRecord(settings.aeadMethod, pskBases.clientToServer, epoch, seq, helloFrame)
        }

        val rng = SudokuXorshift64Star(randomSeed())
        val threshold = rng.pickPaddingThreshold(settings.paddingMin, settings.paddingMax)
        val obfuscated = settings.tablePair.uplink.encode(recordWire, rng, threshold)
        val queryPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(obfuscated)

        return EarlyClientHandshake(queryPayload = queryPayload) { serverObfuscated ->
            val decodedRecordWire = if (settings.pureDownlink) {
                SudokuPureDecoder(settings.tablePair.downlink).decode(serverObfuscated, Int.MAX_VALUE)
            } else {
                SudokuPackedDecoder(settings.tablePair.downlink).decode(serverObfuscated, Int.MAX_VALUE)
            }
            val kipPlaintext = openServerRecords(decodedRecordWire, pskBases.serverToClient)
            val kip = SudokuProtocol.parseKip(kipPlaintext)
            if (kip.consumed != kipPlaintext.size) {
                throw SudokuError.ProtocolViolation("trailing bytes in early KIP server hello")
            }
            val serverPublicKey = when (
                val outcome = SudokuHandshake.classifyServerHello(kip.type, kip.payload, nonce)
            ) {
                is SudokuHandshake.ServerHello.Ready -> outcome.publicKey
                is SudokuHandshake.ServerHello.Rejected ->
                    throw SudokuError.ProtocolViolation(
                        "unexpected early KIP message: 0x%02x".format(outcome.type.toInt() and 0xFF)
                    )
            }
            val shared = X25519Crypto.keyAgreement(privateKey, serverPublicKey)
            SudokuProtocol.sessionBases(settings.psk, shared, nonce)
        }
    }

    private fun openServerRecords(wire: ByteArray, baseRecv: ByteArray): ByteArray {
        if (settings.aeadMethod == SudokuAeadMethod.NONE) return wire
        val out = ByteArrayOutputStream()
        var offset = 0
        var recvEpoch = 0L
        var recvSeq = 0L
        var initialized = false
        while (offset < wire.size) {
            if (wire.size - offset < SudokuProtocol.RECORD_LENGTH_PREFIX_SIZE) {
                throw SudokuError.ProtocolViolation("truncated early KIP record length")
            }
            val bodyLen = SudokuProtocol.parseRecordLength(
                wire.copyOfRange(offset, offset + SudokuProtocol.RECORD_LENGTH_PREFIX_SIZE)
            )
            offset += SudokuProtocol.RECORD_LENGTH_PREFIX_SIZE
            if (wire.size - offset < bodyLen) {
                throw SudokuError.ProtocolViolation("truncated early KIP record body")
            }
            val body = wire.copyOfRange(offset, offset + bodyLen)
            offset += bodyLen

            val epoch = SudokuProtocol.recordEpoch(body)
            val seq = SudokuProtocol.recordSequence(body)
            if (initialized) {
                SudokuProtocol.validateRecordOrder(recvEpoch, recvSeq, epoch, seq)
            }
            val plain = SudokuProtocol.openRecord(settings.aeadMethod, baseRecv, body)
            out.write(plain)
            recvEpoch = epoch
            recvSeq = seq + 1
            initialized = true
        }
        return out.toByteArray()
    }

    private fun parseSessionResponse(body: ByteArray, early: EarlyClientHandshake?): AuthorizeResult {
        val text = String(body, Charsets.UTF_8).trim()
        var token = ""
        var edText = ""
        for (rawLine in text.split('\r', '\n')) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            when {
                line.startsWith("token=") -> token = line.removePrefix("token=").trim()
                line.startsWith("ed=") -> edText = line.removePrefix("ed=").trim()
                token.isEmpty() && !line.contains('=') -> token = line
            }
        }
        val validToken = token.isNotEmpty() && token.length <= 256 && token.all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' || it == '-'
        }
        if (!validToken) {
            throw SudokuError.HttpMaskFailed("invalid HTTP mask token")
        }
        val earlyBases = if (edText.isNotEmpty() && early != null) {
            val serverPayload = decodeBase64Url(edText)
                ?: throw SudokuError.HttpMaskFailed("invalid HTTP mask early handshake")
            early.finish(serverPayload)
        } else {
            null
        }
        return AuthorizeResult(token = token, earlyBases = earlyBases)
    }

    // MARK: - Downlink (/stream)

    private class OpenedPull(
        val transport: Transport,
        val header: HttpHeader,
        val initialBody: ByteArray
    )

    private suspend fun openPullConnection(mode: SudokuHttpMaskMode, token: String): OpenedPull {
        val conn = connectionFactory()
        try {
            val basePath = SudokuProtocol.applyPathRoot(settings.httpMask.pathRoot, "/stream")
            val unixSeconds = System.currentTimeMillis() / 1000L
            val auth = SudokuProtocol.httpMaskAuthToken(settings.psk, mode.id, "GET", "/stream", unixSeconds)
            val encodedToken = URLEncoder.encode(token, "UTF-8")
            val sep = if (basePath.contains('?')) "&" else "?"
            val path = SudokuProtocol.appendAuth("$basePath${sep}token=$encodedToken", auth)
            val request = buildHttpRequest(
                method = "GET",
                path = path,
                mode = mode,
                auth = auth,
                contentType = null,
                body = ByteArray(0)
            )
            conn.send(request)
            val (header, initialBody) = readHttpResponseHeader(conn)
            if (header.statusCode != 200) {
                throw SudokuError.HttpMaskFailed("HTTP mask stream failed: HTTP ${header.statusCode}")
            }
            return OpenedPull(conn, header, initialBody)
        } catch (e: Exception) {
            runCatching { conn.forceCancel() }
            throw e
        }
    }

    private suspend fun runPullLoop(
        conn: Transport,
        mode: SudokuHttpMaskMode,
        header: HttpHeader,
        initialBody: ByteArray
    ) {
        val reader = BufferedTransportReader(conn, initialBody)
        var lineBuffer = ByteArrayOutputStream()

        fun emitPayloadChunk(bytes: ByteArray) {
            if (bytes.isEmpty() || closed.get()) return
            if (mode == SudokuHttpMaskMode.STREAM) {
                receiveChannel.trySend(bytes)
            } else {
                // POLL mode frames downlink as newline-delimited Base64 lines.
                for (b in bytes) {
                    if (b == '\n'.code.toByte()) {
                        val lineBytes = lineBuffer.toByteArray()
                        lineBuffer.reset()
                        val line = String(lineBytes, Charsets.US_ASCII).trim()
                        if (line.isNotEmpty()) {
                            val decoded = try {
                                Base64.getDecoder().decode(line)
                            } catch (_: IllegalArgumentException) {
                                throw SudokuError.HttpMaskFailed("invalid poll base64 frame")
                            }
                            if (decoded.isNotEmpty()) {
                                receiveChannel.trySend(decoded)
                            }
                        }
                    } else {
                        if (lineBuffer.size() >= MAX_POLL_LINE_BYTES) {
                            throw SudokuError.HttpMaskFailed("HTTP mask poll line too large")
                        }
                        lineBuffer.write(b.toInt())
                    }
                }
            }
        }

        try {
            if (header.isChunked) {
                while (!closed.get()) {
                    val sizeLine = reader.readCrLfLine(MAX_CHUNK_HEADER_BYTES) ?: break
                    val sizeHex = sizeLine.substringBefore(';').trim()
                    val chunkSize = sizeHex.toIntOrNull(16)
                        ?: throw SudokuError.HttpMaskFailed("invalid chunk size: $sizeHex")
                    if (chunkSize < 0 || chunkSize > MAX_HTTP_BODY_BYTES) {
                        throw SudokuError.HttpMaskFailed("chunk size out of bounds: $chunkSize")
                    }
                    if (chunkSize == 0) {
                        // Read trailers until blank line.
                        while (true) {
                            val trailerLine = reader.readCrLfLine(MAX_HEADER_BYTES) ?: break
                            if (trailerLine.isEmpty()) break
                        }
                        break
                    }
                    val chunk = reader.readExact(chunkSize)
                        ?: throw SudokuError.HttpMaskFailed("truncated HTTP chunk")
                    val crlf = reader.readExact(2)
                        ?: throw SudokuError.HttpMaskFailed("missing chunk CRLF")
                    if (crlf[0] != '\r'.code.toByte() || crlf[1] != '\n'.code.toByte()) {
                        throw SudokuError.HttpMaskFailed("invalid chunk terminator")
                    }
                    emitPayloadChunk(chunk)
                }
            } else {
                var remaining = header.contentLength
                while (!closed.get()) {
                    if (remaining != null && remaining <= 0) break
                    val chunk = reader.readAvailable( remaining ?: DEFAULT_RECEIVE_MAX) ?: break
                    if (remaining != null) remaining -= chunk.size
                    emitPayloadChunk(chunk)
                }
            }
            if (mode == SudokuHttpMaskMode.POLL && lineBuffer.size() > 0) {
                val trailing = String(lineBuffer.toByteArray(), Charsets.US_ASCII).trim()
                if (trailing.isNotEmpty()) {
                    val decoded = runCatching { Base64.getDecoder().decode(trailing) }.getOrNull()
                    if (decoded != null && decoded.isNotEmpty()) {
                        receiveChannel.trySend(decoded)
                    }
                }
            }
        } catch (_: Exception) {
            // Fall through to close channel cleanly.
        } finally {
            receiveChannel.close()
            runCatching { conn.forceCancel() }
        }
    }

    // MARK: - Uplink (/api/v1/upload)

    private suspend fun uploadBatch(rawBatch: ByteArray, seq: Long) {
        val mode = selectedMode
        val token = sessionToken
        val body: ByteArray
        val contentType: String
        if (mode == SudokuHttpMaskMode.POLL) {
            val encoded = Base64.getEncoder().encodeToString(rawBatch) + "\n"
            body = encoded.toByteArray(Charsets.US_ASCII)
            contentType = "text/plain"
        } else {
            body = rawBatch
            contentType = "application/octet-stream"
        }

        val basePath = SudokuProtocol.applyPathRoot(settings.httpMask.pathRoot, "/api/v1/upload")
        val unixSeconds = System.currentTimeMillis() / 1000L
        val auth = SudokuProtocol.httpMaskAuthToken(settings.psk, mode.id, "POST", "/api/v1/upload", unixSeconds)
        val encodedToken = URLEncoder.encode(token, "UTF-8")
        val sep = if (basePath.contains('?')) "&" else "?"
        val path = SudokuProtocol.appendAuth("$basePath${sep}token=$encodedToken&seq=$seq", auth)
        val request = buildHttpRequest(
            method = "POST",
            path = path,
            mode = mode,
            auth = auth,
            contentType = contentType,
            body = body
        )

        sendUploadRequestWithRetry(request)
    }

    private suspend fun sendUploadRequestWithRetry(request: ByteArray) {
        var existing = pushConnection
        if (existing != null) {
            try {
                existing.send(request)
                val response = readHttpResponse(existing, MAX_CONTROL_BODY_BYTES)
                if (response.header.connectionClose) {
                    pushConnection = null
                    runCatching { existing.forceCancel() }
                }
                if (response.header.statusCode != 200) {
                    throw SudokuError.HttpMaskFailed("HTTP mask upload failed: HTTP ${response.header.statusCode}")
                }
                return
            } catch (e: SudokuError.HttpMaskFailed) {
                if (e.message?.startsWith("HTTP mask upload failed: HTTP ") == true) throw e
                pushConnection = null
                runCatching { existing.forceCancel() }
            } catch (_: Exception) {
                pushConnection = null
                runCatching { existing.forceCancel() }
            }
        }

        val fresh = connectionFactory()
        pushConnection = fresh
        try {
            fresh.send(request)
            val response = readHttpResponse(fresh, MAX_CONTROL_BODY_BYTES)
            if (response.header.connectionClose) {
                pushConnection = null
                runCatching { fresh.forceCancel() }
            }
            if (response.header.statusCode != 200) {
                throw SudokuError.HttpMaskFailed("HTTP mask upload failed: HTTP ${response.header.statusCode}")
            }
        } catch (e: Exception) {
            pushConnection = null
            runCatching { fresh.forceCancel() }
            throw e
        }
    }

    private suspend fun sendCloseNotification(
        mode: SudokuHttpMaskMode,
        token: String,
        existingConn: Transport?
    ) {
        val basePath = SudokuProtocol.applyPathRoot(settings.httpMask.pathRoot, "/api/v1/upload")
        val unixSeconds = System.currentTimeMillis() / 1000L
        val auth = SudokuProtocol.httpMaskAuthToken(settings.psk, mode.id, "POST", "/api/v1/upload", unixSeconds)
        val encodedToken = URLEncoder.encode(token, "UTF-8")
        val sep = if (basePath.contains('?')) "&" else "?"
        val path = SudokuProtocol.appendAuth("$basePath${sep}token=$encodedToken&close=1", auth)
        val request = buildHttpRequest(
            method = "POST",
            path = path,
            mode = mode,
            auth = auth,
            contentType = "text/plain",
            body = ByteArray(0)
        )
        val conn = existingConn ?: connectionFactory()
        try {
            conn.send(request)
            runCatching { readHttpResponse(conn, MAX_CONTROL_BODY_BYTES) }
        } finally {
            runCatching { conn.forceCancel() }
        }
    }

    // MARK: - HTTP/1.1 framing helpers

    private fun buildHttpRequest(
        method: String,
        path: String,
        mode: SudokuHttpMaskMode,
        auth: String,
        contentType: String?,
        body: ByteArray
    ): ByteArray {
        val sb = StringBuilder(256)
        sb.append("$method $path HTTP/1.1\r\n")
        sb.append("Host: ${settings.hostHeader}\r\n")
        sb.append("User-Agent: $USER_AGENT\r\n")
        sb.append("Accept: */*\r\n")
        sb.append("Accept-Language: en-US,en;q=0.9\r\n")
        sb.append("Cache-Control: no-cache\r\n")
        sb.append("Pragma: no-cache\r\n")
        sb.append("Connection: keep-alive\r\n")
        sb.append("X-Sudoku-Tunnel: ${mode.id}\r\n")
        sb.append("X-Sudoku-Version: 1\r\n")
        if (contentType != null) {
            sb.append("Content-Type: $contentType\r\n")
        }
        sb.append("Authorization: Bearer $auth\r\n")
        if (method == "POST" || body.isNotEmpty()) {
            sb.append("Content-Length: ${body.size}\r\n")
        }
        sb.append("\r\n")
        val headerBytes = sb.toString().toByteArray(Charsets.US_ASCII)
        return if (body.isEmpty()) headerBytes else headerBytes + body
    }

    private class HttpHeader(
        val statusCode: Int,
        val headers: Map<String, String>,
        val contentLength: Int?,
        val isChunked: Boolean,
        val connectionClose: Boolean
    )

    private class HttpResponse(
        val header: HttpHeader,
        val body: ByteArray
    )

    private suspend fun readHttpResponseHeader(conn: Transport): Pair<HttpHeader, ByteArray> {
        val buffer = ByteArrayOutputStream()
        while (buffer.size() < MAX_HEADER_BYTES) {
            val chunk = conn.receive()
                ?: throw SudokuError.HttpMaskFailed("EOF reading HTTP response header")
            if (chunk.isEmpty()) {
                throw SudokuError.HttpMaskFailed("EOF reading HTTP response header")
            }
            buffer.write(chunk)
            val bytes = buffer.toByteArray()
            val headerEnd = findCrLfCrLf(bytes)
            if (headerEnd >= 0) {
                val headerText = String(bytes, 0, headerEnd, Charsets.US_ASCII)
                val leftoverBytes = bytes.copyOfRange(headerEnd + 4, bytes.size)
                return parseHttpHeader(headerText) to leftoverBytes
            }
        }
        throw SudokuError.HttpMaskFailed("HTTP response header too large")
    }

    private suspend fun readHttpResponse(conn: Transport, maxBodyBytes: Int): HttpResponse {
        val (header, initialBody) = readHttpResponseHeader(conn)
        val reader = BufferedTransportReader(conn, initialBody)
        val body = when {
            header.isChunked -> {
                val out = ByteArrayOutputStream()
                while (true) {
                    val sizeLine = reader.readCrLfLine(MAX_CHUNK_HEADER_BYTES)
                        ?: throw SudokuError.HttpMaskFailed("truncated chunked response")
                    val sizeHex = sizeLine.substringBefore(';').trim()
                    val chunkSize = sizeHex.toIntOrNull(16)
                        ?: throw SudokuError.HttpMaskFailed("invalid chunk size: $sizeHex")
                    if (chunkSize == 0) {
                        while (true) {
                            val trailer = reader.readCrLfLine(MAX_HEADER_BYTES) ?: break
                            if (trailer.isEmpty()) break
                        }
                        break
                    }
                    if (chunkSize < 0 || out.size() + chunkSize > maxBodyBytes) {
                        throw SudokuError.HttpMaskFailed("HTTP response body too large")
                    }
                    val chunk = reader.readExact(chunkSize)
                        ?: throw SudokuError.HttpMaskFailed("truncated chunk body")
                    val crlf = reader.readExact(2)
                        ?: throw SudokuError.HttpMaskFailed("missing chunk CRLF")
                    if (crlf[0] != '\r'.code.toByte() || crlf[1] != '\n'.code.toByte()) {
                        throw SudokuError.HttpMaskFailed("invalid chunk CRLF")
                    }
                    out.write(chunk)
                }
                out.toByteArray()
            }
            header.contentLength != null -> {
                val len = header.contentLength
                if (len < 0 || len > maxBodyBytes) {
                    throw SudokuError.HttpMaskFailed("HTTP response body too large: $len")
                }
                if (len == 0) ByteArray(0)
                else reader.readExact(len)
                    ?: throw SudokuError.HttpMaskFailed("truncated HTTP response body")
            }
            else -> {
                val out = ByteArrayOutputStream()
                while (out.size() <= maxBodyBytes) {
                    val chunk = reader.readAvailable(maxBodyBytes - out.size() + 1) ?: break
                    out.write(chunk)
                }
                if (out.size() > maxBodyBytes) {
                    throw SudokuError.HttpMaskFailed("HTTP response body too large")
                }
                out.toByteArray()
            }
        }
        return HttpResponse(header, body)
    }

    private fun parseHttpHeader(text: String): HttpHeader {
        val lines = text.split("\r\n")
        val statusLine = lines.firstOrNull()
            ?: throw SudokuError.HttpMaskFailed("empty HTTP response header")
        val parts = statusLine.split(' ', limit = 3)
        if (parts.size < 2 || !parts[0].startsWith("HTTP/1.")) {
            throw SudokuError.HttpMaskFailed("bad HTTP status line: $statusLine")
        }
        val statusCode = parts[1].toIntOrNull()
            ?: throw SudokuError.HttpMaskFailed("bad HTTP status code: $statusLine")

        val headers = LinkedHashMap<String, String>()
        for (i in 1 until lines.size) {
            val line = lines[i]
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val key = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            headers[key] = value
        }
        val contentLength = headers["content-length"]?.toIntOrNull()
        val isChunked = headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true
        val connectionClose = headers["connection"]?.lowercase()?.contains("close") == true
        return HttpHeader(
            statusCode = statusCode,
            headers = headers,
            contentLength = contentLength,
            isChunked = isChunked,
            connectionClose = connectionClose
        )
    }

    private class BufferedTransportReader(
        private val transport: Transport,
        initial: ByteArray
    ) {
        private var buffer = initial
        private var offset = 0

        suspend fun readAvailable(maxBytes: Int): ByteArray? {
            if (maxBytes <= 0) return ByteArray(0)
            val available = buffer.size - offset
            if (available > 0) {
                val count = minOf(maxBytes, available)
                val out = buffer.copyOfRange(offset, offset + count)
                offset += count
                compactIfEmpty()
                return out
            }
            val next = transport.receive() ?: return null
            if (next.isEmpty()) return null
            if (next.size <= maxBytes) return next
            buffer = next
            offset = maxBytes
            return next.copyOf(maxBytes)
        }

        suspend fun readExact(count: Int): ByteArray? {
            if (count == 0) return ByteArray(0)
            val out = ByteArray(count)
            var have = 0
            while (have < count) {
                val chunk = readAvailable(count - have) ?: return null
                chunk.copyInto(out, have)
                have += chunk.size
            }
            return out
        }

        suspend fun readCrLfLine(maxBytes: Int): String? {
            val lineOut = ByteArrayOutputStream()
            while (lineOut.size() <= maxBytes) {
                val b = readExact(1) ?: return if (lineOut.size() == 0) null else {
                    throw SudokuError.HttpMaskFailed("truncated CRLF line")
                }
                val byte = b[0]
                if (byte == '\n'.code.toByte()) {
                    val arr = lineOut.toByteArray()
                    val len = if (arr.isNotEmpty() && arr[arr.size - 1] == '\r'.code.toByte()) arr.size - 1 else arr.size
                    return String(arr, 0, len, Charsets.US_ASCII)
                }
                lineOut.write(byte.toInt())
            }
            throw SudokuError.HttpMaskFailed("CRLF line exceeds $maxBytes bytes")
        }

        private fun compactIfEmpty() {
            if (offset >= buffer.size) {
                buffer = ByteArray(0)
                offset = 0
            }
        }
    }

    private companion object {
        const val USER_AGENT = "Mozilla/5.0"
        const val MAX_HEADER_BYTES = 64 * 1024
        const val MAX_CHUNK_HEADER_BYTES = 1024
        const val MAX_CONTROL_BODY_BYTES = 64 * 1024
        const val MAX_HTTP_BODY_BYTES = 16 * 1024 * 1024
        const val MAX_POLL_LINE_BYTES = 256 * 1024
        const val MAX_POLL_BATCH_BYTES = 49_152
        const val MAX_STREAM_BATCH_BYTES = 262_144
        const val DEFAULT_RECEIVE_MAX = 64 * 1024

        private val random = SecureRandom()

        fun findCrLfCrLf(bytes: ByteArray): Int {
            for (i in 0..bytes.size - 4) {
                if (bytes[i] == '\r'.code.toByte() &&
                    bytes[i + 1] == '\n'.code.toByte() &&
                    bytes[i + 2] == '\r'.code.toByte() &&
                    bytes[i + 3] == '\n'.code.toByte()
                ) {
                    return i
                }
            }
            return -1
        }

        fun decodeBase64Url(text: String): ByteArray? = try {
            Base64.getUrlDecoder().decode(text.trim())
        } catch (_: IllegalArgumentException) {
            null
        }

        fun randomSeed(): Long {
            val bytes = ByteArray(8).also { random.nextBytes(it) }
            var value = 0L
            for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
            return value
        }

        fun randomNonZeroUInt32(): Long {
            while (true) {
                val bytes = ByteArray(4).also { random.nextBytes(it) }
                var value = 0L
                for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
                if (value != 0L && value != 0xFFFFFFFFL) return value
            }
        }

        fun randomNonZeroUInt64(): Long {
            while (true) {
                val bytes = ByteArray(8).also { random.nextBytes(it) }
                var value = 0L
                for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
                if (value != 0L && value != -1L) return value
            }
        }
    }
}
