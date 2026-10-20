package com.mythaia.vpn.protocol.sudoku

import com.mythaia.data.model.TlsVersion
import com.mythaia.data.model.WebSocketConfiguration
import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.protocol.tls.TlsClient
import com.mythaia.vpn.protocol.tls.TlsRecordTransport
import com.mythaia.vpn.protocol.websocket.WebSocketConnection
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.NioSocket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

private val logger = MythaiaLogger("Sudoku")

/**
 * One authenticated Sudoku connection: the carrier beneath it (plain TCP, TLS,
 * WebSocket camouflage, or the split HTTP `stream`/`poll`/`auto` tunnel), the
 * obfuscation and record layers stacked on it, and the KIP exchange that keys
 * them.
 *
 * Authentication has no round trip of its own. The KIP client hello rides the
 * record layer keyed from the pre-shared key; the server's hello, arriving on the
 * same record layer, proves it holds that key and hands over the second half of
 * the X25519 exchange at once. On the split HTTP-mask tunnel (`stream`/`poll`/`auto`),
 * the KIP exchange can ride the `/session?ed=...` request/response body so the
 * record layer is rekeyed to the session secrets before the first `/stream` or
 * `/api/v1/upload` frame is sent.
 *
 * Once authenticated, the session enters one of three modes:
 * - [connectTcp]: sends `KIP_CONNECT_TCP` (`0x10`) and carries one TCP stream.
 * - [openUdp]: sends `KIP_OPEN_UDP_OVER_TCP` (`0x12`) and carries UoT datagrams.
 * - [openMux]: sends `KIP_OPEN_MUX` (`0x11`) so [SudokuMuxSession] can multiplex
 *   many TCP streams over the single record stream.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuSession(
    val settings: SudokuConnectionSettings,
    private val tunnel: ProxyConnection? = null,
    private val rawTransportFactory: (suspend () -> Transport)? = null
) {

    private enum class Phase { IDLE, TRANSPORT_READY, AUTHENTICATED, CONNECTED, CLOSED }

    private val phase = AtomicReference(Phase.IDLE)
    private val tunnelConsumed = AtomicBoolean(false)

    @Volatile
    private var rawTransport: Transport? = null

    /** The authenticated flow, valid once [connectTcp], [openUdp], or [openMux] has returned. */
    @Volatile
    var stream: SudokuRecordStream? = null
        private set

    /** The outer TLS version when `httpMask.tls` is enabled, or null over plain TCP. */
    @Volatile
    var outerTlsVersion: TlsVersion? = null
        private set

    val isConnected: Boolean
        get() = phase.get() != Phase.CLOSED && stream != null

    /**
     * Opens the connection, authenticates, and asks the server to dial
     * [host]:[port]; [initialData], when present, follows the request as the
     * flow's first bytes.
     */
    suspend fun connectTcp(host: String, port: Int, initialData: ByteArray?) {
        val record = openAndAuthenticate()
        record.send(SudokuHandshake.connectTcpRequest(host, port))
        // The connect request carries no answer of its own — success is the flow
        // working — so the initial data can go out right behind it.
        if (initialData != null && initialData.isNotEmpty()) {
            record.send(initialData)
        }
        phase.set(Phase.CONNECTED)
    }

    /** Opens the connection, authenticates, and starts a UDP-over-TCP flow. */
    suspend fun openUdp() {
        val record = openAndAuthenticate()
        record.send(SudokuHandshake.openUdpRequest())
        phase.set(Phase.CONNECTED)
    }

    /** Opens the connection, authenticates, and switches the record stream into multiplexed mode. */
    suspend fun openMux(): SudokuRecordStream {
        val record = openAndAuthenticate()
        record.send(SudokuHandshake.openMuxRequest())
        phase.set(Phase.CONNECTED)
        return record
    }

    /** Tears the connection down; safe to call more than once. */
    fun close() {
        if (phase.getAndSet(Phase.CLOSED) == Phase.CLOSED) return
        // Closing the record closes the obfuscation shell and the socket under
        // it; if we never got that far, the raw transport still needs releasing.
        val record = stream
        if (record != null) {
            record.close()
        } else {
            runCatching { rawTransport?.forceCancel() }
        }
        stream = null
        rawTransport = null
    }

    // MARK: - Bring-up

    private suspend fun openAndAuthenticate(): SudokuRecordStream {
        if (phase.get() != Phase.IDLE) {
            throw SudokuError.ProtocolViolation("Sudoku session already used")
        }
        try {
            val (transport, earlyBases) = openCarrierTransport()
            rawTransport = transport

            // One generator drives the whole uplink; it is seeded from system
            // entropy, then spends its first draw picking this connection's
            // padding rate, exactly as the reference does, before any byte is
            // encoded.
            val rng = SudokuXorshift64Star(randomSeed())
            val threshold = rng.pickPaddingThreshold(settings.paddingMin, settings.paddingMax)
            val tables = settings.tablePair
            val obfs = SudokuObfsTransport(
                transport = transport,
                uplink = tables.uplink,
                downlink = tables.downlink,
                pureDownlink = settings.pureDownlink,
                rng = rng,
                threshold = threshold
            )

            val bases = SudokuProtocol.pskBases(settings.psk)
            val record = SudokuRecordStream(
                obfs = obfs,
                method = settings.aeadMethod,
                baseSend = bases.clientToServer,
                baseRecv = bases.serverToClient
            )
            stream = record
            phase.set(Phase.TRANSPORT_READY)

            if (earlyBases != null) {
                record.rekey(earlyBases.clientToServer, earlyBases.serverToClient)
            } else {
                performKip(record)
            }
            phase.set(Phase.AUTHENTICATED)
            logger.debug("[Sudoku] Authenticated with ${settings.serverHost}:${settings.serverPort}")
            return record
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    private suspend fun openCarrierTransport(): Pair<Transport, SudokuProtocol.DirectionKeys?> {
        if (settings.usesHttpMaskTunnel) {
            val httpMask = SudokuHttpMaskTransport(
                settings = settings,
                enableEarlyHandshake = true,
                connectionFactory = { openSocketOrTlsTransport() }
            )
            httpMask.connect()
            return httpMask to httpMask.earlySessionBases
        }

        if (settings.usesWebSocketMask) {
            val underlying = openSocketOrTlsTransport()
            try {
                val unixSeconds = System.currentTimeMillis() / 1000L
                val auth = SudokuProtocol.httpMaskAuthToken(settings.psk, "ws", "GET", "/ws", unixSeconds)
                val path = SudokuProtocol.appendAuth(
                    SudokuProtocol.applyPathRoot(settings.httpMask.pathRoot, "/ws"),
                    auth
                )
                val wsConfig = WebSocketConfiguration(
                    host = settings.hostHeader,
                    path = path,
                    headers = mapOf(
                        "Accept" to "*/*",
                        "Accept-Language" to "en-US,en;q=0.9",
                        "Cache-Control" to "no-cache",
                        "Pragma" to "no-cache",
                        "X-Sudoku-Tunnel" to "ws",
                        "Authorization" to "Bearer $auth"
                    ),
                    heartbeatPeriod = 30u
                )
                val wsConnection = WebSocketConnection(transport = underlying, configuration = wsConfig)
                wsConnection.performUpgrade()
                val wsTransport = object : Transport {
                    override suspend fun send(data: ByteArray) = wsConnection.send(data)
                    override fun sendAsync(data: ByteArray) = wsConnection.sendAsync(data)
                    override suspend fun receive(): ByteArray? = wsConnection.receive()
                    override fun forceCancel() = wsConnection.cancel()
                }
                return wsTransport to null
            } catch (e: Exception) {
                runCatching { underlying.forceCancel() }
                throw e
            }
        }

        val transport = openSocketOrTlsTransport()
        try {
            // The legacy mask prefix is plaintext and precedes the obfuscated stream,
            // so it is written straight to the underlying transport rather than through the codec.
            settings.legacyMaskHeader?.let { transport.send(it) }
            return transport to null
        } catch (e: Exception) {
            runCatching { transport.forceCancel() }
            throw e
        }
    }

    private suspend fun openSocketOrTlsTransport(): Transport {
        val baseTransport: Transport = when {
            rawTransportFactory != null -> rawTransportFactory.invoke()
            tunnel != null && tunnelConsumed.compareAndSet(false, true) -> TunneledTransport(tunnel)
            else -> NioSocket().also { it.connect(settings.serverHost, settings.serverPort) }
        }
        val tlsConfig = settings.effectiveTlsConfiguration() ?: return baseTransport
        return try {
            val tlsClient = TlsClient(tlsConfig)
            val tlsConn = tlsClient.connect(baseTransport)
            outerTlsVersion = if (tlsConn.isTls13) TlsVersion.TLS13 else TlsVersion.TLS12
            TlsRecordTransport(tlsConn)
        } catch (e: Exception) {
            runCatching { baseTransport.forceCancel() }
            throw e
        }
    }

    /**
     * Runs the KIP exchange over [record] and rekeys it to the session secrets.
     *
     * The ephemeral key pair and the nonce are the only non-deterministic inputs,
     * so they are drawn here and everything else is handed to [SudokuHandshake].
     * A reply that is not a server hello ends the dial: a portal that refuses the
     * credentials says nothing, so a message that *is* something is a peer not
     * speaking KIP, not a slow one.
     */
    private suspend fun performKip(record: SudokuRecordStream) {
        val keyPair = X25519Crypto.generateKeyPair()
        val privateKey = keyPair.copyOf(32)
        val publicKey = keyPair.copyOfRange(32, 64)
        val nonce = ByteArray(SudokuProtocol.KIP_NONCE_SIZE).also { SecureRandom().nextBytes(it) }
        val unixSeconds = System.currentTimeMillis() / 1000L
        val tableHint = if (settings.sendsTableHint) settings.tablePair.hint else null

        val hello = SudokuHandshake.clientHelloFrame(
            keyFingerprintSource = settings.keyFingerprintSource,
            unixSeconds = unixSeconds,
            clientPublicKey = publicKey,
            nonce = nonce,
            tableHint = tableHint
        )
        record.send(hello)

        val reply = readKip(record)
        val serverPublicKey = when (val outcome =
            SudokuHandshake.classifyServerHello(reply.type, reply.payload, nonce)) {
            is SudokuHandshake.ServerHello.Ready -> outcome.publicKey
            is SudokuHandshake.ServerHello.Rejected ->
                throw SudokuError.ProtocolViolation(
                    "Sudoku server did not answer with a KIP hello (type 0x%02x)".format(outcome.type.toInt() and 0xFF)
                )
        }

        val shared = X25519Crypto.keyAgreement(privateKey, serverPublicKey)
        val session = SudokuProtocol.sessionBases(settings.psk, shared, nonce)
        record.rekey(session.clientToServer, session.serverToClient)
    }

    /** Reads one KIP message off the record stream. */
    private suspend fun readKip(record: SudokuRecordStream): SudokuProtocol.KipMessage {
        val header = record.readExact(SudokuProtocol.KIP_HEADER_SIZE)
            ?: throw SudokuError.ProtocolViolation("truncated KIP header")
        if (header[0] != SudokuProtocol.KIP_MAGIC[0] ||
            header[1] != SudokuProtocol.KIP_MAGIC[1] ||
            header[2] != SudokuProtocol.KIP_MAGIC[2]
        ) {
            throw SudokuError.ProtocolViolation("bad KIP magic")
        }
        val type = header[3]
        val length = ((header[4].toInt() and 0xFF) shl 8) or (header[5].toInt() and 0xFF)
        val payload = if (length == 0) {
            ByteArray(0)
        } else {
            record.readExact(length) ?: throw SudokuError.ProtocolViolation("truncated KIP payload")
        }
        return SudokuProtocol.KipMessage(type, payload, SudokuProtocol.KIP_HEADER_SIZE + length)
    }

    private fun randomSeed(): Long {
        val bytes = ByteArray(8).also { SecureRandom().nextBytes(it) }
        var value = 0L
        for (b in bytes) value = (value shl 8) or (b.toLong() and 0xFF)
        return value
    }
}
