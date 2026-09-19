package com.mythaia.vpn.protocol.hysteria

import com.mythaia.data.model.ProxyConfiguration
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.data.model.ProxyError
import com.mythaia.vpn.protocol.http3.Http3Connection
import com.mythaia.vpn.protocol.http3.Http3FrameType
import com.mythaia.vpn.protocol.http3.Http3Framer
import com.mythaia.vpn.protocol.http3.QpackEncoder
import com.mythaia.vpn.protocol.quic.QuicConnection
import com.mythaia.vpn.protocol.quic.QuicStream
import com.mythaia.vpn.protocol.quic.QuicTuning
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

private val logger = MythaiaLogger("Hysteria")

/**
 * Hysteria2: a proxy that authenticates over HTTP/3 and then speaks its own
 * framing on plain QUIC streams.
 *
 * The shape is unusual and worth stating. The connection opens as ordinary
 * HTTP/3 and the client makes one request — a POST to `hysteria/auth` carrying
 * the password. That request exists to look like a website: a server that does
 * not recognise the credentials serves whatever it is masquerading as, so a
 * prober sees a real site rather than a refused proxy. Only after a 233 does
 * anything proxy-shaped happen, and from then on the streams carry Hysteria's
 * own framing rather than HTTP.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class HysteriaClient(private val configuration: ProxyConfiguration) {

    private val lock = Mutex()
    private var quic: QuicConnection? = null
    private var http3: Http3Connection? = null

    /** The rate the server told us to send at, from `Hysteria-CC-RX`. */
    @Volatile
    var serverReceiveBytesPerSecond: Long = 0
        private set

    /** Whether the server will carry UDP for us. */
    @Volatile
    var udpEnabled: Boolean = false
        private set

    // MARK: - Dial

    /**
     * Opens a proxied TCP stream to [host]:[port].
     *
     * The session is brought up on first use and shared afterwards, since a
     * Hysteria connection multiplexes every flow onto one QUIC connection —
     * which is where its speed comes from.
     */
    suspend fun connect(host: String, port: Int, initialData: ByteArray? = null): ProxyConnection {
        val session = ensureSession()

        val stream = session.openStream()
            ?: throw ProxyError.ProtocolError("Hysteria: no stream credit left")

        stream.send(
            HysteriaProtocol.encodeTcpRequest(HysteriaProtocol.formatAddress(host, port))
        )

        val response = readTcpResponse(stream)
        if (response.status != HysteriaProtocol.TCP_RESPONSE_STATUS_OK) {
            stream.cancel()
            throw ProxyError.ProtocolError("Hysteria refused $host:$port: ${response.message}")
        }

        if (initialData != null && initialData.isNotEmpty()) {
            stream.send(initialData)
        }
        return stream
    }

    fun close() {
        http3?.close()
        http3 = null
        quic?.close()
        quic = null
    }

    // MARK: - Session

    private suspend fun ensureSession(): QuicConnection = lock.withLock {
        quic?.takeIf { it.isConnected }?.let { return it }

        close()

        // NAIVE grants the unidirectional stream credit HTTP/3 needs for the
        // server's control stream, which is what the authentication rides on.
        val tuning = QuicTuning.NAIVE
        // The link's obfs/obfs-password; a type this build does not speak is
        // refused here rather than dialled in the clear.
        val obfuscation = HysteriaObfuscation.make(configuration.obfuscation, configuration.obfuscationPassword)
        if (obfuscation == null && !configuration.obfuscation.isNullOrEmpty()) {
            throw ProxyError.ProtocolError("Hysteria: unsupported obfuscation ${configuration.obfuscation}")
        }
        val tls = configuration.tls
        val connection = QuicConnection(
            serverName = configuration.serverAddress,
            serverPort = configuration.serverPort.toInt(),
            alpn = listOf(ALPN),
            tuning = tuning,
            fingerprint = tls?.fingerprint ?: com.mythaia.data.model.TlsFingerprint.CHROME_133,
            tlsServerName = tls?.serverName?.takeIf { it.isNotBlank() } ?: configuration.serverAddress,
            allowInsecure = tls?.allowInsecure == true,
            obfuscator = obfuscation?.let { HysteriaObfuscator.of(it) }
        )
        if (!connection.connect()) {
            connection.close()
            throw ProxyError.ProtocolError("Hysteria: QUIC handshake failed")
        }

        val h3 = Http3Connection(connection)
        if (!h3.start()) {
            connection.close()
            throw ProxyError.ProtocolError("Hysteria: could not start HTTP/3")
        }

        authenticate(h3)

        quic = connection
        http3 = h3
        return connection
    }

    /**
     * The masquerading authentication request.
     *
     * A wrong password does not get an error — it gets whatever website the
     * server is pretending to be, which is the entire point. So anything that
     * is not 233 is treated as a refusal rather than parsed for a reason.
     */
    private suspend fun authenticate(h3: Http3Connection) {
        val password = configuration.password
            ?: configuration.trojanPassword
            ?: throw ProxyError.ProtocolError("Hysteria password not set")

        val headers = QpackEncoder.encodePostHeaders(
            authority = HysteriaProtocol.AUTH_AUTHORITY,
            path = HysteriaProtocol.AUTH_PATH,
            extraHeaders = HysteriaProtocol.authRequestHeaders(
                password = password,
                clientRxBytesPerSec = declaredReceiveRate()
            )
        )

        val stream = h3.request(headers, fin = true)
            ?: throw ProxyError.ProtocolError("Hysteria: no stream for authentication")

        val fields = readResponseHeaders(stream)
        stream.cancel()

        val status = fields[HysteriaProtocol.HEADER_STATUS]?.toIntOrNull()
        if (status != HysteriaProtocol.AUTH_SUCCESS_STATUS) {
            // Deliberately vague: the server is masquerading, and there is
            // nothing here that distinguishes a bad password from a host that
            // was never a Hysteria server.
            throw ProxyError.ProtocolError("Hysteria authentication refused")
        }

        udpEnabled = fields[HysteriaProtocol.HEADER_UDP]?.equals("true", ignoreCase = true) == true
        serverReceiveBytesPerSecond = parseReceiveRate(fields[HysteriaProtocol.HEADER_CC_RX])
        logger.debug("[Hysteria] Authenticated, udp=$udpEnabled, rx=$serverReceiveBytesPerSecond B/s")
    }

    /**
     * What this client says it can receive, in bytes per second.
     *
     * Zero means "you decide", which is what the header spells `auto`; the
     * protocol helper turns the number into the header's own vocabulary.
     */
    private fun declaredReceiveRate(): Long {
        val mbps = configuration.hysteriaDownMbps ?: 0
        return if (mbps <= 0) 0 else mbps * 125_000L
    }

    /** `auto` means the server decides, which this side reports as zero. */
    private fun parseReceiveRate(value: String?): Long = when {
        value == null -> 0
        value.equals(HysteriaProtocol.CC_RX_AUTO, ignoreCase = true) -> 0
        else -> value.toLongOrNull() ?: 0
    }

    // MARK: - Reading

    /** Reads until the response HEADERS frame is complete, then decodes it. */
    private suspend fun readResponseHeaders(stream: QuicStream): Map<String, String> {
        var buffer = ByteArray(0)
        while (true) {
            when (val result = Http3Framer.parse(buffer)) {
                is Http3Framer.ParseResult.Complete -> {
                    if (result.frame.knownType == Http3FrameType.HEADERS) {
                        return QpackEncoder.decodeHeaders(result.frame.payload)
                            ?.toMap()
                            ?: throw ProxyError.ProtocolError("Hysteria: unreadable response headers")
                    }
                    buffer = buffer.copyOfRange(result.bytesConsumed, buffer.size)
                    continue
                }
                is Http3Framer.ParseResult.Malformed ->
                    throw ProxyError.ProtocolError("Hysteria: ${result.reason}")
                Http3Framer.ParseResult.Incomplete -> Unit
            }
            val chunk = stream.receive()
                ?: throw ProxyError.ProtocolError("Hysteria: connection closed during authentication")
            buffer += chunk
        }
    }

    /**
     * Reads the proxy's answer to a TCP request.
     *
     * The response is variable-length and arrives on a stream, so it can be
     * split across reads; the parser says how much it needs rather than
     * guessing from what is there.
     */
    private suspend fun readTcpResponse(stream: QuicStream): HysteriaProtocol.TcpResponse {
        var buffer = ByteArray(0)
        while (true) {
            HysteriaProtocol.parseTcpResponse(buffer)?.let { return it }
            val chunk = stream.receive()
                ?: throw ProxyError.ProtocolError("Hysteria: connection closed before a response")
            buffer += chunk
            if (buffer.size > MAX_RESPONSE) {
                throw ProxyError.ProtocolError("Hysteria: response never completed")
            }
        }
    }

    private companion object {
        const val ALPN = "h3"
        const val MAX_RESPONSE = 8192
    }
}
