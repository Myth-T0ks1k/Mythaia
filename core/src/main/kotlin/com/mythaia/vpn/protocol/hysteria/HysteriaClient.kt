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
import com.mythaia.vpn.protocol.quic.QuicUdpFlow
import com.mythaia.vpn.protocol.quic.UdpReassembler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

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

    private val udpScope = CoroutineScope(SupervisorJob() + Dispatchers.IO + com.mythaia.vpn.tunnelCrashGuard)
    private val udpFlows = ConcurrentHashMap<Long, QuicUdpFlow>()
    private val nextUdpSession = AtomicLong((System.nanoTime() and 0x7FFF_FFFFL))
    private val nextPacketId = AtomicInteger(0)
    private val reassembler = UdpReassembler()

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

        try {
            stream.send(
                HysteriaProtocol.encodeTcpRequest(HysteriaProtocol.formatAddress(host, port))
            )

            val (response, leftover) = readTcpResponse(stream)
            if (response.status != HysteriaProtocol.TCP_RESPONSE_STATUS_OK) {
                throw ProxyError.ProtocolError("Hysteria refused $host:$port: ${response.message}")
            }

            if (initialData != null && initialData.isNotEmpty()) {
                stream.send(initialData)
            }
            // Bytes that arrived in the same stream chunk as the TCPResponse are
            // the start of the proxied payload — a server-first banner (SSH,
            // SMTP, IMAP, MySQL). They are handed back as the first receive()
            // rather than dropped.
            return if (leftover.isEmpty()) stream else HysteriaTcpConnection(stream, leftover)
        } catch (e: Throwable) {
            // A refusal, a read that never completed, or a failed send all leave
            // the stream open in the session otherwise.
            stream.cancel()
            throw e
        }
    }

    /**
     * Opens a UDP flow to [host]:[port], carried in QUIC datagrams.
     *
     * Each flow is a Hysteria UDP session of its own: a 32-bit id the server
     * answers under, with no setup message — the first datagram opens it, and
     * the server forgets it after its idle timeout.
     */
    suspend fun connectUDP(host: String, port: Int): ProxyConnection {
        ensureSession()
        if (!udpEnabled) throw ProxyError.ProtocolError("Hysteria: the server does not relay UDP")
        val id = nextUdpSession.incrementAndGet() and 0xFFFF_FFFFL
        val address = HysteriaProtocol.formatAddress(host, port)
        val flow = QuicUdpFlow(
            scope = udpScope,
            transmit = { payload -> sendUdp(id, address, payload) },
            onClose = { udpFlows.remove(id) }
        )
        udpFlows[id] = flow
        return flow
    }

    /**
     * One UDP payload as one datagram, or as numbered fragments when it does
     * not fit — QUIC Initial packets from an app are 1200+ bytes on their own.
     */
    private suspend fun sendUdp(sessionId: Long, address: String, payload: ByteArray) {
        val session = ensureSession()
        val room = datagramLimit(session) - HysteriaProtocol.udpHeaderSize(address)
        val packetId = nextPacketId.getAndIncrement() and 0xFFFF
        if (payload.size <= room) {
            if (!session.sendDatagram(HysteriaProtocol.UdpMessage(sessionId, packetId, 0, 1, address, payload).encode())) {
                logger.debug("[Hysteria] UDP datagram dropped, QUIC connection gone (${payload.size} bytes to $address)")
            }
            return
        }
        val count = (payload.size + room - 1) / room
        if (count > HysteriaProtocol.MAX_FRAGMENTS) throw ProxyError.ProtocolError("Hysteria: UDP payload too large")
        for (index in 0 until count) {
            val piece = payload.copyOfRange(index * room, minOf(payload.size, (index + 1) * room))
            session.sendDatagram(
                HysteriaProtocol.UdpMessage(sessionId, packetId, index, count, address, piece).encode()
            )
        }
    }

    /** Routes a datagram from the server to its flow, reassembling fragments. */
    private fun onDatagram(bytes: ByteArray) {
        val message = HysteriaProtocol.decodeUdpMessage(bytes) ?: run {
            logger.debug("[Hysteria] undecodable datagram (${bytes.size} bytes)")
            return
        }
        val flow = udpFlows[message.sessionId] ?: return
        val key = (message.sessionId shl 16) or message.packetId.toLong()
        val whole = reassembler.add(key, message.fragId, message.fragCount, message.payload) ?: return
        flow.deliver(whole)
    }

    /** Drops the QUIC session; the next dial brings a new one up. Flows survive. */
    private fun resetSession() {
        http3?.close()
        http3 = null
        quic?.close()
        quic = null
    }

    /** Ends everything: the session, every UDP flow, and the flows' scope. */
    fun close() {
        resetSession()
        udpFlows.values.toList().forEach { it.cancel() }
        udpFlows.clear()
        udpScope.cancel()
    }

    // MARK: - Session

    private suspend fun ensureSession(): QuicConnection = lock.withLock {
        quic?.takeIf { it.isConnected }?.let { return it }

        resetSession()

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
            pinnedCertSha256 = tls?.pinnedCertSha256,
            verifyName = tls?.verifyName,
            obfuscator = obfuscation?.let { HysteriaObfuscator.of(it) }
        )
        // Registered before the handshake so no reply to a UDP flow is lost
        // to a session that is still coming up.
        connection.onDatagramReceived = ::onDatagram
        if (!connection.connect()) {
            connection.close()
            throw ProxyError.ProtocolError("Hysteria: QUIC handshake failed")
        }

        // Plain SETTINGS: with H3_DATAGRAM announced, the server's HTTP/3 layer
        // takes every QUIC datagram for itself and UDP relaying goes silent.
        val h3 = Http3Connection(connection, com.mythaia.vpn.protocol.http3.Http3Framer.PLAIN_CLIENT_SETTINGS)
        if (!h3.start()) {
            connection.close()
            throw ProxyError.ProtocolError("Hysteria: could not start HTTP/3")
        }

        try {
            authenticate(h3)
        } catch (e: Throwable) {
            // The QUIC connection (socket, read/timer threads, ngtcp2 handle)
            // and the HTTP/3 layer would otherwise leak until idle timeout, and
            // every later dial would build and leak another.
            h3.close()
            connection.close()
            throw e
        }

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
     * Reads the proxy's answer to a TCP request, and whatever followed it.
     *
     * The response is variable-length and arrives on a stream, so it can be
     * split across reads; the parser says how much it needs rather than
     * guessing from what is there. The last read often carries the response
     * *and* the first of the proxied payload, so the bytes past the response
     * are returned too rather than thrown away.
     */
    private suspend fun readTcpResponse(stream: QuicStream): Pair<HysteriaProtocol.TcpResponse, ByteArray> {
        var buffer = ByteArray(0)
        while (true) {
            HysteriaProtocol.parseTcpResponse(buffer)?.let { response ->
                val leftover = buffer.copyOfRange(response.consumed, buffer.size)
                return response to leftover
            }
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

        /**
         * The Hysteria UDP message size assumed while QUIC cannot say yet:
         * one that fits a packet on any path after the packet header, AEAD
         * tag and frame header.
         */
        const val MAX_UDP_DATAGRAM = 1100

        /**
         * The largest Hysteria UDP message sent whole: what one QUIC packet
         * carries on this path now, as the official client sends. Messages
         * over it are split into fragments, which some servers (Xray's) never
         * reassemble, so splitting below it lost every large call packet there.
         */
        fun datagramLimit(session: com.mythaia.vpn.protocol.quic.QuicConnection): Int =
            session.maxDatagramPayload().takeIf { it > 0 } ?: MAX_UDP_DATAGRAM
    }
}

/**
 * A proxied TCP stream whose first [receiveRaw] hands back the payload bytes
 * that rode in behind the Hysteria TCPResponse before it reads the stream.
 *
 * Without this a server-first protocol loses its opening banner: the bytes
 * after the response, delivered in the same QUIC stream chunk, would be
 * discarded with the parse buffer.
 */
internal class HysteriaTcpConnection(
    private val stream: ProxyConnection,
    leftover: ByteArray
) : ProxyConnection() {

    private var pending: ByteArray? = leftover.takeIf { it.isNotEmpty() }
    private val pendingLock = Any()

    override val isConnected: Boolean get() = stream.isConnected

    override suspend fun sendRaw(data: ByteArray) = stream.sendRaw(data)
    override fun sendRawAsync(data: ByteArray) = stream.sendRawAsync(data)

    override suspend fun receiveRaw(): ByteArray? {
        synchronized(pendingLock) {
            val held = pending
            if (held != null) {
                pending = null
                return held
            }
        }
        return stream.receiveRaw()
    }

    override fun cancel() = stream.cancel()
}
