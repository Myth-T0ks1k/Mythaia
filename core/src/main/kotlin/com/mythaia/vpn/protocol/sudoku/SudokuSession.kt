package com.mythaia.vpn.protocol.sudoku

import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.TunneledTransport
import com.mythaia.vpn.util.MythaiaLogger
import com.mythaia.vpn.util.NioSocket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

private val logger = MythaiaLogger("Sudoku")

/**
 * One authenticated Sudoku connection: a socket, the obfuscation and record
 * layers stacked on it, and the KIP exchange that keys them.
 *
 * A Sudoku connection in this build carries exactly one proxied flow. That is the
 * shape the protocol supports without its multiplexer: the KIP request that opens
 * the connection also names what it is for — a TCP destination, or a
 * UDP-over-TCP flow — and the record stream then *is* that flow, in both
 * directions. There is therefore no registry of shared sessions here as
 * [com.mythaia.vpn.protocol.nowhere.NowhereSession] keeps, because nothing is
 * shared: two dials to two destinations are two connections. Sharing a single
 * connection across flows is what the mux carrier does, and that is not wired yet
 * (see [SudokuClient]); replicating a shared-session registry over a
 * single-flow carrier would only invite two dials to fight over one stream.
 *
 * What is kept is the phase machine, so a half-built connection is torn down
 * cleanly whatever step failed, and the split between the pure handshake bytes
 * [SudokuHandshake] and the live exchange driven here.
 *
 * Authentication has no round trip of its own. The KIP client hello rides the
 * record layer keyed from the pre-shared key; the server's hello, arriving on the
 * same record layer, proves it holds that key and hands over the second half of
 * the X25519 exchange at once. Only then does the stream rekey to the session
 * secrets and the destination request go out.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal class SudokuSession(
    private val settings: SudokuConnectionSettings,
    private val tunnel: ProxyConnection?
) {

    private enum class Phase { IDLE, TRANSPORT_READY, AUTHENTICATED, CONNECTED, CLOSED }

    private val phase = AtomicReference(Phase.IDLE)

    @Volatile
    private var rawTransport: Transport? = null

    /** The authenticated flow, valid once [connectTcp] or [openUdp] has returned. */
    @Volatile
    var stream: SudokuRecordStream? = null
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
            val transport = openRawTransport()
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

            performKip(record)
            phase.set(Phase.AUTHENTICATED)
            logger.debug("[Sudoku] Authenticated with ${settings.serverHost}:${settings.serverPort}")
            return record
        } catch (e: Exception) {
            close()
            throw e
        }
    }

    private suspend fun openRawTransport(): Transport {
        val transport: Transport = if (tunnel != null) {
            TunneledTransport(tunnel)
        } else {
            NioSocket().also { it.connect(settings.serverHost, settings.serverPort) }
        }
        // The legacy mask prefix is plaintext and precedes the obfuscated stream,
        // so it is written straight to the socket rather than through the codec.
        settings.legacyMaskHeader?.let { transport.send(it) }
        return transport
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
