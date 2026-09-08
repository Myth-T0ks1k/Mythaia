package com.mythaia.vpn.protocol.vless.encryption

import com.mythaia.vpn.protocol.ProxyConnection
import com.mythaia.vpn.util.MythaiaLogger
import kotlinx.coroutines.delay
import java.security.SecureRandom

private val logger = MythaiaLogger("VlessEncryption")

/**
 * The client side of the post-quantum VLESS encryption handshake, and the
 * factory that hands back an encrypting/decrypting connection once it is done.
 *
 * A dial does one of two things. With a cached ticket and 0-RTT enabled it
 * replays the ticket: the client hello and the first application record leave
 * together, betting the ticket still holds. Otherwise it runs the full exchange
 * — offer a hybrid ML-KEM-768 + X25519 public key inside a relay block keyed to
 * the server's advertised keys, read the server's own PFS reply, and derive the
 * record keys from both halves plus the relay secret.
 *
 * This class owns only the handshake and key schedule; the record framing, the
 * counting nonce, and the optional header masking live in the connection it
 * returns. It touches no [com.mythaia.vpn.protocol.vless.VlessClient] state, so
 * an integrator wires it in by handing it the transport connection and using the
 * connection it returns in place of the transport.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class VlessEncryptionClient(
    private val config: VlessEncryptionConfig,
    host: String,
    port: Int,
    private val cache: VlessEncryption0RttCache = VlessEncryption0RttCache.shared
) {

    private val padding = VlessEncryptionPadding.parse(config.padding)
    private val xorMode = config.xorMode
    private val seconds = config.seconds
    private val cacheKey = VlessEncryption0RttCache.cacheKey(host, port, config)
    private val relayBuilder = RelayBlockBuilder(config.publicKeys, xorMode)
    private val random = SecureRandom()

    /**
     * Runs the handshake over [connection] and returns a connection that seals
     * and opens every byte after it. Chooses 0-RTT when a live ticket is cached.
     */
    suspend fun handshake(connection: ProxyConnection): ProxyConnection {
        val cached = if (seconds > 0u) cache.lookup(cacheKey) else null
        if (cached != null) {
            logger.debug("VLESS encryption: 0-RTT handshake")
            return sendClientHello0RTT(connection, cached)
        }
        logger.debug("VLESS encryption: 1-RTT handshake")
        val state = sendClientHello1RTT(connection)
        return readServerHello(connection, state)
    }

    private fun generateIV(): ByteArray = ByteArray(VlessWire.IV_LENGTH).also { random.nextBytes(it) }

    // MARK: - 0-RTT

    /**
     * 0-RTT client hello: `iv || relays || seal(len(32)) || seal(ticket)`,
     * prepended to the first application record so no round trip is spent.
     */
    private fun sendClientHello0RTT(
        connection: ProxyConnection,
        cached: VlessEncryption0RttCache.Entry
    ): ProxyConnection {
        val iv = generateIV()
        val relay = relayBuilder.build(iv)
        val nfsAead = VlessRecordAead(iv, relay.nfsKey)

        val sealedLength = nfsAead.seal(VlessLengthPrefix.encode(VlessWire.ENCRYPTED_TICKET_LENGTH), null)
        val sealedTicket = nfsAead.seal(cached.ticket, null)

        val clientHello = iv + relay.bytes + sealedLength + sealedTicket

        val unitedKey = cached.pfsKey + relay.nfsKey
        // The write key is contexted on the sealed ticket, which the server can
        // reproduce, rather than on a PFS public it has not yet been sent.
        val writeAead = VlessRecordAead(sealedTicket, unitedKey)

        var xorConnection: VlessXorConnection? = null
        var transport: ProxyConnection = connection
        if (xorMode == VlessEncryptionConfig.XorMode.RANDOM) {
            // outSkip leaves the unmasked prelude alone; inSkip=16 passes the
            // server random through so the record layer can key on it.
            val xor = VlessXorConnection(
                inner = connection,
                outCtr = VlessEncryptionCtr(unitedKey, iv),
                inCtr = null,
                outSkip = clientHello.size,
                inSkip = VlessWire.IV_LENGTH
            )
            xorConnection = xor
            transport = xor
        }

        val zeroRtt = VlessEncryptedConnection.ZeroRttState(unitedKey, cached.pfsKey, cacheKey)
        return VlessEncryptedConnection(
            inner = transport,
            writeAead = writeAead,
            readAead = null,
            unitedKey = unitedKey,
            preludeBytes = clientHello,
            pendingServerPaddingLength = 0,
            carryOverBytes = ByteArray(0),
            xorConnection = xorConnection,
            zeroRttState = zeroRtt,
            cache = cache
        )
    }

    // MARK: - 1-RTT

    private class InFlightHandshake(
        val iv: ByteArray,
        val nfsKey: ByteArray,
        val pfs: PfsKeyPair,
        val pfsPublic: ByteArray,
        val nfsAead: VlessRecordAead
    )

    /** Builds the 1-RTT client hello, sends it in padded fragments, returns the mid-state. */
    private suspend fun sendClientHello1RTT(connection: ProxyConnection): InFlightHandshake {
        val iv = generateIV()
        val relay = relayBuilder.build(iv)
        val nfsAead = VlessRecordAead(iv, relay.nfsKey)

        val pfs = VlessHybridCrypto.generatePfsKeyPair()
        val pfsPublic = pfs.publicBytes // 1184 + 32

        // Every length frame encodes the SEALED body size (plaintext + tag), the
        // exact count the server reads next.
        val sealedLengthFrame = nfsAead.seal(
            VlessLengthPrefix.encode(VlessWire.PFS_CLIENT_HELLO_PAYLOAD_LENGTH + VlessWire.AEAD_TAG_LENGTH),
            null
        )
        val sealedPfsPublic = nfsAead.seal(pfsPublic, null)

        val materialized = padding.materialize(random)
        val paddingPayloadLength = maxOf(materialized.totalLength - 18 - 16, 0)
        val paddingPayload = ByteArray(paddingPayloadLength)
        val sealedPaddingLength = nfsAead.seal(
            VlessLengthPrefix.encode(paddingPayloadLength + VlessWire.AEAD_TAG_LENGTH),
            null
        )
        val sealedPaddingBody = nfsAead.seal(paddingPayload, null)

        val clientHello =
            iv + relay.bytes + sealedLengthFrame + sealedPfsPublic + sealedPaddingLength + sealedPaddingBody

        // The first fragment absorbs the pre-padding prefix so the leading wire
        // bytes look like a plausible run rather than a fixed-size block.
        val fragmentLengths = materialized.lengths.toMutableList()
        if (fragmentLengths.isNotEmpty()) {
            val prePadding = clientHello.size - materialized.totalLength
            fragmentLengths[0] = prePadding + fragmentLengths[0]
        } else {
            fragmentLengths.add(clientHello.size)
        }

        sendFragments(connection, clientHello, fragmentLengths, materialized.gapsMs)
        return InFlightHandshake(iv, relay.nfsKey, pfs, pfsPublic, nfsAead)
    }

    /** Sends [buffer] in `lengths`-sized fragments, pausing `gaps[i]` ms after each. */
    private suspend fun sendFragments(
        connection: ProxyConnection,
        buffer: ByteArray,
        lengths: List<Int>,
        gaps: List<Long>
    ) {
        var remaining = buffer
        for (index in lengths.indices) {
            val length = minOf(lengths[index], remaining.size)
            if (length > 0) {
                connection.sendRaw(remaining.copyOfRange(0, length))
                remaining = remaining.copyOfRange(length, remaining.size)
            }
            val gap = if (index < gaps.size) gaps[index] else 0L
            if (gap > 0) delay(gap)
        }
        if (remaining.isNotEmpty()) connection.sendRaw(remaining)
    }

    // MARK: - Server hello

    /** Reads the server PFS hello, derives the session keys, then the ticket and padding. */
    private suspend fun readServerHello(
        connection: ProxyConnection,
        state: InFlightHandshake
    ): ProxyConnection {
        val reader = ByteReader(connection)
        val sealedServerPfs = reader.readExact(VlessWire.PFS_SERVER_HELLO_LENGTH)
        // The server seals its PFS hello with the all-ones nonce, so it can never
        // collide with the client's forward-counting nfs records on the same key.
        val serverPfsPublic = state.nfsAead.open(
            sealedServerPfs,
            ByteArray(VlessWire.NONCE_LENGTH) { 0xFF.toByte() },
            null
        )
        if (serverPfsPublic.size != VlessWire.MLKEM_CIPHERTEXT_LENGTH + 32) {
            throw VlessEncryptionError.HandshakeFailed("PFS server hello has wrong length")
        }
        val mlkemCiphertext = serverPfsPublic.copyOfRange(0, VlessWire.MLKEM_CIPHERTEXT_LENGTH)
        val x25519PubBytes = serverPfsPublic.copyOfRange(
            VlessWire.MLKEM_CIPHERTEXT_LENGTH, serverPfsPublic.size
        )

        val mlkemSecret = VlessHybridCrypto.mlkemDecapsulate(state.pfs.mlkemPrivate, mlkemCiphertext)
        val x25519Secret = VlessHybridCrypto.x25519Agreement(state.pfs.x25519Private, x25519PubBytes)

        val pfsKey = mlkemSecret + x25519Secret
        val unitedKey = deriveUnitedKey(mlkemSecret, x25519Secret, state.nfsKey)

        // Both record keys are contexted on the plaintext PFS public bytes: the
        // client's for writing, the server's for reading.
        val writeAead = VlessRecordAead(state.pfsPublic, unitedKey)
        val readAead = VlessRecordAead(serverPfsPublic, unitedKey)

        return readTicketAndPadding(reader, connection, state, pfsKey, unitedKey, writeAead, readAead)
    }

    private suspend fun readTicketAndPadding(
        reader: ByteReader,
        connection: ProxyConnection,
        state: InFlightHandshake,
        pfsKey: ByteArray,
        unitedKey: ByteArray,
        writeAead: VlessRecordAead,
        readAead: VlessRecordAead
    ): ProxyConnection {
        val sealedTicket = reader.readExact(VlessWire.ENCRYPTED_TICKET_LENGTH)
        val ticketPayload = readAead.open(sealedTicket, null)
        // The first two bytes are a big-endian seconds TTL; zero means no
        // resumption. The cached ticket is the whole 16-byte plaintext body.
        if (seconds > 0u && ticketPayload.size >= 16) {
            val serverSeconds = VlessLengthPrefix.decode(ticketPayload)
            if (serverSeconds > 0) {
                val expireMs = System.currentTimeMillis() + serverSeconds.toLong() * 1000L
                cache.store(cacheKey, pfsKey, ticketPayload.copyOfRange(0, 16), expireMs)
            }
        }

        val sealedLength = reader.readExact(VlessWire.SEALED_LENGTH_FRAME)
        val lenBytes = readAead.open(sealedLength, null)
        if (lenBytes.size < 2) {
            throw VlessEncryptionError.ProtocolViolation(
                "framing: server sealed length frame too short: ${lenBytes.size} bytes"
            )
        }
        // The decoded value is the SEALED padding body size (plaintext + tag).
        val sealedPaddingBodySize = VlessLengthPrefix.decode(lenBytes)
        // Over-read bytes are unmasked padding tail; they bypass the XOR wrapper.
        val leftover = reader.drain()

        var xorConnection: VlessXorConnection? = null
        var transport: ProxyConnection = connection
        if (xorMode == VlessEncryptionConfig.XorMode.RANDOM) {
            val xor = VlessXorConnection(
                inner = connection,
                outCtr = VlessEncryptionCtr(unitedKey, state.iv),
                inCtr = VlessEncryptionCtr(unitedKey, ticketPayload.copyOfRange(0, 16)),
                outSkip = 0,
                // The XOR wrapper must not re-skip the padding tail that already
                // bypassed it as carry-over; only the part still on the wire.
                inSkip = maxOf(0, sealedPaddingBodySize - leftover.size)
            )
            xorConnection = xor
            transport = xor
        }

        return VlessEncryptedConnection(
            inner = transport,
            writeAead = writeAead,
            readAead = readAead,
            unitedKey = unitedKey,
            preludeBytes = null,
            pendingServerPaddingLength = sealedPaddingBodySize,
            carryOverBytes = leftover,
            xorConnection = xorConnection,
            zeroRttState = null,
            cache = cache
        )
    }

    /** A buffered fixed-size reader over a [ProxyConnection]. */
    private class ByteReader(private val connection: ProxyConnection) {
        private var buffer = ByteArray(0)

        suspend fun readExact(count: Int): ByteArray {
            while (buffer.size < count) {
                val data = connection.receiveRaw()
                if (data == null || data.isEmpty()) {
                    throw VlessEncryptionError.ConnectionClosed()
                }
                buffer += data
            }
            val head = buffer.copyOfRange(0, count)
            buffer = buffer.copyOfRange(count, buffer.size)
            return head
        }

        /** Everything read past the last [readExact], handed to the record layer. */
        fun drain(): ByteArray {
            val snapshot = buffer
            buffer = ByteArray(0)
            return snapshot
        }
    }
}
