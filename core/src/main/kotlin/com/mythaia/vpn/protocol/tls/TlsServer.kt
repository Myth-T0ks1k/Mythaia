package com.mythaia.vpn.protocol.tls

import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.mitm.ClientHelloParser
import com.mythaia.vpn.mitm.MitmLeafCertificates
import com.mythaia.vpn.mitm.TlsHandshakeAead
import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.util.MythaiaLogger
import java.security.SecureRandom
import java.security.Signature

private val logger = MythaiaLogger("TLS")

/**
 * Server end of a TLS 1.3 handshake — the driver that [TlsClient] is the mirror
 * of, for a MITM that has to *be* the origin a client dialed.
 *
 * This is the counterpart to [TlsClient.connect]. Where the client builds a
 * ClientHello and reads a server's flight, this reads the ClientHello and
 * produces the flight: ServerHello in the clear, then EncryptedExtensions,
 * Certificate, CertificateVerify and Finished under the handshake keys, then it
 * waits for and verifies the client's Finished. It owns no byte construction of
 * its own — every message comes from [TlsServerHelloBuilder], the exact inverse
 * of the parsing [TlsClient] does, so the two agree by construction and the
 * layouts are pinned by one test rather than by whatever each side happens to
 * emit.
 *
 * Scope is TLS 1.3 only. A client that cannot do 1.3, that offers no X25519
 * key_share, that omits ecdsa_secp256r1_sha256, or that shares no cipher suite
 * is sent the matching fatal alert and the handshake fails — there is no TLS
 * 1.2 fallback and no HelloRetryRequest, because the only peer on the far side
 * of this is a real client being intercepted, and a client that cannot meet
 * those terms is one we decline rather than downgrade for. Both omissions are
 * noted as deferred rather than unreachable: the wire format leaves room for
 * them.
 *
 * The transcript is accumulated the way [TlsClient] accumulates it — raw
 * handshake messages with no record headers, in the order they appear on the
 * wire — because every secret in TLS 1.3 is keyed on that running hash and a
 * single byte out of place on either side turns into an authentication failure
 * with nothing else to point at. Each Finished is computed over the transcript
 * *before* that Finished is appended, and the application keys are derived over
 * the transcript through the *server* Finished (not the client's), which is the
 * point the client derives them from too.
 *
 * Key derivation, record sealing and the leaf signature are all reused, not
 * reimplemented: [Tls13KeyDerivation] for the schedule, [TlsHandshakeAead] for
 * the handshake-flight records (this driver owns the sequence number, starting
 * at 0 for each direction), [X25519Crypto] for the ephemeral and the agreement,
 * and a plain [Signature] over [TlsServerHelloBuilder.certificateVerifyContext]
 * for CertificateVerify — JCA emits DER ECDSA, which is already the wire form.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class TlsServer(
    private val transport: Transport,
    private val leafCertificates: MitmLeafCertificates,
    /**
     * What this server can speak, in preference order. The first of these the
     * client also offered is selected; all three are TLS 1.3 AEAD suites that
     * [Tls13KeyDerivation] and [TlsHandshakeAead] both implement.
     */
    private val preferredCipherSuites: List<Int> = listOf(
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384
    ),
    /** The ALPN protocols offered back, in preference order. */
    private val supportedAlpns: List<String> = listOf("h2", "http/1.1"),
    /** The host a leaf is minted for when the client sent no SNI; in a MITM the SNI is effectively always present. */
    private val defaultHost: String = "localhost",
    private val secureRandom: SecureRandom = SecureRandom()
) {

    /**
     * Runs the handshake to completion over [transport], starting from the
     * already-buffered ClientHello bytes, and returns the established record
     * connection with its negotiated ALPN set.
     *
     * [bufferedClientHello] is whatever was read off the wire before this
     * driver took over — it may be one record or several, and may not yet hold
     * the whole ClientHello, so it is reassembled across records and topped up
     * from [transport] if short.
     *
     * @throws TlsError.HandshakeFailed after the matching fatal alert has been
     *   written, or if the connection closes mid-handshake.
     */
    suspend fun handshake(bufferedClientHello: ByteArray): TlsRecordConnection {
        val clientHelloMessage = reassembleClientHello(bufferedClientHello)
        val hello = ClientHelloParser.parse(clientHelloMessage)
            ?: abort(ALERT_DECODE_ERROR, "malformed ClientHello")

        // TLS 1.3 is the only version on offer. A client that did not advertise
        // it in supported_versions gets protocol_version, the alert that says
        // exactly that rather than a generic failure.
        if (!hello.offersTls13) {
            abort(ALERT_PROTOCOL_VERSION, "client does not offer TLS 1.3")
        }

        // The leaf is signed ecdsa_secp256r1_sha256, so a client that cannot
        // verify that scheme could never authenticate us; refuse before doing
        // the work rather than sending a CertificateVerify it will reject.
        if (!hello.signatureAlgorithms.contains(SIGNATURE_ECDSA_SECP256R1_SHA256)) {
            abort(ALERT_HANDSHAKE_FAILURE, "client does not offer ecdsa_secp256r1_sha256")
        }

        val suite = preferredCipherSuites.firstOrNull { hello.cipherSuites.contains(it) }
            ?: abort(ALERT_HANDSHAKE_FAILURE, "no mutually supported cipher suite")

        // No X25519 key_share is where a spec-complete server would send a
        // HelloRetryRequest asking for one. That is deferred (see the class
        // note); here it is simply a handshake we cannot complete.
        val clientKeyShare = hello.x25519KeyShare
            ?: abort(ALERT_HANDSHAKE_FAILURE, "client offered no X25519 key_share (HelloRetryRequest not supported)")

        val negotiatedAlpn = negotiateAlpn(hello.alpn)

        // Server ephemeral and the shared secret. X25519Crypto is constant-time
        // BouncyCastle and rejects a low-order peer key for us.
        val keyPair = X25519Crypto.generateKeyPair()
        val serverPrivate = keyPair.copyOfRange(0, 32)
        val serverPublic = keyPair.copyOfRange(32, 64)
        val sharedSecret = X25519Crypto.keyAgreement(serverPrivate, clientKeyShare)

        val serverRandom = ByteArray(32).also { secureRandom.nextBytes(it) }
        val serverHello = TlsServerHelloBuilder.buildServerHello(
            random = serverRandom,
            legacySessionId = hello.sessionId,
            cipherSuite = suite,
            serverX25519Pub = serverPublic
        )

        // transcript := ClientHello || ServerHello, the point the handshake keys
        // are keyed on.
        val kd = Tls13KeyDerivation(suite)
        val handshakeTranscript = clientHelloMessage + serverHello
        val (handshakeSecret, keys) = kd.deriveHandshakeKeys(sharedSecret, handshakeTranscript)

        // Build the encrypted flight, growing the transcript message by message.
        val encryptedExtensions = TlsServerHelloBuilder.buildEncryptedExtensions(negotiatedAlpn)
        val leaf = leafCertificates.leaf(hello.serverName ?: defaultHost)
        val certificate = TlsServerHelloBuilder.buildCertificate(leaf.certificateDer)

        // CertificateVerify signs the transcript hash through Certificate.
        val transcriptThroughCertificate = handshakeTranscript + encryptedExtensions + certificate
        val certificateVerify = TlsServerHelloBuilder.buildCertificateVerify(
            signature = signCertificateVerify(leaf, kd.transcriptHash(transcriptThroughCertificate))
        )

        // The server Finished is computed over the transcript through
        // CertificateVerify — before the Finished itself is appended.
        val transcriptThroughCertificateVerify = transcriptThroughCertificate + certificateVerify
        val serverFinished = TlsServerHelloBuilder.buildFinished(
            kd.computeFinishedVerifyData(keys.serverTrafficSecret, transcriptThroughCertificateVerify)
        )
        val transcriptThroughServerFinished = transcriptThroughCertificateVerify + serverFinished

        // Emit: ServerHello in the clear, then the middlebox-compat
        // ChangeCipherSpec (its canonical position, so it is consumed in the
        // client's handshake loop rather than stashed in the record layer),
        // then the four handshake messages as one sealed record at server
        // handshake sequence 0.
        transport.send(plaintextHandshakeRecord(serverHello))
        transport.send(CHANGE_CIPHER_SPEC)
        val flight = encryptedExtensions + certificate + certificateVerify + serverFinished
        transport.send(
            TlsHandshakeAead.seal(
                cipherSuite = suite,
                key = keys.serverKey,
                iv = keys.serverIV,
                sequence = 0L,
                plaintext = flight,
                innerType = TlsHandshakeAead.CONTENT_HANDSHAKE
            )
        )

        // Read and verify the client Finished.
        val clientFinished = readClientFinished(suite, keys.clientKey, keys.clientIV)
        val expectedClientVerify =
            kd.computeFinishedVerifyData(keys.clientTrafficSecret, transcriptThroughServerFinished)
        if (!constantTimeEquals(expectedClientVerify, clientFinished.verifyData)) {
            abort(ALERT_DECRYPT_ERROR, "client Finished verify_data mismatch")
        }

        // Application keys come from the transcript through the *server*
        // Finished, the same cut the client derives them from; the client
        // Finished is not part of it.
        val appKeys = kd.deriveApplicationKeys(handshakeSecret, transcriptThroughServerFinished)

        logger.info("TLS 1.3 server handshake complete (alpn=$negotiatedAlpn, suite=0x${suite.toString(16)})")

        val connection = TlsRecordConnection(
            clientKey = appKeys.clientKey,
            clientIV = appKeys.clientIV,
            serverKey = appKeys.serverKey,
            serverIV = appKeys.serverIV,
            cipherSuite = suite,
            isServer = true
        )
        connection.connection = transport
        // The wire may carry no ALPN (client offered none), but the application
        // layer still has to frame something; default it to http/1.1.
        connection.negotiatedAlpn = negotiatedAlpn ?: DEFAULT_ALPN
        // Anything the client sent after its Finished (e.g. early application
        // data) belongs to the record layer, not the handshake.
        if (clientFinished.trailing.isNotEmpty()) {
            connection.prependToReceiveBuffer(clientFinished.trailing)
        }
        return connection
    }

    /**
     * Intersects the client's ALPN list with [supportedAlpns].
     *
     * Returns null when the client offered no ALPN at all: a server must not
     * send an `application_layer_protocol_negotiation` extension the client did
     * not ask for (RFC 7301 §3.1 / RFC 8446 §4.2), and a strict client aborts
     * with unsupported_extension if it does. Absence is not a refusal, though —
     * the caller still frames the connection as "http/1.1" internally, it just
     * does not advertise it on the wire. A client that offered protocols none
     * of which we speak is a real incompatibility and gets no_application_protocol.
     */
    private suspend fun negotiateAlpn(clientAlpn: List<String>): String? {
        if (clientAlpn.isEmpty()) return null
        return supportedAlpns.firstOrNull { clientAlpn.contains(it) }
            ?: abort(ALERT_NO_APPLICATION_PROTOCOL, "no overlapping ALPN protocol")
    }

    /**
     * Signs the CertificateVerify context with the leaf key.
     *
     * The input is the 64-space / context-string / transcript-hash octet
     * string [TlsServerHelloBuilder.certificateVerifyContext] lays out, and the
     * algorithm is the leaf's own SHA256withECDSA. JCA's ECDSA signer emits the
     * DER SEQUENCE{r,s} that TLS 1.3 puts on the wire, so no reshaping is
     * needed and [TlsClient.verifyCertificateVerify] reads it straight back.
     */
    private fun signCertificateVerify(
        leaf: MitmLeafCertificates.Leaf,
        transcriptHash: ByteArray
    ): ByteArray {
        val context = TlsServerHelloBuilder.certificateVerifyContext(transcriptHash)
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(leaf.privateKey)
        signer.update(context)
        return signer.sign()
    }

    /** The verify_data of the client Finished, plus any bytes that followed its record. */
    private class ClientFinished(val verifyData: ByteArray, val trailing: ByteArray)

    /**
     * Reads TLS records until the client's encrypted Finished arrives, opening
     * it with the client handshake keys.
     *
     * ChangeCipherSpec records are skipped (they carry no sequence number); the
     * single encrypted handshake record is opened at sequence 0 and searched
     * for the Finished message. Whatever trails the Finished record is returned
     * for the record layer to keep.
     */
    private suspend fun readClientFinished(
        cipherSuite: Int,
        clientKey: ByteArray,
        clientIV: ByteArray
    ): ClientFinished {
        var buffer = ByteArray(0)
        var offset = 0
        var sequence = 0L

        while (true) {
            while (offset + RECORD_HEADER_LEN <= buffer.size) {
                val contentType = buffer[offset].toInt() and 0xFF
                val length = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                    (buffer[offset + 4].toInt() and 0xFF)
                if (length > MAX_CIPHERTEXT_RECORD) {
                    abort(ALERT_DECODE_ERROR, "record length $length out of bounds")
                }
                val recordEnd = offset + RECORD_HEADER_LEN + length
                if (recordEnd > buffer.size) break // need more bytes for this record

                val header = buffer.copyOfRange(offset, offset + RECORD_HEADER_LEN)
                val body = buffer.copyOfRange(offset + RECORD_HEADER_LEN, recordEnd)

                when (contentType) {
                    RECORD_CHANGE_CIPHER_SPEC -> { /* middlebox compat — skip */ }
                    RECORD_ALERT ->
                        throw TlsError.HandshakeFailed("client sent an alert during the handshake")
                    RECORD_APPLICATION_DATA -> {
                        val opened = TlsHandshakeAead.open(
                            cipherSuite, clientKey, clientIV, sequence, header, body
                        ) ?: abort(ALERT_DECRYPT_ERROR, "could not open client handshake record")
                        sequence++
                        if (opened.innerType != TlsHandshakeAead.CONTENT_HANDSHAKE) {
                            abort(ALERT_UNEXPECTED_MESSAGE, "expected a handshake record, got inner type ${opened.innerType}")
                        }
                        findFinished(opened.content)?.let { verifyData ->
                            return ClientFinished(verifyData, buffer.copyOfRange(recordEnd, buffer.size))
                        }
                    }
                    else -> abort(ALERT_UNEXPECTED_MESSAGE, "unexpected record type $contentType before client Finished")
                }
                offset = recordEnd
            }

            val more = transport.receive()
                ?: throw TlsError.HandshakeFailed("connection closed before client Finished")
            buffer += more
        }
    }

    /** The verify_data of the first Finished (type 0x14) message in [content], or null if there is none. */
    private fun findFinished(content: ByteArray): ByteArray? {
        var at = 0
        while (at + 4 <= content.size) {
            val type = content[at].toInt() and 0xFF
            val length = ((content[at + 1].toInt() and 0xFF) shl 16) or
                ((content[at + 2].toInt() and 0xFF) shl 8) or
                (content[at + 3].toInt() and 0xFF)
            if (at + 4 + length > content.size) break
            if (type == HANDSHAKE_FINISHED) {
                return content.copyOfRange(at + 4, at + 4 + length)
            }
            at += 4 + length
        }
        return null
    }

    /**
     * Reassembles the ClientHello handshake message from [initial], reading more
     * from [transport] when the buffered bytes do not yet span the whole of it.
     *
     * ClientHello handshake records (content type 0x16) have their 5-byte record
     * headers stripped and their payloads concatenated — the handshake message
     * can be fragmented across records — and the reassembled form is exactly the
     * raw handshake message [TlsClient] feeds into its own transcript.
     */
    private suspend fun reassembleClientHello(initial: ByteArray): ByteArray {
        var buffer = initial
        while (true) {
            extractFirstHandshakeMessage(buffer)?.let { return it }
            val more = transport.receive()
                ?: throw TlsError.HandshakeFailed("connection closed before a complete ClientHello")
            buffer += more
        }
    }

    /**
     * Concatenates the payloads of the leading handshake records in [buffer] and
     * returns the first complete handshake message, or null if the records do
     * not yet contain one.
     */
    private suspend fun extractFirstHandshakeMessage(buffer: ByteArray): ByteArray? {
        val payload = ArrayList<Byte>()
        var offset = 0
        while (offset + RECORD_HEADER_LEN <= buffer.size) {
            val contentType = buffer[offset].toInt() and 0xFF
            if (contentType != RECORD_HANDSHAKE) {
                abort(ALERT_UNEXPECTED_MESSAGE, "expected a handshake record, got type $contentType")
            }
            val length = ((buffer[offset + 3].toInt() and 0xFF) shl 8) or
                (buffer[offset + 4].toInt() and 0xFF)
            if (length == 0 || length > MAX_CIPHERTEXT_RECORD) {
                abort(ALERT_DECODE_ERROR, "record length $length out of bounds")
            }
            val recordEnd = offset + RECORD_HEADER_LEN + length
            if (recordEnd > buffer.size) break
            for (i in (offset + RECORD_HEADER_LEN) until recordEnd) payload.add(buffer[i])
            offset = recordEnd

            if (payload.size >= 4) {
                val bodyLength = ((payload[1].toInt() and 0xFF) shl 16) or
                    ((payload[2].toInt() and 0xFF) shl 8) or
                    (payload[3].toInt() and 0xFF)
                val total = 4 + bodyLength
                if (payload.size >= total) {
                    return payload.subList(0, total).toByteArray()
                }
            }
        }
        return null
    }

    /** Wraps a handshake message in a plaintext TLS record (content type 0x16, version 0x0303). */
    private fun plaintextHandshakeRecord(message: ByteArray): ByteArray {
        val record = ByteArray(RECORD_HEADER_LEN + message.size)
        record[0] = RECORD_HANDSHAKE.toByte()
        record[1] = 0x03
        record[2] = 0x03
        record[3] = ((message.size ushr 8) and 0xFF).toByte()
        record[4] = (message.size and 0xFF).toByte()
        System.arraycopy(message, 0, record, RECORD_HEADER_LEN, message.size)
        return record
    }

    /**
     * Writes a fatal alert for [description] and fails the handshake.
     *
     * Returns [Nothing] so it can stand on the right of an Elvis operator at a
     * validation check and read as "this is the end of the handshake".
     */
    private suspend fun abort(description: Int, reason: String): Nothing {
        logger.warning("TLS server handshake aborting: $reason (alert $description)")
        runCatching {
            transport.send(
                byteArrayOf(
                    RECORD_ALERT.toByte(), 0x03, 0x03, 0x00, 0x02,
                    ALERT_LEVEL_FATAL.toByte(), description.toByte()
                )
            )
        }
        throw TlsError.HandshakeFailed(reason)
    }

    companion object {
        /** ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3); the only scheme this server signs with. */
        const val SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403

        /** The ALPN handed to a client that offered none. */
        const val DEFAULT_ALPN = "http/1.1"

        private const val RECORD_HEADER_LEN = 5
        private const val RECORD_CHANGE_CIPHER_SPEC = 0x14
        private const val RECORD_ALERT = 0x15
        private const val RECORD_HANDSHAKE = 0x16
        private const val RECORD_APPLICATION_DATA = 0x17

        /** Finished handshake message type (RFC 8446 §4.4.4). */
        private const val HANDSHAKE_FINISHED = 0x14

        /** Largest a TLS record body may be: 2^14 plaintext plus AEAD expansion (RFC 8446 §5.2). */
        private const val MAX_CIPHERTEXT_RECORD = 16384 + 256

        private const val ALERT_LEVEL_FATAL = 2

        // Alert descriptions (RFC 8446 §6 / Appendix A.3).
        private const val ALERT_UNEXPECTED_MESSAGE = 10
        private const val ALERT_HANDSHAKE_FAILURE = 40
        private const val ALERT_DECODE_ERROR = 50
        private const val ALERT_DECRYPT_ERROR = 51
        private const val ALERT_PROTOCOL_VERSION = 70
        private const val ALERT_NO_APPLICATION_PROTOCOL = 120

        /** The middlebox-compatibility ChangeCipherSpec, sent once after ServerHello (RFC 8446 §5). */
        private val CHANGE_CIPHER_SPEC = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

        /**
         * Constant-time byte-array equality, exposed for the off-device tests of
         * the client-Finished check.
         *
         * The comparison time depends only on the lengths, never on where the
         * inputs first differ — the same property [TlsClient] relies on for the
         * server Finished. A verify_data is not a secret the way a key is, but a
         * timing oracle on it would let an attacker forge a Finished byte by
         * byte, so the guarantee is load-bearing, not hygiene.
         */
        internal fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
            if (a.size != b.size) return false
            var diff = 0
            for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
            return diff == 0
        }
    }
}
