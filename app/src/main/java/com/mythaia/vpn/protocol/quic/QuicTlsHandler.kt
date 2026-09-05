package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.X25519Crypto
import com.mythaia.vpn.protocol.tls.CertificatePolicy
import com.mythaia.vpn.protocol.tls.Tls13KeyDerivation
import com.mythaia.vpn.protocol.tls.TlsCipherSuite
import com.mythaia.vpn.protocol.tls.TlsClientHelloBuilder
import com.mythaia.vpn.protocol.tls.TlsPeerVerifier
import com.mythaia.vpn.util.MythaiaLogger
import java.security.SecureRandom

private val logger = MythaiaLogger("QuicTls")

/**
 * The TLS 1.3 handshake, as QUIC uses it.
 *
 * QUIC does not run TLS over a record layer; it carries the handshake messages
 * in CRYPTO frames and asks TLS only for keys. So this is a TLS client with the
 * record layer taken out: ngtcp2 hands it bytes through
 * [NativeBridge.QuicCallback.onCryptoData], it hands back messages to submit
 * and secrets to install, and it never sees a packet.
 *
 * Three things differ from the TCP client next door, and only three:
 * the ClientHello carries a `quic_transport_parameters` extension, keys are
 * installed per encryption level rather than into a record layer, and the
 * traffic secrets are handed to ngtcp2 rather than used here — the `quic key`,
 * `quic iv` and `quic hp` expansions happen inside the library.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class QuicTlsHandler(
    private val serverName: String,
    private val alpn: List<String>,
    private val tuning: QuicTuning,
    private val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133
) {

    /** How far the handshake has got. */
    enum class Phase { INITIAL, HELLO_SENT, SERVER_HELLO_SEEN, ESTABLISHED, FAILED }

    var phase: Phase = Phase.INITIAL
        private set

    /** Why the handshake failed, for a caller that wants to say something useful. */
    var failure: String? = null
        private set

    /** The cipher suite the server chose, once it has. */
    var cipherSuite: Int = 0
        private set

    /** What the server advertised, available after EncryptedExtensions. */
    var peerTransportParameters: List<QuicTuning.TransportParameter> = emptyList()
        private set

    /** The certificate chain the server presented, in wire order. */
    val serverCertificates = ArrayList<ByteArray>()

    private val random = SecureRandom()
    private val clientRandom = ByteArray(32).also { random.nextBytes(it) }
    private val sessionId = ByteArray(32).also { random.nextBytes(it) }

    private val privateKey: ByteArray
    private val publicKey: ByteArray

    init {
        val pair = X25519Crypto.generateKeyPair()
        privateKey = pair.copyOfRange(0, 32)
        publicKey = pair.copyOfRange(32, 64)
    }

    /** Every handshake message exchanged, in order — the TLS transcript. */
    private var transcript = ByteArray(0)

    /** The transcript as it stood before the server's Finished. */
    private var transcriptBeforeServerFinished = ByteArray(0)

    /** The transcript CertificateVerify signs: everything up to but not itself. */
    private var transcriptBeforeCertificateVerify: ByteArray? = null

    private var certificateVerifyAlgorithm = 0
    private var certificateVerifySignature: ByteArray? = null

    /** Handshake bytes that did not yet form a whole message. */
    private var pending = ByteArray(0)

    private var keyDerivation: Tls13KeyDerivation? = null
    private var handshakeSecret: ByteArray? = null
    private var clientHandshakeSecret: ByteArray? = null
    private var clientHello: ByteArray? = null

    // MARK: - Outbound

    /**
     * The ClientHello, built once and remembered.
     *
     * ngtcp2 asks for it through `client_initial`, and may ask again if the
     * first Initial packet is lost — the same bytes must come back, since the
     * transcript is already committed to them.
     */
    fun buildClientHello(): ByteArray? {
        clientHello?.let { return it }
        if (phase != Phase.INITIAL) return null

        val parameters = QuicTransportParameters.encode(tuning.advertisedParameters)
        val hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint = fingerprint,
            random = clientRandom,
            sessionId = sessionId,
            serverName = serverName,
            publicKey = publicKey,
            alpn = alpn,
            // QUIC has no room for a post-quantum key share in the first
            // datagram, and the extra flight it would cost is the opposite of
            // what a low-latency transport is for.
            omitPQKeyShares = true,
            extraExtensions = QuicTransportParameters.asExtension(parameters)
        )

        transcript += hello
        clientHello = hello
        phase = Phase.HELLO_SENT
        return hello
    }

    // MARK: - Inbound

    /** What [processCryptoData] wants the caller to do next. */
    enum class Outcome { OK, NEED_MORE, FAILED }

    /**
     * Consumes handshake bytes from one encryption level.
     *
     * Bytes that do not complete a message are kept for the next call: a CRYPTO
     * frame is not a message boundary, and a ServerHello can arrive split
     * across two of them.
     */
    fun processCryptoData(connection: Long, data: ByteArray): Outcome {
        pending += data

        while (pending.size >= 4) {
            val type = pending[0].toInt() and 0xFF
            val length = ((pending[1].toInt() and 0xFF) shl 16) or
                ((pending[2].toInt() and 0xFF) shl 8) or
                (pending[3].toInt() and 0xFF)

            // The length field is 24 bits, but nothing in a TLS 1.3 handshake
            // legitimately approaches that. The cap is not in the RFC; it is
            // here so a corrupt length cannot ask for a 16 MB allocation.
            if (length > 0xFFFF) {
                return fail("handshake message of $length bytes (type $type)")
            }

            val total = 4 + length
            if (pending.size < total) return Outcome.NEED_MORE

            val message = pending.copyOfRange(0, total)
            pending = pending.copyOfRange(total, pending.size)

            // The server's Finished proves the transcript *before* itself, so
            // the snapshot has to be taken before the message is appended.
            if (type == FINISHED) transcriptBeforeServerFinished = transcript
            if (type == CERTIFICATE_VERIFY) transcriptBeforeCertificateVerify = transcript
            transcript += message

            val body = message.copyOfRange(4, message.size)
            val outcome = when (type) {
                SERVER_HELLO -> processServerHello(connection, body)
                ENCRYPTED_EXTENSIONS -> processEncryptedExtensions(body)
                CERTIFICATE -> processCertificate(body)
                CERTIFICATE_VERIFY -> processCertificateVerify(body)
                FINISHED -> processServerFinished(connection)
                NEW_SESSION_TICKET -> Outcome.OK
                else -> {
                    logger.debug("[QUIC-TLS] Ignoring handshake message type $type")
                    Outcome.OK
                }
            }
            if (outcome == Outcome.FAILED) return outcome
        }

        // Leftover bytes are leftover bytes whether or not they reach a header
        // length; saying OK below four and NEED_MORE above it would be the same
        // state described two ways.
        return if (pending.isEmpty()) Outcome.OK else Outcome.NEED_MORE
    }

    // MARK: - Messages

    private fun processServerHello(connection: Long, body: ByteArray): Outcome {
        // legacy_version(2) random(32) session_id_len(1)
        if (body.size < 35) return fail("ServerHello is ${body.size} bytes")
        var at = 34
        val sessionIdLength = body[at].toInt() and 0xFF
        at += 1 + sessionIdLength
        if (at + 3 > body.size) return fail("ServerHello ends inside its cipher suite")

        cipherSuite = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
        at += 2
        at += 1 // legacy_compression_method

        if (!TlsCipherSuite.isAEAD(cipherSuite)) {
            return fail("server chose cipher suite 0x%04x".format(cipherSuite))
        }

        val peerKey = findKeyShare(body, at) ?: return fail("ServerHello has no usable key share")
        val shared = try {
            X25519Crypto.keyAgreement(privateKey, peerKey)
        } catch (e: Exception) {
            return fail("key agreement failed: ${e.message ?: e}")
        }

        // The suite has to reach ngtcp2 before any key does: the crypto backend
        // carries it as the TLS native handle and everything else reads it back.
        val rv = NativeBridge.nativeQuicSetCipherSuite(connection, cipherSuite)
        if (rv != 0) return fail("ngtcp2 refused cipher suite 0x%04x".format(cipherSuite))

        val derivation = Tls13KeyDerivation(cipherSuite)
        keyDerivation = derivation

        val (secret, keys) = derivation.deriveHandshakeKeys(shared, transcript)
        handshakeSecret = secret
        clientHandshakeSecret = keys.clientTrafficSecret

        // The traffic secrets, not the expanded keys: ngtcp2 runs its own
        // `quic key` / `quic iv` / `quic hp` expansion over these.
        if (NativeBridge.nativeQuicInstallKeys(
                connection, LEVEL_HANDSHAKE, keys.serverTrafficSecret, keys.clientTrafficSecret
            ) != 0
        ) {
            return fail("ngtcp2 refused the handshake keys")
        }

        phase = Phase.SERVER_HELLO_SEEN
        return Outcome.OK
    }

    /**
     * The peer's transport parameters ride in EncryptedExtensions.
     *
     * Anything unreadable there is the server's half of the transport contract,
     * so it is a reason to stop rather than to carry on with defaults.
     */
    private fun processEncryptedExtensions(body: ByteArray): Outcome {
        if (body.size < 2) return Outcome.OK
        val total = ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        var at = 2
        val end = minOf(2 + total, body.size)

        while (at + 4 <= end) {
            val type = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
            val length = ((body[at + 2].toInt() and 0xFF) shl 8) or (body[at + 3].toInt() and 0xFF)
            at += 4
            if (at + length > end) break

            if (type == QuicTransportParameters.EXTENSION_TYPE) {
                val parsed = QuicTransportParameters.decode(body.copyOfRange(at, at + length))
                    ?: return fail("server sent malformed transport parameters")
                peerTransportParameters = parsed
            }
            at += length
        }
        return Outcome.OK
    }

    /** Collects the chain; validation is the caller's, against its own policy. */
    private fun processCertificate(body: ByteArray): Outcome {
        if (body.isEmpty()) return Outcome.OK
        var at = 1 + (body[0].toInt() and 0xFF) // certificate_request_context
        if (at + 3 > body.size) return Outcome.OK

        val listLength = ((body[at].toInt() and 0xFF) shl 16) or
            ((body[at + 1].toInt() and 0xFF) shl 8) or (body[at + 2].toInt() and 0xFF)
        at += 3
        val end = minOf(at + listLength, body.size)

        while (at + 3 <= end) {
            val length = ((body[at].toInt() and 0xFF) shl 16) or
                ((body[at + 1].toInt() and 0xFF) shl 8) or (body[at + 2].toInt() and 0xFF)
            at += 3
            if (at + length > end) break
            serverCertificates.add(body.copyOfRange(at, at + length))
            at += length
            if (at + 2 > end) break
            val extensionsLength = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
            at += 2 + extensionsLength
        }
        return Outcome.OK
    }

    /** Keeps the signature; it is checked once the whole chain has arrived. */
    private fun processCertificateVerify(body: ByteArray): Outcome {
        if (body.size < 4) return fail("CertificateVerify is ${body.size} bytes")
        certificateVerifyAlgorithm =
            ((body[0].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)
        val length = ((body[2].toInt() and 0xFF) shl 8) or (body[3].toInt() and 0xFF)
        if (4 + length > body.size) return fail("CertificateVerify signature runs past the message")
        certificateVerifySignature = body.copyOfRange(4, 4 + length)
        return Outcome.OK
    }

    /**
     * Proves the server is who the certificate says it is.
     *
     * Without this the handshake authenticates nothing: anyone able to complete
     * an ECDHE exchange — which is anyone at all, since it needs no secret —
     * would be accepted, and the tunnel would carry traffic to whoever answered
     * first. The chain, the hostname and the CertificateVerify signature are
     * each necessary; the first two say the certificate is legitimate for this
     * name, the third says the peer actually holds its private key.
     */
    private fun validateCertificate(): Outcome {
        if (CertificatePolicy.allowInsecure) return Outcome.OK

        val chain = try {
            TlsPeerVerifier.parseChain(serverCertificates)
        } catch (e: TlsPeerVerifier.Failure) {
            return fail(e.message ?: "certificate did not parse")
        }

        try {
            TlsPeerVerifier.verifyTrust(chain, serverName)
        } catch (e: TlsPeerVerifier.Failure) {
            return fail(e.message ?: "certificate not trusted")
        }

        val signature = certificateVerifySignature
        val signed = transcriptBeforeCertificateVerify
        val derivation = keyDerivation
        if (signature == null || signed == null || derivation == null) {
            return fail("server did not prove it holds the certificate key")
        }
        if (!TlsPeerVerifier.verifySignature(
                chain.first(),
                certificateVerifyAlgorithm,
                signature,
                derivation.transcriptHash(signed)
            )
        ) {
            return fail("CertificateVerify signature did not check out")
        }
        return Outcome.OK
    }

    /**
     * Verifies the server's Finished and moves to application keys.
     *
     * The verify data covers the transcript up to but not including the
     * Finished itself, which is why the snapshot was taken on the way in.
     */
    private fun processServerFinished(connection: Long): Outcome {
        val derivation = keyDerivation ?: return fail("Finished arrived before ServerHello")
        val secret = handshakeSecret ?: return fail("no handshake secret")

        // Before any application key exists: past this point the tunnel would
        // be carrying real traffic to whoever answered.
        if (validateCertificate() == Outcome.FAILED) return Outcome.FAILED

        val (clientApplication, serverApplication) =
            derivation.deriveApplicationSecrets(secret, transcriptBeforeServerFinished)
        if (NativeBridge.nativeQuicInstallKeys(
                connection, LEVEL_APPLICATION, serverApplication, clientApplication
            ) != 0
        ) {
            return fail("ngtcp2 refused the application keys")
        }

        val clientSecret = clientHandshakeSecret ?: return fail("no client handshake secret")
        val verifyData = derivation.computeFinishedVerifyData(clientSecret, transcript)
        val finished = ByteArray(4 + verifyData.size)
        finished[0] = FINISHED.toByte()
        finished[1] = (verifyData.size ushr 16).toByte()
        finished[2] = (verifyData.size ushr 8).toByte()
        finished[3] = verifyData.size.toByte()
        verifyData.copyInto(finished, 4)

        if (NativeBridge.nativeQuicSubmitCrypto(connection, LEVEL_HANDSHAKE, finished) != 0) {
            return fail("ngtcp2 refused the client Finished")
        }
        transcript += finished

        phase = Phase.ESTABLISHED
        return Outcome.OK
    }

    // MARK: - Helpers

    /** The server's `key_share`, which for QUIC is always a single entry. */
    private fun findKeyShare(body: ByteArray, from: Int): ByteArray? {
        if (from + 2 > body.size) return null
        val total = ((body[from].toInt() and 0xFF) shl 8) or (body[from + 1].toInt() and 0xFF)
        var at = from + 2
        val end = minOf(at + total, body.size)

        while (at + 4 <= end) {
            val type = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
            val length = ((body[at + 2].toInt() and 0xFF) shl 8) or (body[at + 3].toInt() and 0xFF)
            at += 4
            if (at + length > end) return null

            if (type == EXTENSION_KEY_SHARE && length >= 4) {
                val group = ((body[at].toInt() and 0xFF) shl 8) or (body[at + 1].toInt() and 0xFF)
                val keyLength = ((body[at + 2].toInt() and 0xFF) shl 8) or (body[at + 3].toInt() and 0xFF)
                if (group != GROUP_X25519 || keyLength != 32) return null
                if (at + 4 + keyLength > end) return null
                return body.copyOfRange(at + 4, at + 4 + keyLength)
            }
            at += length
        }
        return null
    }

    private fun fail(reason: String): Outcome {
        if (failure == null) {
            failure = reason
            logger.warning("[QUIC-TLS] $reason")
        }
        phase = Phase.FAILED
        return Outcome.FAILED
    }

    companion object {
        // ngtcp2_encryption_level
        const val LEVEL_INITIAL = 0
        const val LEVEL_HANDSHAKE = 2
        const val LEVEL_APPLICATION = 3

        private const val SERVER_HELLO = 2
        private const val NEW_SESSION_TICKET = 4
        private const val ENCRYPTED_EXTENSIONS = 8
        private const val CERTIFICATE = 11
        private const val CERTIFICATE_VERIFY = 15
        private const val FINISHED = 20

        private const val EXTENSION_KEY_SHARE = 51
        private const val GROUP_X25519 = 0x001D
    }
}
