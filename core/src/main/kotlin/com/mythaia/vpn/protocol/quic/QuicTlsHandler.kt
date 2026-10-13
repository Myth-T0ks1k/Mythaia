package com.mythaia.vpn.protocol.quic

import com.mythaia.data.model.TlsFingerprint
import com.mythaia.vpn.NativeBridge
import com.mythaia.vpn.Tls13Crypto
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
    private val fingerprint: TlsFingerprint = TlsFingerprint.CHROME_133,
    /** The link's own `insecure` flag; the global policy is honoured as well. */
    private val allowInsecure: Boolean = false,
    /** Certificates trusted by SHA-256 regardless of CA (`pinSHA256=`/`pcs=`). */
    private val pinnedCertSha256: List<String>? = null,
    /** The name the certificate must carry when it is not [serverName] (`vcn=`). */
    private val verifyName: String? = null
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

    /** The protocol the server picked from what was offered. */
    var negotiatedAlpn: String? = null
        private set

    /** What the server advertised, available after EncryptedExtensions. */
    var peerTransportParameters: List<QuicTuning.TransportParameter> = emptyList()
        private set

    /**
     * The local transport parameters in wire form, as ngtcp2 encodes them for
     * the connection. Set before the hello is built; the tuning's own list is
     * the fallback and lacks the connection id a server insists on.
     */
    @Volatile
    var localTransportParameters: ByteArray? = null

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
    private var serverHandshakeSecret: ByteArray? = null
    private var clientHello: ByteArray? = null

    /** Set with the application keys; what [exportKeyingMaterial] derives from. */
    private var exporterMasterSecret: ByteArray? = null

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

        val parameters = localTransportParameters
            ?: QuicTransportParameters.encode(tuning.advertisedParameters)
        val hello = restrictToTls13(
            TlsClientHelloBuilder.buildRawClientHello(
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
        )

        transcript += hello
        clientHello = hello
        phase = Phase.HELLO_SENT
        return hello
    }

    /**
     * Drops every version but TLS 1.3 (and a GREASE value) from the hello's
     * `supported_versions`. RFC 9001 §4.2 forbids offering older versions
     * over QUIC, and Go's TLS (every Hysteria and TUIC server) answers a
     * browser-shaped list with a `protocol_version` alert. The handshake
     * header and extensions length are rewritten; a padding extension, if the
     * fingerprint carries one, is left as it was.
     */
    private fun restrictToTls13(hello: ByteArray): ByteArray {
        fun u16(at: Int) = ((hello[at].toInt() and 0xFF) shl 8) or (hello[at + 1].toInt() and 0xFF)
        if (hello.size < 4 + 2 + 32 + 1 || hello[0].toInt() != 0x01) return hello
        var at = 4 + 2 + 32
        at += 1 + (hello[at].toInt() and 0xFF)            // legacy_session_id
        if (at + 2 > hello.size) return hello
        at += 2 + u16(at)                                  // cipher_suites
        if (at + 1 > hello.size) return hello
        at += 1 + (hello[at].toInt() and 0xFF)            // legacy_compression_methods
        if (at + 2 > hello.size) return hello
        val extensionsLengthAt = at
        val extensionsEnd = at + 2 + u16(at)
        if (extensionsEnd > hello.size) return hello

        val out = java.io.ByteArrayOutputStream(hello.size)
        out.write(hello, 0, extensionsLengthAt + 2)
        var p = extensionsLengthAt + 2
        while (p + 4 <= extensionsEnd) {
            val type = u16(p)
            val length = u16(p + 2)
            val bodyStart = p + 4
            val bodyEnd = bodyStart + length
            if (bodyEnd > extensionsEnd) return hello
            if (type == 0x002b && length >= 1) {
                val versions = ArrayList<Int>()
                var v = bodyStart + 1
                while (v + 2 <= bodyEnd) {
                    val version = u16(v)
                    val grease = (version and 0x0f0f) == 0x0a0a && (version shr 8) == (version and 0xFF)
                    if (version == 0x0304 || grease) versions += version
                    v += 2
                }
                if (0x0304 !in versions) versions += 0x0304
                val newLength = 1 + 2 * versions.size
                out.write(0x00); out.write(0x2b)
                out.write(newLength shr 8); out.write(newLength and 0xFF)
                out.write(2 * versions.size)
                versions.forEach { out.write(it shr 8); out.write(it and 0xFF) }
            } else {
                out.write(hello, p, 4 + length)
            }
            p = bodyEnd
        }
        val result = out.toByteArray()
        val newExtensionsLength = result.size - (extensionsLengthAt + 2)
        result[extensionsLengthAt] = (newExtensionsLength shr 8).toByte()
        result[extensionsLengthAt + 1] = newExtensionsLength.toByte()
        val bodyLength = result.size - 4
        result[1] = (bodyLength shr 16).toByte()
        result[2] = (bodyLength shr 8).toByte()
        result[3] = bodyLength.toByte()
        return result
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
                ENCRYPTED_EXTENSIONS -> processEncryptedExtensions(connection, body)
                CERTIFICATE -> processCertificate(body)
                CERTIFICATE_VERIFY -> processCertificateVerify(body)
                FINISHED -> processServerFinished(connection, body)
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
        serverHandshakeSecret = keys.serverTrafficSecret

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
    private fun processEncryptedExtensions(connection: Long, body: ByteArray): Outcome {
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
                val raw = body.copyOfRange(at, at + length)
                val parsed = QuicTransportParameters.decode(raw)
                    ?: return fail("server sent malformed transport parameters")
                peerTransportParameters = parsed

                // ngtcp2 is the authority on these — it enforces the limits.
                // The parsed list above is for anything that wants to look.
                if (NativeBridge.nativeQuicSetRemoteParams(connection, raw) != 0) {
                    return fail("ngtcp2 refused the peer transport parameters")
                }
            }

            if (type == EXTENSION_ALPN) {
                negotiatedAlpn = readAlpn(body, at, length)
                if (alpn.isNotEmpty() && negotiatedAlpn !in alpn) {
                    return fail("server selected ALPN '$negotiatedAlpn', which was not offered")
                }
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
        if (allowInsecure || CertificatePolicy.allowInsecure) return Outcome.OK

        val chain = try {
            TlsPeerVerifier.parseChain(serverCertificates)
        } catch (e: TlsPeerVerifier.Failure) {
            return fail(e.message ?: "certificate did not parse")
        }

        val pins = pinnedCertSha256
        if (!pins.isNullOrEmpty()) {
            if (chain.none { TlsPeerVerifier.matchesPin(it, pins) }) {
                return fail("certificate does not match the pinned SHA-256")
            }
        } else {
            try {
                TlsPeerVerifier.verifyTrust(chain, verifyName ?: serverName)
            } catch (e: TlsPeerVerifier.Failure) {
                return fail(e.message ?: "certificate not trusted")
            }
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
    private fun processServerFinished(connection: Long, body: ByteArray): Outcome {
        val derivation = keyDerivation ?: return fail("Finished arrived before ServerHello")
        val secret = handshakeSecret ?: return fail("no handshake secret")

        // Before any application key exists: past this point the tunnel would
        // be carrying real traffic to whoever answered.
        if (validateCertificate() == Outcome.FAILED) return Outcome.FAILED

        // RFC 8446 4.4.4: the server's verify_data is
        // HMAC(server finished_key, transcript hash up to but not including
        // this Finished). The snapshot was taken on the way in, before the
        // message was appended. A mismatch means the handshake was tampered
        // with — stop here, before any 1-RTT key is installed or ngtcp2 is
        // told the handshake completed.
        val serverSecret = serverHandshakeSecret ?: return fail("no server handshake secret")
        val expected = derivation.computeFinishedVerifyData(serverSecret, transcriptBeforeServerFinished)
        if (!constantTimeEquals(body, expected)) {
            return fail("server Finished verify data did not match")
        }

        // RFC 8446 7.1: the application secrets are derived over the
        // transcript through the server Finished, which `transcript` already
        // includes. The earlier snapshot is what verifies that Finished, and
        // using it here would derive keys the server does not share.
        val (clientApplication, serverApplication) =
            derivation.deriveApplicationSecrets(secret, transcript)

        // Same transcript as the application secrets, for the same reason: an
        // exporter taken over a different one is a value the peer does not have.
        exporterMasterSecret = Tls13Crypto.deriveExporterMasterSecret(
            cipherSuite, secret, transcript
        )
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

        // Strictly after the certificate check above: this is what promotes the
        // connection to carrying application data, and a connection that has
        // proved nothing must never be promoted.
        NativeBridge.nativeQuicHandshakeCompleted(connection)

        phase = Phase.ESTABLISHED
        return Outcome.OK
    }

    /**
     * Keying material bound to this session (RFC 5705).
     *
     * TUIC turns its password into a token this way, so a token captured on one
     * connection proves nothing on another. Null before the handshake reaches
     * the server Finished, since the secret it derives from does not exist yet.
     */
    fun exportKeyingMaterial(label: ByteArray, context: ByteArray, length: Int): ByteArray? {
        val secret = exporterMasterSecret ?: return null
        return Tls13Crypto.exportKeyingMaterial(cipherSuite, secret, label, context, length)
    }

    /** The single protocol name in an ALPN extension, or null. */
    private fun readAlpn(body: ByteArray, at: Int, length: Int): String? {
        // list length(2) name length(1) name
        if (length < 3) return null
        val nameLength = body[at + 2].toInt() and 0xFF
        if (at + 3 + nameLength > body.size || nameLength == 0) return null
        return String(body, at + 3, nameLength, Charsets.US_ASCII)
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

    /**
     * Compares in time that depends only on the lengths, never on where the
     * bytes first differ. A verify_data is not a key, but a timing oracle on
     * it would let a Finished be forged byte by byte, so this matters — the
     * same guarantee [com.mythaia.vpn.protocol.tls.TlsClient] relies on.
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
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
        // The bridge's own numbering, translated to ngtcp2's enum in C.
        // Deliberately not ngtcp2's values: that enum has been renumbered once
        // already — `ngtcp2_crypto_level` ordered them initial, early,
        // handshake, app — and a constant that silently survived the change
        // installs handshake keys as 1-RTT keys with nothing to show for it.
        const val LEVEL_INITIAL = 0
        const val LEVEL_HANDSHAKE = 1
        const val LEVEL_APPLICATION = 2

        private const val SERVER_HELLO = 2
        private const val NEW_SESSION_TICKET = 4
        private const val ENCRYPTED_EXTENSIONS = 8
        private const val CERTIFICATE = 11
        private const val CERTIFICATE_VERIFY = 15
        private const val FINISHED = 20

        private const val EXTENSION_ALPN = 16
        private const val EXTENSION_KEY_SHARE = 51
        private const val GROUP_X25519 = 0x001D
    }
}
