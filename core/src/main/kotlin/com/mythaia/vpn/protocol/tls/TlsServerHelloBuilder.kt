package com.mythaia.vpn.protocol.tls

/**
 * Pure byte construction of the five TLS 1.3 server handshake messages:
 * ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished.
 *
 * This is the server-side counterpart of [TlsClientHelloBuilder]. It is the
 * exact inverse of the parsing in [TlsClient]: every field this object emits is
 * a field that client reads back (see `PacketUtil.parseServerHello`,
 * `TlsClient.parseCertificateMessage`, and the CertificateVerify / Finished
 * handling in `consumeRemainingHandshake`). The two must agree to the byte, so
 * the layouts here are pinned by [TlsServerHelloBuilderTest] against
 * hand-written RFC 8446 bytes rather than against whatever this code happens to
 * produce.
 *
 * Every method is a pure function returning a fresh [ByteArray]. There is no IO
 * and no logging on purpose: these functions only lay out bytes, so the only
 * failure mode is a caller passing a field too large for its length prefix,
 * which is surfaced eagerly with [require] rather than by silently emitting a
 * truncated, unparseable message.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object TlsServerHelloBuilder {

    // TLS 1.3 handshake message types (RFC 8446 §4).
    private const val TYPE_SERVER_HELLO: Byte = 0x02
    private const val TYPE_ENCRYPTED_EXTENSIONS: Byte = 0x08
    private const val TYPE_CERTIFICATE: Byte = 0x0B
    private const val TYPE_CERTIFICATE_VERIFY: Byte = 0x0F
    private const val TYPE_FINISHED: Byte = 0x14

    // Extension codepoints (RFC 8446 §4.2, RFC 7301).
    private const val EXT_ALPN = 0x0010
    private const val EXT_SUPPORTED_VERSIONS = 0x002B
    private const val EXT_KEY_SHARE = 0x0033

    private const val LEGACY_VERSION_TLS12 = 0x0303   // ServerHello.legacy_version
    private const val SELECTED_VERSION_TLS13 = 0x0304 // supported_versions -> TLS 1.3
    private const val GROUP_X25519 = 0x001D           // NamedGroup.x25519

    /** Default signature scheme: ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3). */
    const val SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403

    /**
     * The prefix a CertificateVerify signature covers, minus the transcript hash
     * itself. 64 octets of 0x20, then the context string, then a single 0x00
     * separator (RFC 8446 §4.4.3).
     */
    private val CERT_VERIFY_LABEL = "TLS 1.3, server CertificateVerify".toByteArray(Charsets.US_ASCII)

    // -- ServerHello --

    /**
     * Builds a TLS 1.3 ServerHello (RFC 8446 §4.1.3).
     *
     * Unlike the Swift reference this takes [random] rather than generating it,
     * so the message is a deterministic function of its inputs and can be pinned
     * by a test. The session id is echoed verbatim from the ClientHello for
     * middlebox compatibility, and only the two server extensions TLS 1.3
     * requires in the ServerHello are emitted — supported_versions (which is how
     * the client learns 1.3 was selected; `PacketUtil.parseServerHello` treats
     * the absence of a key_share as a fall back to 1.2) and key_share carrying
     * the server's ephemeral X25519 public key.
     *
     * @param random 32-byte ServerHello.random.
     * @param legacySessionId the ClientHello's legacy_session_id, echoed back.
     * @param cipherSuite chosen suite, a [TlsCipherSuite] codepoint (low 16 bits used).
     * @param serverX25519Pub 32-byte server ephemeral X25519 public key.
     */
    fun buildServerHello(
        random: ByteArray,
        legacySessionId: ByteArray,
        cipherSuite: Int,
        serverX25519Pub: ByteArray
    ): ByteArray {
        require(random.size == 32) { "ServerHello.random must be 32 bytes, was ${random.size}" }
        require(legacySessionId.size <= 255) {
            "legacy_session_id must fit a 1-byte length, was ${legacySessionId.size}"
        }
        require(serverX25519Pub.size == 32) {
            "X25519 public key must be 32 bytes, was ${serverX25519Pub.size}"
        }

        val body = mutableListOf<Byte>()
        body.appendU16(LEGACY_VERSION_TLS12)
        body.addAll(random.asList())
        body.add(legacySessionId.size.toByte())
        body.addAll(legacySessionId.asList())
        body.appendU16(cipherSuite and 0xFFFF)
        body.add(0x00) // legacy_compression_method: null

        val extensions = mutableListOf<Byte>()
        extensions.addAll(supportedVersionsServerExt())
        extensions.addAll(keyShareServerExt(GROUP_X25519, serverX25519Pub))

        body.appendU16(extensions.size)
        body.addAll(extensions)

        return wrapHandshake(TYPE_SERVER_HELLO, body.toByteArray())
    }

    // -- EncryptedExtensions --

    /**
     * Builds an EncryptedExtensions message (RFC 8446 §4.3.1).
     *
     * The body is just the extension list, so with no ALPN it is the two-byte
     * length 0x0000. When [alpn] is non-null a single-protocol
     * application_layer_protocol_negotiation extension is the only member, which
     * is what the client expects to find once it decrypts this record.
     */
    fun buildEncryptedExtensions(alpn: String?): ByteArray {
        val extensions = mutableListOf<Byte>()
        if (alpn != null) {
            extensions.addAll(alpnExt(listOf(alpn)))
        }

        val body = mutableListOf<Byte>()
        body.appendU16(extensions.size)
        body.addAll(extensions)

        return wrapHandshake(TYPE_ENCRYPTED_EXTENSIONS, body.toByteArray())
    }

    // -- Certificate --

    /**
     * Builds a single-entry TLS 1.3 Certificate message (RFC 8446 §4.4.2).
     *
     * Layout mirrors `TlsClient.parseCertificateMessage` exactly: a zero-length
     * certificate_request_context (the single 0x00), a 3-byte certificate_list
     * length, then one CertificateEntry of `3-byte cert length + DER + 2-byte
     * (empty) extensions`.
     */
    fun buildCertificate(leafDer: ByteArray): ByteArray {
        require(leafDer.size < (1 shl 24)) {
            "certificate DER too large for a 3-byte length: ${leafDer.size}"
        }

        val entry = mutableListOf<Byte>()
        entry.appendU24(leafDer.size)
        entry.addAll(leafDer.asList())
        entry.appendU16(0) // per-certificate extensions: empty

        val body = mutableListOf<Byte>()
        body.add(0x00) // certificate_request_context: length 0
        body.appendU24(entry.size)
        body.addAll(entry)

        return wrapHandshake(TYPE_CERTIFICATE, body.toByteArray())
    }

    // -- CertificateVerify --

    /**
     * Builds a CertificateVerify message (RFC 8446 §4.4.3): the 2-byte signature
     * scheme, a 2-byte signature length, then the signature. [certificateVerifyContext]
     * produces the bytes the [signature] is expected to cover.
     */
    fun buildCertificateVerify(
        signatureScheme: Int = SIGNATURE_ECDSA_SECP256R1_SHA256,
        signature: ByteArray
    ): ByteArray {
        require(signature.size <= 0xFFFF) {
            "signature too large for a 2-byte length: ${signature.size}"
        }

        val body = mutableListOf<Byte>()
        body.appendU16(signatureScheme and 0xFFFF)
        body.appendU16(signature.size)
        body.addAll(signature.asList())

        return wrapHandshake(TYPE_CERTIFICATE_VERIFY, body.toByteArray())
    }

    // -- Finished --

    /**
     * Builds a Finished message (RFC 8446 §4.4.4). The body is the verify_data
     * verbatim; its length is carried only by the handshake header, which the
     * client reads as `hsLen` before comparing against its own computed value.
     */
    fun buildFinished(verifyData: ByteArray): ByteArray {
        return wrapHandshake(TYPE_FINISHED, verifyData.copyOf())
    }

    // -- CertificateVerify signing input --

    /**
     * The exact octet string a server CertificateVerify signature is computed
     * over (RFC 8446 §4.4.3): 64 octets of 0x20, the ASCII context string
     * "TLS 1.3, server CertificateVerify", a single 0x00 separator, then the
     * handshake [transcriptHash].
     *
     * Exposed so a test can pin the 98-byte prefix, and so the signing side and
     * the verifying side in [TlsClient.verifyCertificateVerify] build byte-for-byte
     * identical input.
     */
    fun certificateVerifyContext(transcriptHash: ByteArray): ByteArray {
        val context = mutableListOf<Byte>()
        repeat(64) { context.add(0x20) }
        context.addAll(CERT_VERIFY_LABEL.asList())
        context.add(0x00)
        context.addAll(transcriptHash.asList())
        return context.toByteArray()
    }

    // -- Extension builders --

    /** supported_versions (RFC 8446 §4.2.1), server form: a single selected version. */
    private fun supportedVersionsServerExt(): List<Byte> {
        val ext = mutableListOf<Byte>()
        ext.appendU16(EXT_SUPPORTED_VERSIONS)
        ext.appendU16(2) // ext_data length
        ext.appendU16(SELECTED_VERSION_TLS13)
        return ext
    }

    /** key_share (RFC 8446 §4.2.8), server form: one KeyShareEntry. */
    private fun keyShareServerExt(group: Int, key: ByteArray): List<Byte> {
        val ext = mutableListOf<Byte>()
        ext.appendU16(EXT_KEY_SHARE)
        ext.appendU16(4 + key.size) // ext_data length = group(2) + keyLen(2) + key
        ext.appendU16(group)
        ext.appendU16(key.size)
        ext.addAll(key.asList())
        return ext
    }

    /** application_layer_protocol_negotiation (RFC 7301). */
    private fun alpnExt(protocols: List<String>): List<Byte> {
        val list = mutableListOf<Byte>()
        for (p in protocols) {
            val bytes = p.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..255) { "ALPN protocol length out of range: ${bytes.size}" }
            list.add(bytes.size.toByte())
            list.addAll(bytes.asList())
        }
        val ext = mutableListOf<Byte>()
        ext.appendU16(EXT_ALPN)
        ext.appendU16(2 + list.size) // ext_data length = list length field(2) + list
        ext.appendU16(list.size)     // ProtocolNameList length
        ext.addAll(list)
        return ext
    }

    // -- Primitive helpers --

    private fun MutableList<Byte>.appendU16(value: Int) {
        add(((value shr 8) and 0xFF).toByte())
        add((value and 0xFF).toByte())
    }

    private fun MutableList<Byte>.appendU24(value: Int) {
        add(((value shr 16) and 0xFF).toByte())
        add(((value shr 8) and 0xFF).toByte())
        add((value and 0xFF).toByte())
    }

    /** Prepends the 1-byte handshake type and 3-byte length to [body]. */
    private fun wrapHandshake(type: Byte, body: ByteArray): ByteArray {
        require(body.size < (1 shl 24)) { "handshake body too large: ${body.size}" }
        val out = ByteArray(4 + body.size)
        out[0] = type
        out[1] = ((body.size shr 16) and 0xFF).toByte()
        out[2] = ((body.size shr 8) and 0xFF).toByte()
        out[3] = (body.size and 0xFF).toByte()
        System.arraycopy(body, 0, out, 4, body.size)
        return out
    }
}
