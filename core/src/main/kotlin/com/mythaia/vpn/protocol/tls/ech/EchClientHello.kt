package com.mythaia.vpn.protocol.tls.ech

/**
 * Building the ClientHello pair that Encrypted Client Hello needs.
 *
 * ECH sends two hellos in one. The *inner* one carries the name actually being
 * reached and is encrypted; the *outer* one carries the config's public name in
 * the clear and looks, to anything watching, like an ordinary connection to
 * that host. A server holding the config decrypts the inner and answers it; one
 * that does not answers the outer, and the connection is merely not private
 * rather than broken.
 *
 * The construction has one awkward part, and it is where mistakes live. The
 * encryption's associated data is the serialised *outer* hello — which contains
 * the ciphertext being produced. It is resolved by building the outer twice:
 * once with the payload zero-filled to its eventual length, which is what gets
 * signed over, and once with the real ciphertext. Both are the same length, so
 * the layout is identical and the server can zero the payload back out and
 * arrive at the same associated data.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
object EchClientHello {

    /** `encrypted_client_hello`, RFC 9180's TLS extension. */
    const val EXTENSION_TYPE = 0xFE0D

    /** The byte that says this is the outer half of a pair. */
    private const val ECH_CLIENT_HELLO_OUTER: Byte = 0x00

    /**
     * The inner hello as it is encrypted: header stripped, then padded.
     *
     * The padding is the point. Without it the ciphertext length would leak the
     * length of the name inside — a short domain and a long one would be
     * visibly different — so the body is padded out to hide the difference and
     * then to a multiple of 32 so the total is coarse.
     */
    fun encodeInner(innerMessage: ByteArray, serverName: String, maxNameLength: Int): ByteArray {
        require(innerMessage.size >= 4) { "inner ClientHello is too short to have a header" }

        val body = innerMessage.copyOfRange(4, innerMessage.size)

        var padding = if (serverName.isNotEmpty()) {
            maxOf(0, maxNameLength - serverName.toByteArray(Charsets.UTF_8).size)
        } else {
            // No name at all still has to look like one of typical length,
            // plus the nine bytes an SNI extension costs around it.
            maxNameLength + 9
        }

        // Round the whole thing up to a multiple of 32.
        val offset = (body.size + padding - 1) % 32
        padding += 31 - (if (offset < 0) offset + 32 else offset)

        return if (padding > 0) body + ByteArray(padding) else body
    }

    /**
     * The extension body: which half this is, the suite, the config it answers,
     * the encapsulated key, and the payload.
     */
    fun outerExtensionData(
        configId: Int,
        kdfId: Int,
        aeadId: Int,
        encapsulatedKey: ByteArray,
        payload: ByteArray
    ): ByteArray {
        val out = ByteArray(1 + 2 + 2 + 1 + 2 + encapsulatedKey.size + 2 + payload.size)
        var at = 0
        out[at++] = ECH_CLIENT_HELLO_OUTER
        out[at++] = (kdfId ushr 8).toByte()
        out[at++] = kdfId.toByte()
        out[at++] = (aeadId ushr 8).toByte()
        out[at++] = aeadId.toByte()
        out[at++] = configId.toByte()
        out[at++] = (encapsulatedKey.size ushr 8).toByte()
        out[at++] = encapsulatedKey.size.toByte()
        encapsulatedKey.copyInto(out, at); at += encapsulatedKey.size
        out[at++] = (payload.size ushr 8).toByte()
        out[at++] = payload.size.toByte()
        payload.copyInto(out, at)
        return out
    }

    /** Wraps the body as a TLS extension. */
    fun asExtension(body: ByteArray): ByteArray {
        val out = ByteArray(4 + body.size)
        out[0] = (EXTENSION_TYPE ushr 8).toByte()
        out[1] = EXTENSION_TYPE.toByte()
        out[2] = (body.size ushr 8).toByte()
        out[3] = body.size.toByte()
        body.copyInto(out, 4)
        return out
    }

    /** What [build] produced, and what the caller needs afterwards. */
    class Result(
        /** The hello to put on the wire. */
        val outerMessage: ByteArray,
        /**
         * The inner hello as the server reconstructs it — the outer's session
         * id, not the empty one that was encrypted. This is what goes into the
         * transcript if the server accepts ECH, and using the encrypted form
         * instead produces keys that do not match.
         */
        val innerTranscript: ByteArray,
        val context: EchClientContext
    )

    /**
     * Builds the pair.
     *
     * [buildHello] is asked for a complete ClientHello given a session id, a
     * server name and any extra extension — the caller supplies it so the
     * fingerprint the outer hello wears stays the caller's decision.
     */
    fun build(
        config: EchConfig,
        cipherSuite: EchCipherSuite,
        outerSessionId: ByteArray,
        innerServerName: String,
        buildHello: (sessionId: ByteArray, serverName: String, extra: ByteArray?, inner: Boolean) -> ByteArray
    ): Result {
        val context = EchClientContext.create(config, cipherSuite)

        // The encrypted inner carries no session id; the server puts the
        // outer's back before using it. It carries its own ECH extension, of
        // the inner kind (§7.1): without it, or with the outer's GREASE stub
        // in its place, a server that decrypts it rejects the hello.
        val innerMessage = buildHello(ByteArray(0), innerServerName, innerExtension(), true)
        val encodedInner = encodeInner(innerMessage, innerServerName, config.maxNameLength)
        val ciphertextLength = encodedInner.size + EchClientContext.AEAD_TAG_LENGTH

        // Pass one: an outer whose payload is zeros of the right length. Its
        // body is the associated data the seal is bound to.
        val zeroed = outerExtensionData(
            config.configId, cipherSuite.kdfId, cipherSuite.aeadId,
            context.enc, ByteArray(ciphertextLength)
        )
        val outerForAad = buildHello(outerSessionId, config.publicName, asExtension(zeroed), false)
        val aad = outerForAad.copyOfRange(4, outerForAad.size)

        val ciphertext = context.seal(encodedInner, aad)
        check(ciphertext.size == ciphertextLength) {
            "sealed ${ciphertext.size} bytes where the AAD assumed $ciphertextLength"
        }

        // Pass two: the same hello with the real ciphertext. Identical length
        // means identical layout, which is what lets the server re-derive the
        // associated data by zeroing the payload back out.
        val real = outerExtensionData(
            config.configId, cipherSuite.kdfId, cipherSuite.aeadId,
            context.enc, ciphertext
        )
        val outerMessage = buildHello(outerSessionId, config.publicName, asExtension(real), false)

        return Result(
            outerMessage = outerMessage,
            innerTranscript = buildHello(outerSessionId, innerServerName, innerExtension(), true),
            context = context
        )
    }

    /** The `encrypted_client_hello` extension of type inner: one byte, ECHClientHelloType.inner. */
    private fun innerExtension(): ByteArray = asExtension(byteArrayOf(0x01))
}
