package com.mythaia.vpn.protocol.wireguard

/**
 * The WireGuard handshake: Noise_IKpsk2 over X25519, ChaCha20-Poly1305 and
 * BLAKE2s, with the message layout from the protocol paper.
 *
 * Initiation (148 bytes) and response (92 bytes) are fixed sizes — every field
 * is fixed width, which is itself part of the design: there is nothing on the
 * wire whose length says anything.
 */
class WireGuardHandshake(
    private val localPrivateKey: ByteArray,
    private val localPublicKey: ByteArray,
    private val peerPublicKey: ByteArray,
    /** Optional pre-shared key, mixed in at the end. All zeroes when unused. */
    private val presharedKey: ByteArray = ByteArray(WireGuardCrypto.KEY_SIZE),
    /**
     * AmneziaWG's wire tweaks: renumbered message types (H1, H2) and random
     * bytes prepended to each handshake message (S1, S2). The defaults are
     * plain WireGuard, which is AmneziaWG with every knob at its identity.
     */
    private val initiationType: Int = MESSAGE_INITIATION,
    private val responseType: Int = MESSAGE_RESPONSE,
    private val initiationJunkSize: Int = 0,
    private val responseJunkSize: Int = 0,
    /**
     * WARP's three reserved bytes ([WireGuardConfig.headerReserved]), or null
     * for plain WireGuard. See [stampReserved] and [isType].
     */
    private val reserved: ByteArray? = null
) {

    /** What a completed handshake yields. */
    class Keys(
        val sendKey: ByteArray,
        val receiveKey: ByteArray,
        val localIndex: Int,
        val peerIndex: Int
    )

    private var chainingKey = ByteArray(0)
    private var hash = ByteArray(0)
    private var ephemeralPrivate = ByteArray(0)
    private var ephemeralPublic = ByteArray(0)

    /** Our own index, echoed by the peer so it can be matched to this session. */
    var localIndex: Int = 0
        private set

    /**
     * Builds the initiation message.
     *
     * @param index our sender index, which the peer will echo back.
     * @param timestamp overridable for tests; defaults to now.
     */
    fun buildInitiation(
        index: Int = randomIndex(),
        timestamp: ByteArray = WireGuardCrypto.tai64n()
    ): ByteArray {
        localIndex = index

        // Ci = HASH(CONSTRUCTION); Hi = HASH(Ci ‖ IDENTIFIER); Hi = HASH(Hi ‖ Spub_r)
        chainingKey = WireGuardCrypto.hash(CONSTRUCTION)
        hash = WireGuardCrypto.hash(WireGuardCrypto.hash(chainingKey, IDENTIFIER), peerPublicKey)

        val (ePriv, ePub) = WireGuardCrypto.generateKeyPair()
        ephemeralPrivate = ePriv
        ephemeralPublic = ePub

        // Ci = KDF1(Ci, Epub_i); Hi = HASH(Hi ‖ Epub_i)
        chainingKey = WireGuardCrypto.kdf(chainingKey, ephemeralPublic, 1)[0]
        hash = WireGuardCrypto.hash(hash, ephemeralPublic)

        // (Ci, k) = KDF2(Ci, DH(Epriv_i, Spub_r))
        val es = WireGuardCrypto.sharedSecret(ephemeralPrivate, peerPublicKey)
        var derived = WireGuardCrypto.kdf(chainingKey, es, 2)
        chainingKey = derived[0]

        val encryptedStatic = WireGuardCrypto.seal(derived[1], 0, localPublicKey, hash)
        hash = WireGuardCrypto.hash(hash, encryptedStatic)

        // (Ci, k) = KDF2(Ci, DH(Spriv_i, Spub_r))
        val ss = WireGuardCrypto.sharedSecret(localPrivateKey, peerPublicKey)
        derived = WireGuardCrypto.kdf(chainingKey, ss, 2)
        chainingKey = derived[0]

        val encryptedTimestamp = WireGuardCrypto.seal(derived[1], 0, timestamp, hash)
        hash = WireGuardCrypto.hash(hash, encryptedTimestamp)

        val body = ByteArray(4 + 4 + 32 + 48 + 28)
        var at = 0
        writeLe32(body, at, initiationType); at += 4
        writeLe32(body, at, index); at += 4
        ephemeralPublic.copyInto(body, at); at += 32
        encryptedStatic.copyInto(body, at); at += 48
        encryptedTimestamp.copyInto(body, at); at += 28

        // The MACs cover the message only. S1's junk is prepended afterwards,
        // so it is outside both the MAC and the peer's length check.
        val message = body + macs(body)
        // The reserved bytes go on after the MACs, over a type word the MACs
        // saw as zeroes — which is what WARP verifies against, because every
        // client that speaks to it stamps them at send time the same way.
        stampReserved(message, 0, reserved)
        return junk(initiationJunkSize) + message
    }

    /**
     * Consumes the peer's response and derives the transport keys.
     *
     * @throws WireGuardError when the message is not a well-formed response to
     *         the initiation this instance sent. A wrong key looks the same as
     *         a tampered packet, and both are refused rather than guessed at.
     */
    fun consumeResponse(response: ByteArray): Keys {
        // S2 prepends random bytes to the response; drop them before parsing.
        // Only a response of exactly the junked length is trimmed, so a peer
        // that turns out not to be sending junk still reports a size mismatch
        // rather than being silently misparsed.
        val message = if (responseJunkSize > 0 &&
            response.size == RESPONSE_SIZE + responseJunkSize
        ) {
            response.copyOfRange(responseJunkSize, response.size)
        } else {
            response
        }

        if (message.size != RESPONSE_SIZE) {
            throw WireGuardError("response is ${message.size} bytes, expected $RESPONSE_SIZE")
        }
        val type = readLe32(message, 0)
        if (!isType(type, responseType, reserved)) {
            throw WireGuardError("message type $type is not a handshake response")
        }

        val peerIndex = readLe32(message, 4)
        val echoedIndex = readLe32(message, 8)
        if (echoedIndex != localIndex) {
            throw WireGuardError("response echoes index $echoedIndex, not ours")
        }

        val peerEphemeral = message.copyOfRange(12, 44)
        val encryptedNothing = message.copyOfRange(44, 60)

        // Cr = KDF1(Cr, Epub_r); Hr = HASH(Hr ‖ Epub_r)
        chainingKey = WireGuardCrypto.kdf(chainingKey, peerEphemeral, 1)[0]
        hash = WireGuardCrypto.hash(hash, peerEphemeral)

        // Cr = KDF1(Cr, DH(Epriv_i, Epub_r)); Cr = KDF1(Cr, DH(Spriv_i, Epub_r))
        chainingKey = WireGuardCrypto.kdf(
            chainingKey, WireGuardCrypto.sharedSecret(ephemeralPrivate, peerEphemeral), 1
        )[0]
        chainingKey = WireGuardCrypto.kdf(
            chainingKey, WireGuardCrypto.sharedSecret(localPrivateKey, peerEphemeral), 1
        )[0]

        // (Cr, τ, k) = KDF3(Cr, Q); Hr = HASH(Hr ‖ τ)
        val derived = WireGuardCrypto.kdf(chainingKey, presharedKey, 3)
        chainingKey = derived[0]
        hash = WireGuardCrypto.hash(hash, derived[1])

        WireGuardCrypto.open(derived[2], 0, encryptedNothing, hash)
            ?: throw WireGuardError("response did not authenticate")
        hash = WireGuardCrypto.hash(hash, encryptedNothing)

        // (T_send, T_recv) = KDF2(Cr, ε)
        val transport = WireGuardCrypto.kdf(chainingKey, ByteArray(0), 2)
        return Keys(
            sendKey = transport[0],
            receiveKey = transport[1],
            localIndex = localIndex,
            peerIndex = peerIndex
        )
    }

    /**
     * The two MACs that close every handshake message.
     *
     * mac1 proves the sender knows the peer's public key, which lets a server
     * drop unauthenticated floods cheaply. mac2 answers a cookie challenge and
     * is zero until one arrives.
     */
    private fun macs(body: ByteArray): ByteArray {
        val mac1Key = WireGuardCrypto.hash(LABEL_MAC1, peerPublicKey)
        val mac1 = WireGuardCrypto.mac(mac1Key, body)

        val mac2 = cookie?.let {
            WireGuardCrypto.mac(it, body + mac1)
        } ?: ByteArray(WireGuardCrypto.MAC_SIZE)

        return mac1 + mac2
    }

    /** `size` random bytes, or nothing when no junk was configured. */
    private fun junk(size: Int): ByteArray =
        if (size > 0) WireGuardCrypto.randomBytes(size) else ByteArray(0)

    /** The most recent cookie from the peer, if it has challenged us. */
    var cookie: ByteArray? = null

    companion object {
        // The type field is a 32-bit little-endian word. The paper writes it
        // as type(1) followed by three reserved zero bytes, which is the same
        // encoding for these four values; AmneziaWG replaces the whole word.
        const val MESSAGE_INITIATION: Int = 1
        const val MESSAGE_RESPONSE: Int = 2
        const val MESSAGE_COOKIE: Int = 3
        const val MESSAGE_TRANSPORT: Int = 4

        const val INITIATION_SIZE = 148
        const val RESPONSE_SIZE = 92

        private val CONSTRUCTION =
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".toByteArray(Charsets.US_ASCII)
        private val IDENTIFIER =
            "WireGuard v1 zx2c4 Jason@zx2c4.com".toByteArray(Charsets.US_ASCII)
        private val LABEL_MAC1 = "mac1----".toByteArray(Charsets.US_ASCII)
        val LABEL_COOKIE = "cookie--".toByteArray(Charsets.US_ASCII)

        fun randomIndex(): Int {
            val bytes = WireGuardCrypto.randomBytes(4)
            return ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)
        }

        /**
         * Puts WARP's reserved bytes into octets 1-3 of the type word at [at].
         *
         * Only the octets change, never the length or anything authenticated:
         * a transport message's header is outside its AEAD, and a handshake
         * message's MACs are computed before this is called.
         */
        fun stampReserved(message: ByteArray, at: Int, reserved: ByteArray?) {
            if (reserved == null || reserved.size != 3 || message.size < at + 4) return
            message[at + 1] = reserved[0]
            message[at + 2] = reserved[1]
            message[at + 3] = reserved[2]
        }

        /**
         * Whether a received type word is [expected].
         *
         * The whole word normally — AmneziaWG's H1-H4 fill all four octets.
         * With reserved bytes in use only the low octet is the type: WARP puts
         * its own bytes in the other three, and Xray and sing-box both clear
         * them before looking, so comparing them would drop every reply.
         */
        fun isType(word: Int, expected: Int, reserved: ByteArray?): Boolean =
            if (reserved != null) (word and 0xFF) == (expected and 0xFF) else word == expected

        fun writeLe32(out: ByteArray, at: Int, value: Int) {
            out[at] = (value and 0xFF).toByte()
            out[at + 1] = ((value ushr 8) and 0xFF).toByte()
            out[at + 2] = ((value ushr 16) and 0xFF).toByte()
            out[at + 3] = ((value ushr 24) and 0xFF).toByte()
        }

        fun readLe32(bytes: ByteArray, at: Int): Int =
            (bytes[at].toInt() and 0xFF) or
                ((bytes[at + 1].toInt() and 0xFF) shl 8) or
                ((bytes[at + 2].toInt() and 0xFF) shl 16) or
                ((bytes[at + 3].toInt() and 0xFF) shl 24)

        fun writeLe64(out: ByteArray, at: Int, value: Long) {
            var v = value
            for (i in 0 until 8) {
                out[at + i] = (v and 0xFF).toByte()
                v = v ushr 8
            }
        }

        fun readLe64(bytes: ByteArray, at: Int): Long {
            var v = 0L
            for (i in 7 downTo 0) {
                v = (v shl 8) or (bytes[at + i].toLong() and 0xFF)
            }
            return v
        }
    }
}
