package com.mythaia.vpn

/**
 * JNI bridge to native C libraries (lwIP, BLAKE3, TLS KDF, libyaml).
 *
 * All native functions are declared here and loaded from a single shared library.
 * Packet / DNS / VLESS utilities are pure Kotlin — see
 * [com.mythaia.vpn.util.PacketUtil].
 */
object NativeBridge {

    init {
        System.loadLibrary("mythaia_native")
    }

    // Callback interface — implemented by LwipStack to receive lwIP events.

    interface LwipCallback {
        fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean)
        fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, pcb: Long): Long
        fun onTcpRecv(connId: Long, data: ByteArray?)
        fun onTcpSent(connId: Long, length: Int)
        fun onTcpErr(connId: Long, err: Int)
        fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, data: ByteArray)
    }

    @Volatile
    var callback: LwipCallback? = null

    // Called from JNI
    @JvmStatic
    fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean) {
        callback?.onOutput(packet, length, isIpv6)
    }

    @JvmStatic
    fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, pcb: Long): Long {
        return callback?.onTcpAccept(srcIp, srcPort, dstIp, dstPort, isIpv6, pcb) ?: 0L
    }

    @JvmStatic
    fun onTcpRecv(connId: Long, data: ByteArray?) {
        callback?.onTcpRecv(connId, data)
    }

    @JvmStatic
    fun onTcpSent(connId: Long, length: Int) {
        callback?.onTcpSent(connId, length)
    }

    @JvmStatic
    fun onTcpErr(connId: Long, err: Int) {
        callback?.onTcpErr(connId, err)
    }

    @JvmStatic
    fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int, isIpv6: Boolean, data: ByteArray) {
        callback?.onUdpRecv(srcIp, srcPort, dstIp, dstPort, isIpv6, data)
    }

    // lwIP — Lifecycle & Packet I/O

    /** Initialize the lwIP stack and register JNI callbacks. */
    @JvmStatic
    external fun nativeInit()

    /** Feed a raw IP packet (from the TUN fd) into lwIP. */
    @JvmStatic
    external fun nativeInput(packet: ByteArray, length: Int)

    /** Poll lwIP timers (call every ~100ms). */
    @JvmStatic
    external fun nativeTimerPoll()

    /**
     * Abort every active TCP PCB without tearing down the netif or
     * listeners. Used on device wake / underlying-network change to
     * invalidate outbound proxy sockets the kernel killed during sleep.
     */
    @JvmStatic
    external fun nativeAbortAllTcp()

    /** Shut down the lwIP stack and clean up. */
    @JvmStatic
    external fun nativeShutdown()

    // lwIP — TCP Operations

    /** Write data to a TCP connection. Returns 0 on success, negative on error. */
    @JvmStatic
    external fun nativeTcpWrite(pcb: Long, data: ByteArray, offset: Int, length: Int): Int

    /** Flush pending TCP data for a connection. */
    @JvmStatic
    external fun nativeTcpOutput(pcb: Long)

    /** Acknowledge received data (update TCP window). */
    @JvmStatic
    external fun nativeTcpRecved(pcb: Long, length: Int)

    /** Gracefully close a TCP connection. */
    @JvmStatic
    external fun nativeTcpClose(pcb: Long)

    /** Abort a TCP connection (immediate RST). */
    @JvmStatic
    external fun nativeTcpAbort(pcb: Long)

    /** Get available send buffer space for a TCP connection. */
    @JvmStatic
    external fun nativeTcpSndbuf(pcb: Long): Int

    /** Get the number of segments queued on a TCP connection. */
    @JvmStatic
    external fun nativeTcpSndQueuelen(pcb: Long): Int

    // lwIP — UDP Operations

    /** Send a UDP datagram through lwIP (back to TUN). */
    @JvmStatic
    external fun nativeUdpSendto(
        srcIp: ByteArray, srcPort: Int,
        dstIp: ByteArray, dstPort: Int,
        isIpv6: Boolean,
        data: ByteArray, length: Int
    )

    // lwIP — Utility

    /** Convert raw IP address bytes to a string. */
    @JvmStatic
    external fun nativeIpToString(addr: ByteArray, isIpv6: Boolean): String?

    // BLAKE3 Hashing

    /** Compute BLAKE3 hash of input. Returns 32 bytes. */
    @JvmStatic
    external fun nativeBlake3Hash(input: ByteArray): ByteArray

    /** Compute BLAKE3 keyed hash. Key must be 32 bytes. Returns 32 bytes. */
    @JvmStatic
    external fun nativeBlake3KeyedHash(key: ByteArray, input: ByteArray): ByteArray

    /** Compute BLAKE3 DeriveKey. Uses context string for domain separation. Returns [outLen] bytes. */
    @JvmStatic
    external fun nativeBlake3DeriveKey(context: String, input: ByteArray, outLen: Int): ByteArray

    // X25519 Key Exchange (pure Kotlin, BouncyCastle-backed)

    /**
     * Generate an X25519 key pair.
     * @return 64 bytes: privateKey(32) + publicKey(32). The private key is
     * already clamped per RFC 7748.
     */
    fun nativeX25519GenerateKeyPair(): ByteArray = X25519Crypto.generateKeyPair()

    /**
     * Compute X25519 shared secret.
     * @param privateKey 32-byte private key.
     * @param peerPublicKey 32-byte peer public key.
     * @return 32-byte shared secret.
     * @throws RuntimeException if the result is the all-zero point (low-order).
     */
    fun nativeX25519KeyAgreement(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
        X25519Crypto.keyAgreement(privateKey, peerPublicKey)

    // TLS 1.3 Key Derivation (pure Kotlin, javax.crypto-backed)

    /**
     * Derive TLS 1.3 handshake keys.
     * @param cipherSuite 0x1301 (AES-128-GCM) or 0x1302 (AES-256-GCM)
     * @return Flat byte array: hsSecret + clientKey + clientIV(12) + serverKey + serverIV(12) + clientTrafficSecret + serverTrafficSecret
     */
    fun nativeTls13DeriveHandshakeKeys(cipherSuite: Int, sharedSecret: ByteArray, transcript: ByteArray): ByteArray? =
        Tls13Crypto.deriveHandshakeKeys(cipherSuite, sharedSecret, transcript)

    /**
     * Derive TLS 1.3 application keys.
     * @return Flat byte array: clientKey + clientIV(12) + serverKey + serverIV(12)
     */
    fun nativeTls13DeriveApplicationKeys(cipherSuite: Int, hsSecret: ByteArray, transcript: ByteArray): ByteArray? =
        Tls13Crypto.deriveApplicationKeys(cipherSuite, hsSecret, transcript)

    /**
     * Compute TLS 1.3 Client Finished verify data.
     * @return verifyData (32 or 48 bytes depending on cipher suite)
     */
    fun nativeTls13ComputeFinished(cipherSuite: Int, clientTrafficSecret: ByteArray, transcript: ByteArray): ByteArray? =
        Tls13Crypto.computeFinished(cipherSuite, clientTrafficSecret, transcript)

    /**
     * Compute transcript hash.
     * @return hash (32 or 48 bytes depending on cipher suite)
     */
    fun nativeTls13TranscriptHash(cipherSuite: Int, messages: ByteArray): ByteArray? =
        Tls13Crypto.transcriptHash(cipherSuite, messages)

    // QUIC (ngtcp2)

    /**
     * Runs the vendored QUIC stack through RFC 9001 Appendix A.
     *
     * Returns null when every intermediate matched the bytes the RFC prints,
     * or a description of the first step that did not. It exists because the
     * unit suite runs on a desktop JVM with no library to load: without it,
     * "compiles" and "links" are the strongest claims available for code that
     * only ever executes on the device.
     */
    /**
     * A QUIC connection, as ngtcp2 models one.
     *
     * ngtcp2 is a state machine rather than a socket: it is fed the datagrams
     * that arrived, asked for the datagrams to send, and told when its timer
     * expired. The socket, the event loop and the TLS handshake are all above
     * this line — which is why the handshake callbacks hand their bytes up
     * rather than answering in C. A second TLS implementation next to the
     * Kotlin one would be a second thing to get wrong.
     */
    interface QuicCallback {
        /**
         * Handshake bytes, or a request for the first flight.
         *
         * [level] is the encryption level the bytes arrived at, or -1 to mean
         * "produce the ClientHello" — at which point the implementation is
         * expected to call [nativeQuicSubmitCrypto] before returning.
         */
        fun onCryptoData(level: Int, data: ByteArray?)

        fun onStreamData(streamId: Long, data: ByteArray, fin: Boolean)
        fun onStreamClose(streamId: Long, errorCode: Long)
        fun onHandshakeComplete()
    }

    /** Zero when the connection could not be created. */
    @JvmStatic
    external fun nativeQuicConnCreate(
        remoteIp: String,
        remotePort: Int,
        localIp: String,
        localPort: Int,
        callback: QuicCallback
    ): Long

    @JvmStatic
    external fun nativeQuicConnFree(handle: Long)

    /** Feeds one received datagram in. Negative is an ngtcp2 error code. */
    @JvmStatic
    external fun nativeQuicConnRead(handle: Long, packet: ByteArray, length: Int): Int

    /**
     * The next datagram to send, or null when there is nothing.
     *
     * Call it in a loop until it returns null: ngtcp2 decides from its own
     * pacing and congestion state how much may go out now.
     */
    @JvmStatic
    external fun nativeQuicConnWrite(handle: Long): ByteArray?

    /**
     * Offers stream data and returns the datagram it produced, or null.
     *
     * Both halves matter: ngtcp2 serialises a packet *and* reports how much of
     * the payload went into it, and those are different numbers. The byte count
     * lands in `acceptedOut[0]`. Taking fewer than offered, or none, is normal
     * — flow control and congestion both say so — and the caller offers the
     * remainder again.
     */
    @JvmStatic
    external fun nativeQuicConnWriteStream(
        handle: Long,
        streamId: Long,
        data: ByteArray?,
        fin: Boolean,
        acceptedOut: LongArray
    ): ByteArray?

    /**
     * Marks the end of a send burst so ngtcp2 can pace the next one.
     *
     * Without it the pacing interval is never consulted and a whole window
     * leaves as fast as the socket accepts it.
     */
    @JvmStatic
    external fun nativeQuicConnFlushDone(handle: Long)

    /**
     * Hands the peer's transport parameters to ngtcp2.
     *
     * These are the limits it actually enforces; decoding them in Kotlin is for
     * diagnostics. Without this it keeps its own defaults and never learns the
     * peer's stream or flow-control credit.
     */
    @JvmStatic
    external fun nativeQuicSetRemoteParams(handle: Long, params: ByteArray): Int

    /**
     * Tells ngtcp2 the TLS handshake finished.
     *
     * Only after the server's Finished has been verified — this is what
     * promotes the connection to carrying application data.
     */
    @JvmStatic
    external fun nativeQuicHandshakeCompleted(handle: Long)

    /** When the connection next needs attention, in monotonic nanoseconds. */
    @JvmStatic
    external fun nativeQuicConnExpiry(handle: Long): Long

    @JvmStatic
    external fun nativeQuicConnHandleExpiry(handle: Long): Int

    /**
     * Tells the connection which cipher suite the handshake settled on.
     *
     * The Android crypto backend carries the suite *as* the TLS native handle —
     * an integer where another backend would put a pointer to its TLS object —
     * so nothing can be encrypted until this is set, and it must land as soon
     * as the ServerHello names the suite. Returns 0, or a negative ngtcp2 error
     * for a suite the backend does not implement.
     */
    @JvmStatic
    external fun nativeQuicSetCipherSuite(handle: Long, suite: Int): Int

    /** Hands the handshake bytes produced by the TLS layer to the connection. */
    @JvmStatic
    external fun nativeQuicSubmitCrypto(handle: Long, level: Int, data: ByteArray): Int

    /** Installs the traffic secrets for one encryption level, both directions. */
    @JvmStatic
    external fun nativeQuicInstallKeys(
        handle: Long,
        level: Int,
        rxSecret: ByteArray?,
        txSecret: ByteArray?
    ): Int

    /** The new stream's id, or a negative ngtcp2 error code. */
    @JvmStatic
    external fun nativeQuicOpenBidiStream(handle: Long): Long

    @JvmStatic
    external fun nativeQuicShutdownStream(handle: Long, streamId: Long, errorCode: Long)

    /**
     * Reports that [count] bytes of a stream have been consumed.
     *
     * Without it the peer's flow-control window closes and the transfer stalls
     * partway through with nothing logged anywhere.
     */
    @JvmStatic
    external fun nativeQuicExtendOffsets(handle: Long, streamId: Long, count: Int)

    @JvmStatic
    external fun nativeQuicSelfTest(): String?

    /** The vendored ngtcp2 version, for the log and the About screen. */
    @JvmStatic
    external fun nativeQuicVersion(): String

    // YAML Parsing (libyaml)

    /** Parse YAML content and return JSON string representation. Returns null on failure. */
    @JvmStatic
    external fun nativeParseYaml(yamlContent: String): String?
}
