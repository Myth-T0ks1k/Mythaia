package com.mythaia.vpn.protocol.sudoku

/**
 * The pure half of standing a Sudoku connection up: what goes on the wire during
 * the KIP exchange, and how the server's answer is read back.
 *
 * Kept apart from [SudokuSession] for the same reason [NowhereFlowOpen] is kept
 * apart from its session — the two things that are easy to get subtly wrong are
 * the exact bytes of the client hello and the classification of the reply, and
 * both can be checked against a second transcription of the reference without a
 * socket, an X25519 key, or a record layer under them. Everything here is a
 * function of its arguments; the key agreement and the randomness that feed it
 * live in the session, which is the only part that cannot be made deterministic.
 *
 * KIP has no negotiation to speak of. The client sends one hello carrying its
 * ephemeral X25519 public key and a nonce; the server answers with a hello of
 * its own that echoes the nonce and carries its public key, and that single
 * answer both proves the server holds the pre-shared key (the hello rides the
 * PSK-keyed record layer) and supplies the second half of the exchange. A reply
 * that is not a server hello is therefore not a "try again" — it is a server
 * that is not speaking KIP — which is why the classification below has exactly
 * three outcomes and no waiting state.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
internal object SudokuHandshake {

    /**
     * The KIP client hello, framed and ready to hand to the record layer.
     *
     * The hello is assembled by [SudokuProtocol.encodeClientHello] and wrapped in
     * a KIP frame here; splitting it this way keeps the one place that fixes the
     * on-wire byte order — timestamp, key fingerprint, nonce, public key, feature
     * flags, optional table hint — in the protocol file, and leaves this object
     * responsible only for the envelope.
     *
     * [tableHint] is supplied only when the configuration offers more than one
     * custom layout; with a single agreed layout the hint would be four constant
     * bytes on every hello and thus a fingerprint of its own, so it is omitted.
     */
    fun clientHelloFrame(
        keyFingerprintSource: ByteArray,
        unixSeconds: Long,
        clientPublicKey: ByteArray,
        nonce: ByteArray,
        tableHint: Long?
    ): ByteArray {
        val payload = SudokuProtocol.encodeClientHello(
            unixSeconds = unixSeconds,
            keyFingerprintSource = keyFingerprintSource,
            nonce = nonce,
            clientPublicKey = clientPublicKey,
            tableHint = tableHint
        )
        return SudokuProtocol.encodeKip(SudokuProtocol.KIP_CLIENT_HELLO, payload)
    }

    /** What the server's first KIP message turned out to be. */
    sealed class ServerHello {
        /**
         * A valid server hello, whose nonce echoed the one we sent. [publicKey]
         * is the server's X25519 public key, ready for the shared-secret step.
         */
        class Ready(val publicKey: ByteArray) : ServerHello()

        /**
         * The server answered with a KIP message that is not a server hello.
         *
         * This is not authentication failure — a server that refuses the
         * credentials closes the stream rather than replying — but a peer that
         * is not speaking the handshake at all, so the dial cannot proceed.
         */
        class Rejected(val type: Byte) : ServerHello()
    }

    /**
     * Classifies the server's first KIP message.
     *
     * A message that is not a server hello is [ServerHello.Rejected]; a server
     * hello whose length is wrong or whose nonce does not echo ours is malformed
     * and throws, because accepting either would let a recorded hello be replayed
     * to make the client derive keys for a session the server never opened.
     */
    fun classifyServerHello(type: Byte, payload: ByteArray, expectedNonce: ByteArray): ServerHello {
        if (type != SudokuProtocol.KIP_SERVER_HELLO) return ServerHello.Rejected(type)
        // Throws SudokuError.ProtocolViolation on a bad size or a nonce that does
        // not match — the "malformed" arm the caller must treat as fatal.
        val serverPublicKey = SudokuProtocol.parseServerHello(payload, expectedNonce)
        return ServerHello.Ready(serverPublicKey)
    }

    /**
     * The request that opens a proxied TCP flow to [host]:[port].
     *
     * Sent once the session keys are in place; the destination travels in SOCKS5
     * address form, which is what every Sudoku request and UDP frame carries.
     */
    fun connectTcpRequest(host: String, port: Int): ByteArray =
        SudokuProtocol.encodeKip(SudokuProtocol.KIP_CONNECT_TCP, SudokuProtocol.encodeAddress(host, port))

    /**
     * The request that opens a multiplexed session (`KIP_OPEN_MUX = 0x11`).
     *
     * Like [openUdpRequest], the payload is empty: individual TCP destinations
     * travel in `MUX_OPEN` (`0x01`) frames once the record stream enters
     * multiplexed mode.
     */
    fun openMuxRequest(): ByteArray =
        SudokuProtocol.encodeKip(SudokuProtocol.KIP_OPEN_MUX, ByteArray(0))

    /**
     * The request that opens a UDP-over-TCP flow.
     *
     * The payload is empty: unlike a TCP connect, the destination is not fixed at
     * open time but travels in the header of every datagram frame, so there is
     * nothing to name here.
     */
    fun openUdpRequest(): ByteArray =
        SudokuProtocol.encodeKip(SudokuProtocol.KIP_OPEN_UDP_OVER_TCP, ByteArray(0))
}
