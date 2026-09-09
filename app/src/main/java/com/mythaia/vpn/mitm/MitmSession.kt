package com.mythaia.vpn.mitm

import com.mythaia.vpn.protocol.Transport
import com.mythaia.vpn.protocol.tls.TlsError
import com.mythaia.vpn.protocol.tls.TlsServer
import com.mythaia.vpn.util.MythaiaLogger

private val logger = MythaiaLogger("MitmSession")

/**
 * One intercepted HTTPS connection, assembled from the finished pieces.
 *
 * When the tunnel has sniffed a hostname the user chose to intercept, it hands
 * the still-unanswered client connection here. [intercept] then plays the role
 * the real origin would: it **terminates** the client's TLS with a leaf minted
 * for the host ([TlsServer] over [MitmLeafCertificates]), **dials** the real
 * origin through the injected [intercept]'s `dialUpstream`, and runs the
 * plaintext HTTP/1.1 exchange between the two through [MitmHttp1Bridge] so the
 * configured [MitmRuleSet] can read and edit it.
 *
 * # The HTTP/2 decision
 *
 * [MitmHttp1Bridge] speaks HTTP/1.1 only — HTTP/2 interception is a later
 * effort. [TlsServer] would, left to its defaults, offer `{h2, http/1.1}` in
 * ALPN, and a modern client would pick `h2`; the bridge would then see an `h2`
 * leg and splice the connection through raw, so no rule would ever fire. Worse,
 * once TLS is terminated there is nothing left to splice back to the origin with
 * — the client is already talking to us, not to them.
 *
 * So this takes option (a) from the design note: **do not offer h2**. The
 * server is constructed with `supportedAlpns = listOf("http/1.1")`, which means
 *
 *  - a client that can speak HTTP/1.1 negotiates it, and the bridge handles the
 *    whole connection; the upstream leg is then dialed asking for the same
 *    single protocol ([upstreamAlpns]);
 *  - a client that offers ALPN but *only* `h2` overlaps nothing, so [TlsServer]
 *    sends a `no_application_protocol` fatal alert and the handshake fails —
 *    interception is cleanly abandoned (the connection is torn down, not
 *    silently broken), which is the honest outcome for a host we cannot yet
 *    intercept over h2. This is rare: virtually every `h2` client also offers
 *    `http/1.1`.
 *
 * A raw splice is deliberately *not* attempted as a fallback, because it is
 * impossible after the TLS has been terminated — the correct move is to never
 * offer a protocol we cannot carry, which is exactly what restricting the ALPN
 * does.
 *
 * # Teardown
 *
 * Every exit closes the client side. A handshake failure ([TlsServer] has
 * already written the fatal alert) force-cancels the client transport; a dial
 * failure closes the terminated client leg; a completed exchange is closed by
 * the bridge itself ([MitmHttp1Bridge.run] closes both legs). [intercept] never
 * throws for an ordinary failure — it owns the connection once called and tears
 * it down — so the caller can launch it and forget it.
 *
 * `dialUpstream` is injected rather than reaching into [com.mythaia.vpn.protocol.tls.TlsClient]
 * and the tunnel's routing directly, so the sequencing above is unit-testable
 * with in-memory legs and the session does not hard-couple to how the outer dial
 * is made.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0), Copyright (C) 2026 NodePassProject.
 */
object MitmSession {

    /** The only application protocol an intercepted connection speaks for now. */
    const val HTTP_1_1 = "http/1.1"

    /**
     * Terminates, dials, and bridges one intercepted connection, then tears it
     * down. Does not throw for an ordinary handshake or dial failure.
     *
     * @param clientTransport the client-facing byte stream the tunnel handed
     *   over, positioned just after the sniffed ClientHello.
     * @param bufferedClientHello the ClientHello bytes already read off the
     *   wire (one record or several); [TlsServer] reassembles and, if short,
     *   tops up from [clientTransport].
     * @param host the sniffed SNI host the leaf is minted for and the upstream
     *   is dialed to.
     * @param port the destination port of the upstream dial.
     * @param ruleSet the rule set selected for [host] by [MitmRuleStore].
     * @param authority the CA the minted leaf chains to.
     * @param dialUpstream opens the origin leg given the host, port and the
     *   ALPN protocols to offer; the session calls it with the single protocol
     *   the intercepted client settled on (see [upstreamAlpns]).
     */
    suspend fun intercept(
        clientTransport: Transport,
        bufferedClientHello: ByteArray,
        host: String,
        port: Int,
        ruleSet: MitmRuleSet,
        authority: MitmCertificateAuthority,
        dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg
    ) {
        // Terminate the client TLS, offering http/1.1 only so the bridge always
        // sees a protocol it can carry (see the class note on the h2 decision).
        val server = TlsServer(
            transport = clientTransport,
            leafCertificates = MitmLeafCertificates(authority),
            supportedAlpns = listOf(HTTP_1_1)
        )

        val terminated = try {
            server.handshake(bufferedClientHello)
        } catch (e: TlsError) {
            // TlsServer has already written the fatal alert; close the client
            // side and abandon interception. No upstream was dialed.
            logger.warning("[MITM] $host:$port: client TLS handshake failed (${e.message}); tearing down")
            runCatching { clientTransport.forceCancel() }
            return
        } catch (e: Exception) {
            logger.warning("[MITM] $host:$port: client TLS termination errored (${e.message}); tearing down")
            runCatching { clientTransport.forceCancel() }
            return
        }

        val clientLeg = TlsRecordByteLeg(terminated)
        bridgeTerminatedClient(clientLeg, host, port, ruleSet, dialUpstream)
    }

    /**
     * Dials the upstream for an already-terminated [clientLeg] and runs the
     * HTTP/1.1 bridge between them, closing [clientLeg] if the dial fails.
     *
     * Split out from [intercept] so the dial-and-bridge half can be driven in a
     * unit test with an in-memory client leg — standing up a real [TlsServer]
     * handshake needs the native crypto library, which the off-device suite
     * cannot load (see `TlsServerHandshakeTest`).
     */
    internal suspend fun bridgeTerminatedClient(
        clientLeg: MitmByteLeg,
        host: String,
        port: Int,
        ruleSet: MitmRuleSet,
        dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg
    ) {
        val alpn = upstreamAlpns(clientLeg.negotiatedAlpn)
        val upstreamLeg = try {
            dialUpstream(host, port, alpn)
        } catch (e: Exception) {
            logger.warning("[MITM] $host:$port: upstream dial failed (${e.message}); closing the intercepted client")
            runCatching { clientLeg.close() }
            return
        }

        // The bridge drives the whole exchange and closes both legs when done.
        // Its run() swallows only a framing error before its own teardown, so an
        // ordinary mid-exchange leg failure — an upstream alert or reset surfacing
        // as a thrown record — would otherwise escape here and break the
        // fire-and-forget contract the caller (a detached tunnel coroutine) relies
        // on. The legs are already closed by run()'s finally; all that is left is
        // to keep the throw from propagating.
        logger.info("[MITM] $host:$port: intercepting over ${alpn.joinToString(",")} with rule set '${ruleSet.name}'")
        try {
            MitmHttp1Bridge.forTls(clientLeg, upstreamLeg, ruleSet).run()
        } catch (e: Exception) {
            logger.warning("[MITM] $host:$port: intercepted exchange ended on an error (${e.message})")
        }
    }

    /**
     * The ALPN protocols to offer the origin, given what the intercepted client
     * settled on.
     *
     * Because the client leg only ever negotiates `http/1.1` (we offer nothing
     * else), this resolves to `["http/1.1"]`. It is written defensively all the
     * same: a null or empty negotiated value (client sent no ALPN) and, should
     * the server ever be widened, an `h2` value both fall back to `http/1.1`,
     * because that is the only protocol the bridge can carry on the upstream leg.
     */
    internal fun upstreamAlpns(negotiatedInnerAlpn: String?): List<String> {
        val usable = negotiatedInnerAlpn?.takeIf { it.isNotEmpty() && it != "h2" } ?: HTTP_1_1
        return listOf(usable)
    }
}
