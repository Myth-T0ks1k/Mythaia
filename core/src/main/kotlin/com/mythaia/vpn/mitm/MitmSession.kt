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
 * for the host ([TlsServer] over [MitmLeafCertificates]), then runs the decrypted
 * exchange through the bridge for the negotiated protocol — [MitmHttp1Bridge] or
 * [MitmHttp2Bridge] — **dialing** the real origin (always over HTTP/1.1) through
 * the injected `dialUpstream` so the configured [MitmRuleSet] can read and edit it.
 *
 * # The HTTP/2 decision
 *
 * Both protocols are now carried. [TlsServer] is offered `{h2, http/1.1}` in
 * ALPN, and after termination the bridge is chosen by what the client settled on:
 *
 *  - `h2` → [MitmHttp2Bridge], which terminates the client's h2 connection and,
 *    per request stream, dials the origin over HTTP/1.1 and runs the same rules;
 *  - `http/1.1` (or no ALPN at all) → the unchanged [MitmHttp1Bridge] over a single
 *    upstream leg dialed for the one protocol the client chose ([upstreamAlpns]).
 *
 * The origin is spoken to in HTTP/1.1 in **both** cases — `dialUpstream` returns an
 * h1 leg — so the h2 path is an h2⇄h1 translation, not an h2 splice (which is
 * impossible once TLS is terminated: the client is talking to us, not to them).
 * Offering both protocols means a modern `h2`-preferring client is intercepted
 * rather than having its handshake abandoned, which is why the earlier
 * http/1.1-only restriction is gone.
 *
 * # Teardown
 *
 * Every exit closes the client side. A handshake failure ([TlsServer] has
 * already written the fatal alert) force-cancels the client transport; an h1 dial
 * failure closes the terminated client leg; a completed exchange is closed by the
 * bridge itself ([MitmHttp1Bridge.run] closes both legs; [MitmHttp2Bridge.run]
 * closes the client leg and each stream's own upstream leg). [intercept] never
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

    /** The application protocols an intercepted connection can speak; both are carried. */
    const val HTTP_1_1 = "http/1.1"
    const val H2 = "h2"

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
     *   the intercepted client settled on (see [upstreamAlpns]), and the bridges
     *   call it again for a request a rule rewrote onto another origin.
     * @param leafCertificates the cache the leaf for [host] is taken from;
     *   defaults to the process-wide one (see [leafCertificatesFor]).
     */
    suspend fun intercept(
        clientTransport: Transport,
        bufferedClientHello: ByteArray,
        host: String,
        port: Int,
        ruleSet: MitmRuleSet,
        authority: MitmCertificateAuthority,
        dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg,
        leafCertificates: MitmLeafCertificates = leafCertificatesFor(authority)
    ) {
        // Terminate the client TLS, offering both protocols; the negotiated ALPN
        // then picks the bridge (see the class note on the h2 decision).
        val server = TlsServer(
            transport = clientTransport,
            leafCertificates = leafCertificates,
            supportedAlpns = listOf(H2, HTTP_1_1)
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
     * Dispatches an already-terminated [clientLeg] to the bridge for the protocol
     * it negotiated, then runs it: `h2` → [MitmHttp2Bridge] (which dials one h1
     * origin leg per stream itself), anything else → the single-leg
     * [MitmHttp1Bridge] over an upstream dialed here first.
     *
     * Split out from [intercept] so the dispatch-and-bridge half can be driven in a
     * unit test with an in-memory client leg — standing up a real [TlsServer]
     * handshake needs the native crypto library, which the off-device suite cannot
     * load (see `TlsServerHandshakeTest`). The two `run*Bridge` seams default to the
     * real bridges and are overridden by the dispatch test with recording fakes, so
     * the ALPN routing is asserted without a live handshake.
     */
    internal suspend fun bridgeTerminatedClient(
        clientLeg: MitmByteLeg,
        host: String,
        port: Int,
        ruleSet: MitmRuleSet,
        dialUpstream: suspend (host: String, port: Int, alpn: List<String>) -> MitmByteLeg,
        runH2Bridge: suspend (client: MitmByteLeg) -> Unit =
            { c -> MitmHttp2Bridge.forTls(c, host, port, ruleSet, dialUpstream).run() },
        runH1Bridge: suspend (client: MitmByteLeg, upstream: MitmByteLeg) -> Unit =
            { c, u ->
                // The bridge is told what its leg was dialed to and how to dial
                // another, so a request a rule rewrites onto a different origin
                // reaches that origin rather than the SNI host.
                MitmHttp1Bridge.forTls(
                    c, u, ruleSet, originHost = host, originPort = port, dialUpstream = dialUpstream
                ).run()
            }
    ) {
        // h2: the bridge owns the whole connection and dials per stream, so no
        // single upstream leg is opened here. Its run() closes the client leg.
        if (clientLeg.negotiatedAlpn == H2) {
            logger.info("[MITM] $host:$port: intercepting over h2 with rule set '${ruleSet.name}'")
            try {
                runH2Bridge(clientLeg)
            } catch (e: Exception) {
                logger.warning("[MITM] $host:$port: intercepted h2 exchange ended on an error (${e.message})")
            }
            return
        }

        // http/1.1 (or no ALPN): dial one upstream leg for the whole connection.
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
            runH1Bridge(clientLeg, upstreamLeg)
        } catch (e: Exception) {
            logger.warning("[MITM] $host:$port: intercepted exchange ended on an error (${e.message})")
        }
    }

    /**
     * The ALPN protocols to offer the origin on the **HTTP/1.1** path, given what
     * the intercepted client settled on.
     *
     * The h2 case is dispatched away before this is consulted ([MitmHttp2Bridge]
     * dials its own per-stream h1 legs), so this is reached only for a client that
     * negotiated `http/1.1` or offered no ALPN — both resolve to `["http/1.1"]`,
     * the only protocol the h1 bridge can carry on its single upstream leg. The
     * `h2` fallback is kept defensively (a mis-dispatch would still dial h1, never
     * an h2 origin the h1 bridge cannot frame).
     */
    internal fun upstreamAlpns(negotiatedInnerAlpn: String?): List<String> {
        val usable = negotiatedInnerAlpn?.takeIf { it.isNotEmpty() && it != "h2" } ?: HTTP_1_1
        return listOf(usable)
    }

    /**
     * The leaf cache a connection under [authority] takes its certificate from.
     *
     * In production the tunnel hook reads the CA off [MitmRuleStore.shared], so
     * [authority] is that store's CA and the store's own [MitmRuleStore.leafCertificates]
     * cache is returned: a repeat host reuses its leaf and no P-256 key pair is
     * generated per connection. Building a fresh [MitmLeafCertificates] per
     * interception, as before, minted a new key and certificate for every
     * connection and left the shared cache unused. A CA that is not the shared
     * store's (an isolated store in a test) gets a private cache; so does the
     * rare race where the shared CA is cleared between the two reads.
     */
    internal fun leafCertificatesFor(authority: MitmCertificateAuthority): MitmLeafCertificates {
        val store = MitmRuleStore.shared
        if (store.authority() === authority) {
            runCatching { store.leafCertificates() }.getOrNull()?.let { return it }
        }
        return MitmLeafCertificates(authority)
    }
}
