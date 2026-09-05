package com.mythaia.vpn.protocol.nowhere

import com.mythaia.data.model.TlsConfiguration
import com.mythaia.data.model.TlsVersion

/**
 * Everything a Nowhere carrier needs to know before it says anything.
 *
 * The shape is small but two of its fields are not simply what the user typed.
 * [authKey] is derived from the shared secret once, here, rather than on every
 * connection, because the derivation is the expensive half of authentication
 * and the result is constant for the life of the configuration. And [multiplex]
 * is narrowed on construction: multiplexing needs a stream carrier, so asking
 * for it on a flow that is UDP in both directions is a request that cannot be
 * honoured and is quietly dropped rather than failing a connection later.
 *
 * [sessionId] is not generated here. It identifies one client across every
 * carrier it opens — the portal uses it to pair the two halves of an
 * asymmetric flow — so it has to outlive any single configuration instance and
 * is supplied by whatever owns that identity.
 *
 * Derived from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */
class NowhereConfiguration(
    val proxyHost: String,
    val proxyPort: Int,
    val key: String,
    val uplink: NowhereNetwork,
    val downlink: NowhereNetwork,
    requestedMultiplex: Boolean,
    val sessionId: ByteArray,
    val tls: TlsConfiguration
) {
    /**
     * The ALPN this client offers and requires back.
     *
     * A configuration may name its own, which is how a deployment hides behind
     * some other protocol's identifier; absent that it is
     * [NowhereProtocol.DEFAULT_ALPN].
     */
    val alpn: String

    /** Whether several flows may share one stream carrier. */
    val multiplex: Boolean

    /** The 32-byte key that signs auth frames, derived from [key]. */
    val authKey: ByteArray

    init {
        if (sessionId.size != NowhereProtocol.SESSION_ID_SIZE) {
            throw NowhereError.ProtocolViolation("Invalid Nowhere session ID")
        }
        val negotiated = tls.alpn?.firstOrNull() ?: NowhereProtocol.DEFAULT_ALPN
        // The ALPN length is a single byte on the TLS wire, so a longer one
        // could not be offered even if the portal expected it.
        if (negotiated.isEmpty() || negotiated.toByteArray(Charsets.UTF_8).size > 255) {
            throw NowhereError.ProtocolViolation("Invalid Nowhere ALPN")
        }
        alpn = negotiated
        multiplex = requestedMultiplex &&
            (uplink == NowhereNetwork.TCP || downlink == NowhereNetwork.TCP)
        authKey = NowhereProtocol.deriveAuthKey(key)
    }

    /**
     * The TLS settings a stream carrier dials with.
     *
     * The ALPN list is replaced with exactly the one ALPN, and the version is
     * pinned to 1.3 in both directions: the auth frame is bound to a TLS
     * exporter, and exporters are only defined the way this protocol needs
     * from TLS 1.3 onwards (RFC 8446 §7.5).
     */
    val tcpTlsConfiguration: TlsConfiguration
        get() = tls.copy(
            alpn = listOf(alpn),
            minVersion = TlsVersion.TLS13,
            maxVersion = TlsVersion.TLS13
        )

    /**
     * Whether the ALPN the handshake settled on is the one that was asked for.
     *
     * A portal that negotiated something else is not speaking this protocol,
     * and continuing would put Nowhere framing onto a connection expecting
     * something different.
     */
    fun acceptsNegotiatedAlpn(negotiated: String): Boolean = negotiated == alpn

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is NowhereConfiguration &&
                proxyHost == other.proxyHost &&
                proxyPort == other.proxyPort &&
                key == other.key &&
                uplink == other.uplink &&
                downlink == other.downlink &&
                multiplex == other.multiplex &&
                sessionId.contentEquals(other.sessionId) &&
                tls == other.tls
            )

    override fun hashCode(): Int {
        var result = proxyHost.hashCode()
        result = 31 * result + proxyPort
        result = 31 * result + key.hashCode()
        result = 31 * result + uplink.hashCode()
        result = 31 * result + downlink.hashCode()
        result = 31 * result + multiplex.hashCode()
        result = 31 * result + sessionId.contentHashCode()
        result = 31 * result + tls.hashCode()
        return result
    }

    override fun toString(): String =
        "NowhereConfiguration($proxyHost:$proxyPort up=$uplink down=$downlink " +
            "multiplex=$multiplex alpn=$alpn)"
}
