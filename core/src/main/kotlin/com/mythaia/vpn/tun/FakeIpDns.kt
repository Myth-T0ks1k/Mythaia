package com.mythaia.vpn.tun

import com.mythaia.vpn.FakeIpPool
import com.mythaia.vpn.util.PacketUtil

/**
 * The DNS interception a TUN stack applies to every UDP/53 query that
 * arrives: A and AAAA questions are answered with fake IPs from the pool so
 * the connection that follows carries the domain name to the router, and
 * the record types that would let a client sidestep that are refused.
 *
 * Shared by the Android `LwipStack` and the desktop TUN driver, so the two
 * platforms answer identically.
 */
object FakeIpDns {

    /** What to do with one query. */
    sealed class Answer {
        /** Write [response] back to the client as the reply; no flow is opened. */
        data class Reply(val response: ByteArray, val reason: String?) : Answer()

        /** Not ours: open a normal UDP flow and let the real resolver answer. */
        data object PassThrough : Answer()
    }

    /**
     * Decides [payload], a DNS query as it arrived on port 53.
     *
     * @param ipv6Dns whether AAAA questions get fake IPv6 answers; otherwise
     *   NODATA so clients stay on the fake IPv4 range, which is the only one
     *   the platform routes into the tunnel.
     * @param encryptedDnsEnabled when false, DDR discovery (RFC 9462) is
     *   refused so the system cannot auto-upgrade to DoH/DoT and escape
     *   port-53 interception.
     */
    fun answer(payload: ByteArray, pool: FakeIpPool, ipv6Dns: Boolean, encryptedDnsEnabled: Boolean): Answer {
        val parsed = PacketUtil.parseDnsQueryExt(payload) ?: return Answer.PassThrough
        val domain = parsed.domain.lowercase()
        val qtype = parsed.qtype

        // Block DDR (Discovery of Designated Resolvers, RFC 9462) when encrypted DNS is
        // disabled to prevent the system from auto-upgrading to DoH/DoT, which bypasses
        // port-53 interception needed for fake-IP domain routing.
        if (!encryptedDnsEnabled && domain == "_dns.resolver.arpa") {
            return nodata(payload, qtype, "DDR")
        }

        // Block SVCB/HTTPS (qtype=65, RFC 9460) queries with NODATA.
        // When proxied to real DNS, these queries follow CNAME chains
        // (e.g. example.com → example.com.cdn.net), causing the browser to
        // connect using the CNAME target domain instead of the original.
        // Since routing/bypass rules match on the original domain, the CNAME
        // target may not match, sending traffic through the wrong proxy path.
        // Returning NODATA forces the browser to fall back to A/AAAA records,
        // which are intercepted by our fake-IP system with correct routing.
        if (qtype == 65) {
            return nodata(payload, qtype, "SVCB")
        }

        // Only intercept A (1) and AAAA (28) queries; let MX/SRV/etc. pass through
        if (qtype != 1 && qtype != 28) return Answer.PassThrough

        // Intercept ALL A/AAAA queries with fake IPs — including rejected domains.
        // Routing decisions (direct/reject/proxy) are all made at connection time
        // by checking the router. This avoids NODATA responses that could be
        // negatively cached by the OS, making rule changes stick even after the
        // user removes a REJECT assignment.
        val offset = pool.allocate(domain)

        // A queries always get fake IPv4. AAAA queries get fake IPv6 only when
        // ipv6Dns is true; otherwise NODATA so apps fall back to IPv4 fake IPs.
        val fakeIpBytes: ByteArray? = when (qtype) {
            1 -> FakeIpPool.ipv4Bytes(offset)
            28 -> if (ipv6Dns) FakeIpPool.ipv6Bytes(offset) else null
            else -> null
        }

        val response = PacketUtil.generateDnsResponse(payload, fakeIpBytes, qtype) ?: return Answer.PassThrough
        return Answer.Reply(response, null)
    }

    private fun nodata(payload: ByteArray, qtype: Int, reason: String): Answer {
        val response = PacketUtil.generateDnsResponse(payload, null, qtype) ?: return Answer.PassThrough
        return Answer.Reply(response, reason)
    }
}
