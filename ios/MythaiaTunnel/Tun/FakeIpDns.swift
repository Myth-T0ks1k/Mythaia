import Foundation

/// The DNS interception applied to every UDP/53 query that reaches the
/// stack: A and AAAA questions are answered with fake IPs from the pool, so
/// the connection that follows carries the domain name to the router, and
/// the record types that would let a client sidestep that are refused.
///
/// The same decisions as the Android and desktop stacks, so every platform
/// answers alike.
enum FakeIpDns {

    /// What to do with one query.
    enum Answer {
        /// Write `response` back to the client; no flow is opened. `reason`
        /// names a refused query type, for the log.
        case reply(response: [UInt8], reason: String?)

        /// Not ours: open a normal UDP flow and let a real resolver answer.
        case passThrough
    }

    /// Decides `payload`, a DNS query as it arrived on port 53.
    ///
    /// - Parameters:
    ///   - ipv6Dns: whether AAAA questions get fake IPv6 answers; otherwise
    ///     NODATA, so clients stay on the fake IPv4 range.
    ///   - encryptedDnsEnabled: when false, DDR discovery (RFC 9462) is
    ///     refused, so the system cannot upgrade itself to DoH or DoT and
    ///     leave port 53, where the fake answers come from.
    static func answer(_ payload: [UInt8], pool: FakeIpPool, ipv6Dns: Bool, encryptedDnsEnabled: Bool) -> Answer {
        guard let parsed = PacketUtil.parseDnsQueryExt(payload) else { return .passThrough }
        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype

        if !encryptedDnsEnabled && domain == "_dns.resolver.arpa" {
            return nodata(payload, qtype: qtype, reason: "DDR")
        }

        // SVCB/HTTPS (type 65): answered for real, these follow CNAME chains
        // and the client then connects under the CNAME target's name, which
        // the routing rules do not know. NODATA sends it back to A/AAAA,
        // which are answered here with the right route.
        if qtype == 65 {
            return nodata(payload, qtype: qtype, reason: "SVCB")
        }

        // Only A (1) and AAAA (28) are answered; MX, SRV, TXT and the rest
        // pass through.
        if qtype != 1 && qtype != 28 { return .passThrough }

        // Every A/AAAA question gets a fake IP, rejected domains included:
        // the route is decided when the connection arrives, so a NODATA the
        // system might cache cannot outlive a change of rules.
        let offset = pool.allocate(domain)

        var address: [UInt8]? = nil
        if qtype == 1 {
            address = FakeIpPool.ipv4Bytes(offset)
        } else if ipv6Dns {
            address = FakeIpPool.ipv6Bytes(offset)
        }

        guard let response = PacketUtil.generateDnsResponse(payload, address: address, qtype: qtype) else {
            return .passThrough
        }
        return .reply(response: response, reason: nil)
    }

    private static func nodata(_ payload: [UInt8], qtype: Int, reason: String) -> Answer {
        guard let response = PacketUtil.generateDnsResponse(payload, address: nil, qtype: qtype) else {
            return .passThrough
        }
        return .reply(response: response, reason: reason)
    }
}
