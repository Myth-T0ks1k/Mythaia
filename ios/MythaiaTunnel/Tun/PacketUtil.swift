import Foundation

/// The DNS questions an app sends to the tunnel, parsed and answered in
/// place. `DnsMessage` is the other half: the questions the tunnel itself
/// asks a real resolver.
enum PacketUtil {

    struct DnsQuery {
        let domain: String
        let qtype: Int
    }

    /// The domain (as spelled on the wire) and QTYPE of the first question
    /// in a DNS query, or nil when it is malformed. Compression pointers in
    /// the QNAME are refused: queries do not use them. Callers matching the
    /// name against a case-insensitive table lowercase it themselves.
    static func parseDnsQueryExt(_ data: [UInt8]) -> DnsQuery? {
        if data.count < 12 { return nil }

        let qdcount = (Int(data[4]) << 8) | Int(data[5])
        if qdcount == 0 { return nil }

        var offset = 12
        var name: [UInt8] = []
        while offset < data.count {
            let labelLength = Int(data[offset])
            offset += 1
            if labelLength == 0 { break }
            if (labelLength & 0xC0) != 0 { return nil }
            if offset + labelLength > data.count { return nil }
            if !name.isEmpty { name.append(0x2E) }
            name.append(contentsOf: data[offset..<(offset + labelLength)])
            offset += labelLength
        }

        if name.isEmpty { return nil }
        if offset + 2 > data.count { return nil }
        let qtype = (Int(data[offset]) << 8) | Int(data[offset + 1])

        // Byte for byte, as the Kotlin core reads it (Latin-1); real names
        // are ASCII.
        guard let domain = String(bytes: name, encoding: .isoLatin1) else { return nil }
        return DnsQuery(domain: domain, qtype: qtype)
    }

    /// A response to `query`: one answer holding `address` when it is set
    /// and `qtype` is A (4 bytes) or AAAA (16 bytes), otherwise NODATA (no
    /// answers, no error). The TTL is one second, so a stale answer does not
    /// outlive the pool entry behind it.
    static func generateDnsResponse(_ query: [UInt8], address: [UInt8]?, qtype: Int) -> [UInt8]? {
        if query.count < 12 { return nil }

        // QNAME, then QTYPE (2) and QCLASS (2).
        var offset = 12
        while offset < query.count {
            let labelLength = Int(query[offset])
            offset += 1
            if labelLength == 0 { break }
            if (labelLength & 0xC0) != 0 { break }
            offset += labelLength
        }
        offset += 4
        if offset > query.count { return nil }
        let questionEnd = offset

        var rdLength = 0
        var answerType = 0
        if address != nil {
            if qtype == 1 {
                rdLength = 4
                answerType = 1
            } else if qtype == 28 {
                rdLength = 16
                answerType = 28
            }
        }

        if rdLength > 0, let address = address, address.count >= rdLength {
            // name (2) + type (2) + class (2) + ttl (4) + rdlength (2) + rdata
            let answerLength = 12 + rdLength
            var out = [UInt8](repeating: 0, count: questionEnd + answerLength)
            for index in 0..<questionEnd {
                out[index] = query[index]
            }
            writeResponseHeader(&out, answerCount: 1)

            let answer = questionEnd
            out[answer] = 0xC0
            out[answer + 1] = 0x0C                       // pointer to the QNAME
            out[answer + 2] = UInt8((answerType >> 8) & 0xFF)
            out[answer + 3] = UInt8(answerType & 0xFF)
            out[answer + 4] = 0x00
            out[answer + 5] = 0x01                       // CLASS IN
            out[answer + 6] = 0x00
            out[answer + 7] = 0x00
            out[answer + 8] = 0x00
            out[answer + 9] = 0x01                       // TTL 1 s
            out[answer + 10] = UInt8((rdLength >> 8) & 0xFF)
            out[answer + 11] = UInt8(rdLength & 0xFF)
            for index in 0..<rdLength {
                out[answer + 12 + index] = address[index]
            }
            return out
        }

        var out = [UInt8](query[0..<questionEnd])
        writeResponseHeader(&out, answerCount: 0)
        return out
    }

    private static func writeResponseHeader(_ buffer: inout [UInt8], answerCount: Int) {
        buffer[2] = 0x85                                 // QR, AA, RD
        buffer[3] = 0x80                                 // RA
        buffer[6] = UInt8((answerCount >> 8) & 0xFF)
        buffer[7] = UInt8(answerCount & 0xFF)
        buffer[8] = 0
        buffer[9] = 0                                    // NSCOUNT
        buffer[10] = 0
        buffer[11] = 0                                   // ARCOUNT
    }
}
