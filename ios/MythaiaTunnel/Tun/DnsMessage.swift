import Foundation

/// The DNS wire format (RFC 1035), as much of it as a client needs: a query
/// going out, and the addresses in the answer coming back, read through the
/// name compression every real resolver uses.
///
/// `PacketUtil.parseDnsQueryExt` is the other half: the query an app sent,
/// parsed and answered in place. This one is for questions the tunnel asks.
enum DnsMessage {

    static let typeA = 1
    static let typeAAAA = 28

    private static let typeOPT = 41
    private static let classIN = 1
    private static let headerLength = 12

    /// How a response failed to be the answer that was asked for.
    enum ParseFailure: Error {
        case malformed
        /// Somebody else's answer: a late reply to an earlier query on the
        /// same socket. Keep waiting.
        case identifierMismatch
        case serverFailure(Int)
    }

    /// One question, recursion desired. With `udpPayloadSize` an EDNS OPT
    /// record is added so the server may answer past 512 bytes.
    ///
    /// Nil when the name cannot go on the wire: empty, a label over 63
    /// bytes, or not ASCII (IDNs arrive punycoded or not at all).
    static func makeQuery(domain: String, type: Int, id: Int, udpPayloadSize: Int? = nil) -> [UInt8]? {
        var out: [UInt8] = []
        out.reserveCapacity(32 + domain.utf8.count)

        out.append(UInt8((id >> 8) & 0xFF))
        out.append(UInt8(id & 0xFF))
        out.append(0x01)                                  // RD
        out.append(0x00)
        out.append(0x00)
        out.append(0x01)                                  // QDCOUNT 1
        out.append(0x00)
        out.append(0x00)                                  // ANCOUNT
        out.append(0x00)
        out.append(0x00)                                  // NSCOUNT
        out.append(0x00)
        out.append(udpPayloadSize == nil ? 0x00 : 0x01)   // ARCOUNT

        var labelCount = 0
        for label in domain.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = Array(label.utf8)
            if bytes.isEmpty || bytes.count > 63 { return nil }
            if bytes.contains(where: { $0 >= 0x80 }) { return nil }
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
            labelCount += 1
        }
        if labelCount == 0 { return nil }
        out.append(0)                                     // root label

        out.append(UInt8((type >> 8) & 0xFF))
        out.append(UInt8(type & 0xFF))
        out.append(UInt8((classIN >> 8) & 0xFF))
        out.append(UInt8(classIN & 0xFF))

        if let size = udpPayloadSize {
            out.append(0)                                 // root owner name
            out.append(UInt8((typeOPT >> 8) & 0xFF))
            out.append(UInt8(typeOPT & 0xFF))
            out.append(UInt8((size >> 8) & 0xFF))
            out.append(UInt8(size & 0xFF))
            out.append(contentsOf: [0, 0, 0, 0])          // extended RCODE and flags
            out.append(contentsOf: [0, 0])                // RDLENGTH 0
        }

        if out.count > 512 { return nil }
        return out
    }

    /// Every A and AAAA record in the answer section, IPv4 first, as text.
    static func parseAddresses(_ response: [UInt8], expectedId: Int) throws -> [String] {
        var ipv4: [String] = []
        var ipv6: [String] = []
        try walkAnswers(response, expectedId: expectedId) { type, rdata in
            if type == typeA && rdata.count == 4 {
                if let text = TunAddress.text(rdata) { ipv4.append(text) }
            } else if type == typeAAAA && rdata.count == 16 {
                if let text = TunAddress.text(rdata) { ipv6.append(text) }
            }
        }
        return ipv4 + ipv6
    }

    // MARK: - Internal

    private static func walkAnswers(
        _ response: [UInt8],
        expectedId: Int,
        _ onRecord: (Int, [UInt8]) -> Void
    ) throws {
        if response.count < headerLength { throw ParseFailure.malformed }

        let id = (Int(response[0]) << 8) | Int(response[1])
        if id != expectedId { throw ParseFailure.identifierMismatch }
        if (response[2] & 0x80) == 0 { throw ParseFailure.malformed }   // QR must be set

        let rcode = Int(response[3] & 0x0F)
        if rcode != 0 { throw ParseFailure.serverFailure(rcode) }

        let questionCount = (Int(response[4]) << 8) | Int(response[5])
        let answerCount = (Int(response[6]) << 8) | Int(response[7])

        var offset = headerLength
        var remainingQuestions = questionCount
        while remainingQuestions > 0 {
            guard let next = skipName(response, from: offset) else { throw ParseFailure.malformed }
            offset = next + 4                                            // QTYPE + QCLASS
            if offset > response.count { throw ParseFailure.malformed }
            remainingQuestions -= 1
        }

        var remainingAnswers = answerCount
        while remainingAnswers > 0 {
            guard let next = skipName(response, from: offset) else { throw ParseFailure.malformed }
            offset = next
            if offset + 10 > response.count { throw ParseFailure.malformed }

            let type = (Int(response[offset]) << 8) | Int(response[offset + 1])
            let recordClass = (Int(response[offset + 2]) << 8) | Int(response[offset + 3])
            let rdLength = (Int(response[offset + 8]) << 8) | Int(response[offset + 9])
            offset += 10
            if offset + rdLength > response.count { throw ParseFailure.malformed }

            if recordClass == classIN {
                onRecord(type, [UInt8](response[offset..<(offset + rdLength)]))
            }
            offset += rdLength
            remainingAnswers -= 1
        }
    }

    /// The offset just past a name, spelled out, compressed, or both. A
    /// pointer ends the name and may only point backwards, which keeps a
    /// hostile message from sending the parser in circles.
    private static func skipName(_ bytes: [UInt8], from start: Int) -> Int? {
        var cursor = start
        while cursor < bytes.count {
            let length = Int(bytes[cursor])
            if (length & 0xC0) == 0xC0 {
                if cursor + 2 > bytes.count { return nil }
                let target = ((length & 0x3F) << 8) | Int(bytes[cursor + 1])
                if target >= cursor || target < headerLength { return nil }
                return cursor + 2
            }
            if (length & 0xC0) != 0 { return nil }                      // reserved label type
            cursor += 1
            if length == 0 { return cursor }                            // root label ends the name
            cursor += length
            if cursor > bytes.count { return nil }
        }
        return nil
    }
}
