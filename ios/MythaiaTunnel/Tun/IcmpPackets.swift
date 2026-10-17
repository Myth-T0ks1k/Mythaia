import Foundation

/// ICMP Destination Unreachable (Port Unreachable) packets, ready to be
/// written to the interface.
///
/// Sent when UDP arrives at a stale fake IP no longer in the pool (a
/// previous session's answer), at a rejected destination, or at UDP/443
/// while QUIC is blocked. The client gives up on the destination and
/// re-resolves, or for QUIC falls back to HTTP/2, instead of retrying into a
/// black hole.
///
/// `srcIp`/`srcPort` are the original datagram's sender, `dstIp`/`dstPort`
/// its destination; the reply goes from the destination back to the sender
/// and quotes the reconstructed IP and UDP headers, as RFC 792 and RFC 4443
/// require.
enum IcmpPackets {

    /// IPv4 ICMP type 3 code 3, 56 bytes: outer IPv4 (20) + ICMP (8) + inner
    /// IPv4 (20) + UDP (8). Nil unless both addresses are 4 bytes.
    static func portUnreachableV4(srcIp: [UInt8], srcPort: UInt16, dstIp: [UInt8], dstPort: UInt16, udpPayloadLength: Int) -> [UInt8]? {
        guard srcIp.count == 4 && dstIp.count == 4 else { return nil }
        let packetLength = 56
        var p = [UInt8](repeating: 0, count: packetLength)

        // Outer IPv4 header, from the destination back to the sender.
        p[0] = 0x45                                  // version 4, IHL 5
        p[2] = UInt8(packetLength >> 8)
        p[3] = UInt8(packetLength & 0xFF)
        p[8] = 64                                    // TTL
        p[9] = 1                                     // ICMP
        copy(dstIp, into: &p, at: 12)
        copy(srcIp, into: &p, at: 16)
        let ipChecksum = checksum(p, from: 0, to: 20)
        p[10] = UInt8(ipChecksum >> 8)
        p[11] = UInt8(ipChecksum & 0xFF)

        // ICMP: destination unreachable, port unreachable.
        p[20] = 3
        p[21] = 3

        // The original IPv4 header, reconstructed.
        let udpLength = 8 + udpPayloadLength
        let innerLength = 20 + udpLength
        p[28] = 0x45
        p[30] = UInt8((innerLength >> 8) & 0xFF)
        p[31] = UInt8(innerLength & 0xFF)
        p[36] = 64                                   // TTL
        p[37] = 17                                   // UDP
        copy(srcIp, into: &p, at: 40)
        copy(dstIp, into: &p, at: 44)

        // The first 8 bytes of the original UDP datagram.
        p[48] = UInt8(srcPort >> 8)
        p[49] = UInt8(srcPort & 0xFF)
        p[50] = UInt8(dstPort >> 8)
        p[51] = UInt8(dstPort & 0xFF)
        p[52] = UInt8((udpLength >> 8) & 0xFF)
        p[53] = UInt8(udpLength & 0xFF)

        let icmpChecksum = checksum(p, from: 20, to: packetLength)
        p[22] = UInt8(icmpChecksum >> 8)
        p[23] = UInt8(icmpChecksum & 0xFF)
        return p
    }

    /// ICMPv6 type 1 code 4, 96 bytes: outer IPv6 (40) + ICMPv6 (8) + inner
    /// IPv6 (40) + UDP (8). Nil unless both addresses are 16 bytes.
    static func portUnreachableV6(srcIp: [UInt8], srcPort: UInt16, dstIp: [UInt8], dstPort: UInt16, udpPayloadLength: Int) -> [UInt8]? {
        guard srcIp.count == 16 && dstIp.count == 16 else { return nil }
        let icmpLength = 56                          // 8 + 40 + 8
        let packetLength = 40 + icmpLength
        var p = [UInt8](repeating: 0, count: packetLength)

        // Outer IPv6 header, from the destination back to the sender.
        p[0] = 0x60                                  // version 6
        p[4] = UInt8(icmpLength >> 8)
        p[5] = UInt8(icmpLength & 0xFF)
        p[6] = 58                                    // ICMPv6
        p[7] = 64                                    // hop limit
        copy(dstIp, into: &p, at: 8)
        copy(srcIp, into: &p, at: 24)

        // ICMPv6: destination unreachable, port unreachable.
        p[40] = 1
        p[41] = 4

        // The original IPv6 header, reconstructed.
        let udpLength = 8 + udpPayloadLength
        p[48] = 0x60
        p[52] = UInt8((udpLength >> 8) & 0xFF)
        p[53] = UInt8(udpLength & 0xFF)
        p[54] = 17                                   // UDP
        p[55] = 64                                   // hop limit
        copy(srcIp, into: &p, at: 56)
        copy(dstIp, into: &p, at: 72)

        // The first 8 bytes of the original UDP datagram.
        p[88] = UInt8(srcPort >> 8)
        p[89] = UInt8(srcPort & 0xFF)
        p[90] = UInt8(dstPort >> 8)
        p[91] = UInt8(dstPort & 0xFF)
        p[92] = UInt8((udpLength >> 8) & 0xFF)
        p[93] = UInt8(udpLength & 0xFF)

        // The ICMPv6 checksum covers a pseudo-header (RFC 4443 section 2.3):
        // both addresses, the upper-layer length and next header 58.
        var sum: UInt32 = 0
        var index = 8
        while index < 40 {
            sum &+= word(p, index)
            index += 2
        }
        sum &+= UInt32(icmpLength)
        sum &+= 58
        index = 40
        while index < packetLength {
            sum &+= word(p, index)
            index += 2
        }
        let icmpChecksum = fold(sum)
        p[42] = UInt8(icmpChecksum >> 8)
        p[43] = UInt8(icmpChecksum & 0xFF)
        return p
    }

    /// The one's-complement checksum of `buffer[from..<to]`; the length is even.
    static func checksum(_ buffer: [UInt8], from: Int, to: Int) -> UInt16 {
        var sum: UInt32 = 0
        var index = from
        while index < to {
            sum &+= word(buffer, index)
            index += 2
        }
        return fold(sum)
    }

    private static func word(_ p: [UInt8], _ index: Int) -> UInt32 {
        (UInt32(p[index]) << 8) | UInt32(p[index + 1])
    }

    private static func fold(_ total: UInt32) -> UInt16 {
        var sum = total
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    private static func copy(_ source: [UInt8], into target: inout [UInt8], at offset: Int) {
        for index in 0..<source.count {
            target[offset + index] = source[index]
        }
    }
}
