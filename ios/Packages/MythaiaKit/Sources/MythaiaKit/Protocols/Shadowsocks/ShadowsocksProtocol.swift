import Foundation

/// Shadowsocks wire format.
///
/// Address format: `ATYP(1) + Address(var) + Port(2, big-endian)`
/// - ATYP 0x01: IPv4 (4 bytes)
/// - ATYP 0x03: Domain (1-byte length + string)
/// - ATYP 0x04: IPv6 (16 bytes)
enum ShadowsocksProtocol {
    private static let atypIPv4: UInt8 = 0x01
    private static let atypDomain: UInt8 = 0x03
    private static let atypIPv6: UInt8 = 0x04

    struct UdpPacket: Equatable {
        let host: String
        let port: UInt16
        let payload: Data
    }

    static func buildAddressHeader(host: String, port: UInt16) -> Data {
        return Data(ProtocolAddress.socksAddressPort(host: host, port: port))
    }

    /// Address header followed by the raw payload.
    static func encodeUDPPacket(host: String, port: UInt16, payload: Data) -> Data {
        var out = buildAddressHeader(host: host, port: port)
        out.append(payload)
        return out
    }

    static func decodeUDPPacket(_ data: Data) -> UdpPacket? {
        let bytes = [UInt8](data)
        if bytes.isEmpty { return nil }
        var offset = 0
        let atyp = bytes[offset]
        offset += 1

        let host: String
        switch atyp {
        case atypIPv4:
            if bytes.count - offset < 4 + 2 { return nil }
            host = ProtocolAddress.ipv4Text(Array(bytes[offset..<(offset + 4)]))
            offset += 4
        case atypDomain:
            if bytes.count - offset < 1 { return nil }
            let length = Int(bytes[offset])
            offset += 1
            if bytes.count - offset < length + 2 { return nil }
            host = String(decoding: bytes[offset..<(offset + length)], as: UTF8.self)
            offset += length
        case atypIPv6:
            if bytes.count - offset < 16 + 2 { return nil }
            host = ProtocolAddress.ipv6Text(Array(bytes[offset..<(offset + 16)]))
            offset += 16
        default:
            return nil
        }

        if bytes.count - offset < 2 { return nil }
        let port = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
        offset += 2
        return UdpPacket(host: host, port: port, payload: Data(bytes[offset...]))
    }
}
