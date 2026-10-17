import Foundation

/// Trojan wire format.
///
/// TCP request header: `hex(sha224(password))` (56 ASCII bytes) + CRLF
///                   + cmd(1) + ATYP(1) + address(var) + port(2 BE) + CRLF
/// UDP packet format: ATYP(1) + address(var) + port(2 BE) + length(2 BE) + CRLF + payload
/// Address encoding matches SOCKS5 / Shadowsocks: ATYP 0x01 IPv4, 0x03 domain, 0x04 IPv6.
///
/// The server compares the password hash byte for byte and falls back to its
/// decoy site on any mismatch, so a wrong byte anywhere here looks like a
/// working connection to an unrelated website rather than an error.
enum TrojanProtocol {
    static let commandTCP: UInt8 = 0x01
    static let commandUDP: UInt8 = 0x03

    /// Max per-packet payload size accepted by upstream Trojan servers.
    static let maxUdpPayloadLength = 8192

    private static let atypIPv4: UInt8 = 0x01
    private static let atypDomain: UInt8 = 0x03
    private static let atypIPv6: UInt8 = 0x04

    private static let hexChars = Array("0123456789abcdef".utf8)

    struct DecodedPacket: Equatable {
        let payload: Data
        let consumed: Int
    }

    /// SHA-224 of the password as 56 lowercase hex ASCII bytes — the exact
    /// byte sequence Trojan servers compare against. Lowercase specifically:
    /// an uppercase rendering is a different string to the server.
    static func passwordKey(_ password: String) -> Data {
        let digest = [UInt8](DigestHelper.sha224(Data(password.utf8)))
        var out = [UInt8]()
        out.reserveCapacity(56)
        for b in digest {
            out.append(hexChars[Int(b >> 4)])
            out.append(hexChars[Int(b & 0x0F)])
        }
        return Data(out)
    }

    static func buildRequestHeader(passwordKey: Data, command: UInt8, host: String, port: UInt16) -> Data {
        var out = [UInt8](passwordKey)
        out.append(0x0D)
        out.append(0x0A)
        out.append(command)
        out.append(contentsOf: encodeAddressPort(host: host, port: port))
        out.append(0x0D)
        out.append(0x0A)
        return Data(out)
    }

    /// A name longer than a length byte can hold is trimmed, not overflowed.
    static func encodeAddressPort(host: String, port: UInt16) -> Data {
        return Data(ProtocolAddress.socksAddressPort(host: host, port: port))
    }

    /// Frames one datagram. A payload over `maxUdpPayloadLength` is refused
    /// rather than cut: a truncated datagram is corrupt at the receiver (a DNS
    /// reply with half its records, a QUIC packet that fails its AEAD), and
    /// failing loudly lets the caller drop the whole datagram like a lost packet.
    static func encodeUDPPacket(host: String, port: UInt16, payload: Data) throws -> Data {
        if payload.count > maxUdpPayloadLength {
            throw MythaiaError.protocolError("Trojan: UDP payload of \(payload.count) bytes exceeds \(maxUdpPayloadLength)")
        }
        var out = [UInt8](encodeAddressPort(host: host, port: port))
        let length = payload.count
        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(0x0D)
        out.append(0x0A)
        out.append(contentsOf: payload)
        return Data(out)
    }

    /// One UDP packet from the front of `buffer`, or nil when it is short.
    /// Throws on malformed framing.
    static func tryDecodeUDPPacket(_ buffer: Data) throws -> DecodedPacket? {
        return try tryDecodeUDPPacket([UInt8](buffer), from: 0)
    }

    static func tryDecodeUDPPacket(_ buffer: [UInt8], from start: Int) throws -> DecodedPacket? {
        if buffer.count <= start { return nil }
        var offset = start
        let atyp = buffer[offset]
        offset += 1

        let addressLength: Int
        switch atyp {
        case atypIPv4:
            addressLength = 4
        case atypIPv6:
            addressLength = 16
        case atypDomain:
            if offset >= buffer.count { return nil }
            addressLength = Int(buffer[offset])
            offset += 1
        default:
            throw MythaiaError.protocolError("Trojan: unknown ATYP \(atyp)")
        }

        // Address + port (2) + length (2) + CRLF (2) before the payload.
        if buffer.count - offset < addressLength + 6 { return nil }
        offset += addressLength + 2

        let length = (Int(buffer[offset]) << 8) | Int(buffer[offset + 1])
        offset += 4

        if length > maxUdpPayloadLength {
            throw MythaiaError.protocolError("Trojan: oversize UDP payload (\(length))")
        }
        if buffer.count - offset < length { return nil }

        let payload = Data(buffer[offset..<(offset + length)])
        return DecodedPacket(payload: payload, consumed: offset + length - start)
    }
}
