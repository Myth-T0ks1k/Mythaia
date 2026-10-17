import Foundation

/// The TUIC v5 wire format.
///
/// Every message is a command: a version byte, a type byte, then whatever that
/// type carries. Big-endian throughout. The whole protocol is five commands,
/// and the notable thing about it is what is missing — there are no
/// responses. A client sends `Connect` and starts relaying immediately without
/// waiting, which is where the round trip it saves comes from, and a server
/// that objects says so by closing the stream rather than by answering.
///
/// Written from the TUIC specification (SPEC.md, protocol version 0x05).
enum TuicProtocol {
    static let version: UInt8 = 0x05

    // Command types.
    static let cmdAuthenticate: UInt8 = 0x00
    static let cmdConnect: UInt8 = 0x01
    static let cmdPacket: UInt8 = 0x02
    static let cmdDissociate: UInt8 = 0x03
    static let cmdHeartbeat: UInt8 = 0x04

    // Address types.
    static let addrNone: UInt8 = 0xFF
    static let addrDomain: UInt8 = 0x00
    static let addrIpv4: UInt8 = 0x01
    static let addrIpv6: UInt8 = 0x02

    /// The exporter output length, and so the token length.
    static let tokenLength = 32
    /// `VER` and `TYPE`.
    static let headerSize = 2
    /// assoc(2) + pkt(2) + fragTotal(1) + fragId(1) + size(2).
    static let packetHeaderSize = 8
    /// A domain name cannot be longer than one length byte can describe.
    static let maxDomainLength = 255

    /// `Authenticate`: the UUID's sixteen bytes, then the token the TLS
    /// exporter made from them and the password. That binding is what makes a
    /// token worthless off the connection it was made on.
    static func authenticate(uuid: UUID, token: [UInt8]) throws -> [UInt8] {
        guard token.count == tokenLength else {
            throw MythaiaError.invalidConfiguration("TUIC token must be \(tokenLength) bytes")
        }
        var out: [UInt8] = [version, cmdAuthenticate]
        out.append(contentsOf: uuidBytes(uuid))
        out.append(contentsOf: token)
        return out
    }

    /// Opens a TCP relay. The stream carries payload straight after this.
    static func connect(host: String, port: UInt16) -> [UInt8] {
        return [version, cmdConnect] + encodeAddress(host: host, port: port)
    }

    /// Ends a UDP session, releasing the socket the server bound for it.
    static func dissociate(associationId: Int) -> [UInt8] {
        return [version, cmdDissociate, UInt8(truncatingIfNeeded: associationId >> 8), UInt8(truncatingIfNeeded: associationId)]
    }

    /// Keeps the connection alive while a relay is in progress.
    static func heartbeat() -> [UInt8] {
        return [version, cmdHeartbeat]
    }

    /// One UDP datagram, or one fragment of one.
    struct Packet: Equatable {
        let associationId: Int
        let packetId: Int
        let fragmentTotal: Int
        let fragmentId: Int
        let host: String?
        let port: UInt16
        let payload: [UInt8]
    }

    /// Encodes a packet command. Only the first fragment carries an address;
    /// the rest use the `None` type, because repeating it would waste room in
    /// every fragment of a datagram that was split precisely because room was
    /// short.
    static func packet(_ packet: Packet) -> [UInt8] {
        let address: [UInt8]
        if packet.fragmentId == 0, let host = packet.host {
            address = encodeAddress(host: host, port: packet.port)
        } else {
            address = [addrNone]
        }
        var out: [UInt8] = [
            version, cmdPacket,
            UInt8(truncatingIfNeeded: packet.associationId >> 8), UInt8(truncatingIfNeeded: packet.associationId),
            UInt8(truncatingIfNeeded: packet.packetId >> 8), UInt8(truncatingIfNeeded: packet.packetId),
            UInt8(truncatingIfNeeded: packet.fragmentTotal),
            UInt8(truncatingIfNeeded: packet.fragmentId),
            UInt8(truncatingIfNeeded: packet.payload.count >> 8), UInt8(truncatingIfNeeded: packet.payload.count),
        ]
        out.append(contentsOf: address)
        out.append(contentsOf: packet.payload)
        return out
    }

    /// Decodes a packet command, or nil when the bytes do not hold a whole one:
    /// these arrive in unreliable datagrams, so a short or malformed one is
    /// something to drop.
    static func parsePacket(_ bytes: [UInt8]) -> Packet? {
        if bytes.count < headerSize + packetHeaderSize { return nil }
        if bytes[0] != version || bytes[1] != cmdPacket { return nil }
        var at = headerSize
        let association = readUShort(bytes, at); at += 2
        let packetId = readUShort(bytes, at); at += 2
        let fragmentTotal = Int(bytes[at]); at += 1
        let fragmentId = Int(bytes[at]); at += 1
        let size = readUShort(bytes, at); at += 2
        guard let address = parseAddress(bytes, offset: at) else { return nil }
        at += address.size
        if at + size > bytes.count { return nil }
        return Packet(associationId: association, packetId: packetId, fragmentTotal: fragmentTotal,
                      fragmentId: fragmentId, host: address.host, port: address.port,
                      payload: Array(bytes[at..<(at + size)]))
    }

    // MARK: - Address

    /// A decoded address and how many bytes it took.
    struct Address: Equatable {
        let host: String?
        let port: UInt16
        let size: Int
    }

    /// An IP literal by type, anything else as a name — never resolved here:
    /// a lookup would run on whichever thread happened to be encoding.
    static func encodeAddress(host: String, port: UInt16) -> [UInt8] {
        var out: [UInt8]
        if let v4 = ProtocolAddress.ipv4(host) {
            out = [addrIpv4] + v4
        } else if let v6 = ProtocolAddress.ipv6(host) {
            out = [addrIpv6] + v6
        } else {
            var name = Array(host.utf8)
            if name.count > maxDomainLength { name = Array(name[0..<maxDomainLength]) }
            out = [addrDomain, UInt8(name.count)] + name
        }
        out.append(UInt8(truncatingIfNeeded: port >> 8))
        out.append(UInt8(truncatingIfNeeded: port))
        return out
    }

    /// Reads an address at `offset`, or nil when it runs past the buffer or
    /// names a type the specification does not define.
    static func parseAddress(_ bytes: [UInt8], offset: Int) -> Address? {
        if offset < 0 || offset >= bytes.count { return nil }
        switch bytes[offset] {
        case addrNone:
            return Address(host: nil, port: 0, size: 1)
        case addrIpv4:
            if offset + 1 + 4 + 2 > bytes.count { return nil }
            let host = ProtocolAddress.ipv4Text(Array(bytes[(offset + 1)..<(offset + 5)]))
            return Address(host: host, port: UInt16(readUShort(bytes, offset + 5)), size: 1 + 4 + 2)
        case addrIpv6:
            if offset + 1 + 16 + 2 > bytes.count { return nil }
            let host = ProtocolAddress.ipv6Text(Array(bytes[(offset + 1)..<(offset + 17)]))
            return Address(host: host, port: UInt16(readUShort(bytes, offset + 17)), size: 1 + 16 + 2)
        case addrDomain:
            if offset + 2 > bytes.count { return nil }
            let length = Int(bytes[offset + 1])
            if offset + 2 + length + 2 > bytes.count { return nil }
            let host = String(decoding: bytes[(offset + 2)..<(offset + 2 + length)], as: UTF8.self)
            return Address(host: host, port: UInt16(readUShort(bytes, offset + 2 + length)), size: 1 + 1 + length + 2)
        default:
            return nil
        }
    }

    /// The UUID's sixteen raw bytes, in RFC 4122 order.
    static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        let u = uuid.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    private static func readUShort(_ bytes: [UInt8], _ at: Int) -> Int {
        return Int(bytes[at]) << 8 | Int(bytes[at + 1])
    }
}
