import Foundation

enum VlessCommand: UInt8, CaseIterable {
    case tcp = 0x01
    case udp = 0x02
    case mux = 0x03

    static func fromByte(_ b: UInt8) -> VlessCommand? {
        return VlessCommand(rawValue: b)
    }
}

enum VlessAddressType: UInt8, CaseIterable {
    case ipv4 = 0x01
    case domain = 0x02
    case ipv6 = 0x03

    static func fromByte(_ b: UInt8) -> VlessAddressType? {
        return VlessAddressType(rawValue: b)
    }
}

/// The VLESS request and response headers.
///
/// Every field is fixed width and the header as a whole has no length prefix,
/// so the server reads it positionally: a byte out of place shifts everything
/// after it and the connection fails in a way that looks like a network
/// problem.
enum VlessProtocol {
    static let version: UInt8 = 0x00

    /// Protobuf-encoded addons message: `{ string Flow = 1; bytes Seed = 2; }`.
    private static func encodeAddons(_ flow: String?) -> [UInt8] {
        guard let flow = flow, !flow.isEmpty else { return [] }
        let flowBytes = Array(flow.utf8)
        // Field 1, wire type 2 (length-delimited).
        return [0x0A, UInt8(truncatingIfNeeded: flowBytes.count)] + flowBytes
    }

    /// Encodes a VLESS request header:
    /// - 1 byte version (0x00)
    /// - 16 bytes UUID
    /// - 1 byte addons length (0 for no addons), then the addons
    /// - 1 byte command
    /// - 2 bytes port (big-endian)
    /// - 1 byte address type
    /// - variable address data
    ///
    /// The MUX command omits the address/port section: a mux session carries
    /// many destinations.
    static func encodeRequestHeader(
        uuid: UUID,
        command: VlessCommand,
        destinationAddress: String,
        destinationPort: UInt16,
        flow: String? = nil
    ) -> Data {
        var result = [UInt8]()
        result.append(version)
        result.append(contentsOf: uuidToBytes(uuid))

        let addons = encodeAddons(flow)
        result.append(UInt8(truncatingIfNeeded: addons.count))
        result.append(contentsOf: addons)

        result.append(command.rawValue)

        if command != .mux {
            result.append(contentsOf: ProtocolAddress.portBytes(destinationPort))
            if let v4 = ProtocolAddress.ipv4(destinationAddress) {
                result.append(VlessAddressType.ipv4.rawValue)
                result.append(contentsOf: v4)
            } else if let v6 = ProtocolAddress.ipv6(destinationAddress) {
                result.append(VlessAddressType.ipv6.rawValue)
                result.append(contentsOf: v6)
            } else {
                let name = Array(destinationAddress.utf8.prefix(255))
                result.append(VlessAddressType.domain.rawValue)
                result.append(UInt8(name.count))
                result.append(contentsOf: name)
            }
        }
        return Data(result)
    }

    /// Bytes consumed by the response header at `offset`, or 0 when it is
    /// absent or not complete yet. Zero means "wait for more": returning a
    /// length early would make the caller skip bytes that had not arrived.
    static func decodeResponseHeader(_ data: Data, offset: Int = 0) -> Int {
        let bytes = [UInt8](data)
        let available = bytes.count - offset
        if available < 2 { return 0 }
        if bytes[offset] != version { return 0 }
        let totalLength = 2 + Int(bytes[offset + 1])
        if available < totalLength { return 0 }
        return totalLength
    }

    /// A UUID as its sixteen big-endian bytes.
    static func uuidToBytes(_ uuid: UUID) -> Data {
        var raw = uuid.uuid
        return withUnsafeBytes(of: &raw) { Data($0) }
    }
}
