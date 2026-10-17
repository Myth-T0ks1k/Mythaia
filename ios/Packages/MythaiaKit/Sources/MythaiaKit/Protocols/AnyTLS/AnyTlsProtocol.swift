import Foundation

/// The AnyTLS wire format.
///
/// AnyTLS is a session layer on top of an ordinary TLS connection: after the
/// handshake the client authenticates with a hash of the password, then both
/// sides speak framed, multiplexed streams. What makes it interesting is the
/// padding scheme — the server tells the client how to chop its first few
/// writes into TLS records, so the size pattern a censor sees is not fixed and
/// can be changed server-side without shipping a new client.
///
/// Everything here is a pure function of bytes, which is what lets it be
/// tested against the reference implementation's own default scheme rather
/// than only against itself.
enum AnyTlsProtocol {
    // Commands. 0-6 are protocol version 1; 7-10 arrived with version 2.
    static let cmdWaste: UInt8 = 0
    static let cmdSyn: UInt8 = 1
    static let cmdPsh: UInt8 = 2
    static let cmdFin: UInt8 = 3
    static let cmdSettings: UInt8 = 4
    static let cmdAlert: UInt8 = 5
    static let cmdUpdatePaddingScheme: UInt8 = 6
    static let cmdSynAck: UInt8 = 7
    static let cmdHeartRequest: UInt8 = 8
    static let cmdHeartResponse: UInt8 = 9
    static let cmdServerSettings: UInt8 = 10

    /// command(1) + streamId(4) + length(2).
    static let headerSize = 7

    /// The protocol version this client implements.
    static let version = "2"

    /// UDP is carried as a TCP stream to this name, per sing-box's udp-over-tcp v2.
    static let udpOverTcpHost = "sp.v2.udp-over-tcp.arpa"

    /// The check mark of a padding scheme (`c`); see AnyTlsPaddingScheme.check.
    static let checkMark = -1

    /// A parsed frame header.
    struct Header: Equatable {
        let command: UInt8
        let streamId: UInt32
        let length: Int
    }

    static func readHeader(_ bytes: [UInt8], offset: Int = 0) -> Header {
        var streamId: UInt32 = 0
        for i in 1...4 {
            streamId = (streamId << 8) | UInt32(bytes[offset + i])
        }
        let length = (Int(bytes[offset + 5]) << 8) | Int(bytes[offset + 6])
        return Header(command: bytes[offset], streamId: streamId, length: length)
    }

    /// One frame: header then payload. Big-endian throughout. The payload
    /// must fit the 16-bit length field.
    static func frame(_ command: UInt8, streamId: UInt32, data: [UInt8] = []) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(headerSize + data.count)
        out.append(command)
        out.append(UInt8(truncatingIfNeeded: streamId >> 24))
        out.append(UInt8(truncatingIfNeeded: streamId >> 16))
        out.append(UInt8(truncatingIfNeeded: streamId >> 8))
        out.append(UInt8(truncatingIfNeeded: streamId))
        out.append(UInt8(truncatingIfNeeded: data.count >> 8))
        out.append(UInt8(truncatingIfNeeded: data.count))
        out.append(contentsOf: data)
        return out
    }

    /// The first thing a client sends: sha256(password), then the length of
    /// the zero padding the scheme asks for, then that padding.
    ///
    /// The padding is part of packet 0, which is the only one that cannot be
    /// split across records — it shares a write with the authentication.
    static func authentication(password: String, paddingLength: Int) -> Data {
        let padding = max(0, min(paddingLength, 0xFFFF))
        var out = DigestHelper.sha256(Data(password.utf8))
        out.append(UInt8(truncatingIfNeeded: padding >> 8))
        out.append(UInt8(truncatingIfNeeded: padding))
        // The rest stays zero, which is what the reference client sends.
        out.append(Data(count: padding))
        return out
    }

    /// The `cmdSettings` body: newline-separated `key=value`, UTF-8.
    ///
    /// `padding-md5` is how the server decides whether to push a new scheme,
    /// so it has to be the digest of the exact bytes the client is using.
    static func settings(clientName: String, paddingMd5: String) -> [UInt8] {
        return Array("v=\(version)\nclient=\(clientName)\npadding-md5=\(paddingMd5)".utf8)
    }

    /// Parses the same shape coming back, e.g. `cmdServerSettings`.
    static func parseSettings(_ data: [UInt8]) -> [String: String] {
        var out = [String: String]()
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let at = line.firstIndex(of: "="), at != line.startIndex else { continue }
            let key = line[line.startIndex..<at].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: at)...].trimmingCharacters(in: .whitespaces)
            out[key] = value
        }
        return out
    }

    /// A destination in SOCKS5 address form, which is what a stream carries
    /// first (RFC 1928 §5).
    static func encodeAddress(host: String, port: UInt16) -> [UInt8] {
        return ProtocolAddress.socksAddressPort(host: host, port: port)
    }

    /// Splits one payload into the TLS writes a padding scheme asks for.
    ///
    /// Each returned element is one call into the TLS layer, because the
    /// scheme is defined in terms of record sizes. Where a record is bigger
    /// than what is left of the payload, the slack is filled with a
    /// `cmdWaste` frame the peer reads and drops; where the payload runs out
    /// entirely, a record of pure waste is emitted. A check mark ends the
    /// sequence early once the payload is spent, so a short request is not
    /// followed by padding that would itself be a signature.
    ///
    /// Anything still unsent after the sizes run out goes as one final write.
    static func shapeWrites(_ payload: [UInt8], sizes: [Int]) -> [[UInt8]] {
        var writes = [[UInt8]]()
        var rest = ArraySlice(payload)

        for size in sizes {
            if size == checkMark {
                if rest.isEmpty { return writes }
                continue
            }
            if rest.count > size {
                writes.append(Array(rest.prefix(size)))
                rest = rest.dropFirst(size)
            } else if !rest.isEmpty {
                let padLength = size - rest.count - headerSize
                var record = Array(rest)
                if padLength > 0 {
                    record.append(contentsOf: frame(cmdWaste, streamId: 0, data: [UInt8](repeating: 0, count: padLength)))
                }
                writes.append(record)
                rest = ArraySlice()
            } else {
                writes.append(frame(cmdWaste, streamId: 0, data: [UInt8](repeating: 0, count: size)))
            }
        }

        if !rest.isEmpty {
            writes.append(Array(rest))
        }
        return writes
    }
}
