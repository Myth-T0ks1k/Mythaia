import Foundation

/// The frame types this client names (RFC 9114 §11.2.1).
///
/// The gaps are deliberate. 0x02, 0x06, 0x08 and 0x09 are permanently reserved
/// because HTTP/2 spent them on frames HTTP/3 does not need, and receiving one
/// is a connection error rather than an unknown type to skip over.
enum Http3FrameType: Int64, CaseIterable {
    case data = 0x00
    case headers = 0x01
    case cancelPush = 0x03
    case settings = 0x04
    case pushPromise = 0x05
    case goaway = 0x07
    case maxPushId = 0x0D
}

/// Settings identifiers this client understands (RFC 9114 §7.2.4.1 and the
/// extensions below). An identifier a peer does not recognise must be
/// ignored, which is how the extension settings got here without a new HTTP
/// version.
enum Http3SettingsId: Int64, CaseIterable {
    case qpackMaxTableCapacity = 0x01
    case maxFieldSectionSize = 0x06
    case qpackBlockedStreams = 0x07
    /// RFC 9220: extended CONNECT, which brings the `:protocol` pseudo-header.
    case enableConnectProtocol = 0x08
    /// RFC 9297: HTTP Datagrams, the carrier CONNECT-UDP rides on.
    case h3Datagram = 0x33
}

/// Application error codes (RFC 9114 §8.1): what an endpoint puts in a QUIC
/// CONNECTION_CLOSE, RESET_STREAM or STOP_SENDING to say why HTTP/3, rather
/// than QUIC, gave up.
enum Http3ErrorCode: Int64, CaseIterable {
    case noError = 0x0100
    case generalProtocolError = 0x0101
    case internalError = 0x0102
    case streamCreationError = 0x0103
    case closedCriticalStream = 0x0104
    case frameUnexpected = 0x0105
    case frameError = 0x0106
    case excessiveLoad = 0x0107
    case idError = 0x0108
    case settingsError = 0x0109
    case missingSettings = 0x010A
    case requestRejected = 0x010B
    case requestCancelled = 0x010C
    case requestIncomplete = 0x010D
    case messageError = 0x010E
    case connectError = 0x010F
    case versionFallback = 0x0110
}

/// One identifier/value pair of a SETTINGS frame.
struct Http3Setting: Equatable {
    let id: Int64
    let value: Int64
}

/// The HTTP/3 frame layer: what a peer writes onto a QUIC stream once the
/// connection is up.
///
/// A frame is a varint type, a varint length, then exactly that many payload
/// bytes (RFC 9114 §7.1). There is no fixed-size header to peek at, and a QUIC
/// stream read can end anywhere — including halfway through the length varint.
/// That is what shapes `parse`: it reports `incomplete` without consuming
/// anything, so a caller can append the next read and simply try again.
///
/// Types and settings stay raw `Int64` values next to their enums: HTTP/3
/// reserves whole families of codepoints for extensions and greasing, so an
/// endpoint has to hold onto a value it has no name for instead of rejecting it.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
enum Http3Framer {
    /// A 256 KiB ceiling on the decompressed size of a field section, which
    /// bounds what a server can make this client hold for one response's
    /// headers.
    static let fieldSectionSizeLimit: Int64 = 262_144

    /// The settings a client announces, in the order it announces them. Both
    /// QPACK settings are zero because this client runs QPACK with no dynamic
    /// table; the other two make tunnelling possible — extended CONNECT for
    /// CONNECT-UDP's handshake and HTTP Datagrams for its payloads.
    static let clientSettings: [Http3Setting] = [
        Http3Setting(id: Http3SettingsId.qpackMaxTableCapacity.rawValue, value: 0),
        Http3Setting(id: Http3SettingsId.qpackBlockedStreams.rawValue, value: 0),
        Http3Setting(id: Http3SettingsId.maxFieldSectionSize.rawValue, value: fieldSectionSizeLimit),
        Http3Setting(id: Http3SettingsId.enableConnectProtocol.rawValue, value: 1),
        Http3Setting(id: Http3SettingsId.h3Datagram.rawValue, value: 1),
    ]

    /// SETTINGS without HTTP Datagrams or extended CONNECT, for protocols that
    /// use HTTP/3 only to authenticate and then carry their own framing in raw
    /// QUIC datagrams (Hysteria2). Announcing H3_DATAGRAM there makes the
    /// server's HTTP/3 layer claim every QUIC datagram as an HTTP datagram,
    /// and the protocol's UDP never sees them.
    static let plainClientSettings: [Http3Setting] = [
        Http3Setting(id: Http3SettingsId.qpackMaxTableCapacity.rawValue, value: 0),
        Http3Setting(id: Http3SettingsId.qpackBlockedStreams.rawValue, value: 0),
        Http3Setting(id: Http3SettingsId.maxFieldSectionSize.rawValue, value: fieldSectionSizeLimit),
    ]

    /// One frame off the wire. `type` stays a raw code so a frame this client
    /// has no name for still round-trips intact.
    struct Frame: Equatable {
        let type: Int64
        let payload: [UInt8]

        /// The named type, or nil for an extension or greased frame to ignore.
        var knownType: Http3FrameType? { Http3FrameType(rawValue: type) }
    }

    /// What `parse` found at the offset it was given.
    enum ParseResult: Equatable {
        /// A whole frame, and how many bytes of the buffer it occupied.
        case complete(Frame, bytesConsumed: Int)
        /// The buffer stops short of a whole frame. Nothing was consumed:
        /// read more, append it, and parse again at the same offset.
        case incomplete
        /// The frame can never be completed, so waiting for more bytes would
        /// block the stream forever.
        case malformed(String)
    }

    /// The first bytes of a unidirectional stream say what it is (RFC 9114
    /// §6.2). A varint, not a byte: greasing deliberately uses large values.
    static let streamTypeControl: Int64 = 0x00
    static let streamTypePush: Int64 = 0x01
    static let streamTypeQpackEncoder: Int64 = 0x02
    static let streamTypeQpackDecoder: Int64 = 0x03

    /// The opening bytes that declare a unidirectional stream's type.
    static func uniStreamType(_ type: Int64) -> [UInt8] {
        var out: [UInt8] = []
        QuicVarInt.append(type, to: &out)
        return out
    }

    /// Reads that declaration, or nil when the buffer is still short of it.
    static func readUniStreamType(_ bytes: [UInt8]) -> QuicVarInt.Decoded? {
        return QuicVarInt.decode(bytes)
    }

    /// Wraps `payload` in a frame of the given type.
    static func frame(_ type: Int64, _ payload: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(payload.count + 16)
        QuicVarInt.append(type, to: &out)
        QuicVarInt.append(Int64(payload.count), to: &out)
        out.append(contentsOf: payload)
        return out
    }

    static func frame(_ type: Http3FrameType, _ payload: [UInt8]) -> [UInt8] {
        return frame(type.rawValue, payload)
    }

    /// A DATA frame: request or response body bytes (RFC 9114 §7.2.1).
    static func dataFrame(_ payload: [UInt8]) -> [UInt8] {
        return frame(.data, payload)
    }

    /// A HEADERS frame carrying an already-encoded QPACK field section
    /// (RFC 9114 §7.2.2). The framer never looks inside the block.
    static func headersFrame(_ headerBlock: [UInt8]) -> [UInt8] {
        return frame(.headers, headerBlock)
    }

    /// A SETTINGS frame of the given pairs, each a varint (RFC 9114 §7.2.4).
    /// Order is preserved because it is observable on the wire.
    static func settingsFrame(_ settings: [Http3Setting]) -> [UInt8] {
        var payload: [UInt8] = []
        for setting in settings {
            QuicVarInt.append(setting.id, to: &payload)
            QuicVarInt.append(setting.value, to: &payload)
        }
        return frame(.settings, payload)
    }

    /// The SETTINGS frame this client sends first on its control stream.
    static func clientSettingsFrame(_ settings: [Http3Setting] = clientSettings) -> [UInt8] {
        return settingsFrame(settings)
    }

    /// Reads a SETTINGS payload back into pairs, or nil when it ended
    /// mid-varint (a SETTINGS_ERROR, RFC 9114 §7.2.4.1). Duplicates are kept
    /// as they arrived, because a duplicate is itself an error a map would hide.
    static func parseSettings(_ payload: [UInt8]) -> [Http3Setting]? {
        var out: [Http3Setting] = []
        var at = 0
        while at < payload.count {
            guard let id = QuicVarInt.decode(payload, at) else { return nil }
            at += id.size
            guard let value = QuicVarInt.decode(payload, at) else { return nil }
            at += value.size
            out.append(Http3Setting(id: id.value, value: value.value))
        }
        return out
    }

    /// Reads one frame starting at `offset`. The buffer is left untouched
    /// unless a whole frame is present: frames arrive split across stream
    /// reads, and a parser that consumed a partial header would have nowhere
    /// to put it back.
    static func parse(_ bytes: [UInt8], offset: Int = 0) -> ParseResult {
        guard let type = QuicVarInt.decode(bytes, offset) else { return .incomplete }
        guard let length = QuicVarInt.decode(bytes, offset + type.size) else { return .incomplete }
        let headerSize = type.size + length.size
        // A varint length reaches 2^62-1, far past any buffer this can hold;
        // calling such a frame incomplete would buffer the stream for ever.
        if length.value > Int64(Int32.max) - Int64(headerSize) {
            return .malformed("frame length \(length.value) exceeds what can be buffered")
        }
        let payloadStart = offset + headerSize
        let payloadLength = Int(length.value)
        if payloadLength > bytes.count - payloadStart { return .incomplete }
        let frame = Frame(type: type.value, payload: Array(bytes[payloadStart..<(payloadStart + payloadLength)]))
        return .complete(frame, bytesConsumed: headerSize + payloadLength)
    }
}
