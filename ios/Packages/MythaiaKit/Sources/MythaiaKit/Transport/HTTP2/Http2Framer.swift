import Foundation

/// RFC 9113 §6 frame types this client handles.
enum Http2FrameType: Int {
    case data = 0x0
    case headers = 0x1
    case rstStream = 0x3
    case settings = 0x4
    case ping = 0x6
    case goaway = 0x7
    case windowUpdate = 0x8
    case continuation = 0x9

    static func fromValue(_ value: Int) -> Http2FrameType? {
        Http2FrameType(rawValue: value)
    }
}

enum Http2FrameFlags {
    static let endStream = 0x1
    static let ack = 0x1
    static let endHeaders = 0x4
    static let padded = 0x8
    static let priority = 0x20
}

/// RFC 9113 §4.1 frame. Wire format (9-byte header + payload):
/// ```
/// [3 bytes] Length  (payload length, unsigned 24-bit)
/// [1 byte]  Type
/// [1 byte]  Flags
/// [4 bytes] Stream ID (bit 0 reserved, always 0)
/// [Length bytes] Payload
/// ```
struct Http2Frame: Equatable {
    var type: Http2FrameType
    var flags: Int
    var streamID: Int
    var payload: Data

    init(type: Http2FrameType, flags: Int, streamID: Int, payload: Data) {
        self.type = type
        self.flags = flags
        self.streamID = streamID
        self.payload = payload
    }

    func hasFlag(_ flag: Int) -> Bool {
        (flags & flag) != 0
    }
}

enum Http2Framer {
    static let headerSize = 9
    static let maxDataPayload = 16_384

    /// RFC 9113 §7 error codes used by RST_STREAM and GOAWAY.
    enum ErrorCode {
        static let noError = 0x0
        static let protocolError = 0x1
        static let internalError = 0x2
        static let flowControlError = 0x3
        static let settingsTimeout = 0x4
        static let streamClosed = 0x5
        static let frameSizeError = 0x6
        static let refusedStream = 0x7
        static let cancel = 0x8
    }

    struct GoawayData: Equatable {
        var lastStreamID: Int
        var errorCode: Int
    }

    static func serialize(_ frame: Http2Frame) -> Data {
        let length = frame.payload.count
        let sid = frame.streamID & 0x7FFF_FFFF
        var header = [UInt8](repeating: 0, count: headerSize)
        header[0] = UInt8((length >> 16) & 0xFF)
        header[1] = UInt8((length >> 8) & 0xFF)
        header[2] = UInt8(length & 0xFF)
        header[3] = UInt8(frame.type.rawValue)
        header[4] = UInt8(frame.flags & 0xFF)
        header[5] = UInt8((sid >> 24) & 0xFF)
        header[6] = UInt8((sid >> 16) & 0xFF)
        header[7] = UInt8((sid >> 8) & 0xFF)
        header[8] = UInt8(sid & 0xFF)
        var out = Data(header)
        out.append(frame.payload)
        return out
    }

    /// The next frame in `buffer`, or nil while it holds no complete one.
    static func deserialize(_ buffer: Http2Buffer) -> Http2Frame? {
        if buffer.available < headerSize { return nil }
        let b = buffer.peekHeader()
        let length = (Int(b[0]) << 16) | (Int(b[1]) << 8) | Int(b[2])
        if buffer.available < headerSize + length { return nil }

        let rawType = Int(b[3])
        let flags = Int(b[4])
        let high = (Int(b[5]) << 24) | (Int(b[6]) << 16)
        let low = (Int(b[7]) << 8) | Int(b[8])
        let streamID = (high | low) & 0x7FFF_FFFF

        buffer.skip(headerSize)
        let payload = buffer.read(length)

        guard let type = Http2FrameType.fromValue(rawType) else {
            // An unknown frame type is ignored (RFC 9113 §4.1): an empty DATA
            // placeholder routes to nothing.
            return Http2Frame(type: .data, flags: 0, streamID: streamID, payload: Data())
        }
        return Http2Frame(type: type, flags: flags, streamID: streamID, payload: payload)
    }

    static func settingsFrame(_ settings: [(Int, Int)]) -> Http2Frame {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(settings.count * 6)
        for (id, value) in settings {
            bytes.append(UInt8((id >> 8) & 0xFF))
            bytes.append(UInt8(id & 0xFF))
            bytes.append(contentsOf: uint32Bytes(value))
        }
        return Http2Frame(type: .settings, flags: 0, streamID: 0, payload: Data(bytes))
    }

    static func settingsAckFrame() -> Http2Frame {
        Http2Frame(type: .settings, flags: Http2FrameFlags.ack, streamID: 0, payload: Data())
    }

    static func windowUpdateFrame(streamID: Int, increment: Int) -> Http2Frame {
        Http2Frame(type: .windowUpdate, flags: 0, streamID: streamID, payload: Data(uint32Bytes(increment & 0x7FFF_FFFF)))
    }

    /// HEADERS with END_HEADERS set: header blocks this side sends always fit
    /// one frame, so no CONTINUATION.
    static func headersFrame(streamID: Int, headerBlock: Data, endStream: Bool = false) -> Http2Frame {
        var flags = Http2FrameFlags.endHeaders
        if endStream { flags |= Http2FrameFlags.endStream }
        return Http2Frame(type: .headers, flags: flags, streamID: streamID, payload: headerBlock)
    }

    static func dataFrame(streamID: Int, payload: Data, endStream: Bool = false) -> Http2Frame {
        Http2Frame(type: .data, flags: endStream ? Http2FrameFlags.endStream : 0, streamID: streamID, payload: payload)
    }

    static func pingAckFrame(_ opaqueData: Data) -> Http2Frame {
        Http2Frame(type: .ping, flags: Http2FrameFlags.ack, streamID: 0, payload: opaqueData)
    }

    /// A PING the peer must answer with the same 8 opaque bytes (RFC 9113 §6.7).
    static func pingFrame(_ opaqueData: Data = Data(count: 8)) -> Http2Frame {
        Http2Frame(type: .ping, flags: 0, streamID: 0, payload: opaqueData)
    }

    /// RST_STREAM with the given error code (RFC 9113 §6.4).
    static func rstStreamFrame(streamID: Int, errorCode: Int) -> Http2Frame {
        Http2Frame(type: .rstStream, flags: 0, streamID: streamID, payload: Data(uint32Bytes(errorCode)))
    }

    /// The data of a DATA frame without its padding (RFC 9113 §6.1): with
    /// PADDED set, the first payload byte is the pad length and that many
    /// bytes at the end are padding. Nil when the pad length does not fit the
    /// payload, which §6.1 makes a connection error.
    static func dataPayload(_ frame: Http2Frame) -> Data? {
        stripPadding(frame.payload, padded: frame.hasFlag(Http2FrameFlags.padded))
    }

    /// The header block fragment of a HEADERS frame (RFC 9113 §6.2): the
    /// payload without its padding (PADDED) and without the 5-byte priority
    /// block (PRIORITY: a stream dependency and weight, which this client
    /// ignores). Fed to HPACK as it was, padding and priority bytes decoded
    /// as header fields and derailed the dynamic table for every later block.
    /// Nil when the flags claim more bytes than the payload has.
    static func headerBlockFragment(_ frame: Http2Frame) -> Data? {
        guard let unpadded = stripPadding(frame.payload, padded: frame.hasFlag(Http2FrameFlags.padded)) else {
            return nil
        }
        if !frame.hasFlag(Http2FrameFlags.priority) { return unpadded }
        let bytes = [UInt8](unpadded)
        if bytes.count < 5 { return nil }
        return Data(bytes[5...])
    }

    private static func stripPadding(_ payload: Data, padded: Bool) -> Data? {
        if !padded { return payload }
        let bytes = [UInt8](payload)
        if bytes.isEmpty { return nil }
        let padLength = Int(bytes[0])
        // §6.1: a pad length of the payload's length or more is a PROTOCOL_ERROR.
        if padLength >= bytes.count { return nil }
        return Data(bytes[1..<(bytes.count - padLength)])
    }

    static func parseSettings(_ payload: Data) -> [(Int, Int)] {
        let bytes = [UInt8](payload)
        var result: [(Int, Int)] = []
        var offset = 0
        while offset + 6 <= bytes.count {
            let id = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
            let value = readUInt32(bytes, offset + 2)
            result.append((id, value))
            offset += 6
        }
        return result
    }

    static func parseWindowUpdate(_ payload: Data) -> Int? {
        let bytes = [UInt8](payload)
        if bytes.count < 4 { return nil }
        return readUInt32(bytes, 0) & 0x7FFF_FFFF
    }

    static func parseGoaway(_ payload: Data) -> GoawayData? {
        let bytes = [UInt8](payload)
        if bytes.count < 8 { return nil }
        return GoawayData(lastStreamID: readUInt32(bytes, 0) & 0x7FFF_FFFF, errorCode: readUInt32(bytes, 4))
    }

    static func parseRstStream(_ payload: Data) -> Int? {
        let bytes = [UInt8](payload)
        if bytes.count < 4 { return nil }
        return readUInt32(bytes, 0)
    }

    static func uint32Bytes(_ value: Int) -> [UInt8] {
        [
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ]
    }

    static func readUInt32(_ bytes: [UInt8], _ offset: Int) -> Int {
        let high = (Int(bytes[offset]) << 24) | (Int(bytes[offset + 1]) << 16)
        let low = (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
        return high | low
    }
}

/// Bytes read from the connection and not yet parsed into frames. A read
/// offset instead of copying the rest down after every frame.
final class Http2Buffer {
    private var bytes: [UInt8] = []
    private var readOffset = 0

    init() {}

    var available: Int { bytes.count - readOffset }

    var isEmpty: Bool { available <= 0 }

    func append(_ data: Data) {
        if readOffset > 0 && readOffset > bytes.count / 2 {
            compact()
        }
        bytes.append(contentsOf: data)
    }

    func peekHeader() -> [UInt8] {
        Array(bytes[readOffset..<(readOffset + Http2Framer.headerSize)])
    }

    func skip(_ count: Int) {
        readOffset += count
    }

    func read(_ count: Int) -> Data {
        if count == 0 { return Data() }
        let out = Data(bytes[readOffset..<(readOffset + count)])
        readOffset += count
        return out
    }

    func clear() {
        bytes = []
        readOffset = 0
    }

    private func compact() {
        if readOffset == 0 { return }
        bytes.removeFirst(readOffset)
        readOffset = 0
    }
}
