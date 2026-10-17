import Foundation

/// NaiveProxy's padding negotiation: the headers a CONNECT carries to ask
/// for padding, and reading the server's answer.
enum NaivePaddingNegotiator {
    enum PaddingType: Int {
        /// No padding: the tunnel carries the bytes as they are.
        case unpadded = 0
        case variant1 = 1
    }

    /// The 17 printable ASCII characters whose HPACK Huffman codes are at
    /// least 8 bits, in Huffman table order: a header value made of them
    /// cannot be compressed below its length, so the padding header's size
    /// on the wire is what it says. Characters: ! " # $ & ' ( ) * + , ; < > ? @ X
    static let nonIndexCodes: [UInt8] = [
        0x21, 0x22, 0x23, 0x24, 0x26, 0x27, 0x28, 0x29, 0x2A,
        0x2B, 0x2C, 0x3B, 0x3C, 0x3E, 0x3F, 0x40, 0x58,
    ]

    /// A random padding header value of 16–32 non-indexed characters. The
    /// first 16 come from 4-bit chunks of a random 64-bit value (indexing the
    /// first 16 entries); the rest are the 17th, 'X'.
    static func generatePaddingValue() -> String {
        let length = Int.random(in: 16...32)
        var uniqueBits = UInt64.random(in: UInt64.min...UInt64.max)
        var chars = [UInt8]()
        chars.reserveCapacity(length)
        for i in 0..<length {
            if i < 16 {
                chars.append(nonIndexCodes[Int(uniqueBits & 0x0F)])
                uniqueBits >>= 4
            } else {
                chars.append(nonIndexCodes[16])
            }
        }
        return String(decoding: chars, as: UTF8.self)
    }

    /// The padding headers for a CONNECT request. `fastOpen` adds
    /// `fastopen: 1`, used when the server's padding type is already known.
    static func requestHeaders(fastOpen: Bool = false) -> [HpackHeader] {
        var headers = [HpackHeader("padding", generatePaddingValue()), HpackHeader("padding-type-request", "1, 0")]
        if fastOpen {
            headers.append(HpackHeader("fastopen", "1"))
        }
        return headers
    }

    /// The padding the server chose: its `padding-type-reply` when there is
    /// one; otherwise a `padding` header means variant 1 (older servers);
    /// otherwise none.
    static func parseResponse(_ headers: [HpackHeader]) -> PaddingType {
        if let reply = headers.first(where: { $0.name.lowercased() == "padding-type-reply" }) {
            let value = reply.value.trimmingCharacters(in: .whitespaces)
            if let raw = Int(value) {
                return PaddingType(rawValue: raw) ?? .unpadded
            }
        }
        if headers.contains(where: { $0.name.lowercased() == "padding" }) {
            return .variant1
        }
        return .unpadded
    }
}

/// NaiveProxy padding frames for the first `maxFrames` reads and writes of a
/// tunnel; after them the data passes through unframed.
///
/// Wire format per frame:
/// `[payload_size >> 8] [payload_size & 0xFF] [padding_size] [payload] [padding zeros]`
final class NaivePaddingFramer {
    static let frameHeaderSize = 3
    static let maxPaddingSize = 255

    private enum ReadState {
        case payloadLength1
        case payloadLength2
        case paddingLength
        case payload
        case padding
    }

    private let maxFrames: Int
    private(set) var numReadFrames = 0
    private(set) var numWrittenFrames = 0
    private var state = ReadState.payloadLength1
    private var readPayloadLength = 0
    private var readPaddingLength = 0

    init(maxFrames: Int = 8) {
        self.maxFrames = maxFrames
    }

    var isReadPaddingActive: Bool { numReadFrames < maxFrames }
    var isWritePaddingActive: Bool { numWrittenFrames < maxFrames }

    /// Reads padded input, appending payload bytes to `into`. Returns the
    /// payload bytes found (0 means only padding or a header was consumed,
    /// not the end). The state carries across partial reads.
    func read(_ padded: [UInt8], into: inout [UInt8]) -> Int {
        let start = into.count
        var offset = 0
        while offset < padded.count {
            switch state {
            case .payloadLength1:
                if numReadFrames >= maxFrames {
                    into.append(contentsOf: padded[offset...])
                    offset = padded.count
                    continue
                }
                readPayloadLength = Int(padded[offset])
                offset += 1
                state = .payloadLength2
            case .payloadLength2:
                readPayloadLength = readPayloadLength * 256 + Int(padded[offset])
                offset += 1
                state = .paddingLength
            case .paddingLength:
                readPaddingLength = Int(padded[offset])
                offset += 1
                state = .payload
            case .payload:
                let copySize = min(readPayloadLength, padded.count - offset)
                readPayloadLength -= copySize
                into.append(contentsOf: padded[offset..<(offset + copySize)])
                offset += copySize
                if readPayloadLength == 0 {
                    state = .padding
                }
            case .padding:
                let skipSize = min(readPaddingLength, padded.count - offset)
                readPaddingLength -= skipSize
                offset += skipSize
                if readPaddingLength == 0 {
                    if numReadFrames < Int.max - 1 {
                        numReadFrames += 1
                    }
                    state = .payloadLength1
                }
            }
        }
        return into.count - start
    }

    /// `payload` wrapped in a padding frame: header, payload, zero padding.
    func write(_ payload: [UInt8], paddingSize: Int) -> [UInt8] {
        let padding = max(0, min(paddingSize, NaivePaddingFramer.maxPaddingSize))
        var frame = [UInt8]()
        frame.reserveCapacity(NaivePaddingFramer.frameHeaderSize + payload.count + padding)
        frame.append(UInt8(truncatingIfNeeded: payload.count / 256))
        frame.append(UInt8(truncatingIfNeeded: payload.count % 256))
        frame.append(UInt8(truncatingIfNeeded: padding))
        frame.append(contentsOf: payload)
        frame.append(contentsOf: [UInt8](repeating: 0, count: padding))
        if numWrittenFrames < Int.max - 1 {
            numWrittenFrames += 1
        }
        return frame
    }
}
