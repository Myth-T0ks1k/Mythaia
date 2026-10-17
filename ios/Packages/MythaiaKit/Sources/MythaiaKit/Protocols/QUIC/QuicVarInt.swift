import Foundation

/// QUIC's variable-length integer encoding (RFC 9000 §16).
///
/// The two high bits of the first byte pick a 1, 2, 4 or 8-byte form and the
/// rest of the bits are the value, so small numbers cost one byte. It is used
/// for nearly every length and identifier in QUIC and HTTP/3, which is why it
/// lives on its own rather than inside whichever layer needed it first.
///
/// Values are carried as `Int64`: the encoding tops out at 2^62 - 1,
/// comfortably inside a positive Int64, so a negative value here is a caller's
/// mistake rather than a wrap.
enum QuicVarInt {
    /// The largest value the encoding can express: 2^62 - 1.
    static let max: Int64 = 4_611_686_018_427_387_903

    /// Whether `value` can be written at all.
    static func isEncodable(_ value: Int64) -> Bool {
        return value >= 0 && value <= max
    }

    /// How many bytes `value` will take. Callers write lengths and ids they
    /// produced themselves; anything past the 4-byte range takes 8.
    static func sizeOf(_ value: Int64) -> Int {
        if value >= 0 && value <= 63 { return 1 }
        if value >= 0 && value <= 16_383 { return 2 }
        if value >= 0 && value <= 1_073_741_823 { return 4 }
        return 8
    }

    /// The encoding of `value`; throws for one the encoding cannot express.
    static func encode(_ value: Int64) throws -> [UInt8] {
        guard isEncodable(value) else {
            throw MythaiaError.invalidConfiguration("QUIC varint out of range: \(value)")
        }
        var out: [UInt8] = []
        append(value, to: &out)
        return out
    }

    /// Appends `value`, which must be encodable; the bits above 62 are not
    /// written.
    static func append(_ value: Int64, to out: inout [UInt8]) {
        let size = sizeOf(value)
        let start = out.count
        out.append(contentsOf: [UInt8](repeating: 0, count: size))
        _ = write(&out, start, value)
    }

    /// Writes `value` at `offset` (the buffer must have room) and returns the
    /// number of bytes written.
    @discardableResult
    static func write(_ out: inout [UInt8], _ offset: Int, _ value: Int64) -> Int {
        let size = sizeOf(value)
        let bits = UInt64(bitPattern: value) & 0x3FFF_FFFF_FFFF_FFFF
        switch size {
        case 1:
            out[offset] = UInt8(truncatingIfNeeded: bits)
        case 2:
            out[offset] = 0x40 | UInt8(truncatingIfNeeded: bits >> 8)
            out[offset + 1] = UInt8(truncatingIfNeeded: bits)
        case 4:
            out[offset] = 0x80 | UInt8(truncatingIfNeeded: bits >> 24)
            out[offset + 1] = UInt8(truncatingIfNeeded: bits >> 16)
            out[offset + 2] = UInt8(truncatingIfNeeded: bits >> 8)
            out[offset + 3] = UInt8(truncatingIfNeeded: bits)
        default:
            out[offset] = 0xC0 | UInt8(truncatingIfNeeded: bits >> 56)
            for index in 1..<8 {
                out[offset + index] = UInt8(truncatingIfNeeded: bits >> UInt64((7 - index) * 8))
            }
        }
        return size
    }

    /// A decoded value and how many bytes it occupied.
    struct Decoded: Equatable {
        let value: Int64
        let size: Int
    }

    /// Reads a varint at `offset`, or nil when the buffer stops short of one.
    ///
    /// Nil rather than an error because every caller here is parsing bytes
    /// that arrived over a network: a truncated frame is something to wait
    /// for or drop, not something exceptional.
    static func decode(_ bytes: [UInt8], _ offset: Int = 0) -> Decoded? {
        if offset < 0 || offset >= bytes.count { return nil }
        let first = bytes[offset]
        let size = 1 << Int(first >> 6)
        if offset + size > bytes.count { return nil }
        var value = UInt64(first & 0x3F)
        var index = 1
        while index < size {
            value = (value << 8) | UInt64(bytes[offset + index])
            index += 1
        }
        return Decoded(value: Int64(value), size: size)
    }
}
