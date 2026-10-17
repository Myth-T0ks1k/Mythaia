import Foundation

/**
 * Gzip (RFC 1952) bodies from panels that compress whether asked or not.
 *
 * Foundation inflates raw DEFLATE (`NSData.decompressed(using: .zlib)` is RFC
 * 1951 without a header), so the gzip wrapper — header, optional fields, the
 * CRC-32 and length trailer — is read here around it.
 */
enum Gzip {

    /// The inflated body; throws `connectFailed` when it is not gzip or would exceed `limit` bytes.
    static func decompress(_ data: Data, limit: Int) throws -> Data {
        let bytes = [UInt8](data)
        guard bytes.count >= 18, bytes[0] == 0x1F, bytes[1] == 0x8B, bytes[2] == 8 else {
            throw invalid("no gzip header")
        }
        let flags = bytes[3]
        var i = 10
        if flags & 0x04 != 0 { // FEXTRA
            guard i + 2 <= bytes.count else { throw invalid("truncated header") }
            let length = Int(bytes[i]) | Int(bytes[i + 1]) << 8
            i += 2 + length
        }
        if flags & 0x08 != 0 { // FNAME
            while i < bytes.count && bytes[i] != 0 { i += 1 }
            i += 1
        }
        if flags & 0x10 != 0 { // FCOMMENT
            while i < bytes.count && bytes[i] != 0 { i += 1 }
            i += 1
        }
        if flags & 0x02 != 0 { i += 2 } // FHCRC
        let trailer = bytes.count - 8
        guard i <= trailer else { throw invalid("truncated stream") }

        let expectedCrc = littleEndian32(bytes, trailer)
        let expectedSize = littleEndian32(bytes, trailer + 4)
        // The size is mod 2^32, so this only catches the honest case; the
        // inflated length is checked again below.
        if Int(expectedSize) > limit {
            throw MythaiaError.connectFailed("Response larger than \(limit) bytes")
        }
        if expectedSize == 0 {
            return Data()
        }

        let deflated = Data(bytes[i..<trailer])
        let inflated: Data
        do {
            inflated = try (deflated as NSData).decompressed(using: .zlib) as Data
        } catch {
            throw invalid(error.localizedDescription)
        }
        if inflated.count > limit {
            throw MythaiaError.connectFailed("Response larger than \(limit) bytes")
        }
        if UInt32(truncatingIfNeeded: inflated.count) != expectedSize || crc32(inflated) != expectedCrc {
            throw invalid("checksum mismatch")
        }
        return inflated
    }

    private static func invalid(_ why: String) -> MythaiaError {
        MythaiaError.connectFailed("Response is not valid gzip: \(why)")
    }

    private static func littleEndian32(_ bytes: [UInt8], _ at: Int) -> UInt32 {
        let b0 = UInt32(bytes[at])
        let b1 = UInt32(bytes[at + 1]) << 8
        let b2 = UInt32(bytes[at + 2]) << 16
        let b3 = UInt32(bytes[at + 3]) << 24
        return b0 | b1 | b2 | b3
    }

    private static let crcTable: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 {
            c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1
        }
        return c
    }

    static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        let table = crcTable
        for b in data {
            crc = table[Int((crc ^ UInt32(b)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
