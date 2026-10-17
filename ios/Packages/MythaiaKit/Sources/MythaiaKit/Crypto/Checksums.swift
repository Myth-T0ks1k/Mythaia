import Foundation

/// FNV-1a, 32-bit — the checksum VMess puts at the end of its request header.
/// Not a MAC; it catches a corrupted header, nothing more.
enum FNV1a {
    static let offsetBasis: UInt32 = 0x811C_9DC5
    static let prime: UInt32 = 16_777_619

    static func hash32<S: Sequence>(_ data: S) -> UInt32 where S.Element == UInt8 {
        var hash = offsetBasis
        for byte in data {
            hash ^= UInt32(byte)
            hash = hash &* prime
        }
        return hash
    }
}

/// CRC-32 (IEEE 802.3, the zlib one). VMess seals a CRC of the timestamp and
/// nonce into its authentication ID, and the server recomputes it, so this
/// has to be the exact polynomial and bit order zlib uses.
enum CRC32Checksum {
    private static let table: [UInt32] = {
        var table = [UInt32](repeating: 0, count: 256)
        for i in 0..<256 {
            var c = UInt32(i)
            for _ in 0..<8 {
                if c & 1 != 0 {
                    c = 0xEDB8_8320 ^ (c >> 1)
                } else {
                    c = c >> 1
                }
            }
            table[i] = c
        }
        return table
    }()

    static func compute<S: Sequence>(_ data: S) -> UInt32 where S.Element == UInt8 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = table[index] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
