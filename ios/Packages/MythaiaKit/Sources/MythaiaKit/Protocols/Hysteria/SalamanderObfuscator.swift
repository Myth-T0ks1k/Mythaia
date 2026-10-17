import Foundation

/// Hysteria's Salamander obfuscation.
///
/// Every datagram becomes `salt(8) ‖ (packet XOR keystream)`, where the
/// keystream is BLAKE2b-256 over `password ‖ salt`, cycled to the packet's
/// length. There is no authentication here and none is wanted: QUIC underneath
/// already authenticates everything, and the point of this layer is only that
/// a censor cannot recognise a QUIC Initial packet by its plaintext header.
///
/// A fresh salt per datagram is what stops the keystream repeating — the same
/// password with the same salt produces the same key, so a fixed salt would
/// turn this into a single reused one-time pad.
final class SalamanderObfuscator: @unchecked Sendable {
    static let saltLength = 8
    /// The reference refuses a shorter pre-shared key.
    static let minPskLength = 4
    /// A BLAKE2b-256 digest, which is the whole keystream period.
    static let keyLength = 32

    private let psk: [UInt8]

    /// Throws for a password below the reference minimum: it refuses a
    /// shorter key outright rather than obfuscate weakly, and a server built
    /// on it would reject this client anyway.
    init(password: String) throws {
        psk = Array(password.utf8)
        guard psk.count >= SalamanderObfuscator.minPskLength else {
            throw MythaiaError.invalidConfiguration("Salamander needs a password of at least \(SalamanderObfuscator.minPskLength) bytes")
        }
    }

    /// `salt ‖ ciphertext`.
    func seal(_ packet: [UInt8]) -> [UInt8] {
        let salt = TLSWire.randomBytes(SalamanderObfuscator.saltLength)
        let key = keystream(salt)
        var out = salt
        out.reserveCapacity(SalamanderObfuscator.saltLength + packet.count)
        for index in 0..<packet.count {
            out.append(packet[index] ^ key[index % SalamanderObfuscator.keyLength])
        }
        return out
    }

    /// Reverses `seal`, or nil when the datagram is not one. Anything at or
    /// below the salt length is dropped rather than handed back: it cannot
    /// have come from this layer, and passing the raw bytes through would
    /// deliver un-deobfuscated data to QUIC.
    func open(_ datagram: [UInt8]) -> [UInt8]? {
        let saltLength = SalamanderObfuscator.saltLength
        if datagram.count <= saltLength { return nil }
        let key = keystream(Array(datagram[0..<saltLength]))
        var out = [UInt8](repeating: 0, count: datagram.count - saltLength)
        for index in 0..<out.count {
            out[index] = datagram[saltLength + index] ^ key[index % SalamanderObfuscator.keyLength]
        }
        return out
    }

    private func keystream(_ salt: [UInt8]) -> [UInt8] {
        return Blake2b.hash(psk + salt, outputLength: SalamanderObfuscator.keyLength)
    }
}

/// BLAKE2b (RFC 7693), unkeyed, which CryptoKit does not offer. It runs once
/// per datagram over a 32-byte digest, so a plain implementation is enough.
enum Blake2b {
    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private static let blockLength = 128

    /// The digest of `input`, `outputLength` (1...64) bytes long.
    static func hash(_ input: [UInt8], outputLength: Int) -> [UInt8] {
        let length = min(max(outputLength, 1), 64)
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(length)

        let blocks = max(1, (input.count + blockLength - 1) / blockLength)
        var counter: UInt64 = 0
        for blockIndex in 0..<blocks {
            let start = blockIndex * blockLength
            let end = min(start + blockLength, input.count)
            var block = [UInt8](repeating: 0, count: blockLength)
            if end > start {
                for index in start..<end {
                    block[index - start] = input[index]
                }
            }
            counter &+= UInt64(end - start)
            compress(&h, block: block, counter: counter, last: blockIndex == blocks - 1)
        }

        var out: [UInt8] = []
        out.reserveCapacity(64)
        for word in h {
            for shift in 0..<8 {
                out.append(UInt8(truncatingIfNeeded: word >> UInt64(shift * 8)))
            }
        }
        return Array(out[0..<length])
    }

    private static func compress(_ h: inout [UInt64], block: [UInt8], counter: UInt64, last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for index in 0..<16 {
            var word: UInt64 = 0
            for byte in 0..<8 {
                word |= UInt64(block[index * 8 + byte]) << UInt64(byte * 8)
            }
            m[index] = word
        }
        var v = h + iv
        v[12] ^= counter
        // The counter is 128 bits; the high half stays zero for any input
        // this ever sees.
        if last { v[14] = ~v[14] }

        for round in 0..<12 {
            let s = sigma[round % 10]
            mix(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for index in 0..<8 {
            h[index] ^= v[index] ^ v[index + 8]
        }
    }

    @inline(__always)
    private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 {
        return (x >> n) | (x << (64 - n))
    }

    @inline(__always)
    private static func mix(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = rotr(v[d] ^ v[a], 32)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 24)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = rotr(v[d] ^ v[a], 16)
        v[c] = v[c] &+ v[d]
        v[b] = rotr(v[b] ^ v[c], 63)
    }
}
