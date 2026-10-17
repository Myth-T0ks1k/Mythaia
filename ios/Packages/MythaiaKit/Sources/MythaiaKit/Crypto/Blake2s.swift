import Foundation

/// BLAKE2s (RFC 7693), the hash WireGuard is built on, with the keyed mode its
/// MACs use and the HMAC and HKDF over it that make up its key schedule.
///
/// CryptoKit has none of these. The digest length is a parameter of the hash
/// itself, mixed into the first state word, so a 16-byte BLAKE2s is not the
/// first half of a 32-byte one: WireGuard's mac1 and mac2 have to be computed
/// at 16 bytes, never cut down afterwards.
struct Blake2s {
    static let blockLength = 64
    static let maxOutputLength = 32
    static let maxKeyLength = 32

    private var state: [UInt32]
    private var buffer: [UInt8]
    private var bufferLength = 0
    /// Bytes compressed so far, the key block included; the `t` of the RFC.
    private var counter: UInt64 = 0
    private let outputLength: Int

    /// A hasher producing `outputLength` bytes (1 to 32), keyed when `key`
    /// (at most 32 bytes) is not empty.
    init(outputLength: Int = Blake2s.maxOutputLength, key: [UInt8] = []) {
        precondition(outputLength >= 1 && outputLength <= Blake2s.maxOutputLength, "BLAKE2s outputs 1 to 32 bytes")
        precondition(key.count <= Blake2s.maxKeyLength, "BLAKE2s keys are at most 32 bytes")
        self.outputLength = outputLength
        var initial = blake2sIV
        // The parameter block: digest length, key length, fanout 1, depth 1.
        initial[0] ^= 0x0101_0000 ^ (UInt32(key.count) << 8) ^ UInt32(outputLength)
        state = initial
        buffer = [UInt8](repeating: 0, count: Blake2s.blockLength)
        if !key.isEmpty {
            // The key, zero-padded to a whole block, is the message's first
            // block; with nothing after it, it is also the last.
            for index in 0..<key.count {
                buffer[index] = key[index]
            }
            bufferLength = Blake2s.blockLength
        }
    }

    mutating func update<Bytes: Sequence>(_ input: Bytes) where Bytes.Element == UInt8 {
        for byte in input {
            // A full block is compressed only once more input arrives: the
            // last block, full or not, has to go through with the final flag.
            if bufferLength == Blake2s.blockLength {
                counter &+= UInt64(Blake2s.blockLength)
                compress(isLast: false)
                bufferLength = 0
            }
            buffer[bufferLength] = byte
            bufferLength += 1
        }
    }

    mutating func finalize() -> [UInt8] {
        counter &+= UInt64(bufferLength)
        var index = bufferLength
        while index < Blake2s.blockLength {
            buffer[index] = 0
            index += 1
        }
        compress(isLast: true)
        var out: [UInt8] = []
        out.reserveCapacity(Blake2s.maxOutputLength)
        for word in state {
            out.append(UInt8(truncatingIfNeeded: word))
            out.append(UInt8(truncatingIfNeeded: word >> 8))
            out.append(UInt8(truncatingIfNeeded: word >> 16))
            out.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return Array(out[0..<outputLength])
    }

    /// One-shot BLAKE2s of `input`.
    static func hash(_ input: [UInt8], outputLength: Int = Blake2s.maxOutputLength, key: [UInt8] = []) -> [UInt8] {
        var hasher = Blake2s(outputLength: outputLength, key: key)
        hasher.update(input)
        return hasher.finalize()
    }

    /// HMAC (RFC 2104) over BLAKE2s-256, with BLAKE2s's 64-byte block.
    ///
    /// WireGuard's key schedule uses this rather than BLAKE2s's own keyed
    /// mode, so the two are not interchangeable even with the same key.
    static func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var block = key.count > blockLength ? hash(key) : key
        while block.count < blockLength {
            block.append(0)
        }
        var inner = Blake2s()
        inner.update(block.map { $0 ^ 0x36 })
        inner.update(data)
        let innerDigest = inner.finalize()

        var outer = Blake2s()
        outer.update(block.map { $0 ^ 0x5C })
        outer.update(innerDigest)
        return outer.finalize()
    }

    /// HKDF (RFC 5869) over HMAC-BLAKE2s with an empty info, as WireGuard
    /// uses it: `salt` is the extract key, and the output is `count` blocks of
    /// 32 bytes, T(1) to T(count).
    static func hkdf(salt: [UInt8], input: [UInt8], count: Int) -> [[UInt8]] {
        let prk = hmac(key: salt, data: input)
        var out: [[UInt8]] = []
        out.reserveCapacity(max(0, count))
        var previous: [UInt8] = []
        var index = 1
        while index <= count {
            var message = previous
            message.append(UInt8(truncatingIfNeeded: index))
            previous = hmac(key: prk, data: message)
            out.append(previous)
            index += 1
        }
        return out
    }

    private mutating func compress(isLast: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for index in 0..<16 {
            let at = index * 4
            var word = UInt32(buffer[at])
            word |= UInt32(buffer[at + 1]) << 8
            word |= UInt32(buffer[at + 2]) << 16
            word |= UInt32(buffer[at + 3]) << 24
            m[index] = word
        }

        var v = state
        v.append(contentsOf: blake2sIV)
        v[12] ^= UInt32(truncatingIfNeeded: counter)
        v[13] ^= UInt32(truncatingIfNeeded: counter >> 32)
        if isLast {
            v[14] = ~v[14]
        }

        for round in 0..<10 {
            let s = blake2sSigma[round]
            blake2sG(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            blake2sG(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            blake2sG(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            blake2sG(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            blake2sG(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            blake2sG(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            blake2sG(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            blake2sG(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for index in 0..<8 {
            state[index] ^= v[index] ^ v[index + 8]
        }
    }
}

/// The SHA-256 initial values, which BLAKE2s shares.
private let blake2sIV: [UInt32] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
]

/// The message schedule: which words each of the ten rounds reads, in order.
private let blake2sSigma: [[Int]] = [
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

@inline(__always)
private func blake2sRotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
    return (x &>> n) | (x &<< (32 - n))
}

/// The mixing function, with BLAKE2s's rotations (16, 12, 8, 7).
private func blake2sG(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
    v[a] = v[a] &+ v[b] &+ x
    v[d] = blake2sRotr(v[d] ^ v[a], 16)
    v[c] = v[c] &+ v[d]
    v[b] = blake2sRotr(v[b] ^ v[c], 12)
    v[a] = v[a] &+ v[b] &+ y
    v[d] = blake2sRotr(v[d] ^ v[a], 8)
    v[c] = v[c] &+ v[d]
    v[b] = blake2sRotr(v[b] ^ v[c], 7)
}
