import Foundation

/// The Keccak-f[1600] permutation.
///
/// CryptoKit has no SHA-3 family on the systems this runs on, and VMess needs
/// SHAKE128: its chunk masking XORs every length prefix with a SHAKE128 stream
/// seeded by the body IV, so the stream has to be bit-exact with the server's
/// or the very first chunk desynchronises.
enum Keccak {
    static let roundConstants: [UInt64] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ]

    /// Rho rotation for each step of the pi walk below.
    static let rotationOffsets: [UInt64] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ]

    /// The lane each step of the combined rho-pi walk moves to.
    static let piLanes: [Int] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ]

    @inline(__always)
    static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        return (x &<< n) | (x &>> (64 - n))
    }

    /// The 24-round permutation over 25 little-endian lanes.
    static func permute(_ state: inout [UInt64]) {
        var bc = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            // Theta
            for i in 0..<5 {
                var column = state[i]
                column ^= state[i + 5]
                column ^= state[i + 10]
                column ^= state[i + 15]
                column ^= state[i + 20]
                bc[i] = column
            }
            for i in 0..<5 {
                let t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1)
                var j = 0
                while j < 25 {
                    state[j + i] ^= t
                    j += 5
                }
            }

            // Rho and pi
            var carried = state[1]
            for i in 0..<24 {
                let lane = piLanes[i]
                let saved = state[lane]
                state[lane] = rotl(carried, rotationOffsets[i])
                carried = saved
            }

            // Chi
            var row = 0
            while row < 25 {
                for i in 0..<5 {
                    bc[i] = state[row + i]
                }
                for i in 0..<5 {
                    state[row + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5]
                }
                row += 5
            }

            // Iota
            state[0] ^= roundConstants[round]
        }
    }

    /// SHA3-256, kept for pinning the permutation against published vectors.
    static func sha3_256(_ data: Data) -> [UInt8] {
        var sponge = KeccakSponge(rate: 136, domainSuffix: 0x06)
        sponge.absorb(data)
        return sponge.squeeze(32)
    }
}

/// A Keccak sponge: absorb, pad once, then squeeze as much as is asked for.
///
/// A value type on purpose: copying it forks the output stream, which is how
/// the VMess reader peeks at the next mask without consuming it.
struct KeccakSponge {
    private var state = [UInt64](repeating: 0, count: 25)
    private let rate: Int
    private let domainSuffix: UInt8
    private var position = 0
    private var squeezing = false

    init(rate: Int, domainSuffix: UInt8) {
        self.rate = rate
        self.domainSuffix = domainSuffix
    }

    mutating func absorb<S: Sequence>(_ bytes: S) where S.Element == UInt8 {
        precondition(!squeezing, "Keccak sponge absorbed after squeezing")
        for byte in bytes {
            let shift = UInt64((position & 7) * 8)
            state[position >> 3] ^= UInt64(byte) &<< shift
            position += 1
            if position == rate {
                Keccak.permute(&state)
                position = 0
            }
        }
    }

    mutating func squeeze(_ count: Int) -> [UInt8] {
        if !squeezing {
            let suffixShift = UInt64((position & 7) * 8)
            state[position >> 3] ^= UInt64(domainSuffix) &<< suffixShift
            let last = rate - 1
            let lastShift = UInt64((last & 7) * 8)
            state[last >> 3] ^= UInt64(0x80) &<< lastShift
            Keccak.permute(&state)
            position = 0
            squeezing = true
        }
        var out = [UInt8]()
        out.reserveCapacity(count)
        for _ in 0..<count {
            if position == rate {
                Keccak.permute(&state)
                position = 0
            }
            let shift = UInt64((position & 7) * 8)
            out.append(UInt8(truncatingIfNeeded: state[position >> 3] &>> shift))
            position += 1
        }
        return out
    }
}

/// SHAKE128 (FIPS 202): an extendable-output function read in arbitrary
/// pieces. Squeezing 2 bytes twice yields the same 4 bytes as squeezing 4.
struct Shake128 {
    private var sponge = KeccakSponge(rate: 168, domainSuffix: 0x1F)

    init() {}

    init(seed: Data) {
        sponge.absorb(seed)
    }

    mutating func absorb(_ data: Data) {
        sponge.absorb(data)
    }

    mutating func squeeze(_ count: Int) -> [UInt8] {
        return sponge.squeeze(count)
    }
}
