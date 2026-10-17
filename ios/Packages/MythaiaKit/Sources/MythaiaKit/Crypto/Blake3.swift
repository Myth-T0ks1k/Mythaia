import Foundation

/// BLAKE3 in the three modes the protocols use: the plain hash, the keyed
/// hash, and `derive_key`.
///
/// Shadowsocks 2022 derives every session key with `derive_key` and hashes the
/// identity PSKs with the plain hash; a key that differs from the server's by
/// one bit fails the first AEAD tag and looks like a dead server, so this is
/// pinned against the reference implementation's published vectors in the
/// tests. Outputs of any length are supported: BLAKE3 is an XOF and a shorter
/// output is a prefix of a longer one, which is how a 16-byte key is the first
/// half of the 32-byte derivation.
enum Blake3 {
    static let keyLength = 32

    static func hash(_ input: Data, outputLength: Int = 32) -> Data {
        var hasher = Blake3Hasher(keyWords: blake3IV, flags: 0)
        hasher.update([UInt8](input))
        return Data(hasher.finalize(outputLength))
    }

    /// Keyed hash; `key` must be exactly 32 bytes.
    static func keyedHash(key: Data, _ input: Data, outputLength: Int = 32) -> Data {
        precondition(key.count == keyLength, "BLAKE3 keys are 32 bytes")
        var hasher = Blake3Hasher(keyWords: blake3KeyWords([UInt8](key)), flags: blake3KeyedHash)
        hasher.update([UInt8](input))
        return Data(hasher.finalize(outputLength))
    }

    /// `derive_key`: the context is hashed to a context key, which then keys
    /// a hash of the key material. The context is raw bytes, not text, so
    /// callers whose context is binary need no re-encoding on the way in.
    static func deriveKey(context: Data, material: Data, outputLength: Int = 32) -> Data {
        var contextHasher = Blake3Hasher(keyWords: blake3IV, flags: blake3DeriveKeyContext)
        contextHasher.update([UInt8](context))
        let contextKey = contextHasher.finalize(keyLength)
        var hasher = Blake3Hasher(keyWords: blake3KeyWords(contextKey), flags: blake3DeriveKeyMaterial)
        hasher.update([UInt8](material))
        return Data(hasher.finalize(outputLength))
    }

    static func deriveKey(context: String, material: Data, outputLength: Int = 32) -> Data {
        return deriveKey(context: Data(context.utf8), material: material, outputLength: outputLength)
    }
}

private let blake3IV: [UInt32] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
]

private let blake3MessagePermutation: [Int] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

private let blake3ChunkStart: UInt32 = 1
private let blake3ChunkEnd: UInt32 = 2
private let blake3Parent: UInt32 = 4
private let blake3Root: UInt32 = 8
private let blake3KeyedHash: UInt32 = 16
private let blake3DeriveKeyContext: UInt32 = 32
private let blake3DeriveKeyMaterial: UInt32 = 64

private let blake3BlockLength = 64
private let blake3ChunkLength = 1024

@inline(__always)
private func blake3Rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
    return (x &>> n) | (x &<< (32 - n))
}

private func blake3G(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ mx: UInt32, _ my: UInt32) {
    s[a] = s[a] &+ s[b] &+ mx
    s[d] = blake3Rotr(s[d] ^ s[a], 16)
    s[c] = s[c] &+ s[d]
    s[b] = blake3Rotr(s[b] ^ s[c], 12)
    s[a] = s[a] &+ s[b] &+ my
    s[d] = blake3Rotr(s[d] ^ s[a], 8)
    s[c] = s[c] &+ s[d]
    s[b] = blake3Rotr(s[b] ^ s[c], 7)
}

private func blake3Compress(
    _ chainingValue: [UInt32],
    _ blockWords: [UInt32],
    _ counter: UInt64,
    _ blockLength: UInt32,
    _ flags: UInt32
) -> [UInt32] {
    var s = [UInt32](repeating: 0, count: 16)
    for i in 0..<8 {
        s[i] = chainingValue[i]
    }
    for i in 0..<4 {
        s[8 + i] = blake3IV[i]
    }
    s[12] = UInt32(truncatingIfNeeded: counter)
    s[13] = UInt32(truncatingIfNeeded: counter >> 32)
    s[14] = blockLength
    s[15] = flags

    var m = blockWords
    for round in 0..<7 {
        blake3G(&s, 0, 4, 8, 12, m[0], m[1])
        blake3G(&s, 1, 5, 9, 13, m[2], m[3])
        blake3G(&s, 2, 6, 10, 14, m[4], m[5])
        blake3G(&s, 3, 7, 11, 15, m[6], m[7])
        blake3G(&s, 0, 5, 10, 15, m[8], m[9])
        blake3G(&s, 1, 6, 11, 12, m[10], m[11])
        blake3G(&s, 2, 7, 8, 13, m[12], m[13])
        blake3G(&s, 3, 4, 9, 14, m[14], m[15])
        if round < 6 {
            var permuted = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 {
                permuted[i] = m[blake3MessagePermutation[i]]
            }
            m = permuted
        }
    }
    for i in 0..<8 {
        s[i] ^= s[i + 8]
        s[i + 8] ^= chainingValue[i]
    }
    return s
}

/// Sixteen little-endian words of a 64-byte block, zero padded.
private func blake3BlockWords(_ block: [UInt8]) -> [UInt32] {
    var words = [UInt32](repeating: 0, count: 16)
    for i in 0..<16 {
        var word: UInt32 = 0
        for j in 0..<4 {
            let index = i * 4 + j
            if index < block.count {
                word |= UInt32(block[index]) << UInt32(j * 8)
            }
        }
        words[i] = word
    }
    return words
}

private func blake3KeyWords(_ key: [UInt8]) -> [UInt32] {
    return Array(blake3BlockWords(key).prefix(8))
}

private struct Blake3Output {
    let inputChainingValue: [UInt32]
    let blockWords: [UInt32]
    let counter: UInt64
    let blockLength: UInt32
    let flags: UInt32

    func chainingValue() -> [UInt32] {
        let words = blake3Compress(inputChainingValue, blockWords, counter, blockLength, flags)
        return Array(words.prefix(8))
    }

    func rootBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(count)
        var outputBlock: UInt64 = 0
        while out.count < count {
            let words = blake3Compress(inputChainingValue, blockWords, outputBlock, blockLength, flags | blake3Root)
            for word in words {
                for shift in 0..<4 {
                    if out.count == count { break }
                    out.append(UInt8(truncatingIfNeeded: word >> UInt32(shift * 8)))
                }
            }
            outputBlock += 1
        }
        return out
    }
}

private struct Blake3ChunkState {
    var chainingValue: [UInt32]
    let chunkCounter: UInt64
    let flags: UInt32
    var block = [UInt8](repeating: 0, count: 64)
    var blockLength = 0
    var blocksCompressed = 0

    init(keyWords: [UInt32], chunkCounter: UInt64, flags: UInt32) {
        self.chainingValue = keyWords
        self.chunkCounter = chunkCounter
        self.flags = flags
    }

    var length: Int { blake3BlockLength * blocksCompressed + blockLength }

    var startFlag: UInt32 { blocksCompressed == 0 ? blake3ChunkStart : 0 }

    mutating func update(_ input: [UInt8], from: Int, to: Int) {
        var at = from
        while at < to {
            // A full block is compressed only once more input arrives: the
            // last block of a chunk has to carry CHUNK_END (and maybe ROOT).
            if blockLength == blake3BlockLength {
                let words = blake3BlockWords(block)
                let compressed = blake3Compress(chainingValue, words, chunkCounter, UInt32(blake3BlockLength), flags | startFlag)
                chainingValue = Array(compressed.prefix(8))
                blocksCompressed += 1
                block = [UInt8](repeating: 0, count: 64)
                blockLength = 0
            }
            let take = min(blake3BlockLength - blockLength, to - at)
            for i in 0..<take {
                block[blockLength + i] = input[at + i]
            }
            blockLength += take
            at += take
        }
    }

    func output() -> Blake3Output {
        return Blake3Output(
            inputChainingValue: chainingValue,
            blockWords: blake3BlockWords(block),
            counter: chunkCounter,
            blockLength: UInt32(blockLength),
            flags: flags | startFlag | blake3ChunkEnd
        )
    }
}

private struct Blake3Hasher {
    let keyWords: [UInt32]
    let flags: UInt32
    var chunk: Blake3ChunkState
    var chainingValueStack: [[UInt32]] = []

    init(keyWords: [UInt32], flags: UInt32) {
        self.keyWords = keyWords
        self.flags = flags
        self.chunk = Blake3ChunkState(keyWords: keyWords, chunkCounter: 0, flags: flags)
    }

    func parentOutput(_ left: [UInt32], _ right: [UInt32]) -> Blake3Output {
        return Blake3Output(
            inputChainingValue: keyWords,
            blockWords: left + right,
            counter: 0,
            blockLength: UInt32(blake3BlockLength),
            flags: blake3Parent | flags
        )
    }

    mutating func update(_ input: [UInt8]) {
        var at = 0
        while at < input.count {
            if chunk.length == blake3ChunkLength {
                var chainingValue = chunk.output().chainingValue()
                let nextCounter = chunk.chunkCounter + 1
                // Merge completed subtrees: one merge per trailing zero bit of
                // the number of chunks hashed so far.
                var totalChunks = nextCounter
                while totalChunks & 1 == 0 {
                    let left = chainingValueStack.removeLast()
                    chainingValue = parentOutput(left, chainingValue).chainingValue()
                    totalChunks >>= 1
                }
                chainingValueStack.append(chainingValue)
                chunk = Blake3ChunkState(keyWords: keyWords, chunkCounter: nextCounter, flags: flags)
            }
            let take = min(blake3ChunkLength - chunk.length, input.count - at)
            chunk.update(input, from: at, to: at + take)
            at += take
        }
    }

    func finalize(_ count: Int) -> [UInt8] {
        var output = chunk.output()
        var remaining = chainingValueStack.count
        while remaining > 0 {
            remaining -= 1
            output = parentOutput(chainingValueStack[remaining], output.chainingValue())
        }
        return output.rootBytes(count)
    }
}
