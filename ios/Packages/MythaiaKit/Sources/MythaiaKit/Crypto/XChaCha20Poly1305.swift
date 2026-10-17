import Foundation

/// XChaCha20-Poly1305 as HChaCha20 + ChaCha20-Poly1305: the 24-byte nonce's
/// first 16 bytes derive a subkey, its last 8 (behind four zero bytes) are the
/// ChaCha20-Poly1305 nonce. Shadowsocks 2022's ChaCha UDP variant seals every
/// datagram with a random 24-byte nonce this way.
enum XChaCha20Poly1305 {
    static func seal(key: Data, nonce: Data, plaintext: Data) throws -> Data {
        let parts = try split(key: key, nonce: nonce)
        return try RawAEAD.chaChaPolySeal(key: parts.subkey, nonce: parts.nonce, plaintext: plaintext)
    }

    static func open(key: Data, nonce: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= RawAEAD.tagLength else {
            throw MythaiaError.protocolError("XChaCha20-Poly1305 input shorter than its tag")
        }
        let parts = try split(key: key, nonce: nonce)
        return try RawAEAD.chaChaPolyOpen(key: parts.subkey, nonce: parts.nonce, sealed: ciphertext)
    }

    private static func split(key: Data, nonce: Data) throws -> (subkey: Data, nonce: Data) {
        let keyBytes = [UInt8](key)
        let nonceBytes = [UInt8](nonce)
        guard keyBytes.count == 32, nonceBytes.count == 24 else {
            throw MythaiaError.protocolError("XChaCha20-Poly1305 needs a 32-byte key and a 24-byte nonce")
        }
        let subkey = hChaCha20(key: keyBytes, nonce: Array(nonceBytes[0..<16]))
        var chachaNonce = [UInt8](repeating: 0, count: 4)
        chachaNonce.append(contentsOf: nonceBytes[16..<24])
        return (Data(subkey), Data(chachaNonce))
    }

    /// Derives a 256-bit subkey from a 256-bit key and a 128-bit nonce.
    static func hChaCha20(key: [UInt8], nonce: [UInt8]) -> [UInt8] {
        var state = [UInt32](repeating: 0, count: 16)
        // "expand 32-byte k"
        state[0] = 0x6170_7865
        state[1] = 0x3320_646E
        state[2] = 0x7962_2D32
        state[3] = 0x6B20_6574
        for i in 0..<8 {
            state[4 + i] = readLittleEndian(key, i * 4)
        }
        for i in 0..<4 {
            state[12 + i] = readLittleEndian(nonce, i * 4)
        }

        // 20 rounds = 10 double rounds (column + diagonal).
        for _ in 0..<10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }

        // Output is words 0..3 and 12..15.
        var out = [UInt8]()
        out.reserveCapacity(32)
        for index in [0, 1, 2, 3, 12, 13, 14, 15] {
            let word = state[index]
            out.append(UInt8(truncatingIfNeeded: word))
            out.append(UInt8(truncatingIfNeeded: word >> 8))
            out.append(UInt8(truncatingIfNeeded: word >> 16))
            out.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return out
    }

    private static func readLittleEndian(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        var value = UInt32(bytes[offset])
        value |= UInt32(bytes[offset + 1]) << 8
        value |= UInt32(bytes[offset + 2]) << 16
        value |= UInt32(bytes[offset + 3]) << 24
        return value
    }

    private static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        return (x &<< n) | (x &>> (32 - n))
    }

    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]
        s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]
        s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b]
        s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]
        s[b] = rotl(s[b] ^ s[c], 7)
    }
}
