import CryptoKit
import Foundation

/// The primitives WireGuard's Noise_IKpsk2 handshake is built from.
///
/// BLAKE2s rather than SHA-256, ChaCha20-Poly1305 rather than AES-GCM, and
/// X25519 — the protocol fixes all three, so none of this is negotiable and
/// there is nothing to choose at runtime. CryptoKit has X25519 and
/// ChaCha20-Poly1305 but no BLAKE2s, which is `Blake2s`.
enum WireGuardCrypto {
    static let keySize = 32
    static let hashSize = 32
    static let macSize = 16
    static let tagSize = 16

    // MARK: - BLAKE2s

    /// BLAKE2s-256 of the concatenation of `parts`.
    static func hash(_ parts: [UInt8]...) -> [UInt8] {
        var hasher = Blake2s(outputLength: hashSize)
        for part in parts {
            hasher.update(part)
        }
        return hasher.finalize()
    }

    /// BLAKE2s keyed to `key`, at `length` bytes — WireGuard's MAC. The
    /// length goes into the hash, so this is not a truncated longer MAC.
    static func mac(key: [UInt8], data: [UInt8], length: Int = macSize) -> [UInt8] {
        Blake2s.hash(data, outputLength: length, key: key)
    }

    /// HMAC-BLAKE2s, which is what the KDF below is built on.
    static func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        Blake2s.hmac(key: key, data: data)
    }

    /// HKDF over HMAC-BLAKE2s, returning `count` keys of 32 bytes.
    ///
    /// The protocol needs the outputs one at a time (τ₁, τ₂, τ₃), and the
    /// chaining key it produces is fed straight back in as the next salt.
    static func kdf(_ chainingKey: [UInt8], _ input: [UInt8], count: Int) -> [[UInt8]] {
        precondition(count >= 1 && count <= 3, "WireGuard's KDF is only ever asked for 1 to 3 keys")
        return Blake2s.hkdf(salt: chainingKey, input: input, count: count)
    }

    // MARK: - X25519

    /// A fresh private key and its public key.
    static func generateKeyPair() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return ([UInt8](key.rawRepresentation), [UInt8](key.publicKey.rawRepresentation))
    }

    static func publicKey(_ privateKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == keySize else {
            throw MythaiaError.invalidConfiguration("a WireGuard private key is 32 bytes")
        }
        do {
            let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            return [UInt8](key.publicKey.rawRepresentation)
        } catch {
            throw MythaiaError.invalidConfiguration("the WireGuard private key is not usable")
        }
    }

    /// The X25519 shared secret.
    ///
    /// An all-zero result means a low-order public key, which the peer must not
    /// be able to force: accepting it would fix the secret to a value it also
    /// knows.
    static func sharedSecret(_ privateKey: [UInt8], _ peerPublicKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == keySize, peerPublicKey.count == keySize else {
            throw MythaiaError.protocolError("X25519 keys must be 32 bytes")
        }
        let secret: [UInt8]
        do {
            let local = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let shared = try local.sharedSecretFromKeyAgreement(with: peer)
            secret = shared.withUnsafeBytes { [UInt8]($0) }
        } catch {
            throw MythaiaError.protocolError("X25519 agreement failed")
        }
        if secret.count != keySize || secret.allSatisfy({ $0 == 0 }) {
            throw MythaiaError.protocolError("X25519 produced the all-zero point")
        }
        return secret
    }

    // MARK: - AEAD

    /// ChaCha20-Poly1305 with WireGuard's nonce: four zero bytes then the
    /// counter, little-endian.
    static func nonce(_ counter: UInt64) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 12)
        var value = counter
        for index in 4..<12 {
            out[index] = UInt8(truncatingIfNeeded: value)
            value >>= 8
        }
        return out
    }

    /// `ciphertext ‖ tag`.
    static func seal(key: [UInt8], counter: UInt64, plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        do {
            let box = try ChaChaPoly.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: ChaChaPoly.Nonce(data: nonce(counter)),
                authenticating: aad
            )
            return [UInt8](box.ciphertext) + [UInt8](box.tag)
        } catch {
            throw MythaiaError.protocolError("ChaCha20-Poly1305 seal failed")
        }
    }

    /// Nil when the tag does not verify — a wrong key, or a tampered message.
    static func open(key: [UInt8], counter: UInt64, ciphertext: [UInt8], aad: [UInt8]) -> [UInt8]? {
        openWithNonce(key: key, nonce: nonce(counter), ciphertext: ciphertext, aad: aad)
    }

    /// ChaCha20-Poly1305 with the nonce given outright.
    ///
    /// The handshake's own AEAD numbers its nonces from a counter, but the
    /// cookie reply carries a random one, so that path needs this form.
    static func openWithNonce(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard key.count == keySize, nonce.count == 12, ciphertext.count >= tagSize else { return nil }
        let cut = ciphertext.count - tagSize
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: nonce),
                ciphertext: Data(ciphertext[0..<cut]),
                tag: Data(ciphertext[cut...])
            )
            let plaintext = try ChaChaPoly.open(box, using: SymmetricKey(data: key), authenticating: aad)
            return [UInt8](plaintext)
        } catch {
            return nil
        }
    }

    /// XChaCha20-Poly1305, which is what a cookie reply is sealed with.
    ///
    /// The 24-byte nonce is split: the first 16 bytes derive a subkey through
    /// HChaCha20, and the last 8 become the low half of an ordinary 12-byte
    /// ChaCha20-Poly1305 nonce. Nil when the tag does not verify.
    static func xopen(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard key.count == keySize, nonce.count == 24 else { return nil }
        let subkey = XChaCha20Poly1305.hChaCha20(key: key, nonce: Array(nonce[0..<16]))
        var inner = [UInt8](repeating: 0, count: 4)
        inner.append(contentsOf: nonce[16..<24])
        return openWithNonce(key: subkey, nonce: inner, ciphertext: ciphertext, aad: aad)
    }

    // MARK: - Timestamp

    /// TAI64N, which is what WireGuard puts in the initiation message.
    ///
    /// The responder keeps the greatest timestamp it has seen from each peer and
    /// rejects anything not greater, which is what stops an initiation being
    /// replayed. Wall-clock time, not a monotonic clock, for that reason: it
    /// has to keep increasing across restarts of this client.
    static func tai64n(millis: Int64 = Int64((Date().timeIntervalSince1970 * 1000).rounded(.down))) -> [UInt8] {
        let seconds = millis / 1000
        let nanos = (millis % 1000) * 1_000_000

        var out = [UInt8](repeating: 0, count: 12)
        // 2^62 plus the Unix second count, big-endian; the 10 is TAI's offset.
        var value = UInt64(0x4000_0000_0000_000A) &+ UInt64(bitPattern: seconds)
        var index = 7
        while index >= 0 {
            out[index] = UInt8(truncatingIfNeeded: value)
            value >>= 8
            index -= 1
        }
        var n = UInt32(truncatingIfNeeded: nanos)
        index = 11
        while index >= 8 {
            out[index] = UInt8(truncatingIfNeeded: n)
            n >>= 8
            index -= 1
        }
        return out
    }

    /// `count` bytes from the system's cryptographic generator.
    static func randomBytes(_ count: Int) -> [UInt8] {
        [UInt8](CryptoRandom.bytes(count))
    }
}
