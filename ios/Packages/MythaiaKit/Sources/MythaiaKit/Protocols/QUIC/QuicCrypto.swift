import CryptoKit
import Foundation

/// QUIC packet protection: the three AEADs RFC 9001 allows, and the nonce each
/// packet is sealed under.
///
/// A QUIC packet is not protected the way a TLS record is. There is no explicit
/// nonce on the wire — the packet number is the nonce, exclusive-ORed into a
/// per-direction IV — and the associated data is the packet header itself, so
/// anything a middlebox rewrites in the header breaks authentication rather
/// than being silently accepted.
///
/// The live tunnel does not go through here: ngtcp2 is built against mbedTLS
/// and seals and opens packets in C, which is what the traffic secrets are
/// handed to. This is the same computation written independently on CryptoKit,
/// so that packet protection can be checked against published test vectors.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
enum QuicCrypto {
    /// Every AEAD QUIC may use has a 16-byte tag (RFC 9001 §5.3), so a sealed
    /// payload is always sixteen bytes longer than what went in.
    static let tagLength = 16

    /// RFC 9001 §5.1 fixes the nonce at the larger of 8 and the AEAD's
    /// minimum, which is 12 for all three suites.
    static let nonceLength = 12

    /// The AEADs a QUIC connection can end up using, one per TLS 1.3 cipher
    /// suite RFC 9001 §5.3 permits. AES-128-CCM is deliberately absent: no
    /// server this client talks to offers it.
    enum Aead: CaseIterable {
        case aes128Gcm
        case aes256Gcm
        case chacha20Poly1305

        var keyLength: Int {
            switch self {
            case .aes128Gcm: return 16
            case .aes256Gcm, .chacha20Poly1305: return 32
            }
        }
    }

    /// The nonce for one packet, per RFC 9001 §5.3: the packet number,
    /// big-endian and left-padded to the width of `iv`, exclusive-ORed with
    /// it. Only the trailing eight bytes of the IV can ever change, which is
    /// what makes an eight-byte IV the shortest QUIC allows.
    ///
    /// `packetNumber` is the full reconstructed number, not the truncated form
    /// from the header; the truncated one would agree with the peer only until
    /// the first wrap.
    static func nonce(iv: [UInt8], packetNumber: Int64) throws -> [UInt8] {
        guard iv.count >= 8 else {
            throw MythaiaError.invalidConfiguration("a QUIC IV is at least 8 bytes, got \(iv.count)")
        }
        guard packetNumber >= 0 else {
            throw MythaiaError.invalidConfiguration("packet numbers are 62-bit and non-negative: \(packetNumber)")
        }
        var out = iv
        for index in 0..<8 {
            let position = out.count - 1 - index
            out[position] ^= UInt8(truncatingIfNeeded: packetNumber >> Int64(index * 8))
        }
        return out
    }

    /// Ciphertext followed by the 16-byte tag, the layout QUIC puts on the
    /// wire. A key or nonce of the wrong length is this side's bug and throws.
    static func seal(_ aead: Aead, key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        try checkKeyAndNonce(aead, key: key, nonce: nonce)
        let symmetricKey = SymmetricKey(data: key)
        switch aead {
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(plaintext, using: symmetricKey,
                                          nonce: try ChaChaPoly.Nonce(data: nonce), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        case .aes128Gcm, .aes256Gcm:
            let box = try AES.GCM.seal(plaintext, using: symmetricKey,
                                       nonce: try AES.GCM.Nonce(data: nonce), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        }
    }

    /// Opens what `seal` produced, or nil when it does not authenticate.
    ///
    /// Nil rather than an error because a packet that fails to open is
    /// ordinary: QUIC endpoints receive stray, replayed and injected
    /// datagrams, and RFC 9001 §5.2 says an unprotectable packet is
    /// discarded. A wrong key or nonce length, by contrast, throws.
    static func open(_ aead: Aead, key: [UInt8], nonce: [UInt8], sealed: [UInt8], aad: [UInt8]) throws -> [UInt8]? {
        try checkKeyAndNonce(aead, key: key, nonce: nonce)
        if sealed.count < tagLength { return nil }
        let split = sealed.count - tagLength
        let ciphertext = Array(sealed[0..<split])
        let tag = Array(sealed[split...])
        let symmetricKey = SymmetricKey(data: key)
        do {
            switch aead {
            case .chacha20Poly1305:
                let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return Array(try ChaChaPoly.open(box, using: symmetricKey, authenticating: aad))
            case .aes128Gcm, .aes256Gcm:
                let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
                return Array(try AES.GCM.open(box, using: symmetricKey, authenticating: aad))
            }
        } catch {
            return nil
        }
    }

    private static func checkKeyAndNonce(_ aead: Aead, key: [UInt8], nonce: [UInt8]) throws {
        guard key.count == aead.keyLength else {
            throw MythaiaError.invalidConfiguration("\(aead) takes a \(aead.keyLength)-byte key, got \(key.count)")
        }
        guard nonce.count == nonceLength else {
            throw MythaiaError.invalidConfiguration("a QUIC nonce is \(nonceLength) bytes, got \(nonce.count)")
        }
    }

    // MARK: - Initial secrets (RFC 9001 §5.2)

    /// The salt QUIC version 1 extracts its Initial secret with.
    static let initialSaltV1: [UInt8] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ]

    /// The client and server Initial secrets for a client-chosen destination
    /// connection id: HKDF-Extract over the salt, then the "client in" and
    /// "server in" labels, through the same key schedule the TLS client uses.
    /// ngtcp2 derives these itself in C; this is the Swift side's
    /// independent check that the labels are right.
    static func initialSecrets(destinationConnectionId: [UInt8]) -> (client: [UInt8], server: [UInt8]) {
        let initial = Tls13Crypto.hkdfExtract(.sha256, salt: initialSaltV1, ikm: destinationConnectionId)
        let client = Tls13Crypto.hkdfExpandLabel(.sha256, secret: initial, label: "client in", context: [], length: 32)
        let server = Tls13Crypto.hkdfExpandLabel(.sha256, secret: initial, label: "server in", context: [], length: 32)
        return (client, server)
    }

    /// The packet key, IV and header-protection key a traffic secret expands
    /// to under QUIC's own labels (RFC 9001 §5.1).
    static func packetProtectionKeys(secret: [UInt8], keyLength: Int, hash: TLSHash = .sha256)
        -> (key: [UInt8], iv: [UInt8], hp: [UInt8]) {
        let key = Tls13Crypto.hkdfExpandLabel(hash, secret: secret, label: "quic key", context: [], length: keyLength)
        let iv = Tls13Crypto.hkdfExpandLabel(hash, secret: secret, label: "quic iv", context: [], length: 12)
        let hp = Tls13Crypto.hkdfExpandLabel(hash, secret: secret, label: "quic hp", context: [], length: keyLength)
        return (key, iv, hp)
    }
}
