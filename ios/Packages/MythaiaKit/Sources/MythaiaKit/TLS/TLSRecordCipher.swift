import CryptoKit
import Foundation

/// One direction of TLS 1.3 record protection (RFC 8446 §5.2-5.4): the AEAD,
/// its key and IV, and the sequence number that feeds the nonce.
///
/// The sequence number counts records this direction actually sealed or
/// opened; a record that fails to open does not consume one.
struct TLSRecordCipher {
    /// The most plaintext one record may carry (RFC 8446 §5.1).
    static let maxPlaintext = 16384

    let aead: TLSAEAD
    private let key: SymmetricKey
    private let iv: [UInt8]
    private(set) var sequence: UInt64 = 0

    init(suite: Tls13Suite, key: [UInt8], iv: [UInt8]) {
        self.aead = suite.aead
        self.key = SymmetricKey(data: key)
        self.iv = iv
    }

    init(suite: Tls13Suite, trafficSecret: [UInt8]) {
        let derived = Tls13Crypto.trafficKeys(suite, secret: trafficSecret)
        self.init(suite: suite, key: derived.key, iv: derived.iv)
    }

    /// A complete record: the outer header says application_data, and the
    /// real content type travels encrypted after the content.
    mutating func seal(_ content: [UInt8], contentType: UInt8) throws -> [UInt8] {
        var inner = content
        inner.append(contentType)
        let sealedLength = inner.count + TLSAEAD.tagLength
        var header: [UInt8] = [0x17, 0x03, 0x03]
        header.append(contentsOf: TLSWire.u16Bytes(sealedLength))
        let nonce = TLSWire.xorNonce(iv, sequence)
        let sealed = try aead.seal(key: key, nonce: nonce, plaintext: inner, aad: header)
        sequence += 1
        return header + sealed
    }

    /// Opens one record and splits off its inner content type, after the
    /// zero padding a sender may add behind it.
    mutating func open(header: [UInt8], body: [UInt8]) throws -> (contentType: UInt8, content: [UInt8]) {
        if body.count < TLSAEAD.tagLength {
            throw MythaiaError.tls("ciphertext too short")
        }
        let nonce = TLSWire.xorNonce(iv, sequence)
        let plaintext = try aead.open(key: key, nonce: nonce, ciphertextAndTag: body, aad: header)
        sequence += 1
        var end = plaintext.count - 1
        while end >= 0 && plaintext[end] == 0 {
            end -= 1
        }
        if end < 0 {
            throw MythaiaError.tls("record has no content type")
        }
        return (plaintext[end], Array(plaintext[0..<end]))
    }
}
