import CryptoKit
import Foundation

/// TLS 1.3 cipher suite codepoints (RFC 8446 §B.4).
///
/// The fingerprinted ClientHellos also list TLS 1.2 suites, because the
/// browsers they copy do; this client completes only a TLS 1.3 handshake, so
/// only these three are ever negotiated.
enum TlsCipherSuite {
    static let TLS_AES_128_GCM_SHA256 = 0x1301
    static let TLS_AES_256_GCM_SHA384 = 0x1302
    static let TLS_CHACHA20_POLY1305_SHA256 = 0x1303
}

/// The transcript hash a suite uses, with the HMAC built on it.
enum TLSHash {
    case sha256
    case sha384

    var length: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        }
    }

    func digest(_ data: [UInt8]) -> [UInt8] {
        switch self {
        case .sha256: return Array(SHA256.hash(data: data))
        case .sha384: return Array(SHA384.hash(data: data))
        }
    }

    func hmac(key: [UInt8], data: [UInt8]) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        switch self {
        case .sha256:
            let code = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
            return Array(code)
        case .sha384:
            let code = HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey)
            return Array(code)
        }
    }
}

/// The record cipher of a suite. Both are AEADs with a 16-byte tag and a
/// 12-byte nonce, which is all the record layer needs to know.
enum TLSAEAD {
    case aesGCM
    case chaChaPoly

    static let tagLength = 16

    /// Ciphertext followed by the tag.
    func seal(key: SymmetricKey, nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        switch self {
        case .aesGCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.seal(plaintext, using: key, nonce: gcmNonce, authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        case .chaChaPoly:
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaNonce, authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        }
    }

    /// Throws when the tag does not verify.
    func open(key: SymmetricKey, nonce: [UInt8], ciphertextAndTag: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let total = ciphertextAndTag.count
        if total < TLSAEAD.tagLength {
            throw MythaiaError.tls("ciphertext too short")
        }
        let split = total - TLSAEAD.tagLength
        let ciphertext = Array(ciphertextAndTag[0..<split])
        let tag = Array(ciphertextAndTag[split..<total])
        switch self {
        case .aesGCM:
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            return Array(try AES.GCM.open(box, using: key, authenticating: aad))
        case .chaChaPoly:
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ciphertext, tag: tag)
            return Array(try ChaChaPoly.open(box, using: key, authenticating: aad))
        }
    }
}

/// Everything the key schedule and the record layer need to know about a
/// negotiated TLS 1.3 suite.
struct Tls13Suite {
    let code: Int
    let hash: TLSHash
    let keyLength: Int
    let aead: TLSAEAD

    static func forCode(_ code: Int) -> Tls13Suite? {
        switch code {
        case TlsCipherSuite.TLS_AES_128_GCM_SHA256:
            return Tls13Suite(code: code, hash: .sha256, keyLength: 16, aead: .aesGCM)
        case TlsCipherSuite.TLS_AES_256_GCM_SHA384:
            return Tls13Suite(code: code, hash: .sha384, keyLength: 32, aead: .aesGCM)
        case TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
            return Tls13Suite(code: code, hash: .sha256, keyLength: 32, aead: .chaChaPoly)
        default:
            return nil
        }
    }
}
