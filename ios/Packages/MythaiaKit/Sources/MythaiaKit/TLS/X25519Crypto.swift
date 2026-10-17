import CryptoKit
import Foundation

/// X25519 Diffie-Hellman (RFC 7748) on CryptoKit.
enum X25519Crypto {

    /// A fresh key pair: the 32-byte private scalar and the 32-byte public key.
    static func generateKeyPair() -> (privateKey: [UInt8], publicKey: [UInt8]) {
        let key = Curve25519.KeyAgreement.PrivateKey()
        return (Array(key.rawRepresentation), Array(key.publicKey.rawRepresentation))
    }

    /// The 32-byte shared secret.
    ///
    /// An all-zero result means the peer sent a low-order point; it is
    /// refused, since every party on the path could compute the same value.
    static func keyAgreement(privateKey: [UInt8], peerPublicKey: [UInt8]) throws -> [UInt8] {
        guard privateKey.count == 32 else {
            throw MythaiaError.tls("X25519 private key must be 32 bytes")
        }
        let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        return try agree(key, peerPublicKey: peerPublicKey)
    }

    static func agree(_ key: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: [UInt8]) throws -> [UInt8] {
        guard peerPublicKey.count == 32 else {
            throw MythaiaError.tls("X25519 public key must be 32 bytes")
        }
        let peer: Curve25519.KeyAgreement.PublicKey
        let secret: SharedSecret
        do {
            peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            secret = try key.sharedSecretFromKeyAgreement(with: peer)
        } catch {
            throw MythaiaError.tls("X25519 key agreement failed")
        }
        let shared = secret.withUnsafeBytes { Array($0) }
        var accumulator: UInt8 = 0
        for byte in shared { accumulator |= byte }
        if accumulator == 0 {
            throw MythaiaError.tls("X25519 key agreement failed (low-order point)")
        }
        return shared
    }
}

/// One ephemeral key a ClientHello offers in key_share, and the agreement it
/// makes with the server's share of the same group.
///
/// X25519 is what every fingerprint offers. The NIST curves are here for the
/// Firefox profiles, which also send a P-256 share, and for a server that
/// answers with a HelloRetryRequest for a curve it prefers. X25519MLKEM768
/// is not: CryptoKit gains ML-KEM only in iOS 26, so the hybrid share is
/// never offered.
enum TLSKeyShare {
    case x25519(Curve25519.KeyAgreement.PrivateKey)
    case p256(P256.KeyAgreement.PrivateKey)
    case p384(P384.KeyAgreement.PrivateKey)
    case p521(P521.KeyAgreement.PrivateKey)

    static let groupX25519 = 0x001D
    static let groupSecp256r1 = 0x0017
    static let groupSecp384r1 = 0x0018
    static let groupSecp521r1 = 0x0019

    /// A fresh key for `group`, or nil for a group this client cannot do.
    static func generate(group: Int) -> TLSKeyShare? {
        switch group {
        case groupX25519: return .x25519(Curve25519.KeyAgreement.PrivateKey())
        case groupSecp256r1: return .p256(P256.KeyAgreement.PrivateKey())
        case groupSecp384r1: return .p384(P384.KeyAgreement.PrivateKey())
        case groupSecp521r1: return .p521(P521.KeyAgreement.PrivateKey())
        default: return nil
        }
    }

    var group: Int {
        switch self {
        case .x25519: return TLSKeyShare.groupX25519
        case .p256: return TLSKeyShare.groupSecp256r1
        case .p384: return TLSKeyShare.groupSecp384r1
        case .p521: return TLSKeyShare.groupSecp521r1
        }
    }

    /// The key_share bytes: 32 raw bytes for X25519, the uncompressed point
    /// (0x04 || x || y) for the NIST curves.
    var publicKey: [UInt8] {
        switch self {
        case .x25519(let key): return Array(key.publicKey.rawRepresentation)
        case .p256(let key): return Array(key.publicKey.x963Representation)
        case .p384(let key): return Array(key.publicKey.x963Representation)
        case .p521(let key): return Array(key.publicKey.x963Representation)
        }
    }

    /// The (EC)DHE shared secret with the server's share; for the NIST curves
    /// that is the x-coordinate, as TLS 1.3 uses it (RFC 8446 §7.4.2).
    func sharedSecret(peer: [UInt8]) throws -> [UInt8] {
        switch self {
        case .x25519(let key):
            return try X25519Crypto.agree(key, peerPublicKey: peer)
        case .p256(let key):
            do {
                let peerKey = try P256.KeyAgreement.PublicKey(x963Representation: peer)
                let secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
                return secret.withUnsafeBytes { Array($0) }
            } catch {
                throw MythaiaError.tls("P-256 key agreement failed")
            }
        case .p384(let key):
            do {
                let peerKey = try P384.KeyAgreement.PublicKey(x963Representation: peer)
                let secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
                return secret.withUnsafeBytes { Array($0) }
            } catch {
                throw MythaiaError.tls("P-384 key agreement failed")
            }
        case .p521(let key):
            do {
                let peerKey = try P521.KeyAgreement.PublicKey(x963Representation: peer)
                let secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
                return secret.withUnsafeBytes { Array($0) }
            } catch {
                throw MythaiaError.tls("P-521 key agreement failed")
            }
        }
    }
}
