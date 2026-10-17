import CommonCrypto
import CryptoKit
import Foundation
import Security

/// AES-GCM and ChaCha20-Poly1305 with the raw 12-byte nonces and 16-byte tags
/// the proxy protocols put on the wire.
///
/// CryptoKit hands back sealed boxes; the protocols want `ciphertext ‖ tag`
/// (Shadowsocks, VMess) or the two apart, and a nonce they count themselves.
/// Every failure, a wrong tag above all, comes out as a `MythaiaError`.
enum RawAEAD {
    static let tagLength = 16

    // MARK: - AES-GCM

    /// `ciphertext ‖ tag`. The key length picks AES-128 or AES-256.
    static func aesGcmSeal(key: Data, nonce: Data, plaintext: Data, aad: Data? = nil) throws -> Data {
        let sealed = try aesGcmSealDetached(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        var out = sealed.ciphertext
        out.append(sealed.tag)
        return out
    }

    static func aesGcmSealDetached(key: Data, nonce: Data, plaintext: Data, aad: Data? = nil) throws -> (ciphertext: Data, tag: Data) {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let box: AES.GCM.SealedBox
            if let aad = aad {
                box = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce, authenticating: aad)
            } else {
                box = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce)
            }
            return (Data(box.ciphertext), Data(box.tag))
        } catch {
            throw MythaiaError.protocolError("AES-GCM seal failed")
        }
    }

    /// Opens `ciphertext ‖ tag`.
    static func aesGcmOpen(key: Data, nonce: Data, sealed: Data, aad: Data? = nil) throws -> Data {
        let parts = try split(sealed)
        return try aesGcmOpenDetached(key: key, nonce: nonce, ciphertext: parts.ciphertext, tag: parts.tag, aad: aad)
    }

    static func aesGcmOpenDetached(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data? = nil) throws -> Data {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
            if let aad = aad {
                return try AES.GCM.open(box, using: symmetricKey, authenticating: aad)
            }
            return try AES.GCM.open(box, using: symmetricKey)
        } catch {
            throw MythaiaError.protocolError("AES-GCM authentication failed")
        }
    }

    // MARK: - ChaCha20-Poly1305

    static func chaChaPolySeal(key: Data, nonce: Data, plaintext: Data, aad: Data? = nil) throws -> Data {
        let sealed = try chaChaPolySealDetached(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        var out = sealed.ciphertext
        out.append(sealed.tag)
        return out
    }

    static func chaChaPolySealDetached(key: Data, nonce: Data, plaintext: Data, aad: Data? = nil) throws -> (ciphertext: Data, tag: Data) {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let box: ChaChaPoly.SealedBox
            if let aad = aad {
                box = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: chachaNonce, authenticating: aad)
            } else {
                box = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: chachaNonce)
            }
            return (Data(box.ciphertext), Data(box.tag))
        } catch {
            throw MythaiaError.protocolError("ChaCha20-Poly1305 seal failed")
        }
    }

    static func chaChaPolyOpen(key: Data, nonce: Data, sealed: Data, aad: Data? = nil) throws -> Data {
        let parts = try split(sealed)
        return try chaChaPolyOpenDetached(key: key, nonce: nonce, ciphertext: parts.ciphertext, tag: parts.tag, aad: aad)
    }

    static func chaChaPolyOpenDetached(key: Data, nonce: Data, ciphertext: Data, tag: Data, aad: Data? = nil) throws -> Data {
        do {
            let symmetricKey = SymmetricKey(data: key)
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ciphertext, tag: tag)
            if let aad = aad {
                return try ChaChaPoly.open(box, using: symmetricKey, authenticating: aad)
            }
            return try ChaChaPoly.open(box, using: symmetricKey)
        } catch {
            throw MythaiaError.protocolError("ChaCha20-Poly1305 authentication failed")
        }
    }

    private static func split(_ sealed: Data) throws -> (ciphertext: Data, tag: Data) {
        let bytes = [UInt8](sealed)
        guard bytes.count >= tagLength else {
            throw MythaiaError.protocolError("sealed data shorter than its tag")
        }
        let cut = bytes.count - tagLength
        return (Data(bytes[0..<cut]), Data(bytes[cut...]))
    }
}

/// HKDF (RFC 5869) over CryptoKit, with the output as plain bytes.
enum HKDFHelper {
    /// HKDF-SHA1: legacy Shadowsocks AEAD derives its per-connection subkey with it.
    static func sha1(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> Data {
        let key = HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
        return key.withUnsafeBytes { Data($0) }
    }

    static func sha256(inputKeyMaterial: Data, salt: Data, info: Data, outputByteCount: Int) -> Data {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: inputKeyMaterial),
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
        return key.withUnsafeBytes { Data($0) }
    }
}

/// Single-block AES in ECB mode.
///
/// ECB is correct here and only here: Shadowsocks 2022 identity headers and
/// the VMess authentication ID are each exactly one block, so there is no
/// second block for a chaining mode to chain to, and any mode would change
/// the bytes on the wire.
enum AesEcb {
    static func encrypt(key: Data, block: Data) throws -> Data {
        return try run(CCOperation(kCCEncrypt), key: key, block: block)
    }

    static func decrypt(key: Data, block: Data) throws -> Data {
        return try run(CCOperation(kCCDecrypt), key: key, block: block)
    }

    private static func run(_ operation: CCOperation, key: Data, block: Data) throws -> Data {
        let keyBytes = [UInt8](key)
        let input = [UInt8](block)
        guard input.count == kCCBlockSizeAES128 else {
            throw MythaiaError.protocolError("AES block must be 16 bytes")
        }
        guard keyBytes.count == kCCKeySizeAES128 || keyBytes.count == kCCKeySizeAES192 || keyBytes.count == kCCKeySizeAES256 else {
            throw MythaiaError.protocolError("AES key has an invalid length")
        }
        var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var moved = 0
        let status = CCCrypt(
            operation,
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode),
            keyBytes,
            keyBytes.count,
            nil,
            input,
            input.count,
            &output,
            outputCapacity,
            &moved
        )
        guard status == CCCryptorStatus(kCCSuccess), moved == kCCBlockSizeAES128 else {
            throw MythaiaError.protocolError("AES block operation failed")
        }
        return Data(output[0..<kCCBlockSizeAES128])
    }
}

/// The plain digests the protocols name, including the ones CryptoKit lacks
/// (SHA-224, which Trojan hashes its password with).
enum DigestHelper {
    static func md5(_ data: Data) -> Data {
        return Data(Insecure.MD5.hash(data: data))
    }

    static func sha1(_ data: Data) -> Data {
        return Data(Insecure.SHA1.hash(data: data))
    }

    static func sha224(_ data: Data) -> Data {
        let input = [UInt8](data)
        var output = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        _ = CC_SHA224(input, CC_LONG(input.count), &output)
        return Data(output)
    }

    static func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }
}

/// Bytes and numbers from the system's cryptographic generator.
enum CryptoRandom {
    static func bytes(_ count: Int) -> Data {
        guard count > 0 else { return Data() }
        var out = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &out)
        if status != errSecSuccess {
            var generator = SystemRandomNumberGenerator()
            for i in 0..<count {
                out[i] = UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            }
        }
        return Data(out)
    }

    /// A uniform value in `0..<bound`; 0 when the bound is not positive.
    static func int(below bound: Int) -> Int {
        guard bound > 0 else { return 0 }
        return Int.random(in: 0..<bound)
    }

    static func byte() -> UInt8 {
        return UInt8.random(in: UInt8.min...UInt8.max)
    }
}
