import CryptoKit
import Foundation

/// VMessAEAD's key-derivation function.
///
/// It is HMAC-SHA256 where the *hash* is itself an HMAC — each path element
/// keys another layer, innermost first. CryptoKit's HMAC takes a named hash
/// function, not another HMAC, so HMAC is written out here over a small hash
/// abstraction.
///
/// RFC 2104 with a 64-byte block throughout: SHA-256's block is 64, and an
/// HMAC-SHA256 used as a hash reports its underlying block size, so every
/// layer pads to 64 regardless of depth.
enum VmessKdf {
    private static let blockSize = 64

    /// The salt every derivation starts from.
    private static let rootSalt = "VMess AEAD KDF"

    static let saltAuthIdEncryption = "AES Auth ID Encryption"
    static let saltHeaderPayloadKey = "VMess Header AEAD Key"
    static let saltHeaderPayloadIv = "VMess Header AEAD Nonce"
    static let saltHeaderLengthKey = "VMess Header AEAD Key_Length"
    static let saltHeaderLengthIv = "VMess Header AEAD Nonce_Length"
    static let saltRespHeaderLenKey = "AEAD Resp Header Len Key"
    static let saltRespHeaderLenIv = "AEAD Resp Header Len IV"
    static let saltRespHeaderPayloadKey = "AEAD Resp Header Key"
    static let saltRespHeaderPayloadIv = "AEAD Resp Header IV"

    /// 32 bytes derived from `key` under `path`.
    ///
    /// The layers nest outward: the root salt keys the innermost HMAC, each
    /// path element keys one around it, and `key` is the message fed to the
    /// outermost. Path elements are raw bytes, not text: some of them — the
    /// auth ID, the connection nonce — are arbitrary binary, and putting them
    /// through a character encoding on the way in would change them.
    static func kdf(_ key: Data, path: [Data]) -> Data {
        let rootKey = Array(VmessKdf.rootSalt.utf8)
        var creator: () -> VmessKdfHasher = {
            VmessKdfHmacHasher(key: rootKey, inner: { VmessKdfSha256Hasher() })
        }
        for element in path {
            let parent = creator
            let elementBytes = [UInt8](element)
            creator = { VmessKdfHmacHasher(key: elementBytes, inner: parent) }
        }
        let hasher = creator()
        hasher.update([UInt8](key))
        return Data(hasher.digest())
    }

    static func kdf(_ key: Data, _ path: Data...) -> Data {
        return kdf(key, path: path)
    }

    /// The first 16 bytes of `kdf` — an AES-128 key.
    static func kdf16(_ key: Data, _ path: Data...) -> Data {
        return Data(kdf(key, path: path).prefix(16))
    }

    /// The first 12 bytes of `kdf` — a GCM nonce.
    static func kdf12(_ key: Data, _ path: Data...) -> Data {
        return Data(kdf(key, path: path).prefix(12))
    }

    /// A constant salt as the bytes the KDF wants.
    static func salt(_ text: String) -> Data {
        return Data(text.utf8)
    }

    /// The command key: MD5 of the user ID followed by VMess's fixed salt.
    ///
    /// MD5 is not a choice here; it is what the protocol specifies, and this
    /// value is a key derivation input rather than a security claim of its own.
    static func commandKey(_ id: UUID) -> Data {
        var input = uuidBytes(id)
        input.append(Data("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
        return DigestHelper.md5(input)
    }

    /// A UUID as its 16 big-endian bytes.
    static func uuidBytes(_ id: UUID) -> Data {
        var raw = id.uuid
        return withUnsafeBytes(of: &raw) { Data($0) }
    }

    /// FNV-1a, 32-bit — the checksum at the end of the request header.
    static func fnv1a32(_ data: Data) -> UInt32 {
        return FNV1a.hash32(data)
    }
}

/// A hash that can stand in for SHA-256 inside an outer HMAC.
private protocol VmessKdfHasher: AnyObject {
    func update(_ data: [UInt8])
    func digest() -> [UInt8]
}

private final class VmessKdfSha256Hasher: VmessKdfHasher {
    private var hasher = SHA256()

    func update(_ data: [UInt8]) {
        hasher.update(data: data)
    }

    func digest() -> [UInt8] {
        return Array(hasher.finalize())
    }
}

/// HMAC over `inner`, keyed by `key`. Itself usable as the hash of another.
private final class VmessKdfHmacHasher: VmessKdfHasher {
    private static let blockSize = 64

    private let inner: () -> VmessKdfHasher
    private let ipadHasher: VmessKdfHasher
    private let paddedKey: [UInt8]

    init(key: [UInt8], inner: @escaping () -> VmessKdfHasher) {
        self.inner = inner
        // A key longer than the block is hashed down first — by the enclosing
        // layer, not by SHA-256, which is what Go's hmac.New does with a
        // custom hash function — then padded with zeros to the full block.
        var normalised = key
        if key.count > VmessKdfHmacHasher.blockSize {
            let reducer = inner()
            reducer.update(key)
            normalised = reducer.digest()
        }
        var padded = [UInt8](repeating: 0, count: VmessKdfHmacHasher.blockSize)
        for i in 0..<normalised.count {
            padded[i] = normalised[i]
        }
        paddedKey = padded

        var ipad = [UInt8](repeating: 0, count: VmessKdfHmacHasher.blockSize)
        for i in 0..<VmessKdfHmacHasher.blockSize {
            ipad[i] = padded[i] ^ 0x36
        }
        let hasher = inner()
        hasher.update(ipad)
        ipadHasher = hasher
    }

    func update(_ data: [UInt8]) {
        ipadHasher.update(data)
    }

    func digest() -> [UInt8] {
        let innerDigest = ipadHasher.digest()
        var opad = [UInt8](repeating: 0, count: VmessKdfHmacHasher.blockSize)
        for i in 0..<VmessKdfHmacHasher.blockSize {
            opad[i] = paddedKey[i] ^ 0x5C
        }
        let outer = inner()
        outer.update(opad)
        outer.update(innerDigest)
        return outer.digest()
    }
}
