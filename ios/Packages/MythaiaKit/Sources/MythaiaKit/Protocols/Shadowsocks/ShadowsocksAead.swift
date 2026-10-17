import Foundation

enum ShadowsocksCipher: CaseIterable {
    case aes128Gcm
    case aes256Gcm
    case chacha20Poly1305
    /// `none` / `plain`: no encryption at all.
    case plain
    case blake3Aes128Gcm
    case blake3Aes256Gcm
    case blake3Chacha20Poly1305

    var keySize: Int {
        switch self {
        case .aes128Gcm, .blake3Aes128Gcm: return 16
        case .aes256Gcm, .chacha20Poly1305, .blake3Aes256Gcm, .blake3Chacha20Poly1305: return 32
        case .plain: return 0
        }
    }

    var isSS2022: Bool {
        switch self {
        case .blake3Aes128Gcm, .blake3Aes256Gcm, .blake3Chacha20Poly1305: return true
        default: return false
        }
    }

    var saltSize: Int { keySize }
    var tagSize: Int { self == .plain ? 0 : 16 }
    var nonceSize: Int { self == .plain ? 0 : 12 }

    var isChaCha: Bool {
        return self == .chacha20Poly1305 || self == .blake3Chacha20Poly1305
    }

    static func fromMethod(_ method: String) -> ShadowsocksCipher? {
        switch method.lowercased() {
        case "aes-128-gcm": return .aes128Gcm
        case "aes-256-gcm": return .aes256Gcm
        case "chacha20-ietf-poly1305", "chacha20-poly1305": return .chacha20Poly1305
        case "none", "plain": return .plain
        case "2022-blake3-aes-128-gcm": return .blake3Aes128Gcm
        case "2022-blake3-aes-256-gcm": return .blake3Aes256Gcm
        case "2022-blake3-chacha20-poly1305": return .blake3Chacha20Poly1305
        default: return nil
        }
    }
}

/// The errors Shadowsocks reports, as the messages a user sees.
enum ShadowsocksError {
    static func invalidMethod(_ method: String) -> MythaiaError {
        return .invalidConfiguration("Unsupported Shadowsocks method: \(method)")
    }

    static let decryptionFailed = MythaiaError.protocolError("Shadowsocks AEAD decryption failed")
    static let invalidAddress = MythaiaError.protocolError("Invalid Shadowsocks address header")
    static let badTimestamp = MythaiaError.protocolError("Shadowsocks 2022 bad timestamp")
    static let badRequestSalt = MythaiaError.protocolError("Shadowsocks 2022 bad request salt")
    static let badHeaderType = MythaiaError.protocolError("Shadowsocks 2022 bad header type")
    static let invalidPSK = MythaiaError.invalidConfiguration("Invalid Shadowsocks 2022 PSK")
}

enum ShadowsocksKeyDerivation {
    /// EVP_BytesToKey (MD5-based) master-key derivation from a password.
    static func deriveKey(password: String, keySize: Int) -> Data {
        if keySize <= 0 { return Data() }
        let pass = Data(password.utf8)
        var previous = Data()
        var result = Data()
        while result.count < keySize {
            var input = previous
            input.append(pass)
            previous = DigestHelper.md5(input)
            result.append(previous)
        }
        return Data(result.prefix(keySize))
    }

    /// HKDF-SHA1 subkey derivation with info = "ss-subkey".
    static func deriveSubkey(masterKey: Data, salt: Data, keySize: Int) -> Data {
        return HKDFHelper.sha1(
            inputKeyMaterial: masterKey,
            salt: salt,
            info: Data("ss-subkey".utf8),
            outputByteCount: keySize
        )
    }

    /// A base64 SS 2022 PSK. A colon-separated multi-PSK returns only the
    /// last entry (the client PSK).
    static func decodePSK(_ password: String, keySize: Int) -> Data? {
        guard let last = password.split(separator: ":", omittingEmptySubsequences: false).last else { return nil }
        guard let psk = decodeBase64(String(last)), psk.count == keySize else { return nil }
        return psk
    }

    /// Every colon-separated base64 PSK, for multi-user mode.
    static func decodePSKList(_ password: String, keySize: Int) -> [Data]? {
        var result = [Data]()
        for part in password.split(separator: ":", omittingEmptySubsequences: false) {
            guard let psk = decodeBase64(String(part)), psk.count == keySize else { return nil }
            result.append(psk)
        }
        return result.isEmpty ? nil : result
    }

    /// The first 16 bytes of BLAKE3(data): the identity header's pskHash.
    static func blake3Hash16(_ data: Data) -> Data {
        return Blake3.hash(data, outputLength: 16)
    }

    /// BLAKE3 derive_key with context "shadowsocks 2022 identity subkey", input = psk + salt.
    static func deriveIdentitySubkey(psk: Data, salt: Data, keySize: Int) -> Data {
        var material = psk
        material.append(salt)
        return Blake3.deriveKey(context: "shadowsocks 2022 identity subkey", material: material, outputLength: keySize)
    }

    /// BLAKE3 derive_key with context "shadowsocks 2022 session subkey", input = psk + salt.
    static func deriveSessionKey(psk: Data, salt: Data, keySize: Int) -> Data {
        var material = psk
        material.append(salt)
        return Blake3.deriveKey(context: "shadowsocks 2022 session subkey", material: material, outputLength: keySize)
    }

    private static func decodeBase64(_ text: String) -> Data? {
        var normalized = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: normalized)
    }
}

/// Incrementing AEAD nonce. Starts at all 0xFF so the first `next()` is all
/// zeros; increments little-endian on each call.
final class ShadowsocksNonce {
    private var bytes: [UInt8]

    init(size: Int) {
        bytes = [UInt8](repeating: 0xFF, count: size)
    }

    func next() -> Data {
        for i in 0..<bytes.count {
            bytes[i] = bytes[i] &+ 1
            if bytes[i] != 0 { break }
        }
        return Data(bytes)
    }
}

enum ShadowsocksAEADCrypto {
    static func seal(_ cipher: ShadowsocksCipher, key: Data, nonce: Data, plaintext: Data) throws -> Data {
        if cipher == .plain { return plaintext }
        if cipher.isChaCha {
            return try RawAEAD.chaChaPolySeal(key: key, nonce: nonce, plaintext: plaintext)
        }
        return try RawAEAD.aesGcmSeal(key: key, nonce: nonce, plaintext: plaintext)
    }

    static func open(_ cipher: ShadowsocksCipher, key: Data, nonce: Data, ciphertext: Data) throws -> Data {
        if cipher == .plain { return ciphertext }
        do {
            if cipher.isChaCha {
                return try RawAEAD.chaChaPolyOpen(key: key, nonce: nonce, sealed: ciphertext)
            }
            return try RawAEAD.aesGcmOpen(key: key, nonce: nonce, sealed: ciphertext)
        } catch {
            throw ShadowsocksError.decryptionFailed
        }
    }

    static func generateRandomSalt(_ size: Int) -> Data {
        return CryptoRandom.bytes(size)
    }
}

/// Encrypts data into Shadowsocks AEAD chunks.
///
/// Chunk: `[encrypted 2-byte length + 16-byte tag] [encrypted payload + 16-byte tag]`.
/// At most 0x3FFF (16,383) payload bytes per chunk. The salt goes in front of
/// the first output.
final class ShadowsocksAEADWriter {
    static let maxPayloadSize = 0x3FFF

    private let cipher: ShadowsocksCipher
    private let nonce: ShadowsocksNonce
    private let salt: Data
    private let subkey: Data
    private var saltWritten = false

    init(cipher: ShadowsocksCipher, masterKey: Data) {
        self.cipher = cipher
        self.nonce = ShadowsocksNonce(size: cipher.nonceSize)
        if cipher == .plain {
            salt = Data()
            subkey = Data()
        } else {
            salt = ShadowsocksAEADCrypto.generateRandomSalt(cipher.saltSize)
            subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey: masterKey, salt: salt, keySize: cipher.keySize)
        }
    }

    /// Prepends the salt on the first call; later calls emit chunks only.
    func seal(_ plaintext: Data) throws -> Data {
        if cipher == .plain { return plaintext }

        var output = Data()
        if !saltWritten {
            output.append(salt)
            saltWritten = true
        }

        let bytes = [UInt8](plaintext)
        var offset = 0
        while offset < bytes.count {
            let chunkSize = min(bytes.count - offset, ShadowsocksAEADWriter.maxPayloadSize)
            let chunk = Data(bytes[offset..<(offset + chunkSize)])
            let lengthBytes = Data([UInt8(truncatingIfNeeded: chunkSize >> 8), UInt8(truncatingIfNeeded: chunkSize)])
            output.append(try ShadowsocksAEADCrypto.seal(cipher, key: subkey, nonce: nonce.next(), plaintext: lengthBytes))
            output.append(try ShadowsocksAEADCrypto.seal(cipher, key: subkey, nonce: nonce.next(), plaintext: chunk))
            offset += chunkSize
        }
        return output
    }
}

/// Decrypts Shadowsocks AEAD chunks.
/// State machine: waiting for the salt → reading a length ⇄ reading a payload.
final class ShadowsocksAEADReader {
    private enum State {
        case waitingSalt
        case readingLength
        case readingPayload
    }

    /// Compaction waits until the dead space is significant, to avoid an
    /// O(n) shift on every read.
    private static let compactThreshold = 4096

    private let cipher: ShadowsocksCipher
    private let masterKey: Data
    private let nonce: ShadowsocksNonce
    private var subkey = Data()
    private var state: State
    private var buffer = [UInt8]()
    private var offset = 0
    private var pendingPayloadLength = 0

    init(cipher: ShadowsocksCipher, masterKey: Data) {
        self.cipher = cipher
        self.masterKey = masterKey
        self.nonce = ShadowsocksNonce(size: cipher.nonceSize)
        self.state = cipher == .plain ? .readingLength : .waitingSalt
    }

    func open(_ ciphertext: Data) throws -> Data {
        if cipher == .plain { return ciphertext }

        buffer.append(contentsOf: ciphertext)
        var output = Data()

        loop: while true {
            let remaining = buffer.count - offset
            switch state {
            case .waitingSalt:
                if remaining < cipher.saltSize { break loop }
                let salt = Data(buffer[offset..<(offset + cipher.saltSize)])
                offset += cipher.saltSize
                subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey: masterKey, salt: salt, keySize: cipher.keySize)
                state = .readingLength
            case .readingLength:
                let needed = 2 + cipher.tagSize
                if remaining < needed { break loop }
                let encrypted = Data(buffer[offset..<(offset + needed)])
                offset += needed
                let lengthData = [UInt8](try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: nonce.next(), ciphertext: encrypted))
                guard lengthData.count == 2 else { throw ShadowsocksError.decryptionFailed }
                pendingPayloadLength = (Int(lengthData[0]) << 8) | Int(lengthData[1])
                state = .readingPayload
            case .readingPayload:
                let needed = pendingPayloadLength + cipher.tagSize
                if remaining < needed { break loop }
                let encrypted = Data(buffer[offset..<(offset + needed)])
                offset += needed
                output.append(try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: nonce.next(), ciphertext: encrypted))
                state = .readingLength
            }
        }

        if offset > 0 && offset == buffer.count {
            buffer = []
            offset = 0
        } else if offset > ShadowsocksAEADReader.compactThreshold {
            buffer = Array(buffer[offset...])
            offset = 0
        }
        return output
    }
}

/// Per-packet AEAD for legacy Shadowsocks UDP: a fresh salt and one seal
/// under an all-zero nonce per datagram, no chunking.
enum ShadowsocksUDPCrypto {
    static func encrypt(_ cipher: ShadowsocksCipher, masterKey: Data, payload: Data) throws -> Data {
        if cipher == .plain { return payload }
        let salt = ShadowsocksAEADCrypto.generateRandomSalt(cipher.saltSize)
        let subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey: masterKey, salt: salt, keySize: cipher.keySize)
        let nonce = Data(count: cipher.nonceSize)
        var out = salt
        out.append(try ShadowsocksAEADCrypto.seal(cipher, key: subkey, nonce: nonce, plaintext: payload))
        return out
    }

    static func decrypt(_ cipher: ShadowsocksCipher, masterKey: Data, data: Data) throws -> Data {
        if cipher == .plain { return data }
        let bytes = [UInt8](data)
        guard bytes.count > cipher.saltSize + cipher.tagSize else {
            throw MythaiaError.protocolError("Shadowsocks UDP packet too short")
        }
        let salt = Data(bytes[0..<cipher.saltSize])
        let ciphertext = Data(bytes[cipher.saltSize...])
        let subkey = ShadowsocksKeyDerivation.deriveSubkey(masterKey: masterKey, salt: salt, keySize: cipher.keySize)
        let nonce = Data(count: cipher.nonceSize)
        return try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: nonce, ciphertext: ciphertext)
    }
}
