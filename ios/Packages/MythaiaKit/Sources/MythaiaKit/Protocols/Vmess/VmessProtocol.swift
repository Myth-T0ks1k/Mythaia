import Foundation

/// How the VMess body is encrypted.
enum VmessSecurity: String, CaseIterable {
    case aes128Gcm = "aes-128-gcm"
    case chacha20Poly1305 = "chacha20-poly1305"
    /// `none`: chunked but unencrypted.
    case plain = "none"
    case zero = "zero"

    var id: UInt8 {
        switch self {
        case .aes128Gcm: return 0x03
        case .chacha20Poly1305: return 0x04
        case .plain: return 0x05
        case .zero: return 0x06
        }
    }

    var displayName: String {
        switch self {
        case .aes128Gcm: return "AES-128-GCM"
        case .chacha20Poly1305: return "ChaCha20-Poly1305"
        case .plain: return "None"
        case .zero: return "Zero"
        }
    }

    /// `auto` is what most links and panels write; on every device this app
    /// runs on AES has hardware backing, so it resolves to AES-128-GCM.
    static func fromRaw(_ value: String?) -> VmessSecurity {
        guard let raw = value?.lowercased() else { return .aes128Gcm }
        switch raw {
        case "", "auto", "aes-128-gcm": return .aes128Gcm
        case "chacha20-poly1305", "chacha20-ietf-poly1305": return .chacha20Poly1305
        case "none": return .plain
        case "zero": return .zero
        default: return .aes128Gcm
        }
    }
}

/// The VMessAEAD request header and its sealing.
///
/// Only the AEAD form is implemented — `alterId` 0. The legacy
/// MD5-authenticated header with a non-zero alterId was deprecated by v2ray
/// in 2022 and is refused rather than half-supported.
enum VmessProtocol {
    static let version: UInt8 = 1

    // Request options.
    static let optionChunkStream = 0x01
    static let optionChunkMasking = 0x04
    static let optionGlobalPadding = 0x08

    static let commandTCP: UInt8 = 1
    static let commandUDP: UInt8 = 2

    private static let addressIPv4: UInt8 = 1
    private static let addressDomain: UInt8 = 2
    private static let addressIPv6: UInt8 = 3

    /// Everything the client must remember to read the reply.
    final class Session {
        let requestBodyKey: Data
        let requestBodyIv: Data
        let responseHeader: UInt8
        let security: VmessSecurity
        let option: Int
        /// The reply is keyed by the hash of the request's key and IV.
        let responseBodyKey: Data
        let responseBodyIv: Data

        init(requestBodyKey: Data, requestBodyIv: Data, responseHeader: UInt8, security: VmessSecurity, option: Int) {
            self.requestBodyKey = requestBodyKey
            self.requestBodyIv = requestBodyIv
            self.responseHeader = responseHeader
            self.security = security
            self.option = option
            self.responseBodyKey = Data(DigestHelper.sha256(requestBodyKey).prefix(16))
            self.responseBodyIv = Data(DigestHelper.sha256(requestBodyIv).prefix(16))
        }
    }

    struct SealedRequest {
        let bytes: Data
        let session: Session
    }

    /// Builds and seals a request header for `host`:`port`.
    ///
    /// The result is `authID ‖ encrypted length ‖ nonce ‖ encrypted header`,
    /// everything that goes on the wire before the first body chunk.
    static func sealRequest(id: UUID, host: String, port: UInt16, command: UInt8, security: VmessSecurity) throws -> SealedRequest {
        let commandKey = VmessKdf.commandKey(id)

        let bodyKey = CryptoRandom.bytes(16)
        let bodyIv = CryptoRandom.bytes(16)
        let responseHeader = CryptoRandom.byte()
        let option = optionsFor(security)

        let header = try buildHeader(
            bodyKey: bodyKey,
            bodyIv: bodyIv,
            responseHeader: responseHeader,
            option: option,
            security: security,
            command: command,
            host: host,
            port: port
        )
        let authId = try generateAuthId(commandKey: commandKey, time: Int64(Date().timeIntervalSince1970))
        let nonce = CryptoRandom.bytes(8)

        let lengthKey = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltHeaderLengthKey), authId, nonce)
        let lengthNonce = VmessKdf.kdf12(commandKey, VmessKdf.salt(VmessKdf.saltHeaderLengthIv), authId, nonce)
        let lengthPlain = Data([UInt8(truncatingIfNeeded: header.count >> 8), UInt8(truncatingIfNeeded: header.count)])
        let sealedLength = try aesGcmSeal(key: lengthKey, nonce: lengthNonce, plaintext: lengthPlain, aad: authId)

        let payloadKey = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltHeaderPayloadKey), authId, nonce)
        let payloadNonce = VmessKdf.kdf12(commandKey, VmessKdf.salt(VmessKdf.saltHeaderPayloadIv), authId, nonce)
        let sealedHeader = try aesGcmSeal(key: payloadKey, nonce: payloadNonce, plaintext: header, aad: authId)

        var out = authId
        out.append(sealedLength)
        out.append(nonce)
        out.append(sealedHeader)

        let session = Session(requestBodyKey: bodyKey, requestBodyIv: bodyIv, responseHeader: responseHeader, security: security, option: option)
        return SealedRequest(bytes: out, session: session)
    }

    /// The request options that go with `security`.
    ///
    /// Masking and global padding only make sense over an AEAD body: they act
    /// on the length prefix and the trailing bytes of a sealed chunk. With
    /// `none` the chunk carries the payload verbatim, so padding would be
    /// delivered to the destination as part of the stream.
    static func optionsFor(_ security: VmessSecurity) -> Int {
        switch security {
        case .aes128Gcm, .chacha20Poly1305:
            return optionChunkStream | optionChunkMasking | optionGlobalPadding
        case .plain, .zero:
            // Chunked, so lengths still frame the stream, but nothing is
            // added to the payload that the far side would have to strip.
            return optionChunkStream
        }
    }

    /// The 16-byte authentication ID: a timestamp and some randomness under a
    /// CRC32, encrypted with AES-128 in ECB — correct here and only here, as
    /// the plaintext is exactly one block.
    static func generateAuthId(commandKey: Data, time: Int64) throws -> Data {
        var plain = [UInt8](repeating: 0, count: 16)
        var t = UInt64(bitPattern: time)
        var i = 7
        while i >= 0 {
            plain[i] = UInt8(truncatingIfNeeded: t)
            t >>= 8
            i -= 1
        }
        let random = [UInt8](CryptoRandom.bytes(4))
        for j in 0..<4 {
            plain[8 + j] = random[j]
        }
        let crc = CRC32Checksum.compute(plain[0..<12])
        plain[12] = UInt8(truncatingIfNeeded: crc >> 24)
        plain[13] = UInt8(truncatingIfNeeded: crc >> 16)
        plain[14] = UInt8(truncatingIfNeeded: crc >> 8)
        plain[15] = UInt8(truncatingIfNeeded: crc)

        let key = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltAuthIdEncryption))
        return try AesEcb.encrypt(key: key, block: Data(plain))
    }

    /// The plaintext header, FNV-1a checksum included.
    static func buildHeader(
        bodyKey: Data,
        bodyIv: Data,
        responseHeader: UInt8,
        option: Int,
        security: VmessSecurity,
        command: UInt8,
        host: String,
        port: UInt16
    ) throws -> Data {
        var out = [UInt8]()
        out.reserveCapacity(64)
        out.append(version)
        out.append(contentsOf: bodyIv)
        out.append(contentsOf: bodyKey)
        out.append(responseHeader)
        out.append(UInt8(truncatingIfNeeded: option))

        // High nibble is the padding length, low nibble the cipher.
        let paddingLength = CryptoRandom.int(below: 16)
        out.append(UInt8(truncatingIfNeeded: paddingLength << 4) | security.id)
        out.append(0) // reserved
        out.append(command)
        out.append(contentsOf: ProtocolAddress.portBytes(port))

        try appendAddress(&out, host: host)

        if paddingLength > 0 {
            out.append(contentsOf: CryptoRandom.bytes(paddingLength))
        }

        let checksum = FNV1a.hash32(out)
        out.append(UInt8(truncatingIfNeeded: checksum >> 24))
        out.append(UInt8(truncatingIfNeeded: checksum >> 16))
        out.append(UInt8(truncatingIfNeeded: checksum >> 8))
        out.append(UInt8(truncatingIfNeeded: checksum))
        return Data(out)
    }

    /// The destination, as a literal address when it is one and as a name
    /// otherwise. A name is never resolved here: the point of sending it is
    /// to let the server resolve it on its own side.
    private static func appendAddress(_ out: inout [UInt8], host: String) throws {
        if let v4 = ProtocolAddress.ipv4(host) {
            out.append(addressIPv4)
            out.append(contentsOf: v4)
        } else if let v6 = ProtocolAddress.ipv6(host) {
            out.append(addressIPv6)
            out.append(contentsOf: v6)
        } else {
            let name = Array(host.utf8)
            if name.isEmpty || name.count > 255 {
                throw MythaiaError.protocolError("VMess: destination name is not addressable")
            }
            out.append(addressDomain)
            out.append(UInt8(name.count))
            out.append(contentsOf: name)
        }
    }

    /// Reads the sealed reply header and checks it answers our request.
    /// Returns the bytes consumed, or -1 when more input is needed.
    static func openResponseHeader(_ session: Session, _ input: [UInt8]) throws -> Int {
        // 2 bytes of length plus the GCM tag.
        if input.count < 18 { return -1 }
        let lengthKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderLenKey))
        let lengthNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderLenIv))
        guard let lengthPlain = aesGcmOpen(key: lengthKey, nonce: lengthNonce, ciphertext: Data(input[0..<18]), aad: nil),
              lengthPlain.count == 2 else {
            throw MythaiaError.protocolError("VMess: response length failed authentication")
        }
        let lengthBytes = [UInt8](lengthPlain)
        let headerLength = (Int(lengthBytes[0]) << 8) | Int(lengthBytes[1])

        let total = 18 + headerLength + 16
        if input.count < total { return -1 }

        let payloadKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadKey))
        let payloadNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadIv))
        guard let header = aesGcmOpen(key: payloadKey, nonce: payloadNonce, ciphertext: Data(input[18..<total]), aad: nil) else {
            throw MythaiaError.protocolError("VMess: response header failed authentication")
        }
        let headerBytes = [UInt8](header)
        if headerBytes.isEmpty || headerBytes[0] != session.responseHeader {
            throw MythaiaError.protocolError("VMess: response header does not match the request")
        }
        // headerBytes[1] is an option byte and the rest a dynamic-port command
        // we do not act on; the server is free to send it and we skip it whole.
        return total
    }

    // MARK: - AEAD helpers

    static func aesGcmSeal(key: Data, nonce: Data, plaintext: Data, aad: Data?) throws -> Data {
        return try RawAEAD.aesGcmSeal(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
    }

    /// Nil when the tag does not verify — a wrong key, or a tampered message.
    static func aesGcmOpen(key: Data, nonce: Data, ciphertext: Data, aad: Data?) -> Data? {
        return try? RawAEAD.aesGcmOpen(key: key, nonce: nonce, sealed: ciphertext, aad: aad)
    }
}
