import Foundation

private let ss2022HeaderTypeClient: UInt8 = 0
private let ss2022HeaderTypeServer: UInt8 = 1
private let ss2022MaxPaddingLength = 900
private let ss2022MaxTimestampDifference: Int64 = 30
private let ss2022TagSize = 16

/// A Shadowsocks 2022 TCP stream.
///
/// Request: `salt + [identity headers] + seal(fixedHeader) + seal(variableHeader + payload) [+ AEAD chunks]`
/// Response: `salt + seal(fixedHeader) + seal(data) [+ AEAD chunks]`
final class Shadowsocks2022Connection: ByteStream, @unchecked Sendable {
    /// Compaction waits until the dead space is significant, to avoid an
    /// O(n) shift on every read.
    private static let compactThreshold = 4096

    private let inner: ByteStream
    private let cipher: ShadowsocksCipher
    private let pskList: [Data]
    private let psk: Data
    private let pskHashes: [Data]

    // Send side, under sendLock.
    private let sendLock = NSLock()
    private var addressHeader: Data?
    private var handshakeSent = false
    private var requestSalt: Data?
    private let writeNonce: ShadowsocksNonce
    private var writeSubkey: Data?

    // Receive side, under receiveLock (requestSalt is read under sendLock).
    private let receiveLock = NSLock()
    private let readNonce: ShadowsocksNonce
    private var readSubkey: Data?
    private var readBuffer = [UInt8]()
    private var readOffset = 0
    private var responseHeaderParsed = false
    private var pendingVariableHeaderLength: Int?
    private var pendingPayloadLength: Int?

    /// `pskList` is the colon-separated PSKs decoded, the client's last.
    init(_ inner: ByteStream, cipher: ShadowsocksCipher, pskList: [Data], addressHeader: Data) {
        precondition(!pskList.isEmpty, "Shadowsocks 2022 needs at least one PSK")
        self.inner = inner
        self.cipher = cipher
        self.pskList = pskList
        self.psk = pskList[pskList.count - 1]
        var hashes = [Data]()
        if pskList.count > 1 {
            for i in 1..<pskList.count {
                hashes.append(ShadowsocksKeyDerivation.blake3Hash16(pskList[i]))
            }
        }
        self.pskHashes = hashes
        self.addressHeader = addressHeader
        self.writeNonce = ShadowsocksNonce(size: cipher.nonceSize)
        self.readNonce = ShadowsocksNonce(size: cipher.nonceSize)
    }

    func send(_ data: Data) async throws {
        let output = try prepareSend(data)
        if output.isEmpty { return }
        try await inner.send(output)
    }

    func receive() async throws -> Data? {
        while true {
            guard let data = try await inner.receive() else { return nil }
            if data.isEmpty { continue }
            let plaintext = try processReceived(data)
            if !plaintext.isEmpty { return plaintext }
        }
    }

    func close() {
        inner.close()
    }

    // MARK: - Sending

    private func prepareSend(_ data: Data) throws -> Data {
        sendLock.lock()
        defer { sendLock.unlock() }
        if !handshakeSent {
            handshakeSent = true
            let header = addressHeader ?? Data()
            addressHeader = nil
            return try buildRequest([UInt8](data), addressHeader: [UInt8](header))
        }
        return try sealChunks([UInt8](data))
    }

    private func buildRequest(_ payload: [UInt8], addressHeader: [UInt8]) throws -> Data {
        let keySize = cipher.keySize
        let salt = ShadowsocksAEADCrypto.generateRandomSalt(keySize)
        requestSalt = salt
        let sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: salt, keySize: keySize)
        writeSubkey = sessionKey

        var output = salt
        if pskList.count >= 2 {
            for i in 0..<(pskList.count - 1) {
                let identitySubkey = ShadowsocksKeyDerivation.deriveIdentitySubkey(psk: pskList[i], salt: salt, keySize: keySize)
                output.append(try AesEcb.encrypt(key: identitySubkey, block: pskHashes[i]))
            }
        }

        // A small first write is padded so the handshake has no fixed size;
        // an empty one must be, or the header alone would be the fingerprint.
        let paddingLength = payload.count < ss2022MaxPaddingLength ? CryptoRandom.int(below: ss2022MaxPaddingLength) + 1 : 0

        // The variable header is one AEAD chunk, so it is bound by the chunk
        // limit like any other — its length field would wrap past 65535, and
        // servers read it into a chunk-sized buffer. The first write can be
        // everything the app queued during the dial (hundreds of KB), so only
        // what fits goes in the header; the rest follows as ordinary chunks in
        // the same write.
        let headerRoom = ShadowsocksAEADWriter.maxPayloadSize - addressHeader.count - 2 - paddingLength
        let inHeader = max(0, min(payload.count, headerRoom))
        let variableHeaderLength = addressHeader.count + 2 + paddingLength + inHeader

        // Fixed header (11 bytes): type(1) + timestamp(8) + variableHeaderLength(2).
        var fixedHeader = [UInt8]()
        fixedHeader.append(ss2022HeaderTypeClient)
        let timestamp = UInt64(max(0, Int64(Date().timeIntervalSince1970)))
        for shift in stride(from: 56, through: 0, by: -8) {
            fixedHeader.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(shift)))
        }
        fixedHeader.append(UInt8(truncatingIfNeeded: variableHeaderLength >> 8))
        fixedHeader.append(UInt8(truncatingIfNeeded: variableHeaderLength))
        output.append(try ShadowsocksAEADCrypto.seal(cipher, key: sessionKey, nonce: writeNonce.next(), plaintext: Data(fixedHeader)))

        // Variable header: address + paddingLength(2) + padding + initial payload.
        var variableHeader = addressHeader
        variableHeader.append(UInt8(truncatingIfNeeded: paddingLength >> 8))
        variableHeader.append(UInt8(truncatingIfNeeded: paddingLength))
        if paddingLength > 0 {
            variableHeader.append(contentsOf: [UInt8](repeating: 0, count: paddingLength))
        }
        variableHeader.append(contentsOf: payload[0..<inHeader])
        output.append(try ShadowsocksAEADCrypto.seal(cipher, key: sessionKey, nonce: writeNonce.next(), plaintext: Data(variableHeader)))

        if inHeader < payload.count {
            output.append(try sealChunks(Array(payload[inHeader...])))
        }
        return output
    }

    /// Standard AEAD chunks for writes after the handshake.
    private func sealChunks(_ plaintext: [UInt8]) throws -> Data {
        guard let subkey = writeSubkey else { throw ShadowsocksError.decryptionFailed }
        var output = Data()
        var offset = 0
        while offset < plaintext.count {
            let chunkSize = min(plaintext.count - offset, ShadowsocksAEADWriter.maxPayloadSize)
            let lengthBytes = Data([UInt8(truncatingIfNeeded: chunkSize >> 8), UInt8(truncatingIfNeeded: chunkSize)])
            output.append(try ShadowsocksAEADCrypto.seal(cipher, key: subkey, nonce: writeNonce.next(), plaintext: lengthBytes))
            let chunk = Data(plaintext[offset..<(offset + chunkSize)])
            output.append(try ShadowsocksAEADCrypto.seal(cipher, key: subkey, nonce: writeNonce.next(), plaintext: chunk))
            offset += chunkSize
        }
        return output
    }

    // MARK: - Receiving

    private var currentRequestSalt: Data? {
        sendLock.lock()
        defer { sendLock.unlock() }
        return requestSalt
    }

    private func processReceived(_ data: Data) throws -> Data {
        let expectedSalt = currentRequestSalt
        receiveLock.lock()
        defer { receiveLock.unlock() }

        readBuffer.append(contentsOf: data)
        var output = Data()

        if let variableLength = pendingVariableHeaderLength {
            guard let parsed = try parseVariableHeader(variableLength) else { return Data() }
            output.append(parsed)
        }
        if !responseHeaderParsed {
            guard let parsed = try parseResponseHeader(expectedSalt: expectedSalt) else { return Data() }
            output.append(parsed)
        }
        if responseHeaderParsed {
            output.append(try decryptChunks())
        }

        if readOffset > 0 && readOffset == readBuffer.count {
            readBuffer = []
            readOffset = 0
        } else if readOffset > Shadowsocks2022Connection.compactThreshold {
            readBuffer = Array(readBuffer[readOffset...])
            readOffset = 0
        }
        return output
    }

    private var readAvailable: Int { readBuffer.count - readOffset }

    private func takeBytes(_ count: Int) -> Data {
        let out = Data(readBuffer[readOffset..<(readOffset + count)])
        readOffset += count
        return out
    }

    private func parseResponseHeader(expectedSalt: Data?) throws -> Data? {
        let keySize = cipher.keySize
        // salt + sealed fixed header (type 1 + timestamp 8 + request salt + length 2, plus the tag)
        let fixedPlainLength = 1 + 8 + keySize + 2
        let minimum = keySize + fixedPlainLength + ss2022TagSize
        if readAvailable < minimum { return nil }

        let salt = takeBytes(keySize)
        let sessionKey = ShadowsocksKeyDerivation.deriveSessionKey(psk: psk, salt: salt, keySize: keySize)
        readSubkey = sessionKey

        let fixedChunk = takeBytes(fixedPlainLength + ss2022TagSize)
        let fixedHeader = [UInt8](try ShadowsocksAEADCrypto.open(cipher, key: sessionKey, nonce: readNonce.next(), ciphertext: fixedChunk))
        guard fixedHeader.count == fixedPlainLength else { throw ShadowsocksError.decryptionFailed }

        var offset = 0
        if fixedHeader[offset] != ss2022HeaderTypeServer { throw ShadowsocksError.badHeaderType }
        offset += 1

        var epoch: Int64 = 0
        for i in 0..<8 {
            epoch = (epoch << 8) | Int64(fixedHeader[offset + i])
        }
        offset += 8
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > ss2022MaxTimestampDifference { throw ShadowsocksError.badTimestamp }

        let responseSalt = Data(fixedHeader[offset..<(offset + keySize)])
        offset += keySize
        if let expected = expectedSalt, responseSalt != expected {
            throw ShadowsocksError.badRequestSalt
        }

        let variableLength = (Int(fixedHeader[offset]) << 8) | Int(fixedHeader[offset + 1])
        return try parseVariableHeader(variableLength) ?? Data()
    }

    private func parseVariableHeader(_ variableLength: Int) throws -> Data? {
        let chunkLength = variableLength + ss2022TagSize
        if readAvailable < chunkLength {
            pendingVariableHeaderLength = variableLength
            return nil
        }
        let chunk = takeBytes(chunkLength)
        guard let subkey = readSubkey else { throw ShadowsocksError.decryptionFailed }
        let data = try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: readNonce.next(), ciphertext: chunk)
        pendingVariableHeaderLength = nil
        responseHeaderParsed = true
        return data
    }

    private func decryptChunks() throws -> Data {
        guard let subkey = readSubkey else { return Data() }
        var output = Data()
        while true {
            let payloadLength: Int
            if let pending = pendingPayloadLength {
                payloadLength = pending
            } else {
                let lengthNeeded = 2 + ss2022TagSize
                if readAvailable < lengthNeeded { break }
                let encryptedLength = Data(readBuffer[readOffset..<(readOffset + lengthNeeded)])
                let lengthData = [UInt8](try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: readNonce.next(), ciphertext: encryptedLength))
                guard lengthData.count == 2 else { throw ShadowsocksError.decryptionFailed }
                readOffset += lengthNeeded
                payloadLength = (Int(lengthData[0]) << 8) | Int(lengthData[1])
            }

            let payloadNeeded = payloadLength + ss2022TagSize
            if readAvailable < payloadNeeded {
                pendingPayloadLength = payloadLength
                break
            }
            pendingPayloadLength = nil
            let encryptedPayload = takeBytes(payloadNeeded)
            output.append(try ShadowsocksAEADCrypto.open(cipher, key: subkey, nonce: readNonce.next(), ciphertext: encryptedPayload))
        }
        return output
    }
}
