import Foundation
import XCTest
@testable import MythaiaKit

/// The first write of a Shadowsocks connection, decoded the way a server
/// would decode it.
///
/// The address header rides the first write, so the client flushes it at
/// connect time even when the app has nothing to send yet. For AEAD that is
/// a chunk holding only the header; for 2022 it is a request whose initial
/// payload is empty and whose padding is therefore mandatory. And a first
/// write may be everything the app queued during the dial — hundreds of KB —
/// which the 2022 variable-length header cannot hold on its own.
final class ShadowsocksConnectionTests: XCTestCase {
    private let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: "example.com", port: 443)

    private func hexString(_ data: Data) -> String { ProtocolTestStreams.hexString(data) }

    /// The nonce a server counts with: little-endian, starting at zero.
    private func nonce(_ counter: Int) -> Data {
        var out = [UInt8](repeating: 0, count: 12)
        var value = counter
        var i = 0
        while value > 0 {
            out[i] = UInt8(value & 0xFF)
            value >>= 8
            i += 1
        }
        return Data(out)
    }

    // MARK: - Key derivation

    func testPasswordKeyIsEvpBytesToKey() {
        // OpenSSL's EVP_BytesToKey with MD5, as every Shadowsocks server derives it.
        XCTAssertEqual(hexString(ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 16)), "8fe4c11451281c094a6578e6ddbf5eed")
        XCTAssertEqual(hexString(ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 32)),
                       "8fe4c11451281c094a6578e6ddbf5eedf20d7dd70da901c0c447221c81864826")
    }

    func testSubkeyIsHkdfSha1WithSsSubkeyInfo() {
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 16)
        let salt = Data((0..<16).map { UInt8($0) })
        XCTAssertEqual(hexString(ShadowsocksKeyDerivation.deriveSubkey(masterKey: masterKey, salt: salt, keySize: 16)),
                       "95cb710faa002b7b8014aa03a0bcf7bb")
    }

    func testNonceStartsAtZeroAndCountsLittleEndian() {
        let counter = ShadowsocksNonce(size: 12)
        XCTAssertEqual(counter.next(), nonce(0))
        XCTAssertEqual(counter.next(), nonce(1))
        for _ in 2..<256 {
            _ = counter.next()
        }
        XCTAssertEqual(counter.next(), nonce(256))
    }

    func testMethodsMapToCiphers() {
        XCTAssertEqual(ShadowsocksCipher.fromMethod("AES-128-GCM"), .aes128Gcm)
        XCTAssertEqual(ShadowsocksCipher.fromMethod("chacha20-ietf-poly1305"), .chacha20Poly1305)
        XCTAssertEqual(ShadowsocksCipher.fromMethod("2022-blake3-aes-256-gcm"), .blake3Aes256Gcm)
        XCTAssertEqual(ShadowsocksCipher.fromMethod("none"), .plain)
        XCTAssertNil(ShadowsocksCipher.fromMethod("rc4-md5"))
        XCTAssertEqual(ShadowsocksCipher.blake3Aes128Gcm.keySize, 16)
        XCTAssertTrue(ShadowsocksCipher.blake3Chacha20Poly1305.isSS2022)
    }

    func testPskListDecodesEveryEntry() {
        let a = Data(repeating: 1, count: 16)
        let b = Data(repeating: 2, count: 16)
        let password = a.base64EncodedString() + ":" + b.base64EncodedString()
        XCTAssertEqual(ShadowsocksKeyDerivation.decodePSKList(password, keySize: 16), [a, b])
        XCTAssertEqual(ShadowsocksKeyDerivation.decodePSK(password, keySize: 16), b)
        XCTAssertNil(ShadowsocksKeyDerivation.decodePSKList(password, keySize: 32))
    }

    // MARK: - AEAD

    func testEmptyFirstWriteIsOneChunkCarryingOnlyTheAddressHeader() async throws {
        let cipher = ShadowsocksCipher.aes128Gcm
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: cipher.keySize)
        let inner = ProtocolTestStreams.Scripted()
        let connection = ShadowsocksConnection(inner, cipher: cipher, masterKey: masterKey, addressHeader: addressHeader)

        try await connection.send(Data())

        XCTAssertEqual(inner.writes.count, 1)
        let wire = [UInt8](inner.written)
        // salt + sealed length + sealed header: nothing more.
        XCTAssertEqual(wire.count, 16 + (2 + 16) + (addressHeader.count + 16))

        // Decoded as a server would.
        let salt = Data(wire[0..<16])
        let subkey = HKDFHelper.sha1(inputKeyMaterial: masterKey, salt: salt, info: Data("ss-subkey".utf8), outputByteCount: 16)
        let length = try RawAEAD.aesGcmOpen(key: subkey, nonce: nonce(0), sealed: Data(wire[16..<34]))
        XCTAssertEqual(length, Data([0x00, UInt8(addressHeader.count)]))
        let header = try RawAEAD.aesGcmOpen(key: subkey, nonce: nonce(1), sealed: Data(wire[34...]))
        XCTAssertEqual(header, addressHeader)
    }

    func testLargeWritesAreChunkedAndReadBackWhateverTheReadSizes() throws {
        for cipher in [ShadowsocksCipher.aes256Gcm, .chacha20Poly1305] {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "secret", keySize: cipher.keySize)
            let writer = ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey)
            let reader = ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey)
            let payload = Data((0..<40000).map { UInt8($0 % 251) })
            let wire = [UInt8](try writer.seal(payload))
            // Three chunks of at most 0x3FFF, each with two tags, behind the salt.
            XCTAssertEqual(wire.count, cipher.saltSize + 3 * (2 + 16 + 16) + payload.count)

            var out = Data()
            var at = 0
            let sizes = [1, 7, 33, 5000, 2, 9000]
            var i = 0
            while at < wire.count {
                let end = min(wire.count, at + sizes[i % sizes.count])
                i += 1
                out.append(try reader.open(Data(wire[at..<end])))
                at = end
            }
            XCTAssertEqual(out, payload)
        }
    }

    func testTamperedChunkIsAnError() throws {
        let cipher = ShadowsocksCipher.aes128Gcm
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 16)
        var wire = [UInt8](try ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey).seal(Data("hello".utf8)))
        wire[wire.count - 1] ^= 0x01
        XCTAssertThrowsError(try ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey).open(Data(wire)))
    }

    // MARK: - 2022

    private struct DecodedRequest {
        let salt: Data
        let timestamp: UInt64
        let variableHeaderLength: Int
        let paddingLength: Int
        let initialPayload: Data
        let chunkLengths: [Int]
        let payload: Data
    }

    /// Decodes `wire` as the server would: salt, the sealed fixed header, the
    /// sealed variable header, then length/payload chunk pairs until the
    /// bytes run out.
    private func decode(_ wire: Data, cipher: ShadowsocksCipher, psk: Data) throws -> DecodedRequest {
        let bytes = [UInt8](wire)
        let keySize = cipher.keySize
        var at = 0
        let salt = Data(bytes[0..<keySize])
        at += keySize
        var material = psk
        material.append(salt)
        let key = Blake3.deriveKey(context: "shadowsocks 2022 session subkey", material: material, outputLength: keySize)
        var counter = 0

        func open(_ length: Int) throws -> [UInt8] {
            let sealed = Data(bytes[at..<(at + length + 16)])
            at += length + 16
            let n = nonce(counter)
            counter += 1
            if cipher.isChaCha {
                return [UInt8](try RawAEAD.chaChaPolyOpen(key: key, nonce: n, sealed: sealed))
            }
            return [UInt8](try RawAEAD.aesGcmOpen(key: key, nonce: n, sealed: sealed))
        }

        let fixed = try open(11)
        XCTAssertEqual(fixed[0], 0)
        var timestamp: UInt64 = 0
        for i in 1...8 {
            timestamp = (timestamp << 8) | UInt64(fixed[i])
        }
        let variableLength = (Int(fixed[9]) << 8) | Int(fixed[10])

        let variable = try open(variableLength)
        let headerBytes = [UInt8](addressHeader)
        XCTAssertEqual(Array(variable[0..<headerBytes.count]), headerBytes)
        var v = headerBytes.count
        let paddingLength = (Int(variable[v]) << 8) | Int(variable[v + 1])
        v += 2 + paddingLength
        let initialPayload = Data(variable[v...])

        var chunkLengths = [Int]()
        var payload = initialPayload
        while at < bytes.count {
            let lengthBytes = try open(2)
            let length = (Int(lengthBytes[0]) << 8) | Int(lengthBytes[1])
            chunkLengths.append(length)
            payload.append(contentsOf: try open(length))
        }
        XCTAssertEqual(at, bytes.count, "every byte of the write is accounted for")
        return DecodedRequest(salt: salt, timestamp: timestamp, variableHeaderLength: variableLength,
                              paddingLength: paddingLength, initialPayload: initialPayload,
                              chunkLengths: chunkLengths, payload: payload)
    }

    func test2022RequestWithNoPayloadStillCarriesPadding() async throws {
        let cipher = ShadowsocksCipher.blake3Aes128Gcm
        let psk = CryptoRandom.bytes(cipher.keySize)
        let inner = ProtocolTestStreams.Scripted()
        let connection = Shadowsocks2022Connection(inner, cipher: cipher, pskList: [psk], addressHeader: addressHeader)

        try await connection.send(Data())

        let decoded = try decode(inner.written, cipher: cipher, psk: psk)
        XCTAssertTrue((1...900).contains(decoded.paddingLength), "padding \(decoded.paddingLength)")
        XCTAssertEqual(decoded.initialPayload.count, 0)
        XCTAssertEqual(decoded.variableHeaderLength, addressHeader.count + 2 + decoded.paddingLength)
        XCTAssertEqual(decoded.chunkLengths, [])
        let now = UInt64(Date().timeIntervalSince1970)
        XCTAssertLessThanOrEqual(max(now, decoded.timestamp) - min(now, decoded.timestamp), 5)
    }

    func testLarge2022FirstWriteSpillsFromTheHeaderIntoChunks() async throws {
        let cipher = ShadowsocksCipher.blake3Aes128Gcm
        let psk = CryptoRandom.bytes(cipher.keySize)
        let inner = ProtocolTestStreams.Scripted()
        let connection = Shadowsocks2022Connection(inner, cipher: cipher, pskList: [psk], addressHeader: addressHeader)

        let payload = Data((0..<(100 * 1024)).map { UInt8($0 % 251) })
        try await connection.send(payload)

        XCTAssertEqual(inner.writes.count, 1, "one write")
        let decoded = try decode(inner.written, cipher: cipher, psk: psk)
        XCTAssertLessThanOrEqual(decoded.variableHeaderLength, ShadowsocksAEADWriter.maxPayloadSize)
        XCTAssertEqual(decoded.paddingLength, 0, "a payload this large is not padded")
        for length in decoded.chunkLengths {
            XCTAssertTrue((1...ShadowsocksAEADWriter.maxPayloadSize).contains(length), "chunk \(length)")
        }
        XCTAssertFalse(decoded.chunkLengths.isEmpty, "the remainder went out as chunks")
        XCTAssertEqual(decoded.payload, payload)
    }

    func testSmall2022FirstWriteFitsTheHeaderAndIsPadded() async throws {
        let cipher = ShadowsocksCipher.blake3Chacha20Poly1305
        let psk = CryptoRandom.bytes(cipher.keySize)
        let inner = ProtocolTestStreams.Scripted()
        let connection = Shadowsocks2022Connection(inner, cipher: cipher, pskList: [psk], addressHeader: addressHeader)

        let payload = Data("GET / HTTP/1.1\r\n\r\n".utf8)
        try await connection.send(payload)

        let decoded = try decode(inner.written, cipher: cipher, psk: psk)
        XCTAssertTrue((1...900).contains(decoded.paddingLength))
        XCTAssertEqual(decoded.initialPayload, payload)
        XCTAssertEqual(decoded.chunkLengths, [])
    }

    /// The server's answer: its own salt, a fixed header naming our request
    /// salt, then the data — built here by hand.
    func test2022ResponseIsReadBack() async throws {
        let cipher = ShadowsocksCipher.blake3Aes256Gcm
        let psk = CryptoRandom.bytes(cipher.keySize)
        let inner = ProtocolTestStreams.Scripted()
        let connection = Shadowsocks2022Connection(inner, cipher: cipher, pskList: [psk], addressHeader: addressHeader)
        try await connection.send(Data())
        let requestSalt = Data([UInt8](inner.written)[0..<32])

        let serverSalt = CryptoRandom.bytes(32)
        var material = psk
        material.append(serverSalt)
        let key = Blake3.deriveKey(context: "shadowsocks 2022 session subkey", material: material)
        let firstData = Data("SSH-2.0-banner".utf8)
        var fixed: [UInt8] = [1]
        let now = UInt64(Date().timeIntervalSince1970)
        for shift in stride(from: 56, through: 0, by: -8) {
            fixed.append(UInt8(truncatingIfNeeded: now >> UInt64(shift)))
        }
        fixed.append(contentsOf: requestSalt)
        fixed.append(contentsOf: [UInt8(firstData.count >> 8), UInt8(firstData.count & 0xFF)])
        var response = serverSalt
        response.append(try RawAEAD.aesGcmSeal(key: key, nonce: nonce(0), plaintext: Data(fixed)))
        response.append(try RawAEAD.aesGcmSeal(key: key, nonce: nonce(1), plaintext: firstData))
        let more = Data("more".utf8)
        response.append(try RawAEAD.aesGcmSeal(key: key, nonce: nonce(2), plaintext: Data([0, UInt8(more.count)])))
        response.append(try RawAEAD.aesGcmSeal(key: key, nonce: nonce(3), plaintext: more))

        // Split at an awkward place.
        let raw = [UInt8](response)
        inner.queue(Data(raw[0..<40]))
        inner.queue(Data(raw[40...]))

        let first = try await connection.receive()
        var received = first ?? Data()
        if received.count < firstData.count + more.count {
            let second = try await connection.receive()
            received.append(second ?? Data())
        }
        XCTAssertEqual(received, firstData + more)
    }

    // MARK: - UDP

    private final class NoSocket: DatagramStream, @unchecked Sendable {
        func send(_ packet: Data) async throws {}
        func receive() async throws -> Data? { return nil }
        func close() {}
    }

    func testLegacyUdpPacketIsSaltThenOneSealUnderAZeroNonce() throws {
        let cipher = ShadowsocksCipher.aes128Gcm
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 16)
        let udp = ShadowsocksUdpConnection(socket: NoSocket(), mode: .legacy(cipher: cipher, masterKey: masterKey),
                                           destinationHost: "8.8.8.8", destinationPort: 53)
        let packet = [UInt8](try udp.encryptPacket(Data([0xDE, 0xAD])))

        let salt = Data(packet[0..<16])
        let subkey = HKDFHelper.sha1(inputKeyMaterial: masterKey, salt: salt, info: Data("ss-subkey".utf8), outputByteCount: 16)
        let plain = try RawAEAD.aesGcmOpen(key: subkey, nonce: Data(count: 12), sealed: Data(packet[16...]))
        XCTAssertEqual([UInt8](plain), [0x01, 8, 8, 8, 8, 0x00, 53, 0xDE, 0xAD])

        // A reply, built the same way, comes back as its payload.
        let replySalt = CryptoRandom.bytes(16)
        let replyKey = HKDFHelper.sha1(inputKeyMaterial: masterKey, salt: replySalt, info: Data("ss-subkey".utf8), outputByteCount: 16)
        var reply = replySalt
        reply.append(try RawAEAD.aesGcmSeal(key: replyKey, nonce: Data(count: 12), plaintext: Data([0x01, 8, 8, 8, 8, 0x00, 53, 0xBE, 0xEF])))
        let decoded = try udp.decryptPacket(reply)
        XCTAssertEqual(decoded.host, "8.8.8.8")
        XCTAssertEqual(decoded.port, 53)
        XCTAssertEqual(decoded.payload, Data([0xBE, 0xEF]))
    }

    func test2022AesUdpPacketDecodesAsTheServerReadsIt() throws {
        let cipher = ShadowsocksCipher.blake3Aes128Gcm
        let psk = CryptoRandom.bytes(16)
        let udp = ShadowsocksUdpConnection(socket: NoSocket(), mode: .ss2022Aes(cipher: cipher, pskList: [psk]),
                                           destinationHost: "1.1.1.1", destinationPort: 443)
        let packet = [UInt8](try udp.encryptPacket(Data("quic".utf8)))

        // Server side: the separate header under the PSK, then the body.
        let header = [UInt8](try AesEcb.decrypt(key: psk, block: Data(packet[0..<16])))
        let sessionID = Data(header[0..<8])
        XCTAssertEqual(Array(header[8..<16]), [0, 0, 0, 0, 0, 0, 0, 1], "the first packet id is 1")
        var material = psk
        material.append(sessionID)
        let key = Blake3.deriveKey(context: "shadowsocks 2022 session subkey", material: material, outputLength: 16)
        let body = [UInt8](try RawAEAD.aesGcmOpen(key: key, nonce: Data(header[4..<16]), sealed: Data(packet[16...])))
        XCTAssertEqual(body[0], 0, "client header type")
        XCTAssertEqual(Array(body[9..<11]), [0, 0], "no padding off port 53")
        XCTAssertEqual(Array(body[11..<18]), [0x01, 1, 1, 1, 1, 0x01, 0xBB])
        XCTAssertEqual(Array(body[18...]), Array("quic".utf8))

        // The server's reply, which names our session.
        var serverHeader = [UInt8](repeating: 0, count: 8)
        serverHeader[7] = 0x42
        serverHeader.append(contentsOf: [0, 0, 0, 0, 0, 0, 0, 1])
        var serverMaterial = psk
        serverMaterial.append(Data(serverHeader[0..<8]))
        let serverKey = Blake3.deriveKey(context: "shadowsocks 2022 session subkey", material: serverMaterial, outputLength: 16)
        var replyBody: [UInt8] = [1]
        let now = UInt64(Date().timeIntervalSince1970)
        for shift in stride(from: 56, through: 0, by: -8) {
            replyBody.append(UInt8(truncatingIfNeeded: now >> UInt64(shift)))
        }
        replyBody.append(contentsOf: sessionID)
        replyBody.append(contentsOf: [0, 0])
        replyBody.append(contentsOf: [0x01, 1, 1, 1, 1, 0x01, 0xBB])
        replyBody.append(contentsOf: Array("answer".utf8))
        var reply = try AesEcb.encrypt(key: psk, block: Data(serverHeader))
        reply.append(try RawAEAD.aesGcmSeal(key: serverKey, nonce: Data(serverHeader[4..<16]), plaintext: Data(replyBody)))
        let decoded = try udp.decryptPacket(reply)
        XCTAssertEqual(decoded.port, 443)
        XCTAssertEqual(decoded.payload, Data("answer".utf8))
    }

    func testUdpAddressDecoding() {
        let v6 = ShadowsocksProtocol.encodeUDPPacket(host: "2001:db8::1", port: 53, payload: Data([9]))
        let decoded = ShadowsocksProtocol.decodeUDPPacket(v6)
        XCTAssertEqual(decoded?.host, "2001:db8:0:0:0:0:0:1")
        XCTAssertEqual(decoded?.port, 53)
        XCTAssertEqual(decoded?.payload, Data([9]))
        XCTAssertNil(ShadowsocksProtocol.decodeUDPPacket(Data([0x03, 5, 0x61])))
    }
}
