import CryptoKit
import Foundation
import XCTest
@testable import MythaiaKit

final class VmessTests: XCTestCase {
    private let id = UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811")!

    private func hexString(_ data: Data) -> String { ProtocolTestStreams.hexString(data) }

    private func rootHmac(_ message: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: Data("VMess AEAD KDF".utf8)))
        return Data(code)
    }

    // MARK: - KDF

    /// With no path elements the KDF is plain HMAC-SHA256 under the root
    /// salt, which CryptoKit computes independently — pinning the
    /// hand-written HMAC (block size, ipad/opad, key padding).
    func testBaseCaseMatchesCryptoKitHmacSha256() {
        let key = Data("the key".utf8)
        XCTAssertEqual(VmessKdf.kdf(key), rootHmac(key))
        XCTAssertEqual(hexString(VmessKdf.kdf(key)), "c295c6d3a5fe5c0703137217b4a306dd70ac9dd047efa2ab1d5af91ec945ee44")
    }

    /// One path element is HMAC keyed by that element, over a hash that is
    /// itself the base HMAC — written out here with explicit ipad/opad.
    func testOnePathElementNestsHmacOverHmac() {
        let key = Data("the key".utf8)
        let path = Data("Some Salt".utf8)

        var padded = [UInt8](repeating: 0, count: 64)
        for (i, b) in path.enumerated() {
            padded[i] = b
        }
        let ipad = Data(padded.map { $0 ^ 0x36 })
        let opad = Data(padded.map { $0 ^ 0x5C })

        let expected = rootHmac(opad + rootHmac(ipad + key))
        XCTAssertEqual(VmessKdf.kdf(key, path), expected)
    }

    /// RFC 2104 replaces an over-long key with its hash — and the hash here
    /// is the enclosing layer, not SHA-256, which is what Go's hmac.New does
    /// with a custom hash function. Getting this wrong only shows up against
    /// a real server, never in a self-consistent round trip.
    func testPathElementLongerThanTheBlockIsReducedByTheParentHash() {
        let longKey = Data((0..<100).map { UInt8($0) })
        let message = Data("msg".utf8)

        let reduced = VmessKdf.kdf(longKey)
        XCTAssertEqual(reduced.count, 32)
        XCTAssertEqual(VmessKdf.kdf(message, reduced), VmessKdf.kdf(message, longKey))
        XCTAssertNotEqual(VmessKdf.kdf(message, DigestHelper.sha256(longKey)), VmessKdf.kdf(message, longKey))
        // From an independent implementation of the same nesting.
        XCTAssertEqual(hexString(VmessKdf.kdf(message, longKey)), "1769f3c07cc6c77e5dad4e985840c01baf19f09e0b034da4a43d821dec8f7d18")
    }

    /// A non-UTF-8 byte must survive; encoding it on the way in would change
    /// the derived key and break every handshake against a real server.
    func testPathElementsAreRawBytesNotText() {
        let binary = Data([0x00, 0xFF, 0x80, 0x7F])
        let asText = Data(String(decoding: binary, as: UTF8.self).utf8)
        XCTAssertNotEqual(VmessKdf.kdf(Data("k".utf8), binary), VmessKdf.kdf(Data("k".utf8), asText))
    }

    func testKdfSlicesArePrefixesOfTheFullDerivation() {
        let key = Data("k".utf8)
        let full = VmessKdf.kdf(key, VmessKdf.salt("x"))
        XCTAssertEqual(VmessKdf.kdf16(key, VmessKdf.salt("x")), Data(full.prefix(16)))
        XCTAssertEqual(VmessKdf.kdf12(key, VmessKdf.salt("x")), Data(full.prefix(12)))
    }

    /// The command key and two derivations from it, from an independent
    /// implementation of the protocol's key schedule.
    func testCommandKeyAndHeaderKeysMatchAnIndependentImplementation() {
        let commandKey = VmessKdf.commandKey(id)
        XCTAssertEqual(hexString(commandKey), "b50d916ac0cec067981af8e5f38a758f")
        XCTAssertEqual(hexString(VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltAuthIdEncryption))),
                       "1415ba74ca8b3d041a8f583fb4116315")
        let authId = Data((0..<16).map { UInt8($0) })
        let nonce = Data((0..<8).map { UInt8($0) })
        XCTAssertEqual(hexString(VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltHeaderLengthKey), authId, nonce)),
                       "e6e3dfda1dad7338c6454d172ca8ac0a")
    }

    // MARK: - FNV-1a and UUID bytes

    func testFnv1aMatchesItsPublishedVectors() {
        XCTAssertEqual(VmessKdf.fnv1a32(Data()), 0x811C_9DC5)
        XCTAssertEqual(VmessKdf.fnv1a32(Data("a".utf8)), 0xE40C_292C)
        XCTAssertEqual(VmessKdf.fnv1a32(Data("foobar".utf8)), 0xBF9C_F968)
    }

    func testUuidBecomesItsSixteenBigEndianBytes() {
        let bytes = [UInt8](VmessKdf.uuidBytes(id))
        XCTAssertEqual(bytes.count, 16)
        XCTAssertEqual(bytes[0], 0xB8)
        XCTAssertEqual(bytes[1], 0x31)
        XCTAssertEqual(bytes[15], 0x11)
    }

    // MARK: - Request header

    /// The sealed request opened the way a server opens it: the auth ID under
    /// AES-ECB, the length and the header under their derived keys, every
    /// field checked in place.
    func testSealedRequestOpensAsTheServerReadsIt() throws {
        let sealed = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 443,
                                                   command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let wire = [UInt8](sealed.bytes)
        let commandKey = VmessKdf.commandKey(id)

        let authId = Data(wire[0..<16])
        let authKey = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltAuthIdEncryption))
        let authPlain = [UInt8](try AesEcb.decrypt(key: authKey, block: authId))
        var time: UInt64 = 0
        for i in 0..<8 {
            time = (time << 8) | UInt64(authPlain[i])
        }
        let now = UInt64(Date().timeIntervalSince1970)
        XCTAssertLessThanOrEqual(max(now, time) - min(now, time), 5, "timestamp")
        let crc = CRC32Checksum.compute(authPlain[0..<12])
        XCTAssertEqual(Array(authPlain[12..<16]), [UInt8(crc >> 24), UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)])

        let nonce = Data(wire[34..<42])
        let lengthKey = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltHeaderLengthKey), authId, nonce)
        let lengthNonce = VmessKdf.kdf12(commandKey, VmessKdf.salt(VmessKdf.saltHeaderLengthIv), authId, nonce)
        let lengthPlain = [UInt8](try RawAEAD.aesGcmOpen(key: lengthKey, nonce: lengthNonce, sealed: Data(wire[16..<34]), aad: authId))
        let headerLength = (Int(lengthPlain[0]) << 8) | Int(lengthPlain[1])
        XCTAssertEqual(wire.count, 42 + headerLength + 16)

        let payloadKey = VmessKdf.kdf16(commandKey, VmessKdf.salt(VmessKdf.saltHeaderPayloadKey), authId, nonce)
        let payloadNonce = VmessKdf.kdf12(commandKey, VmessKdf.salt(VmessKdf.saltHeaderPayloadIv), authId, nonce)
        let header = [UInt8](try RawAEAD.aesGcmOpen(key: payloadKey, nonce: payloadNonce, sealed: Data(wire[42...]), aad: authId))

        XCTAssertEqual(header[0], 1, "version")
        XCTAssertEqual(Data(header[1..<17]), sealed.session.requestBodyIv)
        XCTAssertEqual(Data(header[17..<33]), sealed.session.requestBodyKey)
        XCTAssertEqual(header[33], sealed.session.responseHeader)
        XCTAssertEqual(header[34], 0x0D, "chunk stream, masking, global padding")
        let paddingLength = Int(header[35] >> 4)
        XCTAssertEqual(header[35] & 0x0F, 0x03, "AES-128-GCM")
        XCTAssertEqual(header[36], 0, "reserved")
        XCTAssertEqual(header[37], VmessProtocol.commandTCP)
        XCTAssertEqual(Array(header[38..<40]), [0x01, 0xBB])
        XCTAssertEqual(header[40], 2, "domain")
        XCTAssertEqual(Int(header[41]), 11)
        XCTAssertEqual(Array(header[42..<53]), Array("example.com".utf8))
        XCTAssertEqual(header.count, 53 + paddingLength + 4)
        let checksum = FNV1a.hash32(header[0..<(53 + paddingLength)])
        let trailer = Array(header[(53 + paddingLength)...])
        XCTAssertEqual(trailer, [UInt8(checksum >> 24), UInt8((checksum >> 16) & 0xFF), UInt8((checksum >> 8) & 0xFF), UInt8(checksum & 0xFF)])
    }

    func testIPv4DestinationAndPlainSecurityOptions() throws {
        let sealed = try VmessProtocol.sealRequest(id: id, host: "10.0.0.1", port: 53,
                                                   command: VmessProtocol.commandUDP, security: .plain)
        XCTAssertEqual(sealed.session.option, VmessProtocol.optionChunkStream)
        let built = [UInt8](try VmessProtocol.buildHeader(bodyKey: Data(count: 16), bodyIv: Data(count: 16), responseHeader: 7,
                                                           option: 1, security: .plain, command: VmessProtocol.commandUDP,
                                                           host: "10.0.0.1", port: 53))
        XCTAssertEqual(built[35] & 0x0F, 0x05)
        XCTAssertEqual(built[37], VmessProtocol.commandUDP)
        XCTAssertEqual(Array(built[38..<45]), [0x00, 53, 1, 10, 0, 0, 1])
    }

    func testUnaddressableNameIsRefused() {
        XCTAssertThrowsError(try VmessProtocol.sealRequest(id: id, host: "", port: 80, command: VmessProtocol.commandTCP, security: .aes128Gcm))
    }

    func testTwoRequestsNeverRepeatTheirAuthId() throws {
        let a = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 443, command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let b = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 443, command: VmessProtocol.commandTCP, security: .aes128Gcm)
        XCTAssertNotEqual(Data(a.bytes.prefix(16)), Data(b.bytes.prefix(16)))
    }

    func testResponseBodyKeysDeriveFromTheRequests() throws {
        let sealed = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 443, command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let session = sealed.session
        XCTAssertEqual(session.responseBodyKey, Data(Data(SHA256.hash(data: session.requestBodyKey)).prefix(16)))
        XCTAssertEqual(session.responseBodyIv, Data(Data(SHA256.hash(data: session.requestBodyIv)).prefix(16)))
    }

    // MARK: - Chunk stream

    private let chunkKey = Data((0..<16).map { UInt8($0) })
    private let chunkIv = Data((0..<16).map { UInt8(($0 * 3) & 0xFF) })

    private func streams(_ security: VmessSecurity, masking: Bool, padding: Bool) -> (VmessChunkStream, VmessChunkStream) {
        return (
            VmessChunkStream(key: chunkKey, iv: chunkIv, security: security, masking: masking, globalPadding: padding),
            VmessChunkStream(key: chunkKey, iv: chunkIv, security: security, masking: masking, globalPadding: padding)
        )
    }

    func testChunksRoundTripInEveryMode() throws {
        for security in [VmessSecurity.aes128Gcm, .chacha20Poly1305, .plain] {
            for masking in [true, false] {
                for padding in [true, false] {
                    let label = "\(security) masking=\(masking) padding=\(padding)"
                    let (writer, reader) = streams(security, masking: masking, padding: padding)
                    let payloads = [Data("hello".utf8), Data([7]), Data((0..<5000).map { UInt8($0 % 251) })]
                    var wire = [UInt8]()
                    for p in payloads {
                        wire.append(contentsOf: try writer.encode(p))
                    }
                    var at = 0
                    var received = Data()
                    while at < wire.count {
                        switch try reader.decode(wire, from: at) {
                        case .chunk(let payload, let consumed):
                            received.append(payload)
                            at += consumed
                        case .needMore:
                            XCTFail("truncated at \(at) (\(label))")
                            at = wire.count
                        case .endOfStream:
                            XCTFail("unexpected end (\(label))")
                            at = wire.count
                        }
                    }
                    var expected = Data()
                    for p in payloads {
                        expected.append(p)
                    }
                    XCTAssertEqual(received, expected, label)
                }
            }
        }
    }

    private func draws(_ count: Int) -> [Int] {
        var shake = Shake128(seed: chunkIv)
        var out = [Int]()
        for _ in 0..<count {
            let b = shake.squeeze(2)
            out.append((Int(b[0]) << 8) | Int(b[1]))
        }
        return out
    }

    /// Pins the draw ORDER against the reference, which a round trip cannot:
    /// the padding draw first, then the mask draw, from a SHAKE128 stream
    /// driven separately here.
    func testLengthFieldMatchesAStreamDrivenInV2rayDrawOrder() throws {
        let writer = VmessChunkStream(key: chunkKey, iv: chunkIv, security: .aes128Gcm, masking: true, globalPadding: true)
        let payload = Data("hello".utf8)
        let wire = [UInt8](try writer.encode(payload))

        let reference = draws(2)
        let paddingLength = reference[0] % 64
        let mask = reference[1]
        let sealedLength = payload.count + 16
        let expected = (sealedLength + paddingLength) ^ mask

        XCTAssertEqual((Int(wire[0]) << 8) | Int(wire[1]), expected, "length field disagrees with the reference draw order")
        XCTAssertEqual(wire.count, 2 + sealedLength + paddingLength)
    }

    /// The same order on the read side: a chunk framed by hand in reference
    /// order decodes.
    func testChunkFramedInReferenceOrderDecodes() throws {
        let payload = Data("some payload".utf8)
        var nonce = [UInt8](repeating: 0, count: 12)
        let ivBytes = [UInt8](chunkIv)
        for i in 2..<12 {
            nonce[i] = ivBytes[i]
        }
        let sealed = try RawAEAD.aesGcmSeal(key: chunkKey, nonce: Data(nonce), plaintext: payload)

        let reference = draws(2)
        let paddingLength = reference[0] % 64
        let onWire = sealed.count + paddingLength
        let length = onWire ^ reference[1]
        var wire: [UInt8] = [UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        wire.append(contentsOf: sealed)
        wire.append(contentsOf: [UInt8](repeating: 0, count: paddingLength))

        let reader = VmessChunkStream(key: chunkKey, iv: chunkIv, security: .aes128Gcm, masking: true, globalPadding: true)
        XCTAssertEqual(try reader.decode(wire, from: 0), .chunk(payload: payload, consumed: wire.count))
    }

    /// The mask and the chunk counter advance once per complete chunk. If a
    /// short read consumed a draw, every later chunk would decode as garbage.
    func testPartialChunkCanBeRetriedWithoutLosingTheDrawStream() throws {
        let (writer, reader) = streams(.aes128Gcm, masking: true, padding: true)
        let payload = Data((0..<300).map { UInt8($0 & 0xFF) })
        var wire = [UInt8](try writer.encode(payload))
        wire.append(contentsOf: try writer.encode(payload))

        for cut in 1..<min(wire.count, 40) {
            let fresh = VmessChunkStream(key: chunkKey, iv: chunkIv, security: .aes128Gcm, masking: true, globalPadding: true)
            XCTAssertEqual(try fresh.decode(Array(wire[0..<cut]), from: 0), .needMore, "cut=\(cut)")
        }

        var at = 0
        for _ in 0..<2 {
            guard case .chunk(let decoded, let consumed) = try reader.decode(wire, from: at) else {
                XCTFail("expected a chunk")
                return
            }
            XCTAssertEqual(decoded, payload)
            at += consumed
        }
        XCTAssertEqual(at, wire.count)
    }

    func testEmptyPayloadWritesNothingAndTheTerminatorEndsTheStream() throws {
        let (writer, reader) = streams(.aes128Gcm, masking: true, padding: true)
        XCTAssertEqual(try writer.encode(Data()).count, 0)
        let wire = try writer.encodeTerminator()
        XCTAssertEqual(try reader.decode(wire, from: 0), .endOfStream)
    }

    /// sing-box frames 16384-byte chunks; the field is sixteen bits, so a
    /// peer may send up to 65535.
    func testChunkAsLargeAsTheLengthFieldAllowsIsAccepted() throws {
        let reader = VmessChunkStream(key: chunkKey, iv: chunkIv, security: .plain, masking: false, globalPadding: false)
        let payload = Data((0..<16384).map { UInt8($0 % 251) })
        var wire = Data([0x40, 0x00])
        wire.append(payload)
        XCTAssertEqual(try reader.decode(wire, from: 0), .chunk(payload: payload, consumed: wire.count))

        var waiting = Data([0xFF, 0xFF])
        waiting.append(Data(count: 10))
        XCTAssertEqual(try reader.decode(waiting, from: 0), .needMore)
    }

    func testTamperedChunkFailsAuthenticationRatherThanDecoding() throws {
        let (writer, reader) = streams(.aes128Gcm, masking: false, padding: false)
        var wire = [UInt8](try writer.encode(Data("secret".utf8)))
        wire[4] ^= 0x01
        XCTAssertThrowsError(try reader.decode(wire, from: 0)) { error in
            guard case MythaiaError.protocolError = error else {
                XCTFail("expected a protocol error, got \(error)")
                return
            }
        }
    }

    func testSecurityNamesMapToTheirProtocolIds() {
        XCTAssertEqual(VmessSecurity.aes128Gcm.id, 0x03)
        XCTAssertEqual(VmessSecurity.chacha20Poly1305.id, 0x04)
        XCTAssertEqual(VmessSecurity.plain.id, 0x05)
        XCTAssertEqual(VmessSecurity.fromRaw("auto"), .aes128Gcm)
        XCTAssertEqual(VmessSecurity.fromRaw(nil), .aes128Gcm)
        XCTAssertEqual(VmessSecurity.fromRaw("chacha20-ietf-poly1305"), .chacha20Poly1305)
        XCTAssertEqual(VmessSecurity.fromRaw("none"), .plain)
    }

    // MARK: - Connection

    /// A whole exchange: the first write is the sealed header plus a chunk;
    /// the server's sealed response header and its first chunk come back as
    /// the payload.
    func testConnectionWritesTheHeaderOnceAndReadsTheServersReply() async throws {
        let sealed = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 80,
                                                   command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let session = sealed.session
        let inner = ProtocolTestStreams.Scripted()
        let connection = VmessConnection(inner, session: session, requestHeader: sealed.bytes)

        try await connection.send(Data("GET /".utf8))
        try await connection.send(Data("more".utf8))
        let writes = inner.writes
        XCTAssertEqual(writes.count, 2)
        XCTAssertEqual(Data(writes[0].prefix(sealed.bytes.count)), sealed.bytes)
        let serverReader = VmessChunkStream(key: session.requestBodyKey, iv: session.requestBodyIv,
                                            security: .aes128Gcm, masking: true, globalPadding: true)
        let firstBody = [UInt8](writes[0].dropFirst(sealed.bytes.count))
        XCTAssertEqual(try serverReader.decode(firstBody, from: 0), .chunk(payload: Data("GET /".utf8), consumed: firstBody.count))
        XCTAssertEqual(try serverReader.decode([UInt8](writes[1]), from: 0), .chunk(payload: Data("more".utf8), consumed: writes[1].count))

        // The server's side.
        let lengthKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderLenKey))
        let lengthNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderLenIv))
        let headerKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadKey))
        let headerNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadIv))
        let responseHeader = Data([session.responseHeader, 0x00, 0x00, 0x00])
        var reply = try RawAEAD.aesGcmSeal(key: lengthKey, nonce: lengthNonce, plaintext: Data([0x00, 0x04]))
        reply.append(try RawAEAD.aesGcmSeal(key: headerKey, nonce: headerNonce, plaintext: responseHeader))
        let serverWriter = VmessChunkStream(key: session.responseBodyKey, iv: session.responseBodyIv,
                                            security: .aes128Gcm, masking: true, globalPadding: true)
        reply.append(try serverWriter.encode(Data("HTTP/1.1 200 OK".utf8)))
        reply.append(try serverWriter.encodeTerminator())
        let raw = [UInt8](reply)
        inner.queue(Data(raw[0..<10]))
        inner.queue(Data(raw[10...]))

        let received = try await connection.receive()
        XCTAssertEqual(received, Data("HTTP/1.1 200 OK".utf8))
        let end = try await connection.receive()
        XCTAssertNil(end)
    }

    func testResponseHeaderForAnotherRequestIsRefused() async throws {
        let sealed = try VmessProtocol.sealRequest(id: id, host: "example.com", port: 80,
                                                   command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let session = sealed.session
        let lengthKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderLenKey))
        let lengthNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderLenIv))
        let headerKey = VmessKdf.kdf16(session.responseBodyKey, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadKey))
        let headerNonce = VmessKdf.kdf12(session.responseBodyIv, VmessKdf.salt(VmessKdf.saltRespHeaderPayloadIv))
        var reply = try RawAEAD.aesGcmSeal(key: lengthKey, nonce: lengthNonce, plaintext: Data([0x00, 0x04]))
        reply.append(try RawAEAD.aesGcmSeal(key: headerKey, nonce: headerNonce,
                                            plaintext: Data([session.responseHeader ^ 0xFF, 0, 0, 0])))
        XCTAssertThrowsError(try VmessProtocol.openResponseHeader(session, [UInt8](reply)))
        XCTAssertEqual(try VmessProtocol.openResponseHeader(session, Array([UInt8](reply).prefix(17))), -1)
    }
}
