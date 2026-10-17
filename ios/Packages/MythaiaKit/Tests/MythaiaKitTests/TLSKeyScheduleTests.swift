import XCTest
@testable import MythaiaKit

/// The TLS 1.3 key schedule against RFC 8448 §3 ("Simple 1-RTT Handshake",
/// TLS_AES_128_GCM_SHA256, X25519). Every expected value is the RFC's; the
/// ClientHello and ServerHello are the RFC's bytes, so the transcript hash is
/// checked too, not only the expansions after it.
final class TLSKeyScheduleTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        return TLSTestHex.bytes(hex)
    }

    private let clientHello = TLSTestHex.bytes("""
        010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b\
        0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099\
        381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e04030503060302030804080508\
        0604010501060102010402050206020202002d00020101001c00024001
        """)

    private let serverHello = TLSTestHex.bytes("""
        020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c98288\
        76112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304
        """)

    private let clientPrivate = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"
    private let clientPublic = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"
    private let serverPrivate = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"
    private let serverPublic = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"
    private let sharedSecret = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"

    func testHelloBytesAreTheRFCs() {
        XCTAssertEqual(clientHello.count, 196)
        XCTAssertEqual(serverHello.count, 90)
        XCTAssertEqual(
            TLSWire.hex(TLSHash.sha256.digest(clientHello + serverHello)),
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
        )
    }

    func testX25519SharedSecret() throws {
        let fromClient = try X25519Crypto.keyAgreement(privateKey: bytes(clientPrivate), peerPublicKey: bytes(serverPublic))
        let fromServer = try X25519Crypto.keyAgreement(privateKey: bytes(serverPrivate), peerPublicKey: bytes(clientPublic))
        XCTAssertEqual(TLSWire.hex(fromClient), sharedSecret)
        XCTAssertEqual(TLSWire.hex(fromServer), sharedSecret)
    }

    func testX25519RFC7748Vector() throws {
        let alicePrivate = bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPublic = bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let shared = try X25519Crypto.keyAgreement(privateKey: alicePrivate, peerPublicKey: bobPublic)
        XCTAssertEqual(TLSWire.hex(shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    }

    func testX25519RefusesALowOrderPoint() {
        let zeroPoint = [UInt8](repeating: 0, count: 32)
        XCTAssertThrowsError(try X25519Crypto.keyAgreement(privateKey: bytes(clientPrivate), peerPublicKey: zeroPoint))
    }

    func testEarlyAndDerivedSecrets() {
        let early = Tls13Crypto.earlySecret(.sha256)
        XCTAssertEqual(TLSWire.hex(early), "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        let derived = Tls13Crypto.deriveSecret(.sha256, secret: early, label: "derived", messages: [])
        XCTAssertEqual(TLSWire.hex(derived), "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        XCTAssertEqual(
            TLSWire.hex(Tls13Crypto.earlySecret(.sha384)),
            "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5"
        )
    }

    func testHandshakeSecretAndTrafficSecrets() {
        let handshakeSecret = Tls13Crypto.handshakeSecret(.sha256, sharedSecret: bytes(sharedSecret))
        XCTAssertEqual(TLSWire.hex(handshakeSecret), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")

        let clientSecret = Tls13Crypto.deriveSecret(.sha256, secret: handshakeSecret, label: "c hs traffic", messages: clientHello + serverHello)
        let serverSecret = Tls13Crypto.deriveSecret(.sha256, secret: handshakeSecret, label: "s hs traffic", messages: clientHello + serverHello)
        XCTAssertEqual(TLSWire.hex(clientSecret), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        XCTAssertEqual(TLSWire.hex(serverSecret), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    }

    func testKeyDerivationProducesTheRFCHandshakeKeys() throws {
        let derivation = try Tls13KeyDerivation(cipherSuite: TlsCipherSuite.TLS_AES_128_GCM_SHA256)
        XCTAssertEqual(derivation.hashLength, 32)
        XCTAssertEqual(derivation.keyLength, 16)
        let result = derivation.deriveHandshakeKeys(sharedSecret: bytes(sharedSecret), transcript: clientHello + serverHello)
        XCTAssertEqual(TLSWire.hex(result.handshakeSecret), "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        XCTAssertEqual(TLSWire.hex(result.keys.serverKey), "3fce516009c21727d0f2e4e86ee403bc")
        XCTAssertEqual(TLSWire.hex(result.keys.serverIV), "5d313eb2671276ee13000b30")
        XCTAssertEqual(TLSWire.hex(result.keys.clientKey), "dbfaa693d1762c5b666af5d950258d01")
        XCTAssertEqual(TLSWire.hex(result.keys.clientIV), "5bd3c71b836e0b76bb73265f")
        XCTAssertEqual(TLSWire.hex(result.keys.clientTrafficSecret), "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        XCTAssertEqual(TLSWire.hex(result.keys.serverTrafficSecret), "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
    }

    func testMasterSecretAndApplicationSecrets() throws {
        let handshakeSecret = bytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        let derived = Tls13Crypto.deriveSecret(.sha256, secret: handshakeSecret, label: "derived", messages: [])
        XCTAssertEqual(TLSWire.hex(derived), "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")
        let master = Tls13Crypto.masterSecret(.sha256, handshakeSecret: handshakeSecret)
        XCTAssertEqual(TLSWire.hex(master), "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")

        // The RFC's transcript hash through the server Finished.
        let throughFinished = bytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
        let clientSecret = Tls13Crypto.deriveSecret(.sha256, secret: master, label: "c ap traffic", transcriptHash: throughFinished)
        let serverSecret = Tls13Crypto.deriveSecret(.sha256, secret: master, label: "s ap traffic", transcriptHash: throughFinished)
        XCTAssertEqual(TLSWire.hex(clientSecret), "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        XCTAssertEqual(TLSWire.hex(serverSecret), "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")

        let suite = try XCTUnwrap(Tls13Suite.forCode(TlsCipherSuite.TLS_AES_128_GCM_SHA256))
        let server = Tls13Crypto.trafficKeys(suite, secret: serverSecret)
        XCTAssertEqual(TLSWire.hex(server.key), "9f02283b6c9c07efc26bb9f2ac92e356")
        XCTAssertEqual(TLSWire.hex(server.iv), "cf782b88dd83549aadf1e984")
        let client = Tls13Crypto.trafficKeys(suite, secret: clientSecret)
        XCTAssertEqual(TLSWire.hex(client.key), "17422dda596ed5d9acd890e3c63f5051")
        XCTAssertEqual(TLSWire.hex(client.iv), "5b78923dee08579033e523d9")
    }

    func testFinishedVerifyData() {
        // Finished keys from the handshake traffic secrets, then the HMAC
        // over the RFC's transcript hashes.
        let serverSecret = bytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        let serverFinishedKey = Tls13Crypto.hkdfExpandLabel(.sha256, secret: serverSecret, label: "finished", context: [], length: 32)
        XCTAssertEqual(TLSWire.hex(serverFinishedKey), "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")
        let throughCertificateVerify = bytes("edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed")
        XCTAssertEqual(
            TLSWire.hex(TLSHash.sha256.hmac(key: serverFinishedKey, data: throughCertificateVerify)),
            "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718"
        )

        let clientSecret = bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        let clientFinishedKey = Tls13Crypto.hkdfExpandLabel(.sha256, secret: clientSecret, label: "finished", context: [], length: 32)
        XCTAssertEqual(TLSWire.hex(clientFinishedKey), "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4")
        let throughServerFinished = bytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13")
        XCTAssertEqual(
            TLSWire.hex(TLSHash.sha256.hmac(key: clientFinishedKey, data: throughServerFinished)),
            "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
        )
    }

    func testKeyUpdateSecret() throws {
        // HKDF-Expand-Label(secret, "traffic upd", "", 32) of the RFC's server
        // application secret; the expected values were computed separately.
        let serverSecret = bytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
        let next = Tls13Crypto.nextTrafficSecret(.sha256, secret: serverSecret)
        XCTAssertEqual(TLSWire.hex(next), "51921b8aa3001976eb401d0a4319a8516416a6c56001a357e5d162031e84f916")
        let suite = try XCTUnwrap(Tls13Suite.forCode(TlsCipherSuite.TLS_AES_128_GCM_SHA256))
        let keys = Tls13Crypto.trafficKeys(suite, secret: next)
        XCTAssertEqual(TLSWire.hex(keys.key), "2e63be99d67b39097feb9786cf7a15a0")
        XCTAssertEqual(TLSWire.hex(keys.iv), "628a0a8298ac953baef4255a")
    }

    func testMessageHashReplacesTheFirstClientHello() {
        let stand = Tls13Crypto.messageHash(.sha256, clientHello: clientHello)
        XCTAssertEqual(Array(stand[0..<4]), [0xFE, 0x00, 0x00, 0x20])
        XCTAssertEqual(Array(stand[4...]), TLSHash.sha256.digest(clientHello))
    }

    func testUnsupportedSuiteIsRefused() {
        XCTAssertThrowsError(try Tls13KeyDerivation(cipherSuite: 0xC02F))
        XCTAssertNotNil(Tls13Suite.forCode(0x1302))
        XCTAssertEqual(Tls13Suite.forCode(0x1302)?.hash.length, 48)
        XCTAssertEqual(Tls13Suite.forCode(0x1303)?.keyLength, 32)
    }
}
