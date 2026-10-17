import CryptoKit
import XCTest
@testable import MythaiaKit

/// REALITY: the auth key, the sealed session id and the certificate check
/// against values computed independently, then whole handshakes against the
/// test server, which checks the session id the way a REALITY server does.
final class RealityClientTests: XCTestCase {

    /// RFC 7748 §6.1: Alice's private key and Bob's public key.
    private let clientPrivate = TLSTestHex.bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    private let serverPublic = TLSTestHex.bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    private let random = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 11 + 5) }
    private let authKey = TLSTestHex.bytes("cb12feafc423a6d9d9cd0ebfc2e3a557aca7c5bc138e12f2deaf4e728b17952a")

    private static let realityCertificate = TLSTestFixtures.base64("""
        MIH0MIGnoAMCAQICBAEjRWcwBQYDK2VwMBUxEzARBgNVBAMMCmVkLmV4YW1wbGUwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAVMRMwEQ\
        YDVQQDDAplZC5leGFtcGxlMCowBQYDK2VwAyEAT1M95M273Izx46qlf9k2twLWfvqFUH+bQ3gb149jruijGTAXMBUGA1UdEQQOMAyCCmVkLmV4YW1w\
        bGUwBQYDK2VwA0EAVVPQFNLTyYDE+y6PMKB8g5Ois+HCQHR7EFaQEB74DFJ5vB3TgY35BBP3LQoAXtmfgVcT3GNzCBU6mPU/4oFmOg==
        """)

    /// A TLS 1.3 Certificate message body holding one certificate.
    private func certificateMessageBody(_ der: [UInt8]) -> [UInt8] {
        var entry: [UInt8] = [UInt8(der.count >> 16), UInt8((der.count >> 8) & 0xFF), UInt8(der.count & 0xFF)]
        entry.append(contentsOf: der)
        entry.append(contentsOf: [0x00, 0x00])
        var body: [UInt8] = [0x00, UInt8(entry.count >> 16), UInt8((entry.count >> 8) & 0xFF), UInt8(entry.count & 0xFF)]
        body.append(contentsOf: entry)
        return body
    }

    // -- Client authentication --

    func testAuthKeyDerivation() throws {
        let shared = try X25519Crypto.keyAgreement(privateKey: clientPrivate, peerPublicKey: serverPublic)
        XCTAssertEqual(TLSWire.hex(shared), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        XCTAssertEqual(TLSWire.hex(random), "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a")
        let derived = RealityClient.deriveAuthKey(sharedSecret: shared, random: random)
        XCTAssertEqual(derived, authKey)
    }

    func testSessionIdPlaintextLayout() {
        let full = RealityClient.sessionIdPlaintext(shortId: TLSTestHex.bytes("0123456789abcdef"), timestamp: 0x6500_0000)
        XCTAssertEqual(TLSWire.hex(full), "1a041900650000000123456789abcdef")
        let short = RealityClient.sessionIdPlaintext(shortId: [0xAB, 0xCD], timestamp: 0x6500_0000)
        XCTAssertEqual(TLSWire.hex(short), "1a04190065000000abcd000000000000")
        let none = RealityClient.sessionIdPlaintext(shortId: [], timestamp: 1)
        XCTAssertEqual(TLSWire.hex(none), "1a041900000000010000000000000000")
    }

    func testTheSessionIdIsSealedWithAESGCM() throws {
        let plaintext = TLSTestHex.bytes("1a041900650000000123456789abcdef")
        let aad = (0..<100).map { UInt8($0) }
        let sealed = try RealityClient.sealSessionId(plaintext, authKey: authKey, random: random, aad: aad)
        XCTAssertEqual(sealed.count, 32)
        XCTAssertEqual(TLSWire.hex(sealed), "4affc40c04fa46dae45a4153016a8755db46bc3c97f2110d65315941322fac6c")
    }

    // -- Server authentication --

    func testTheRealityCertificateIsRecognised() {
        let body = certificateMessageBody(RealityClientTests.realityCertificate)
        XCTAssertTrue(RealityClient.verifyRealityCertificate(body, authKey: authKey))
        var otherKey = authKey
        otherKey[0] ^= 0x01
        XCTAssertFalse(RealityClient.verifyRealityCertificate(body, authKey: otherKey))
    }

    func testAnOrdinaryCertificateIsNotARealityOne() {
        // The real site's certificate: Ed25519 with a real signature, or not
        // Ed25519 at all. Neither is an error, just not the server we want.
        let ed25519 = certificateMessageBody(TLSTestFixtures.ed25519Certificate)
        XCTAssertFalse(RealityClient.verifyRealityCertificate(ed25519, authKey: authKey))
        let p256 = certificateMessageBody(TLSTestFixtures.p256Certificate)
        XCTAssertFalse(RealityClient.verifyRealityCertificate(p256, authKey: authKey))
        XCTAssertFalse(RealityClient.verifyRealityCertificate([0x00, 0x00], authKey: authKey))
        XCTAssertFalse(RealityClient.verifyRealityCertificate([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x09], authKey: authKey))
    }

    func testEd25519ComponentsComeOutOfTheCertificate() throws {
        let components = try XCTUnwrap(RealityClient.extractEd25519Components(TLSTestFixtures.ed25519Certificate))
        XCTAssertEqual(components.publicKey, TLSTestHex.bytes(TLSTestFixtures.ed25519PublicKey))
        XCTAssertEqual(components.signature, TLSTestHex.bytes(TLSTestFixtures.ed25519CertificateSignature))
        XCTAssertNil(RealityClient.extractEd25519Components(TLSTestFixtures.p256Certificate))
        XCTAssertNil(RealityClient.extractEd25519Components(Array(TLSTestFixtures.ed25519Certificate.prefix(60))))
    }

    func testFirstCertificateOfAMessage() {
        let body = certificateMessageBody([0x30, 0x03, 0x01, 0x02, 0x03])
        XCTAssertEqual(RealityClient.extractFirstCertificate(body), [0x30, 0x03, 0x01, 0x02, 0x03])
        XCTAssertNil(RealityClient.extractFirstCertificate([0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x09]))
    }

    // -- Whole handshakes --

    private func connect(
        serverKey: Curve25519.KeyAgreement.PrivateKey,
        clientPublicKey: [UInt8],
        shortId: [UInt8],
        fingerprint: TlsFingerprint,
        now: Date
    ) async throws -> (client: TLSSessionStream, server: TLSTestServer) {
        var serverOptions = TLSTestServer.Options()
        serverOptions.realityPrivateKey = serverKey
        serverOptions.realityShortId = shortId
        let ends = TLSTestStreams.pair()
        let server = TLSTestServer(stream: ends.server, options: serverOptions)
        let serverTask = Task { try await server.handshake() }
        do {
            let session = try await RealityClient.handshake(
                over: ends.client,
                serverName: "www.example.com",
                publicKey: clientPublicKey,
                shortId: shortId,
                fingerprint: fingerprint,
                alpn: [],
                now: now
            )
            try await serverTask.value
            return (session, server)
        } catch {
            ends.server.close()
            _ = try? await serverTask.value
            throw error
        }
    }

    func testAHandshakeWithEveryTls13Fingerprint() async throws {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = Array(serverKey.publicKey.rawRepresentation)
        let fingerprints: [TlsFingerprint] = [
            .chrome133, .firefox148, .safari26, .ios14, .edge85,
            .chrome120, .firefox120, .safari16, .edge106, .random,
        ]
        for fingerprint in fingerprints {
            let result = try await connect(
                serverKey: serverKey,
                clientPublicKey: publicKey,
                shortId: [0xAB, 0xCD],
                fingerprint: fingerprint,
                now: Date(timeIntervalSince1970: 1_700_000_000)
            )
            // The server opened the session id: version, time, short id.
            XCTAssertEqual(
                result.server.realityPlaintext.map { TLSWire.hex($0) },
                "1a0419006553f100abcd000000000000",
                "\(fingerprint)"
            )
            try await result.client.send(Data("ping".utf8))
            let atServer = try await result.server.receive()
            XCTAssertEqual(atServer, Array("ping".utf8), "\(fingerprint)")
            try await result.server.send(Array("pong".utf8))
            let atClient = try await result.client.receive()
            XCTAssertEqual(atClient, Data("pong".utf8), "\(fingerprint)")
            result.client.close()
        }
    }

    func testTheWrongServerKeyFailsAuthentication() async {
        // The server cannot open the session id, so it answers as the real
        // site would, and the client must notice.
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        let wrongKey = Array(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
        do {
            let result = try await connect(
                serverKey: serverKey,
                clientPublicKey: wrongKey,
                shortId: [0x01],
                fingerprint: .chrome133,
                now: Date()
            )
            result.client.close()
            XCTFail("a server without the REALITY key was accepted")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("REALITY server authentication failed"), error.localizedDescription)
        }
    }

    func testTheWrongShortIdFailsAuthentication() async {
        let serverKey = Curve25519.KeyAgreement.PrivateKey()
        var serverOptions = TLSTestServer.Options()
        serverOptions.realityPrivateKey = serverKey
        serverOptions.realityShortId = [0x11, 0x22]
        let ends = TLSTestStreams.pair()
        let server = TLSTestServer(stream: ends.server, options: serverOptions)
        let serverTask = Task { try await server.handshake() }
        do {
            let session = try await RealityClient.handshake(
                over: ends.client,
                serverName: "www.example.com",
                publicKey: Array(serverKey.publicKey.rawRepresentation),
                shortId: [0x33, 0x44],
                fingerprint: .chrome133,
                alpn: []
            )
            session.close()
            XCTFail("a short id the server does not know was accepted")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("REALITY"), error.localizedDescription)
        }
        ends.server.close()
        _ = try? await serverTask.value
    }

    func testABadConfigurationIsRefusedBeforeAnythingIsSent() async {
        let ends = TLSTestStreams.pair()
        do {
            _ = try await RealityClient.handshake(
                over: ends.client,
                serverName: "www.example.com",
                publicKey: [0x01, 0x02],
                shortId: [],
                fingerprint: .chrome133,
                alpn: []
            )
            XCTFail("a 2-byte public key was accepted")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("public key"), error.localizedDescription)
        }
        XCTAssertTrue(ends.client.sentBytes.isEmpty)
    }
}
