import XCTest
@testable import MythaiaKit

/// Signature schemes, chain parsing, pins and the CertificateVerify content:
/// the places where being slightly wrong means accepting a certificate
/// issued for somebody else, or a signature made under different rules. The
/// certificates and signatures come from an independent implementation.
final class TLSPeerVerifierTests: XCTestCase {

    override func tearDown() {
        CertificatePolicy.setTrustedFingerprints([])
        CertificatePolicy.setAllowInsecure(false)
        super.tearDown()
    }

    func testAnUnknownSignatureSchemeIsRefusedNotMappedToPKCS1() {
        XCTAssertNil(TlsPeerVerifier.secKeyAlgorithm(for: 0x0420))
        XCTAssertNil(TlsPeerVerifier.secKeyAlgorithm(for: 0x0808))
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0809), .rsaSignatureMessagePSSSHA256)
    }

    func testEverySignatureSchemeMapsToTheMatchingAlgorithm() {
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0403), .ecdsaSignatureMessageX962SHA256)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0503), .ecdsaSignatureMessageX962SHA384)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0603), .ecdsaSignatureMessageX962SHA512)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0804), .rsaSignatureMessagePSSSHA256)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0805), .rsaSignatureMessagePSSSHA384)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0806), .rsaSignatureMessagePSSSHA512)
        XCTAssertEqual(TlsPeerVerifier.secKeyAlgorithm(for: 0x0401), .rsaSignatureMessagePKCS1v15SHA256)
    }

    func testTls13ForbidsPKCS1AndSHA1InCertificateVerify() {
        XCTAssertFalse(TlsPeerVerifier.tls13CertificateVerifySchemes.contains(0x0401))
        XCTAssertFalse(TlsPeerVerifier.tls13CertificateVerifySchemes.contains(0x0201))
        XCTAssertFalse(TlsPeerVerifier.tls13CertificateVerifySchemes.contains(0x0203))
        XCTAssertTrue(TlsPeerVerifier.tls13CertificateVerifySchemes.contains(0x0804))
        XCTAssertTrue(TlsPeerVerifier.tls13CertificateVerifySchemes.contains(0x0807))
    }

    func testAnEmptyChainIsRefusedRatherThanTreatedAsTrusted() {
        XCTAssertThrowsError(try TlsPeerVerifier.parseChain([])) { error in
            XCTAssertTrue((error as? TlsPeerVerifier.Failure)?.message.contains("no certificate") ?? false)
        }
    }

    func testBytesThatAreNotACertificateAreRefused() {
        XCTAssertThrowsError(try TlsPeerVerifier.parseChain([[UInt8](repeating: 0x41, count: 16)])) { error in
            XCTAssertTrue((error as? TlsPeerVerifier.Failure)?.message.contains("did not parse") ?? false)
        }
    }

    func testTheFixturesParse() throws {
        let chain = try TlsPeerVerifier.parseChain([
            TLSTestFixtures.p256Certificate,
            TLSTestFixtures.rsaCertificate,
        ])
        XCTAssertEqual(chain.count, 2)
    }

    func testTheCertificateVerifyContentIsLaidOutByHand() {
        let transcriptHash = [UInt8](repeating: 0x99, count: 32)
        let content = TlsPeerVerifier.certificateVerifyContent(transcriptHash)
        // "TLS 1.3, server CertificateVerify", one byte per character.
        let label: [UInt8] = [
            0x54, 0x4C, 0x53, 0x20, 0x31, 0x2E, 0x33, 0x2C, 0x20,
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20,
            0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
            0x56, 0x65, 0x72, 0x69, 0x66, 0x79,
        ]
        XCTAssertEqual(label.count, 33)
        var expected = [UInt8](repeating: 0x20, count: 64)
        expected.append(contentsOf: label)
        expected.append(0x00)
        expected.append(contentsOf: transcriptHash)
        XCTAssertEqual(content, expected)
        XCTAssertEqual(content.count, 98 + 32)
        XCTAssertEqual(content[97], 0x00)
        XCTAssertEqual(content, TLSTestFixtures.signedContent)
    }

    func testAnECDSASignatureVerifies() {
        let signature = TLSTestHex.bytes(TLSTestFixtures.p256Signature)
        let content = TLSTestFixtures.signedContent
        XCTAssertTrue(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.p256Certificate, scheme: 0x0403, signature: signature, content: content))
        var otherContent = content
        otherContent[otherContent.count - 1] ^= 0x01
        XCTAssertFalse(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.p256Certificate, scheme: 0x0403, signature: signature, content: otherContent))
        // The right signature under the wrong scheme is not a valid one.
        XCTAssertFalse(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.p256Certificate, scheme: 0x0503, signature: signature, content: content))
    }

    func testAnRSAPSSSignatureVerifies() {
        let signature = TLSTestHex.bytes(TLSTestFixtures.rsaPSSSignature)
        let content = TLSTestFixtures.signedContent
        XCTAssertTrue(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.rsaCertificate, scheme: 0x0804, signature: signature, content: content))
        XCTAssertFalse(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.rsaCertificate, scheme: 0x0401, signature: signature, content: content))
        XCTAssertFalse(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.p256Certificate, scheme: 0x0804, signature: signature, content: content))
    }

    func testAnEd25519SignatureVerifies() {
        let signature = TLSTestHex.bytes(TLSTestFixtures.ed25519Signature)
        let content = TLSTestFixtures.signedContent
        XCTAssertEqual(
            TlsPeerVerifier.ed25519PublicKey(certificateDER: TLSTestFixtures.ed25519Certificate),
            TLSTestHex.bytes(TLSTestFixtures.ed25519PublicKey)
        )
        XCTAssertTrue(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.ed25519Certificate, scheme: 0x0807, signature: signature, content: content))
        var forged = signature
        forged[0] ^= 0x80
        XCTAssertFalse(TlsPeerVerifier.verifySignature(
            certificateDER: TLSTestFixtures.ed25519Certificate, scheme: 0x0807, signature: forged, content: content))
        XCTAssertNil(TlsPeerVerifier.ed25519PublicKey(certificateDER: TLSTestFixtures.p256Certificate))
    }

    func testPinsCompareTheWholeCertificateHash() {
        let pin = Data(TLSTestHex.bytes(TLSTestFixtures.p256CertificateSHA256))
        XCTAssertEqual(TLSWire.hex(TlsPeerVerifier.sha256(TLSTestFixtures.p256Certificate)), TLSTestFixtures.p256CertificateSHA256)
        XCTAssertTrue(TlsPeerVerifier.matchesPin(TLSTestFixtures.p256Certificate, pins: [pin]))
        XCTAssertTrue(TlsPeerVerifier.matchesPin(TLSTestFixtures.p256Certificate, pins: [Data(count: 32), pin]))
        XCTAssertFalse(TlsPeerVerifier.matchesPin(TLSTestFixtures.p256Certificate, pins: [Data(count: 32)]))
        XCTAssertFalse(TlsPeerVerifier.matchesPin(TLSTestFixtures.rsaCertificate, pins: [pin]))
        XCTAssertFalse(TlsPeerVerifier.matchesPin(TLSTestFixtures.p256Certificate, pins: [pin.prefix(16)]))
    }

    func testTheUsersTrustedFingerprintsAreHonoured() {
        XCTAssertFalse(TlsPeerVerifier.isUserTrusted(TLSTestFixtures.p256Certificate))
        CertificatePolicy.setTrustedFingerprints(["00", TLSTestFixtures.p256CertificateSHA256])
        XCTAssertTrue(TlsPeerVerifier.isUserTrusted(TLSTestFixtures.p256Certificate))
        XCTAssertFalse(TlsPeerVerifier.isUserTrusted(TLSTestFixtures.rsaCertificate))
    }

    func testASelfSignedCertificateIsNotTrustedByTheSystem() async throws {
        let chain = try TlsPeerVerifier.parseChain([TLSTestFixtures.p256Certificate])
        let verdict = await TlsPeerVerifier.evaluateSystemTrust(chain, serverName: "self-signed.example")
        XCTAssertNotNil(verdict)
    }

    func testVerifyServerNeedsACertificateVerify() async {
        do {
            try await TlsPeerVerifier.verifyServer(
                certificates: [TLSTestFixtures.p256Certificate],
                serverName: "self-signed.example",
                pins: [Data(TLSTestHex.bytes(TLSTestFixtures.p256CertificateSHA256))],
                signedTranscriptHash: nil,
                scheme: 0,
                signature: nil
            )
            XCTFail("a chain without CertificateVerify was accepted")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("CertificateVerify"))
        }
    }

    func testVerifyServerAcceptsAPinnedCertificateWithItsSignature() async throws {
        try await TlsPeerVerifier.verifyServer(
            certificates: [TLSTestFixtures.p256Certificate],
            serverName: "self-signed.example",
            pins: [Data(TLSTestHex.bytes(TLSTestFixtures.p256CertificateSHA256))],
            signedTranscriptHash: [UInt8](repeating: 0x99, count: 32),
            scheme: 0x0403,
            signature: TLSTestHex.bytes(TLSTestFixtures.p256Signature)
        )
    }

    func testVerifyServerRefusesAForbiddenScheme() async {
        do {
            try await TlsPeerVerifier.verifyServer(
                certificates: [TLSTestFixtures.rsaCertificate],
                serverName: "rsa.example",
                pins: [Data(TlsPeerVerifier.sha256(TLSTestFixtures.rsaCertificate))],
                signedTranscriptHash: [UInt8](repeating: 0x99, count: 32),
                scheme: 0x0401,
                signature: TLSTestHex.bytes(TLSTestFixtures.rsaPSSSignature)
            )
            XCTFail("PKCS#1 v1.5 was accepted in a TLS 1.3 CertificateVerify")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("forbids"))
        }
    }

    func testAZlibCompressedCertificateInflates() {
        // A Certificate message body compressed with zlib (RFC 1950 framing).
        let compressed = TLSTestHex.bytes("""
            000100002c00003478da636060d06060506660646266616563e7e0e4e2e6e1e5e317101412161115139790949296919593575054\
            626000002c50029f
            """)
        let body = TLSTestHex.bytes("""
            00000028000023000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021220000
            """)
        XCTAssertEqual(TLSCertificateDecompression.decompress(compressed), body)
    }

    func testCertificateDecompressionRefusesWhatItCannotRead() {
        // Unknown algorithm, truncated body, bad zlib header.
        XCTAssertNil(TLSCertificateDecompression.decompress([0x00, 0x09, 0x00, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00]))
        XCTAssertNil(TLSCertificateDecompression.decompress([0x00, 0x01, 0x00]))
        XCTAssertNil(TLSCertificateDecompression.decompress([0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00]))
    }
}
