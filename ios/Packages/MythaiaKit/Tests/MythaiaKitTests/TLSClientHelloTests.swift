import CryptoKit
import XCTest
@testable import MythaiaKit

/// The fingerprinted ClientHello: byte-exact against reference hellos, the
/// SNI and supported_versions rules, the HelloRetryRequest rewrite, and the
/// helpers that read a hello back.
final class TLSClientHelloTests: XCTestCase {

    /// Reference hellos for random[i] = 7i + 3, session id 0xA0 + i, X25519
    /// key 0x40 + i, SNI www.example.com and the default ALPN. The Android
    /// build produces the same bytes from the same inputs; a difference here
    /// is a fingerprint drifting between the two.
    private static let referenceHellos: [(TlsFingerprint, String)] = [
        (.chrome133, """
            0100020d0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001a42a\
            2a0000ff010001000023000000000014001200000f7777772e6578616d706c652e636f6d002b0007067a7a0304030344cd000500030268\
            320010000e000c02683208687474702f312e3100120000000b00020100fe0d00da0000010001cd00208149e25aee2766a5aacba514fc75\
            aefcfbbab1a09c106e20ab80bf9c56fcacf300b078c5083cfb6912c96de4fc1839a82809e0cebe24dc4e90599e48565e2776547097bc7c\
            10dc5516b57d669b34d15a8d725f42858c4917192dc93b4fc8ff4c252a3e66070dea8f13f2c75cdfdb388ce98cb9e8abcdcebea2a60d91\
            672514624d258c7260d466d89b401e08b47d3125186aaf7a8fbca2eb31dc892c53c2b0e74013fb7a1bf09320616c1edae7a3f3832469f2\
            16b11a7d5c9a15201ee8b3dd83e434e6b5d9283ab930167e764521c40410d4000d0012001004030804040105030805050108060601002d\
            00020101001b0003020002001700000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758\
            595a5b5c5d5e5f000500050100000000000a000a00089a9a001d00170018eaea0000
            """),
        (.safari26, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf002ababa130213031301c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc0\
            08c012000a010001892a2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000c000a9a9a00\
            1d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d00160014040308040401050308\
            0508050501080606010201001200000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758\
            595a5b5c5d5e5f002d00020101002b0007067a7a03040303001b0003020001eaea0000001500c600000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.ios14, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0036baba130113021303c02cc02bcca9c030c02fcca8c024c023c00ac009c028c027c014c01300\
            9d009c003d003c0035002fc008c012000a0100017d2a2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01\
            000100000a000c000a9a9a001d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d00\
            18001604030804040105030203080508050501080606010201001200000033002b00299a9a000100001d0020404142434445464748494a\
            4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d00020101002b000b0a7a7a0304030303020301eaea0000001500bb0000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.edge85, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001932a\
            2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000a00089a9a001d00170018000b000201\
            00002300000010000e000c02683208687474702f312e31000500050100000000000d001200100403080404010503080505010806060100\
            1200000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d000201\
            01002b000b0a7a7a0304030303020301001b0003020002eaea0000001500ce000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.chrome120, """
            0100020d0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001a42a\
            2a0000ff010001000023000000000014001200000f7777772e6578616d706c652e636f6d002b0007067a7a030403034469000500030268\
            320010000e000c02683208687474702f312e3100120000000b00020100fe0d00da0000010001cd00208149e25aee2766a5aacba514fc75\
            aefcfbbab1a09c106e20ab80bf9c56fcacf300b078c5083cfb6912c96de4fc1839a82809e0cebe24dc4e90599e48565e2776547097bc7c\
            10dc5516b57d669b34d15a8d725f42858c4917192dc93b4fc8ff4c252a3e66070dea8f13f2c75cdfdb388ce98cb9e8abcdcebea2a60d91\
            672514624d258c7260d466d89b401e08b47d3125186aaf7a8fbca2eb31dc892c53c2b0e74013fb7a1bf09320616c1edae7a3f3832469f2\
            16b11a7d5c9a15201ee8b3dd83e434e6b5d9283ab930167e764521c40410d4000d0012001004030804040105030805050108060601002d\
            00020101001b0003020002001700000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758\
            595a5b5c5d5e5f000500050100000000000a000a00089a9a001d00170018eaea0000
            """),
        (.edge106, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001932a\
            2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000a00089a9a001d00170018000b000201\
            00002300000010000e000c02683208687474702f312e31000500050100000000000d001200100403080404010503080505010806060100\
            1200000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d000201\
            01002b0007067a7a03040303001b0003020002446900050003026832eaea0000001500c900000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.safari16, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf002ababa130113021303c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc0\
            08c012000a010001892a2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000c000a9a9a00\
            1d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d00180016040308040401050302\
            03080508050501080606010201001200000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f50515253545556\
            5758595a5b5c5d5e5f002d00020101002b000b0a7a7a0304030303020301001b0003020001eaea0000001500c000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.qq11, """
            010001fc0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0020baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001932a\
            2a000000000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000a00089a9a001d00170018000b000201\
            00002300000010000e000c02683208687474702f312e31000500050100000000000d001200100403080404010503080505010806060100\
            1200000033002b00299a9a000100001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002d000201\
            01002b000b0a7a7a0304030303020301001b0003020002446900050003026832eaea0000001500c5000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000
            """),
        (.android11, """
            010000b50303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0018c02bc02ccca9c02fc030cca8c013c014009c009d002f00350100005400000014001200000f\
            7777772e6578616d706c652e636f6d00170000ff01000100000a00080006001d00170018000b00020100000500050100000000000d0014\
            0012040308040401050308050501080606010201
            """),
        (.browser360, """
            010000f10303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0028c00ac0140039006b0035003dc007c009c023c011c013c02700330067003200050004002f00\
            3c000a0100008000000014001200000f7777772e6578616d706c652e636f6dff01000100000a00080006001700180019000b0002010000\
            2300003374000000100022002006737064792f3206737064792f3308737064792f332e3108687474702f312e31754f0000000500050100\
            000000000d0012001004010501020104030503020304020202
            """),
    ]

    /// Chrome 133 again for random[i] = 255 - 5i, a zero session id, SNI a.test and
    /// ALPN http/1.1 only: other GREASE values and another shuffle.
    private static let chrome133Second = """
        010002010303fffaf5f0ebe6e1dcd7d2cdc8c3beb9b4afaaa5a09b96918c87827d78736e69642000000000000000000000000000000000\
        0000000000000000000000000000000000207a7a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001982a\
        2a0000000500050100000000001b0003020002fe0d00da00000100013100204761ac720d874379a713c3ad774db5012095f26241c01f2c\
        9a0d16c0a26969ed00b0c1ebe49007934d5f055501f74ebf9b972c7cd7f723bfadb37fc3ef443321197c36ac8e77401b9d5e6efe151391\
        b8e6fdc2f4e255edff05a243ea66b46847294799047b1f62bd6ac7a49e33608beeeccc5b3f2e466fc6f3fd4fe2d9a25ba4472bd8b113ed\
        961005bddf8677c37c2afc9e0307615c40346346aa93e9384aa69ab25fca6dd1100945ec65335d508af365e0e7ec7e46900522f64c06d3\
        5e1a154c7f92676f67d55cee9beafa08e1b510b8c00000000b0009000006612e74657374000b00020100002d0002010100170000000a00\
        0a0008dada001d0017001844cd000500030268320033002b0029dada000100001d0020404142434445464748494a4b4c4d4e4f50515253\
        5455565758595a5b5c5d5e5f0010000b000908687474702f312e31000d001200100403080404010503080505010806060100230000ff01\
        00010000120000002b0007063a3a03040303eaea0000
        """

    /// The Firefox profiles with the P-256 share fixed at 0x04 followed by 64
    /// zero bytes, every other input as above.
    private static let firefoxHellos: [(TlsFingerprint, String)] = [
        (.firefox148, """
            010002970303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010002\
            2c00000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00\
            0201000010000e000c02683208687474702f312e310005000501000000000022000a00080403050306030203001200000033006b006900\
            1d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0017004104000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b00050403\
            040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001b00050400010002fe0d01\
            190000010003cd00208149e25aee2766a5aacba514fc75aefcfbbab1a09c106e20ab80bf9c56fcacf300ef78c5083cfb6912c96de4fc18\
            39a82809e0cebe24dc4e90599e48565e2776547097bc7c10dc5516b57d669b34d15a8d725f42858c4917192dc93b4fc8ff4c252a3e6607\
            0dea8f13f2c75cdfdb388ce98cb9e8abcdcebea2a60d91672514624d258c7260d466d89b401e08b47d3125186aaf7a8fbca2eb31dc892c\
            53c2b0e74013fb7a1bf09320616c1edae7a3f3832469f216b11a7d5c9a15201ee8b3dd83e434e6b5d9283ab930167e764521c40410d470\
            28a79fc49661b813d8142fb6391ab82d6879b9c6d3e2dc3d70b5b76d4f1b0dabee74ce56e6e89b1656e803b9d02f3079f5f19614967456\
            4b713ae8d9ba1e
            """),
        (.firefox120, """
            0100028e0303030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc20a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
            b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035010002\
            2300000014001200000f7777772e6578616d706c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00\
            020100002300000010000e000c02683208687474702f312e310005000501000000000022000a000804030503060302030033006b006900\
            1d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f0017004104000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b00050403\
            040303000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001fe0d01190000010003cd0020\
            8149e25aee2766a5aacba514fc75aefcfbbab1a09c106e20ab80bf9c56fcacf300ef78c5083cfb6912c96de4fc1839a82809e0cebe24dc\
            4e90599e48565e2776547097bc7c10dc5516b57d669b34d15a8d725f42858c4917192dc93b4fc8ff4c252a3e66070dea8f13f2c75cdfdb\
            388ce98cb9e8abcdcebea2a60d91672514624d258c7260d466d89b401e08b47d3125186aaf7a8fbca2eb31dc892c53c2b0e74013fb7a1b\
            f09320616c1edae7a3f3832469f216b11a7d5c9a15201ee8b3dd83e434e6b5d9283ab930167e764521c40410d47028a79fc49661b813d8\
            142fb6391ab82d6879b9c6d3e2dc3d70b5b76d4f1b0dabee74ce56e6e89b1656e803b9d02f3079f5f196149674564b713ae8d9ba1e
            """),
    ]

    private let random = (0..<32).map { UInt8($0 * 7 + 3) }
    private let sessionId = (0..<32).map { UInt8(0xA0 + $0) }
    private let publicKey = (0..<32).map { UInt8(0x40 + $0) }

    func testEveryDeterministicFingerprintMatchesItsReference() {
        for (fingerprint, expected) in TLSClientHelloTests.referenceHellos {
            let hello = TlsClientHelloBuilder.buildRawClientHello(
                fingerprint: fingerprint,
                random: random,
                sessionId: sessionId,
                serverName: "www.example.com",
                publicKey: publicKey,
                alpn: nil,
                omitPQKeyShares: true
            )
            XCTAssertEqual(TLSWire.hex(hello), expected, "\(fingerprint)")
        }
    }

    func testChrome133WithAnotherRandomMatchesItsReference() {
        let otherRandom = (0..<32).map { UInt8(255 - $0 * 5) }
        let hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome133,
            random: otherRandom,
            sessionId: [UInt8](repeating: 0, count: 32),
            serverName: "a.test",
            publicKey: publicKey,
            alpn: ["http/1.1"],
            omitPQKeyShares: true
        )
        XCTAssertEqual(TLSWire.hex(hello), TLSClientHelloTests.chrome133Second)
    }

    func testFirefoxMatchesItsReference() {
        var p256: [UInt8] = [0x04]
        p256.append(contentsOf: [UInt8](repeating: 0, count: 64))
        for (fingerprint, expected) in TLSClientHelloTests.firefoxHellos {
            let hello = TlsClientHelloBuilder.buildRawClientHello(
                fingerprint: fingerprint,
                random: random,
                sessionId: sessionId,
                serverName: "www.example.com",
                publicKey: publicKey,
                omitPQKeyShares: true,
                p256PublicKey: p256
            )
            XCTAssertEqual(TLSWire.hex(hello), expected, "\(fingerprint)")
        }
    }

    func testPaddedProfilesComeOutAt512Bytes() {
        // BoringSSL pads a hello of 256 to 511 bytes to exactly 512.
        let hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .safari26,
            random: random,
            sessionId: sessionId,
            serverName: "www.example.com",
            publicKey: publicKey
        )
        XCTAssertEqual(hello.count, 512)
        XCTAssertNotNil(TlsClientHelloBuilder.extensionBody(in: hello, type: 0x0015))
    }

    func testFirefoxCarriesTheP256ShareItWasGiven() {
        let p256 = Array(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        for fingerprint in [TlsFingerprint.firefox148, .firefox120] {
            let hello = TlsClientHelloBuilder.buildRawClientHello(
                fingerprint: fingerprint,
                random: random,
                sessionId: sessionId,
                serverName: "www.example.com",
                publicKey: publicKey,
                omitPQKeyShares: true,
                p256PublicKey: p256
            )
            XCTAssertEqual(TlsClientHelloBuilder.keyShareGroups(in: hello), [0x001D, 0x0017], "\(fingerprint)")
            let shares = TLSTestServer.keyShares(in: hello)
            XCTAssertEqual(shares.first(where: { $0.group == 0x0017 })?.key, p256, "\(fingerprint)")
            XCTAssertEqual(shares.first(where: { $0.group == 0x001D })?.key, publicKey, "\(fingerprint)")
            // Firefox does not pad.
            XCTAssertNil(TlsClientHelloBuilder.extensionBody(in: hello, type: 0x0015), "\(fingerprint)")
        }
    }

    func testTheHelloStillOffersTls12() {
        let hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome133,
            random: (0..<32).map { UInt8($0) },
            sessionId: [UInt8](repeating: 0, count: 32),
            serverName: "public.example",
            publicKey: [UInt8](repeating: 7, count: 32),
            omitPQKeyShares: true
        )
        let versions = TlsClientHelloBuilder.extensionBody(in: hello, type: 0x002B) ?? []
        var offered: [Int] = []
        var index = 1
        while index + 2 <= versions.count {
            offered.append((Int(versions[index]) << 8) | Int(versions[index + 1]))
            index += 2
        }
        XCTAssertTrue(offered.contains(0x0303))
        XCTAssertTrue(offered.contains(0x0304))
        XCTAssertEqual(Int(versions.first ?? 0), versions.count - 1)
        XCTAssertTrue(TlsClientHelloBuilder.offersTls13(hello))
    }

    func testTls12OnlyProfilesDoNotOfferTls13() {
        for fingerprint in [TlsFingerprint.android11, .browser360] {
            let hello = TlsClientHelloBuilder.buildRawClientHello(
                fingerprint: fingerprint,
                random: random,
                sessionId: sessionId,
                serverName: "www.example.com",
                publicKey: publicKey
            )
            XCTAssertFalse(TlsClientHelloBuilder.offersTls13(hello), "\(fingerprint)")
        }
    }

    func testSniCarriesTheALabelAndIsLeftOutForAnIpLiteral() {
        let named = TlsClientHelloBuilder.buildSNIExtension("bücher.example")
        XCTAssertEqual(TLSWire.hex(named), "0000001a0018000015786e2d2d62636865722d6b76612e6578616d706c65")
        let name = String(decoding: named[9...], as: UTF8.self)
        XCTAssertEqual(name, "xn--bcher-kva.example")

        XCTAssertEqual(TlsClientHelloBuilder.buildSNIExtension("203.0.113.5").count, 0)
        XCTAssertEqual(TlsClientHelloBuilder.buildSNIExtension("2001:db8::1").count, 0)
        XCTAssertEqual(TlsClientHelloBuilder.buildSNIExtension("").count, 0)
    }

    func testPunycodeAndALabels() {
        XCTAssertEqual(TLSHostName.punycodeEncode("bücher"), "bcher-kva")
        XCTAssertEqual(TLSHostName.punycodeEncode("münchen"), "mnchen-3ya")
        XCTAssertEqual(TLSHostName.punycodeEncode("日本語"), "wgv71a119e")
        XCTAssertEqual(TLSHostName.punycodeEncode("правительство"), "80aealotwbjpid2k")
        XCTAssertEqual(TLSHostName.punycodeEncode("a-ü-b"), "a--b-1ra")
        // Non-ASCII labels are case-folded first; ASCII labels pass through.
        XCTAssertEqual(TLSHostName.asciiName("ÄÖÜ.de"), "xn--4ca0bs.de")
        XCTAssertEqual(TLSHostName.asciiName("Example.COM"), "Example.COM")
        XCTAssertEqual(TLSHostName.asciiName("shop.bücher.example"), "shop.xn--bcher-kva.example")
    }

    func testIpLiterals() {
        XCTAssertTrue(TLSHostName.isIpLiteral("203.0.113.5"))
        XCTAssertTrue(TLSHostName.isIpLiteral("2001:db8::1"))
        XCTAssertFalse(TLSHostName.isIpLiteral("example.com"))
        XCTAssertFalse(TLSHostName.isIpLiteral(""))
        XCTAssertFalse(TLSHostName.isIpLiteral("1.2.3.example"))
    }

    func testRandomResolvesFromTheFirstRandomByte() {
        var pick = [UInt8](repeating: 0, count: 32)
        for index in 1..<32 { pick[index] = UInt8(index) }
        pick[0] = 5
        XCTAssertEqual(TlsClientHelloBuilder.resolveFingerprint(.random, random: pick), .chrome120)
        let viaRandom = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .random, random: pick, sessionId: [UInt8](repeating: 0, count: 32),
            serverName: "r.test", publicKey: publicKey, omitPQKeyShares: true
        )
        let direct = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome120, random: pick, sessionId: [UInt8](repeating: 0, count: 32),
            serverName: "r.test", publicKey: publicKey, omitPQKeyShares: true
        )
        XCTAssertEqual(viaRandom, direct)
        XCTAssertEqual(TlsClientHelloBuilder.resolveFingerprint(.safari26, random: pick), .safari26)
    }

    func testAPQShareGoesOutOnlyWithARealKey() {
        let encapsulationKey = [UInt8](repeating: 0x33, count: 1184)
        let withKey = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome133, random: random, sessionId: sessionId,
            serverName: "www.example.com", publicKey: publicKey,
            omitPQKeyShares: false, mlkemEncapsulationKey: encapsulationKey
        )
        let groups = TlsClientHelloBuilder.keyShareGroups(in: withKey)
        XCTAssertTrue(groups.contains(0x11EC))
        let hybrid = TLSTestServer.keyShares(in: withKey).first(where: { $0.group == 0x11EC })?.key
        XCTAssertEqual(hybrid, encapsulationKey + publicKey)

        let omitted = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome133, random: random, sessionId: sessionId,
            serverName: "www.example.com", publicKey: publicKey,
            omitPQKeyShares: true, mlkemEncapsulationKey: encapsulationKey
        )
        XCTAssertFalse(TlsClientHelloBuilder.keyShareGroups(in: omitted).contains(0x11EC))
    }

    func testTheHelloParsesBack() throws {
        let hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .chrome133, random: random, sessionId: sessionId,
            serverName: "www.example.com", publicKey: publicKey, omitPQKeyShares: true
        )
        let parsed = try TlsClientHelloBuilder.parse(hello)
        XCTAssertEqual(parsed.random, random)
        XCTAssertEqual(parsed.sessionId, sessionId)
        XCTAssertEqual(parsed.cipherSuites.count, 32)
        XCTAssertEqual(parsed.extensions.count, 18)
        XCTAssertEqual(TLSHandshakeDriver.alpnProtocols(in: hello), ["h2", "http/1.1"])
        XCTAssertEqual(TLSHandshakeDriver.supportedGroups(in: hello).count, 4)
        // The GREASE share first, then X25519.
        let groups = TlsClientHelloBuilder.keyShareGroups(in: hello)
        XCTAssertEqual(groups.count, 2)
        XCTAssertTrue(TlsClientHelloBuilder.isGREASE(groups[0]))
        XCTAssertEqual(groups[1], 0x001D)
    }

    func testTheRetryHelloKeepsEverythingButTheShare() throws {
        let first = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: .safari26, random: random, sessionId: sessionId,
            serverName: "www.example.com", publicKey: publicKey, omitPQKeyShares: true
        )
        let p256 = Array(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let cookie: [UInt8] = [0xC0, 0x0C, 0x1E]
        let second = try TlsClientHelloBuilder.retryClientHello(first, keyShare: (group: 0x0017, key: p256), cookie: cookie)

        let before = try TlsClientHelloBuilder.parse(first)
        let after = try TlsClientHelloBuilder.parse(second)
        XCTAssertEqual(after.random, before.random)
        XCTAssertEqual(after.sessionId, before.sessionId)
        XCTAssertEqual(after.cipherSuites, before.cipherSuites)
        XCTAssertEqual(TlsClientHelloBuilder.keyShareGroups(in: second), [0x0017])
        XCTAssertEqual(TLSTestServer.keyShares(in: second).first?.key, p256)
        XCTAssertEqual(TlsClientHelloBuilder.extensionBody(in: second, type: 0x002C), [0x00, 0x03, 0xC0, 0x0C, 0x1E])

        // The cookie follows key_share; every other extension keeps its place.
        let typesBefore = before.extensions.map { $0.type }.filter { $0 != 0x0015 }
        var typesAfter = after.extensions.map { $0.type }.filter { $0 != 0x0015 }
        let keyShareIndex = try XCTUnwrap(typesAfter.firstIndex(of: 0x0033))
        XCTAssertEqual(typesAfter[keyShareIndex + 1], 0x002C)
        typesAfter.remove(at: keyShareIndex + 1)
        XCTAssertEqual(typesAfter, typesBefore)

        // The bigger share and the cookie still fit under 512 bytes, so the
        // padding is recomputed to land on 512 again, at the end.
        XCTAssertEqual(second.count, 512)
        XCTAssertEqual(after.extensions.last?.type, 0x0015)
        XCTAssertEqual(TLSWire.u24(second, 1), second.count - 4)
    }

    func testRecordWrapping() {
        let record = TlsClientHelloBuilder.wrapInTLSRecord([0x01, 0x00, 0x00, 0x00])
        XCTAssertEqual(record, [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
    }
}
