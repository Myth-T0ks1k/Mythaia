import Foundation
import XCTest
@testable import MythaiaKit

/// BLAKE3 pinned against the reference implementation's published test
/// vectors, not against what this port emits.
///
/// Input case `n` is the bytes `i mod 251` for `i` in `0..<n`; the keyed-hash
/// key and the derive-key context are the fixed strings the vector file
/// names. The lengths straddle every boundary that matters: one block (64),
/// one chunk (1024), and the tree merges past several chunks.
final class Blake3Tests: XCTestCase {
    private let key = Data("whats the Elvish word for friend".utf8)
    private let context = Data("BLAKE3 2019-12-27 16:29:52 test vectors context".utf8)

    private func seq(_ n: Int) -> Data { ProtocolTestStreams.sequence(n) }
    private func hexString(_ data: Data) -> String { ProtocolTestStreams.hexString(data) }

    private let hashes: [(Int, String)] = [
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"),
        (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b"),
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98"),
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee"),
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a"),
        (2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030"),
        (3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2"),
        (5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff"),
        (8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b"),
        (31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47"),
    ]

    private let keyedHashes: [(Int, String)] = [
        (0, "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
        (1, "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"),
        (64, "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6"),
        (1024, "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4"),
        (1025, "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69"),
        (5121, "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024"),
    ]

    private let derivedKeys: [(Int, String)] = [
        (0, "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (1024, "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
        (2049, "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
        (8193, "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1"),
    ]

    func testPlainHashMatchesThePublishedVectors() {
        for (length, expected) in hashes {
            XCTAssertEqual(hexString(Blake3.hash(seq(length))), expected, "input length \(length)")
        }
    }

    func testKeyedHashMatchesThePublishedVectors() {
        for (length, expected) in keyedHashes {
            XCTAssertEqual(hexString(Blake3.keyedHash(key: key, seq(length))), expected, "input length \(length)")
        }
    }

    func testDeriveKeyMatchesThePublishedVectors() {
        for (length, expected) in derivedKeys {
            XCTAssertEqual(hexString(Blake3.deriveKey(context: context, material: seq(length))), expected, "input length \(length)")
        }
    }

    /// The extended output: the root compressed again with a counter.
    func testExtendedOutputMatchesThePublishedVector() {
        let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd3330"
            + "50338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdb"
            + "da7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d"
        XCTAssertEqual(hexString(Blake3.hash(Data(), outputLength: 131)), expected)

        let long = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255d"
            + "e60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e562"
            + "7be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a"
        XCTAssertEqual(hexString(Blake3.hash(seq(1025), outputLength: 131)), long)
    }

    /// A 16-byte Shadowsocks key is the first half of the 32-byte derivation.
    func testShortOutputsArePrefixes() {
        let short = Blake3.deriveKey(context: context, material: seq(1), outputLength: 16)
        XCTAssertEqual(hexString(short), "b3e2e340a117a499c6cf2398a19ee0d2")
    }

    func testStringContextIsItsUtf8Bytes() {
        let fromString = Blake3.deriveKey(context: "shadowsocks 2022 identity subkey", material: seq(48))
        let fromBytes = Blake3.deriveKey(context: Data("shadowsocks 2022 identity subkey".utf8), material: seq(48))
        XCTAssertEqual(fromString, fromBytes)
        // From the reference implementation.
        XCTAssertEqual(hexString(fromString), "d03d862b5351843498b5fe4be23a74771a24cb45b0501c85bae9070b0e993f18")
    }
}
