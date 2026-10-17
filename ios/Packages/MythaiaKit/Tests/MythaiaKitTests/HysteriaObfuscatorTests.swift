import Foundation
import XCTest
@testable import MythaiaKit

/// Hysteria2 obfuscation against fixed vectors rather than against itself.
///
/// The chain is deliberate. First the BLAKE2b implementation is pinned to the
/// published BLAKE2b-256 vectors, which establishes that the primitive is the
/// one the protocol names. Then the keystream is pinned to
/// `BLAKE2b-256(password ‖ salt)` for a fixed password and salt. Then whole
/// datagrams — salamander ones and gecko fragments alike — are built by hand
/// from those bytes and fed to `open`, so the decoder is exercised against
/// input this code never produced.
///
/// That ordering matters because a round trip is nearly worthless here on its
/// own: hashing `salt ‖ password` instead of `password ‖ salt`, using
/// BLAKE2b-512 truncated, or cycling the key at the wrong period all round-trip
/// perfectly and all fail against a real server, which drops the packet without
/// saying anything.
final class HysteriaObfuscatorTests: XCTestCase {

    private let password = "gecko-and-salamander"

    private func bytes(_ hex: String) -> [UInt8] {
        let digits = Array(hex.utf8)
        var out: [UInt8] = []
        var index = 0
        while index + 1 < digits.count {
            let pair = String(decoding: digits[index..<(index + 2)], as: UTF8.self)
            guard let value = UInt8(pair, radix: 16) else {
                XCTFail("not hex: \(pair)")
                return []
            }
            out.append(value)
            index += 2
        }
        return out
    }

    private func hexString(_ bytes: [UInt8]) -> String {
        return bytes.map { byte -> String in
            let digits = String(byte, radix: 16)
            return digits.count == 1 ? "0" + digits : digits
        }.joined()
    }

    /// The salt used for every hand-built salamander vector below: 00 01 .. 07.
    private let salt: [UInt8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]

    /// BLAKE2b-256("gecko-and-salamander" ‖ 00 01 02 03 04 05 06 07).
    ///
    /// Computed with an independent BLAKE2b (Python's `hashlib.blake2b`,
    /// `digest_size=32`), which the first test below cross-checks against the
    /// published BLAKE2b-256 digests so the oracle itself is not taken on trust.
    private var keystream: [UInt8] {
        return bytes("4b573de086e062590efde6ab76057f96c276f1ff61806ada148f8c209140da13")
    }

    /// 0x00..0x2f XORed with the keystream, which wraps back to its first byte
    /// at offset 32.
    private var ciphertext48: [UInt8] {
        return bytes(
            "4b563fe382e5645e06f4eca07a087199d267e3ec75957ccd0c96963b8d5dc40c" +
                "6b761fc3a2c5447e26d4cc805a2851b9"
        )
    }

    // MARK: - The primitive

    func testBlake2b256MatchesThePublishedDigests() {
        // These two are the standard BLAKE2b-256 vectors. If this fails,
        // everything below is measuring the wrong hash.
        XCTAssertEqual(
            hexString(Blake2b.hash([], outputLength: 32)),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        )
        XCTAssertEqual(
            hexString(Blake2b.hash(Array("abc".utf8), outputLength: 32)),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        )
    }

    // MARK: - Salamander

    func testTheKeystreamIsBlake2b256OverPasswordThenSalt() throws {
        // XORing a run of zeroes leaves the keystream itself in the clear, so
        // this reads the derived key straight back out of the decoder.
        let obfuscator = try SalamanderPacketObfuscator(password: password)
        let recovered = try XCTUnwrap(obfuscator.open(salt + [UInt8](repeating: 0, count: 32)))
        XCTAssertEqual(recovered, keystream)
    }

    func testTheKeystreamCyclesEvery32BytesSoALongPacketReusesIt() throws {
        // Hand-built: 48 bytes of 0x00..0x2f XORed with the keystream, which
        // wraps back to its first byte at offset 32.
        let payload = (0..<48).map { UInt8($0) }
        let ciphertext = ciphertext48
        let obfuscator = try SalamanderPacketObfuscator(password: password)
        let recovered = try XCTUnwrap(obfuscator.open(salt + ciphertext))
        XCTAssertEqual(recovered, payload)

        // The wrap is the part a hand-rolled keystream gets wrong, so assert it
        // directly too: byte 32 of the stream equals byte 0.
        let stream = (0..<48).map { ciphertext[$0] ^ payload[$0] }
        XCTAssertEqual(Array(stream[0..<32]), keystream)
        XCTAssertEqual(Array(stream[32..<48]), Array(keystream[0..<16]))
    }

    func testSealThenOpenIsTheIdentity() throws {
        let obfuscator = try HysteriaObfuscators.make(.salamander(password: password))
        for size in [1, 16, 32, 33, 1200, 1500] {
            let packet = (0..<size).map { UInt8(truncatingIfNeeded: $0 * 31 + 7) }
            let sealed = obfuscator.seal(packet)
            XCTAssertEqual(sealed.count, 1, "size \(size)")
            guard let datagram = sealed.first else { continue }
            XCTAssertEqual(obfuscator.open(datagram), packet, "size \(size)")
        }
    }

    func testASalamanderDatagramIsExactlySaltPlusPacket() throws {
        let obfuscator = try SalamanderPacketObfuscator(password: password)
        for size in [1, 64, 1200] {
            XCTAssertEqual(
                obfuscator.seal([UInt8](repeating: 0, count: size)).first?.count,
                SalamanderObfuscator.saltLength + size
            )
        }
    }

    func testADifferentPasswordDoesNotRecoverThePacket() throws {
        // Fixed bytes, so this is a statement about the key derivation and not
        // a lucky draw: the same datagram under the wrong password must not
        // come back as 0x00..0x2f.
        let payload = (0..<48).map { UInt8($0) }
        let datagram = salt + ciphertext48
        let wrongObfuscator = try SalamanderPacketObfuscator(password: "wrong-password")
        let wrong = try XCTUnwrap(wrongObfuscator.open(datagram))
        XCTAssertEqual(wrong.count, payload.count)
        XCTAssertNotEqual(wrong, payload)

        // And the failure is total, not a near miss: BLAKE2b-256 of the wrong
        // password with the same salt begins 0xa1, so the first byte comes out
        // 0x4b xor 0xa1 = 0xea instead of 0x00.
        XCTAssertEqual(wrong.first, 0xEA)
    }

    // MARK: - Gecko wire format

    private func gecko(
        password pw: String? = nil,
        min: Int = HysteriaObfuscation.geckoMinPacketSizeDefault,
        max: Int = HysteriaObfuscation.geckoMaxPacketSizeDefault
    ) throws -> GeckoObfuscator {
        return try GeckoObfuscator(password: pw ?? password, minPacketSize: min, maxPacketSize: max)
    }

    /// The 16-byte long-header packet the hand-built fragments below carry.
    private var fragmentedPacket: [UInt8] {
        return bytes("c00102030405060708090a0b0c0d0e0f")
    }

    /// Fragment 0 of message 0x2a, 2 chunks, 3 bytes of padding, carrying
    /// `c0 01 .. 07`.
    ///
    /// Built by hand as `80 2a 02 00 03 | aa bb cc | c001020304050607`, then
    /// XORed with BLAKE2b-256(password ‖ 10*8) and prefixed with that salt.
    private var handBuiltFragment0: [UInt8] {
        return bytes("10101010101010100ee3dece31812ab3813ff3d3b1d690ab")
    }

    /// Fragment 1 of the same message: `80 2a 12 00 00 | 08090a0b0c0d0e0f`,
    /// XORed with BLAKE2b-256(password ‖ 20*8) under that salt. No padding, to
    /// cover the zero-pad path where the payload starts right after the header.
    private var handBuiltFragment1: [UInt8] {
        return bytes("20202020202020201b6d65d965c5af5fed871954dd")
    }

    func testHandBuiltFragmentsReassembleIntoTheOriginalPacket() throws {
        let obfuscator = try gecko()
        // The first fragment yields nothing: there is no packet to deliver yet.
        XCTAssertNil(obfuscator.open(handBuiltFragment0))
        XCTAssertEqual(obfuscator.open(handBuiltFragment1), fragmentedPacket)
    }

    func testFragmentsArrivingOutOfOrderStillReassemble() throws {
        // Reassembly is keyed by the index in the header, not by arrival order,
        // which is the only thing that makes this safe over UDP.
        let obfuscator = try gecko()
        XCTAssertNil(obfuscator.open(handBuiltFragment1))
        XCTAssertEqual(obfuscator.open(handBuiltFragment0), fragmentedPacket)
    }

    func testARepeatedFragmentIsIgnoredRatherThanCountedTwice() throws {
        let obfuscator = try gecko()
        XCTAssertNil(obfuscator.open(handBuiltFragment0))
        XCTAssertNil(obfuscator.open(handBuiltFragment0))
        // If the duplicate had counted, the message would have "completed" here
        // holding a missing second chunk.
        XCTAssertEqual(obfuscator.open(handBuiltFragment1), fragmentedPacket)
    }

    func testAnIncompleteMessageYieldsNothing() throws {
        XCTAssertNil(try gecko().open(handBuiltFragment0))
    }

    func testADifferentPasswordDoesNotReassembleTheFragments() throws {
        let obfuscator = try gecko(password: "wrong-password")
        let results = [obfuscator.open(handBuiltFragment0), obfuscator.open(handBuiltFragment1)].compactMap { $0 }
        XCTAssertFalse(results.contains(fragmentedPacket))
    }

    // MARK: - Gecko behaviour

    func testALongHeaderPacketRoundTripsThroughFragmentation() throws {
        let sender = try gecko()
        let receiver = try gecko()
        var packet = (0..<1200).map { UInt8(truncatingIfNeeded: $0 * 13 + 5) }
        packet[0] = 0xC0

        for _ in 0..<50 {
            let datagrams = sender.seal(packet)
            XCTAssertTrue((GeckoObfuscator.minChunks...GeckoObfuscator.maxChunks).contains(datagrams.count),
                          "\(datagrams.count) datagrams")

            let delivered = datagrams.compactMap { receiver.open($0) }
            XCTAssertEqual(delivered.count, 1)
            XCTAssertEqual(delivered.first, packet)
        }
    }

    func testAShortHeaderPacketIsNotFragmented() throws {
        // 1-RTT traffic reveals little on its own, so it rides salamander alone
        // rather than paying the per-fragment overhead.
        let obfuscator = try gecko()
        var packet = (0..<600).map { UInt8(truncatingIfNeeded: $0 * 3) }
        packet[0] = 0x40
        let datagrams = obfuscator.seal(packet)
        XCTAssertEqual(datagrams.count, 1)
        guard let datagram = datagrams.first else { return }
        XCTAssertEqual(datagram.count, SalamanderObfuscator.saltLength + packet.count)
        XCTAssertEqual(obfuscator.open(datagram), packet)
    }

    func testAnEmptyPacketProducesNoDatagrams() throws {
        XCTAssertTrue(try gecko().seal([]).isEmpty)
    }

    func testEveryFragmentIsPaddedIntoTheConfiguredSizeWindow() throws {
        let obfuscator = try gecko(min: 512, max: 1200)
        var packet = (0..<1200).map { UInt8(truncatingIfNeeded: $0) }
        packet[0] = 0xC0
        var counts = Set<Int>()

        for _ in 0..<300 {
            let datagrams = obfuscator.seal(packet)
            counts.insert(datagrams.count)
            for datagram in datagrams where !(512...1200).contains(datagram.count) {
                XCTFail("size \(datagram.count) outside 512...1200")
            }
        }
        // The whole 2...8 range should have been exercised; otherwise the bound
        // above was only checked for one chunk count.
        XCTAssertEqual(counts, Set(2...8))
    }

    func testAChunkLargerThanTheMaximumIsSentUnpaddedRatherThanSplitAgain() throws {
        // 8000 bytes over at most 8 chunks leaves every chunk above 600, so the
        // window is unreachable and padding must be skipped entirely. Sealed
        // size is then exactly salt + header + chunk.
        let obfuscator = try gecko(min: 512, max: 600)
        var packet = (0..<8000).map { UInt8(truncatingIfNeeded: $0) }
        packet[0] = 0xC0

        for _ in 0..<50 {
            let datagrams = obfuscator.seal(packet)
            let overhead = SalamanderObfuscator.saltLength + GeckoObfuscator.headerLength
            XCTAssertEqual(
                datagrams.reduce(0) { $0 + $1.count },
                packet.count + overhead * datagrams.count
            )
            XCTAssertTrue(datagrams.allSatisfy { $0.count > 600 })
        }
    }

    func testFragmentsOfDifferentMessagesDoNotBleedIntoEachOther() throws {
        let sender = try gecko()
        let receiver = try gecko()
        var first = (0..<400).map { UInt8(truncatingIfNeeded: $0) }
        first[0] = 0xC0
        var second = (0..<400).map { UInt8(truncatingIfNeeded: 255 - $0) }
        second[0] = 0xC0

        let a = sender.seal(first)
        let b = sender.seal(second)
        // Interleaved, which is what a real network produces. The two messages
        // rarely have the same fragment count, so this cannot be a zip.
        var interleaved: [[UInt8]] = []
        for index in 0..<Swift.max(a.count, b.count) {
            if index < a.count { interleaved.append(a[index]) }
            if index < b.count { interleaved.append(b[index]) }
        }
        let delivered = interleaved.compactMap { receiver.open($0) }

        XCTAssertEqual(delivered.count, 2)
        XCTAssertTrue(delivered.contains(first))
        XCTAssertTrue(delivered.contains(second))
    }

    func testATruncatedOrNonsensicalFragmentHeaderIsRejected() throws {
        let obfuscator = try gecko()
        let inner = try SalamanderObfuscator(password: password)

        // A chunk count outside 2...8 cannot have come from a real sender; the
        // count lives in a nibble, so 0, 1 and 9...15 are all reachable by a
        // corrupted or hostile byte.
        for total in [0, 1, 9, 15] {
            let frame: [UInt8] = [0x80, 0x01, UInt8(total), 0x00, 0x00, 0x11]
            XCTAssertNil(obfuscator.open(inner.seal(frame)), "total=\(total)")
        }
        // An index at or beyond the count has nowhere to go.
        XCTAssertNil(obfuscator.open(inner.seal([0x80, 0x02, 0x22, 0x00, 0x00, 0x11])))
        // A pad length that runs off the end of the frame.
        XCTAssertNil(obfuscator.open(inner.seal([0x80, 0x03, 0x02, 0x00, 0xFF])))
        // Fewer bytes than the header itself.
        XCTAssertNil(obfuscator.open(inner.seal([0x80, 0x04])))
        // Not even a salt.
        XCTAssertNil(obfuscator.open([UInt8](repeating: 0, count: 4)))
    }

    func testAMessageIdReusedWithADifferentChunkCountStartsOver() throws {
        // Otherwise a stale half-message would poison the id until it expired.
        let obfuscator = try gecko()
        let inner = try SalamanderObfuscator(password: password)
        func fragment(_ messageId: Int, _ index: Int, _ total: Int, _ payload: [UInt8]) -> [UInt8] {
            let header: [UInt8] = [0x80, UInt8(messageId), UInt8((index << 4) | total), 0x00, 0x00]
            return inner.seal(header + payload)
        }

        XCTAssertNil(obfuscator.open(fragment(7, 0, 3, [0x11])))
        // Same id, now claiming two chunks: the three-chunk attempt is dropped.
        XCTAssertNil(obfuscator.open(fragment(7, 0, 2, [0x22])))
        XCTAssertEqual(obfuscator.open(fragment(7, 1, 2, [0x33])), [0x22, 0x33])
    }

    // MARK: - Configuration

    private func assertSizes(_ actual: (Int, Int), _ low: Int, _ high: Int,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(actual.0, low, "minimum", file: file, line: line)
        XCTAssertEqual(actual.1, high, "maximum", file: file, line: line)
    }

    func testGeckoSizesFallBackClampAndUnInvert() {
        let defaultLow = HysteriaObfuscation.geckoMinPacketSizeDefault
        let defaultHigh = HysteriaObfuscation.geckoMaxPacketSizeDefault

        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(nil, nil), defaultLow, defaultHigh)
        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(0, 0), defaultLow, defaultHigh)
        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(-5, -1), defaultLow, defaultHigh)

        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(100, 900), 100, 900)
        // Clamped to the 0...2048 range.
        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(9000, 9000), 2048, 2048)
        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(100, 99999), 100, 2048)
        // An inverted maximum is raised to the minimum, not swapped with it.
        assertSizes(HysteriaObfuscation.normalizedGeckoSizes(900, 100), 900, 900)
    }

    func testAConfigIsBuiltFromTheWireTag() {
        XCTAssertEqual(
            HysteriaObfuscation.make(type: "salamander", password: "s3cret"),
            HysteriaObfuscation.salamander(password: "s3cret")
        )
        // Tags arrive from links and YAML in whatever case the author used.
        XCTAssertEqual(
            HysteriaObfuscation.make(type: "SALAMANDER", password: "s3cret"),
            HysteriaObfuscation.salamander(password: "s3cret")
        )
        XCTAssertEqual(
            HysteriaObfuscation.make(type: "Gecko", password: "s3cret"),
            HysteriaObfuscation.gecko(password: "s3cret", minPacketSize: 512, maxPacketSize: 1200)
        )
        XCTAssertEqual(
            HysteriaObfuscation.make(type: "gecko", password: "s3cret", geckoMinPacketSize: 300, geckoMaxPacketSize: 700),
            HysteriaObfuscation.gecko(password: "s3cret", minPacketSize: 300, maxPacketSize: 700)
        )
        // Unknown, empty and absent types are all "the caller decides".
        XCTAssertNil(HysteriaObfuscation.make(type: "chameleon", password: "s3cret"))
        XCTAssertNil(HysteriaObfuscation.make(type: "", password: "s3cret"))
        XCTAssertNil(HysteriaObfuscation.make(type: nil, password: "s3cret"))
        // A missing password is not an error here; it becomes empty.
        XCTAssertEqual(HysteriaObfuscation.make(type: "salamander", password: nil)?.password, "")
    }

    func testTheWireTagsAreTheOnesTheProtocolNames() {
        XCTAssertEqual(HysteriaObfuscation.salamander(password: "x").typeTag, "salamander")
        XCTAssertEqual(HysteriaObfuscation.gecko(password: "x", minPacketSize: 512, maxPacketSize: 1200).typeTag, "gecko")
    }

    func testTheFactoryReturnsTheModeTheConfigAskedFor() throws {
        let salamander = try HysteriaObfuscators.make(.salamander(password: password))
        XCTAssertNotNil(salamander as? SalamanderPacketObfuscator)
        let geckoConfig = HysteriaObfuscation.gecko(password: password, minPacketSize: 512, maxPacketSize: 1200)
        XCTAssertNotNil(try HysteriaObfuscators.make(geckoConfig) as? GeckoObfuscator)
    }

    func testAPasswordTheReferenceWouldRejectIsRefusedAtSetup() {
        // Failing here beats a connection that silently never completes.
        let configs: [HysteriaObfuscation] = [
            .salamander(password: "abc"),
            .gecko(password: "abc", minPacketSize: 512, maxPacketSize: 1200),
        ]
        for config in configs {
            XCTAssertThrowsError(try HysteriaObfuscators.make(config), "expected a refusal for \(config.typeTag)")
        }
    }
}
