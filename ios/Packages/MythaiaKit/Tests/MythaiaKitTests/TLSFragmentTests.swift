import XCTest
@testable import MythaiaKit

/// ClientHello fragmentation. The invariant that matters: however the record
/// is cut, the bytes a server reassembles must be exactly the bytes that were
/// going to be sent, and each cut must reach the stream as its own write.
final class TLSFragmentTests: XCTestCase {

    override func tearDown() {
        FragmentPolicy.set(FragmentSettings())
        super.tearDown()
    }

    /// A well-formed handshake record with a `payload`-byte body.
    private func hello(payload: Int) -> [UInt8] {
        var record: [UInt8] = [0x16, 0x03, 0x01, UInt8(payload >> 8), UInt8(payload & 0xFF)]
        for index in 0..<payload {
            record.append(UInt8(truncatingIfNeeded: index))
        }
        return record
    }

    private func payloadOf(_ record: [UInt8]) -> [UInt8] {
        return Array(record[5...])
    }

    private func declaredLength(_ record: [UInt8]) -> Int {
        return (Int(record[3]) << 8) | Int(record[4])
    }

    private func rejoined(_ pieces: [[UInt8]]) -> [UInt8] {
        var out: [UInt8] = []
        for piece in pieces { out.append(contentsOf: payloadOf(piece)) }
        return out
    }

    // MARK: - split(record, lengths)

    func testSplitsIntoTheRequestedLengthsAndPreservesThePayload() {
        let original = hello(payload: 300)
        let pieces = TlsHelloFragmenter.split(original, lengths: [100, 120, 500])

        XCTAssertEqual(pieces.count, 3)
        XCTAssertEqual(declaredLength(pieces[0]), 100)
        XCTAssertEqual(declaredLength(pieces[1]), 120)
        XCTAssertEqual(declaredLength(pieces[2]), 80)

        // Every piece is a complete record with the same type and version.
        for piece in pieces {
            XCTAssertEqual(piece[0], 0x16)
            XCTAssertEqual(piece[1], original[1])
            XCTAssertEqual(piece[2], original[2])
            XCTAssertEqual(declaredLength(piece), piece.count - 5)
        }
        XCTAssertEqual(rejoined(pieces), payloadOf(original))
    }

    func testAShortLengthsListRepeatsItsLastValue() {
        let pieces = TlsHelloFragmenter.split(hello(payload: 250), lengths: [100])
        XCTAssertEqual(pieces.map { declaredLength($0) }, [100, 100, 50])
    }

    func testARecordNoLongerThanOnePieceComesBackWhole() {
        let original = hello(payload: 50)
        XCTAssertEqual(TlsHelloFragmenter.split(original, lengths: [100]), [original])
    }

    func testNonHandshakeAndMalformedRecordsPassThroughUntouched() {
        var applicationData = hello(payload: 100)
        applicationData[0] = 0x17
        XCTAssertEqual(TlsHelloFragmenter.split(applicationData, lengths: [1]), [applicationData])

        // Declared length disagrees with the actual size.
        let truncated = Array(hello(payload: 100)[0..<60])
        XCTAssertEqual(TlsHelloFragmenter.split(truncated, lengths: [1]), [truncated])

        // Header only, no payload.
        let headerOnly: [UInt8] = [0x16, 0x00, 0x00, 0x00, 0x00]
        XCTAssertEqual(TlsHelloFragmenter.split(headerOnly, lengths: [1]), [headerOnly])

        // Empty and zero lengths are refused rather than looping.
        XCTAssertEqual(TlsHelloFragmenter.split(hello(payload: 100), lengths: []), [hello(payload: 100)])
        XCTAssertEqual(TlsHelloFragmenter.split(hello(payload: 100), lengths: [0]), [hello(payload: 100)])
    }

    // MARK: - split(record, lengthRange)

    func testRandomLengthsStayInsideTheRangeAndCoverThePayload() {
        let original = hello(payload: 1000)
        var generator = SystemRandomNumberGenerator()
        let pieces = TlsHelloFragmenter.split(original, lengthRange: 100...200, using: &generator)

        XCTAssertGreaterThan(pieces.count, 1)
        // Every piece but the last is a full draw; the last takes what remains.
        for piece in pieces.dropLast() {
            XCTAssertTrue((100...200).contains(declaredLength(piece)), "piece of \(declaredLength(piece))")
        }
        XCTAssertTrue((1...200).contains(declaredLength(pieces[pieces.count - 1])))
        XCTAssertEqual(rejoined(pieces), payloadOf(original))
    }

    func testASingleValueRangeWorks() {
        var generator = SystemRandomNumberGenerator()
        let pieces = TlsHelloFragmenter.split(hello(payload: 300), lengthRange: 100...100, using: &generator)
        XCTAssertEqual(pieces.map { declaredLength($0) }, [100, 100, 100])
    }

    func testDrawsStayInsideTheirRange() {
        var generator = TLSFragmentTestGenerator(state: 42)
        for _ in 0..<500 {
            let value = TlsHelloFragmenter.nextInRange(10...20, using: &generator)
            XCTAssertTrue((10...20).contains(value))
        }
        XCTAssertEqual(TlsHelloFragmenter.nextInRange(7...7, using: &generator), 7)
    }

    // MARK: - FinalMask shapes

    private let finalMask =
        "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"lengths\":[\"3\"],\"delays\":[\"1\"],\"maxSplit\":\"2\"}}]}"

    func testMaxSplitMakesTheSecondPieceCarryTheRest() throws {
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(finalMask))
        let record = hello(payload: 300)
        var generator = SystemRandomNumberGenerator()
        let pieces = TlsHelloFragmenter.split(record, lengthRanges: settings.lengthRanges,
                                              maxSplit: settings.maxSplit, using: &generator)
        XCTAssertEqual(pieces.count, 2)
        XCTAssertEqual(pieces[0].count, 5 + 3)
        XCTAssertEqual(pieces[1].count, 5 + 297)
        XCTAssertEqual(rejoined(pieces), payloadOf(record))
    }

    func testWithoutACapTheLastRangeKeepsDrawing() {
        var generator = SystemRandomNumberGenerator()
        let pieces = TlsHelloFragmenter.split(hello(payload: 20), lengthRanges: [3...3], maxSplit: 0, using: &generator)
        XCTAssertEqual(pieces.count, 7)
        XCTAssertEqual(pieces[pieces.count - 1].count, 5 + 2)
    }

    func testPerPieceRangesAreUsedInOrder() {
        var generator = SystemRandomNumberGenerator()
        let pieces = TlsHelloFragmenter.split(hello(payload: 100), lengthRanges: [1...1, 2...2, 10...10],
                                              maxSplit: 0, using: &generator)
        XCTAssertEqual(pieces.map { declaredLength($0) }, [1, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 7])
    }

    // MARK: - Share link forms

    func testShareLinkParsesFixedAndRangedForms() throws {
        let fixed = try XCTUnwrap(FragmentSettings.fromShareLink("3,1,tlshello"))
        XCTAssertEqual(fixed.lengthRange, 3...3)
        XCTAssertEqual(fixed.intervalRange, 1...1)

        let ranged = try XCTUnwrap(FragmentSettings.fromShareLink(" 1-10 , 5-20 , tlshello "))
        XCTAssertEqual(ranged.lengthRange, 1...10)
        XCTAssertEqual(ranged.intervalRange, 5...20)

        // A packets field other than tlshello is still taken as tlshello.
        let raw = try XCTUnwrap(FragmentSettings.fromShareLink("100-200,10-20,1-3"))
        XCTAssertEqual(raw.lengthRange, 100...200)
        XCTAssertEqual(raw.intervalRange, 10...20)
    }

    func testShareLinkRejectsMalformedValues() {
        let bad = ["", "3,1", "3,1,tlshello,extra", "a,1,tlshello", "3,b,tlshello",
                   "3,1,", "0,1,tlshello", "10-1,1,tlshello", "-5,1,tlshello"]
        for value in bad {
            XCTAssertNil(FragmentSettings.fromShareLink(value), value)
        }
    }

    func testShareLinkValueRoundTrips() throws {
        let settings = FragmentSettings(minLength: 100, maxLength: 200, minInterval: 10, maxInterval: 20)
        XCTAssertEqual(settings.toShareLinkValue(), "100-200,10-20,tlshello")
        let reparsed = try XCTUnwrap(FragmentSettings.fromShareLink(settings.toShareLinkValue()))
        XCTAssertEqual(reparsed.lengthRange, settings.lengthRange)
        XCTAssertEqual(reparsed.intervalRange, settings.intervalRange)

        let fixed = FragmentSettings(minLength: 3, maxLength: 3, minInterval: 1, maxInterval: 1)
        XCTAssertEqual(fixed.toShareLinkValue(), "3,1,tlshello")
    }

    // MARK: - Sending

    func testEachPieceIsItsOwnWriteWithThePauseBetween() async throws {
        let ends = TLSTestStreams.pair()
        let pieces = TlsHelloFragmenter.split(hello(payload: 30), lengths: [10])
        var generator = SystemRandomNumberGenerator()
        try await TlsHelloFragmenter.send(pieces, over: ends.client, delayRanges: [40...40], using: &generator)

        let writes = ends.client.sentWrites
        XCTAssertEqual(writes.map { $0.bytes }, pieces)
        for index in 1..<writes.count {
            let gap = writes[index].at.timeIntervalSince(writes[index - 1].at)
            XCTAssertGreaterThanOrEqual(gap, 0.035, "gap \(index) was \(gap) s")
        }
        ends.client.close()
    }

    func testThePauseAfterTheNthPieceComesFromTheNthDelay() async throws {
        let ends = TLSTestStreams.pair()
        let pieces = TlsHelloFragmenter.split(hello(payload: 30), lengths: [10])
        var generator = SystemRandomNumberGenerator()
        try await TlsHelloFragmenter.send(pieces, over: ends.client, delayRanges: [0...0, 60...60], using: &generator)

        let writes = ends.client.sentWrites
        XCTAssertEqual(writes.count, 3)
        let second = writes[2].at.timeIntervalSince(writes[1].at)
        XCTAssertGreaterThanOrEqual(second, 0.055)
        ends.client.close()
    }

    // MARK: - FragmentPolicy

    func testThePolicyIsOnByDefaultWithTheUsualRanges() {
        let initial = FragmentSettings()
        XCTAssertTrue(initial.isEnabled)
        XCTAssertEqual(initial.lengthRange, 100...200)
        XCTAssertEqual(initial.intervalRange, 10...20)
    }

    func testTheServersOwnSettingWinsAndOffMeansOff() {
        FragmentPolicy.set(FragmentSettings(isEnabled: true, minLength: 5, maxLength: 5))
        XCTAssertEqual(FragmentPolicy.settings.lengthRange, 5...5)

        // No setting on the server: the tunnel-wide one.
        XCTAssertEqual(FragmentPolicy.effective(for: nil)?.lengthRange, 5...5)

        // The server's own, even when it differs.
        let own = FragmentSettings(isEnabled: true, minLength: 3, maxLength: 3)
        XCTAssertEqual(FragmentPolicy.effective(for: own)?.lengthRange, 3...3)

        // A server switched off stays off, whatever the tunnel-wide value.
        XCTAssertNil(FragmentPolicy.effective(for: FragmentSettings(isEnabled: false)))

        // Tunnel-wide off and nothing on the server: no fragmentation.
        FragmentPolicy.set(FragmentSettings(isEnabled: false))
        XCTAssertNil(FragmentPolicy.effective(for: nil))
        XCTAssertNotNil(FragmentPolicy.effective(for: own))
    }

    // MARK: - The TLS client's first flight

    private func clientOptions() -> TLSClientOptions {
        return TLSClientOptions(serverName: "self-signed.example", alpn: ["h2", "http/1.1"], allowInsecure: true)
    }

    /// A handshake against the test server; returns the client's writes.
    private func handshake(
        fragment: FragmentSettings?,
        server serverOptions: TLSTestServer.Options = TLSTestServer.Options()
    ) async throws -> (writes: [(bytes: [UInt8], at: Date)], server: TLSTestServer, session: TLSSessionStream) {
        let ends = TLSTestStreams.pair()
        let server = TLSTestServer(stream: ends.server, options: serverOptions)
        let serverTask = Task { try await server.handshake() }
        do {
            let session = try await TLSClient.handshake(over: ends.client, options: clientOptions(),
                                                        fingerprint: .chrome133, fragment: fragment)
            try await serverTask.value
            return (ends.client.sentWrites, server, session)
        } catch {
            ends.server.close()
            _ = try? await serverTask.value
            throw error
        }
    }

    func testThreeBytesThenTheRestReachTheServerAsTwoRecords() async throws {
        let settings = try XCTUnwrap(FragmentSettings.fromFinalMask(finalMask))
        let result = try await handshake(fragment: settings)
        let writes = result.writes.map { $0.bytes }

        // The hello: a 3-byte record, then the rest, as separate writes.
        XCTAssertGreaterThanOrEqual(writes.count, 3)
        XCTAssertEqual(writes[0].count, 5 + 3)
        XCTAssertEqual(Array(writes[0][0..<5]), [0x16, 0x03, 0x01, 0x00, 0x03])
        XCTAssertEqual(writes[1][0], 0x16)
        XCTAssertEqual(declaredLength(writes[1]), writes[1].count - 5)

        // Together they are exactly the hello the server read.
        let hello = payloadOf(writes[0]) + payloadOf(writes[1])
        XCTAssertEqual(hello, result.server.firstClientHello)

        try await result.session.send(Data("ping".utf8))
        let atServer = try await result.server.receive()
        XCTAssertEqual(atServer, Array("ping".utf8))
        result.session.close()
    }

    func testRandomPiecesStayInRangeAndTheHandshakeCompletes() async throws {
        let settings = FragmentSettings(isEnabled: true, minLength: 100, maxLength: 200, minInterval: 1, maxInterval: 2)
        let result = try await handshake(fragment: settings)
        let writes = result.writes.map { $0.bytes }

        // The pieces of the hello come before the Finished flight, whose first
        // record is the ChangeCipherSpec.
        let helloWrites = Array(writes.prefix(while: { $0[0] == 0x16 }))
        XCTAssertGreaterThan(helloWrites.count, 1)
        for piece in helloWrites.dropLast() {
            XCTAssertTrue((100...200).contains(declaredLength(piece)), "piece of \(declaredLength(piece))")
        }
        XCTAssertEqual(rejoined(helloWrites), result.server.firstClientHello)
        result.session.close()
    }

    func testWithoutFragmentationTheHelloIsOneWrite() async throws {
        let result = try await handshake(fragment: nil)
        let first = result.writes[0].bytes
        XCTAssertEqual(payloadOf(first), result.server.firstClientHello)
        result.session.close()

        let off = try await handshake(fragment: FragmentSettings(isEnabled: false, minLength: 3, maxLength: 3))
        XCTAssertEqual(payloadOf(off.writes[0].bytes), off.server.firstClientHello)
        off.session.close()
    }

    func testOnlyTheFirstHelloIsCutWhenTheServerAsksForARetry() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.helloRetryGroup = 0x0017
        let settings = FragmentSettings(isEnabled: true, minLength: 50, maxLength: 50, minInterval: 0, maxInterval: 0)
        let result = try await handshake(fragment: settings, server: serverOptions)
        let writes = result.writes.map { $0.bytes }

        let pieces = Array(writes.prefix(while: { $0[0] == 0x16 }))
        XCTAssertGreaterThan(pieces.count, 1)
        XCTAssertEqual(rejoined(pieces), result.server.firstClientHello)

        // The retry goes out whole, after its ChangeCipherSpec, in one write.
        let second = try XCTUnwrap(result.server.secondClientHello)
        let retryWrite = writes[pieces.count]
        XCTAssertEqual(Array(retryWrite[0..<6]), [0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
        XCTAssertEqual(Array(retryWrite[11...]), second)
        result.session.close()
    }
}

/// A seeded generator, so draws are repeatable.
private struct TLSFragmentTestGenerator: RandomNumberGenerator {
    var state: UInt64

    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state ^ (state >> 29)
    }
}
