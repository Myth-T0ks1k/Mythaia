import Foundation
import XCTest
@testable import MythaiaKit

/// The handler's parsing, which reads bytes a server controls.
///
/// The handshake itself cannot run here — it installs keys into the native
/// QUIC connection — so what is tested is everything that happens before a
/// key is touched: the ClientHello this end builds, message framing across
/// CRYPTO frame boundaries, and refusing malformed input rather than
/// misreading it. Inbound bytes are fed with no sink, because every case below
/// must fail or wait before one would be needed.
final class QuicTlsHandlerTests: XCTestCase {

    private func makeHandler() -> QuicTlsHandler {
        return QuicTlsHandler(serverName: "example.com", alpn: ["h3"], tuning: QuicTuning.naive)
    }

    /// A handler that has sent its hello, which is where inbound bytes start.
    private func handlerAfterHello() -> QuicTlsHandler {
        let handler = makeHandler()
        XCTAssertNotNil(handler.buildClientHello())
        return handler
    }

    private func failureMentions(_ handler: QuicTlsHandler, _ text: String) -> Bool {
        guard let failure = handler.failure else { return false }
        return failure.contains(text)
    }

    // MARK: - ClientHello

    func testTheHelloIsAClientHelloCarryingTheTransportParameters() throws {
        let hello = try XCTUnwrap(makeHandler().buildClientHello())

        // Handshake type 1, then a uint24 length that frames the rest exactly.
        XCTAssertEqual(hello[0], 1)
        let length = (Int(hello[1]) << 16) | (Int(hello[2]) << 8) | Int(hello[3])
        XCTAssertEqual(length, hello.count - 4)

        // The extension must be present, under the assigned identifier.
        XCTAssertTrue(containsExtension(hello, QuicTransportParameters.extensionType))
        // And it carries what the tuning advertises, when no connection has
        // supplied its own encoding.
        XCTAssertEqual(
            extensionBody(hello, QuicTransportParameters.extensionType),
            QuicTransportParameters.encode(QuicTuning.naive.advertisedParameters)
        )
    }

    func testTheHelloOffersOnlyTls13AndAnEmptySessionId() throws {
        // RFC 9001 §4.2 forbids offering anything older than TLS 1.3 over
        // QUIC, and Go's TLS — every Hysteria and TUIC server — answers a
        // browser-shaped version list with a protocol_version alert. GREASE
        // stays, as a browser would send it.
        let hello = try XCTUnwrap(makeHandler().buildClientHello())
        let body = try XCTUnwrap(extensionBody(hello, 0x002B))

        // A one-byte list length that frames the rest, two bytes per version.
        XCTAssertFalse(body.isEmpty)
        guard !body.isEmpty else { return }
        XCTAssertEqual(Int(body[0]), body.count - 1)
        XCTAssertEqual(body.count % 2, 1)

        var versions: [Int] = []
        var index = 1
        while index + 2 <= body.count {
            versions.append((Int(body[index]) << 8) | Int(body[index + 1]))
            index += 2
        }
        XCTAssertTrue(versions.contains(0x0304))
        for version in versions {
            let grease = (version & 0x0F0F) == 0x0A0A
            XCTAssertTrue(
                version == 0x0304 || grease,
                "offers version 0x\(String(version, radix: 16))"
            )
        }

        // RFC 9001 §8.4: no middlebox compatibility mode over QUIC, so the
        // legacy session id is empty. It sits after the header, version and
        // random.
        XCTAssertEqual(hello[4 + 2 + 32], 0)
    }

    func testTheSameHelloComesBackOnARepeatRequest() throws {
        // ngtcp2 asks again when the first Initial is lost, and the transcript
        // is already committed to the first answer.
        let handler = makeHandler()
        let first = try XCTUnwrap(handler.buildClientHello())
        let second = try XCTUnwrap(handler.buildClientHello())
        XCTAssertEqual(first, second)
    }

    func testTwoHandlersDoNotShareAKeyShare() throws {
        // A reused ephemeral key would make two sessions decryptable together.
        let a = try XCTUnwrap(makeHandler().buildClientHello())
        let b = try XCTUnwrap(makeHandler().buildClientHello())
        XCTAssertNotEqual(a, b)
    }

    func testBuildingStartsTheTranscriptSoThePhaseMovesOn() {
        let handler = makeHandler()
        XCTAssertEqual(handler.phase, QuicTlsHandler.Phase.initial)
        _ = handler.buildClientHello()
        XCTAssertEqual(handler.phase, QuicTlsHandler.Phase.helloSent)
    }

    // MARK: - Message framing

    func testAMessageSplitAcrossTwoFramesWaitsForTheRest() {
        // A CRYPTO frame is not a message boundary: a ServerHello routinely
        // arrives in pieces, and treating a piece as a message loses the
        // handshake.
        let handler = handlerAfterHello()

        let half: [UInt8] = [2, 0, 0, 40, 3, 3]
        XCTAssertEqual(handler.processCryptoData(half, sink: nil), QuicTlsHandler.Outcome.needMore)
        XCTAssertEqual(handler.phase, QuicTlsHandler.Phase.helloSent)
    }

    func testFewerThanFourBytesIsNotYetAHeader() {
        let handler = handlerAfterHello()
        XCTAssertEqual(handler.processCryptoData([2, 0], sink: nil), QuicTlsHandler.Outcome.needMore)
    }

    func testAnUnknownMessageTypeIsSteppedOverNotFatal() {
        // TLS 1.3 adds message types over time and a middlebox can inject one;
        // the RFC says to ignore what is not understood.
        let handler = handlerAfterHello()

        let unknown: [UInt8] = [99, 0, 0, 2, 0xAA, 0xBB]
        XCTAssertEqual(handler.processCryptoData(unknown, sink: nil), QuicTlsHandler.Outcome.ok)
        XCTAssertNil(handler.failure)
    }

    func testAnAbsurdLengthIsRefusedRatherThanAllocated() {
        // The length field is 24 bits. Nothing in a real handshake approaches
        // it, and a corrupt one would otherwise ask for a 16 MB buffer.
        let handler = handlerAfterHello()

        let huge: [UInt8] = [2, 0xFF, 0xFF, 0xFF]
        XCTAssertEqual(handler.processCryptoData(huge, sink: nil), QuicTlsHandler.Outcome.failed)
        XCTAssertEqual(handler.phase, QuicTlsHandler.Phase.failed)
        XCTAssertNotNil(handler.failure)
    }

    func testATruncatedServerHelloIsRefusedBeforeAnyKeyIsDerived() {
        let handler = handlerAfterHello()

        // Type 2, length 4, but a ServerHello needs at least 35 bytes of body.
        let short: [UInt8] = [2, 0, 0, 4, 3, 3, 0, 0]
        XCTAssertEqual(handler.processCryptoData(short, sink: nil), QuicTlsHandler.Outcome.failed)
        XCTAssertTrue(failureMentions(handler, "ServerHello"), handler.failure ?? "no failure recorded")
    }

    func testAServerHelloNamingASuiteWeDoNotImplementIsRefused() {
        let handler = handlerAfterHello()

        // 38 bytes of body: version, random, an empty session id, a suite of
        // 0x0000 which is not one of the three TLS 1.3 AEADs, and the
        // compression method.
        var body = [UInt8](repeating: 0, count: 38)
        body[0] = 3
        body[1] = 3
        body[34] = 0                // session id length
        body[35] = 0
        body[36] = 0                // cipher suite 0x0000
        let message: [UInt8] = [2, 0, 0, UInt8(body.count)] + body

        XCTAssertEqual(handler.processCryptoData(message, sink: nil), QuicTlsHandler.Outcome.failed)
        XCTAssertTrue(failureMentions(handler, "cipher suite"), handler.failure ?? "no failure recorded")
    }

    func testAFinishedBeforeAnyServerHelloIsRefusedNotCrashedOn() {
        let handler = handlerAfterHello()

        let finished: [UInt8] = [20, 0, 0, 4, 1, 2, 3, 4]
        XCTAssertEqual(handler.processCryptoData(finished, sink: nil), QuicTlsHandler.Outcome.failed)
        XCTAssertTrue(failureMentions(handler, "ServerHello"), handler.failure ?? "no failure recorded")
    }

    // MARK: - Encryption levels

    func testTheLevelNumbersAreContiguousAndAreNotNgtcp2sOwn() {
        // These are the bridge's numbering, translated to ngtcp2's enum in C.
        // Deliberately not ngtcp2's raw values: that enum has been renumbered
        // once already — ngtcp2_crypto_level ordered them initial, early,
        // handshake, app, while ngtcp2_encryption_level orders them initial,
        // handshake, 1-RTT, 0-RTT. Constants copied from the old order install
        // handshake keys as 1-RTT keys, the handshake never completes, and
        // nothing anywhere reports why.
        XCTAssertEqual(QuicTlsHandler.levelInitial, 0)
        XCTAssertEqual(QuicTlsHandler.levelHandshake, 1)
        XCTAssertEqual(QuicTlsHandler.levelApplication, 2)
    }

    func testTheSuitesTheHandlerAcceptsAreTheThreeTls13Aeads() {
        XCTAssertNotNil(Tls13Suite.forCode(0x1301))
        XCTAssertNotNil(Tls13Suite.forCode(0x1302))
        XCTAssertNotNil(Tls13Suite.forCode(0x1303))
        XCTAssertNil(Tls13Suite.forCode(0x0000))
    }

    // MARK: - Walking the hello

    /// Whether the ClientHello carries extension `wanted`.
    private func containsExtension(_ hello: [UInt8], _ wanted: Int) -> Bool {
        return extensionBody(hello, wanted) != nil
    }

    /// The body of extension `wanted`, found by walking the ClientHello's
    /// extension list by hand rather than through the parser under test.
    private func extensionBody(_ hello: [UInt8], _ wanted: Int) -> [UInt8]? {
        var at = 4 + 2 + 32                                 // header, version, random
        if at >= hello.count { return nil }
        at += 1 + Int(hello[at])                            // session id
        if at + 2 > hello.count { return nil }
        let suitesLength = (Int(hello[at]) << 8) | Int(hello[at + 1])
        at += 2 + suitesLength
        if at >= hello.count { return nil }
        at += 1 + Int(hello[at])                            // compression methods
        if at + 2 > hello.count { return nil }

        let extensionsLength = (Int(hello[at]) << 8) | Int(hello[at + 1])
        at += 2
        let end = min(at + extensionsLength, hello.count)

        while at + 4 <= end {
            let type = (Int(hello[at]) << 8) | Int(hello[at + 1])
            let length = (Int(hello[at + 2]) << 8) | Int(hello[at + 3])
            if type == wanted {
                let start = at + 4
                if start + length > end { return nil }
                return Array(hello[start..<(start + length)])
            }
            at += 4 + length
        }
        return nil
    }
}
