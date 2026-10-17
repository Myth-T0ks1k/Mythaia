import Foundation
import XCTest
@testable import MythaiaKit

/// NaiveProxy's padding negotiation and framing, byte for byte as Chrome's
/// NaiveProxy client puts them on the wire.
final class ProtocolNaiveTests: XCTestCase {
    // MARK: - Negotiation

    func testPaddingValueUsesOnlyCharactersHpackCannotShrink() {
        let allowed = Set(NaivePaddingNegotiator.nonIndexCodes)
        for _ in 0..<100 {
            let value = Array(NaivePaddingNegotiator.generatePaddingValue().utf8)
            XCTAssertTrue((16...32).contains(value.count), "length \(value.count)")
            XCTAssertTrue(value.allSatisfy { allowed.contains($0) })
            // Past the first sixteen, only 'X'.
            XCTAssertTrue(value.dropFirst(16).allSatisfy { $0 == 0x58 })
        }
    }

    func testRequestHeadersAskForVariantOneThenNone() {
        let headers = NaivePaddingNegotiator.requestHeaders()
        XCTAssertEqual(headers.map { $0.name }, ["padding", "padding-type-request"])
        XCTAssertEqual(headers[1].value, "1, 0")
        XCTAssertEqual(NaivePaddingNegotiator.requestHeaders(fastOpen: true).last, HpackHeader("fastopen", "1"))
    }

    func testConnectHeadersCarryCredentialsAndTheBrowserAgentFirst() {
        let headers = NaiveClient.requestHeaders(username: "user", password: "pass")
        XCTAssertEqual(headers.map { $0.name }, ["proxy-authorization", "user-agent", "padding", "padding-type-request"])
        XCTAssertEqual(headers[0].value, "Basic dXNlcjpwYXNz")
        XCTAssertEqual(NaiveClient.requestHeaders(username: nil, password: nil).first?.name, "user-agent")
    }

    func testResponseDecidesThePadding() {
        XCTAssertEqual(NaivePaddingNegotiator.parseResponse([HpackHeader(":status", "200"), HpackHeader("padding-type-reply", " 1 ")]), .variant1)
        XCTAssertEqual(NaivePaddingNegotiator.parseResponse([HpackHeader("padding-type-reply", "0")]), .unpadded)
        XCTAssertEqual(NaivePaddingNegotiator.parseResponse([HpackHeader("padding-type-reply", "7")]), .unpadded)
        // Older servers answer with a padding header of their own.
        XCTAssertEqual(NaivePaddingNegotiator.parseResponse([HpackHeader("padding", "!!!!")]), .variant1)
        XCTAssertEqual(NaivePaddingNegotiator.parseResponse([HpackHeader(":status", "200")]), .unpadded)
    }

    // MARK: - Framing

    func testFrameLayoutIsLengthPaddingLengthPayloadZeros() {
        let framer = NaivePaddingFramer()
        let frame = framer.write([7, 8, 9], paddingSize: 4)
        XCTAssertEqual(frame, [0x00, 0x03, 0x04, 7, 8, 9, 0, 0, 0, 0])
        XCTAssertEqual(framer.write([], paddingSize: 999).count, 3 + 255, "padding is capped at 255")
    }

    func testFramesReadBackAcrossAnySplitAndPassThroughAfterEight() {
        let writer = NaivePaddingFramer()
        var wire = [UInt8]()
        var expected = [UInt8]()
        for n in 0..<8 {
            let payload = (0..<(n * 37 + 1)).map { UInt8(($0 + n) & 0xFF) }
            expected.append(contentsOf: payload)
            wire.append(contentsOf: writer.write(payload, paddingSize: n * 11))
        }
        XCTAssertFalse(writer.isWritePaddingActive)
        let tail: [UInt8] = [1, 2, 3, 4, 5]
        wire.append(contentsOf: tail)
        expected.append(contentsOf: tail)

        let reader = NaivePaddingFramer()
        var out = [UInt8]()
        var at = 0
        let sizes = [1, 2, 3, 50, 7, 300]
        var i = 0
        while at < wire.count {
            let end = min(wire.count, at + sizes[i % sizes.count])
            i += 1
            _ = reader.read(Array(wire[at..<end]), into: &out)
            at = end
        }
        XCTAssertEqual(out, expected)
        XCTAssertFalse(reader.isReadPaddingActive)
    }

    func testSendPaddingIsBiasedForSmallPayloads() {
        for _ in 0..<200 {
            XCTAssertTrue((245...255).contains(NaiveProxyConnection.generateSendPaddingSize(10)))
            XCTAssertTrue((0...255).contains(NaiveProxyConnection.generateSendPaddingSize(500)))
        }
    }

    // MARK: - The tunnel

    /// Reads one write back as frames: the payload sizes in order.
    private func payloadSizes(_ writes: [Data]) -> [Int] {
        let reader = NaivePaddingFramer()
        var sizes = [Int]()
        for write in writes {
            var out = [UInt8]()
            sizes.append(reader.read([UInt8](write), into: &out))
        }
        return sizes
    }

    func testMediumWritesAreCutIntoPaddedPieces() async throws {
        let tunnel = ProtocolTestStreams.Scripted()
        let connection = NaiveProxyConnection(tunnel, paddingType: .variant1)
        try await connection.send(Data(count: 700))
        let sizes = payloadSizes(tunnel.writes)
        XCTAssertEqual(sizes.reduce(0, +), 700)
        for size in sizes.dropLast() {
            XCTAssertTrue((200...300).contains(size), "piece of \(size)")
        }
        XCTAssertLessThanOrEqual(sizes.last ?? 0, 300)
    }

    func testPaddingEndsAfterEightFramesAndUnpaddedTunnelsPassThrough() async throws {
        let tunnel = ProtocolTestStreams.Scripted()
        let connection = NaiveProxyConnection(tunnel, paddingType: .variant1)
        for _ in 0..<8 {
            try await connection.send(Data([1]))
        }
        try await connection.send(Data([9, 9]))
        XCTAssertEqual(tunnel.writes.count, 9)
        XCTAssertEqual(tunnel.writes[8], Data([9, 9]), "the ninth write goes as it is")

        let plain = ProtocolTestStreams.Scripted()
        try await NaiveProxyConnection(plain, paddingType: .unpadded).send(Data([1, 2]))
        XCTAssertEqual(plain.writes, [Data([1, 2])])
    }

    func testReceiveUnpadsAndSkipsFramesOfPurePadding() async throws {
        let server = NaivePaddingFramer()
        let tunnel = ProtocolTestStreams.Scripted(reads: [
            Data(server.write([], paddingSize: 20)),
            Data(server.write(Array("hello".utf8), paddingSize: 3)),
        ])
        let connection = NaiveProxyConnection(tunnel, paddingType: .variant1)
        let first = try await connection.receive()
        XCTAssertEqual(first, Data("hello".utf8))
        let end = try await connection.receive()
        XCTAssertNil(end)
    }

    func testCloseRunsTheReleaseOnce() {
        var released = 0
        let connection = NaiveProxyConnection(ProtocolTestStreams.Scripted(), paddingType: .unpadded, onClose: { released += 1 })
        connection.close()
        connection.close()
        XCTAssertEqual(released, 1)
    }

    func testPoolKeyFollowsTheTlsSettings() {
        var configuration = ProxyConfiguration(name: "n", serverAddress: "proxy.example", serverPort: 443,
                                               uuid: UUID(), encryption: "none")
        configuration.outboundProtocol = .naiveHttp2
        let plain = NaiveSessionPool.key(for: configuration)
        XCTAssertEqual(plain.serverName, "proxy.example")
        configuration.tls = TlsConfiguration(serverName: "front.example", allowInsecure: true)
        let edited = NaiveSessionPool.key(for: configuration)
        XCTAssertEqual(edited.serverName, "front.example")
        XCTAssertNotEqual(plain, edited)
        XCTAssertFalse(NaiveSessionPool.shared.holds(edited))
    }
}
