import Foundation
import XCTest
@testable import MythaiaKit

/// The AnyTLS wire format, against the reference implementation rather than
/// against itself.
///
/// The MD5 below is the one anytls-go computes over its own default scheme.
/// It is the whole point of the first test: the server compares that digest
/// to decide whether to push a replacement, so a scheme that differs by a
/// single newline still works — it just triggers an update on every session.
final class ProtocolAnyTlsTests: XCTestCase {
    /// A one-packet scheme, built the way a server would send it.
    private func scheme(_ line: String, stop: Int = 2) -> Data {
        return Data(["stop=\(stop)", line].joined(separator: "\n").utf8)
    }

    // MARK: - Padding scheme

    func testDefaultSchemeIsByteIdenticalToTheReference() {
        XCTAssertEqual(AnyTlsPaddingScheme.defaultScheme.raw.count, 137)
        XCTAssertEqual(AnyTlsPaddingScheme.defaultScheme.md5, "75cff2ad89aadf5e257059ee571ebe11")
    }

    func testStopBoundsWhichPacketsAreShaped() {
        let scheme = AnyTlsPaddingScheme.defaultScheme
        XCTAssertTrue(scheme.shapes(0))
        XCTAssertTrue(scheme.shapes(7))
        // stop=8 means packets 0..7, so 8 onwards go out unshaped.
        XCTAssertFalse(scheme.shapes(8))
        XCTAssertFalse(scheme.shapes(9))
    }

    func testFixedRangeYieldsExactlyThatSize() {
        // "0=30-30": the padding that rides along with authentication.
        XCTAssertEqual(AnyTlsPaddingScheme.defaultScheme.recordSizes(0), [30])
    }

    func testRangeStaysInsideItselfOverManyDraws() {
        for _ in 0..<200 {
            let sizes = AnyTlsPaddingScheme.defaultScheme.recordSizes(1)
            XCTAssertEqual(sizes.count, 1)
            XCTAssertTrue((100...400).contains(sizes[0]), "out of range: \(sizes[0])")
        }
    }

    func testCheckMarksAreKeptInOrderAmongTheSizes() {
        // "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000"
        let sizes = AnyTlsPaddingScheme.defaultScheme.recordSizes(2)
        XCTAssertEqual(sizes.count, 9)
        XCTAssertTrue((400...500).contains(sizes[0]))
        for i in [1, 3, 5, 7] {
            XCTAssertEqual(sizes[i], AnyTlsPaddingScheme.check, "position \(i) should be a check mark")
        }
        for i in [2, 4, 6, 8] {
            XCTAssertTrue((500...1000).contains(sizes[i]), "position \(i) out of range: \(sizes[i])")
        }
    }

    func testUnshapedPacketHasNoSizes() {
        XCTAssertEqual(AnyTlsPaddingScheme.defaultScheme.recordSizes(42), [])
    }

    func testServerSchemeReplacesTheDefaultAndCarriesItsOwnDigest() throws {
        let scheme = try XCTUnwrap(AnyTlsPaddingScheme.parse(Data("stop=2\n0=10-10\n1=20-30".utf8)))
        XCTAssertEqual(scheme.recordSizes(0), [10])
        XCTAssertTrue(scheme.shapes(1))
        XCTAssertFalse(scheme.shapes(2))
        XCTAssertNotEqual(scheme.md5, AnyTlsPaddingScheme.defaultScheme.md5)
    }

    /// The first version packed a range into one negative Int; at a minimum
    /// of 32768 it came back positive, read as a FIXED size of about 1.6 GB,
    /// and was allocated. This is the regression guard.
    func testLargeRangeStaysARangeInsteadOfOverflowing() throws {
        let scheme = try XCTUnwrap(AnyTlsPaddingScheme.parse(self.scheme("2=40000-50000", stop: 4)))
        for _ in 0..<50 {
            let sizes = scheme.recordSizes(2)
            XCTAssertEqual(sizes.count, 1)
            XCTAssertTrue((1...AnyTlsPaddingScheme.maxRecord).contains(sizes[0]), "size \(sizes[0])")
        }
    }

    func testRangesAroundTheOldOverflowBoundaryBehave() throws {
        for spec in ["32767-40000", "32768-40000", "65535-70000", "1-100000"] {
            let scheme = try XCTUnwrap(AnyTlsPaddingScheme.parse(self.scheme("1=\(spec)")))
            let sizes = scheme.recordSizes(1)
            XCTAssertEqual(sizes.count, 1, spec)
            XCTAssertTrue((1...AnyTlsPaddingScheme.maxRecord).contains(sizes[0]), "\(spec) gave \(sizes[0])")
        }
    }

    /// Go rejects only non-positive bounds. Dropping a part would emit fewer
    /// records than the server asked for.
    func testRangeTheReferenceAcceptsIsNotDropped() throws {
        let scheme = try XCTUnwrap(AnyTlsPaddingScheme.parse(self.scheme("1=1-100000,c,20000-30000")))
        XCTAssertEqual(scheme.recordSizes(1).count, 3)
    }

    func testNonsenseIsRefusedSoTheWorkingSchemeSurvives() {
        XCTAssertNil(AnyTlsPaddingScheme.parse(Data()))
        // No stop, no scheme.
        XCTAssertNil(AnyTlsPaddingScheme.parse(Data("0=30-30".utf8)))
        XCTAssertNil(AnyTlsPaddingScheme.parse(Data("stop=x\n0=30-30".utf8)))
    }

    // MARK: - Frames

    func testFrameHeaderIsBigEndianInBothFields() {
        let f = AnyTlsProtocol.frame(AnyTlsProtocol.cmdPsh, streamId: 0x0102_0304, data: [9, 9, 9])
        XCTAssertEqual(f.count, AnyTlsProtocol.headerSize + 3)
        XCTAssertEqual(f[0], AnyTlsProtocol.cmdPsh)
        XCTAssertEqual(Array(f[1..<5]), [0x01, 0x02, 0x03, 0x04])
        XCTAssertEqual(Array(f[5..<7]), [0x00, 0x03])
        XCTAssertEqual(Array(f[7..<10]), [9, 9, 9])
    }

    /// Stream ids are an unsigned 32-bit counter; the top bit must survive.
    func testHeaderReadsBackAHighStreamId() {
        let f = AnyTlsProtocol.frame(AnyTlsProtocol.cmdSyn, streamId: 0xFFFF_FFFF)
        let h = AnyTlsProtocol.readHeader(f)
        XCTAssertEqual(h, AnyTlsProtocol.Header(command: AnyTlsProtocol.cmdSyn, streamId: 0xFFFF_FFFF, length: 0))
    }

    func testFullLengthFrameEncodesItsLength() {
        let f = AnyTlsProtocol.frame(AnyTlsProtocol.cmdPsh, streamId: 1, data: [UInt8](repeating: 0, count: 65535))
        XCTAssertEqual(AnyTlsProtocol.readHeader(f).length, 65535)
    }

    // MARK: - Authentication

    func testAuthenticationIsThePasswordDigestThenThePaddingLength() {
        let auth = [UInt8](AnyTlsProtocol.authentication(password: "hunter2", paddingLength: 30))
        XCTAssertEqual(auth.count, 32 + 2 + 30)
        // SHA-256("hunter2"), computed by OpenSSL.
        XCTAssertEqual(ProtocolTestStreams.hexString(Data(auth[0..<32])),
                       "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7")
        // Big-endian uint16, then that many zero bytes.
        XCTAssertEqual(auth[32], 0)
        XCTAssertEqual(auth[33], 30)
        XCTAssertTrue(auth[34...].allSatisfy { $0 == 0 })
    }

    func testNoPaddingStillCarriesTheLengthField() {
        let auth = [UInt8](AnyTlsProtocol.authentication(password: "x", paddingLength: 0))
        XCTAssertEqual(auth.count, 34)
        XCTAssertEqual(auth[32], 0)
        XCTAssertEqual(auth[33], 0)
    }

    // MARK: - Settings

    func testSettingsNameTheVersionTheClientAndTheSchemeDigest() {
        let text = String(decoding: AnyTlsProtocol.settings(clientName: "mythaia/1.0", paddingMd5: AnyTlsPaddingScheme.defaultScheme.md5), as: UTF8.self)
        XCTAssertEqual(text, "v=2\nclient=mythaia/1.0\npadding-md5=75cff2ad89aadf5e257059ee571ebe11")
    }

    func testServerSettingsParseAndAnUnknownKeyIsNotFatal() {
        let parsed = AnyTlsProtocol.parseSettings(Array("v=2\nsomething=else".utf8))
        XCTAssertEqual(parsed["v"], "2")
        XCTAssertEqual(parsed["something"], "else")
        XCTAssertNil(parsed["absent"])
    }

    // MARK: - Addresses

    func testAnAddressIsSocks5Form() {
        XCTAssertEqual(AnyTlsProtocol.encodeAddress(host: "1.2.3.4", port: 443), [0x01, 1, 2, 3, 4, 0x01, 0xBB])
        let domain = AnyTlsProtocol.encodeAddress(host: "example.com", port: 80)
        XCTAssertEqual(domain[0], 0x03)
        XCTAssertEqual(domain[1], 11)
        XCTAssertEqual(String(decoding: domain[2..<13], as: UTF8.self), "example.com")
        XCTAssertEqual(Array(domain[13..<15]), [0x00, 0x50])
        let v6 = AnyTlsProtocol.encodeAddress(host: "2001:db8::1", port: 443)
        XCTAssertEqual(v6[0], 0x04)
        XCTAssertEqual(v6.count, 1 + 16 + 2)
    }

    func testUdpOverTcpHostIsTheOneSingBoxExpects() {
        XCTAssertEqual(AnyTlsProtocol.udpOverTcpHost, "sp.v2.udp-over-tcp.arpa")
    }

    // MARK: - A session on the wire

    private func frames(_ bytes: [UInt8]) -> [AnyTlsProtocol.Header] {
        var out = [AnyTlsProtocol.Header]()
        var at = 0
        while bytes.count - at >= AnyTlsProtocol.headerSize {
            let header = AnyTlsProtocol.readHeader(bytes, offset: at)
            out.append(header)
            at += AnyTlsProtocol.headerSize + header.length
        }
        XCTAssertEqual(at, bytes.count, "the write is whole frames")
        return out
    }

    /// Packet 1 is the settings, the first SYN and its address in one TLS
    /// write — with no shaping, exactly those three frames.
    func testFirstStreamComposesPacketOneAndCarriesData() async throws {
        let (client, server) = ProtocolTestStreams.pair()
        let scheme = try XCTUnwrap(AnyTlsPaddingScheme.parse(Data("stop=0".utf8)))
        let session = AnyTlsSession(tls: client, padding: scheme, clientName: "test", onPaddingScheme: { _ in })
        try await session.start()
        let stream = try await session.openStream(host: "example.com", port: 443)

        let first = try await server.receive()
        var expected = AnyTlsProtocol.frame(AnyTlsProtocol.cmdSettings, streamId: 0,
                                            data: AnyTlsProtocol.settings(clientName: "test", paddingMd5: scheme.md5))
        expected.append(contentsOf: AnyTlsProtocol.frame(AnyTlsProtocol.cmdSyn, streamId: 1))
        expected.append(contentsOf: AnyTlsProtocol.frame(AnyTlsProtocol.cmdPsh, streamId: 1,
                                                         data: AnyTlsProtocol.encodeAddress(host: "example.com", port: 443)))
        XCTAssertEqual(first.map { [UInt8]($0) }, expected)

        try await stream.send(Data("GET".utf8))
        let push = try await server.receive()
        XCTAssertEqual(push.map { [UInt8]($0) }, AnyTlsProtocol.frame(AnyTlsProtocol.cmdPsh, streamId: 1, data: Array("GET".utf8)))

        // The server answers, pads, and ends the stream.
        var answer = AnyTlsProtocol.frame(AnyTlsProtocol.cmdWaste, streamId: 0, data: [0, 0, 0])
        answer.append(contentsOf: AnyTlsProtocol.frame(AnyTlsProtocol.cmdPsh, streamId: 1, data: Array("OK".utf8)))
        answer.append(contentsOf: AnyTlsProtocol.frame(AnyTlsProtocol.cmdFin, streamId: 1))
        try await server.send(Data(answer))

        let reply = try await stream.receive()
        XCTAssertEqual(reply, Data("OK".utf8))
        let end = try await stream.receive()
        XCTAssertNil(end, "the FIN ends the stream after its data")
        XCTAssertEqual(session.activeStreams, 0)
        session.close()
    }

    /// With the default scheme packet 1 is one record of 100–400 bytes: the
    /// three frames (96 bytes here) topped up with a waste frame — unless the
    /// draw left less room than a frame header, when the record goes short.
    func testDefaultSchemeShapesPacketOneIntoOnePaddedRecord() async throws {
        let (client, server) = ProtocolTestStreams.pair()
        let session = AnyTlsSession(tls: client, padding: AnyTlsPaddingScheme.defaultScheme, clientName: "test", onPaddingScheme: { _ in })
        try await session.start()
        _ = try await session.openStream(host: "example.com", port: 443)

        let received = try await server.receive()
        let record = try XCTUnwrap(received)
        let commands = frames([UInt8](record)).map { $0.command }
        let content = [AnyTlsProtocol.cmdSettings, AnyTlsProtocol.cmdSyn, AnyTlsProtocol.cmdPsh]
        if record.count == 96 {
            XCTAssertEqual(commands, content)
        } else {
            XCTAssertTrue((104..<400).contains(record.count), "record of \(record.count) bytes")
            XCTAssertEqual(commands, content + [AnyTlsProtocol.cmdWaste])
        }
        session.close()
    }

    func testServerPushedSchemeReachesTheClient() async throws {
        let (client, server) = ProtocolTestStreams.pair()
        let received = SchemeBox()
        let session = AnyTlsSession(tls: client, padding: AnyTlsPaddingScheme.defaultScheme, clientName: "test",
                                    onPaddingScheme: { received.set($0) })
        try await session.start()
        _ = try await session.openStream(host: "example.com", port: 80)
        _ = try await server.receive()

        let text = Array("stop=1\n0=10-10".utf8)
        try await server.send(Data(AnyTlsProtocol.frame(AnyTlsProtocol.cmdUpdatePaddingScheme, streamId: 0, data: text)))
        for _ in 0..<200 {
            if received.get() != nil { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(received.get()?.raw, Data(text))
        session.close()
    }

    private final class SchemeBox: @unchecked Sendable {
        private let lock = NSLock()
        private var scheme: AnyTlsPaddingScheme?

        func set(_ value: AnyTlsPaddingScheme) {
            lock.lock()
            scheme = value
            lock.unlock()
        }

        func get() -> AnyTlsPaddingScheme? {
            lock.lock()
            defer { lock.unlock() }
            return scheme
        }
    }

    // MARK: - UDP over TCP

    func testUdpRequestGoesOnceThenLengthPrefixedDatagrams() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let udp = AnyTlsUdpConnection(inner, destinationHost: "1.1.1.1", destinationPort: 53)
        try await udp.send(Data([0xAA, 0xBB]))
        try await udp.send(Data([0xCC]))
        XCTAssertEqual(inner.writes, [
            Data([0x01, 0x01, 1, 1, 1, 1, 0x00, 53, 0x00, 0x02, 0xAA, 0xBB]),
            Data([0x00, 0x01, 0xCC]),
        ])

        let replies = ProtocolTestStreams.Scripted(reads: [Data([0x00, 0x02, 0x01]), Data([0x02, 0x00, 0x01, 0x03])])
        let reader = AnyTlsUdpConnection(replies, destinationHost: "1.1.1.1", destinationPort: 53)
        let first = try await reader.receive()
        XCTAssertEqual(first, Data([0x01, 0x02]))
        let second = try await reader.receive()
        XCTAssertEqual(second, Data([0x03]))
    }
}
