import Foundation
import XCTest
@testable import MythaiaKit

/// Vision's flow control against what Xray's VisionReader and VisionWriter do.
///
/// Vision's whole value is switching the uplink to a raw copy once it has
/// seen a TLS 1.3 ServerHello; if that detection never fires, every byte
/// stays double-encrypted for the life of the connection and nothing visibly
/// fails. So the tests drive a connection end to end and look at the bytes
/// that come out, not at the state inside.
final class VlessVisionTests: XCTestCase {
    private let uuid = UUID(uuidString: "b831381d-6324-4d53-ad4f-8cda48b30811")!
    private var uuidBytes: [UInt8] { [UInt8](VlessProtocol.uuidToBytes(uuid)) }

    /// A TLS 1.3 ServerHello record as the filter recognises it: record type
    /// 0x16 (version 0x0303), handshake type 2, a 32-byte session id, the
    /// TLS_AES_128_GCM_SHA256 suite and a supported_versions extension
    /// naming 0x0304.
    private func serverHello13() -> [UInt8] {
        var body: [UInt8] = [0x03, 0x03]                      // legacy_version
        body.append(contentsOf: (0..<32).map { UInt8($0) })   // random
        body.append(32)                                       // session id
        body.append(contentsOf: [UInt8](repeating: 9, count: 32))
        body.append(contentsOf: [0x13, 0x01])                 // cipher suite
        body.append(0x00)                                     // compression
        body.append(contentsOf: [0x00, 0x06])                 // extensions length
        body.append(contentsOf: [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]) // supported_versions = 1.3
        var handshake: [UInt8] = [0x02, 0x00, UInt8(body.count >> 8), UInt8(body.count & 0xFF)]
        handshake.append(contentsOf: body)
        var record: [UInt8] = [0x16, 0x03, 0x03, UInt8(handshake.count >> 8), UInt8(handshake.count & 0xFF)]
        record.append(contentsOf: handshake)
        return record
    }

    /// The same shape without the supported_versions extension: TLS 1.2.
    private func serverHello12() -> [UInt8] {
        var hello = Array(serverHello13().dropLast(8)) // extensions length + extension
        let recordLength = hello.count - 5
        hello[3] = UInt8(recordLength >> 8)
        hello[4] = UInt8(recordLength & 0xFF)
        let handshakeLength = hello.count - 9
        hello[7] = UInt8(handshakeLength >> 8)
        hello[8] = UInt8(handshakeLength & 0xFF)
        return hello
    }

    private func clientHello() -> [UInt8] {
        let body = [UInt8](repeating: 1, count: 100)
        var handshake: [UInt8] = [0x01, 0x00, 0x00, UInt8(body.count)]
        handshake.append(contentsOf: body)
        var record: [UInt8] = [0x16, 0x03, 0x01, 0x00, UInt8(handshake.count)]
        record.append(contentsOf: handshake)
        return record
    }

    private func applicationData(_ length: Int) -> [UInt8] {
        var record: [UInt8] = [0x17, 0x03, 0x03, UInt8(length >> 8), UInt8(length & 0xFF)]
        record.append(contentsOf: [UInt8](repeating: 5, count: length))
        return record
    }

    private func header() -> Data {
        return VlessProtocol.encodeRequestHeader(uuid: uuid, command: .tcp, destinationAddress: "example.com", destinationPort: 443, flow: "xtls-rprx-vision")
    }

    private func be16(_ bytes: [UInt8], _ at: Int) -> Int {
        return (Int(bytes[at]) << 8) | Int(bytes[at + 1])
    }

    private func connection(_ inner: ProtocolTestStreams.Scripted) -> VlessVisionConnection {
        return VlessVisionConnection(VlessConnection(inner), userUUID: VlessProtocol.uuidToBytes(uuid))
    }

    func testRequestHeaderAndFirstPaddedFrameShareOneWrite() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let vision = connection(inner)
        let requestHeader = [UInt8](header())

        try await vision.sendRequest(header(), initialData: nil)

        // One write: a header in a record of its own has a size an observer
        // can read, which is exactly what the padding is there to hide.
        XCTAssertEqual(inner.writes.count, 1)
        let write = [UInt8](inner.writes[0])
        XCTAssertEqual(Array(write[0..<requestHeader.count]), requestHeader)

        var at = requestHeader.count
        XCTAssertEqual(Array(write[at..<(at + 16)]), uuidBytes); at += 16
        XCTAssertEqual(write[at], VisionCommand.paddingContinue.rawValue); at += 1
        XCTAssertEqual(be16(write, at), 0, "no content"); at += 2
        let padding = be16(write, at); at += 2
        XCTAssertTrue((900..<1400).contains(padding), "long padding, got \(padding)")
        XCTAssertEqual(write.count, at + padding)
    }

    func testFirstDataRidesTheSameWriteAsTheHeader() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let vision = connection(inner)
        let requestHeader = [UInt8](header())
        let hello = clientHello()

        try await vision.sendRequest(header(), initialData: Data(hello))

        XCTAssertEqual(inner.writes.count, 1)
        let write = [UInt8](inner.writes[0])
        XCTAssertEqual(Array(write[0..<requestHeader.count]), requestHeader)
        var at = requestHeader.count
        XCTAssertEqual(Array(write[at..<(at + 16)]), uuidBytes); at += 16
        XCTAssertEqual(write[at], VisionCommand.paddingContinue.rawValue); at += 1
        XCTAssertEqual(be16(write, at), hello.count); at += 2
        let padding = be16(write, at); at += 2
        XCTAssertEqual(Array(write[at..<(at + hello.count)]), hello)
        XCTAssertEqual(write.count, at + hello.count + padding)
    }

    func testPaddedServerHelloIsRecognisedAndTheUplinkSwitchesToDirectCopy() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let vision = connection(inner)
        try await vision.sendRequest(header(), initialData: Data(clientHello()))

        // The server's first frame, padded as Xray's server pads it: UUID,
        // command END, the ServerHello as content. In front of it the VLESS
        // response header, which the inner connection strips.
        let serverSide = VisionTrafficState(userUUID: VlessProtocol.uuidToBytes(uuid))
        let frame = visionPadding(serverHello13(), command: .paddingEnd, state: serverSide, longPadding: false)
        inner.queue(Data([0x00, 0x00] + frame))

        let received = try await vision.receive()
        XCTAssertEqual(received.map { [UInt8]($0) }, serverHello13())

        // The filter must have seen the ServerHello, which only exists once
        // the padding is off; this write goes DIRECT.
        let record = applicationData(64)
        try await vision.send(Data(record))
        let write = [UInt8](inner.writes[inner.writes.count - 1])
        XCTAssertEqual(write[0], VisionCommand.paddingDirect.rawValue,
                       "a complete application-data record after a TLS 1.3 ServerHello is sent DIRECT")
        XCTAssertEqual(be16(write, 1), record.count)
        XCTAssertEqual(Array(write[5..<(5 + record.count)]), record)

        // From here on the writer copies raw: no command, no padding.
        try await vision.send(Data(record))
        XCTAssertEqual([UInt8](inner.writes[inner.writes.count - 1]), record)
    }

    func testPaddedTls12ServerHelloEndsPaddingWithoutDirectCopy() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let vision = connection(inner)
        try await vision.sendRequest(header(), initialData: Data(clientHello()))

        let hello12 = serverHello12()
        let serverSide = VisionTrafficState(userUUID: VlessProtocol.uuidToBytes(uuid))
        inner.queue(Data([0x00, 0x00] + visionPadding(hello12, command: .paddingEnd, state: serverSide, longPadding: false)))
        let received = try await vision.receive()
        XCTAssertEqual(received.map { [UInt8]($0) }, hello12)

        try await vision.send(Data(applicationData(64)))
        XCTAssertEqual([UInt8](inner.writes[inner.writes.count - 1])[0], VisionCommand.paddingEnd.rawValue)
    }

    /// When the server switches to direct copy, the next outer record does
    /// not decrypt; the TLS layer hands back those raw bytes, and they are
    /// the inner TLS the app is waiting for.
    func testUndecryptableRecordSwitchesTheReaderToDirectCopy() async throws {
        let raw = Data(applicationData(10))
        let inner = ProtocolTestStreams.Scripted(failure: TLSDecryptionFailed(rawData: raw))
        let vision = connection(inner)
        let received = try await vision.receive()
        XCTAssertEqual(received, raw)
    }

    func testUnpaddingSkipsPurePaddingAndReadsOn() async throws {
        let inner = ProtocolTestStreams.Scripted()
        let vision = connection(inner)
        let serverSide = VisionTrafficState(userUUID: VlessProtocol.uuidToBytes(uuid))
        let paddingOnly = visionPadding(nil, command: .paddingContinue, state: serverSide, longPadding: true)
        let content = visionPadding([1, 2, 3], command: .paddingEnd, state: serverSide, longPadding: false)
        inner.queue(Data([0x00, 0x00] + paddingOnly))
        inner.queue(Data(content))
        let received = try await vision.receive()
        XCTAssertEqual(received, Data([1, 2, 3]))
    }

    func testCompleteTlsRecordDetection() {
        XCTAssertTrue(isCompleteTlsRecord(applicationData(10)))
        XCTAssertTrue(isCompleteTlsRecord(applicationData(10) + applicationData(3)))
        XCTAssertFalse(isCompleteTlsRecord(Array(applicationData(10).dropLast())))
        XCTAssertFalse(isCompleteTlsRecord(clientHello()))
        XCTAssertFalse(isCompleteTlsRecord([0x17, 0x03]))
    }

    func testReshapeKeepsEveryPieceUnderTheFrameLimit() {
        let big = [UInt8](repeating: 7, count: 20000)
        let pieces = reshapeData(big)
        XCTAssertGreaterThan(pieces.count, 1)
        for piece in pieces {
            XCTAssertLessThan(piece.count, 8192 - 21)
        }
        XCTAssertEqual(pieces.flatMap { $0 }, big)
    }
}
