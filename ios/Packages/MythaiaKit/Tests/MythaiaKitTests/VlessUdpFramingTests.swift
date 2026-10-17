import Foundation
import XCTest
@testable import MythaiaKit

final class VlessUdpFramingTests: XCTestCase {
    private func packet(_ n: Int, _ size: Int) -> Data {
        var out = [UInt8](repeating: 0, count: size)
        for i in 0..<size {
            out[i] = UInt8(truncatingIfNeeded: n + i)
        }
        return Data(out)
    }

    func testFrameIsABigEndianLengthThenThePacket() {
        let framed = [UInt8](UdpFraming.frame(Data([7, 8, 9])))
        XCTAssertEqual(framed, [0x00, 0x03, 7, 8, 9])
        let big = [UInt8](UdpFraming.frame(Data(count: 0x1234)))
        XCTAssertEqual(big[0], 0x12)
        XCTAssertEqual(big[1], 0x34)
        XCTAssertEqual(big.count, 2 + 0x1234)
    }

    func testEveryPacketOfAStreamComesOutOneChunkAtATime() {
        let state = UdpBufferState()
        for n in 0..<50 {
            let p = packet(n, 20 + n)
            state.append(UdpFraming.frame(p))
            XCTAssertEqual(UdpFraming.extract(state), p, "packet \(n)")
            XCTAssertNil(UdpFraming.extract(state))
        }
    }

    func testPacketsSplitAcrossChunksAndSeveralInOneChunk() {
        var packets = [Data]()
        for i in 0..<30 {
            packets.append(packet(i, 1 + i * 37 % 1200))
        }
        var wire = Data()
        for p in packets {
            wire.append(UdpFraming.frame(p))
        }
        let wireBytes = [UInt8](wire)
        let state = UdpBufferState()
        var out = [Data]()
        var at = 0
        let sizes = [1, 3, 700, 2, 1500, 5, 9000]
        var i = 0
        while at < wireBytes.count {
            let end = min(wireBytes.count, at + sizes[i % sizes.count])
            i += 1
            state.append(Data(wireBytes[at..<end]))
            at = end
            while let next = UdpFraming.extract(state) {
                out.append(next)
            }
        }
        XCTAssertEqual(out.count, packets.count)
        for (n, p) in packets.enumerated() {
            XCTAssertEqual(out[n], p, "packet \(n)")
        }
    }

    /// The datagrams a VLESS UDP flow puts on the stream, and the ones it
    /// reads back, response header and all.
    func testUdpConnectionFramesWritesAndReassemblesReads() async throws {
        let reply1 = Data([0xAA, 0xBB])
        let reply2 = Data([0xCC])
        var wire = Data([0x00, 0x00]) // VLESS response header
        wire.append(UdpFraming.frame(reply1))
        wire.append(UdpFraming.frame(reply2))
        let wireBytes = [UInt8](wire)
        // Split mid-frame to make the reassembly work for it.
        let inner = ProtocolTestStreams.Scripted(reads: [Data(wireBytes[0..<5]), Data(wireBytes[5...])])
        let udp = VlessUdpConnection(VlessConnection(inner))

        try await udp.send(Data([1, 2, 3]))
        XCTAssertEqual(inner.writes, [Data([0x00, 0x03, 1, 2, 3])])

        let first = try await udp.receive()
        XCTAssertEqual(first, reply1)
        let second = try await udp.receive()
        XCTAssertEqual(second, reply2)
        let end = try await udp.receive()
        XCTAssertNil(end)
    }
}
