import Foundation
import XCTest
@testable import MythaiaKit

/// The SOCKS5 client handshake, byte for byte as RFC 1928 and RFC 1929 put it.
final class SocksClientTests: XCTestCase {
    /// The parts, one after another; typed up front so literal-heavy
    /// expressions stay cheap to type-check.
    private func join(_ parts: [UInt8]...) -> Data {
        var out = Data()
        for part in parts {
            out.append(contentsOf: part)
        }
        return out
    }

    func testConnectWithoutAuthentication() async throws {
        let server = ProtocolTestStreams.Scripted(reads: [
            Data([0x05, 0x00]),
            Data([0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90]),
        ])
        let stream = try await SocksClient.connect(over: server, to: Endpoint(host: "example.com", port: 443),
                                                   username: nil, password: nil)
        XCTAssertEqual(server.writes, [
            Data([0x05, 0x01, 0x00]),
            join([0x05, 0x01, 0x00, 0x03, 11], Array("example.com".utf8), [0x01, 0xBB]),
        ])
        try await stream.send(Data("hi".utf8))
        XCTAssertEqual(server.writes.last, Data("hi".utf8))
    }

    func testConnectWithUsernameAndPassword() async throws {
        let server = ProtocolTestStreams.Scripted(reads: [
            Data([0x05, 0x02]),
            Data([0x01, 0x00]),
            Data([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        ])
        _ = try await SocksClient.connect(over: server, to: Endpoint(host: "1.2.3.4", port: 80),
                                          username: "user", password: "pass")
        XCTAssertEqual(server.writes, [
            Data([0x05, 0x01, 0x02]),
            join([0x01, 4], Array("user".utf8), [4], Array("pass".utf8)),
            Data([0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 80]),
        ])
    }

    /// Bytes the server sent right behind its reply belong to the tunnel
    /// (a server-speaks-first banner) and must reach the caller first.
    func testBytesBehindTheReplyAreDeliveredFirst() async throws {
        let server = ProtocolTestStreams.Scripted(reads: [
            Data([0x05, 0x00]),
            join([0x05, 0x00, 0x00, 0x04], [UInt8](repeating: 0, count: 16), [0x00, 0x50], Array("SSH-2.0".utf8)),
            Data("-x".utf8),
        ])
        let stream = try await SocksClient.connect(over: server, to: Endpoint(host: "2001:db8::1", port: 22),
                                                   username: nil, password: nil)
        XCTAssertEqual(server.writes[1], join([0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0D, 0xB8], [UInt8](repeating: 0, count: 11), [0x01, 0x00, 22]))
        let first = try await stream.receive()
        XCTAssertEqual(first, Data("SSH-2.0".utf8))
        let second = try await stream.receive()
        XCTAssertEqual(second, Data("-x".utf8))
    }

    func testRefusedCommandIsAnError() async {
        let server = ProtocolTestStreams.Scripted(reads: [
            Data([0x05, 0x00]),
            Data([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        ])
        do {
            _ = try await SocksClient.connect(over: server, to: Endpoint(host: "example.com", port: 443), username: nil, password: nil)
            XCTFail("expected an error")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .protocolError("SOCKS5 command failed (reply 5)"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testNoAcceptableMethodIsAnError() async {
        let server = ProtocolTestStreams.Scripted(reads: [Data([0x05, 0xFF])])
        do {
            _ = try await SocksClient.connect(over: server, to: Endpoint(host: "example.com", port: 443), username: "u", password: "p")
            XCTFail("expected an error")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .protocolError("SOCKS5 server: no matching auth method"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testServerClosingMidHandshakeIsAnError() async {
        let server = ProtocolTestStreams.Scripted(reads: [Data([0x05])])
        do {
            _ = try await SocksClient.connect(over: server, to: Endpoint(host: "example.com", port: 443), username: nil, password: nil)
            XCTFail("expected an error")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, .protocolError("SOCKS5 server closed during handshake"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testUdpAssociateReturnsTheRelayEndpoint() async throws {
        let server = ProtocolTestStreams.Scripted(reads: [
            Data([0x05, 0x00]),
            Data([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x04, 0xD2]),
        ])
        let relay = try await SocksClient.udpAssociate(over: server, username: nil, password: nil)
        XCTAssertEqual(relay, SocksClient.BoundAddress(host: "192.168.1.1", port: 1234))
        XCTAssertEqual(server.writes[1], Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    }

    func testUdpHeaderAndItsStripping() {
        XCTAssertEqual(SocksClient.udpHeader(host: "8.8.8.8", port: 53), [0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53])
        let reply: [UInt8] = [0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 0xAB, 0xCD]
        XCTAssertEqual(SocksClient.stripUdpHeader(reply), [0xAB, 0xCD])
        // A fragment is refused, and so is a header with nothing behind it.
        XCTAssertNil(SocksClient.stripUdpHeader([0, 0, 1, 0x01, 8, 8, 8, 8, 0, 53, 0xAB]))
        XCTAssertNil(SocksClient.stripUdpHeader([0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53]))
        XCTAssertEqual(SocksClient.stripUdpHeader([0, 0, 0, 0x03, 1, 0x61, 0, 53, 7]), [7])
    }

    func testUdpAssociationFramesDatagrams() async throws {
        final class Datagrams: DatagramStream, @unchecked Sendable {
            var sent: [Data] = []
            var replies: [Data]
            init(replies: [Data]) { self.replies = replies }
            func send(_ packet: Data) async throws { sent.append(packet) }
            func receive() async throws -> Data? { return replies.isEmpty ? nil : replies.removeFirst() }
            func close() {}
        }
        let socket = Datagrams(replies: [
            Data([0, 0, 1, 0x01, 8, 8, 8, 8, 0, 53, 0x01]),     // a fragment: skipped
            Data([0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 0x02, 0x03]),
        ])
        let control = ProtocolTestStreams.Scripted()
        let udp = SocksUdpConnection(control: control, socket: socket, destinationHost: "8.8.8.8", destinationPort: 53)
        try await udp.send(Data([0x99]))
        XCTAssertEqual(socket.sent, [Data([0, 0, 0, 0x01, 8, 8, 8, 8, 0, 53, 0x99])])
        let reply = try await udp.receive()
        XCTAssertEqual(reply, Data([0x02, 0x03]))
        udp.close()
        XCTAssertTrue(control.closed)
    }
}
