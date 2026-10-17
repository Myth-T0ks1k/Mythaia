import Foundation
import XCTest
@testable import MythaiaKit

/// A read that fails must reach the reader as that failure, through every
/// protocol layer, and a clean end as nil — never the other way round. A
/// failure turned into an end looks like a finished download; an end turned
/// into a failure tears down flows that closed normally.
final class ProtocolReceiveFailureTests: XCTestCase {
    private let failure = MythaiaError.connectFailed("HTTP/2 CONNECT tunnel failed with status 421")

    private func layers(over inner: ByteStream) -> [(String, ByteStream)] {
        let masterKey = ShadowsocksKeyDerivation.deriveKey(password: "pw", keySize: 16)
        let address = ShadowsocksProtocol.buildAddressHeader(host: "example.com", port: 443)
        return [
            ("VLESS", VlessConnection(inner)),
            ("Trojan", TrojanConnection(inner, password: "pw", destinationHost: "example.com", destinationPort: 443)),
            ("Shadowsocks", ShadowsocksConnection(inner, cipher: .aes128Gcm, masterKey: masterKey, addressHeader: address)),
            ("Shadowsocks 2022", Shadowsocks2022Connection(inner, cipher: .blake3Aes128Gcm, pskList: [Data(count: 16)], addressHeader: address)),
            ("Vision", VlessVisionConnection(VlessConnection(inner), userUUID: Data(count: 16))),
        ]
    }

    func testFailedReadReachesTheCallerAsThatFailure() async {
        for index in 0..<5 {
            let inner = ProtocolTestStreams.Scripted(failure: failure)
            let (name, layer) = layers(over: inner)[index]
            do {
                _ = try await layer.receive()
                XCTFail("\(name): the failure was swallowed")
            } catch let error as MythaiaError {
                XCTAssertEqual(error, failure, name)
            } catch {
                XCTFail("\(name): unexpected \(error)")
            }
        }
    }

    func testCleanEndIsReportedAsNoError() async throws {
        for index in 0..<5 {
            let inner = ProtocolTestStreams.Scripted()
            let (name, layer) = layers(over: inner)[index]
            let result = try await layer.receive()
            XCTAssertNil(result, name)
        }
    }

    func testVmessFailureAndEnd() async throws {
        let sealed = try VmessProtocol.sealRequest(id: UUID(), host: "example.com", port: 443,
                                                   command: VmessProtocol.commandTCP, security: .aes128Gcm)
        let failing = VmessConnection(ProtocolTestStreams.Scripted(failure: failure), session: sealed.session, requestHeader: sealed.bytes)
        do {
            _ = try await failing.receive()
            XCTFail("the failure was swallowed")
        } catch let error as MythaiaError {
            XCTAssertEqual(error, failure)
        }
        let ending = VmessConnection(ProtocolTestStreams.Scripted(), session: sealed.session, requestHeader: sealed.bytes)
        let result = try await ending.receive()
        XCTAssertNil(result)
    }

    func testUdpLayersReportTheFailureToo() async {
        let udp: [DatagramStream] = [
            VlessUdpConnection(VlessConnection(ProtocolTestStreams.Scripted(failure: failure))),
            TrojanUdpConnection(ProtocolTestStreams.Scripted(failure: failure), password: "pw", destinationHost: "1.1.1.1", destinationPort: 53),
        ]
        for stream in udp {
            do {
                _ = try await stream.receive()
                XCTFail("the failure was swallowed")
            } catch let error as MythaiaError {
                XCTAssertEqual(error, failure)
            } catch {
                XCTFail("unexpected \(error)")
            }
        }
    }
}
