import Foundation
import XCTest
@testable import MythaiaKit

/// The interface driver's protocol side, without a socket: how a received
/// datagram is sorted, how a packet's own length is read, and the whole life
/// of a session — first handshake, AmneziaWG's junk, cookies, keepalives,
/// rekeys, expiry and giving up — driven by a clock the test moves and
/// answered by the responder written out from the paper.
final class WireGuardTunnelTests: XCTestCase {
    private typealias Support = WireGuardTestSupport

    private final class TestClock {
        var now: Double = 1000
    }

    private let fixedPrivate: [UInt8] = (0..<32).map { UInt8($0) }
    private let fixedPeer: [UInt8] = (0..<32).map { UInt8(truncatingIfNeeded: $0 * 7) }

    private func tunnel(extraInterface: String = "") throws -> WireGuardTunnel {
        let text = Support.ini(privateKey: fixedPrivate, peerPublicKey: fixedPeer, extraInterface: extraInterface)
        return try WireGuardTunnel(config: WireGuardConfig.parse(text))
    }

    private func message(size: Int, typeAt: Int, type: UInt32) -> Data {
        var bytes = [UInt8](repeating: 0xAB, count: size)
        WireGuardHandshake.writeLe32(&bytes, typeAt, type)
        return Data(bytes)
    }

    // MARK: - Classification

    func testPlainWireGuardReadsTheTypeAtOffsetZero() throws {
        let wg = try tunnel()
        XCTAssertEqual(wg.classify(message(size: WireGuardHandshake.responseSize, typeAt: 0, type: 2)), .response)
        XCTAssertEqual(wg.classify(message(size: 64, typeAt: 0, type: 3)), .cookie)
        XCTAssertEqual(wg.classify(message(size: 128, typeAt: 0, type: 4)), .transport)
        XCTAssertEqual(wg.classify(message(size: 128, typeAt: 0, type: 9)), .unknown)
    }

    func testAnS2JunkedResponseIsRecognisedPastItsJunk() throws {
        // The response is the only message AmneziaWG pads, and the padding is
        // random — so a dispatcher reading offset 0 sees noise and throws the
        // handshake away, leaving the tunnel retrying forever.
        let junk = 30
        let wg = try tunnel(extraInterface: "S2 = \(junk)\nH2 = 2")
        XCTAssertEqual(wg.classify(message(size: WireGuardHandshake.responseSize + junk, typeAt: junk, type: 2)), .response)
    }

    func testAJunkedResponseIsRecognisedUnderARenumberedH2() throws {
        let junk = 15
        let h2: UInt32 = 0x2A3B_4C5D
        let wg = try tunnel(extraInterface: "S2 = \(junk)\nH1 = 1234567\nH2 = \(h2)\nH3 = 3333333\nH4 = 4433221")
        XCTAssertEqual(wg.classify(message(size: WireGuardHandshake.responseSize + junk, typeAt: junk, type: h2)), .response)
    }

    func testADatagramOfTheJunkedLengthThatIsNotAResponseIsLeftAlone() throws {
        // Length alone must not be enough: a transport packet that happens to
        // be 92 + S2 bytes long would otherwise be handed to the handshake.
        let junk = 30
        let wg = try tunnel(extraInterface: "S2 = \(junk)\nH2 = 2")
        XCTAssertEqual(wg.classify(message(size: WireGuardHandshake.responseSize + junk, typeAt: 0, type: 4)), .transport)
    }

    func testARuntDatagramIsNotClassified() throws {
        XCTAssertEqual(try tunnel().classify(Data(count: 3)), .unknown)
    }

    // MARK: - Packet length

    func testAnIPv4PacketReportsItsOwnTotalLength() {
        var packet = [UInt8](repeating: 0, count: 64)
        packet[0] = 0x45
        packet[3] = 40
        XCTAssertEqual(WireGuardTunnel.ipPacketLength(Data(packet)), 40)
    }

    func testAnIPv6PacketReportsTheHeaderPlusItsPayload() {
        var packet = [UInt8](repeating: 0, count: 128)
        packet[0] = 0x60
        packet[5] = 24
        XCTAssertEqual(WireGuardTunnel.ipPacketLength(Data(packet)), 64)
    }

    func testATruncatedOrUnknownHeaderHasNoLength() {
        XCTAssertNil(WireGuardTunnel.ipPacketLength(Data()))
        XCTAssertNil(WireGuardTunnel.ipPacketLength(Data(repeating: 0x45, count: 10)))
        XCTAssertNil(WireGuardTunnel.ipPacketLength(Data(repeating: 0x25, count: 64)))
    }

    // MARK: - A session, end to end

    /// A tunnel and the peer behind it, the peer's side written from the paper.
    private struct Pair {
        let tunnel: WireGuardTunnel
        let clock: TestClock
        let client: (privateKey: [UInt8], publicKey: [UInt8])
        let server: (privateKey: [UInt8], publicKey: [UInt8])
    }

    private func makePair(extraInterface: String = "", extraPeer: String = "") throws -> Pair {
        let client = Support.keyPair()
        let server = Support.keyPair()
        let clock = TestClock()
        let text = Support.ini(privateKey: client.privateKey, peerPublicKey: server.publicKey, extraInterface: extraInterface, extraPeer: extraPeer)
        let tunnel = try WireGuardTunnel(config: WireGuardConfig.parse(text), clock: { clock.now })
        return Pair(tunnel: tunnel, clock: clock, client: client, server: server)
    }

    /// The peer's answer to `initiation` and the transport it now holds.
    private func answer(
        _ initiation: Data,
        in pair: Pair,
        transportType: UInt32 = WireGuardHandshake.messageTransport
    ) throws -> (response: [UInt8], peer: WireGuardTransport) {
        let bytes = [UInt8](initiation)
        let result = try Support.respond(bytes, responderPrivate: pair.server.privateKey, responderPublic: pair.server.publicKey)
        let peer = WireGuardTransport(
            sendKey: result.sendKey,
            receiveKey: result.receiveKey,
            peerIndex: WireGuardHandshake.readLe32(bytes, 4),
            localIndex: Support.responderIndex,
            transportType: transportType
        )
        return (result.response, peer)
    }

    /// A cookie reply as a peer under load writes it: `cookie` sealed with
    /// XChaCha20-Poly1305 under HASH("cookie--" ‖ its public key), with the
    /// challenged initiation's mac1 as the additional data.
    private func cookieReply(_ cookie: [UInt8], receiver: UInt32, mac1: [UInt8], in pair: Pair) throws -> [UInt8] {
        let key = WireGuardCrypto.hash(WireGuardHandshake.labelCookie, pair.server.publicKey)
        let nonce = WireGuardCrypto.randomBytes(24)
        let subkey = XChaCha20Poly1305.hChaCha20(key: key, nonce: Array(nonce[0..<16]))
        var innerNonce = [UInt8](repeating: 0, count: 4)
        innerNonce.append(contentsOf: nonce[16..<24])
        let sealed = try RawAEAD.chaChaPolySeal(key: Data(subkey), nonce: Data(innerNonce), plaintext: Data(cookie), aad: Data(mac1))
        var reply = [UInt8](repeating: 0, count: 8)
        WireGuardHandshake.writeLe32(&reply, 0, WireGuardHandshake.messageCookie)
        WireGuardHandshake.writeLe32(&reply, 4, receiver)
        reply.append(contentsOf: nonce)
        reply.append(contentsOf: [UInt8](sealed))
        return reply
    }

    /// Brings a session up; returns the peer's transport.
    private func establish(_ pair: Pair) throws -> WireGuardTransport {
        let tick = pair.tunnel.tick()
        let initiation = try XCTUnwrap(tick.datagrams.last)
        let (response, peer) = try answer(initiation, in: pair)
        let inbound = pair.tunnel.receive(Data(response))
        XCTAssertTrue(pair.tunnel.hasSession)
        XCTAssertEqual(inbound.datagrams.count, 1)
        return peer
    }

    private func ipv4Packet(_ length: Int, fill: UInt8) -> Data {
        var bytes = [UInt8](repeating: fill, count: length)
        bytes[0] = 0x45
        bytes[1] = 0
        bytes[2] = UInt8(length >> 8)
        bytes[3] = UInt8(length & 0xFF)
        return Data(bytes)
    }

    func testTheFirstTickSendsAnInitiationAndNothingIsSentBeforeASession() throws {
        let pair = try makePair()
        XCTAssertNil(pair.tunnel.encapsulate(ipv4Packet(40, fill: 1)), "a packet went out with no session")

        let tick = pair.tunnel.tick()
        XCTAssertEqual(tick.datagrams.count, 1)
        let initiation = [UInt8](tick.datagrams[0])
        XCTAssertEqual(initiation.count, WireGuardHandshake.initiationSize)
        XCTAssertEqual(Array(initiation[0..<4]), [1, 0, 0, 0])
        XCTAssertNil(tick.failure)
        XCTAssertFalse(tick.resolveEndpoint)
    }

    func testAHandshakeThroughTheTunnelCarriesPacketsBothWays() throws {
        let pair = try makePair()
        let initiation = try XCTUnwrap(pair.tunnel.tick().datagrams.first)
        let (response, peer) = try answer(initiation, in: pair)

        let inbound = pair.tunnel.receive(Data(response))
        XCTAssertTrue(inbound.established)
        XCTAssertNil(inbound.packet)
        // The keepalive that tells the peer the session is live, which it
        // opens to nothing.
        let keepalive = try XCTUnwrap(inbound.datagrams.first)
        XCTAssertEqual(keepalive.count, WireGuardTransport.headerSize + WireGuardCrypto.tagSize)
        XCTAssertEqual(peer.decapsulate(keepalive)?.count, 0)

        // Up: the peer reads what the interface handed over.
        let up = ipv4Packet(37, fill: 0x11)
        let sealed = try XCTUnwrap(pair.tunnel.encapsulate(up))
        XCTAssertEqual(peer.decapsulate(sealed)?.prefix(37), up)

        // Down: the padding the peer added is cut off by the IP length.
        let down = ipv4Packet(45, fill: 0x22)
        let fromPeer = pair.tunnel.receive(try peer.encapsulate(down))
        XCTAssertEqual(fromPeer.packet, down)
        XCTAssertFalse(fromPeer.established)

        // A keepalive from the peer writes nothing to the interface.
        XCTAssertNil(pair.tunnel.receive(try peer.encapsulate(Data())).packet)
    }

    func testOnlyTheFirstSessionCountsAsEstablished() throws {
        let pair = try makePair()
        _ = try establish(pair)
        pair.clock.now += WireGuardTunnel.rekeyAfterTime
        let initiation = try XCTUnwrap(pair.tunnel.tick().datagrams.last)
        let (response, _) = try answer(initiation, in: pair)
        XCTAssertFalse(pair.tunnel.receive(Data(response)).established)
    }

    func testAmneziaWGSendsItsJunkAndTalksPastTheS2Junk() throws {
        // Every knob at once: junk datagrams, S1 and S2, renumbered types.
        let h1: UInt32 = 0x1A2B_3C4D
        let h2: UInt32 = 0x2A3B_4C5D
        let h4: UInt32 = 0x7060_9579
        let pair = try makePair(extraInterface: [
            "Jc = 3", "Jmin = 40", "Jmax = 40", "S1 = 15", "S2 = 30",
            "H1 = \(h1)", "H2 = \(h2)", "H3 = 3333333", "H4 = \(h4)",
        ].joined(separator: "\n"))

        let tick = pair.tunnel.tick()
        XCTAssertEqual(tick.datagrams.count, 4)
        for junk in tick.datagrams.prefix(3) {
            XCTAssertEqual(junk.count, 40)
        }
        let junked = [UInt8](tick.datagrams[3])
        XCTAssertEqual(junked.count, 15 + WireGuardHandshake.initiationSize)
        // H1, all four octets of it, right after the S1 junk.
        XCTAssertEqual(Array(junked[15..<19]), [0x4D, 0x3C, 0x2B, 0x1A])

        // The peer strips S1 and reads the message as it would under type 1.
        var initiation = Array(junked[15...])
        WireGuardHandshake.writeLe32(&initiation, 0, WireGuardHandshake.messageInitiation)
        let (response, peer) = try answer(Data(initiation), in: pair, transportType: h4)

        // Its response goes out under H2 with 30 random bytes in front, which
        // is where a dispatcher reading offset 0 would lose it.
        var renumbered = response
        WireGuardHandshake.writeLe32(&renumbered, 0, h2)
        let onTheWire = WireGuardCrypto.randomBytes(30) + renumbered
        XCTAssertEqual(pair.tunnel.classify(Data(onTheWire)), .response)
        let inbound = pair.tunnel.receive(Data(onTheWire))
        XCTAssertTrue(inbound.established)

        // Transport messages carry H4, all four octets, both ways.
        let keepalive = try XCTUnwrap(inbound.datagrams.first)
        XCTAssertEqual([UInt8](keepalive.prefix(4)), [0x79, 0x95, 0x60, 0x70])
        XCTAssertEqual(peer.decapsulate(keepalive)?.count, 0)
        let down = ipv4Packet(33, fill: 0x44)
        XCTAssertEqual(pair.tunnel.receive(try peer.encapsulate(down)).packet, down)
        // A message under plain type 4 is not this peer's.
        var plainType = [UInt8](try peer.encapsulate(down))
        WireGuardHandshake.writeLe32(&plainType, 0, WireGuardHandshake.messageTransport)
        XCTAssertEqual(pair.tunnel.classify(Data(plainType)), .unknown)
    }

    func testAnUnansweredInitiationIsRetriedAfterFiveSeconds() throws {
        let pair = try makePair()
        XCTAssertEqual(pair.tunnel.tick().datagrams.count, 1)
        pair.clock.now += 1
        XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
        pair.clock.now += WireGuardTunnel.rekeyTimeout - 1
        XCTAssertEqual(pair.tunnel.tick().datagrams.count, 1)
    }

    func testAPeerSilentForNinetySecondsIsReportedOnceAndLookedUpAgain() throws {
        let pair = try makePair()
        var failures: [String] = []
        var lookups = 0
        let start = pair.clock.now
        while pair.clock.now - start <= 2 * WireGuardTunnel.handshakeGiveUp + 1 {
            let tick = pair.tunnel.tick()
            if let failure = tick.failure { failures.append(failure) }
            if tick.resolveEndpoint { lookups += 1 }
            pair.clock.now += 1
        }
        // One report per outage, but a fresh lookup every ninety seconds.
        XCTAssertEqual(failures.count, 1)
        XCTAssertEqual(lookups, 2)

        // A completed handshake ends the outage; the next one is reported again.
        pair.clock.now += WireGuardTunnel.rekeyTimeout
        _ = try establish(pair)
        pair.clock.now += WireGuardTunnel.rejectAfterTime
        var later: [String] = []
        let resumed = pair.clock.now
        while pair.clock.now - resumed <= WireGuardTunnel.handshakeGiveUp + 1 {
            if let failure = pair.tunnel.tick().failure { later.append(failure) }
            pair.clock.now += 1
        }
        XCTAssertEqual(later.count, 1)
    }

    func testACookieReplyIsAnsweredAtOnceWithMac2() throws {
        let pair = try makePair()
        let first = [UInt8](try XCTUnwrap(pair.tunnel.tick().datagrams.first))
        let mac1 = Array(first[116..<132])

        // The peer is under load: it seals a cookie to the initiation's mac1.
        let cookie: [UInt8] = (0..<16).map { UInt8(0x30 + $0) }
        let reply = try cookieReply(cookie, receiver: WireGuardHandshake.readLe32(first, 4), mac1: mac1, in: pair)
        XCTAssertEqual(reply.count, WireGuardTunnel.cookieReplySize)

        let inbound = pair.tunnel.receive(Data(reply))
        XCTAssertNil(inbound.packet)
        XCTAssertTrue(inbound.datagrams.isEmpty)

        // Retried at once, not after the five-second timer, with mac2 set.
        let retry = [UInt8](try XCTUnwrap(pair.tunnel.tick().datagrams.first))
        XCTAssertEqual(Array(retry[132..<148]), WireGuardCrypto.mac(key: cookie, data: Array(retry[0..<132])))
        // And the peer accepts it as an ordinary initiation.
        XCTAssertNoThrow(try answer(Data(retry), in: pair))
    }

    func testACookieSealedToAnotherMac1IsIgnored() throws {
        let pair = try makePair()
        let first = [UInt8](try XCTUnwrap(pair.tunnel.tick().datagrams.first))
        let reply = try cookieReply(
            [UInt8](repeating: 7, count: 16),
            receiver: WireGuardHandshake.readLe32(first, 4),
            mac1: [UInt8](repeating: 0, count: 16),
            in: pair
        )
        _ = pair.tunnel.receive(Data(reply))

        // No early retry, and the next initiation has no mac2.
        XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
        pair.clock.now += WireGuardTunnel.rekeyTimeout
        let retry = [UInt8](try XCTUnwrap(pair.tunnel.tick().datagrams.first))
        XCTAssertEqual(Array(retry[132..<148]), [UInt8](repeating: 0, count: 16))
    }

    func testPersistentKeepaliveFollowsTheLastSend() throws {
        let pair = try makePair(extraPeer: "PersistentKeepalive = 25")
        let peer = try establish(pair)

        pair.clock.now += 24
        XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
        pair.clock.now += 1
        let tick = pair.tunnel.tick()
        XCTAssertEqual(tick.datagrams.count, 1)
        XCTAssertEqual(peer.decapsulate(tick.datagrams[0])?.count, 0)

        // Traffic counts as a send: no keepalive while packets flow.
        pair.clock.now += 20
        XCTAssertNotNil(pair.tunnel.encapsulate(ipv4Packet(20, fill: 3)))
        pair.clock.now += 10
        XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
    }

    func testNoKeepaliveWithoutPersistentKeepalive() throws {
        let pair = try makePair()
        _ = try establish(pair)
        for _ in 0..<100 {
            pair.clock.now += 1
            XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
        }
    }

    func testARekeyKeepsTheOldSessionReadableUntilTheNewOneIsUp() throws {
        let pair = try makePair()
        let oldPeer = try establish(pair)

        pair.clock.now += WireGuardTunnel.rekeyAfterTime - 1
        XCTAssertTrue(pair.tunnel.tick().datagrams.isEmpty)
        pair.clock.now += 1
        let initiation = try XCTUnwrap(pair.tunnel.tick().datagrams.last)
        XCTAssertEqual(initiation.count, WireGuardHandshake.initiationSize)

        // Still sending under the old keys while the new handshake is out.
        let packet = ipv4Packet(20, fill: 9)
        XCTAssertEqual(oldPeer.decapsulate(try XCTUnwrap(pair.tunnel.encapsulate(packet)))?.prefix(20), packet)

        let (response, newPeer) = try answer(initiation, in: pair)
        _ = pair.tunnel.receive(Data(response))

        // New packets use the new session; the old one still reads.
        XCTAssertNotNil(newPeer.decapsulate(try XCTUnwrap(pair.tunnel.encapsulate(packet))))
        XCTAssertEqual(pair.tunnel.receive(try oldPeer.encapsulate(packet)).packet, packet)
        XCTAssertEqual(pair.tunnel.receive(try newPeer.encapsulate(packet)).packet, packet)
    }

    func testASessionPastRejectAfterTimeCarriesNothing() throws {
        let pair = try makePair()
        _ = try establish(pair)
        pair.clock.now += WireGuardTunnel.rejectAfterTime
        let tick = pair.tunnel.tick()
        XCTAssertFalse(pair.tunnel.hasSession)
        XCTAssertNil(pair.tunnel.encapsulate(ipv4Packet(20, fill: 1)))
        // And a fresh handshake is under way.
        XCTAssertEqual(tick.datagrams.last?.count, WireGuardHandshake.initiationSize)
    }

    func testANetworkChangeDropsTheSessionAndStartsAgainAtOnce() throws {
        let pair = try makePair()
        _ = try establish(pair)
        pair.tunnel.networkChanged()
        XCTAssertFalse(pair.tunnel.hasSession)
        XCTAssertNil(pair.tunnel.encapsulate(ipv4Packet(20, fill: 1)))
        XCTAssertEqual(pair.tunnel.tick().datagrams.count, 1)
    }

    func testAResponseToAnOlderInitiationIsRefused() throws {
        let pair = try makePair()
        let first = try XCTUnwrap(pair.tunnel.tick().datagrams.first)
        pair.clock.now += WireGuardTunnel.rekeyTimeout
        let second = try XCTUnwrap(pair.tunnel.tick().datagrams.first)

        // Only the latest attempt is pending.
        let (stale, _) = try answer(first, in: pair)
        _ = pair.tunnel.receive(Data(stale))
        XCTAssertFalse(pair.tunnel.hasSession)

        let (fresh, _) = try answer(second, in: pair)
        XCTAssertTrue(pair.tunnel.receive(Data(fresh)).established)
    }

    func testWarpReservedBytesAreStampedAndToleratedOnTheWayBack() throws {
        let pair = try makePair(extraInterface: "Reserved = 1,2,3")
        let initiation = [UInt8](try XCTUnwrap(pair.tunnel.tick().datagrams.first))
        XCTAssertEqual(Array(initiation[0..<4]), [1, 1, 2, 3])

        var cleared = initiation
        cleared[1] = 0
        cleared[2] = 0
        cleared[3] = 0
        let (response, peer) = try answer(Data(cleared), in: pair)
        var stamped = response
        stamped[1] = 9
        stamped[2] = 9
        stamped[3] = 9
        let inbound = pair.tunnel.receive(Data(stamped))
        XCTAssertTrue(inbound.established)
        let keepalive = try XCTUnwrap(inbound.datagrams.first)
        XCTAssertEqual([UInt8](keepalive.prefix(4)), [4, 1, 2, 3])
        // The peer reads past the stamp once it clears it, as WARP does.
        var unstamped = [UInt8](keepalive)
        unstamped[1] = 0
        unstamped[2] = 0
        unstamped[3] = 0
        XCTAssertEqual(peer.decapsulate(Data(unstamped))?.count, 0)
    }
}
