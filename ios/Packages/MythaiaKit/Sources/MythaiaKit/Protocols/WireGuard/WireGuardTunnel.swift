import Foundation

/// A WireGuard interface's protocol side: the handshake, its retries and
/// rekeys, keepalives, the cookie challenge, AmneziaWG's junk, and the
/// sessions packets are sealed and opened under.
///
/// Unlike every other outbound, WireGuard is not a stream proxy — there is no
/// per-flow dial and nothing for a packet stack to terminate. Whole IP packets
/// go in and come back out, so the tunnel runs this *instead of* its packet
/// stack. The sockets, the interface and the timer belong to the caller,
/// which feeds this what they produce and sends or writes what comes back; so
/// all of the protocol's decisions can be tested without a network.
///
/// Every method may be called from any thread. The live session and the one
/// it replaced are swapped under a lock, never mutated, so a rekey cannot tear
/// a packet in half; sealing and opening run outside it.
public final class WireGuardTunnel: @unchecked Sendable {

    /// What kind of message a received datagram is.
    public enum Kind: Equatable {
        case response, cookie, transport, unknown
    }

    /// What one datagram from the peer produced.
    public struct Inbound {
        /// An IP packet for the interface, cut to the length its header
        /// declares (the sender padded it to a multiple of 16).
        public var packet: Data?
        /// Datagrams for the peer: after a handshake, the keepalive that
        /// confirms the new session to it.
        public var datagrams: [Data] = []
        /// A session has just been established for the first time.
        public var established = false
    }

    /// What a timer tick asks for.
    public struct Tick {
        /// Datagrams for the peer: junk and an initiation, or a keepalive.
        public var datagrams: [Data] = []
        /// Set once per outage: the peer has not completed a handshake for
        /// `handshakeGiveUp` seconds.
        public var failure: String?
        /// Look the endpoint's name up again before the next attempt: a peer
        /// that stopped answering may have moved.
        public var resolveEndpoint = false
    }

    // WireGuard's own timers, in seconds.
    static let rekeyAfterTime: Double = 120
    static let rekeyTimeout: Double = 5
    static let handshakeGiveUp: Double = 90
    static let rejectAfterTime: Double = 180
    static let keepaliveTimeout: Double = 10
    static let cookieLifetime: Double = 120

    /// How often the caller should call `tick()`.
    public static let tickInterval: Double = 1

    /// type(4) + receiver(4) + nonce(24) + sealed cookie(16 + tag 16).
    static let cookieReplySize = 64

    public let config: WireGuardConfig

    private let clock: () -> Double
    private let lock = NSLock()

    // The four message types this peer uses. Plain WireGuard leaves them at
    // 1-4; AmneziaWG replaces each with its H1-H4.
    private let amnezia: AmneziaSettings
    private let initiationType: UInt32
    private let responseType: UInt32
    private let cookieType: UInt32
    private let transportType: UInt32
    // Cloudflare WARP's client id, stamped into octets 1-3 of what we send;
    // with it set, received types are matched on their low octet only.
    private let reserved: [UInt8]?

    private let privateKey: [UInt8]
    private let publicKey: [UInt8]
    private let peerPublicKey: [UInt8]
    private let presharedKey: [UInt8]

    // Everything below is guarded by `lock`.

    /// The live session, and the one it replaced. A rekey does not stop the
    /// peer sending under the old keys for a moment, so the previous session
    /// stays readable until the next rekey retires it.
    private var session: WireGuardTransport?
    private var previousSession: WireGuardTransport?
    private var sessionStartedAt: Double?

    /// The handshake waiting for a response, if one is in flight.
    private var pending: WireGuardHandshake?
    private var lastHandshakeAttempt: Double?
    /// When the current run of handshake attempts began. Separate from
    /// `lastHandshakeAttempt`, which moves on every retry: timing the give-up
    /// against that would compare a value to itself and never give up.
    private var handshakeSeriesStartedAt: Double?
    /// Whether the failure has already been reported for the current outage.
    private var failureReported = false
    private var lastSendAt: Double?

    private var cookie: [UInt8]?
    /// When the stored cookie stops being usable; mac2 reverts to zero after.
    private var cookieExpiresAt: Double = 0
    /// The mac1 of the initiation last sent. A cookie reply is sealed with it
    /// as the additional data, so it has to outlive the message it belonged to.
    private var lastSentMac1: [UInt8]?

    /// `clock` is seconds on a monotonic clock that keeps counting while the
    /// device sleeps, so a session left over from before a night's sleep is
    /// seen as the expired session it is; tests pass their own.
    public init(config: WireGuardConfig, clock: (() -> Double)? = nil) throws {
        let localPrivate = [UInt8](config.privateKey)
        let peerPublic = [UInt8](config.peer.publicKey)
        let psk = config.peer.presharedKey.map { [UInt8]($0) }
            ?? [UInt8](repeating: 0, count: WireGuardCrypto.keySize)
        guard localPrivate.count == WireGuardCrypto.keySize, peerPublic.count == WireGuardCrypto.keySize,
              psk.count == WireGuardCrypto.keySize else {
            throw MythaiaError.invalidConfiguration("WireGuard keys must be 32 bytes")
        }
        let localPublic = try WireGuardCrypto.publicKey(localPrivate)

        self.config = config
        self.clock = clock ?? EngineClock.seconds
        amnezia = config.amnezia
        initiationType = config.amnezia.initiationType
        responseType = config.amnezia.responseType
        cookieType = config.amnezia.cookieType
        transportType = config.amnezia.transportType
        reserved = config.headerReserved.map { [UInt8]($0) }
        privateKey = localPrivate
        publicKey = localPublic
        peerPublicKey = peerPublic
        presharedKey = psk
    }

    /// Whether a session is up to carry packets.
    public var hasSession: Bool {
        withLock { session != nil }
    }

    // MARK: - Packets

    /// Seals one packet read from the interface; nil when there is no session
    /// to send it under yet. The packet is dropped rather than queued then:
    /// TCP will resend, and a queue here would only add latency to whatever the
    /// handshake eventually carries.
    public func encapsulate(_ packet: Data) -> Data? {
        guard let active = withLock({ session }) else { return nil }
        do {
            let wrapped = try active.encapsulate(packet)
            let now = clock()
            withLock { lastSendAt = now }
            return wrapped
        } catch {
            Log.warning("[WG] Encapsulation failed: \(error.localizedDescription)")
            return nil
        }
    }

    /// Handles one datagram from the peer.
    public func receive(_ datagram: Data) -> Inbound {
        var result = Inbound()
        guard datagram.count >= 4 else { return result }
        switch classify(datagram) {
        case .response:
            completeHandshake([UInt8](datagram), into: &result)
        case .cookie:
            handleCookie([UInt8](datagram))
        case .transport:
            result.packet = deliver(datagram)
        case .unknown:
            // An initiation arriving at a client is the peer trying to be the
            // initiator; this side does not answer those.
            break
        }
        return result
    }

    /// Sorts a received datagram by kind.
    ///
    /// The type word is normally at offset 0, but AmneziaWG prepends S2 random
    /// bytes to the handshake response — and only to that message — so for a
    /// datagram of exactly the junked length the type is read past the junk
    /// instead. Reading offset 0 unconditionally would see random bytes and
    /// throw every response away, which is a handshake that never completes.
    public func classify(_ message: Data) -> Kind {
        if message.count < 4 { return .unknown }

        let junk = amnezia.responsePacketJunkSize
        if junk > 0 && message.count == WireGuardHandshake.responseSize + junk &&
            WireGuardHandshake.isType(WireGuardHandshake.readLe32(message, junk), responseType, reserved) {
            return .response
        }

        let type = WireGuardHandshake.readLe32(message, 0)
        if WireGuardHandshake.isType(type, responseType, reserved) { return .response }
        if WireGuardHandshake.isType(type, cookieType, reserved) { return .cookie }
        if WireGuardHandshake.isType(type, transportType, reserved) { return .transport }
        return .unknown
    }

    /// Opens one transport message; the packet inside, or nil for a
    /// keepalive or anything that does not open.
    private func deliver(_ message: Data) -> Data? {
        let (active, older) = withLock { (session, previousSession) }
        guard let packet = active?.decapsulate(message) ?? older?.decapsulate(message) else { return nil }

        // A keepalive is an empty packet; there is nothing to write.
        if packet.isEmpty { return nil }

        // The plaintext is padded to a multiple of 16, so the IP header's own
        // length field is what says where the packet actually ends.
        guard let length = WireGuardTunnel.ipPacketLength(packet), length <= packet.count else { return nil }
        if length == packet.count { return packet }
        return packet.prefix(length)
    }

    // MARK: - Handshake

    /// Begins an attempt: AmneziaWG's junk datagrams, then the initiation.
    /// Called with the lock held.
    private func beginHandshake(now: Double, into datagrams: inout [Data]) {
        lastHandshakeAttempt = now
        if handshakeSeriesStartedAt == nil { handshakeSeriesStartedAt = now }

        let handshake = WireGuardHandshake(
            localPrivateKey: privateKey,
            localPublicKey: publicKey,
            peerPublicKey: peerPublicKey,
            presharedKey: presharedKey,
            initiationType: initiationType,
            responseType: responseType,
            initiationJunkSize: amnezia.initPacketJunkSize,
            responseJunkSize: amnezia.responsePacketJunkSize,
            reserved: reserved
        )
        handshake.cookie = now < cookieExpiresAt ? cookie : nil

        // AmneziaWG opens with a burst of junk datagrams, so the first packet
        // of a session is not a recognisable handshake initiation.
        if amnezia.junkPacketCount > 0 {
            for _ in 0..<amnezia.junkPacketCount {
                let size = amnezia.junkSize()
                if size > 0 {
                    datagrams.append(Data(WireGuardCrypto.randomBytes(size)))
                }
            }
        }

        let initiation: [UInt8]
        do {
            initiation = try handshake.buildInitiation()
        } catch {
            Log.warning("[WG] Could not build the initiation: \(error.localizedDescription)")
            return
        }

        // mac1 is the 16 bytes before mac2, at the very end of the message.
        let end = initiation.count
        lastSentMac1 = Array(initiation[(end - 2 * WireGuardCrypto.macSize)..<(end - WireGuardCrypto.macSize)])

        pending = handshake
        datagrams.append(Data(initiation))
        lastSendAt = now
        Log.debug("[WG] Handshake initiation sent")
    }

    private func completeHandshake(_ message: [UInt8], into result: inout Inbound) {
        lock.lock()
        defer { lock.unlock() }
        guard let handshake = pending else { return }
        let keys: WireGuardHandshake.Keys
        do {
            keys = try handshake.consumeResponse(message)
        } catch {
            Log.warning("[WG] Handshake response refused: \(error.localizedDescription)")
            return
        }

        pending = nil
        handshakeSeriesStartedAt = nil
        failureReported = false
        previousSession = session
        let fresh = WireGuardTransport(
            sendKey: keys.sendKey,
            receiveKey: keys.receiveKey,
            peerIndex: keys.peerIndex,
            localIndex: keys.localIndex,
            transportType: transportType,
            reserved: reserved
        )
        session = fresh
        let first = sessionStartedAt == nil
        let now = clock()
        sessionStartedAt = now

        Log.info("[WG] Session established with \(config.peer.endpointHost)")
        result.established = first

        // A fresh session is silent until something is sent on it, and the peer
        // will not route to us before it has seen one authenticated packet.
        if let keepalive = try? fresh.encapsulate(Data()) {
            result.datagrams.append(keepalive)
            lastSendAt = now
        }
    }

    /// Stores the cookie from an under-load challenge.
    ///
    /// Layout is type(4) ‖ receiver(4) ‖ nonce(24) ‖ sealed cookie(32). The
    /// cookie is sealed with XChaCha20-Poly1305 under HASH(LABEL_COOKIE ‖ the
    /// peer's public key), with the mac1 of the message being answered as the
    /// additional data — so a reply cannot be replayed onto a different
    /// initiation, and the raw bytes are ciphertext, not the cookie.
    private func handleCookie(_ message: [UInt8]) {
        guard message.count >= WireGuardTunnel.cookieReplySize else { return }
        guard let mac1 = withLock({ lastSentMac1 }) else { return }

        let key = WireGuardCrypto.hash(WireGuardHandshake.labelCookie, peerPublicKey)
        let plaintext = WireGuardCrypto.xopen(
            key: key,
            nonce: Array(message[8..<32]),
            ciphertext: Array(message[32..<WireGuardTunnel.cookieReplySize]),
            aad: mac1
        )
        guard let cookieValue = plaintext, cookieValue.count == WireGuardCrypto.macSize else {
            Log.debug("[WG] Cookie reply did not authenticate")
            return
        }

        let now = clock()
        withLock {
            cookie = cookieValue
            cookieExpiresAt = now + WireGuardTunnel.cookieLifetime
            // The peer refused the initiation it challenged, so retry at once
            // with mac2 filled in rather than waiting out the retry timer.
            lastHandshakeAttempt = nil
        }
        Log.debug("[WG] Cookie challenge answered")
    }

    // MARK: - Timer

    /// Rekeying, retries, expiry and keepalives; call it every
    /// `tickInterval` seconds. The first call starts the first handshake.
    public func tick() -> Tick {
        var result = Tick()
        let now = clock()
        lock.lock()
        defer { lock.unlock() }

        retireExpiredSessions(now)

        if let active = session, !needsRekey(active, now) {
            let keepalive = config.peer.persistentKeepalive
            var due = true
            if let last = lastSendAt {
                due = now - last >= Double(keepalive)
            }
            if keepalive > 0 && due {
                if let wrapped = try? active.encapsulate(Data()) {
                    result.datagrams.append(wrapped)
                    lastSendAt = now
                }
            }
            return result
        }

        if let last = lastHandshakeAttempt, now - last < WireGuardTunnel.rekeyTimeout {
            return result
        }
        // A run of attempts that has got nowhere: the name may point somewhere
        // else now, so look it up again before spending another ninety
        // seconds on the same address.
        if let series = handshakeSeriesStartedAt, now - series >= WireGuardTunnel.handshakeGiveUp {
            result.resolveEndpoint = true
            handshakeSeriesStartedAt = now
            let reason = "no handshake for \(Int(WireGuardTunnel.handshakeGiveUp))s"
            if !failureReported {
                failureReported = true
                Log.warning("[WG] \(reason)")
                result.failure = reason
            }
        }
        beginHandshake(now: now, into: &result.datagrams)
        return result
    }

    /// Drops a session that has outlived its keys.
    ///
    /// Past REJECT_AFTER_TIME a peer must stop using a session entirely rather
    /// than keep sending under it: the far side has already discarded it, so
    /// everything sent after that point goes nowhere. Retiring it here is what
    /// makes the uplink stop and a fresh handshake start.
    private func retireExpiredSessions(_ now: Double) {
        guard let started = sessionStartedAt else { return }
        let age = now - started
        if age >= WireGuardTunnel.rejectAfterTime {
            if session != nil { Log.debug("[WG] Session expired, rekeying") }
            session = nil
            previousSession = nil
        } else if age >= WireGuardTunnel.rekeyAfterTime + WireGuardTunnel.keepaliveTimeout {
            // The replaced session stops being useful long before the live one.
            previousSession = nil
        }
    }

    private func needsRekey(_ active: WireGuardTransport, _ now: Double) -> Bool {
        if active.needsRekey || active.isExhausted { return true }
        guard let started = sessionStartedAt else { return true }
        return now - started >= WireGuardTunnel.rekeyAfterTime
    }

    // MARK: - Network changes

    /// Forgets every session after the network underneath changed.
    ///
    /// The socket was bound on a path that no longer exists, and the name may
    /// resolve somewhere else on the new one; the caller replaces both, and the
    /// next tick starts a fresh handshake rather than waiting out a rekey that
    /// would go out of the wrong interface.
    public func networkChanged() {
        withLock {
            session = nil
            previousSession = nil
            pending = nil
            sessionStartedAt = nil
            handshakeSeriesStartedAt = nil
            lastHandshakeAttempt = nil
            failureReported = false
        }
    }

    // MARK: - Helpers

    /// The length an IP packet declares for itself, or nil when the header is
    /// not one this tunnel carries.
    public static func ipPacketLength(_ packet: Data) -> Int? {
        guard let first = packet.first else { return nil }
        let base = packet.startIndex
        switch first >> 4 {
        case 4:
            guard packet.count >= 20 else { return nil }
            return (Int(packet[base + 2]) << 8) | Int(packet[base + 3])
        case 6:
            guard packet.count >= 40 else { return nil }
            // IPv6's length covers the payload only; the header is fixed.
            return 40 + ((Int(packet[base + 4]) << 8) | Int(packet[base + 5]))
        default:
            return nil
        }
    }

    @discardableResult
    private func withLock<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}
