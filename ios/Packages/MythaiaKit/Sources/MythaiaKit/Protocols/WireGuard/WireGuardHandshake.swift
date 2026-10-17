import Foundation

/// The WireGuard handshake: Noise_IKpsk2 over X25519, ChaCha20-Poly1305 and
/// BLAKE2s, with the message layout from the protocol paper.
///
/// Initiation (148 bytes) and response (92 bytes) are fixed sizes — every field
/// is fixed width, which is itself part of the design: there is nothing on the
/// wire whose length says anything.
///
/// One instance is one attempt: build the initiation, then consume the
/// response to it.
final class WireGuardHandshake {

    /// What a completed handshake yields.
    struct Keys {
        let sendKey: [UInt8]
        let receiveKey: [UInt8]
        let localIndex: UInt32
        let peerIndex: UInt32
    }

    // The type field is a 32-bit little-endian word. The paper writes it as
    // type(1) followed by three reserved zero bytes, which is the same encoding
    // for these four values; AmneziaWG replaces the whole word.
    static let messageInitiation: UInt32 = 1
    static let messageResponse: UInt32 = 2
    static let messageCookie: UInt32 = 3
    static let messageTransport: UInt32 = 4

    static let initiationSize = 148
    static let responseSize = 92

    static let construction = Array("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".utf8)
    static let identifier = Array("WireGuard v1 zx2c4 Jason@zx2c4.com".utf8)
    static let labelMac1 = Array("mac1----".utf8)
    static let labelCookie = Array("cookie--".utf8)

    private let localPrivateKey: [UInt8]
    private let localPublicKey: [UInt8]
    private let peerPublicKey: [UInt8]
    /// Optional pre-shared key, mixed in at the end. All zeroes when unused.
    private let presharedKey: [UInt8]
    /// AmneziaWG's wire tweaks: renumbered message types (H1, H2) and random
    /// bytes prepended to each handshake message (S1, S2). The defaults are
    /// plain WireGuard, which is AmneziaWG with every knob at its identity.
    private let initiationType: UInt32
    private let responseType: UInt32
    private let initiationJunkSize: Int
    private let responseJunkSize: Int
    /// WARP's three reserved bytes (`WireGuardConfig.headerReserved`), or nil
    /// for plain WireGuard. See `stampReserved` and `isType`.
    private let reserved: [UInt8]?

    private var chainingKey: [UInt8] = []
    private var hash: [UInt8] = []
    private var ephemeralPrivate: [UInt8] = []
    private var ephemeralPublic: [UInt8] = []

    /// Our own index, echoed by the peer so it can be matched to this session.
    private(set) var localIndex: UInt32 = 0

    /// The most recent cookie from the peer, if it has challenged us; mac2 is
    /// computed with it.
    var cookie: [UInt8]?

    init(
        localPrivateKey: [UInt8],
        localPublicKey: [UInt8],
        peerPublicKey: [UInt8],
        presharedKey: [UInt8] = [UInt8](repeating: 0, count: WireGuardCrypto.keySize),
        initiationType: UInt32 = WireGuardHandshake.messageInitiation,
        responseType: UInt32 = WireGuardHandshake.messageResponse,
        initiationJunkSize: Int = 0,
        responseJunkSize: Int = 0,
        reserved: [UInt8]? = nil
    ) {
        self.localPrivateKey = localPrivateKey
        self.localPublicKey = localPublicKey
        self.peerPublicKey = peerPublicKey
        self.presharedKey = presharedKey
        self.initiationType = initiationType
        self.responseType = responseType
        self.initiationJunkSize = max(0, initiationJunkSize)
        self.responseJunkSize = max(0, responseJunkSize)
        self.reserved = reserved
    }

    /// Builds the initiation message.
    ///
    /// - Parameters:
    ///   - index: our sender index, which the peer will echo back.
    ///   - timestamp: overridable for tests; defaults to now.
    ///   - ephemeralPrivateKey: overridable for tests, which need the whole
    ///     message to come out the same every time; a fresh key otherwise.
    func buildInitiation(
        index: UInt32 = WireGuardHandshake.randomIndex(),
        timestamp: [UInt8] = WireGuardCrypto.tai64n(),
        ephemeralPrivateKey: [UInt8]? = nil
    ) throws -> [UInt8] {
        localIndex = index

        // Ci = HASH(CONSTRUCTION); Hi = HASH(Ci ‖ IDENTIFIER); Hi = HASH(Hi ‖ Spub_r)
        var c = WireGuardCrypto.hash(WireGuardHandshake.construction)
        var h = WireGuardCrypto.hash(WireGuardCrypto.hash(c, WireGuardHandshake.identifier), peerPublicKey)

        if let given = ephemeralPrivateKey {
            ephemeralPrivate = given
            ephemeralPublic = try WireGuardCrypto.publicKey(given)
        } else {
            let pair = WireGuardCrypto.generateKeyPair()
            ephemeralPrivate = pair.privateKey
            ephemeralPublic = pair.publicKey
        }

        // Ci = KDF1(Ci, Epub_i); Hi = HASH(Hi ‖ Epub_i)
        c = WireGuardCrypto.kdf(c, ephemeralPublic, count: 1)[0]
        h = WireGuardCrypto.hash(h, ephemeralPublic)

        // (Ci, k) = KDF2(Ci, DH(Epriv_i, Spub_r))
        let es = try WireGuardCrypto.sharedSecret(ephemeralPrivate, peerPublicKey)
        var derived = WireGuardCrypto.kdf(c, es, count: 2)
        c = derived[0]

        let encryptedStatic = try WireGuardCrypto.seal(key: derived[1], counter: 0, plaintext: localPublicKey, aad: h)
        h = WireGuardCrypto.hash(h, encryptedStatic)

        // (Ci, k) = KDF2(Ci, DH(Spriv_i, Spub_r))
        let ss = try WireGuardCrypto.sharedSecret(localPrivateKey, peerPublicKey)
        derived = WireGuardCrypto.kdf(c, ss, count: 2)
        c = derived[0]

        let encryptedTimestamp = try WireGuardCrypto.seal(key: derived[1], counter: 0, plaintext: timestamp, aad: h)
        h = WireGuardCrypto.hash(h, encryptedTimestamp)

        chainingKey = c
        hash = h

        var body = [UInt8](repeating: 0, count: 8)
        WireGuardHandshake.writeLe32(&body, 0, initiationType)
        WireGuardHandshake.writeLe32(&body, 4, index)
        body.append(contentsOf: ephemeralPublic)
        body.append(contentsOf: encryptedStatic)
        body.append(contentsOf: encryptedTimestamp)
        guard body.count == 116 else {
            throw MythaiaError.protocolError("WireGuard initiation came out \(body.count) bytes before its MACs")
        }

        // The MACs cover the message only. S1's junk is prepended afterwards,
        // so it is outside both the MAC and the peer's length check.
        var message = body + macs(body)
        // The reserved bytes go on after the MACs, over a type word the MACs
        // saw as zeroes — which is what WARP verifies against, because every
        // client that speaks to it stamps them at send time the same way.
        WireGuardHandshake.stampReserved(&message, 0, reserved)
        return junk(initiationJunkSize) + message
    }

    /// Consumes the peer's response and derives the transport keys.
    ///
    /// Throws when the message is not a well-formed response to the initiation
    /// this instance sent. A wrong key looks the same as a tampered packet, and
    /// both are refused rather than guessed at. Nothing is kept from a refused
    /// response, so the genuine one can still follow it.
    func consumeResponse(_ response: [UInt8]) throws -> Keys {
        // S2 prepends random bytes to the response; drop them before parsing.
        // Only a response of exactly the junked length is trimmed, so a peer
        // that turns out not to be sending junk still reports a size mismatch
        // rather than being silently misparsed.
        let message: [UInt8]
        if responseJunkSize > 0 && response.count == WireGuardHandshake.responseSize + responseJunkSize {
            message = Array(response[responseJunkSize...])
        } else {
            message = response
        }

        if message.count != WireGuardHandshake.responseSize {
            throw MythaiaError.protocolError("WireGuard response is \(message.count) bytes, expected \(WireGuardHandshake.responseSize)")
        }
        let type = WireGuardHandshake.readLe32(message, 0)
        if !WireGuardHandshake.isType(type, responseType, reserved) {
            throw MythaiaError.protocolError("WireGuard message type \(type) is not a handshake response")
        }
        guard !ephemeralPrivate.isEmpty else {
            throw MythaiaError.protocolError("WireGuard response arrived before an initiation was sent")
        }

        let peerIndex = WireGuardHandshake.readLe32(message, 4)
        let echoedIndex = WireGuardHandshake.readLe32(message, 8)
        if echoedIndex != localIndex {
            throw MythaiaError.protocolError("WireGuard response echoes index \(echoedIndex), not ours")
        }

        let peerEphemeral = Array(message[12..<44])
        let encryptedNothing = Array(message[44..<60])

        // Cr = KDF1(Cr, Epub_r); Hr = HASH(Hr ‖ Epub_r)
        var c = WireGuardCrypto.kdf(chainingKey, peerEphemeral, count: 1)[0]
        var h = WireGuardCrypto.hash(hash, peerEphemeral)

        // Cr = KDF1(Cr, DH(Epriv_i, Epub_r)); Cr = KDF1(Cr, DH(Spriv_i, Epub_r))
        let ee = try WireGuardCrypto.sharedSecret(ephemeralPrivate, peerEphemeral)
        c = WireGuardCrypto.kdf(c, ee, count: 1)[0]
        let se = try WireGuardCrypto.sharedSecret(localPrivateKey, peerEphemeral)
        c = WireGuardCrypto.kdf(c, se, count: 1)[0]

        // (Cr, τ, k) = KDF3(Cr, Q); Hr = HASH(Hr ‖ τ)
        let derived = WireGuardCrypto.kdf(c, presharedKey, count: 3)
        c = derived[0]
        h = WireGuardCrypto.hash(h, derived[1])

        guard WireGuardCrypto.open(key: derived[2], counter: 0, ciphertext: encryptedNothing, aad: h) != nil else {
            throw MythaiaError.protocolError("WireGuard response did not authenticate")
        }
        h = WireGuardCrypto.hash(h, encryptedNothing)

        chainingKey = c
        hash = h

        // (T_send, T_recv) = KDF2(Cr, ε)
        let transport = WireGuardCrypto.kdf(c, [], count: 2)
        return Keys(sendKey: transport[0], receiveKey: transport[1], localIndex: localIndex, peerIndex: peerIndex)
    }

    /// The two MACs that close every handshake message.
    ///
    /// mac1 proves the sender knows the peer's public key, which lets a server
    /// drop unauthenticated floods cheaply. mac2 answers a cookie challenge and
    /// is zero until one arrives.
    private func macs(_ body: [UInt8]) -> [UInt8] {
        let mac1Key = WireGuardCrypto.hash(WireGuardHandshake.labelMac1, peerPublicKey)
        let mac1 = WireGuardCrypto.mac(key: mac1Key, data: body)

        let mac2: [UInt8]
        if let cookie = cookie {
            mac2 = WireGuardCrypto.mac(key: cookie, data: body + mac1)
        } else {
            mac2 = [UInt8](repeating: 0, count: WireGuardCrypto.macSize)
        }
        return mac1 + mac2
    }

    /// `size` random bytes, or nothing when no junk was configured.
    private func junk(_ size: Int) -> [UInt8] {
        size > 0 ? WireGuardCrypto.randomBytes(size) : []
    }

    static func randomIndex() -> UInt32 {
        readLe32(WireGuardCrypto.randomBytes(4), 0)
    }

    /// Puts WARP's reserved bytes into octets 1-3 of the type word at `at`.
    ///
    /// Only the octets change, never the length or anything authenticated:
    /// a transport message's header is outside its AEAD, and a handshake
    /// message's MACs are computed before this is called.
    static func stampReserved(_ message: inout [UInt8], _ at: Int, _ reserved: [UInt8]?) {
        guard let reserved = reserved, reserved.count == 3, message.count >= at + 4 else { return }
        message[at + 1] = reserved[0]
        message[at + 2] = reserved[1]
        message[at + 3] = reserved[2]
    }

    /// Whether a received type word is `expected`.
    ///
    /// The whole word normally — AmneziaWG's H1-H4 fill all four octets.
    /// With reserved bytes in use only the low octet is the type: WARP puts
    /// its own bytes in the other three, and Xray and sing-box both clear
    /// them before looking, so comparing them would drop every reply.
    static func isType(_ word: UInt32, _ expected: UInt32, _ reserved: [UInt8]?) -> Bool {
        if reserved != nil {
            return (word & 0xFF) == (expected & 0xFF)
        }
        return word == expected
    }

    // MARK: - Little-endian fields

    static func writeLe32(_ out: inout [UInt8], _ at: Int, _ value: UInt32) {
        out[at] = UInt8(truncatingIfNeeded: value)
        out[at + 1] = UInt8(truncatingIfNeeded: value >> 8)
        out[at + 2] = UInt8(truncatingIfNeeded: value >> 16)
        out[at + 3] = UInt8(truncatingIfNeeded: value >> 24)
    }

    static func readLe32(_ bytes: [UInt8], _ at: Int) -> UInt32 {
        UInt32(bytes[at]) |
            (UInt32(bytes[at + 1]) << 8) |
            (UInt32(bytes[at + 2]) << 16) |
            (UInt32(bytes[at + 3]) << 24)
    }

    static func writeLe64(_ out: inout [UInt8], _ at: Int, _ value: UInt64) {
        var v = value
        for index in 0..<8 {
            out[at + index] = UInt8(truncatingIfNeeded: v)
            v >>= 8
        }
    }

    static func readLe64(_ bytes: [UInt8], _ at: Int) -> UInt64 {
        var v: UInt64 = 0
        var index = 7
        while index >= 0 {
            v = (v << 8) | UInt64(bytes[at + index])
            index -= 1
        }
        return v
    }

    /// A field of a received datagram, which may be a slice that does not
    /// start at index 0.
    static func readLe32(_ data: Data, _ at: Int) -> UInt32 {
        let base = data.startIndex + at
        return UInt32(data[base]) |
            (UInt32(data[base + 1]) << 8) |
            (UInt32(data[base + 2]) << 16) |
            (UInt32(data[base + 3]) << 24)
    }

    static func readLe64(_ data: Data, _ at: Int) -> UInt64 {
        let base = data.startIndex + at
        var v: UInt64 = 0
        var index = 7
        while index >= 0 {
            v = (v << 8) | UInt64(data[base + index])
            index -= 1
        }
        return v
    }
}
