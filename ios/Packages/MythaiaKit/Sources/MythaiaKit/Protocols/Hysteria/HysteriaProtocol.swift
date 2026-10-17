import Foundation

/// The Hysteria 2 wire format.
///
/// Hysteria runs everything inside one QUIC connection to the server. The
/// client first authenticates over HTTP/3 — a `POST /auth` whose interesting
/// parts are three request headers and a private success status — and
/// afterwards a proxied TCP flow is a QUIC stream carrying one framed request,
/// while proxied UDP is carried in QUIC datagrams that name their own
/// destination. Because a datagram cannot be split by the transport the way a
/// stream can, Hysteria does its own fragmentation: every datagram header
/// carries a packet id and a fragment index so the far side can put a large
/// UDP packet back together.
///
/// Everything here is a pure function of bytes, which is what lets it be
/// checked against the specification instead of against itself.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
enum HysteriaProtocol {
    /// The varint that prefixes every proxied TCP request.
    static let tcpRequestFrameType: Int64 = 0x401
    /// Closing cleanly.
    static let closeErrCodeOk: Int64 = 0x100
    /// Closing because the peer broke the framing rules.
    static let closeErrCodeProtocolError: Int64 = 0x101
    /// The only accepting value of a TCP response's status byte.
    static let tcpResponseStatusOk: UInt8 = 0

    /// The status the server answers `/auth` with when it accepts the
    /// password. Deliberately outside the registered range, so a probe sees an
    /// ordinary HTTP/3 server answering 404 rather than anything that
    /// identifies Hysteria.
    static let authSuccessStatus = 233
    /// The `:authority` the auth request claims; it is never resolved.
    static let authAuthority = "hysteria"
    static let authPath = "/auth"

    /// HTTP/3 field names are lowercase, so these match verbatim.
    static let headerStatus = ":status"
    static let headerAuth = "hysteria-auth"
    static let headerCcRx = "hysteria-cc-rx"
    static let headerPadding = "hysteria-padding"
    static let headerUdp = "hysteria-udp"
    static let headerContentLength = "content-length"

    /// The `hysteria-cc-rx` value meaning "run your own bandwidth detection".
    static let ccRxAuto = "auto"

    /// Length of the padding on the auth request and its response.
    static let authPaddingRange = 256...2047
    /// Length of the padding on a TCP request.
    static let tcpRequestPaddingRange = 64...511

    // Parsing limits, so a hostile server cannot make the client allocate on
    // the strength of a length field alone.
    static let maxAddressLength = 2048
    static let maxResponseMessageLength = 2048
    static let maxPaddingLength = 4096

    /// A destination the way Hysteria writes it: `host:port`, UTF-8, with an
    /// IPv6 literal in brackets per RFC 3986 §3.2.2 so the colons inside the
    /// address cannot be mistaken for the port separator.
    static func formatAddress(host: String, port: UInt16) -> String {
        return host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    // MARK: - TCP

    /// A proxy request: the frame type, the destination, and cover-traffic
    /// padding, each length-prefixed with a QUIC varint. `padding` is a
    /// parameter so the bytes are reproducible under test; the server never
    /// looks at it.
    static func encodeTcpRequest(address: String, padding: [UInt8]? = nil) -> [UInt8] {
        let pad = padding ?? randomPadding(range: tcpRequestPaddingRange)
        let addr = Array(address.utf8)
        var out: [UInt8] = []
        QuicVarInt.append(tcpRequestFrameType, to: &out)
        QuicVarInt.append(Int64(addr.count), to: &out)
        out.append(contentsOf: addr)
        QuicVarInt.append(Int64(pad.count), to: &out)
        out.append(contentsOf: pad)
        return out
    }

    /// The server's answer to a proxy request. `consumed` is how much of the
    /// buffer the response occupied, so a caller reading a stream knows where
    /// the proxied payload begins.
    struct TcpResponse: Equatable {
        let status: UInt8
        let message: String
        let consumed: Int

        var isOk: Bool { status == HysteriaProtocol.tcpResponseStatusOk }
    }

    /// Parses a TCP response, or nil when `bytes` does not yet hold a whole
    /// one. Nil also comes back when a length exceeds its limit, which a
    /// caller cannot tell apart from "wait for more"; the limits are far above
    /// anything a real server sends, so both mean this connection will not
    /// produce a usable response.
    static func parseTcpResponse(_ bytes: [UInt8]) -> TcpResponse? {
        if bytes.isEmpty { return nil }
        let status = bytes[0]
        var at = 1
        guard let messageLength = QuicVarInt.decode(bytes, at) else { return nil }
        if messageLength.value > Int64(maxResponseMessageLength) { return nil }
        at += messageLength.size
        if Int64(at) + messageLength.value > Int64(bytes.count) { return nil }
        // Lenient on purpose: this is a human-readable diagnostic, and losing
        // a character to U+FFFD beats discarding the reason for a refusal.
        let message = String(decoding: bytes[at..<(at + Int(messageLength.value))], as: UTF8.self)
        at += Int(messageLength.value)

        guard let paddingLength = QuicVarInt.decode(bytes, at) else { return nil }
        if paddingLength.value > Int64(maxPaddingLength) { return nil }
        at += paddingLength.size
        if Int64(at) + paddingLength.value > Int64(bytes.count) { return nil }
        at += Int(paddingLength.value)
        return TcpResponse(status: status, message: message, consumed: at)
    }

    // MARK: - UDP

    /// sessionId(4) ‖ packetId(2) ‖ fragId(1) ‖ fragCount(1), big-endian.
    static let udpHeaderFixedSize = 4 + 2 + 1 + 1
    /// A fragment index is one byte, so no packet can be cut into more.
    static let maxFragments = 255

    /// One Hysteria UDP datagram. Neither the address nor the payload carries
    /// a trailing length: the address is varint-prefixed and the payload runs
    /// to the end of the datagram, which QUIC delivers whole.
    struct UdpMessage: Equatable {
        let sessionId: Int64
        let packetId: Int
        let fragId: Int
        let fragCount: Int
        /// UTF-8 `host:port`, as `formatAddress` produces it.
        let address: String
        let payload: [UInt8]

        /// Throws for a field its wire width cannot hold, rather than
        /// truncating it into a different number.
        init(sessionId: Int64, packetId: Int, fragId: Int, fragCount: Int, address: String, payload: [UInt8]) throws {
            guard (0...0xFFFF_FFFF).contains(sessionId) else {
                throw MythaiaError.invalidConfiguration("session id out of range: \(sessionId)")
            }
            guard (0...0xFFFF).contains(packetId) else {
                throw MythaiaError.invalidConfiguration("packet id out of range: \(packetId)")
            }
            guard (0...0xFF).contains(fragId) else {
                throw MythaiaError.invalidConfiguration("fragment id out of range: \(fragId)")
            }
            guard (0...0xFF).contains(fragCount) else {
                throw MythaiaError.invalidConfiguration("fragment count out of range: \(fragCount)")
            }
            self.sessionId = sessionId
            self.packetId = packetId
            self.fragId = fragId
            self.fragCount = fragCount
            self.address = address
            self.payload = payload
        }

        func encode() -> [UInt8] {
            let addr = Array(address.utf8)
            var out: [UInt8] = [
                UInt8(truncatingIfNeeded: sessionId >> 24),
                UInt8(truncatingIfNeeded: sessionId >> 16),
                UInt8(truncatingIfNeeded: sessionId >> 8),
                UInt8(truncatingIfNeeded: sessionId),
                UInt8(truncatingIfNeeded: packetId >> 8),
                UInt8(truncatingIfNeeded: packetId),
                UInt8(truncatingIfNeeded: fragId),
                UInt8(truncatingIfNeeded: fragCount),
            ]
            out.reserveCapacity(out.count + 2 + addr.count + payload.count)
            QuicVarInt.append(Int64(addr.count), to: &out)
            out.append(contentsOf: addr)
            out.append(contentsOf: payload)
            return out
        }
    }

    /// Parses a datagram, or nil when it is not a well-formed one. A datagram
    /// whose payload would be empty is rejected: the reassembly table is keyed
    /// by packet id, and zero-byte fragments are otherwise a free way to
    /// occupy every slot in it. Nothing legitimate sends one.
    static func decodeUdpMessage(_ datagram: [UInt8]) -> UdpMessage? {
        if datagram.count < udpHeaderFixedSize { return nil }
        let sessionId = Int64(datagram[0]) << 24 | Int64(datagram[1]) << 16 | Int64(datagram[2]) << 8 | Int64(datagram[3])
        let packetId = Int(datagram[4]) << 8 | Int(datagram[5])
        let fragId = Int(datagram[6])
        let fragCount = Int(datagram[7])

        guard let addressLength = QuicVarInt.decode(datagram, udpHeaderFixedSize) else { return nil }
        if addressLength.value <= 0 || addressLength.value > Int64(maxAddressLength) { return nil }
        let at = udpHeaderFixedSize + addressLength.size
        // Strictly less than: the address must be followed by payload.
        if Int64(at) + addressLength.value >= Int64(datagram.count) { return nil }
        let end = at + Int(addressLength.value)
        guard let address = strictUtf8(Array(datagram[at..<end])) else { return nil }
        return try? UdpMessage(sessionId: sessionId, packetId: packetId, fragId: fragId, fragCount: fragCount,
                               address: address, payload: Array(datagram[end...]))
    }

    /// How many bytes a datagram spends before its payload.
    static func udpHeaderSize(address: String) -> Int {
        let length = address.utf8.count
        return udpHeaderFixedSize + QuicVarInt.sizeOf(Int64(length)) + length
    }

    /// Cuts a UDP payload into datagrams that each fit `maxDatagramSize`. A
    /// payload that already fits becomes one message marked `fragCount = 1`,
    /// which the far side forwards without touching its reassembly table.
    /// Empty when the payload would need more than `maxFragments` pieces: the
    /// count has nowhere to go, and the write must fail rather than truncate.
    static func fragmentUdp(sessionId: Int64, packetId: Int, address: String, payload: [UInt8],
                            maxDatagramSize: Int) -> [UdpMessage] {
        let maxPayload = max(1, maxDatagramSize - udpHeaderSize(address: address))
        if payload.count <= maxPayload {
            if let single = try? UdpMessage(sessionId: sessionId, packetId: packetId, fragId: 0, fragCount: 1,
                                            address: address, payload: payload) {
                return [single]
            }
            return []
        }
        let chunks = (payload.count + maxPayload - 1) / maxPayload
        if chunks > maxFragments { return [] }
        var out: [UdpMessage] = []
        for index in 0..<chunks {
            let start = index * maxPayload
            let end = min(start + maxPayload, payload.count)
            guard let message = try? UdpMessage(sessionId: sessionId, packetId: packetId, fragId: index,
                                                fragCount: chunks, address: address,
                                                payload: Array(payload[start..<end])) else { return [] }
            out.append(message)
        }
        return out
    }

    // MARK: - Authentication

    /// The Hysteria-specific headers of the `POST /auth` request.
    /// `content-length: 0` because the request carries no body; the password
    /// travels as a header, which is what lets the whole exchange look like an
    /// ordinary HTTP/3 request.
    static func authRequestHeaders(password: String, clientRxBytesPerSec: Int64, padding: String? = nil) -> [Http3Field] {
        return [
            Http3Field(name: headerAuth, value: password),
            Http3Field(name: headerCcRx, value: String(clientRxBytesPerSec)),
            Http3Field(name: headerPadding, value: padding ?? randomPaddingString(range: authPaddingRange)),
            Http3Field(name: headerContentLength, value: "0"),
        ]
    }

    /// What the server said in reply. `serverRxBytesPerSec` is nil when it
    /// answered `auto` — it will measure its own downlink — which is a
    /// different instruction from a declared rate of zero.
    struct AuthResponse: Equatable {
        let status: Int
        let udpSupported: Bool
        let serverRxBytesPerSec: Int64?

        var isAccepted: Bool { status == HysteriaProtocol.authSuccessStatus }
    }

    /// Reads the auth response headers, or nil when there is no usable
    /// `:status` — a reply that cannot be graded is a failure, not a refusal.
    static func parseAuthResponse(_ headers: [Http3Field]) -> AuthResponse? {
        guard let statusText = headers.first(where: { $0.name == headerStatus })?.value,
              let status = Int(statusText) else { return nil }
        let udp = headers.first(where: { $0.name == headerUdp })?.value.lowercased() == "true"
        let ccRx = headers.first(where: { $0.name == headerCcRx })?.value ?? ""
        let rate: Int64? = ccRx.lowercased() == ccRxAuto ? nil : (Int64(ccRx) ?? 0)
        return AuthResponse(status: status, udpSupported: udp, serverRxBytesPerSec: rate)
    }

    // MARK: - Padding

    /// The alphabet Hysteria's padding is drawn from. Printable ASCII lets the
    /// same generator fill both a binary frame and an HTTP header value.
    static let paddingAlphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)

    /// `length` bytes of `[A-Za-z0-9]` cover traffic. Folding random bytes into
    /// a 62-letter alphabet is slightly biased; nothing reads these bytes
    /// back, and the only property that matters is that sizes vary.
    static func randomPadding(length: Int) -> [UInt8] {
        if length <= 0 { return [] }
        return TLSWire.randomBytes(length).map { paddingAlphabet[Int($0) % paddingAlphabet.count] }
    }

    static func randomPadding(range: ClosedRange<Int>) -> [UInt8] {
        return randomPadding(length: Int.random(in: range))
    }

    /// The same bytes as a string, for the `hysteria-padding` header.
    static func randomPaddingString(range: ClosedRange<Int> = authPaddingRange) -> String {
        return String(decoding: randomPadding(range: range), as: UTF8.self)
    }

    /// Strict UTF-8: a malformed address is refused rather than turned into
    /// replacement characters, which would proxy to a destination nobody named.
    static func strictUtf8(_ bytes: [UInt8]) -> String? {
        let text = String(decoding: bytes, as: UTF8.self)
        return Array(text.utf8) == bytes ? text : nil
    }
}

/// Puts fragmented Hysteria UDP datagrams back together.
///
/// Fragments of one packet share a packet id and arrive in no particular
/// order, so each id gets a slot holding the pieces seen so far. An incomplete
/// slot — a fragment lost in the network — would otherwise sit there forever;
/// the two bounds below stop that becoming a leak a peer could drive.
///
/// Per-flow state, not synchronised: one instance belongs to one UDP session.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class HysteriaDefragmenter {
    /// How long an incomplete packet is worth holding on to.
    static let slotTtlNanos: Int64 = 10 * 1_000_000_000
    /// How many packets may be part-assembled at once.
    static let maxSlots = 32

    private struct Slot {
        let fragmentCount: Int
        let createdAt: Int64
        var fragments: [[UInt8]?]
        var received = 0
    }

    private let maxSlots: Int
    private let slotTtlNanos: Int64
    private let clock: () -> Int64
    private var slots: [Int: Slot] = [:]

    /// `clock` is injectable so the expiry rule can be exercised without waiting.
    init(maxSlots: Int = HysteriaDefragmenter.maxSlots, slotTtlNanos: Int64 = HysteriaDefragmenter.slotTtlNanos,
         clock: @escaping () -> Int64 = { Int64(DispatchTime.now().uptimeNanoseconds) }) {
        self.maxSlots = maxSlots
        self.slotTtlNanos = slotTtlNanos
        self.clock = clock
    }

    /// How many packets are part-assembled; bounded by `maxSlots`.
    var slotCount: Int { slots.count }

    /// Feeds one datagram in, returning the whole payload once its packet is
    /// complete and nil while pieces are missing. An unfragmented message
    /// passes straight through.
    func accept(_ message: HysteriaProtocol.UdpMessage) -> [UInt8]? {
        if message.fragCount <= 1 { return message.payload }
        // An index past the end names a fragment that cannot exist.
        if message.fragId >= message.fragCount { return nil }

        let now = clock()
        let existing = slots[message.packetId]
        let expired = existing.map { now - $0.createdAt > slotTtlNanos } ?? false

        var slot: Slot
        if let current = existing, !expired, current.fragmentCount == message.fragCount {
            slot = current
        } else {
            // Only a genuinely new packet can push the table over its bound;
            // replacing a slot whose fragment count disagrees reuses the key.
            if (existing == nil || expired) && slots.count >= maxSlots {
                evictOne(now)
            }
            slot = Slot(fragmentCount: message.fragCount, createdAt: now,
                        fragments: [[UInt8]?](repeating: nil, count: message.fragCount))
        }

        // First writer wins, so a retransmitted fragment cannot inflate the
        // count and complete a packet that is still missing a piece.
        if slot.fragments[message.fragId] == nil {
            slot.fragments[message.fragId] = message.payload
            slot.received += 1
        }
        if slot.received < slot.fragmentCount {
            slots[message.packetId] = slot
            return nil
        }
        slots.removeValue(forKey: message.packetId)
        var out: [UInt8] = []
        for part in slot.fragments {
            guard let part = part else { return nil }
            out.append(contentsOf: part)
        }
        return out
    }

    /// Drops every part-assembled packet, for a session that is going away.
    func clear() {
        slots.removeAll()
    }

    /// Expired slots go first, and among equals the oldest does.
    private func evictOne(_ now: Int64) {
        let victim = slots.min { a, b in
            let aExpired = now - a.value.createdAt > slotTtlNanos
            let bExpired = now - b.value.createdAt > slotTtlNanos
            if aExpired != bExpired { return aExpired }
            return a.value.createdAt < b.value.createdAt
        }
        if let victim = victim {
            slots.removeValue(forKey: victim.key)
        }
    }
}
