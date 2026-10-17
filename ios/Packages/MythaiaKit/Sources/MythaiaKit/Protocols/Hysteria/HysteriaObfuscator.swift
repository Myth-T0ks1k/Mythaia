import Foundation

/// The datagram-level disguise applied under Hysteria2's QUIC connection.
///
/// Both modes exist to defeat the same thing: a censor that recognises a QUIC
/// Initial packet by its cleartext header and drops it. Salamander XORs a
/// password-derived keystream over the whole datagram, which destroys the
/// header's shape but preserves its size. Gecko goes further and also breaks a
/// handshake packet into several padded pieces, so neither the byte pattern
/// nor the characteristic size of a QUIC handshake survives.
///
/// `seal` returns a list because gecko turns one packet into several; each
/// element is sent as its own UDP datagram. `open` handles one received
/// datagram and returns nil when it yields nothing to deliver — for gecko the
/// ordinary case, since all but the last fragment of a message produce no
/// packet at all.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
protocol HysteriaObfuscator: AnyObject {
    /// Disguises one outbound packet as one or more datagrams to send.
    func seal(_ packet: [UInt8]) -> [[UInt8]]
    /// Recovers a packet from one inbound datagram, or nil if there is none yet.
    func open(_ datagram: [UInt8]) -> [UInt8]?
}

enum HysteriaObfuscators {
    /// The obfuscator a configuration asks for. Throws for a password below
    /// the Salamander minimum, which is worth failing at setup: a server built
    /// on the reference would refuse the same password, so the node could
    /// never connect.
    static func make(_ configuration: HysteriaObfuscation) throws -> HysteriaObfuscator {
        switch configuration {
        case .salamander(let password):
            return try SalamanderPacketObfuscator(password: password)
        case .gecko(let password, let minimum, let maximum):
            return try GeckoObfuscator(password: password, minPacketSize: minimum, maxPacketSize: maximum)
        }
    }
}

/// Salamander as a packet obfuscator: one packet in, one datagram out.
final class SalamanderPacketObfuscator: HysteriaObfuscator, @unchecked Sendable {
    private let inner: SalamanderObfuscator

    init(password: String) throws {
        inner = try SalamanderObfuscator(password: password)
    }

    func seal(_ packet: [UInt8]) -> [[UInt8]] {
        return [inner.seal(packet)]
    }

    func open(_ datagram: [UInt8]) -> [UInt8]? {
        return inner.open(datagram)
    }
}

/// Gecko: salamander, plus fragmentation of the handshake.
///
/// Only long-header packets are split. A QUIC long header carries the version
/// and connection ids in the clear and appears only during the handshake, so
/// it is both the packet a censor can fingerprint and a rare enough one that
/// splitting it costs nothing. 1-RTT traffic has a short header that reveals
/// almost nothing, and fragmenting every data packet would multiply
/// per-datagram overhead for no gain.
///
/// Each fragment carries a five-byte header — flag, message id, index and
/// count packed into one byte, then the pad length — followed by random
/// padding and then the slice of the original packet. Reassembly state is
/// bounded in time and size, because the fragments come off an
/// unauthenticated UDP socket.
final class GeckoObfuscator: HysteriaObfuscator, @unchecked Sendable {
    /// QUIC's own long-header bit, reused as the fragment marker. A fragment
    /// frame is only ever made from a packet that had the bit set, and the
    /// receiver reads it back off the deobfuscated frame.
    static let fragmentFlag: UInt8 = 0x80
    /// flag(1) + msgId(1) + index/count(1) + padLength(2).
    static let headerLength = 5
    /// The count lives in a nibble, so eight is the ceiling the format allows.
    static let minChunks = 2
    static let maxChunks = 8

    private static let reassemblyTtlNanos: UInt64 = 8_000_000_000
    private static let sweepIntervalNanos: UInt64 = 4_000_000_000
    private static let maxReassembly = 64

    private let inner: SalamanderObfuscator
    let minPacketSize: Int
    let maxPacketSize: Int

    private let lock = NSLock()
    private var messageCounter = 0
    private var table: [Int: Reassembly] = [:]
    private var lastSweep = DispatchTime.now().uptimeNanoseconds

    /// The fragments of one in-flight message, and when to give up on them.
    private struct Reassembly {
        let total: Int
        let deadline: UInt64
        var chunks: [[UInt8]?]
        var received = 0
    }

    /// The bounds are normalized again here rather than trusted: an inverted
    /// or absurd window would otherwise ask for a negative amount of padding.
    init(password: String, minPacketSize: Int, maxPacketSize: Int) throws {
        inner = try SalamanderObfuscator(password: password)
        let sizes = HysteriaObfuscation.normalizedGeckoSizes(minPacketSize, maxPacketSize)
        self.minPacketSize = sizes.0
        self.maxPacketSize = sizes.1
    }

    func seal(_ packet: [UInt8]) -> [[UInt8]] {
        if packet.isEmpty { return [] }
        // Short-header (1-RTT) data rides salamander alone.
        if packet[0] & GeckoObfuscator.fragmentFlag != GeckoObfuscator.fragmentFlag {
            return [inner.seal(packet)]
        }
        let chunks = Int.random(in: GeckoObfuscator.minChunks...GeckoObfuscator.maxChunks)
        let chunkSize = packet.count / chunks
        lock.lock()
        messageCounter = (messageCounter + 1) & 0xFF
        let messageId = messageCounter
        lock.unlock()

        var out: [[UInt8]] = []
        for index in 0..<chunks {
            let start = index * chunkSize
            // The last chunk absorbs the remainder of an uneven division.
            let end = index < chunks - 1 ? start + chunkSize : packet.count
            let padLength = randomPadLength(end - start)
            var frame: [UInt8] = [
                GeckoObfuscator.fragmentFlag,
                UInt8(messageId),
                UInt8(((index << 4) | (chunks & 0x0F)) & 0xFF),
                UInt8(truncatingIfNeeded: padLength >> 8),
                UInt8(truncatingIfNeeded: padLength),
            ]
            if padLength > 0 {
                frame.append(contentsOf: TLSWire.randomBytes(padLength))
            }
            frame.append(contentsOf: packet[start..<end])
            out.append(inner.seal(frame))
        }
        return out
    }

    /// How much padding lifts this fragment into the size window: the sealed
    /// datagram is `salt + header + pad + chunk` bytes, so the padding is
    /// whatever reaches the minimum plus random headroom up to the maximum. A
    /// chunk already over the maximum gets none rather than being split again.
    private func randomPadLength(_ chunkLength: Int) -> Int {
        let base = SalamanderObfuscator.saltLength + GeckoObfuscator.headerLength + chunkLength
        let low = max(minPacketSize, base)
        if low > maxPacketSize { return 0 }
        return (low - base) + Int.random(in: 0...(maxPacketSize - low))
    }

    func open(_ datagram: [UInt8]) -> [UInt8]? {
        guard let opened = inner.open(datagram), !opened.isEmpty else { return nil }
        // A short header means this was never fragmented.
        if opened[0] & GeckoObfuscator.fragmentFlag != GeckoObfuscator.fragmentFlag { return opened }
        if opened.count < GeckoObfuscator.headerLength { return nil }
        let messageId = Int(opened[1])
        let chunkIndex = Int(opened[2] >> 4)
        let totalChunks = Int(opened[2] & 0x0F)
        let padLength = Int(opened[3]) << 8 | Int(opened[4])
        if totalChunks < GeckoObfuscator.minChunks || totalChunks > GeckoObfuscator.maxChunks { return nil }
        if chunkIndex >= totalChunks { return nil }
        let payloadStart = GeckoObfuscator.headerLength + padLength
        if payloadStart > opened.count { return nil }
        return acceptChunk(messageId, chunkIndex, totalChunks, Array(opened[payloadStart...]))
    }

    /// Files one fragment, returning the whole packet once the last one lands.
    /// A fragment that contradicts what is held for its id — another chunk
    /// count, or an index already filled — discards or ignores rather than
    /// merging two messages into one packet QUIC would take as genuine.
    private func acceptChunk(_ messageId: Int, _ chunkIndex: Int, _ totalChunks: Int, _ payload: [UInt8]) -> [UInt8]? {
        lock.lock()
        defer { lock.unlock() }
        let now = DispatchTime.now().uptimeNanoseconds
        if now &- lastSweep >= GeckoObfuscator.sweepIntervalNanos {
            table = table.filter { $0.value.deadline >= now }
            lastSweep = now
        }
        if let existing = table[messageId], existing.total != totalChunks {
            table.removeValue(forKey: messageId)
        }
        var entry: Reassembly
        if let existing = table[messageId] {
            entry = existing
        } else {
            if table.count >= GeckoObfuscator.maxReassembly {
                // The message closest to expiry goes, so a flood of first
                // fragments cannot starve one that is nearly complete.
                if let victim = table.min(by: { $0.value.deadline < $1.value.deadline }) {
                    table.removeValue(forKey: victim.key)
                }
            }
            entry = Reassembly(total: totalChunks, deadline: now + GeckoObfuscator.reassemblyTtlNanos,
                               chunks: [[UInt8]?](repeating: nil, count: totalChunks))
        }
        if chunkIndex >= entry.chunks.count || entry.chunks[chunkIndex] != nil {
            table[messageId] = entry
            return nil
        }
        entry.chunks[chunkIndex] = payload
        entry.received += 1
        if entry.received < entry.total {
            table[messageId] = entry
            return nil
        }
        table.removeValue(forKey: messageId)
        var out: [UInt8] = []
        for chunk in entry.chunks {
            if let chunk = chunk { out.append(contentsOf: chunk) }
        }
        return out
    }
}
