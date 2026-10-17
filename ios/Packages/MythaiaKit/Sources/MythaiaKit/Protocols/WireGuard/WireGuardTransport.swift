import CryptoKit
import Foundation

/// The data phase: one IP packet per message, each with its own counter.
///
/// Layout is type(4, LE) ‖ receiver index(4, LE) ‖ counter(8, LE) ‖ sealed
/// packet. The counter is the AEAD nonce, so it must never repeat under one
/// key — which is what the rekey limits below are about.
///
/// The paper writes the first field as type(1) ‖ reserved(3), which is the same
/// four bytes: type 4 little-endian is `04 00 00 00`. AmneziaWG replaces the
/// whole word with H4, a value normally well above 255, so it has to be read
/// and written as one 32-bit field rather than a byte. Cloudflare WARP goes the
/// other way: the type stays a byte and the three reserved octets carry its
/// client id, so with `Reserved` set only the low octet is compared.
///
/// Safe to use from several threads: the send counter and the replay window
/// each sit behind a lock.
final class WireGuardTransport: @unchecked Sendable {
    static let headerSize = 16
    static let paddingMultiple = 16

    /// The kernel's window, in packets.
    static let windowSize: UInt64 = 2048

    /// Rekey well before the counter could wrap.
    static let rekeyAfterMessages: UInt64 = 1 << 60

    /// The protocol's hard limit, 2^64 - 2^13 - 1: past it a peer must stop
    /// sending entirely rather than reuse a nonce. A session is replaced at
    /// `rekeyAfterMessages` long before, and even that is more packets than
    /// a link could carry in years.
    static let rejectAfterMessages: UInt64 = UInt64.max - (1 << 13)

    let localIndex: UInt32
    private let peerIndex: UInt32
    private let sendKey: SymmetricKey
    private let receiveKey: SymmetricKey
    /// AmneziaWG renumbers the message types; plain WireGuard leaves them.
    private let transportType: UInt32
    /// WARP's reserved bytes, stamped into octets 1-3 of every message sent;
    /// with them set, a received message is matched on its low octet only.
    private let reserved: [UInt8]?

    private let lock = NSLock()
    private var sendCounter: UInt64 = 0
    private let replay = ReplayWindow()

    init(
        sendKey: [UInt8],
        receiveKey: [UInt8],
        peerIndex: UInt32,
        localIndex: UInt32,
        transportType: UInt32 = WireGuardHandshake.messageTransport,
        reserved: [UInt8]? = nil
    ) {
        self.sendKey = SymmetricKey(data: sendKey)
        self.receiveKey = SymmetricKey(data: receiveKey)
        self.peerIndex = peerIndex
        self.localIndex = localIndex
        self.transportType = transportType
        self.reserved = reserved
    }

    /// How many packets this session has carried, for the rekey decision.
    var packetsSent: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return sendCounter
    }

    /// Whether the session should be replaced.
    ///
    /// WireGuard rekeys well before the counter could wrap; past the hard limit
    /// a peer must stop sending entirely rather than reuse a nonce.
    var needsRekey: Bool { packetsSent >= WireGuardTransport.rekeyAfterMessages }
    var isExhausted: Bool { packetsSent >= WireGuardTransport.rejectAfterMessages }

    /// Wraps one IP packet.
    ///
    /// The plaintext is padded to a multiple of 16 so the ciphertext length says
    /// less about the packet inside it. The padding is zeroes, and the far side
    /// drops it by reading the IP header's own length. An empty packet is a
    /// keepalive and is not padded.
    func encapsulate(_ packet: Data) throws -> Data {
        lock.lock()
        if sendCounter >= WireGuardTransport.rejectAfterMessages {
            lock.unlock()
            throw MythaiaError.protocolError("WireGuard session has sent too many packets; rekey required")
        }
        let counter = sendCounter
        sendCounter += 1
        lock.unlock()

        var padded = packet
        let remainder = packet.count % WireGuardTransport.paddingMultiple
        if !packet.isEmpty && remainder != 0 {
            padded.append(Data(count: WireGuardTransport.paddingMultiple - remainder))
        }

        let box: ChaChaPoly.SealedBox
        do {
            box = try ChaChaPoly.seal(padded, using: sendKey, nonce: ChaChaPoly.Nonce(data: WireGuardCrypto.nonce(counter)))
        } catch {
            throw MythaiaError.protocolError("WireGuard could not seal a packet")
        }

        var header = [UInt8](repeating: 0, count: WireGuardTransport.headerSize)
        WireGuardHandshake.writeLe32(&header, 0, transportType)
        WireGuardHandshake.stampReserved(&header, 0, reserved)
        WireGuardHandshake.writeLe32(&header, 4, peerIndex)
        WireGuardHandshake.writeLe64(&header, 8, counter)

        var out = Data(capacity: WireGuardTransport.headerSize + padded.count + WireGuardCrypto.tagSize)
        out.append(contentsOf: header)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    /// Unwraps one transport message.
    ///
    /// Nil when it is not for us, is a replay, or does not authenticate — all
    /// three are things a network can produce on its own, so none of them is an
    /// error worth tearing the session down for.
    ///
    /// A keepalive arrives as an empty packet and comes back as empty data,
    /// which the caller drops rather than writing to the interface. Anything
    /// else still carries its padding.
    func decapsulate(_ message: Data) -> Data? {
        guard message.count >= WireGuardTransport.headerSize + WireGuardCrypto.tagSize else { return nil }
        guard WireGuardHandshake.isType(WireGuardHandshake.readLe32(message, 0), transportType, reserved) else { return nil }
        guard WireGuardHandshake.readLe32(message, 4) == localIndex else { return nil }

        let counter = WireGuardHandshake.readLe64(message, 8)
        // Checked before the AEAD so a flood of replays costs nothing.
        guard replay.mayAccept(counter) else { return nil }

        let start = message.startIndex + WireGuardTransport.headerSize
        let tagStart = message.endIndex - WireGuardCrypto.tagSize
        let plaintext: Data
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: WireGuardCrypto.nonce(counter)),
                ciphertext: message[start..<tagStart],
                tag: message[tagStart..<message.endIndex]
            )
            plaintext = try ChaChaPoly.open(box, using: receiveKey)
        } catch {
            return nil
        }

        // Only a message that authenticated advances the window; otherwise
        // anyone could burn counter space by sending garbage. Checked again
        // here, so the same counter opened twice at once is still one packet.
        guard replay.accept(counter) else { return nil }
        return plaintext
    }

    /// The sliding window that stops a packet being accepted twice.
    ///
    /// A counter far enough behind the highest one seen is refused outright; one
    /// inside the window is refused if its bit is already set. This is the same
    /// shape as the kernel implementation's, at the same width.
    private final class ReplayWindow {
        private static let words = Int(WireGuardTransport.windowSize / 64)

        private let lock = NSLock()
        /// The highest counter accepted; nil before the first.
        private var highest: UInt64?
        private var bits = [UInt64](repeating: 0, count: ReplayWindow.words)

        func mayAccept(_ counter: UInt64) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return mayAcceptLocked(counter)
        }

        /// Marks `counter` seen; false when it already was, or fell behind.
        func accept(_ counter: UInt64) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            guard mayAcceptLocked(counter) else { return false }
            if let top = highest {
                if counter > top {
                    let shift = counter - top
                    if shift >= WireGuardTransport.windowSize {
                        for index in 0..<bits.count {
                            bits[index] = 0
                        }
                    } else {
                        // Clear the range the window has just moved over, so a
                        // counter that comes round again is not mistaken for
                        // one already seen.
                        var c = top + 1
                        while c <= counter {
                            clear(c)
                            c += 1
                        }
                    }
                    highest = counter
                }
            } else {
                highest = counter
            }
            set(counter)
            return true
        }

        private func mayAcceptLocked(_ counter: UInt64) -> Bool {
            if counter >= WireGuardTransport.rejectAfterMessages { return false }
            guard let top = highest else { return true }
            if counter > top { return true }
            if top - counter >= WireGuardTransport.windowSize { return false }
            return !isSet(counter)
        }

        private func index(_ counter: UInt64) -> Int {
            Int((counter % WireGuardTransport.windowSize) / 64)
        }

        private func mask(_ counter: UInt64) -> UInt64 {
            UInt64(1) << ((counter % WireGuardTransport.windowSize) % 64)
        }

        private func isSet(_ counter: UInt64) -> Bool {
            bits[index(counter)] & mask(counter) != 0
        }

        private func set(_ counter: UInt64) {
            bits[index(counter)] |= mask(counter)
        }

        private func clear(_ counter: UInt64) {
            bits[index(counter)] &= ~mask(counter)
        }
    }
}
