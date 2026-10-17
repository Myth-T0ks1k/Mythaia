import Foundation

/// Thrown by `TLSSessionStream.receive()` when a record does not decrypt.
///
/// XTLS Vision depends on it: once the server switches a REALITY or TLS
/// connection to direct copy it stops wrapping the inner TLS in the outer
/// records, and the first record that fails to open is the signal. `rawData`
/// is that record and everything read after it, undecrypted, for the caller
/// to hand on; `receiveRaw()` and `sendRaw(_:)` carry the rest.
public struct TLSDecryptionFailed: Error, LocalizedError {
    public let rawData: Data

    public init(rawData: Data) {
        self.rawData = rawData
    }

    public var errorDescription: String? { "TLS error: a record did not decrypt" }
}

/// An established TLS 1.3 session over another stream, from `TLSClient` or
/// `RealityClient`.
///
/// Sending splits data into records of at most 2^14 bytes; receiving returns
/// the content of every complete record already read, batched. Post-handshake
/// messages are handled here: NewSessionTicket is ignored (sessions are not
/// resumed), KeyUpdate moves the receiving keys forward and, when the server
/// asks, ours too before the next record we send (RFC 8446 §4.6.3).
public final class TLSSessionStream: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let suite: Tls13Suite
    private let alpn: String?

    // Sending side, and the flags close() reads.
    private let sendLock = NSLock()
    private var sendCipher: TLSRecordCipher
    private var sendSecret: [UInt8]
    private var keyUpdateOwed = false
    private var sendInProgress = false
    private var closed = false

    // Receiving side.
    private let receiveLock = NSLock()
    private var receiveCipher: TLSRecordCipher
    private var receiveSecret: [UInt8]
    private var receiveBuffer: [UInt8]
    private var postHandshake: [UInt8] = []
    private var peerClosed = false

    /// The protocol the server picked from our ALPN offer, if it picked one.
    public var negotiatedALPN: String? { alpn }

    init(inner: ByteStream, suite: Tls13Suite, keys: TlsApplicationKeys, leftover: [UInt8], negotiatedALPN: String?) {
        self.inner = inner
        self.suite = suite
        self.alpn = negotiatedALPN
        self.sendSecret = keys.clientTrafficSecret
        self.sendCipher = TLSRecordCipher(suite: suite, key: keys.clientKey, iv: keys.clientIV)
        self.receiveSecret = keys.serverTrafficSecret
        self.receiveCipher = TLSRecordCipher(suite: suite, key: keys.serverKey, iv: keys.serverIV)
        self.receiveBuffer = leftover
    }

    // MARK: Sending

    public func send(_ data: Data) async throws {
        if data.isEmpty {
            if isClosed { throw MythaiaError.closed }
            return
        }
        let records = try sealForSending(Array(data))
        do {
            try await inner.send(Data(records))
        } catch {
            finishSending()
            throw error
        }
        finishSending()
    }

    /// Bytes straight to the stream below, unencrypted: XTLS Vision's direct
    /// copy, after both sides stopped using the outer records.
    public func sendRaw(_ data: Data) async throws {
        try await inner.send(data)
    }

    private func sealForSending(_ bytes: [UInt8]) throws -> [UInt8] {
        sendLock.lock()
        defer { sendLock.unlock() }
        if closed { throw MythaiaError.closed }
        var out: [UInt8] = []
        do {
            if keyUpdateOwed {
                // Our KeyUpdate goes out under the old keys; everything
                // after it under the new ones.
                let keyUpdate: [UInt8] = [0x18, 0x00, 0x00, 0x01, 0x00]
                out.append(contentsOf: try sendCipher.seal(keyUpdate, contentType: 0x16))
                sendSecret = Tls13Crypto.nextTrafficSecret(suite.hash, secret: sendSecret)
                sendCipher = TLSRecordCipher(suite: suite, trafficSecret: sendSecret)
                keyUpdateOwed = false
            }
            var offset = 0
            while offset < bytes.count {
                let end = min(offset + TLSRecordCipher.maxPlaintext, bytes.count)
                let chunk = Array(bytes[offset..<end])
                out.append(contentsOf: try sendCipher.seal(chunk, contentType: 0x17))
                offset = end
            }
        } catch {
            throw MythaiaError.tls("could not encrypt a record")
        }
        sendInProgress = true
        return out
    }

    private func finishSending() {
        sendLock.lock()
        sendInProgress = false
        sendLock.unlock()
    }

    private var isClosed: Bool {
        sendLock.lock()
        defer { sendLock.unlock() }
        return closed
    }

    // MARK: Receiving

    public func receive() async throws -> Data? {
        while true {
            switch try processBuffered() {
            case .data(let bytes):
                return Data(bytes)
            case .end:
                return nil
            case .needMore:
                break
            }
            if isClosed { throw MythaiaError.closed }
            guard let chunk = try await inner.receive() else {
                if isClosed { throw MythaiaError.closed }
                return nil
            }
            appendReceived(chunk)
        }
    }

    /// Whatever is buffered undecrypted, then the stream below as it comes:
    /// the receiving half of Vision's direct copy.
    public func receiveRaw() async throws -> Data? {
        if let pending = takeBuffered() {
            return pending
        }
        while true {
            guard let chunk = try await inner.receive() else { return nil }
            if !chunk.isEmpty { return chunk }
        }
    }

    private func appendReceived(_ chunk: Data) {
        receiveLock.lock()
        receiveBuffer.append(contentsOf: chunk)
        receiveLock.unlock()
    }

    private func takeBuffered() -> Data? {
        receiveLock.lock()
        defer { receiveLock.unlock() }
        if receiveBuffer.isEmpty { return nil }
        let pending = receiveBuffer
        receiveBuffer = []
        return Data(pending)
    }

    private enum ReceiveStep {
        case data([UInt8])
        case end
        case needMore
    }

    /// Opens every complete record in the buffer. Content from several
    /// records comes back as one piece.
    private func processBuffered() throws -> ReceiveStep {
        receiveLock.lock()
        defer { receiveLock.unlock() }
        if peerClosed { return .end }

        var batched: [UInt8] = []
        var offset = 0
        while offset + 5 <= receiveBuffer.count {
            let contentType = receiveBuffer[offset]
            let length = TLSWire.u16(receiveBuffer, offset + 3)
            let total = 5 + length
            if offset + total > receiveBuffer.count { break }

            if contentType == 0x17 {
                let header = Array(receiveBuffer[offset..<(offset + 5)])
                let body = Array(receiveBuffer[(offset + 5)..<(offset + total)])
                let opened: (contentType: UInt8, content: [UInt8])
                do {
                    opened = try receiveCipher.open(header: header, body: body)
                } catch {
                    // What was read before this record is handed out first;
                    // the failing record stays buffered and fails again on
                    // the next call, this time with nothing in front of it.
                    let raw = Array(receiveBuffer[offset...])
                    if !batched.isEmpty {
                        receiveBuffer = raw
                        return .data(batched)
                    }
                    receiveBuffer = []
                    throw TLSDecryptionFailed(rawData: Data(raw))
                }
                offset += total

                switch opened.contentType {
                case 0x17:
                    batched.append(contentsOf: opened.content)
                case 0x16:
                    try handlePostHandshake(opened.content, consumed: offset)
                case 0x15:
                    let level = opened.content.count > 0 ? Int(opened.content[0]) : 2
                    let description = opened.content.count > 1 ? Int(opened.content[1]) : 0
                    if description == 0 {
                        // close_notify: nothing follows, so end the stream here
                        // rather than wait for the transport to close.
                        peerClosed = true
                        receiveBuffer = []
                        return batched.isEmpty ? .end : .data(batched)
                    }
                    if level == 2 {
                        receiveBuffer.removeFirst(offset)
                        throw MythaiaError.tls("server sent \(TLSAlert.describe(level: level, description: description))")
                    }
                    // A warning (user_canceled) carries no data.
                default:
                    receiveBuffer.removeFirst(offset)
                    throw MythaiaError.tls("unexpected record type \(opened.contentType) after the handshake")
                }
            } else if contentType == 0x15 {
                // A plaintext alert: the peer gave up on the record layer.
                let description = length >= 2 ? Int(receiveBuffer[offset + 6]) : -1
                receiveBuffer.removeFirst(offset + total)
                throw MythaiaError.tls("server sent plaintext alert \(description)")
            } else {
                // ChangeCipherSpec and the like carry nothing for us.
                offset += total
            }
        }
        if offset > 0 {
            receiveBuffer.removeFirst(offset)
        }
        if !batched.isEmpty { return .data(batched) }
        return .needMore
    }

    /// Post-handshake messages, which may span records. Called with the
    /// receive lock held.
    private func handlePostHandshake(_ bytes: [UInt8], consumed: Int) throws {
        postHandshake.append(contentsOf: bytes)
        if postHandshake.count > 1 << 20 {
            receiveBuffer.removeFirst(consumed)
            throw MythaiaError.tls("post-handshake message too large")
        }
        while postHandshake.count >= 4 {
            let length = TLSWire.u24(postHandshake, 1)
            if postHandshake.count < 4 + length { break }
            let type = postHandshake[0]
            let body = Array(postHandshake[4..<(4 + length)])
            postHandshake.removeFirst(4 + length)
            if type == 24 {
                // KeyUpdate (RFC 8446 §4.6.3). It must end its record: the
                // next record is already under the new key.
                if body.count != 1 || body[0] > 1 || !postHandshake.isEmpty {
                    receiveBuffer.removeFirst(consumed)
                    throw MythaiaError.tls("malformed KeyUpdate")
                }
                receiveSecret = Tls13Crypto.nextTrafficSecret(suite.hash, secret: receiveSecret)
                receiveCipher = TLSRecordCipher(suite: suite, trafficSecret: receiveSecret)
                if body[0] == 1 {
                    sendLock.lock()
                    keyUpdateOwed = true
                    sendLock.unlock()
                }
            }
            // NewSessionTicket (4) and anything else: nothing to do, since
            // sessions are not resumed.
        }
    }

    // MARK: Closing

    /// Closes the session. A close_notify goes out first when no send is
    /// under way (a send parked on a stalled peer must not hold close up);
    /// either way the stream below is closed within a second.
    public func close() {
        sendLock.lock()
        if closed {
            sendLock.unlock()
            return
        }
        closed = true
        var alert: [UInt8]?
        if !sendInProgress {
            alert = try? sendCipher.seal([0x01, 0x00], contentType: 0x15)
        }
        sendLock.unlock()

        receiveLock.lock()
        receiveBuffer = []
        receiveLock.unlock()

        let stream = inner
        guard let closeNotify = alert else {
            stream.close()
            return
        }
        Task {
            try? await stream.send(Data(closeNotify))
            stream.close()
        }
        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            stream.close()
        }
    }
}
