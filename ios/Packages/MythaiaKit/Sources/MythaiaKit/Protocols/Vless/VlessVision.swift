import Foundation

enum VisionCommand: UInt8, CaseIterable {
    case paddingContinue = 0x00
    case paddingEnd = 0x01
    case paddingDirect = 0x02

    static func fromByte(_ b: UInt8) -> VisionCommand? {
        return VisionCommand(rawValue: b)
    }
}

private let tls13SupportedVersions: [UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]
private let tlsHandshakeTypeClientHello: UInt8 = 0x01
private let tlsHandshakeTypeServerHello: UInt8 = 0x02

/// TLS 1.3 cipher suites that support XTLS direct copy. 0x1305 is intentionally excluded.
private let tls13CipherSuites: Set<Int> = [
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0x1304, // TLS_AES_128_CCM_SHA256
]

/// Buffers this large need splitting to leave room for the 21-byte padding header.
private let visionReshapeThreshold = 8192 - 21

/// Both directions' Vision state for one connection. The reader and the
/// writer share it (the writer's filter notices the ClientHello, the reader's
/// the ServerHello), so it is only touched under the connection's lock.
final class VisionTrafficState {
    static let defaultTestseed = [900, 500, 900, 256]

    let userUUID: [UInt8]
    /// `[contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]`.
    let testseed: [Int]

    var numberOfPacketsToFilter = 8
    var enableXtls = false
    var isTLS12orAbove = false
    var isTLS = false
    var cipher = 0
    var remainingServerHello = -1

    var writerIsPadding = true
    var writerDirectCopy = false

    var readerWithinPaddingBuffers = true
    var readerDirectCopy = false
    var remainingCommand = -1
    var remainingContent = -1
    var remainingPadding = -1
    var currentCommand = 0

    /// The UUID goes in front of the first frame only; cleared once sent.
    var writeOnceUserUUID: [UInt8]?

    init(userUUID: Data, testseed: [Int] = VisionTrafficState.defaultTestseed) {
        self.userUUID = [UInt8](userUUID)
        self.testseed = testseed.count >= 4 ? testseed : VisionTrafficState.defaultTestseed
        self.writeOnceUserUUID = [UInt8](userUUID)
    }
}

/// Splits data that would not fit one padded frame. Splits at the last TLS
/// application-data boundary when there is one in range, at the midpoint
/// otherwise, recursively.
func reshapeData(_ data: [UInt8]) -> [[UInt8]] {
    if data.count < visionReshapeThreshold { return [data] }

    var splitIndex = data.count / 2
    var i = data.count - 3
    while i >= 0 {
        if data[i] == 0x17 && data[i + 1] == 0x03 && data[i + 2] == 0x03 {
            if i >= 21 && i <= visionReshapeThreshold {
                splitIndex = i
                break
            }
        }
        i -= 1
    }

    let first = Array(data[0..<splitIndex])
    let second = Array(data[splitIndex...])
    return reshapeData(first) + reshapeData(second)
}

/// Adds Vision padding. Frame format:
/// `[UUID 16 (first frame only)] [command 1] [contentLen 2] [paddingLen 2] [content] [padding]`
func visionPadding(_ data: [UInt8]?, command: VisionCommand, state: VisionTrafficState, longPadding: Bool) -> [UInt8] {
    let contentLength = data?.count ?? 0
    let seed = state.testseed
    var paddingLength: Int
    if contentLength < seed[0] && longPadding {
        paddingLength = CryptoRandom.int(below: seed[1]) + seed[2] - contentLength
    } else {
        paddingLength = CryptoRandom.int(below: seed[3])
    }
    let maxPadding = 8192 - 21 - contentLength
    paddingLength = min(paddingLength, maxPadding)
    paddingLength = max(paddingLength, 0)

    var result = [UInt8]()
    result.reserveCapacity(16 + 5 + contentLength + paddingLength)
    if let uuid = state.writeOnceUserUUID {
        state.writeOnceUserUUID = nil
        result.append(contentsOf: uuid)
    }
    result.append(command.rawValue)
    result.append(UInt8(truncatingIfNeeded: contentLength >> 8))
    result.append(UInt8(truncatingIfNeeded: contentLength))
    result.append(UInt8(truncatingIfNeeded: paddingLength >> 8))
    result.append(UInt8(truncatingIfNeeded: paddingLength))
    if let data = data {
        result.append(contentsOf: data)
    }
    if paddingLength > 0 {
        result.append(contentsOf: CryptoRandom.bytes(paddingLength))
    }
    return result
}

/// A read position over a byte array.
final class VisionDataCursor {
    private let data: [UInt8]
    private var offset: Int

    init(_ data: [UInt8], offset: Int = 0) {
        self.data = data
        self.offset = offset
    }

    var remaining: Int { data.count - offset }

    func startsWith(_ prefix: [UInt8]) -> Bool {
        if remaining < prefix.count { return false }
        for i in 0..<prefix.count where data[offset + i] != prefix[i] {
            return false
        }
        return true
    }

    func advance(_ count: Int) {
        offset += count
    }

    func readByte() -> UInt8 {
        let b = data[offset]
        offset += 1
        return b
    }

    func readBytes(_ count: Int) -> ArraySlice<UInt8> {
        let out = data[offset..<(offset + count)]
        offset += count
        return out
    }

    func readAll() -> ArraySlice<UInt8> {
        let out = data[offset...]
        offset = data.count
        return out
    }
}

/// Removes Vision padding from the cursor's bytes and returns the content.
func visionUnpadding(_ data: VisionDataCursor, state: VisionTrafficState) -> [UInt8] {
    if state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1 {
        if data.remaining >= 21 && data.startsWith(state.userUUID) {
            data.advance(16)
            state.remainingCommand = 5
        } else {
            return Array(data.readAll())
        }
    }

    var result = [UInt8]()
    while data.remaining > 0 {
        if state.remainingCommand > 0 {
            let byte = Int(data.readByte())
            switch state.remainingCommand {
            case 5: state.currentCommand = byte
            case 4: state.remainingContent = byte << 8
            case 3: state.remainingContent = state.remainingContent | byte
            case 2: state.remainingPadding = byte << 8
            case 1: state.remainingPadding = state.remainingPadding | byte
            default: break
            }
            state.remainingCommand -= 1
        } else if state.remainingContent > 0 {
            let toRead = min(state.remainingContent, data.remaining)
            result.append(contentsOf: data.readBytes(toRead))
            state.remainingContent -= toRead
        } else if state.remainingPadding > 0 {
            let toSkip = min(state.remainingPadding, data.remaining)
            data.advance(toSkip)
            state.remainingPadding -= toSkip
        }

        if state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0 {
            if state.currentCommand == 0 {
                state.remainingCommand = 5
            } else {
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if data.remaining > 0 {
                    result.append(contentsOf: data.readAll())
                }
                break
            }
        }
    }
    return result
}

/// Watches the first packets for a TLS 1.3 ServerHello with a suite that
/// allows XTLS direct copy.
func visionFilterTLS(_ data: [UInt8], state: VisionTrafficState) {
    if state.numberOfPacketsToFilter <= 0 { return }
    state.numberOfPacketsToFilter -= 1

    if data.count < 6 { return }

    let isHandshakeRecord = data[0] == 0x16 && data[1] == 0x03
    if isHandshakeRecord && data[2] == 0x03 && data[5] == tlsHandshakeTypeServerHello {
        let recordLength = (Int(data[3]) << 8) | Int(data[4])
        state.remainingServerHello = recordLength + 5
        state.isTLS12orAbove = true
        state.isTLS = true

        if data.count >= 79 && state.remainingServerHello >= 79 {
            let sessionIdLength = Int(data[43])
            let cipherOffset = 43 + sessionIdLength + 1
            if data.count > cipherOffset + 2 {
                state.cipher = (Int(data[cipherOffset]) << 8) | Int(data[cipherOffset + 1])
            }
        }
    } else if isHandshakeRecord && data[5] == tlsHandshakeTypeClientHello {
        state.isTLS = true
    }

    if state.remainingServerHello > 0 {
        let end = min(state.remainingServerHello, data.count)
        state.remainingServerHello -= data.count

        if containsSubarray(data, from: 0, to: end, tls13SupportedVersions) {
            if tls13CipherSuites.contains(state.cipher) {
                state.enableXtls = true
            }
            state.numberOfPacketsToFilter = 0
            return
        } else if state.remainingServerHello <= 0 {
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

/// Whether `data` is exactly a run of whole TLS application-data records.
func isCompleteTlsRecord(_ data: [UInt8]) -> Bool {
    if data.count < 5 { return false }
    var offset = 0
    while offset < data.count {
        if offset + 5 > data.count { return false }
        if data[offset] != 0x17 || data[offset + 1] != 0x03 || data[offset + 2] != 0x03 {
            return false
        }
        let recordLength = (Int(data[offset + 3]) << 8) | Int(data[offset + 4])
        offset += 5
        if offset + recordLength > data.count { return false }
        offset += recordLength
    }
    return offset == data.count
}

private func containsSubarray(_ data: [UInt8], from: Int, to: Int, _ sub: [UInt8]) -> Bool {
    if sub.isEmpty { return true }
    let end = min(to, data.count) - sub.count
    if end < from { return false }
    var i = from
    while i <= end {
        var matches = true
        for j in 0..<sub.count where data[i + j] != sub[j] {
            matches = false
            break
        }
        if matches { return true }
        i += 1
    }
    return false
}

/// VLESS with the `xtls-rprx-vision` flow.
///
/// Until the inner TLS handshake is over, every write is wrapped in a padded
/// frame that hides record sizes, and every read is unpadded. Once both ends
/// have seen a TLS 1.3 ServerHello with a suitable suite, the frame carrying
/// the first application-data record says "direct", and from then on the
/// inner TLS records go raw on the connection under the outer TLS, saving the
/// second layer of encryption. `raw` is that outer session (our own TLS or
/// REALITY), whose `sendRaw`/`receiveRaw` reach below its records; without
/// one, `inner` is taken to be the raw stream itself.
final class VlessVisionConnection: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let raw: TLSSessionStream?
    private let trafficState: VisionTrafficState
    private let lock = NSLock()

    /// `inner` strips the VLESS response header (a `VlessConnection`).
    init(_ inner: ByteStream, userUUID: Data, testseed: [Int] = VisionTrafficState.defaultTestseed, raw: TLSSessionStream? = nil) {
        self.inner = inner
        self.raw = raw
        self.trafficState = VisionTrafficState(userUUID: userUUID, testseed: testseed)
    }

    /// Sends the VLESS request `header` and the first padded frame as one write.
    ///
    /// Xray composes them through one buffered writer, and for a reason: a
    /// header in a TLS record of its own has a length an observer can read
    /// off the wire, and hiding that length is exactly what the padding is
    /// for. With no `initialData` the frame is pure long padding, as Xray
    /// inserts when the app has nothing to say within its wait.
    func sendRequest(_ header: Data, initialData: Data?) async throws {
        let frame = firstFrame(initialData)
        var request = [UInt8](header)
        request.append(contentsOf: frame)
        try await inner.send(Data(request))
    }

    func send(_ data: Data) async throws {
        let prepared = prepareSend([UInt8](data))
        if prepared.bytes.isEmpty { return }
        if prepared.direct, let raw = raw {
            try await raw.sendRaw(Data(prepared.bytes))
        } else {
            try await inner.send(Data(prepared.bytes))
        }
    }

    func receive() async throws -> Data? {
        while true {
            if readerIsDirect() {
                if let raw = raw {
                    return try await raw.receiveRaw()
                }
                return try await inner.receive()
            }

            let data: Data?
            do {
                data = try await inner.receive()
            } catch let failure as TLSDecryptionFailed {
                // A record that does not open is the server having switched
                // to direct copy: it is the raw inner TLS, no longer wrapped.
                // Switch the reader and hand those bytes on.
                switchReaderToDirect()
                if !failure.rawData.isEmpty {
                    return failure.rawData
                }
                if let raw = raw {
                    return try await raw.receiveRaw()
                }
                return try await inner.receive()
            }

            guard let received = data else { return nil }
            if received.isEmpty { continue }
            let content = processReceived([UInt8](received))
            // Empty after unpadding means only padding arrived: read on
            // rather than return, which would look like the end.
            if !content.isEmpty {
                return Data(content)
            }
        }
    }

    func close() {
        inner.close()
    }

    // MARK: - State, under the lock

    private func firstFrame(_ initialData: Data?) -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        if let initialData = initialData, !initialData.isEmpty {
            return processSendData([UInt8](initialData))
        }
        return visionPadding(nil, command: .paddingContinue, state: trafficState, longPadding: true)
    }

    /// The bytes to write, and whether they go raw. The direct flag is read
    /// before processing: the frame that switches to direct copy still goes
    /// through the outer TLS, only the writes after it go raw.
    private func prepareSend(_ data: [UInt8]) -> (direct: Bool, bytes: [UInt8]) {
        lock.lock()
        defer { lock.unlock() }
        let direct = trafficState.writerDirectCopy
        return (direct, processSendData(data))
    }

    private func readerIsDirect() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return trafficState.readerDirectCopy
    }

    private func switchReaderToDirect() {
        lock.lock()
        defer { lock.unlock() }
        trafficState.readerDirectCopy = true
        trafficState.readerWithinPaddingBuffers = false
    }

    private func processReceived(_ data: [UInt8]) -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return processReceiveData(data)
    }

    private func processSendData(_ data: [UInt8]) -> [UInt8] {
        let state = trafficState
        // Outbound bytes go through the same filter as inbound ones, as in
        // Xray's VisionWriter: it is what notices the ClientHello (so the
        // padding becomes long), and each write it inspects counts against
        // the same packet budget the reader draws on.
        if state.numberOfPacketsToFilter > 0 {
            visionFilterTLS(data, state: state)
        }

        if state.writerDirectCopy { return data }
        if !state.writerIsPadding { return data }

        let longPadding = state.isTLS
        let isComplete = isCompleteTlsRecord(data)
        let chunks = reshapeData(data)

        let startsWithApplicationData = data.count >= 6 && data[0] == 0x17 && data[1] == 0x03 && data[2] == 0x03
        if state.isTLS && startsWithApplicationData && isComplete {
            var result = [UInt8]()
            for (index, chunk) in chunks.enumerated() {
                if index == chunks.count - 1 {
                    let command: VisionCommand
                    if state.enableXtls {
                        command = .paddingDirect
                        state.writerDirectCopy = true
                    } else {
                        command = .paddingEnd
                    }
                    state.writerIsPadding = false
                    result.append(contentsOf: visionPadding(chunk, command: command, state: state, longPadding: false))
                } else {
                    result.append(contentsOf: visionPadding(chunk, command: .paddingContinue, state: state, longPadding: true))
                }
            }
            return result
        }

        // Compatibility: end padding one packet early for pre-TLS 1.2 receivers.
        if !state.isTLS12orAbove && state.numberOfPacketsToFilter <= 1 {
            state.writerIsPadding = false
            var result = [UInt8]()
            for (index, chunk) in chunks.enumerated() {
                let command: VisionCommand = index == chunks.count - 1 ? .paddingEnd : .paddingContinue
                result.append(contentsOf: visionPadding(chunk, command: command, state: state, longPadding: longPadding))
            }
            return result
        }

        var result = [UInt8]()
        for chunk in chunks {
            result.append(contentsOf: visionPadding(chunk, command: .paddingContinue, state: state, longPadding: longPadding))
        }
        return result
    }

    private func processReceiveData(_ data: [UInt8]) -> [UInt8] {
        let state = trafficState
        if state.readerDirectCopy { return data }

        var content = data
        if state.readerWithinPaddingBuffers || state.numberOfPacketsToFilter > 0 {
            content = visionUnpadding(VisionDataCursor(data), state: state)

            if state.remainingContent > 0 || state.remainingPadding > 0 || state.currentCommand == 0 {
                state.readerWithinPaddingBuffers = true
            } else if state.currentCommand == 1 {
                state.readerWithinPaddingBuffers = false
            } else if state.currentCommand == 2 {
                state.readerWithinPaddingBuffers = false
                state.readerDirectCopy = true
            }
        }

        // The filter looks for the ServerHello, which only exists once the
        // padding is off: run on the padded bytes (which begin with the UUID)
        // it never matched, TLS 1.3 was never detected, and the uplink stayed
        // double-encrypted for the life of the connection. Xray's VisionReader
        // unpads first for the same reason, and like it skips an empty result
        // (pure padding) so it does not spend a packet of the budget.
        if !content.isEmpty && state.numberOfPacketsToFilter > 0 {
            visionFilterTLS(content, state: state)
        }
        return content
    }
}
