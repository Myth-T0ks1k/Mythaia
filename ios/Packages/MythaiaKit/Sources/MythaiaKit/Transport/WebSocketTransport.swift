import CryptoKit
import Foundation

/// The WebSocket transport (RFC 6455) as Xray serves it: one upgrade request,
/// then every write a masked binary frame.
public enum WebSocketTransport {
    /// Upgrades `stream` and returns the WebSocket over it. `earlyData` is the
    /// flow's first bytes: as many as `maxEarlyData` allows ride in the
    /// upgrade request (base64url, in `earlyDataHeaderName`), saving the
    /// server a round trip; the rest follows as the first frame. On failure
    /// `stream` is closed, as nobody else holds it.
    public static func open(over stream: ByteStream, configuration: WebSocketConfiguration, earlyData: Data?) async throws -> ByteStream {
        let connection = WebSocketConnection(inner: stream, settings: WebSocketConnection.Settings(configuration))
        do {
            let embedded = try await connection.performUpgrade(earlyData: earlyData)
            if let earlyData = earlyData, embedded < earlyData.count {
                let bytes = [UInt8](earlyData)
                try await connection.send(Data(bytes[embedded...]))
            }
            return TransportErrorMappingStream(connection)
        } catch {
            connection.close()
            throw TransportErrors.map(error)
        }
    }
}

enum WebSocketError: Error, LocalizedError, Equatable, TransportErrorConvertible {
    case upgradeFailed(String)
    case invalidFrame(String)
    case connectionClosed(code: Int, reason: String)

    var message: String {
        switch self {
        case .upgradeFailed(let reason):
            return "WebSocket upgrade failed: \(reason)"
        case .invalidFrame(let reason):
            return "WebSocket invalid frame: \(reason)"
        case .connectionClosed(let code, let reason):
            return "WebSocket closed (\(code)): \(reason)"
        }
    }

    var errorDescription: String? { message }

    var mythaiaError: MythaiaError { .protocolError(message) }
}

/// A WebSocket connection implementing RFC 6455 framing over any byte stream.
final class WebSocketConnection: ByteStream, @unchecked Sendable {
    /// What the connection needs from WebSocketConfiguration, headers in a
    /// fixed order (sorted by name) so one configuration always sends one
    /// request.
    struct Settings {
        var host: String
        var path: String
        var headers: [(String, String)]
        var maxEarlyData: Int
        var earlyDataHeaderName: String
        /// Seconds between pings; 0 sends none.
        var heartbeatPeriod: Int

        init(host: String, path: String = "/", headers: [(String, String)] = [], maxEarlyData: Int = 0,
             earlyDataHeaderName: String = "Sec-WebSocket-Protocol", heartbeatPeriod: Int = 0) {
            self.host = host
            self.path = path
            self.headers = headers
            self.maxEarlyData = maxEarlyData
            self.earlyDataHeaderName = earlyDataHeaderName
            self.heartbeatPeriod = heartbeatPeriod
        }

        init(_ configuration: WebSocketConfiguration) {
            let sorted = configuration.headers.sorted { $0.key < $1.key }
            self.init(
                host: configuration.host,
                path: configuration.path,
                headers: sorted.map { ($0.key, $0.value) },
                maxEarlyData: Int(configuration.maxEarlyData),
                earlyDataHeaderName: configuration.earlyDataHeaderName,
                heartbeatPeriod: Int(configuration.heartbeatPeriod)
            )
        }
    }

    /// The largest frame accepted; one declaring more is refused at once
    /// rather than waited for. Xray writes a WebSocket frame per buffer it
    /// relays, so frames of some hundred kilobytes are normal.
    static let maxFramePayload = 16 * 1024 * 1024

    /// Normal closure, going away, and a close with no status code (RFC 6455 §7.4.1).
    static let normalCloseCodes: Set<Int> = [1000, 1001, 1005]

    /// A whole maximum frame plus the read that completed it. The buffer
    /// holds at most one incomplete frame, since a complete one is taken out
    /// before the next read.
    static let maxReceiveBufferSize = maxFramePayload + 4 * 1024 * 1024

    /// The most a 101 response head may take before it is given up on.
    static let maxResponseHeadSize = 64 * 1024

    /// RFC 6455 §1.3: appended to the key before hashing it for the accept value.
    static let acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    /// Chrome's current User-Agent, which the HTTP transports send unless the
    /// link sets one. It moves on by a version every 35 days from Chrome 144
    /// (2026-01-13), as Chrome stable does, so it never looks stale.
    static var chromeUserAgent: String { cachedChromeUserAgent }

    private static let cachedChromeUserAgent: String = computeChromeUserAgent()

    private static func computeChromeUserAgent() -> String {
        let baseVersion = 144
        let baseDate = Date(timeIntervalSince1970: 1_768_262_400)
        let days = max(0, Int(Date().timeIntervalSince(baseDate) / 86_400))
        let version = baseVersion + days / 35
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(version).0.0.0 Safari/537.36"
    }

    private let inner: ByteStream
    private let settings: Settings
    private let lock = NSLock()
    private var receiveBuffer: [UInt8] = []
    private var receiveStart = 0
    private var connected = true
    private var closeReceived = false
    private var heartbeatTask: Task<Void, Never>?

    /// Data, pongs and pings come from different tasks; each frame must reach
    /// the stream below whole.
    private let sendMutex = TransportAsyncMutex()

    init(inner: ByteStream, settings: Settings) {
        self.inner = inner
        self.settings = settings
    }

    var isConnected: Bool {
        lock.lock()
        defer { lock.unlock() }
        return connected
    }

    /// Sends the upgrade request and waits for the 101. Returns how many
    /// bytes of `earlyData` rode in the request.
    @discardableResult
    func performUpgrade(earlyData: Data? = nil) async throws -> Int {
        let key = Data(TransportEncoding.randomBytes(16)).base64EncodedString()

        var request = "GET \(settings.path) HTTP/1.1\r\n"
        request += "Host: \(settings.host)\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Sec-WebSocket-Key: \(key)\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"
        for (name, value) in settings.headers {
            request += "\(name): \(value)\r\n"
        }
        let hasUserAgent = settings.headers.contains { $0.0.caseInsensitiveCompare("User-Agent") == .orderedSame }
        if !hasUserAgent {
            request += "User-Agent: \(WebSocketConnection.chromeUserAgent)\r\n"
        }

        var embedded = 0
        if let earlyData = earlyData, !earlyData.isEmpty, settings.maxEarlyData > 0 {
            let bytes = [UInt8](earlyData)
            let count = min(bytes.count, settings.maxEarlyData)
            let encoded = TransportEncoding.base64URL(Data(bytes[0..<count]))
            request += "\(settings.earlyDataHeaderName): \(encoded)\r\n"
            embedded = count
        }
        request += "\r\n"

        try await sendRaw(Data(request.utf8))
        try await receiveUpgradeResponse(key: key)
        startHeartbeat()
        return embedded
    }

    private func receiveUpgradeResponse(key: String) async throws {
        while true {
            guard let data = try await inner.receive(), !data.isEmpty else {
                throw WebSocketError.upgradeFailed("Empty response from server")
            }
            if let head = try takeResponseHead(appending: data) {
                try checkUpgradeResponse(head, key: key)
                return
            }
        }
    }

    /// Adds `data` to what has arrived; once the head is complete, returns it
    /// and keeps what follows it as the start of the frames.
    private func takeResponseHead(appending data: Data) throws -> [UInt8]? {
        lock.lock()
        defer { lock.unlock() }
        receiveBuffer.append(contentsOf: data)
        guard let end = TransportEncoding.headerEnd(receiveBuffer, from: receiveStart) else {
            if receiveBuffer.count - receiveStart > WebSocketConnection.maxResponseHeadSize {
                throw WebSocketError.upgradeFailed("response head longer than \(WebSocketConnection.maxResponseHeadSize) bytes")
            }
            return nil
        }
        let head = Array(receiveBuffer[receiveStart..<end])
        receiveStart = end + 4
        compactLocked()
        return head
    }

    private func checkUpgradeResponse(_ head: [UInt8], key: String) throws {
        let text = String(decoding: head, as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        let firstLine = lines.first ?? ""
        if !firstLine.contains("101") {
            throw WebSocketError.upgradeFailed("Expected HTTP 101, got: \(firstLine)")
        }
        var accept: String?
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            if name.caseInsensitiveCompare("Sec-WebSocket-Accept") == .orderedSame {
                accept = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        // A wrong accept value means something other than a WebSocket server
        // answered (a captive portal, a cache). A missing one is tolerated:
        // the 101 alone has always been enough for the servers this talks to.
        if let accept = accept {
            if accept != WebSocketConnection.acceptValue(forKey: key) {
                throw WebSocketError.upgradeFailed("Sec-WebSocket-Accept does not match the key")
            }
        } else {
            Log.debug("WebSocket: the 101 response carries no Sec-WebSocket-Accept")
        }
    }

    /// RFC 6455 §4.2.2: base64 of the SHA-1 of the key and the GUID.
    static func acceptValue(forKey key: String) -> String {
        let digest = Insecure.SHA1.hash(data: Data((key + acceptGUID).utf8))
        return Data(digest).base64EncodedString()
    }

    /// Sends `data` as one binary frame (masked, opcode 0x02).
    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await sendRaw(WebSocketConnection.buildFrame(opcode: 0x02, payload: [UInt8](data)))
    }

    private func sendRaw(_ data: Data) async throws {
        await sendMutex.acquire()
        defer { sendMutex.release() }
        try await inner.send(data)
    }

    /// The next message's bytes, or nil at the end of the stream: the
    /// transport's EOF or a normal close frame. A close reporting a fault
    /// throws. Fragments come out as they arrive, which for a byte stream is
    /// the same as reassembling them.
    ///
    /// Loops instead of recursing so consecutive control frames (Ping/Pong)
    /// cannot blow the stack.
    func receive() async throws -> Data? {
        while true {
            if isCloseReceived { return nil }
            if let frame = try extractFrame() {
                switch frame {
                case .binary(let payload):
                    if payload.isEmpty { continue }
                    return Data(payload)
                case .ping(let payload):
                    do {
                        try await sendRaw(WebSocketConnection.buildFrame(opcode: 0x0A, payload: payload))
                    } catch {
                        Log.debug("WebSocket: could not answer a ping: \(error)")
                    }
                    continue
                case .pong:
                    continue
                case .close(let code, let reason):
                    // Echo the code; 1005 only stands for "none" and must
                    // never be sent (RFC 6455 §7.4.1), so an empty close gets
                    // an empty one back.
                    var reply: [UInt8] = []
                    if code != 1005 {
                        reply = [UInt8((code >> 8) & 0xFF), UInt8(code & 0xFF)]
                    }
                    do {
                        try await sendRaw(WebSocketConnection.buildFrame(opcode: 0x08, payload: reply))
                    } catch {
                        Log.debug("WebSocket: could not answer the close: \(error)")
                    }
                    markCloseReceived()
                    // A close frame is how a WebSocket server ends the stream:
                    // Xray sends 1000 when the target hangs up, and a CDN in
                    // front of it often relays that as an empty close (1005).
                    // That is the end of the data, like EOF on a socket.
                    // Treated as a failure, it made the stack reset the app's
                    // connection and drop the bytes still queued for it,
                    // cutting the tail off responses. Codes that report a
                    // fault still fail.
                    if WebSocketConnection.normalCloseCodes.contains(code) { return nil }
                    throw WebSocketError.connectionClosed(code: code, reason: reason)
                }
            }

            guard let data = try await inner.receive() else { return nil }
            if data.isEmpty { continue }
            try appendToReceiveBuffer(data)
        }
    }

    private var isCloseReceived: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closeReceived
    }

    private func markCloseReceived() {
        lock.lock()
        closeReceived = true
        connected = false
        lock.unlock()
    }

    func close() {
        lock.lock()
        connected = false
        receiveBuffer = []
        receiveStart = 0
        let heartbeat = heartbeatTask
        heartbeatTask = nil
        lock.unlock()
        heartbeat?.cancel()
        inner.close()
    }

    /// A Ping every `heartbeatPeriod` seconds, which keeps idle connections
    /// open through CDNs and NATs. Stops when a send fails.
    private func startHeartbeat() {
        let period = settings.heartbeatPeriod
        if period <= 0 { return }
        let task = Task { [weak self] in
            while true {
                try? await Task.sleep(nanoseconds: UInt64(period) * 1_000_000_000)
                if Task.isCancelled { return }
                guard let connection = self, connection.isConnected else { return }
                do {
                    try await connection.sendRaw(WebSocketConnection.buildFrame(opcode: 0x09, payload: []))
                } catch {
                    return
                }
            }
        }
        lock.lock()
        heartbeatTask = task
        lock.unlock()
    }

    /// A frame with FIN set and the payload masked, as RFC 6455 §5.3 requires
    /// of every client frame. `maskKey` is for tests; frames on the wire get
    /// a fresh random one.
    static func buildFrame(opcode: UInt8, payload: [UInt8], maskKey: [UInt8]? = nil) -> Data {
        let length = payload.count
        var frame: [UInt8] = []
        frame.reserveCapacity(length + 14)
        frame.append(0x80 | opcode)
        if length <= 125 {
            frame.append(UInt8(length) | 0x80)
        } else if length <= 65535 {
            frame.append(126 | 0x80)
            frame.append(UInt8((length >> 8) & 0xFF))
            frame.append(UInt8(length & 0xFF))
        } else {
            frame.append(127 | 0x80)
            var shift = 56
            while shift >= 0 {
                frame.append(UInt8((length >> shift) & 0xFF))
                shift -= 8
            }
        }
        let mask = maskKey ?? TransportEncoding.randomBytes(4)
        frame.append(contentsOf: mask)
        for i in 0..<length {
            frame.append(payload[i] ^ mask[i & 3])
        }
        return Data(frame)
    }

    private enum FrameResult {
        case binary([UInt8])
        case ping([UInt8])
        case pong
        case close(Int, String)
    }

    /// The next complete frame in the buffer, or nil until more arrives.
    private func extractFrame() throws -> FrameResult? {
        lock.lock()
        defer { lock.unlock() }
        let available = receiveBuffer.count - receiveStart
        if available < 2 { return nil }

        let byte0 = receiveBuffer[receiveStart]
        let byte1 = receiveBuffer[receiveStart + 1]
        let isMasked = (byte1 & 0x80) != 0
        var payloadLength = UInt64(byte1 & 0x7F)
        var headerSize = 2

        if payloadLength == 126 {
            if available < 4 { return nil }
            let high = UInt64(receiveBuffer[receiveStart + 2]) << 8
            payloadLength = high | UInt64(receiveBuffer[receiveStart + 3])
            headerSize = 4
        } else if payloadLength == 127 {
            if available < 10 { return nil }
            payloadLength = 0
            for i in 0..<8 {
                payloadLength = (payloadLength << 8) | UInt64(receiveBuffer[receiveStart + 2 + i])
            }
            headerSize = 10
        }

        if payloadLength > UInt64(WebSocketConnection.maxFramePayload) {
            receiveBuffer = []
            receiveStart = 0
            throw WebSocketError.invalidFrame("frame of \(payloadLength) bytes, more than \(WebSocketConnection.maxFramePayload)")
        }

        if isMasked { headerSize += 4 }
        let length = Int(payloadLength)
        let totalFrameSize = headerSize + length
        if available < totalFrameSize { return nil }

        let payloadStart = receiveStart + headerSize
        var payload = Array(receiveBuffer[payloadStart..<(payloadStart + length)])
        if isMasked {
            let maskStart = payloadStart - 4
            let mask = Array(receiveBuffer[maskStart..<payloadStart])
            for i in 0..<length {
                payload[i] ^= mask[i & 3]
            }
        }
        receiveStart += totalFrameSize
        compactLocked()

        let opcode = byte0 & 0x0F
        switch opcode {
        case 0x08:
            var code = 1005
            var reason = ""
            if payload.count >= 2 {
                code = (Int(payload[0]) << 8) | Int(payload[1])
                if payload.count > 2 {
                    reason = String(decoding: payload[2...], as: UTF8.self)
                }
            }
            return .close(code, reason)
        case 0x09:
            return .ping(payload)
        case 0x0A:
            return .pong
        default:
            // Text, binary and continuation frames all carry the stream's bytes.
            return .binary(payload)
        }
    }

    private func appendToReceiveBuffer(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        if receiveBuffer.count - receiveStart + data.count > WebSocketConnection.maxReceiveBufferSize {
            receiveBuffer = []
            receiveStart = 0
            throw WebSocketError.invalidFrame("receive buffer overflow (more than \(WebSocketConnection.maxReceiveBufferSize) bytes)")
        }
        receiveBuffer.append(contentsOf: data)
    }

    /// Drops consumed bytes: all of them once the buffer is drained, otherwise
    /// once they are the larger part of it.
    private func compactLocked() {
        if receiveStart >= receiveBuffer.count {
            receiveBuffer.removeAll(keepingCapacity: receiveBuffer.capacity <= 1 << 20)
            receiveStart = 0
        } else if receiveStart > 64 * 1024 && receiveStart * 2 > receiveBuffer.count {
            receiveBuffer.removeFirst(receiveStart)
            receiveStart = 0
        }
    }
}
