import Foundation

/// One AnyTLS session: many streams multiplexed over a single TLS connection.
///
/// The session owns the write side, because the padding scheme is defined in
/// terms of TLS writes — it says how to split the first few of them into
/// records of particular sizes. Every stream therefore hands its bytes here
/// rather than touching the connection, and `writeShaped` decides what
/// actually goes out: each element it produces is one `send` into the TLS
/// session, which seals it as its own record.
final class AnyTlsSession: @unchecked Sendable {
    /// The length field is a uint16, so no frame can carry more than this.
    static let maxFramePayload = 65535

    /// How long a version-2 server has to acknowledge a stream.
    static let synAckTimeoutNanoseconds: UInt64 = 3_000_000_000

    private let tls: ByteStream
    private let clientName: String
    /// Called when the server pushes a new scheme, so the pool can adopt it.
    private let onPaddingScheme: (AnyTlsPaddingScheme) -> Void

    private let writeMutex = TransportAsyncMutex()
    private let lock = NSLock()
    private var currentPadding: AnyTlsPaddingScheme
    private var streams: [UInt32: AnyTlsStream] = [:]
    private var nextStreamId: UInt32 = 0
    private var packetCounter = 0
    private var closed = false
    private var opening = 0
    /// Per-stream SYNACK timers, armed only against a version-2 server.
    private var synWatchdogs: [UInt32: Task<Void, Never>] = [:]
    private var receiveTask: Task<Void, Never>?
    /// Whether padding is still applied. Off for good once the counter
    /// passes the scheme's stop.
    private var shaping = true
    /// Buffered writes, used only to make the settings frame and the first
    /// stream's SYN share one TLS write: the scheme numbers packets, and
    /// packet 1 is settings plus the first SYN and its address. Sending them
    /// separately would shift every later packet by one.
    private var buffering = false
    private var buffer = [UInt8]()
    private var version = 1
    private var idleHandler: (() -> Void)?

    init(tls: ByteStream, padding: AnyTlsPaddingScheme, clientName: String,
         onPaddingScheme: @escaping (AnyTlsPaddingScheme) -> Void) {
        self.tls = tls
        self.currentPadding = padding
        self.clientName = clientName
        self.onPaddingScheme = onPaddingScheme
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return closed
    }

    /// Streams live or being opened, for the pool's idle check.
    var activeStreams: Int {
        lock.lock()
        defer { lock.unlock() }
        return streams.count + opening
    }

    /// The protocol version the server reported; version-2 features stay off below it.
    var peerVersion: Int {
        lock.lock()
        defer { lock.unlock() }
        return version
    }

    var padding: AnyTlsPaddingScheme {
        lock.lock()
        defer { lock.unlock() }
        return currentPadding
    }

    /// Notified when the last stream goes, so the pool can retire the session.
    var onIdle: (() -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return idleHandler
        }
        set {
            lock.lock()
            idleHandler = newValue
            lock.unlock()
        }
    }

    /// Queues the settings frame and starts reading. Settings must be the
    /// first thing on a new session — a server that sees a SYN before it
    /// refuses the session — and it goes out with the first stream's SYN.
    func start() async throws {
        setBuffering(true)
        try await writeFrame(AnyTlsProtocol.cmdSettings, streamId: 0,
                             data: AnyTlsProtocol.settings(clientName: clientName, paddingMd5: padding.md5))
        let task = Task<Void, Never> { [weak self] in
            guard let self else { return }
            await self.receiveLoop()
        }
        lock.lock()
        receiveTask = task
        lock.unlock()
    }

    /// Opens a stream to `host`:`port`. The address goes out as the
    /// stream's first data, in SOCKS5 form, and that write is what flushes
    /// the buffered settings — which is exactly how the reference client
    /// composes packet 1.
    func openStream(host: String, port: UInt16) async throws -> AnyTlsStream {
        let stream = try reserveStream()
        do {
            try await writeFrame(AnyTlsProtocol.cmdSyn, streamId: stream.streamId)
            setBuffering(false)
            // Registered only once the SYN is away, as the reference does: a
            // stream the peer never heard about would hold the session
            // non-idle forever.
            register(stream)
            try await sendStreamData(stream.streamId, AnyTlsProtocol.encodeAddress(host: host, port: port))
        } catch {
            unregister(stream.streamId)
            close()
            throw error
        }
        armSynWatchdog(stream.streamId)
        return stream
    }

    private func reserveStream() throws -> AnyTlsStream {
        lock.lock()
        defer { lock.unlock() }
        if closed { throw MythaiaError.protocolError("AnyTLS session is closed") }
        nextStreamId &+= 1
        opening += 1
        return AnyTlsStream(streamId: nextStreamId, session: self)
    }

    private func register(_ stream: AnyTlsStream) {
        lock.lock()
        streams[stream.streamId] = stream
        opening -= 1
        lock.unlock()
    }

    private func unregister(_ streamId: UInt32) {
        lock.lock()
        if streams.removeValue(forKey: streamId) == nil && opening > 0 {
            opening -= 1
        }
        lock.unlock()
    }

    private func setBuffering(_ value: Bool) {
        lock.lock()
        buffering = value
        lock.unlock()
    }

    /// Closes the session if a version-2 server never acknowledges a stream.
    /// Without this the client waits on the system's own timeout, which on a
    /// tunnel that has silently died can be minutes: the reason the protocol
    /// added cmdSYNACK.
    private func armSynWatchdog(_ streamId: UInt32) {
        guard peerVersion >= 2, streamId >= 2 else { return }
        let task = Task { [weak self] in
            try? await Task.sleep(nanoseconds: AnyTlsSession.synAckTimeoutNanoseconds)
            if Task.isCancelled { return }
            guard let self = self else { return }
            if self.removeWatchdog(streamId) {
                Log.debug("AnyTLS: no SYNACK for stream \(streamId); the session is stuck")
                self.close()
            }
        }
        lock.lock()
        synWatchdogs[streamId] = task
        lock.unlock()
    }

    /// True when a watchdog for `streamId` was still armed.
    @discardableResult
    private func removeWatchdog(_ streamId: UInt32) -> Bool {
        lock.lock()
        let task = synWatchdogs.removeValue(forKey: streamId)
        lock.unlock()
        task?.cancel()
        return task != nil
    }

    /// Sends FIN without waiting, for callers that must not block.
    func closeStreamAsync(_ streamId: UInt32) {
        lock.lock()
        let known = streams.removeValue(forKey: streamId) != nil
        let isClosed = closed
        let nowIdle = streams.isEmpty && opening == 0
        lock.unlock()
        guard known else { return }
        removeWatchdog(streamId)
        if isClosed { return }
        Task { [weak self] in
            guard let self = self else { return }
            try? await self.writeFrame(AnyTlsProtocol.cmdFin, streamId: streamId)
            if nowIdle {
                self.onIdle?()
            }
        }
    }

    /// Sends one stream's payload, split to fit the 16-bit length field.
    func sendStreamData(_ streamId: UInt32, _ data: [UInt8]) async throws {
        var offset = 0
        while offset < data.count {
            let take = min(AnyTlsSession.maxFramePayload, data.count - offset)
            try await writeFrame(AnyTlsProtocol.cmdPsh, streamId: streamId, data: Array(data[offset..<(offset + take)]))
            offset += take
        }
    }

    func close() {
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        closed = true
        let watchdogs = Array(synWatchdogs.values)
        synWatchdogs = [:]
        let live = Array(streams.values)
        streams = [:]
        let task = receiveTask
        receiveTask = nil
        lock.unlock()
        for watchdog in watchdogs {
            watchdog.cancel()
        }
        for stream in live {
            stream.onPeerClosed()
        }
        tls.close()
        task?.cancel()
        Log.debug("AnyTLS: session closed")
    }

    // MARK: - Writing

    private func writeFrame(_ command: UInt8, streamId: UInt32, data: [UInt8] = []) async throws {
        try await writeShaped(AnyTlsProtocol.frame(command, streamId: streamId, data: data))
    }

    private enum WritePlan {
        case buffered
        case plain([UInt8])
        case shaped([[UInt8]])
    }

    /// Writes bytes, split into the records the padding scheme asks for.
    private func writeShaped(_ bytes: [UInt8]) async throws {
        await writeMutex.acquire()
        defer { writeMutex.release() }
        if isClosed { throw MythaiaError.closed }
        switch plan(bytes) {
        case .buffered:
            return
        case .plain(let payload):
            try await tls.send(Data(payload))
        case .shaped(let records):
            for record in records {
                try await tls.send(Data(record))
            }
        }
    }

    /// What to write for `bytes`, under the state lock; called with the
    /// write mutex held, so packets are numbered in the order they go out.
    private func plan(_ bytes: [UInt8]) -> WritePlan {
        lock.lock()
        defer { lock.unlock() }
        if buffering {
            buffer.append(contentsOf: bytes)
            return .buffered
        }
        var payload = bytes
        if !buffer.isEmpty {
            payload = buffer + bytes
            buffer = []
        }
        if !shaping {
            return .plain(payload)
        }
        packetCounter += 1
        if !currentPadding.shapes(packetCounter) {
            // Past the scheme's stop: nothing is shaped again on this session.
            shaping = false
            return .plain(payload)
        }
        let sizes = currentPadding.recordSizes(packetCounter)
        return .shaped(AnyTlsProtocol.shapeWrites(payload, sizes: sizes))
    }

    // MARK: - Reading

    private func receiveLoop() async {
        var buffer = [UInt8]()
        var offset = 0
        do {
            while !isClosed {
                // One whole frame from the buffer, reading more as needed.
                if buffer.count - offset >= AnyTlsProtocol.headerSize {
                    let header = AnyTlsProtocol.readHeader(buffer, offset: offset)
                    let total = AnyTlsProtocol.headerSize + header.length
                    if buffer.count - offset >= total {
                        let start = offset + AnyTlsProtocol.headerSize
                        let body = Array(buffer[start..<(offset + total)])
                        offset += total
                        if offset == buffer.count {
                            buffer = []
                            offset = 0
                        } else if offset > 65536 {
                            buffer = Array(buffer[offset...])
                            offset = 0
                        }
                        await dispatch(header, body)
                        continue
                    }
                }
                guard let chunk = try await tls.receive() else { break }
                buffer.append(contentsOf: chunk)
            }
        } catch {
            if !isClosed {
                Log.debug("AnyTLS: session read ended: \(error.localizedDescription)")
            }
        }
        close()
    }

    private var isIdle: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !closed && streams.isEmpty && opening == 0
    }

    private func stream(_ streamId: UInt32) -> AnyTlsStream? {
        lock.lock()
        defer { lock.unlock() }
        return streams[streamId]
    }

    private func removeStream(_ streamId: UInt32) -> AnyTlsStream? {
        lock.lock()
        defer { lock.unlock() }
        return streams.removeValue(forKey: streamId)
    }

    private func dispatch(_ header: AnyTlsProtocol.Header, _ body: [UInt8]) async {
        switch header.command {
        case AnyTlsProtocol.cmdPsh:
            // A zero-length push is not data: forwarded, it would read as
            // the end of the stream. The stream may hold this loop here until
            // its reader catches up — deliberately, so the TCP window is what
            // throttles the server rather than memory.
            if !body.isEmpty, let target = stream(header.streamId) {
                await target.onData(Data(body))
            }

        case AnyTlsProtocol.cmdFin:
            removeStream(header.streamId)?.onPeerClosed()
            // The server ended the last stream: the session is free again,
            // whether or not the application has closed its side yet.
            if isIdle {
                onIdle?()
            }

        case AnyTlsProtocol.cmdWaste:
            // Padding: read and dropped.
            break

        case AnyTlsProtocol.cmdSynAck:
            // Answered either way: an error body still means the server
            // replied, so the stuck-session watchdog has done its job.
            removeWatchdog(header.streamId)
            // Empty means the outbound connected; a body is an error text.
            if !body.isEmpty {
                let reason = String(decoding: body, as: UTF8.self)
                Log.debug("AnyTLS: stream \(header.streamId) refused: \(reason)")
                removeStream(header.streamId)?.onPeerClosed(MythaiaError.connectFailed("the AnyTLS server refused the stream: \(reason)"))
            }

        case AnyTlsProtocol.cmdServerSettings:
            let settings = AnyTlsProtocol.parseSettings(body)
            let reported = settings["v"].flatMap { Int($0) } ?? 1
            lock.lock()
            version = reported
            lock.unlock()

        case AnyTlsProtocol.cmdUpdatePaddingScheme:
            if let next = AnyTlsPaddingScheme.parse(Data(body)) {
                // Applies to sessions opened from now on, as the protocol
                // says; this session keeps counting packets against it.
                lock.lock()
                currentPadding = next
                lock.unlock()
                onPaddingScheme(next)
                Log.debug("AnyTLS: padding scheme updated (\(next.md5))")
            } else {
                Log.warning("AnyTLS: the server sent a padding scheme that does not parse")
            }

        case AnyTlsProtocol.cmdHeartRequest:
            try? await writeFrame(AnyTlsProtocol.cmdHeartResponse, streamId: header.streamId)

        case AnyTlsProtocol.cmdHeartResponse:
            break

        case AnyTlsProtocol.cmdAlert:
            // The server explaining why it is about to hang up.
            Log.error("AnyTLS: server alert: \(String(decoding: body, as: UTF8.self))")
            close()

        default:
            Log.debug("AnyTLS: ignoring command \(header.command)")
        }
    }
}
