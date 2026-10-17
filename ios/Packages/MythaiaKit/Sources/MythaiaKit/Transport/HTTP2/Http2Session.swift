import Foundation

enum Http2Error: Error, LocalizedError, Equatable, TransportErrorConvertible {
    case notReady
    case connectionFailed(String)
    case protocolError(String)
    case tunnelFailed(String)
    case authenticationRequired
    case goaway
    case streamReset(Int)

    var message: String {
        switch self {
        case .notReady:
            return "HTTP/2 connection not ready"
        case .connectionFailed(let reason):
            return "HTTP/2 connection failed: \(reason)"
        case .protocolError(let reason):
            return "HTTP/2 protocol error: \(reason)"
        case .tunnelFailed(let status):
            return "HTTP/2 CONNECT tunnel failed with status \(status)"
        case .authenticationRequired:
            return "HTTP/2 proxy authentication required (407)"
        case .goaway:
            return "HTTP/2 GOAWAY received"
        case .streamReset(let streamID):
            return "HTTP/2 stream \(streamID) reset"
        }
    }

    var errorDescription: String? { message }

    var mythaiaError: MythaiaError {
        switch self {
        case .tunnelFailed(let status):
            return .http(Int(status) ?? 0, "the server refused the request")
        case .authenticationRequired:
            return .http(407, "proxy authentication required")
        default:
            return .protocolError(message)
        }
    }
}

/// What a session opens the connection with, and how it gives the server
/// back the window its data used.
struct Http2SessionProfile {
    /// The SETTINGS frame this side opens with, in order.
    var settings: [(Int, Int)]
    /// Our SETTINGS_INITIAL_WINDOW_SIZE: a stream is credited once half of
    /// it has been read.
    var streamReceiveWindow: Int
    /// The WINDOW_UPDATE on stream 0 that follows our SETTINGS.
    var connectionWindowIncrement: Int
    /// Bytes read across the connection that earn the server a
    /// connection-level WINDOW_UPDATE.
    var connectionUpdateThreshold: Int
    /// Our SETTINGS_HEADER_TABLE_SIZE, which bounds the HPACK decoder's table.
    var headerTableSize: Int
    /// Streams open right after the preface, without waiting for the
    /// server's SETTINGS (RFC 9113 §3.4 allows it), saving a round trip on
    /// every new connection.
    var eagerStart: Bool

    /// NaiveProxy's (Chrome's): 64 MB stream window, 128 MB connection window.
    static let naive = Http2SessionProfile(
        settings: [
            (0x1, 65_536),
            (0x2, 0),
            (0x3, Http2Session.maxConcurrentStreams),
            (0x4, Http2FlowControl.naiveInitialWindowSize),
            (0x5, 16_384),
            (0x6, 262_144),
        ],
        streamReceiveWindow: Http2FlowControl.naiveInitialWindowSize,
        connectionWindowIncrement: Http2FlowControl.connectionWindowUpdateIncrement,
        connectionUpdateThreshold: Http2FlowControl.naiveSessionMaxRecvWindow / 2,
        headerTableSize: 65_536,
        eagerStart: false
    )

    /// What Xray's gRPC and XHTTP clients open with: no push, `streamWindow`
    /// per stream, a 10 MB header list and a 1 GB connection window, the
    /// first request sent along with the preface.
    static func xrayClient(streamWindow: Int) -> Http2SessionProfile {
        Http2SessionProfile(
            settings: [
                (0x2, 0),
                (0x4, streamWindow),
                (0x6, 0x00A0_0000),
            ],
            streamReceiveWindow: streamWindow,
            connectionWindowIncrement: 1_073_741_824,
            connectionUpdateThreshold: max(1, streamWindow / 2),
            headerTableSize: HpackDecoder.defaultTableSize,
            eagerStart: true
        )
    }
}

/// One HTTP/2 connection carrying many concurrent streams: NaiveProxy's
/// CONNECT tunnels, or ordinary requests such as gRPC's and XHTTP's. Owns
/// the read loop that routes frames to the streams, the connection's receive
/// window, and the write lock every frame goes out under. The first caller to
/// need it dials (`dial`) and runs the handshake; concurrent callers wait for
/// that.
final class Http2Session: @unchecked Sendable {
    enum State {
        case idle
        case connecting
        case ready
        case closed
    }

    /// Silence from the server, with streams open, that earns a PING.
    static let defaultKeepaliveIdleMs: Int64 = 30_000
    /// How long after that PING the connection is given up on when nothing at all arrives.
    static let defaultKeepaliveTimeoutMs: Int64 = 15_000

    /// Why a stream fails when its session was closed under it.
    static let closedMessage = "Session closed"

    static let maxConcurrentStreams = 100

    /// RFC 9113 §5.1.1: the last stream id a client can use.
    static let maxStreamID = 0x7FFF_FFFF

    private static let connectionPreface: [UInt8] = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    private static let maxReceiveBufferSize = 2_097_152

    /// Our SETTINGS_MAX_HEADER_LIST_SIZE, and the most of one header block
    /// buffered across CONTINUATION.
    private static let maxHeaderBlockSize = 262_144

    let profile: Http2SessionProfile
    private let dial: () async throws -> ByteStream
    private let keepaliveEnabled: Bool
    private let keepaliveIdleMs: Int64
    private let keepaliveTimeoutMs: Int64

    private let lock = NSLock()
    private var state: State = .idle
    private var goawayReceived = false
    private var goawayLastStreamID = Int.max
    /// Every odd id up to maxStreamID used: like a GOAWAY, no new streams here.
    private var streamIdsExhausted = false
    private var transport: ByteStream?
    /// The server's SETTINGS_MAX_CONCURRENT_STREAMS, when lower than ours.
    private var streamLimit = Http2Session.maxConcurrentStreams
    /// When the last stream ended or the last frame arrived; see idleNanos.
    private var lastActivityNanos: UInt64
    /// When the last frame arrived, whatever it was: the keepalive's measure
    /// of the server's silence.
    private var lastFrameNanos: UInt64
    private var readTask: Task<Void, Never>?
    private var keepaliveTask: Task<Void, Never>?
    private var streams: [Int: Http2Stream] = [:]
    private var nextID = 1
    /// Streams handed out but not opened yet: they hold a slot, not yet an id.
    private var reserved = 0
    private var connectionSendWindow = Http2FlowControl.defaultInitialWindowSize
    private var connectionRecvConsumed = 0
    private var connectionWindowAwaiter: TransportDeferred<Void>?
    private var serverInitialWindow = Http2FlowControl.defaultInitialWindowSize
    private var closeHandler: (() -> Void)?

    // Touched only by the handshake and then the read loop, never both at once.
    private let receiveBuffer = Http2Buffer()
    /// A header block whose HEADERS frame lacked END_HEADERS, collecting its
    /// CONTINUATION frames; RFC 9113 §6.10 lets nothing else arrive meanwhile.
    private var pendingHeaderBlock: [UInt8]?
    private var pendingHeadersStreamID = 0
    private var pendingHeadersFlags = 0
    let hpackDecoder: HpackDecoder

    private let writeMutex = TransportAsyncMutex()
    /// One dial at a time: concurrent first callers wait here for the handshake.
    private let readyMutex = TransportAsyncMutex()
    /// Completed by the server's first SETTINGS.
    private let serverSettings = TransportDeferred<Void>()

    /// `keepalive` turns on the PING after `keepaliveIdleMs` of silence with
    /// streams open, and gives the connection up when nothing at all arrives
    /// within `keepaliveTimeoutMs` after it. Without it a stream on a
    /// connection the network had dropped silently hung until the
    /// application gave up on its own.
    init(profile: Http2SessionProfile = .naive,
         keepalive: Bool = false,
         keepaliveIdleMs: Int64 = Http2Session.defaultKeepaliveIdleMs,
         keepaliveTimeoutMs: Int64 = Http2Session.defaultKeepaliveTimeoutMs,
         dial: @escaping () async throws -> ByteStream) {
        self.profile = profile
        self.dial = dial
        self.keepaliveEnabled = keepalive
        self.keepaliveIdleMs = keepaliveIdleMs
        self.keepaliveTimeoutMs = keepaliveTimeoutMs
        self.hpackDecoder = HpackDecoder(maxTableSize: profile.headerTableSize)
        let now = transportMonotonicNanos()
        self.lastActivityNanos = now
        self.lastFrameNanos = now
    }

    /// Called once when the session closes, for whoever pools it.
    var onClose: (() -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return closeHandler
        }
        set {
            lock.lock()
            closeHandler = newValue
            lock.unlock()
        }
    }

    /// The id the next stream gets. Settable so a test can walk it to the
    /// end of the id space.
    var nextStreamID: Int {
        get {
            lock.lock()
            defer { lock.unlock() }
            return nextID
        }
        set {
            lock.lock()
            nextID = newValue
            lock.unlock()
        }
    }

    /// The server's SETTINGS_INITIAL_WINDOW_SIZE, which new streams start with.
    var serverInitialWindowSize: Int {
        lock.lock()
        defer { lock.unlock() }
        return serverInitialWindow
    }

    /// How long the session has carried no stream at all; 0 while one is open.
    var idleNanos: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        if !streams.isEmpty || reserved > 0 { return 0 }
        let now = transportMonotonicNanos()
        return now >= lastActivityNanos ? now - lastActivityNanos : 0
    }

    /// Not dialled yet, or still in its handshake: a caller may join and wait.
    var isStarting: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .idle || state == .connecting
    }

    var hasCapacity: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .ready && !goawayReceived && !streamIdsExhausted && streams.count + reserved < streamLimit
    }

    var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .closed
    }

    private var currentState: State {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    /// A new stream, not yet opened, on this connection; dials first if
    /// nobody has.
    func acquireStream(_ destination: String) async throws -> Http2Stream {
        try await ensureReady()
        let window = try reserveSlot()
        return Http2Stream(session: self, destination: destination, initialSendWindow: window,
                           receiveWindow: profile.streamReceiveWindow)
    }

    private func reserveSlot() throws -> Int {
        lock.lock()
        defer { lock.unlock() }
        if state != .ready { throw Http2Error.notReady }
        if goawayReceived || streamIdsExhausted { throw Http2Error.goaway }
        reserved += 1
        lastActivityNanos = transportMonotonicNanos()
        return serverInitialWindow
    }

    /// Checks capacity and reserves a stream slot in one step; nil when the
    /// session is full, going away or closed, so concurrent callers cannot
    /// exceed the stream limit.
    func tryReserveStream(_ destination: String) -> Http2Stream? {
        lock.lock()
        let full = streams.count + reserved >= streamLimit
        if state != .ready || goawayReceived || streamIdsExhausted || full {
            lock.unlock()
            return nil
        }
        reserved += 1
        lastActivityNanos = transportMonotonicNanos()
        let window = serverInitialWindow
        lock.unlock()
        return Http2Stream(session: self, destination: destination, initialSendWindow: window,
                           receiveWindow: profile.streamReceiveWindow)
    }

    /// A stream handed out and closed without ever opening gives its slot back.
    func releaseReservation() {
        lock.lock()
        if reserved > 0 { reserved -= 1 }
        lastActivityNanos = transportMonotonicNanos()
        lock.unlock()
    }

    func removeStream(_ streamID: Int) {
        lock.lock()
        streams.removeValue(forKey: streamID)
        lastActivityNanos = transportMonotonicNanos()
        let finished = (goawayReceived || streamIdsExhausted) && streams.isEmpty
        lock.unlock()
        if finished { close() }
    }

    /// Opens `stream`: gives it the next id and writes its HEADERS in one
    /// step under the write lock, so ids reach the server in increasing order
    /// however the openers interleave (RFC 9113 §5.1.1: an id lower than one
    /// already used is a connection error, which took every stream on the
    /// connection down with it).
    private func openStream(_ stream: Http2Stream, makeFrame: (Int) -> Http2Frame) async throws {
        await writeMutex.acquire()
        defer { writeMutex.release() }
        let (wire, id) = try assignStreamID(stream)
        try await wire.send(Http2Framer.serialize(makeFrame(id)))
    }

    private func assignStreamID(_ stream: Http2Stream) throws -> (ByteStream, Int) {
        lock.lock()
        defer { lock.unlock() }
        guard let wire = transport, state != .closed else {
            throw Http2Error.connectionFailed("Transport closed")
        }
        // The id space is finite (§5.1.1). Running out is treated like a
        // GOAWAY: no new streams here. The reservation stays with the
        // caller, which releases it on the way out.
        if nextID < 1 || nextID > Http2Session.maxStreamID {
            streamIdsExhausted = true
            throw Http2Error.goaway
        }
        let id = nextID
        nextID += 2
        if nextID > Http2Session.maxStreamID {
            // The last usable id just went out: hasCapacity turns false now.
            streamIdsExhausted = true
        }
        if reserved > 0 { reserved -= 1 }
        streams[id] = stream
        stream.assignId(id)
        stream.flowControl.setInitialSendWindow(serverInitialWindow)
        return (wire, id)
    }

    /// Opens `stream` as an ordinary request with `headerBlock` (HPACK); the
    /// body, if any, follows through sendData. `endStream` for a request
    /// without a body, such as a GET.
    func sendRequestHeaders(_ stream: Http2Stream, headerBlock: Data, endStream: Bool) async throws {
        try await openStream(stream) { id in
            Http2Framer.headersFrame(streamID: id, headerBlock: headerBlock, endStream: endStream)
        }
    }

    /// Sends `data` on `stream` in frames of at most 16 KB, each within both
    /// the stream's and the connection's send window, waiting for a
    /// WINDOW_UPDATE whenever either runs out.
    func sendData(_ stream: Http2Stream, _ data: Data, endStream: Bool = false) async throws {
        let bytes = [UInt8](data)
        let streamID = stream.streamID
        let flow = stream.flowControl

        if bytes.isEmpty {
            if endStream {
                try await writeFrame(Http2Framer.dataFrame(streamID: streamID, payload: Data(), endStream: true))
            }
            return
        }

        var offset = 0
        while offset < bytes.count {
            // Checked per chunk: a stream reset or closed in the middle of a
            // long write used to keep sending DATA on it to the end.
            if !stream.isConnected { throw Http2Error.streamReset(streamID) }
            let chunkSize = try takeSendCredit(remaining: bytes.count - offset, flow: flow)
            if chunkSize <= 0 {
                try await waitForSendWindow(flow)
                continue
            }
            _ = flow.consumeSend(chunkSize)
            let last = offset + chunkSize >= bytes.count
            let chunk = Data(bytes[offset..<(offset + chunkSize)])
            try await writeFrame(Http2Framer.dataFrame(streamID: streamID, payload: chunk, endStream: endStream && last))
            offset += chunkSize
        }
    }

    /// Takes what may be sent now from the connection window, under the
    /// lock: with many streams sending at once, an unlocked read-then-subtract
    /// let two of them spend the same window.
    private func takeSendCredit(remaining: Int, flow: Http2StreamFlowControl) throws -> Int {
        lock.lock()
        defer { lock.unlock() }
        if state == .closed { throw Http2Error.connectionFailed(Http2Session.closedMessage) }
        let allowed = min(remaining, Http2Framer.maxDataPayload, connectionSendWindow, flow.sendWindow)
        if allowed > 0 { connectionSendWindow -= allowed }
        return allowed
    }

    /// Waits for a WINDOW_UPDATE on whichever window ran out.
    private func waitForSendWindow(_ flow: Http2StreamFlowControl) async throws {
        if let awaiter = try connectionAwaiterIfBlocked() {
            try await awaiter.wait()
        } else {
            try await flow.awaitWindow()
        }
    }

    private func connectionAwaiterIfBlocked() throws -> TransportDeferred<Void>? {
        lock.lock()
        defer { lock.unlock() }
        if state == .closed { throw Http2Error.connectionFailed(Http2Session.closedMessage) }
        if connectionSendWindow > 0 { return nil }
        if let existing = connectionWindowAwaiter { return existing }
        let created = TransportDeferred<Void>()
        connectionWindowAwaiter = created
        return created
    }

    /// Credits `bytes` the application read from `streamID`: the connection
    /// window and the stream's, each with a WINDOW_UPDATE once half of it is
    /// used. Deferred to read time so back-pressure reaches the server.
    func acknowledgeConsumedData(streamID: Int, bytes: Int) {
        if bytes <= 0 { return }
        creditConnection(bytes)
        guard let stream = streamFor(streamID) else { return }
        if let increment = stream.flowControl.consumeRecv(bytes) {
            Task { await self.sendWindowUpdate(streamID: streamID, increment: increment) }
        }
    }

    /// The connection half of acknowledgeConsumedData: `bytes` of DATA the
    /// server sent are done with, whether the application read them or they
    /// went to a stream that was already gone. RFC 9113 §6.9: every DATA byte
    /// counts against the connection window, so every one has to be credited
    /// back, or the window runs out and the server stops sending to everyone
    /// on the connection.
    func creditConnection(_ bytes: Int) {
        if bytes <= 0 { return }
        lock.lock()
        connectionRecvConsumed += bytes
        var increment: Int?
        if connectionRecvConsumed >= profile.connectionUpdateThreshold {
            increment = connectionRecvConsumed
            connectionRecvConsumed = 0
        }
        lock.unlock()
        if let increment = increment {
            Task { await self.sendWindowUpdate(streamID: 0, increment: increment) }
        }
    }

    /// RST_STREAM, so the server reclaims the stream's slot when this side
    /// gives a stream up before the server ended it.
    func sendReset(streamID: Int, errorCode: Int) {
        let frame = Http2Framer.rstStreamFrame(streamID: streamID, errorCode: errorCode)
        Task { await self.sendFrameRaw(frame) }
    }

    /// A PING; the keepalive of transports that ask for one on a timer.
    func sendPing() async {
        await sendFrameRaw(Http2Framer.pingFrame())
    }

    /// Waits for the server's SETTINGS: until then nothing has proved that
    /// an HTTP/2 server is on the other end at all.
    func awaitServerSettings() async throws {
        try await serverSettings.wait()
    }

    private func ensureReady() async throws {
        switch currentState {
        case .ready:
            return
        case .closed:
            throw Http2Error.connectionFailed(Http2Session.closedMessage)
        default:
            break
        }

        // A lock rather than a flag: callers on several threads used to be
        // able to see "not connecting" at once and both dial.
        await readyMutex.acquire()
        defer { readyMutex.release() }

        switch currentState {
        case .ready:
            return
        case .closed:
            throw Http2Error.connectionFailed(Http2Session.closedMessage)
        default:
            break
        }

        do {
            try beginConnecting()
            let wire = try await dial()
            // close() while the dial was in flight had no transport to
            // cancel; going on from here made a ready session with a read
            // loop nobody could reach any more.
            guard adoptTransport(wire) else {
                throw Http2Error.connectionFailed(Http2Session.closedMessage)
            }
            try await sendConnectionPreface(wire)
            if !profile.eagerStart {
                try await processHandshake(wire)
            }
            try markReady()
            startLoops(wire)
        } catch {
            closeWithError(error)
            throw error
        }
    }

    private func beginConnecting() throws {
        lock.lock()
        defer { lock.unlock() }
        if state == .closed { throw Http2Error.connectionFailed(Http2Session.closedMessage) }
        state = .connecting
    }

    /// Stores `wire` as the transport unless the session closed meanwhile,
    /// in which case it closes it.
    private func adoptTransport(_ wire: ByteStream) -> Bool {
        lock.lock()
        if state != .closed {
            transport = wire
            lock.unlock()
            return true
        }
        lock.unlock()
        wire.close()
        return false
    }

    private func markReady() throws {
        lock.lock()
        defer { lock.unlock() }
        if state == .closed { throw Http2Error.connectionFailed(Http2Session.closedMessage) }
        state = .ready
        let now = transportMonotonicNanos()
        lastActivityNanos = now
        lastFrameNanos = now
    }

    private func startLoops(_ wire: ByteStream) {
        let reader = Task { await self.readLoop(wire) }
        var pinger: Task<Void, Never>?
        if keepaliveEnabled {
            pinger = Task { await self.keepaliveLoop() }
        }
        lock.lock()
        readTask = reader
        keepaliveTask = pinger
        lock.unlock()
    }

    private func sendConnectionPreface(_ wire: ByteStream) async throws {
        var out = Data(Http2Session.connectionPreface)
        out.append(Http2Framer.serialize(Http2Framer.settingsFrame(profile.settings)))
        out.append(Http2Framer.serialize(Http2Framer.windowUpdateFrame(streamID: 0, increment: profile.connectionWindowIncrement)))
        try await wire.send(out)
    }

    /// Reads frames until the server's SETTINGS arrives and is acknowledged.
    private func processHandshake(_ wire: ByteStream) async throws {
        while true {
            guard let frame = Http2Framer.deserialize(receiveBuffer) else {
                try await readFromTransport(wire)
                continue
            }
            switch frame.type {
            case .settings:
                if frame.hasFlag(Http2FrameFlags.ack) { continue }
                handleServerSettings(frame)
                await sendFrameRaw(Http2Framer.settingsAckFrame())
                return
            case .windowUpdate:
                if frame.streamID == 0, let increment = Http2Framer.parseWindowUpdate(frame.payload) {
                    addConnectionSendWindow(increment)
                }
            case .ping:
                if !frame.hasFlag(Http2FrameFlags.ack) {
                    await sendFrameRaw(Http2Framer.pingAckFrame(frame.payload))
                }
            case .goaway:
                let parsed = Http2Framer.parseGoaway(frame.payload)
                Log.warning("HTTP/2: GOAWAY during handshake: last stream \(parsed?.lastStreamID ?? -1), error \(parsed?.errorCode ?? -1)")
                throw Http2Error.goaway
            default:
                break
            }
        }
    }

    /// Pooled connections only: a PING once streams are open and the server
    /// has sent nothing for keepaliveIdleMs; no frame at all within
    /// keepaliveTimeoutMs after it fails the connection and every stream on
    /// it, so the applications reconnect on a fresh one.
    private func keepaliveLoop() async {
        while !isClosed {
            let (silentMs, busy) = keepaliveSnapshot()
            if !busy || silentMs < keepaliveIdleMs {
                let wait = busy ? keepaliveIdleMs - silentMs : keepaliveIdleMs
                try? await Task.sleep(nanoseconds: UInt64(max(1, wait)) * 1_000_000)
                if Task.isCancelled { return }
                continue
            }
            let before = lastFrameTime()
            await sendFrameRaw(Http2Framer.pingFrame())
            try? await Task.sleep(nanoseconds: UInt64(max(1, keepaliveTimeoutMs)) * 1_000_000)
            if Task.isCancelled { return }
            if lastFrameTime() == before && !isClosed {
                closeWithError(Http2Error.connectionFailed("no reply to keepalive PING within \(keepaliveTimeoutMs) ms"))
            }
        }
    }

    private func keepaliveSnapshot() -> (Int64, Bool) {
        lock.lock()
        defer { lock.unlock() }
        let now = transportMonotonicNanos()
        let silent = now >= lastFrameNanos ? now - lastFrameNanos : 0
        return (Int64(silent / 1_000_000), !streams.isEmpty)
    }

    private func lastFrameTime() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return lastFrameNanos
    }

    private func touchFrameTime() {
        lock.lock()
        let now = transportMonotonicNanos()
        lastActivityNanos = now
        lastFrameNanos = now
        lock.unlock()
    }

    private func readLoop(_ wire: ByteStream) async {
        do {
            while !isClosed {
                if let frame = Http2Framer.deserialize(receiveBuffer) {
                    try routeFrame(frame)
                } else {
                    try await readFromTransport(wire)
                }
            }
        } catch {
            if !isClosed {
                Log.warning("HTTP/2: read loop ended: \(error.localizedDescription)")
                closeWithError(error)
            }
        }
    }

    private func streamFor(_ streamID: Int) -> Http2Stream? {
        lock.lock()
        defer { lock.unlock() }
        return streams[streamID]
    }

    @discardableResult
    private func removeStreamEntry(_ streamID: Int) -> Http2Stream? {
        lock.lock()
        defer { lock.unlock() }
        return streams.removeValue(forKey: streamID)
    }

    /// Routes one frame; throws on a connection error, which readLoop turns
    /// into closeWithError.
    private func routeFrame(_ frame: Http2Frame) throws {
        touchFrameTime()

        // RFC 9113 §6.10: an unfinished header block may be followed by
        // nothing but its own CONTINUATION frames.
        if pendingHeaderBlock != nil && (frame.type != .continuation || frame.streamID != pendingHeadersStreamID) {
            throw Http2Error.protocolError("\(frame.type) on stream \(frame.streamID) inside the header block of stream \(pendingHeadersStreamID)")
        }

        switch frame.type {
        case .data:
            if frame.streamID == 0 { return }
            guard let data = Http2Framer.dataPayload(frame) else {
                throw Http2Error.protocolError("DATA on stream \(frame.streamID): padding longer than the frame")
            }
            guard let stream = streamFor(frame.streamID) else {
                // Closed on our side already (our RST and this frame crossed),
                // but the server spent connection window on it: credit it.
                creditConnection(frame.payload.count)
                return
            }
            // §6.1: padding counts against both windows but never reaches
            // the application, so it is acknowledged here and now.
            let padding = frame.payload.count - data.count
            if padding > 0 {
                acknowledgeConsumedData(streamID: frame.streamID, bytes: padding)
            }
            if !data.isEmpty {
                stream.deliverData(data)
            }
            if frame.hasFlag(Http2FrameFlags.endStream) {
                // END_STREAM is a clean half-close from the server, not a reset.
                stream.deliverEndStream()
                removeStreamEntry(frame.streamID)
            }

        case .headers:
            if frame.streamID == 0 { throw Http2Error.protocolError("HEADERS on stream 0") }
            guard let fragment = Http2Framer.headerBlockFragment(frame) else {
                throw Http2Error.protocolError("HEADERS on stream \(frame.streamID): padding or priority longer than the frame")
            }
            if frame.hasFlag(Http2FrameFlags.endHeaders) {
                try deliverHeaderBlock(streamID: frame.streamID, flags: frame.flags, block: fragment)
            } else {
                pendingHeadersStreamID = frame.streamID
                pendingHeadersFlags = frame.flags
                pendingHeaderBlock = [UInt8](fragment)
            }

        case .continuation:
            guard var block = pendingHeaderBlock else {
                throw Http2Error.protocolError("CONTINUATION on stream \(frame.streamID) without HEADERS")
            }
            if block.count + frame.payload.count > Http2Session.maxHeaderBlockSize {
                throw Http2Error.protocolError("header block on stream \(frame.streamID) over \(Http2Session.maxHeaderBlockSize) bytes")
            }
            block.append(contentsOf: frame.payload)
            if frame.hasFlag(Http2FrameFlags.endHeaders) {
                pendingHeaderBlock = nil
                try deliverHeaderBlock(streamID: pendingHeadersStreamID, flags: pendingHeadersFlags, block: Data(block))
            } else {
                pendingHeaderBlock = block
            }

        case .rstStream:
            if frame.streamID == 0 { return }
            if let stream = removeStreamEntry(frame.streamID) {
                stream.deliverReset()
            }

        case .settings:
            if frame.hasFlag(Http2FrameFlags.ack) { return }
            handleServerSettings(frame)
            Task { await self.sendFrameRaw(Http2Framer.settingsAckFrame()) }

        case .ping:
            if !frame.hasFlag(Http2FrameFlags.ack) {
                let ack = Http2Framer.pingAckFrame(frame.payload)
                Task { await self.sendFrameRaw(ack) }
            }

        case .windowUpdate:
            guard let increment = Http2Framer.parseWindowUpdate(frame.payload) else { return }
            if frame.streamID == 0 {
                addConnectionSendWindow(increment)
            } else {
                streamFor(frame.streamID)?.deliverWindowUpdate(increment)
            }

        case .goaway:
            handleGoaway(frame)
        }
    }

    /// Decodes a complete header block and hands it to its stream. Decoded
    /// whether or not the stream still exists: HPACK's dynamic table is
    /// shared by every stream on the connection (RFC 7541 §2.2), and skipping
    /// the block of a stream already reset here (its response was in flight)
    /// dropped the table insertions it carried, after which every later
    /// header block decoded to garbage. A block that does not decode leaves
    /// the table in an unknown state, so it is a connection error (RFC 9113
    /// §4.3, COMPRESSION_ERROR), not a stream's problem.
    private func deliverHeaderBlock(streamID: Int, flags: Int, block: Data) throws {
        guard let headers = hpackDecoder.decode(block) else {
            throw Http2Error.protocolError("COMPRESSION_ERROR: header block on stream \(streamID) does not decode")
        }
        guard let stream = streamFor(streamID) else { return }
        stream.deliverHeaders(headers)
        // Trailers (gRPC's grpc-status) end the stream on a HEADERS frame.
        if (flags & Http2FrameFlags.endStream) != 0 {
            stream.deliverEndStream()
            removeStreamEntry(streamID)
        }
    }

    private func handleGoaway(_ frame: Http2Frame) {
        let parsed = Http2Framer.parseGoaway(frame.payload)
        var affected: [Http2Stream] = []
        lock.lock()
        goawayReceived = true
        if let parsed = parsed {
            goawayLastStreamID = parsed.lastStreamID
            let ids = streams.keys.filter { $0 > parsed.lastStreamID }
            for id in ids {
                if let stream = streams.removeValue(forKey: id) {
                    affected.append(stream)
                }
            }
        }
        let empty = streams.isEmpty
        lock.unlock()

        if let parsed = parsed {
            Log.warning("HTTP/2: GOAWAY: last stream \(parsed.lastStreamID), error \(parsed.errorCode)")
        }
        for stream in affected {
            stream.deliverGoaway()
        }
        if empty { close() }
    }

    private func handleServerSettings(_ frame: Http2Frame) {
        for (id, value) in Http2Framer.parseSettings(frame.payload) {
            switch id {
            case 0x3:
                // SETTINGS_MAX_CONCURRENT_STREAMS
                lock.lock()
                streamLimit = min(Http2Session.maxConcurrentStreams, max(1, value))
                lock.unlock()
            case 0x4:
                // SETTINGS_INITIAL_WINDOW_SIZE. RFC 9113 §6.9.2: every open
                // stream's send window moves by the difference. A snapshot:
                // streams open and close on other threads meanwhile.
                lock.lock()
                let delta = value - serverInitialWindow
                serverInitialWindow = value
                let open = Array(streams.values)
                lock.unlock()
                for stream in open {
                    stream.adjustSendWindow(delta)
                }
            default:
                break
            }
        }
        serverSettings.complete(())
    }

    private func addConnectionSendWindow(_ increment: Int) {
        lock.lock()
        connectionSendWindow += increment
        let awaiter = connectionWindowAwaiter
        connectionWindowAwaiter = nil
        lock.unlock()
        // Wakes a sender waiting on connection-level flow control.
        awaiter?.complete(())
    }

    private func sendWindowUpdate(streamID: Int, increment: Int) async {
        await sendFrameRaw(Http2Framer.windowUpdateFrame(streamID: streamID, increment: increment))
    }

    private func currentTransport() -> ByteStream? {
        lock.lock()
        defer { lock.unlock() }
        return transport
    }

    /// Writes one frame under the write lock; failures are the caller's.
    private func writeFrame(_ frame: Http2Frame) async throws {
        await writeMutex.acquire()
        defer { writeMutex.release() }
        guard let wire = currentTransport() else {
            throw Http2Error.connectionFailed("Transport closed")
        }
        try await wire.send(Http2Framer.serialize(frame))
    }

    /// Writes one control frame; a failure only matters to the read loop,
    /// which sees the connection go down anyway.
    private func sendFrameRaw(_ frame: Http2Frame) async {
        await writeMutex.acquire()
        defer { writeMutex.release() }
        guard let wire = currentTransport() else { return }
        do {
            try await wire.send(Http2Framer.serialize(frame))
        } catch {
            Log.debug("HTTP/2: could not send \(frame.type): \(error.localizedDescription)")
        }
    }

    private func readFromTransport(_ wire: ByteStream) async throws {
        guard let data = try await wire.receive(), !data.isEmpty else {
            throw Http2Error.connectionFailed("Connection closed")
        }
        receiveBuffer.append(data)
        if receiveBuffer.available > Http2Session.maxReceiveBufferSize {
            receiveBuffer.clear()
            throw Http2Error.connectionFailed("Receive buffer exceeded \(Http2Session.maxReceiveBufferSize) bytes")
        }
    }

    private func closeWithError(_ error: Error) {
        // Taken under the lock adoptTransport and markReady use, so a close
        // during the dial is never lost.
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        state = .closed
        let open = Array(streams.values)
        streams.removeAll()
        let pinger = keepaliveTask
        keepaliveTask = nil
        let reader = readTask
        readTask = nil
        let awaiter = connectionWindowAwaiter
        connectionWindowAwaiter = nil
        let wire = transport
        transport = nil
        let handler = closeHandler
        closeHandler = nil
        lock.unlock()

        pinger?.cancel()
        reader?.cancel()
        for stream in open {
            stream.deliverError(error)
        }
        awaiter?.fail(error)
        serverSettings.fail(error)
        wire?.close()
        handler?()
    }

    /// Closes the connection; every stream still on it fails with
    /// `connectionFailed(closedMessage)`.
    func close() {
        closeWithError(Http2Error.connectionFailed(Http2Session.closedMessage))
    }
}
