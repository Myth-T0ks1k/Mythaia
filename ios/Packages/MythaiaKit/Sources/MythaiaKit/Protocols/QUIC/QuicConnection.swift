import CQuic
import Foundation
import Network

/// One QUIC connection: a UDP socket, an event loop, and the streams on top.
///
/// The three pieces below this each know one thing. ngtcp2 (through the CQuic
/// bridge) knows the protocol but not where the bytes come from;
/// `QuicTlsHandler` knows the handshake but never sees a packet; this knows
/// the socket and the clock, and carries bytes between them.
///
/// Everything that touches ngtcp2 runs on one serial queue, the engine queue:
/// the socket delivers there, the timer fires there, and stream writes hop
/// onto it. A `ngtcp2_conn` is not thread-safe, and ngtcp2 calls back into
/// Swift from inside those calls, so the callbacks run on that queue too and
/// must never wait on it. Teardown is always scheduled onto the queue rather
/// than done inline, so a callback that fails the connection never frees the
/// handle out from under the C call it is running in.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class QuicConnection: @unchecked Sendable {
    /// The bridge's CQUIC_WRITE_AGAIN: nothing fit this time; offer the same
    /// bytes again. Anything below it is terminal.
    static let writeAgain: Int64 = -1

    /// The default bound on the handshake.
    static let handshakeTimeout: Double = 10

    /// quic-go queues 32; fragments of a large payload count one each.
    private static let maxPendingDatagrams = 64
    /// How long a datagram may wait for room before it is dropped.
    private static let maxDatagramAgeNanos: UInt64 = 500_000_000
    /// The longest the timer waits before looking again, so a deadline
    /// ngtcp2 moved without telling anyone is never missed by much.
    private static let maxTimerWaitNanos: Int64 = 50_000_000
    /// The shortest, so a deadline already past cannot spin the queue.
    private static let minTimerWaitNanos: Int64 = 100_000
    /// How long a writer blocked on flow control or congestion waits before
    /// offering again, when nothing arrives to wake it sooner.
    private static let writeRetryMilliseconds = 5

    /// Where the datagrams go: a host name to resolve or an address.
    private let serverName: String
    private let serverPort: UInt16
    private let tuning: QuicTuning
    private let obfuscator: HysteriaObfuscator?
    private let tls: QuicTlsHandler
    let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<Bool>()

    // Engine state: touched on `queue` only.
    private var handle: OpaquePointer?
    private var udp: NWConnection?
    private var timer: DispatchSourceTimer?
    private var streams: [Int64: QuicStream] = [:]
    private var pendingDatagrams: [(data: [UInt8], queuedAt: UInt64)] = []
    private var verificationStarted = false
    private var tornDown = false
    private var writeGeneration: UInt64 = 0
    private var nextWaiterId: UInt64 = 0
    private var writeWaiters: [UInt64: CheckedContinuation<Void, Never>] = [:]
    private var datagramHandler: ((Data) -> Void)?

    // Shared state, behind `lock`.
    private let lock = NSLock()
    private enum State {
        case idle
        case connecting
        case established
        case closed
    }
    private var state: State = .idle
    private var handshakeContinuation: CheckedContinuation<Void, Error>?
    private var failure: MythaiaError?
    private var maxDatagramPayloadCache = 0

    init(
        serverName: String,
        serverPort: UInt16,
        alpn: [String],
        tuning: QuicTuning = .naive,
        fingerprint: TlsFingerprint = .chrome133,
        tlsServerName: String? = nil,
        allowInsecure: Bool = false,
        pinnedCertSha256: [String]? = nil,
        verifyName: String? = nil,
        obfuscator: HysteriaObfuscator? = nil
    ) {
        self.serverName = serverName
        self.serverPort = serverPort
        self.tuning = tuning
        self.obfuscator = obfuscator
        let name = (tlsServerName?.isEmpty == false) ? tlsServerName! : serverName
        self.tls = QuicTlsHandler(
            serverName: name,
            alpn: alpn,
            tuning: tuning,
            fingerprint: fingerprint,
            allowInsecure: allowInsecure,
            pinnedCertSha256: pinnedCertSha256,
            verifyName: verifyName
        )
        self.queue = DispatchQueue(label: "com.mythaia.quic")
        queue.setSpecific(key: queueKey, value: true)
    }

    deinit {
        timer?.setEventHandler(handler: nil)
        timer?.cancel()
        udp?.stateUpdateHandler = nil
        udp?.cancel()
        if let handle = handle {
            cquic_conn_free(handle)
        }
    }

    private var onQueue: Bool { DispatchQueue.getSpecific(key: queueKey) == true }

    /// Runs `body` on the engine queue and waits for it; inline when already there.
    private func onEngine<T>(_ body: () -> T) -> T {
        if onQueue { return body() }
        return queue.sync(execute: body)
    }

    // MARK: - Public state

    var isConnected: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .established
    }

    /// Why the connection ended, when it did not end cleanly.
    var failureReason: MythaiaError? {
        lock.lock()
        defer { lock.unlock() }
        return failure
    }

    /// Where unreliable datagrams go. Set before `connect`, so no datagram
    /// arriving with the handshake is lost; called on the engine queue.
    func setDatagramHandler(_ handler: @escaping (Data) -> Void) {
        onEngine { datagramHandler = handler }
    }

    /// Keying material bound to this session (RFC 5705). TUIC turns its
    /// password into a token this way, so a token captured on one connection
    /// proves nothing on another. Nil before the handshake finishes.
    func exportKeyingMaterial(label: [UInt8], context: [UInt8], length: Int) -> [UInt8]? {
        return onEngine { tls.exportKeyingMaterial(label: label, context: context, length: length) }
    }

    /// What the peer advertised, once the handshake has got that far.
    var peerTransportParameters: [QuicTuning.TransportParameter] {
        return onEngine { tls.peerTransportParameters }
    }

    // MARK: - Lifecycle

    /// Brings the connection up, returning when the handshake completes and
    /// the server has been verified. Throws why it did not; the connection is
    /// closed then.
    func connect(timeout: Double = QuicConnection.handshakeTimeout) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                lock.lock()
                if state != .idle {
                    let error = failure ?? MythaiaError.closed
                    lock.unlock()
                    continuation.resume(throwing: error)
                    return
                }
                state = .connecting
                handshakeContinuation = continuation
                lock.unlock()
                queue.async { self.startSocket() }
                queue.asyncAfter(deadline: .now() + max(0.5, timeout)) { [weak self] in
                    guard let self = self else { return }
                    self.fail(.timeout("QUIC handshake with \(self.serverName)"), onlyWhileConnecting: true)
                }
            }
        } onCancel: {
            self.fail(.timeout("QUIC handshake with \(self.serverName)"), onlyWhileConnecting: true)
        }
    }

    /// Ends the connection, telling the peer when there is one to tell.
    /// Safe from any thread, any number of times.
    func close() {
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        state = .closed
        let continuation = handshakeContinuation
        handshakeContinuation = nil
        lock.unlock()
        continuation?.resume(throwing: MythaiaError.closed)
        queue.async { self.teardown() }
    }

    /// Ends the connection with `error`: a pending connect gets it, and every
    /// stream sees the connection go.
    private func fail(_ error: MythaiaError, onlyWhileConnecting: Bool = false) {
        lock.lock()
        if state == .closed || (onlyWhileConnecting && state != .connecting) {
            lock.unlock()
            return
        }
        state = .closed
        if failure == nil { failure = error }
        let continuation = handshakeContinuation
        handshakeContinuation = nil
        lock.unlock()
        Log.debug("[QUIC] \(serverName): \(error.localizedDescription)")
        continuation?.resume(throwing: error)
        queue.async { self.teardown() }
    }

    private var isClosed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .closed
    }

    /// On the queue: says goodbye, frees the engine, wakes everything waiting.
    private func teardown() {
        if tornDown { return }
        tornDown = true
        let error = failureReason ?? MythaiaError.closed
        let open = streams
        streams.removeAll()
        for stream in open.values {
            stream.onConnectionClosed(error)
        }

        // Tell the peer, best effort: without a CONNECTION_CLOSE the server
        // keeps the session, its streams and its UDP sessions until its idle
        // timeout, and a client that reconnects straight away holds two.
        var farewell: [UInt8]?
        if let handle = handle {
            let length = cquic_conn_write_close(handle)
            if length > 0, let out = cquic_conn_out(handle) {
                farewell = Array(UnsafeBufferPointer(start: out, count: Int(length)))
            }
            cquic_conn_free(handle)
            self.handle = nil
        }
        timer?.setEventHandler(handler: nil)
        timer?.cancel()
        timer = nil
        pendingDatagrams.removeAll()
        datagramHandler = nil
        wakeWriters()

        if let socket = udp {
            udp = nil
            socket.stateUpdateHandler = nil
            if let farewell = farewell {
                for piece in sealed(farewell) {
                    socket.send(content: Data(piece), completion: .idempotent)
                }
                // Cancelling at once could drop the farewell still queued.
                queue.asyncAfter(deadline: .now() + 0.5) { socket.cancel() }
            } else {
                socket.cancel()
            }
        }
    }

    // MARK: - Socket

    private func startSocket() {
        if isClosed { return }
        guard let port = NWEndpoint.Port(rawValue: serverPort), serverPort != 0 else {
            fail(.invalidConfiguration("UDP port \(serverPort) is not valid"))
            return
        }
        let parameters = NWParameters.udp
        // The tunnel points the system proxy at its own listener; without
        // this its own dials would loop back into it.
        parameters.preferNoProxies = true
        let socket = NWConnection(host: NWEndpoint.Host(serverName), port: port, using: parameters)
        udp = socket
        socket.stateUpdateHandler = { [weak self] state in
            self?.socketStateChanged(state)
        }
        socket.start(queue: queue)
    }

    private func socketStateChanged(_ state: NWConnection.State) {
        switch state {
        case .ready:
            if handle == nil && !tornDown {
                startEngine()
            }
        case .waiting(let error):
            // Waiting means "not now" (no route, no network). Failing at once
            // lets the caller try the next server instead of sitting out the
            // whole timeout.
            fail(.connectFailed("UDP to \(serverName): \(error.localizedDescription)"))
        case .failed(let error):
            fail(.connectFailed("UDP to \(serverName): \(error.localizedDescription)"))
        case .cancelled:
            fail(.closed)
        default:
            break
        }
    }

    /// The address bytes of a resolved endpoint, or nil for a name.
    private static func addressBytes(_ host: NWEndpoint.Host) -> [UInt8]? {
        switch host {
        case .ipv4(let address):
            return [UInt8](address.rawValue)
        case .ipv6(let address):
            return [UInt8](address.rawValue)
        default:
            return nil
        }
    }

    /// The socket is connected and its addresses are known: the engine can be
    /// created, and its first write asks the TLS handler for the ClientHello.
    private func startEngine() {
        guard let socket = udp, let path = socket.currentPath,
              let remoteEndpoint = path.remoteEndpoint,
              case .hostPort(let remoteHost, let remotePort) = remoteEndpoint,
              let remote = QuicConnection.addressBytes(remoteHost) else {
            fail(.connectFailed("could not resolve \(serverName)"))
            return
        }
        // ngtcp2 only compares the path it is given on every read with the one
        // it was created with, so a placeholder serves when the system does
        // not say which local address it picked.
        var local = [UInt8](repeating: 0, count: remote.count)
        var localPort: UInt16 = 0
        if let localEndpoint = path.localEndpoint,
           case .hostPort(let localHost, let port) = localEndpoint,
           let bytes = QuicConnection.addressBytes(localHost), bytes.count == remote.count {
            local = bytes
            localPort = port.rawValue
        }

        var callbacks = cquic_callbacks()
        callbacks.user = Unmanaged.passUnretained(self).toOpaque()
        callbacks.crypto_data = { user, level, data, length in
            guard let user = user else { return -1 }
            let connection = Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue()
            let bytes = data.map { [UInt8](UnsafeBufferPointer(start: $0, count: length)) }
            return connection.onCryptoData(level: Int(level), data: bytes)
        }
        callbacks.stream_data = { user, streamId, data, length, fin in
            guard let user = user else { return -1 }
            let connection = Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue()
            let bytes = data.map { Data(bytes: $0, count: length) } ?? Data()
            connection.onStreamData(streamId, bytes, fin: fin != 0)
            return 0
        }
        callbacks.stream_close = { user, streamId, _ in
            guard let user = user else { return }
            Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue().onStreamClose(streamId)
        }
        callbacks.stream_reset = { user, streamId, code in
            guard let user = user else { return }
            Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue().onStreamReset(streamId, code: code)
        }
        callbacks.handshake_completed = { user in
            guard let user = user else { return }
            Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue().onHandshakeCompleted()
        }
        callbacks.datagram = { user, data, length in
            guard let user = user, let data = data else { return }
            let connection = Unmanaged<QuicConnection>.fromOpaque(user).takeUnretainedValue()
            connection.onDatagram(Data(bytes: data, count: length))
        }
        callbacks.log = { _, message in
            guard let message = message else { return }
            Log.debug("[QUIC] \(String(cString: message))")
        }

        var settings = tuning.nativeSettings
        let created: OpaquePointer? = remote.withUnsafeBufferPointer { remoteBuffer in
            local.withUnsafeBufferPointer { localBuffer in
                cquic_conn_new(remoteBuffer.baseAddress, remoteBuffer.count, remotePort.rawValue,
                               localBuffer.baseAddress, localBuffer.count, localPort,
                               &settings, &callbacks)
            }
        }
        guard let engine = created else {
            fail(.connectFailed("QUIC: ngtcp2 refused to create the connection"))
            return
        }
        handle = engine

        // The hello advertises what ngtcp2 was created with, connection id included.
        var parameters = [UInt8](repeating: 0, count: 1024)
        let length = parameters.withUnsafeMutableBufferPointer { buffer in
            cquic_conn_local_transport_params(engine, buffer.baseAddress, buffer.count)
        }
        if length > 0 {
            tls.localTransportParameters = Array(parameters[0..<Int(length)])
        }

        let source = DispatchSource.makeTimerSource(queue: queue)
        source.setEventHandler { [weak self] in
            self?.onTimer()
        }
        source.schedule(deadline: .distantFuture)
        source.resume()
        timer = source

        receiveNext()
        // The first flight goes out as soon as something asks ngtcp2 to write.
        flush()
    }

    private func receiveNext() {
        guard let socket = udp, !tornDown else { return }
        socket.receiveMessage { [weak self] content, _, _, error in
            guard let self = self, !self.tornDown else { return }
            if let content = content, !content.isEmpty {
                self.onPacket(content)
            }
            if let error = error {
                self.fail(.connectFailed("UDP from \(self.serverName): \(error.localizedDescription)"))
                return
            }
            self.receiveNext()
        }
    }

    /// One datagram from the server.
    private func onPacket(_ content: Data) {
        guard let handle = handle else { return }
        var packet = [UInt8](content)
        if let obfuscator = obfuscator {
            // An obfuscated datagram that does not open is not ours: noise on
            // the port, or a piece the obfuscator is still reassembling.
            guard let opened = obfuscator.open(packet) else { return }
            packet = opened
        }
        let result = packet.withUnsafeBufferPointer { buffer in
            cquic_conn_read(handle, buffer.baseAddress, buffer.count)
        }
        if result < 0 {
            fail(describeFailure(Int32(result)))
            return
        }
        startVerificationIfNeeded()
        wakeWriters()
        flush()
    }

    /// Runs ngtcp2's own timer: loss detection, pacing, keep-alive and the
    /// idle and handshake deadlines all hang off it, and missing it does not
    /// fail loudly — it just stops retransmitting.
    private func onTimer() {
        guard let handle = handle else { return }
        if cquic_conn_expiry_delay(handle) == 0 {
            let result = cquic_conn_handle_expiry(handle)
            if result < 0 {
                fail(describeFailure(result))
                return
            }
            wakeWriters()
        }
        flush()
    }

    private func armTimer() {
        guard let handle = handle, let timer = timer else { return }
        let delay = cquic_conn_expiry_delay(handle)
        let wait: Int64
        if delay < 0 {
            wait = QuicConnection.maxTimerWaitNanos
        } else {
            wait = min(max(delay, QuicConnection.minTimerWaitNanos), QuicConnection.maxTimerWaitNanos)
        }
        timer.schedule(deadline: .now() + .nanoseconds(Int(wait)), leeway: .microseconds(100))
    }

    // MARK: - Sending

    /// The datagrams one QUIC packet goes out as.
    private func sealed(_ packet: [UInt8]) -> [[UInt8]] {
        guard let obfuscator = obfuscator else { return [packet] }
        return obfuscator.seal(packet)
    }

    /// Puts the packet ngtcp2 just built (in the bridge's output buffer) on the wire.
    private func sendBuilt(_ length: Int64) {
        guard length > 0, let handle = handle, let socket = udp, let out = cquic_conn_out(handle) else { return }
        let packet = [UInt8](UnsafeBufferPointer(start: out, count: Int(length)))
        for piece in sealed(packet) {
            socket.send(content: Data(piece), completion: .idempotent)
        }
    }

    /// Drains everything ngtcp2 wants to send: queued datagrams first, then
    /// whatever else it has, then tells it the burst is over so it can pace
    /// the next one.
    private func flush() {
        guard let handle = handle else { return }
        let body = {
            self.drainDatagrams()
            var packets = 0
            while self.handle != nil {
                let length = cquic_conn_write(handle)
                if length < 0 {
                    if cquic_err_is_fatal(Int32(length)) != 0 {
                        self.fail(self.describeFailure(Int32(length)))
                    }
                    break
                }
                if length == 0 { break }
                self.sendBuilt(length)
                packets += 1
                // A bound, so one flush cannot hold the queue for ever.
                if packets >= 512 { break }
            }
        }
        if let socket = udp {
            socket.batch(body)
        } else {
            body()
        }
        if self.handle != nil {
            cquic_conn_flush_done(handle)
            armTimer()
        }
    }

    /// Hands queued datagrams to ngtcp2 while it has room, sending every
    /// packet it builds, including ones that came back without the datagram.
    private func drainDatagrams() {
        guard let handle = handle else { return }
        while !pendingDatagrams.isEmpty {
            // Stale ones go unsent: late audio is useless, and a datagram
            // ngtcp2 can never fit must not hold up the queue for good.
            let now = DispatchTime.now().uptimeNanoseconds
            while let first = pendingDatagrams.first, now &- first.queuedAt > QuicConnection.maxDatagramAgeNanos {
                pendingDatagrams.removeFirst()
            }
            guard let next = pendingDatagrams.first else { return }
            var status: Int32 = 0
            let length = next.data.withUnsafeBufferPointer { buffer in
                cquic_conn_write_datagram(handle, buffer.baseAddress, buffer.count, &status)
            }
            // Sent, or never sendable: either way it leaves the queue.
            if status != 0 { pendingDatagrams.removeFirst() }
            if status < 0 { Log.debug("[QUIC] datagram refused (\(String(cString: cquic_strerror(status))))") }
            if length > 0 {
                sendBuilt(length)
            } else if status == 0 {
                // No room yet: the next ACK read or pacing deadline flushes again.
                return
            }
        }
    }

    // MARK: - Streams

    /// Opens a bidirectional stream; nil when the peer's stream credit is
    /// spent or the connection is gone.
    func openStream() -> QuicStream? {
        return onEngine { openStreamOnQueue(unidirectional: false) }
    }

    /// Opens a unidirectional stream, which only this end may write to. HTTP/3
    /// needs one for its control stream, TUIC for its commands.
    func openUniStream() -> QuicStream? {
        return onEngine { openStreamOnQueue(unidirectional: true) }
    }

    private func openStreamOnQueue(unidirectional: Bool) -> QuicStream? {
        guard let handle = handle, !isClosed else { return nil }
        let id = unidirectional ? cquic_conn_open_uni_stream(handle) : cquic_conn_open_bidi_stream(handle)
        if id < 0 {
            Log.debug("[QUIC] no stream credit left (\(String(cString: cquic_strerror(Int32(truncatingIfNeeded: id)))))")
            return nil
        }
        let stream = QuicStream(id: id, connection: self, creditThreshold: max(1, tuning.initialMaxStreamDataBidiLocal / 2))
        streams[id] = stream
        return stream
    }

    /// What became of one offer of stream data.
    enum WriteResult: Equatable {
        /// Every byte (and the FIN, if asked) went out.
        case complete
        /// Bytes up to `offset` went out; nothing more fits until the
        /// generation moves on.
        case blocked(offset: Int, generation: UInt64)
        /// The stream or the connection is finished.
        case failed(code: Int64)
    }

    /// Offers `data[offset...]` to ngtcp2 and puts every packet it builds on
    /// the wire. ngtcp2 reports the packet and the accepted byte count as
    /// different numbers, and both are used: sending only the count would
    /// leave ngtcp2 waiting to have a packet acknowledged that never left.
    func writeStream(_ streamId: Int64, _ data: [UInt8], from offset: Int, fin: Bool) async -> WriteResult {
        return await withCheckedContinuation { (continuation: CheckedContinuation<WriteResult, Never>) in
            queue.async {
                continuation.resume(returning: self.writeStreamOnQueue(streamId, data, from: offset, fin: fin))
            }
        }
    }

    private func writeStreamOnQueue(_ streamId: Int64, _ data: [UInt8], from start: Int, fin: Bool) -> WriteResult {
        guard let handle = handle, !isClosed else { return .failed(code: -2) }
        var offset = start
        var result: WriteResult = .complete
        let body = {
            while true {
                let remaining = data.count - offset
                var accepted: Int64 = QuicConnection.writeAgain
                let length: Int64 = data.withUnsafeBufferPointer { buffer in
                    let base = remaining > 0 ? buffer.baseAddress.map { $0 + offset } : nil
                    return cquic_conn_write_stream(handle, streamId, base, remaining, fin ? 1 : 0, &accepted)
                }
                if length > 0 { self.sendBuilt(length) }
                if accepted < QuicConnection.writeAgain {
                    result = .failed(code: accepted)
                    return
                }
                if accepted == QuicConnection.writeAgain {
                    result = .blocked(offset: offset, generation: self.writeGeneration)
                    return
                }
                offset += Int(accepted)
                if offset >= data.count {
                    result = .complete
                    return
                }
            }
        }
        if let socket = udp {
            socket.batch(body)
        } else {
            body()
        }
        flush()
        return result
    }

    /// Waits until something may have opened room — an acknowledgement, a
    /// window update, a pacing deadline — or a few milliseconds, whichever
    /// is first. Returns at once when that already happened after
    /// `generation` was read.
    func waitWritable(after generation: UInt64) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                if self.writeGeneration != generation || self.tornDown {
                    continuation.resume()
                    return
                }
                self.nextWaiterId &+= 1
                let id = self.nextWaiterId
                self.writeWaiters[id] = continuation
                self.queue.asyncAfter(deadline: .now() + .milliseconds(QuicConnection.writeRetryMilliseconds)) {
                    self.writeWaiters.removeValue(forKey: id)?.resume()
                }
            }
        }
    }

    private func wakeWriters() {
        writeGeneration &+= 1
        if writeWaiters.isEmpty { return }
        let waiting = writeWaiters
        writeWaiters.removeAll()
        for continuation in waiting.values {
            continuation.resume()
        }
    }

    /// Resets a stream in both directions and hands back the receive credit
    /// it still held, so the connection-level window does not leak while
    /// other streams live on.
    func shutdownStream(_ streamId: Int64, returningCredit credit: Int64) {
        queue.async {
            self.streams.removeValue(forKey: streamId)
            guard let handle = self.handle else { return }
            if credit > 0 {
                cquic_conn_extend_offsets(handle, streamId, UInt64(credit))
            }
            cquic_conn_shutdown_stream(handle, streamId, 0)
            self.flush()
        }
    }

    /// Reports consumed bytes so the peer reopens the window.
    ///
    /// Skipping this stalls a transfer partway through with nothing logged:
    /// the peer is simply not allowed to send more. `wake` sends the
    /// MAX_STREAM_DATA / MAX_DATA frames now rather than on the next read or
    /// timer; it must be false from inside a callback, where ngtcp2 may not
    /// be asked to write.
    func extendOffsets(_ streamId: Int64, _ count: Int64, wake: Bool) {
        if count <= 0 { return }
        if onQueue && !wake {
            if let handle = handle {
                cquic_conn_extend_offsets(handle, streamId, UInt64(count))
            }
            return
        }
        queue.async {
            guard let handle = self.handle else { return }
            cquic_conn_extend_offsets(handle, streamId, UInt64(count))
            if wake { self.flush() }
        }
    }

    // MARK: - Datagrams

    /// Sends one unreliable datagram, now or as soon as the congestion window
    /// and pacing allow. False only when the connection is gone; nothing
    /// retransmits a datagram, so that is all the failure handling there is.
    @discardableResult
    func sendDatagram(_ data: [UInt8]) -> Bool {
        if isClosed { return false }
        queue.async {
            guard self.handle != nil else { return }
            // Full: the oldest goes. For a call, a fresh packet is worth more.
            if self.pendingDatagrams.count >= QuicConnection.maxPendingDatagrams {
                self.pendingDatagrams.removeFirst()
            }
            self.pendingDatagrams.append((data: data, queuedAt: DispatchTime.now().uptimeNanoseconds))
            self.flush()
        }
        return true
    }

    /// The largest datagram that goes out as one packet right now, or 0 when
    /// not yet known. Protocols that split UDP payloads split above this.
    func maxDatagramPayload() -> Int {
        return onEngine {
            guard let handle = handle else { return 0 }
            return Int(cquic_conn_max_datagram_payload(handle))
        }
    }

    // MARK: - Callbacks from ngtcp2, on the queue, inside a bridge call

    private func onCryptoData(level: Int, data: [UInt8]?) -> Int32 {
        guard let handle = handle else { return -1 }
        guard let data = data else {
            guard let hello = tls.buildClientHello() else { return -1 }
            let result = hello.withUnsafeBufferPointer { buffer in
                cquic_conn_submit_crypto(handle, Int32(QuicTlsHandler.levelInitial), buffer.baseAddress, buffer.count)
            }
            return result == 0 ? 0 : -1
        }
        if tls.processCryptoData(data, sink: self) == .failed {
            fail(.tls(tls.failure ?? "QUIC handshake failed"))
            return -1
        }
        return 0
    }

    private func onStreamData(_ streamId: Int64, _ data: Data, fin: Bool) {
        guard let stream = streams[streamId] else {
            // A stream this end never opened (the server's HTTP/3 control
            // stream, say). Nobody reads it, so the credit it consumed is
            // handed straight back; otherwise every byte on it shrinks the
            // connection window for good.
            extendOffsets(streamId, Int64(data.count), wake: false)
            return
        }
        // The credit comes back when the app reads the bytes, not here: see
        // QuicStream. Crediting on arrival let a fast server fill the memory.
        if !data.isEmpty { stream.onData(data) }
        if fin { stream.onPeerFinished() }
    }

    private func onStreamClose(_ streamId: Int64) {
        streams.removeValue(forKey: streamId)?.onTransportClosed()
    }

    private func onStreamReset(_ streamId: Int64, code: UInt64) {
        streams.removeValue(forKey: streamId)?.onPeerReset(code)
    }

    /// Handed to whoever registered for datagrams; dropped when nobody has.
    private func onDatagram(_ data: Data) {
        datagramHandler?(data)
    }

    private func onHandshakeCompleted() {
        lock.lock()
        let continuation = handshakeContinuation
        handshakeContinuation = nil
        if state == .connecting { state = .established }
        lock.unlock()
        Log.debug("[QUIC] handshake complete with \(serverName)")
        continuation?.resume()
    }

    /// The certificate check runs on the system's trust evaluation, which is
    /// asynchronous; the handshake waits for it with nothing installed for
    /// 1-RTT, then resumes on the queue.
    private func startVerificationIfNeeded() {
        guard tls.phase == .verifying, !verificationStarted, let request = tls.pendingVerification else { return }
        verificationStarted = true
        Task {
            var outcome: Error?
            do {
                try await TlsPeerVerifier.verifyServer(
                    certificates: request.certificates,
                    serverName: request.serverName,
                    pins: request.pins,
                    signedTranscriptHash: request.signedTranscriptHash,
                    scheme: request.scheme,
                    signature: request.signature
                )
            } catch {
                outcome = error
            }
            self.queue.async {
                self.finishVerification(outcome)
            }
        }
    }

    private func finishVerification(_ error: Error?) {
        guard handle != nil, !tornDown else { return }
        if tls.completeVerification(error, sink: self) == .failed {
            fail(.tls(tls.failure ?? "certificate check failed"))
            return
        }
        flush()
    }

    /// Why ngtcp2 gave up, in the words a user can act on: the server's own
    /// CONNECTION_CLOSE when it sent one, the TLS failure when ours was the
    /// reason, the deadline when there was nothing at all.
    private func describeFailure(_ code: Int32) -> MythaiaError {
        if tls.phase == .failed, let reason = tls.failure {
            return .tls(reason)
        }
        if let handle = handle {
            var errorCode: UInt64 = 0
            let kind = cquic_conn_close_error(handle, &errorCode)
            switch kind {
            case CQUIC_CLOSE_TRANSPORT:
                if errorCode >= 0x100 && errorCode <= 0x1FF {
                    let alert = TLSAlert.describe(level: 2, description: Int(errorCode - 0x100))
                    return .tls("server refused the handshake: \(alert)")
                }
                return .connectFailed("server closed the QUIC connection (error 0x\(String(errorCode, radix: 16)))")
            case CQUIC_CLOSE_APPLICATION:
                return .connectFailed("server closed the QUIC connection (application error 0x\(String(errorCode, radix: 16)))")
            case CQUIC_CLOSE_VERSION_NEGOTIATION:
                return .connectFailed("server does not speak QUIC version 1")
            case CQUIC_CLOSE_IDLE:
                return .closed
            default:
                break
            }
        }
        switch cquic_error_kind(code) {
        case CQUIC_ERROR_HANDSHAKE_TIMEOUT:
            return .timeout("QUIC handshake with \(serverName)")
        case CQUIC_ERROR_IDLE_CLOSE, CQUIC_ERROR_CLOSING, CQUIC_ERROR_DRAINING:
            return .closed
        default:
            return .connectFailed("QUIC: \(String(cString: cquic_strerror(code)))")
        }
    }
}

/// The TLS handler's requests, answered through the bridge. Only ever called
/// from inside `processCryptoData` or `completeVerification`, on the queue.
extension QuicConnection: QuicHandshakeSink {
    func setCipherSuite(_ suite: Int) -> Int32 {
        guard let handle = handle else { return -1 }
        return cquic_conn_set_cipher_suite(handle, Int32(suite))
    }

    func installKeys(level: Int, rx: [UInt8], tx: [UInt8]) -> Int32 {
        guard let handle = handle else { return -1 }
        return rx.withUnsafeBufferPointer { rxBuffer in
            tx.withUnsafeBufferPointer { txBuffer in
                cquic_conn_install_keys(handle, Int32(level), rxBuffer.baseAddress, rxBuffer.count,
                                        txBuffer.baseAddress, txBuffer.count)
            }
        }
    }

    func setRemoteTransportParameters(_ raw: [UInt8]) -> Int32 {
        guard let handle = handle else { return -1 }
        return raw.withUnsafeBufferPointer { buffer in
            cquic_conn_set_remote_params(handle, buffer.baseAddress, buffer.count)
        }
    }

    func submitCrypto(level: Int, data: [UInt8]) -> Int32 {
        guard let handle = handle else { return -1 }
        return data.withUnsafeBufferPointer { buffer in
            cquic_conn_submit_crypto(handle, Int32(level), buffer.baseAddress, buffer.count)
        }
    }

    func handshakeCompleted() {
        guard let handle = handle else { return }
        cquic_conn_handshake_completed(handle)
    }
}

/// The C side's own check, for the tests: RFC 9001 Appendix A through the
/// vendored ngtcp2 and its mbedTLS backend. Nil when every step matched.
enum QuicNativeSelfTest {
    static func run() -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        let result = buffer.withUnsafeMutableBufferPointer { pointer in
            cquic_self_test(pointer.baseAddress, pointer.count)
        }
        if result == 0 { return nil }
        return String(cString: buffer)
    }

    static var ngtcp2Version: String {
        return String(cString: cquic_version())
    }
}
