import Foundation

/// One stream of an Http2Session: a CONNECT tunnel (openTunnel) or an
/// ordinary request (openRequest) such as gRPC's. As a ByteStream, send
/// writes DATA and receive returns the response body.
/// Lifecycle: idle, then tunnelPending (waiting for the response) or
/// tunnelOpen, then closed.
final class Http2Stream: ByteStream, @unchecked Sendable {
    enum State {
        case idle
        case tunnelPending
        case tunnelOpen
        case closed
    }

    private let session: Http2Session
    let destination: String
    let flowControl: Http2StreamFlowControl

    private let lock = NSLock()
    /// Given when the stream's HEADERS are written, not when it is handed
    /// out: ids must reach the server in increasing order (RFC 9113 §5.1.1),
    /// and streams handed out together can open in any order. 0 until then.
    private var id = 0
    private var state: State = .idle
    private var receivedTrailers: [HpackHeader]?
    private var receivedResponse: [HpackHeader]?
    private var responseSeen = false

    private let dataChannel = TransportChannel<Data>()

    /// One send at a time: two concurrent senders used to interleave their
    /// DATA frames chunk by chunk, which is corrupt payload to the other side.
    private let sendMutex = TransportAsyncMutex()

    private let tunnelReady = TransportDeferred<Void>()

    init(session: Http2Session, destination: String, initialSendWindow: Int, receiveWindow: Int) {
        self.session = session
        self.destination = destination
        self.flowControl = Http2StreamFlowControl(initialSendWindow: initialSendWindow, recvWindowSize: receiveWindow)
    }

    var streamID: Int {
        lock.lock()
        defer { lock.unlock() }
        return id
    }

    func assignId(_ newID: Int) {
        lock.lock()
        id = newID
        lock.unlock()
    }

    var isConnected: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state == .tunnelOpen
    }

    /// The trailing headers (gRPC's grpc-status), once the server sent them.
    var trailers: [HpackHeader]? {
        lock.lock()
        defer { lock.unlock() }
        return receivedTrailers
    }

    /// The response headers, `:status` among them, once they arrived.
    var responseHeaders: [HpackHeader]? {
        lock.lock()
        defer { lock.unlock() }
        return receivedResponse
    }

    private var currentState: State {
        lock.lock()
        defer { lock.unlock() }
        return state
    }

    private func beginOpening(_ next: State, what: String) throws {
        lock.lock()
        defer { lock.unlock() }
        if state != .idle {
            throw Http2Error.protocolError("Stream \(id): invalid state for \(what)")
        }
        state = next
    }

    /// Opens the stream as a CONNECT tunnel with `headerBlock` (built with
    /// HpackEncoder.encodeConnectRequest) and waits for the 200.
    func openTunnel(headerBlock: Data) async throws {
        try beginOpening(.tunnelPending, what: "openTunnel")
        do {
            try await session.sendRequestHeaders(self, headerBlock: headerBlock, endStream: false)
            try await tunnelReady.wait()
        } catch {
            abandon()
            throw error
        }
    }

    /// Opens the stream as an ordinary request: sends `headerBlock` (HPACK),
    /// with `endStream` for a request without a body. Unless `awaitResponse`,
    /// the body may follow at once, as gRPC clients send their first message
    /// without waiting for the response headers; those are checked when they
    /// arrive, and a refusal ends the stream (the reader sees the failure).
    func openRequest(_ headerBlock: Data, endStream: Bool = false, awaitResponse: Bool = false) async throws {
        try beginOpening(awaitResponse ? .tunnelPending : .tunnelOpen, what: "openRequest")
        do {
            try await session.sendRequestHeaders(self, headerBlock: headerBlock, endStream: endStream)
            if awaitResponse {
                try await tunnelReady.wait()
            }
        } catch {
            abandon()
            throw error
        }
    }

    /// An open that failed or was given up on: the stream is over, the
    /// server is told so when it had heard of it, and its place is released.
    private func abandon() {
        lock.lock()
        let wasLive = state == .tunnelPending || state == .tunnelOpen
        state = .closed
        let streamID = id
        lock.unlock()
        dataChannel.close()
        discardBuffered()
        flowControl.cancelAwaiters(Http2Error.connectionFailed("Stream closed"))
        tunnelReady.fail(Http2Error.connectionFailed("Stream closed"))
        if wasLive && streamID != 0 {
            session.sendReset(streamID: streamID, errorCode: Http2Framer.ErrorCode.cancel)
        }
        release()
    }

    func sendData(_ data: Data) async throws {
        if currentState != .tunnelOpen { throw Http2Error.notReady }
        await sendMutex.acquire()
        defer { sendMutex.release() }
        try await session.sendData(self, data)
    }

    /// Sends `data` and ends this side of the stream (an upload's last piece).
    func sendLastData(_ data: Data) async throws {
        if currentState != .tunnelOpen { throw Http2Error.notReady }
        await sendMutex.acquire()
        defer { sendMutex.release() }
        try await session.sendData(self, data, endStream: true)
    }

    /// The next piece of the response body; nil at the server's END_STREAM.
    ///
    /// Drains before reporting the end: END_STREAM closes the channel the
    /// moment it arrives, usually while DATA ahead of it is still buffered,
    /// and returning nil on the closed state alone threw that tail away. A
    /// reset, GOAWAY or connection error fails the channel, and the reader
    /// sees that error: as a plain nil it was indistinguishable from
    /// END_STREAM, and a download cut off midway looked complete.
    func receiveData() async throws -> Data? {
        guard let data = try await dataChannel.receive() else { return nil }
        if !data.isEmpty {
            // WINDOW_UPDATE at read time, so back-pressure reaches the server.
            session.acknowledgeConsumedData(streamID: streamID, bytes: data.count)
        }
        return data
    }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await sendData(data)
    }

    func receive() async throws -> Data? {
        try await receiveData()
    }

    /// Ends the stream from this side: RST_STREAM(CANCEL) so the server
    /// reclaims the slot when the stream was still live.
    func close() {
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        let prior = state
        state = .closed
        let streamID = id
        lock.unlock()
        dataChannel.close()
        discardBuffered()
        flowControl.cancelAwaiters(Http2Error.connectionFailed("Stream closed"))
        tunnelReady.fail(Http2Error.connectionFailed("Stream closed"))
        if (prior == .tunnelPending || prior == .tunnelOpen) && streamID != 0 {
            session.sendReset(streamID: streamID, errorCode: Http2Framer.ErrorCode.cancel)
        }
        release()
    }

    /// Gives the stream's place back: its slot if it never opened, its id otherwise.
    private func release() {
        let streamID = self.streamID
        if streamID == 0 {
            session.releaseReservation()
        } else {
            session.removeStream(streamID)
        }
    }

    /// Drops what the application never read and gives the server its
    /// connection window back for it (RFC 9113 §6.9): the window is otherwise
    /// only credited as the application reads, so bytes left behind by a
    /// stream that ended early were lost from the shared connection's window
    /// for good.
    private func discardBuffered() {
        var bytes = 0
        while let chunk = dataChannel.tryReceive() {
            bytes += chunk.count
        }
        if bytes > 0 {
            session.creditConnection(bytes)
        }
    }

    /// Completes the open on a 200 response and fails it on any other
    /// status. A second header block, without `:status`, is the trailers.
    func deliverHeaders(_ headers: [HpackHeader]) {
        let status = headers.first { $0.name == ":status" }
        lock.lock()
        guard let statusHeader = status else {
            if responseSeen {
                receivedTrailers = headers
                lock.unlock()
                return
            }
            let streamID = id
            lock.unlock()
            fail(Http2Error.protocolError("Stream \(streamID): missing :status"))
            return
        }
        responseSeen = true
        receivedResponse = headers
        // gRPC's Trailers-Only response (a call refused before any message):
        // `:status 200` and grpc-status in one block, END_STREAM on it. Kept
        // as the trailers too, or the reader took the refusal for a clean end.
        if headers.contains(where: { $0.name == "grpc-status" }) {
            receivedTrailers = headers
        }
        switch statusHeader.value {
        case "200":
            if state == .tunnelPending { state = .tunnelOpen }
            lock.unlock()
            tunnelReady.complete(())
        case "407":
            lock.unlock()
            fail(Http2Error.authenticationRequired)
        default:
            lock.unlock()
            fail(Http2Error.tunnelFailed(statusHeader.value))
        }
    }

    /// A refused request: closes the stream, so a request that did not wait
    /// for the answer ends too.
    private func fail(_ error: Http2Error) {
        lock.lock()
        state = .closed
        lock.unlock()
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)
        tunnelReady.fail(error)
    }

    func deliverData(_ data: Data) {
        let closed = currentState == .closed
        if closed || !dataChannel.trySend(data) {
            // Nobody will read it, but the server spent connection window on
            // it: give that back, or the shared connection runs dry (§6.9).
            session.creditConnection(data.count)
        }
    }

    func deliverWindowUpdate(_ increment: Int) {
        flowControl.applyWindowUpdate(increment)
    }

    func deliverReset() {
        endWithError(Http2Error.streamReset(streamID))
    }

    /// The server's END_STREAM: a clean half-close. What is buffered can
    /// still be read, then the reader sees the end.
    func deliverEndStream() {
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        state = .closed
        lock.unlock()
        dataChannel.close()
        flowControl.cancelAwaiters(Http2Error.connectionFailed("Stream END_STREAM"))
        tunnelReady.fail(Http2Error.connectionFailed("Stream ended before its response"))
    }

    /// GOAWAY named a lower last stream id: the server never processed this
    /// stream. It ends with goaway, never a clean end, so the caller knows to
    /// try again on a new connection.
    func deliverGoaway() {
        endWithError(Http2Error.goaway)
    }

    func deliverError(_ error: Error) {
        endWithError(error)
    }

    private func endWithError(_ error: Error) {
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        state = .closed
        lock.unlock()
        dataChannel.close(error)
        discardBuffered()
        flowControl.cancelAwaiters(error)
        tunnelReady.fail(error)
    }

    /// RFC 9113 §6.9.2: moves the send window when SETTINGS_INITIAL_WINDOW_SIZE changes.
    func adjustSendWindow(_ delta: Int) {
        flowControl.adjustSendWindow(delta)
    }
}
