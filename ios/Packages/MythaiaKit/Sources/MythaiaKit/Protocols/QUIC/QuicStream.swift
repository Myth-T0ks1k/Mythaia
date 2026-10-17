import Foundation

/// One QUIC stream, presented as an ordinary byte stream.
///
/// A stream owns no socket — several share the connection underneath — so
/// closing one leaves the rest running, which is the whole reason to
/// multiplex.
///
/// Receive-side flow control is deferred to consume time: `buffered` is what
/// arrived but has not been read, `owedCredit` what has been read but not yet
/// credited back to the peer. The peer's window only reopens as the reader
/// reads, so a fast server cannot fill memory faster than the tunnel drains —
/// the failure crediting on arrival caused. When the stream ends abnormally
/// both counts are handed back, so the connection-level window does not leak.
final class QuicStream: ByteStream, @unchecked Sendable {
    let streamId: Int64
    private let connection: QuicConnection
    /// How much is read before the credit goes back: half the stream window,
    /// so ngtcp2 sends a MAX_STREAM_DATA per batch rather than per chunk.
    private let creditThreshold: Int64

    private let lock = NSLock()
    private var chunks: [Data] = []
    private var waiter: CheckedContinuation<Data?, Error>?
    /// No more data will arrive; what is queued is still readable.
    private var ended = false
    /// The stream is gone on the transport: reads drain what is queued but
    /// credit nothing more, since it was all handed back already.
    private var detached = false
    /// Closed by this end.
    private var cancelled = false
    /// Why the stream failed: a peer reset, or the connection going away.
    private var failure: MythaiaError?
    private var buffered: Int64 = 0
    private var owedCredit: Int64 = 0

    init(id: Int64, connection: QuicConnection, creditThreshold: Int64) {
        self.streamId = id
        self.connection = connection
        self.creditThreshold = max(1, creditThreshold)
    }

    // MARK: - ByteStream

    /// Writes all of `data`. ngtcp2 accepts as much as flow control and
    /// congestion allow and no more, so a partial accept is ordinary; what is
    /// left waits for the window to open. A terminal answer — the stream does
    /// not exist, is shut for writing, or the connection is closing — fails
    /// the write rather than spinning.
    func send(_ data: Data) async throws {
        // Nothing to frame: ngtcp2 would build no STREAM frame and report
        // "nothing fit" for ever.
        if data.isEmpty {
            try checkWritable()
            return
        }
        try await write([UInt8](data), fin: false)
    }

    /// Ends this side of the stream without abandoning it: a request that has
    /// sent its whole body says so with a FIN, and the response still comes
    /// back afterwards. The FIN is offered until ngtcp2 has room for it — a
    /// FIN dropped on a full congestion window is never resent on its own.
    func finish() async throws {
        try await write([], fin: true)
    }

    private func write(_ bytes: [UInt8], fin: Bool) async throws {
        var offset = 0
        while true {
            try checkWritable()
            try Task.checkCancellation()
            let result = await connection.writeStream(streamId, bytes, from: offset, fin: fin)
            switch result {
            case .complete:
                return
            case .blocked(let reached, let generation):
                // Nothing (more) fit this time — congestion, pacing, a full
                // packet or a blocked window.
                offset = reached
                await connection.waitWritable(after: generation)
            case .failed(let code):
                try checkWritable()
                throw MythaiaError.connectFailed("QUIC stream \(streamId) write failed (\(code))")
            }
        }
    }

    private func checkWritable() throws {
        lock.lock()
        defer { lock.unlock() }
        if cancelled { throw MythaiaError.closed }
        if let failure = failure { throw failure }
    }

    /// The next chunk, or nil once the stream ended *and* was drained. Not
    /// gated on the end alone: a peer usually delivers the last data and the
    /// FIN together, and refusing to read after the FIN would throw away the
    /// tail of every response. Reading is what reopens the peer's window.
    func receive() async throws -> Data? {
        let chunk: Data? = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
                lock.lock()
                if !chunks.isEmpty {
                    let next = chunks.removeFirst()
                    buffered -= Int64(next.count)
                    lock.unlock()
                    continuation.resume(returning: next)
                    return
                }
                if cancelled {
                    lock.unlock()
                    continuation.resume(throwing: MythaiaError.closed)
                    return
                }
                if let failure = failure {
                    lock.unlock()
                    continuation.resume(throwing: failure)
                    return
                }
                if ended {
                    lock.unlock()
                    continuation.resume(returning: nil)
                    return
                }
                if waiter != nil {
                    lock.unlock()
                    continuation.resume(throwing: MythaiaError.protocolError("two reads at once on one QUIC stream"))
                    return
                }
                waiter = continuation
                lock.unlock()
            }
        } onCancel: {
            self.close()
        }
        if let chunk = chunk {
            creditConsumed(Int64(chunk.count))
        }
        return chunk
    }

    /// Abandons the stream in both directions. The window for anything
    /// buffered but never read goes back to the connection.
    func close() {
        lock.lock()
        if cancelled {
            lock.unlock()
            return
        }
        cancelled = true
        ended = true
        let credit = detached ? 0 : owedCredit + buffered
        owedCredit = 0
        buffered = 0
        chunks.removeAll()
        let pending = waiter
        waiter = nil
        lock.unlock()
        pending?.resume(throwing: MythaiaError.closed)
        connection.shutdownStream(streamId, returningCredit: credit)
    }

    // MARK: - From the connection, on its queue

    func onData(_ data: Data) {
        lock.lock()
        if ended || cancelled || failure != nil {
            lock.unlock()
            // Nothing will read it, so the window goes straight back.
            connection.extendOffsets(streamId, Int64(data.count), wake: false)
            return
        }
        if let pending = waiter {
            waiter = nil
            lock.unlock()
            pending.resume(returning: data)
            return
        }
        chunks.append(data)
        buffered += Int64(data.count)
        lock.unlock()
    }

    /// A clean FIN: no more data, but what is queued stays readable.
    func onPeerFinished() {
        lock.lock()
        if ended {
            lock.unlock()
            return
        }
        ended = true
        let pending = chunks.isEmpty ? waiter : nil
        if pending != nil { waiter = nil }
        lock.unlock()
        pending?.resume(returning: nil)
    }

    /// The transport closed the stream (both sides shut). Like a FIN, and the
    /// credit for what is still buffered goes back now: the stream id is gone,
    /// so reading it later would credit nothing.
    func onTransportClosed() {
        lock.lock()
        let credit = detached ? 0 : owedCredit + buffered
        detached = true
        owedCredit = 0
        let pending = (!ended && chunks.isEmpty) ? waiter : nil
        if pending != nil { waiter = nil }
        ended = true
        lock.unlock()
        connection.extendOffsets(streamId, credit, wake: false)
        pending?.resume(returning: nil)
    }

    /// The peer sent RESET_STREAM. The receive ends in an error rather than a
    /// clean nil, so the reader can tell a refused flow from a finished one.
    func onPeerReset(_ code: UInt64) {
        lock.lock()
        if failure != nil || cancelled {
            lock.unlock()
            return
        }
        let error = MythaiaError.protocolError("QUIC stream reset by the server (error \(code))")
        failure = error
        ended = true
        let credit = detached ? 0 : owedCredit + buffered
        detached = true
        owedCredit = 0
        buffered = 0
        chunks.removeAll()
        let pending = waiter
        waiter = nil
        lock.unlock()
        connection.extendOffsets(streamId, credit, wake: false)
        pending?.resume(throwing: error)
    }

    /// The whole connection went away. A stream the peer had already
    /// finished keeps its clean end; anything else fails.
    func onConnectionClosed(_ error: MythaiaError) {
        lock.lock()
        if failure == nil && !cancelled && !ended { failure = error }
        detached = true
        ended = true
        let pending = chunks.isEmpty ? waiter : nil
        if pending != nil { waiter = nil }
        lock.unlock()
        pending?.resume(throwing: error)
    }

    /// Credits consumed bytes, in batches: a MAX_STREAM_DATA per chunk would
    /// be a frame per read.
    private func creditConsumed(_ count: Int64) {
        lock.lock()
        if detached || cancelled {
            lock.unlock()
            return
        }
        owedCredit += count
        var flush: Int64 = 0
        if owedCredit >= creditThreshold {
            flush = owedCredit
            owedCredit = 0
        }
        lock.unlock()
        if flush > 0 {
            connection.extendOffsets(streamId, flush, wake: true)
        }
    }
}
