import Foundation

/// One multiplexed stream, presented as an ordinary byte stream.
///
/// Everything a caller sends becomes `cmdPSH` frames on the session;
/// everything the session routes here arrives through a channel. The stream
/// owns no connection of its own, which is the whole point — several of these
/// share one TLS connection, and closing one leaves the rest running.
final class AnyTlsStream: ByteStream, @unchecked Sendable {
    /// Unread bytes one stream may hold before the session stops reading for it.
    static let inboundBudget = 1024 * 1024

    let streamId: UInt32
    /// Held strongly: a session nothing pools lives as long as its streams.
    private let session: AnyTlsSession
    private let incoming = TransportChannel<Data>()

    private let lock = NSLock()
    /// Bytes queued in `incoming` and not yet read. The channel itself is
    /// unbounded, so this is what bounds it: past the budget the session's
    /// read loop waits in `onData` until the reader drains some. That is the
    /// backpressure — the loop stops reading the TLS connection, its TCP
    /// window fills, and the server slows down — that the reference gets from
    /// its blocking pipe. Without it a slow reader had the whole response
    /// accumulate in memory.
    private var buffered = 0
    /// Completed when the reader has drained below budget; nil while under it.
    private var drained: TransportDeferred<Void>?
    /// No more data will arrive; queued data is still readable.
    private var ended = false
    /// This side gave up on the stream.
    private var cancelled = false

    init(streamId: UInt32, session: AnyTlsSession) {
        self.streamId = streamId
        self.session = session
    }

    func send(_ data: Data) async throws {
        if isCancelled { throw MythaiaError.closed }
        if data.isEmpty { return }
        try await session.sendStreamData(streamId, [UInt8](data))
    }

    /// The next chunk, or nil once the stream has ended *and* been drained.
    ///
    /// Not gated on the ended flag: a server that finishes a response and
    /// closes usually delivers the last data frame and the FIN in one read,
    /// so refusing to read after the FIN would throw away the tail of every
    /// response. Closing the channel marks the end, and a closed channel
    /// still yields what is already in it.
    func receive() async throws -> Data? {
        guard let data = try await incoming.receive() else { return nil }
        consumed(data.count)
        return data
    }

    /// Gives up on this stream from our side. The FIN goes out without
    /// waiting for it, so a caller closing many flows is not held up by the
    /// uplink.
    func close() {
        lock.lock()
        if cancelled {
            lock.unlock()
            return
        }
        cancelled = true
        ended = true
        lock.unlock()
        incoming.close()
        // A session loop waiting on this stream must not stay waiting for a
        // reader that is gone.
        openGate()
        session.closeStreamAsync(streamId)
    }

    private var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    private func consumed(_ count: Int) {
        lock.lock()
        buffered -= count
        let below = buffered <= AnyTlsStream.inboundBudget
        lock.unlock()
        if below {
            openGate()
        }
    }

    /// Data the session routed to this stream. Waits — holding up the
    /// session's read loop, so every stream on the session — while this
    /// stream holds more than the budget of unread bytes.
    func onData(_ data: Data) async {
        lock.lock()
        if ended {
            lock.unlock()
            return
        }
        buffered += data.count
        lock.unlock()
        incoming.trySend(data)

        while true {
            guard let gate = gateToWaitOn() else { return }
            _ = try? await gate.wait()
        }
    }

    /// The gate to wait on while over budget, or nil when there is nothing
    /// to wait for. Published and re-checked under one lock, so a drain that
    /// lands meanwhile cannot leave the loop waiting on a gate nobody opens.
    private func gateToWaitOn() -> TransportDeferred<Void>? {
        lock.lock()
        defer { lock.unlock() }
        if buffered <= AnyTlsStream.inboundBudget || ended {
            return nil
        }
        if let existing = drained {
            return existing
        }
        let gate = TransportDeferred<Void>()
        drained = gate
        return gate
    }

    /// Wakes a session loop waiting in `onData`, if one is.
    private func openGate() {
        lock.lock()
        let gate = drained
        drained = nil
        lock.unlock()
        gate?.complete(())
    }

    /// The peer sent FIN or refused the stream, or the session went away.
    /// The channel is closed rather than emptied, so a reader still drains
    /// what arrived before the end; `error`, when given, is what it then sees.
    func onPeerClosed(_ error: Error? = nil) {
        lock.lock()
        if ended {
            lock.unlock()
            return
        }
        ended = true
        lock.unlock()
        incoming.close(error)
        openGate()
    }
}
