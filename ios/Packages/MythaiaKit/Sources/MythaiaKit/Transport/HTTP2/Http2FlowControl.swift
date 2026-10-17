import Foundation

/// One stream's flow control: what this side may still send on it, and when
/// what it received earns the server a WINDOW_UPDATE (at half the receive
/// window).
final class Http2StreamFlowControl: @unchecked Sendable {
    private let lock = NSLock()
    private var currentSendWindow: Int
    private var recvConsumed = 0
    private let recvWindowSize: Int
    private var windowAwaiter: TransportDeferred<Void>?

    /// Set once the stream is over: a sender arriving after that must not
    /// wait for a window that will never open.
    private var cancelledWith: Error?

    init(initialSendWindow: Int = Http2FlowControl.defaultInitialWindowSize,
         recvWindowSize: Int = Http2FlowControl.naiveInitialWindowSize) {
        self.currentSendWindow = initialSendWindow
        self.recvWindowSize = recvWindowSize
    }

    var sendWindow: Int {
        lock.lock()
        defer { lock.unlock() }
        return currentSendWindow
    }

    /// The window a stream opens with: the server's SETTINGS_INITIAL_WINDOW_SIZE
    /// at the moment its HEADERS go out.
    func setInitialSendWindow(_ value: Int) {
        lock.lock()
        currentSendWindow = value
        lock.unlock()
    }

    /// Under the lock: the window is credited under it by WINDOW_UPDATE and
    /// SETTINGS from the read loop while a sender spends it, and an unlocked
    /// decrement could over-send past the peer's window or lose a credit.
    func consumeSend(_ bytes: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if currentSendWindow < bytes { return false }
        currentSendWindow -= bytes
        return true
    }

    func applyWindowUpdate(_ increment: Int) {
        lock.lock()
        currentSendWindow += increment
        let awaiter = windowAwaiter
        windowAwaiter = nil
        lock.unlock()
        awaiter?.complete(())
    }

    /// Waits until the send window opens (WINDOW_UPDATE arrives) or the
    /// stream ends.
    func awaitWindow() async throws {
        guard let awaiter = try currentAwaiter() else { return }
        try await awaiter.wait()
    }

    private func currentAwaiter() throws -> TransportDeferred<Void>? {
        lock.lock()
        defer { lock.unlock() }
        if let error = cancelledWith { throw error }
        if currentSendWindow > 0 { return nil }
        if let existing = windowAwaiter { return existing }
        let created = TransportDeferred<Void>()
        windowAwaiter = created
        return created
    }

    /// Wakes any sender waiting in awaitWindow with `error`, and fails any
    /// that come later.
    func cancelAwaiters(_ error: Error) {
        lock.lock()
        if cancelledWith == nil { cancelledWith = error }
        let awaiter = windowAwaiter
        windowAwaiter = nil
        lock.unlock()
        awaiter?.fail(error)
    }

    /// RFC 9113 §6.9.2: shifts the send window by `delta` when
    /// SETTINGS_INITIAL_WINDOW_SIZE changes.
    func adjustSendWindow(_ delta: Int) {
        lock.lock()
        currentSendWindow += delta
        var awaiter: TransportDeferred<Void>?
        if currentSendWindow > 0 {
            awaiter = windowAwaiter
            windowAwaiter = nil
        }
        lock.unlock()
        awaiter?.complete(())
    }

    /// The WINDOW_UPDATE increment once half the receive window has been
    /// consumed; nil until then.
    func consumeRecv(_ bytes: Int) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        recvConsumed += bytes
        if recvConsumed >= recvWindowSize / 2 {
            let increment = recvConsumed
            recvConsumed = 0
            return increment
        }
        return nil
    }
}

/// Connection and stream flow control for a connection that carries a single
/// stream. Window sizing follows NaiveProxy's BDP calculation: 64 MB stream
/// window, 128 MB connection window.
final class Http2FlowControl: @unchecked Sendable {
    /// RFC 9113 §6.9.2 default.
    static let defaultInitialWindowSize = 65_535

    static let naiveInitialWindowSize = 67_108_864
    static let naiveSessionMaxRecvWindow = 134_217_728

    /// Increment for the post-SETTINGS WINDOW_UPDATE on stream 0 (raises 65,535 to 128 MB).
    static let connectionWindowUpdateIncrement = naiveSessionMaxRecvWindow - defaultInitialWindowSize

    struct RecvWindowResult: Equatable {
        var connectionIncrement: Int?
        var streamIncrement: Int?
    }

    private let lock = NSLock()
    private var connectionWindow = Http2FlowControl.defaultInitialWindowSize
    private var streamWindow = Http2FlowControl.defaultInitialWindowSize
    private var connectionRecvConsumed = 0
    private var streamRecvConsumed = 0
    private let streamRecvWindowSize = Http2FlowControl.naiveInitialWindowSize
    private let connectionRecvWindowSize = Http2FlowControl.naiveSessionMaxRecvWindow
    private var windowAwaiter: TransportDeferred<Void>?

    init() {}

    var connectionSendWindow: Int {
        lock.lock()
        defer { lock.unlock() }
        return connectionWindow
    }

    var streamSendWindow: Int {
        lock.lock()
        defer { lock.unlock() }
        return streamWindow
    }

    var maxSendBytes: Int {
        lock.lock()
        defer { lock.unlock() }
        return min(connectionWindow, streamWindow)
    }

    func consumeSendWindow(_ bytes: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if connectionWindow < bytes || streamWindow < bytes { return false }
        connectionWindow -= bytes
        streamWindow -= bytes
        return true
    }

    /// The WINDOW_UPDATE increments due (connection, stream); either is nil
    /// until half its window has been consumed.
    func consumeRecvWindow(_ bytes: Int) -> RecvWindowResult {
        lock.lock()
        defer { lock.unlock() }
        connectionRecvConsumed += bytes
        streamRecvConsumed += bytes
        var result = RecvWindowResult(connectionIncrement: nil, streamIncrement: nil)
        if connectionRecvConsumed >= connectionRecvWindowSize / 2 {
            result.connectionIncrement = connectionRecvConsumed
            connectionRecvConsumed = 0
        }
        if streamRecvConsumed >= streamRecvWindowSize / 2 {
            result.streamIncrement = streamRecvConsumed
            streamRecvConsumed = 0
        }
        return result
    }

    func applyWindowUpdate(streamID: Int, increment: Int) {
        lock.lock()
        if streamID == 0 {
            connectionWindow += increment
        } else {
            streamWindow += increment
        }
        let awaiter = takeAwaiterIfOpenLocked()
        lock.unlock()
        awaiter?.complete(())
    }

    /// Waits until both the connection and the stream window have room.
    func awaitWindow() async throws {
        let awaiter: TransportDeferred<Void>? = currentAwaiter()
        guard let waiting = awaiter else { return }
        try await waiting.wait()
    }

    private func currentAwaiter() -> TransportDeferred<Void>? {
        lock.lock()
        defer { lock.unlock() }
        if min(connectionWindow, streamWindow) > 0 { return nil }
        if let existing = windowAwaiter { return existing }
        let created = TransportDeferred<Void>()
        windowAwaiter = created
        return created
    }

    func cancelAwaiters(_ error: Error) {
        lock.lock()
        let awaiter = windowAwaiter
        windowAwaiter = nil
        lock.unlock()
        awaiter?.fail(error)
    }

    /// RFC 9113 §6.9.2: shifts the stream send window by the new initial
    /// window's distance from the default.
    func applySettings(initialWindowSize: Int) {
        lock.lock()
        streamWindow += initialWindowSize - Http2FlowControl.defaultInitialWindowSize
        let awaiter = takeAwaiterIfOpenLocked()
        lock.unlock()
        awaiter?.complete(())
    }

    private func takeAwaiterIfOpenLocked() -> TransportDeferred<Void>? {
        if min(connectionWindow, streamWindow) <= 0 { return nil }
        let awaiter = windowAwaiter
        windowAwaiter = nil
        return awaiter
    }
}
