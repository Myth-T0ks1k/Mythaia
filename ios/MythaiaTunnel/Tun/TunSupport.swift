import Foundation

/// A monotonic clock in seconds that keeps counting while the device sleeps,
/// so an idle flow measured across a night is a night idle.
enum TunClock {
    static func now() -> Double {
        Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
    }
}

/// IP addresses as raw bytes (4 or 16, network order), the form lwIP hands
/// them over in, and their text form.
enum TunAddress {
    /// Copies `count` address bytes out of a C buffer.
    static func bytes(_ pointer: UnsafeRawPointer, count: Int) -> [UInt8] {
        let buffer = UnsafeRawBufferPointer(start: pointer, count: count)
        return [UInt8](buffer)
    }

    /// "1.2.3.4" or "2001:db8::1"; nil unless `bytes` is 4 or 16 long.
    static func text(_ bytes: [UInt8]) -> String? {
        let family: Int32
        switch bytes.count {
        case 4: family = AF_INET
        case 16: family = AF_INET6
        default: return nil
        }
        var buffer = [CChar](repeating: 0, count: 64)
        let capacity = socklen_t(buffer.count)
        let converted: Bool = bytes.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return buffer.withUnsafeMutableBufferPointer { out -> Bool in
                guard let target = out.baseAddress else { return false }
                return inet_ntop(family, base, target, capacity) != nil
            }
        }
        guard converted else { return nil }
        let end = buffer.firstIndex(of: 0) ?? buffer.count
        let utf8 = buffer[0..<end].map { UInt8(bitPattern: $0) }
        return String(decoding: utf8, as: UTF8.self)
    }

    /// The 4 or 16 bytes of an IP literal (IPv6 without brackets); nil for
    /// anything else, a host name included. Never resolves.
    static func parse(_ text: String) -> [UInt8]? {
        var literal = text.trimmingCharacters(in: .whitespaces)
        if literal.hasPrefix("[") && literal.hasSuffix("]") && literal.count >= 2 {
            literal = String(literal.dropFirst().dropLast())
        }
        if literal.isEmpty { return nil }
        if literal.contains(":") {
            if let percent = literal.firstIndex(of: "%") {
                literal = String(literal[literal.startIndex..<percent])
            }
            var address = in6_addr()
            guard inet_pton(AF_INET6, literal, &address) == 1 else { return nil }
            return withUnsafeBytes(of: &address) { [UInt8]($0) }
        }
        var address = in_addr()
        guard inet_pton(AF_INET, literal, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { [UInt8]($0) }
    }

    static func isLiteral(_ text: String) -> Bool {
        parse(text) != nil
    }
}

/// A FIFO of bytes: appends at the tail, consumes from the head.
///
/// Consuming advances a read offset instead of moving the whole backlog on
/// every acknowledgement (a slow reader would otherwise cost a copy of the
/// backlog per ACK); the storage is compacted only once the offset passes
/// half of it, so each byte is moved a bounded number of times. Storage
/// that grew large is given back once the queue empties, so a long-lived
/// connection does not keep its peak.
struct ByteQueue {
    private var storage: [UInt8] = []
    private var head = 0

    /// Storage above this is released when the queue empties.
    private static let shrinkThreshold = 64 * 1024

    var count: Int { storage.count - head }
    var isEmpty: Bool { storage.count == head }

    mutating func append(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        compactBeforeAppend()
        storage.append(contentsOf: bytes)
    }

    mutating func append(_ data: Data) {
        guard !data.isEmpty else { return }
        compactBeforeAppend()
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Void in
            storage.append(contentsOf: raw)
        }
    }

    /// Moves everything out of `other` onto the end of this queue.
    mutating func append(takingAllFrom other: inout ByteQueue) {
        guard !other.isEmpty else { return }
        append(other.takeAll())
    }

    /// The first `limit` bytes (fewer if the queue is shorter), left queued.
    func prefix(_ limit: Int) -> [UInt8] {
        let length = min(limit, count)
        guard length > 0 else { return [] }
        return [UInt8](storage[head..<(head + length)])
    }

    /// Removes and returns up to `limit` bytes from the head.
    mutating func take(_ limit: Int) -> Data {
        let length = min(limit, count)
        guard length > 0 else { return Data() }
        let start = head
        let out: Data = storage.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Data in
            guard let base = raw.baseAddress else { return Data() }
            return Data(bytes: base + start, count: length)
        }
        consume(length)
        return out
    }

    /// Removes and returns everything queued.
    mutating func takeAll() -> [UInt8] {
        guard !isEmpty else { return [] }
        let out: [UInt8]
        if head == 0 {
            out = storage
        } else {
            out = [UInt8](storage[head..<storage.count])
        }
        removeAll()
        return out
    }

    /// Drops the first `length` bytes.
    mutating func consume(_ length: Int) {
        guard length > 0 else { return }
        head += length
        if head >= storage.count {
            removeAll()
        } else if head > 4096 && head > storage.count / 2 {
            storage.removeFirst(head)
            head = 0
        }
    }

    mutating func removeAll() {
        let release = storage.capacity > ByteQueue.shrinkThreshold
        storage.removeAll(keepingCapacity: !release)
        head = 0
    }

    /// Calls `body` with a pointer to the queued byte at `offset`; `offset`
    /// must be less than `count`. The pointer is valid only inside `body`.
    func withBytes<T>(from offset: Int, _ body: (UnsafeRawPointer) -> T) -> T? {
        guard offset >= 0, offset < count else { return nil }
        let start = head + offset
        return storage.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> T? in
            guard let base = raw.baseAddress else { return nil }
            return body(base + start)
        }
    }

    /// Reclaims the consumed prefix before the storage would grow.
    private mutating func compactBeforeAppend() {
        if head > 0 && head == storage.count {
            storage.removeAll(keepingCapacity: true)
            head = 0
        } else if head > 0 && storage.count == storage.capacity {
            storage.removeFirst(head)
            head = 0
        }
    }
}

/// Detects inactivity: every interval it checks whether `update()` was
/// called since the last check, and if not calls `onTimeout` once.
///
/// Runs on the lwIP queue and must only be touched there. The timer holds
/// neither the timer object nor the connection strongly, so a closed
/// connection is freed even before its timer is cancelled.
final class ActivityTimer: @unchecked Sendable {
    private let queue: DispatchQueue
    private let onTimeout: () -> Void
    private var source: DispatchSourceTimer?
    private var hasActivity = false
    private var cancelled = false

    init(queue: DispatchQueue, timeoutMs: Int, onTimeout: @escaping () -> Void) {
        self.queue = queue
        self.onTimeout = onTimeout
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { [weak self] in
            self?.tick()
        }
        source = timer
        schedule(timer, timeoutMs: timeoutMs)
        timer.resume()
    }

    deinit {
        source?.setEventHandler(handler: nil)
        source?.cancel()
    }

    /// Signals that something happened.
    func update() {
        hasActivity = true
    }

    /// Changes the interval, restarting the countdown. Pending activity is
    /// kept: the next check still sees what happened before the change.
    func setTimeout(_ timeoutMs: Int) {
        if cancelled { return }
        if timeoutMs <= 0 {
            cancel()
            onTimeout()
            return
        }
        if let timer = source {
            schedule(timer, timeoutMs: timeoutMs)
        }
    }

    func cancel() {
        if cancelled { return }
        cancelled = true
        source?.setEventHandler(handler: nil)
        source?.cancel()
        source = nil
    }

    private func schedule(_ timer: DispatchSourceTimer, timeoutMs: Int) {
        let interval = DispatchTimeInterval.milliseconds(timeoutMs)
        let leeway = DispatchTimeInterval.milliseconds(max(10, timeoutMs / 20))
        timer.schedule(deadline: .now() + interval, repeating: interval, leeway: leeway)
    }

    private func tick() {
        if cancelled { return }
        if hasActivity {
            hasActivity = false
        } else {
            cancel()
            onTimeout()
        }
    }
}

/// Runs `work` on `queue` after `milliseconds`, unless the returned item is
/// cancelled first. `work` should hold its owner weakly: a cancelled item
/// stays queued until its time comes.
@discardableResult
func scheduleOnce(on queue: DispatchQueue, after milliseconds: Int, _ work: @escaping () -> Void) -> DispatchWorkItem {
    let item = DispatchWorkItem(block: work)
    queue.asyncAfter(deadline: .now() + .milliseconds(milliseconds), execute: item)
    return item
}

/// The text of an error as the user should read it (`MythaiaError` says
/// what failed in plain words through `LocalizedError`).
func describeTunError(_ error: Error) -> String {
    if let localized = (error as? LocalizedError)?.errorDescription {
        return localized
    }
    return String(describing: error)
}

/// lwIP's `err_t` values by name, for the logs.
func describeLwipError(_ err: Int32) -> String {
    switch err {
    case 0: return "ERR_OK"
    case -1: return "ERR_MEM (out of memory)"
    case -2: return "ERR_BUF (buffer error)"
    case -3: return "ERR_TIMEOUT (timed out)"
    case -4: return "ERR_RTE (routing problem)"
    case -5: return "ERR_INPROGRESS"
    case -6: return "ERR_VAL (illegal value)"
    case -7: return "ERR_WOULDBLOCK"
    case -8: return "ERR_USE (address in use)"
    case -9: return "ERR_ALREADY (already connecting)"
    case -10: return "ERR_ISCONN (already connected)"
    case -11: return "ERR_CONN (not connected)"
    case -12: return "ERR_IF (low-level netif error)"
    case -13: return "ERR_ABRT (aborted locally)"
    case -14: return "ERR_RST (reset by peer)"
    case -15: return "ERR_CLSD (connection closed)"
    case -16: return "ERR_ARG (illegal argument)"
    default: return "lwIP err=\(err)"
    }
}
