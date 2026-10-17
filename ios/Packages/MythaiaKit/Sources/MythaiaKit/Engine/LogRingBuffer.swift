import Foundation

/// The last few hundred log lines, for a process whose log the user cannot
/// otherwise see: the tunnel keeps one as its `Log` sink and hands its
/// lines to the app's log screen in a provider message.
///
/// Fixed capacity and a cap on each line keep it small inside the tunnel's
/// memory limit however chatty a session gets.
public final class LogRingBuffer: @unchecked Sendable {
    public let capacity: Int

    /// Longer lines are cut; a server's error page pasted into a message
    /// would otherwise take the room of many lines.
    public static let maxLineLength = 1000

    private let lock = NSLock()
    private var storage: [String] = []
    /// When full, the index of the oldest line.
    private var head = 0
    private let formatter: DateFormatter

    public init(capacity: Int = 500) {
        self.capacity = max(1, capacity)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss.SSS"
        self.formatter = formatter
        storage.reserveCapacity(self.capacity)
    }

    /// Appends "time level message".
    public func append(level: Log.Level, message: String, date: Date = Date()) {
        lock.lock()
        let stamp = formatter.string(from: date)
        lock.unlock()
        append(stamp + " " + level.tag + " " + message)
    }

    public func append(_ line: String) {
        let text: String
        if line.count > LogRingBuffer.maxLineLength {
            text = String(line.prefix(LogRingBuffer.maxLineLength)) + "..."
        } else {
            text = line
        }
        lock.lock()
        if storage.count < capacity {
            storage.append(text)
        } else {
            storage[head] = text
            head = (head + 1) % capacity
        }
        lock.unlock()
    }

    /// Oldest first; with `last`, only that many of the newest.
    public func lines(last: Int? = nil) -> [String] {
        lock.lock()
        let ordered: [String]
        if storage.count < capacity || head == 0 {
            ordered = storage
        } else {
            ordered = Array(storage[head...]) + Array(storage[..<head])
        }
        lock.unlock()
        if let last, last >= 0, last < ordered.count {
            return Array(ordered.suffix(last))
        }
        return ordered
    }

    public var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage.count
    }

    public func clear() {
        lock.lock()
        storage.removeAll(keepingCapacity: true)
        head = 0
        lock.unlock()
    }
}
