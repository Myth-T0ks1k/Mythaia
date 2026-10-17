import Foundation
import os

/// Logging shared by the app and the tunnel. Lines go to the unified log and,
/// when a sink is installed, to it as well (the tunnel keeps a ring buffer
/// the app's log screen reads).
public enum Log {
    public enum Level: Int, Comparable, Codable {
        case debug, info, warning, error

        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }

        public var tag: String {
            switch self {
            case .debug: return "D"
            case .info: return "I"
            case .warning: return "W"
            case .error: return "E"
            }
        }
    }

    private static let logger = os.Logger(subsystem: "com.mythaia", category: "core")
    private static let lock = NSLock()
    nonisolated(unsafe) private static var sink: ((Level, String) -> Void)?
    nonisolated(unsafe) public static var minimumLevel: Level = .info

    /// Installs (or with nil removes) a second destination for log lines.
    public static func setSink(_ newSink: ((Level, String) -> Void)?) {
        lock.lock()
        sink = newSink
        lock.unlock()
    }

    public static func debug(_ message: @autoclosure () -> String) { write(.debug, message) }
    public static func info(_ message: @autoclosure () -> String) { write(.info, message) }
    public static func warning(_ message: @autoclosure () -> String) { write(.warning, message) }
    public static func error(_ message: @autoclosure () -> String) { write(.error, message) }

    private static func write(_ level: Level, _ message: () -> String) {
        guard level >= minimumLevel else { return }
        let text = message()
        switch level {
        case .debug: logger.debug("\(text, privacy: .public)")
        case .info: logger.info("\(text, privacy: .public)")
        case .warning: logger.warning("\(text, privacy: .public)")
        case .error: logger.error("\(text, privacy: .public)")
        }
        lock.lock()
        let current = sink
        lock.unlock()
        current?(level, text)
    }
}
