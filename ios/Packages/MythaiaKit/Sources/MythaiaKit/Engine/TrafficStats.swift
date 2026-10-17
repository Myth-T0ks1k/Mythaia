import Foundation

/// The byte counters the home screen shows, as one value the tunnel can hand
/// the app in a provider message.
public struct TrafficStats: Codable, Hashable {
    /// Client to server, since the proxy started.
    public var uploadBytes: Int64
    /// Server to client, since the proxy started.
    public var downloadBytes: Int64
    /// Bytes per second over the last second or so.
    public var uploadSpeed: Int64
    public var downloadSpeed: Int64
    /// Connections open right now.
    public var connections: Int

    public init(
        uploadBytes: Int64 = 0,
        downloadBytes: Int64 = 0,
        uploadSpeed: Int64 = 0,
        downloadSpeed: Int64 = 0,
        connections: Int = 0
    ) {
        self.uploadBytes = uploadBytes
        self.downloadBytes = downloadBytes
        self.uploadSpeed = uploadSpeed
        self.downloadSpeed = downloadSpeed
        self.connections = connections
    }
}

/// A monotonic clock in seconds that keeps counting while the device sleeps,
/// so an interval measured across a night is a night long.
enum EngineClock {
    static func seconds() -> Double {
        Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1_000_000_000
    }
}

/// The counters behind `TrafficStats`. Speed is computed when someone asks:
/// a timer ticking every second would wake the tunnel for nothing while the
/// app is closed.
final class TrafficCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var up: Int64 = 0
    private var down: Int64 = 0
    private var open = 0
    private var sampleTime: Double = 0
    private var sampleUp: Int64 = 0
    private var sampleDown: Int64 = 0
    private var upSpeed: Int64 = 0
    private var downSpeed: Int64 = 0

    /// The shortest interval a speed is computed over; a read sooner than
    /// this after the last one returns the last speed.
    static let minimumSampleInterval: Double = 0.8

    func addUp(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        up += Int64(count)
        lock.unlock()
    }

    func addDown(_ count: Int) {
        guard count > 0 else { return }
        lock.lock()
        down += Int64(count)
        lock.unlock()
    }

    func connectionOpened() {
        lock.lock()
        open += 1
        lock.unlock()
    }

    func connectionClosed() {
        lock.lock()
        open = max(0, open - 1)
        lock.unlock()
    }

    func reset() {
        lock.lock()
        up = 0
        down = 0
        sampleTime = 0
        sampleUp = 0
        sampleDown = 0
        upSpeed = 0
        downSpeed = 0
        lock.unlock()
    }

    func snapshot(now: Double) -> TrafficStats {
        lock.lock()
        defer { lock.unlock() }
        if sampleTime == 0 {
            sampleTime = now
            sampleUp = up
            sampleDown = down
        } else {
            let elapsed = now - sampleTime
            if elapsed >= TrafficCounter.minimumSampleInterval {
                upSpeed = Int64(Double(max(0, up - sampleUp)) / elapsed)
                downSpeed = Int64(Double(max(0, down - sampleDown)) / elapsed)
                sampleTime = now
                sampleUp = up
                sampleDown = down
            }
        }
        return TrafficStats(
            uploadBytes: up,
            downloadBytes: down,
            uploadSpeed: upSpeed,
            downloadSpeed: downSpeed,
            connections: open
        )
    }
}

/// The client side of a relayed connection, counting what passes and when:
/// what the client sends is upload, what it receives is download.
final class FlowCountingStream: ByteStream {
    private let inner: ByteStream
    private let counter: TrafficCounter
    private let onActivity: () -> Void

    init(_ inner: ByteStream, counter: TrafficCounter, onActivity: @escaping () -> Void) {
        self.inner = inner
        self.counter = counter
        self.onActivity = onActivity
    }

    func send(_ data: Data) async throws {
        try await inner.send(data)
        counter.addDown(data.count)
        onActivity()
    }

    func receive() async throws -> Data? {
        let chunk = try await inner.receive()
        if let chunk {
            counter.addUp(chunk.count)
            onActivity()
        }
        return chunk
    }

    func close() {
        inner.close()
    }
}
