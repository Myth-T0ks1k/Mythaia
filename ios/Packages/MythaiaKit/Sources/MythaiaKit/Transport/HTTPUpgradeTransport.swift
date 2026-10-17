import Foundation

/// Xray's HTTPUpgrade transport: the WebSocket upgrade request and its 101,
/// after which the connection carries raw bytes with no framing at all.
public enum HTTPUpgradeTransport {
    /// Upgrades `stream` and returns it ready for the protocol above. On
    /// failure `stream` is closed, as nobody else holds it.
    public static func open(over stream: ByteStream, configuration: HttpUpgradeConfiguration) async throws -> ByteStream {
        let headers = configuration.headers.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
        let connection = HttpUpgradeConnection(inner: stream, host: configuration.host, path: configuration.path, headers: headers)
        do {
            try await connection.performUpgrade()
            return connection
        } catch {
            connection.close()
            throw TransportErrors.map(error)
        }
    }
}

enum HttpUpgradeError: Error, LocalizedError, Equatable, TransportErrorConvertible {
    case upgradeFailed(String)

    var message: String {
        switch self {
        case .upgradeFailed(let reason):
            return "HTTP upgrade failed: \(reason)"
        }
    }

    var errorDescription: String? { message }

    var mythaiaError: MythaiaError { .protocolError(message) }
}

/// An HTTP upgrade handshake, then the bytes passed through as they are.
final class HttpUpgradeConnection: ByteStream, @unchecked Sendable {
    /// The most a 101 response head may take before it is given up on.
    static let maxResponseHeadSize = 64 * 1024

    private let inner: ByteStream
    private let host: String
    private let path: String
    private let headers: [(String, String)]
    private let lock = NSLock()
    private var leftover: [UInt8] = []
    private var connected = true

    init(inner: ByteStream, host: String, path: String, headers: [(String, String)]) {
        self.inner = inner
        self.host = host
        self.path = path
        self.headers = headers
    }

    var isConnected: Bool {
        lock.lock()
        defer { lock.unlock() }
        return connected
    }

    /// Sends a GET with `Connection: Upgrade` and `Upgrade: websocket`, then
    /// waits for the 101.
    func performUpgrade() async throws {
        var request = "GET \(path) HTTP/1.1\r\n"
        request += "Host: \(host)\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Upgrade: websocket\r\n"
        // Custom headers first, then the default User-Agent only if none of
        // them is one (names compared without case).
        for (name, value) in headers {
            request += "\(name): \(value)\r\n"
        }
        let hasUserAgent = headers.contains { $0.0.caseInsensitiveCompare("User-Agent") == .orderedSame }
        if !hasUserAgent {
            request += "User-Agent: \(WebSocketConnection.chromeUserAgent)\r\n"
        }
        request += "\r\n"

        try await inner.send(Data(request.utf8))
        try await receiveUpgradeResponse()
    }

    /// Reads the response head and checks it: status 101, `Upgrade:
    /// websocket` and `Connection: upgrade` (values compared without case).
    private func receiveUpgradeResponse() async throws {
        var buffer: [UInt8] = []
        while true {
            guard let data = try await inner.receive(), !data.isEmpty else {
                throw HttpUpgradeError.upgradeFailed("Empty response from server")
            }
            buffer.append(contentsOf: data)
            guard let end = TransportEncoding.headerEnd(buffer) else {
                if buffer.count > HttpUpgradeConnection.maxResponseHeadSize {
                    throw HttpUpgradeError.upgradeFailed("response head longer than \(HttpUpgradeConnection.maxResponseHeadSize) bytes")
                }
                continue
            }
            // Whatever followed the head is the first data; receive() returns it first.
            storeLeftover(Array(buffer[(end + 4)...]))
            try HttpUpgradeConnection.checkResponse(String(decoding: buffer[0..<end], as: UTF8.self))
            return
        }
    }

    static func checkResponse(_ head: String) throws {
        let lines = head.components(separatedBy: "\r\n")
        guard let statusLine = lines.first, !statusLine.isEmpty else {
            throw HttpUpgradeError.upgradeFailed("Empty response")
        }
        if !statusLine.contains("101") {
            throw HttpUpgradeError.upgradeFailed("Expected HTTP 101, got: \(statusLine)")
        }
        var hasUpgradeWebSocket = false
        var hasConnectionUpgrade = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces).lowercased()
            if key == "upgrade" && value == "websocket" {
                hasUpgradeWebSocket = true
            }
            if key == "connection" && value == "upgrade" {
                hasConnectionUpgrade = true
            }
        }
        if !hasUpgradeWebSocket || !hasConnectionUpgrade {
            throw HttpUpgradeError.upgradeFailed("Missing Upgrade/Connection headers in 101 response")
        }
    }

    private func storeLeftover(_ bytes: [UInt8]) {
        lock.lock()
        leftover = bytes
        lock.unlock()
    }

    private func takeLeftover() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        let out = leftover
        leftover = []
        return out
    }

    func send(_ data: Data) async throws {
        try await inner.send(data)
    }

    /// On the first call, returns what arrived right after the 101's head.
    func receive() async throws -> Data? {
        let pending = takeLeftover()
        if !pending.isEmpty {
            return Data(pending)
        }
        guard let data = try await inner.receive(), !data.isEmpty else {
            return nil
        }
        return data
    }

    func close() {
        lock.lock()
        connected = false
        leftover = []
        lock.unlock()
        inner.close()
    }
}
