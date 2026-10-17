import Foundation
import Network

/// A plain TCP connection: the bottom of every dial that is not tunnelled
/// through another server. Closing it from any thread fails whatever is in
/// progress on it with `closed`.
public final class TCPStream: ByteStream, @unchecked Sendable {
    private let connection: TransportNWConnection

    private init(connection: TransportNWConnection) {
        self.connection = connection
    }

    /// Connects to `host` (a name or an IP literal, IPv6 without brackets).
    /// `timeout` bounds the whole connect; cancelling the calling task
    /// abandons it.
    public static func connect(host: String, port: UInt16, timeout: Double = 10) async throws -> TCPStream {
        let parameters = TransportNWConnection.outboundParameters(tls: nil, timeout: timeout)
        let connection = try TransportNWConnection(host: host, port: port, parameters: parameters, what: "TCP")
        do {
            try await connection.start(timeout: timeout)
        } catch {
            connection.close()
            throw error
        }
        return TCPStream(connection: connection)
    }

    public func send(_ data: Data) async throws {
        try await connection.send(data)
    }

    public func receive() async throws -> Data? {
        try await connection.receive()
    }

    public func close() {
        connection.close()
    }
}
