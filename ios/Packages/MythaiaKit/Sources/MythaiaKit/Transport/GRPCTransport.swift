import Foundation

/// Xray's gRPC transport ("gun"): one bidirectional streaming call to
/// `/<serviceName>/Tun` (or `/TunMulti`) over HTTP/2, the tunnelled bytes
/// carried as `Hunk` protobuf messages behind gRPC's 5-byte length prefix.
public enum GRPCTransport {
    /// Runs HTTP/2 over `stream` (TLS with ALPN h2, or REALITY) and opens the
    /// call. `authority` is the `:authority` header: the configuration's own
    /// override, else the TLS or REALITY server name, else the address. The
    /// connection belongs to the returned stream; closing it closes both. On
    /// failure `stream` is closed, as nobody else holds it.
    public static func open(over stream: ByteStream, configuration: GrpcConfiguration, authority: String) async throws -> ByteStream {
        let configured = configuration.initialWindowsSize
        let streamWindow = configured > 0 ? configured : GrpcCodec.defaultStreamWindow
        let userAgent = configuration.userAgent.isEmpty ? WebSocketConnection.chromeUserAgent : configuration.userAgent
        let headers = GrpcCodec.requestHeaders(authority: authority, path: configuration.resolvedPath(), userAgent: userAgent)

        let session = Http2Session(profile: .xrayClient(streamWindow: streamWindow), keepalive: true, dial: { stream })
        do {
            let call = try await session.acquireStream("grpc")
            // HEADERS go out with the preface, and the first message may
            // follow before the response: gRPC clients do not wait for it.
            try await call.openRequest(headers, endStream: false, awaitResponse: false)
            // Until the server's SETTINGS nothing proves an HTTP/2 server
            // answered; a TLS server speaking something else fails here
            // rather than on the first read.
            try await session.awaitServerSettings()
            let tunnel = GrpcTunnelStream(stream: call, session: session, pingInterval: configuration.idleTimeout)
            return TransportErrorMappingStream(tunnel)
        } catch {
            session.close()
            stream.close()
            throw TransportErrors.map(error)
        }
    }
}

enum GrpcError: Error, LocalizedError, Equatable, TransportErrorConvertible {
    case setupFailed(String)
    case connectionClosed
    case invalidResponse(String)
    case compressedMessageUnsupported
    case callFailed(status: Int, statusName: String, detail: String?)

    var message: String {
        switch self {
        case .setupFailed(let reason):
            return "gRPC setup failed: \(reason)"
        case .connectionClosed:
            return "gRPC connection closed"
        case .invalidResponse(let reason):
            return "gRPC invalid response: \(reason)"
        case .compressedMessageUnsupported:
            return "gRPC compressed messages are not supported"
        case .callFailed(let status, let statusName, let detail):
            if let detail = detail, !detail.isEmpty {
                return "gRPC call failed: \(statusName) (\(status)) — \(detail)"
            }
            return "gRPC call failed: \(statusName) (\(status))"
        }
    }

    var errorDescription: String? { message }

    var mythaiaError: MythaiaError {
        switch self {
        case .connectionClosed:
            return .closed
        default:
            return .protocolError(message)
        }
    }

    var status: Int? {
        if case .callFailed(let status, _, _) = self { return status }
        return nil
    }
}

/// One gRPC tunnel: a stream of an HTTP/2 session, the bytes going out as
/// Hunk messages and coming back out of them.
final class GrpcTunnelStream: ByteStream, @unchecked Sendable {
    let stream: Http2Stream
    /// The session the tunnel owns, closed with it; nil when shared.
    private let session: Http2Session?
    private let messages = GrpcCodec.MessageReader()
    private let lock = NSLock()
    private var pingTask: Task<Void, Never>?

    /// `pingInterval`, in seconds, is the configuration's idle_timeout: a
    /// PING that often keeps the connection alive through NATs; 0 sends none.
    init(stream: Http2Stream, session: Http2Session?, pingInterval: Int = 0) {
        self.stream = stream
        self.session = session
        if pingInterval > 0, let session = session {
            let call = stream
            pingTask = Task {
                while true {
                    try? await Task.sleep(nanoseconds: UInt64(pingInterval) * 1_000_000_000)
                    if Task.isCancelled || !call.isConnected { return }
                    await session.sendPing()
                }
            }
        }
    }

    var isConnected: Bool { stream.isConnected }

    /// Sends `data` as one Hunk message.
    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await stream.sendData(GrpcCodec.wrapMessage(GrpcCodec.encodeHunk(data)))
    }

    /// The next payload; nil at the end of the call. Trailers with a
    /// grpc-status other than OK fail it instead.
    func receive() async throws -> Data? {
        while true {
            if let payload = try messages.next() {
                // An empty Hunk carries nothing; above us an empty read means the end.
                if payload.isEmpty { continue }
                return payload
            }
            guard let chunk = try await stream.receiveData() else {
                if let failure = GrpcCodec.failureIn(stream.trailers) {
                    throw failure
                }
                return nil
            }
            messages.add(chunk)
        }
    }

    func close() {
        lock.lock()
        let task = pingTask
        pingTask = nil
        lock.unlock()
        task?.cancel()
        stream.close()
        session?.close()
    }
}

/// The gRPC framing: request headers, `Hunk` messages and their 5-byte prefix.
enum GrpcCodec {
    /// The stream window the call asks for unless initial_windows_size says otherwise.
    static let defaultStreamWindow = 4_194_304

    /// The largest message accepted from the server.
    static let maxMessage = 16 * 1024 * 1024

    /// The request's header block, as Xray's client sends it: `:authority`,
    /// `:method POST`, `:path`, `:scheme https`, then content-type, te,
    /// grpc-encoding, grpc-accept-encoding and user-agent, the literals with
    /// incremental indexing.
    static func requestHeaders(authority: String, path: String, userAgent: String) -> Data {
        var block: [UInt8] = []
        block.append(contentsOf: HpackEncoder.literalWithIndexing(nameIndex: 1))
        block.append(contentsOf: HpackEncoder.encodeString(authority))
        // :method POST, static-table entry 3
        block.append(0x83)
        block.append(contentsOf: HpackEncoder.literalWithIndexing(nameIndex: 4))
        block.append(contentsOf: HpackEncoder.encodeString(path))
        // :scheme https, static-table entry 7
        block.append(0x87)
        block.append(contentsOf: HpackEncoder.literalWithIndexing(nameIndex: 31))
        block.append(contentsOf: HpackEncoder.encodeString("application/grpc"))
        // te: trailers, which the gRPC protocol requires
        block.append(0x40)
        block.append(contentsOf: HpackEncoder.encodeString("te"))
        block.append(contentsOf: HpackEncoder.encodeString("trailers"))
        block.append(0x40)
        block.append(contentsOf: HpackEncoder.encodeString("grpc-encoding"))
        block.append(contentsOf: HpackEncoder.encodeString("identity"))
        block.append(0x40)
        block.append(contentsOf: HpackEncoder.encodeString("grpc-accept-encoding"))
        block.append(contentsOf: HpackEncoder.encodeString("identity"))
        block.append(contentsOf: HpackEncoder.literalWithIndexing(nameIndex: 58))
        block.append(contentsOf: HpackEncoder.encodeString(userAgent))
        return Data(block)
    }

    /// `Hunk { bytes data = 1; }`: tag 0x0A, a varint length, the bytes. A
    /// MultiHunk with one element is the same bytes, so TunMulti sends these too.
    static func encodeHunk(_ data: Data) -> Data {
        var header: [UInt8] = [0x0A]
        var length = UInt64(data.count)
        while length >= 0x80 {
            header.append(UInt8(length & 0x7F) | 0x80)
            length >>= 7
        }
        header.append(UInt8(length))
        var out = Data(header)
        out.append(data)
        return out
    }

    /// The 5-byte gRPC prefix: not compressed, then the length, big-endian.
    static func wrapMessage(_ message: Data) -> Data {
        let length = message.count
        var out = Data([0])
        out.append(contentsOf: Http2Framer.uint32Bytes(length))
        out.append(message)
        return out
    }

    /// grpc-status other than 0 in the trailers, as an error; nil when the
    /// call ended well or said nothing.
    static func failureIn(_ trailers: [HpackHeader]?) -> GrpcError? {
        guard let trailers = trailers,
              let text = trailers.first(where: { $0.name == "grpc-status" })?.value,
              let status = Int(text) else {
            return nil
        }
        if status == 0 { return nil }
        let detail = trailers.first(where: { $0.name == "grpc-message" })?.value
        return .callFailed(status: status, statusName: statusName(status), detail: detail)
    }

    static func statusName(_ code: Int) -> String {
        let names = [
            "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
            "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION",
            "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS",
            "UNAUTHENTICATED",
        ]
        if code >= 0 && code < names.count { return names[code] }
        return "UNKNOWN(\(code))"
    }

    /// Reassembles gRPC messages from DATA payloads and decodes their Hunks.
    final class MessageReader {
        private var buffer: [UInt8] = []
        private var start = 0

        init() {}

        func add(_ chunk: Data) {
            buffer.append(contentsOf: chunk)
        }

        /// The next whole message's payload, or nil until more bytes arrive.
        func next() throws -> Data? {
            let available = buffer.count - start
            if available < 5 { return nil }
            if buffer[start] != 0 { throw GrpcError.compressedMessageUnsupported }
            let size = Http2Framer.readUInt32(buffer, start + 1)
            if size > GrpcCodec.maxMessage {
                throw GrpcError.invalidResponse("message of \(size) bytes")
            }
            if available < 5 + size { return nil }
            let message = Array(buffer[(start + 5)..<(start + 5 + size)])
            start += 5 + size
            if start >= buffer.count {
                buffer.removeAll(keepingCapacity: true)
                start = 0
            } else if start > 64 * 1024 && start * 2 > buffer.count {
                buffer.removeFirst(start)
                start = 0
            }
            return try GrpcCodec.decodeHunks(message)
        }
    }

    /// Field 1 of a Hunk or MultiHunk, concatenated; other fields skipped.
    static func decodeHunks(_ message: [UInt8]) throws -> Data {
        var out = Data()
        var offset = 0

        func varint() throws -> UInt64 {
            var value: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                if offset >= message.count { throw GrpcError.invalidResponse("truncated varint") }
                let b = message[offset]
                offset += 1
                value |= UInt64(b & 0x7F) << shift
                if (b & 0x80) == 0 { return value }
                shift += 7
                if shift >= 64 { throw GrpcError.invalidResponse("varint too long") }
            }
        }

        while offset < message.count {
            let tag = try varint()
            switch tag & 0x07 {
            case 2:
                let length = try varint()
                if length > UInt64(message.count - offset) {
                    throw GrpcError.invalidResponse("truncated field")
                }
                let end = offset + Int(length)
                if (tag >> 3) == 1 {
                    out.append(contentsOf: message[offset..<end])
                }
                offset = end
            case 0:
                _ = try varint()
            case 5:
                if offset + 4 > message.count { throw GrpcError.invalidResponse("truncated fixed32 field") }
                offset += 4
            case 1:
                if offset + 8 > message.count { throw GrpcError.invalidResponse("truncated fixed64 field") }
                offset += 8
            default:
                throw GrpcError.invalidResponse("unknown wire type")
            }
        }
        return out
    }
}
