import Foundation

/// One VMess stream over `inner`.
///
/// The sealed request header rides the first write, so a connection costs no
/// extra round trip. The reply's header is read once, lazily, on the first
/// receive — the server sends it in front of the first body chunk.
final class VmessConnection: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let session: VmessProtocol.Session
    private let writer: VmessChunkStream
    private let reader: VmessChunkStream

    /// The chunk writer advances a counter and a mask stream per chunk, and
    /// the header must go out exactly once and first: both under this lock.
    private let sendLock = NSLock()
    private var pendingHeader: Data?

    // Receive side; one receiving task at a time.
    private var buffer = [UInt8]()
    private var responseHeaderRead = false
    private var ended = false

    init(_ inner: ByteStream, session: VmessProtocol.Session, requestHeader: Data) {
        self.inner = inner
        self.session = session
        let masking = session.option & VmessProtocol.optionChunkMasking != 0
        let padding = session.option & VmessProtocol.optionGlobalPadding != 0
        self.writer = VmessChunkStream(
            key: session.requestBodyKey,
            iv: session.requestBodyIv,
            security: session.security,
            masking: masking,
            globalPadding: padding
        )
        self.reader = VmessChunkStream(
            key: session.responseBodyKey,
            iv: session.responseBodyIv,
            security: session.security,
            masking: masking,
            globalPadding: padding
        )
        self.pendingHeader = requestHeader
    }

    func send(_ data: Data) async throws {
        let out = try frame(data)
        if out.isEmpty { return }
        try await inner.send(out)
    }

    func receive() async throws -> Data? {
        if ended { return nil }
        while true {
            if !responseHeaderRead {
                let consumed = try VmessProtocol.openResponseHeader(session, buffer)
                if consumed >= 0 {
                    buffer.removeFirst(consumed)
                    responseHeaderRead = true
                } else {
                    let more = try await fill()
                    if !more { return nil }
                    continue
                }
            }

            switch try reader.decode(buffer, from: 0) {
            case .chunk(let payload, let consumed):
                buffer.removeFirst(consumed)
                // A zero-length payload is not the terminator — that is a
                // separate case — so only skip it and keep reading.
                if !payload.isEmpty { return payload }
            case .endOfStream:
                ended = true
                return nil
            case .needMore:
                let more = try await fill()
                if !more { return nil }
            }
        }
    }

    func close() {
        inner.close()
    }

    private func frame(_ data: Data) throws -> Data {
        sendLock.lock()
        defer { sendLock.unlock() }
        var out = pendingHeader ?? Data()
        pendingHeader = nil
        out.append(try writer.encode(data))
        return out
    }

    /// Reads more from the stream. False when it is finished.
    private func fill() async throws -> Bool {
        while true {
            guard let more = try await inner.receive() else { return false }
            if more.isEmpty { continue }
            buffer.append(contentsOf: more)
            return true
        }
    }
}

/// VMess UDP: the UDP command, then one datagram per chunk — which is what
/// the server does on the other side.
final class VmessUdpConnection: DatagramStream, @unchecked Sendable {
    private let stream: VmessConnection

    init(_ stream: VmessConnection) {
        self.stream = stream
    }

    func send(_ packet: Data) async throws {
        if packet.isEmpty { return }
        try await stream.send(packet)
    }

    func receive() async throws -> Data? {
        return try await stream.receive()
    }

    func close() {
        stream.close()
    }
}
