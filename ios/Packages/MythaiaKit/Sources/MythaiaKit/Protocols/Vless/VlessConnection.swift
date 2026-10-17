import Foundation

/// A VLESS stream: sends pass straight through, and the 2-byte response
/// header (`version` + `addonsLength`, then the addons) is stripped from the
/// first bytes the server returns.
///
/// Header bytes are buffered across reads, so transports that deliver a
/// fragmented header (WebSocket, XHTTP, HTTP/2) work. A read that held only
/// header bytes reads again rather than returning, or the caller would take
/// the empty result for the end of the stream.
final class VlessConnection: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let lock = NSLock()
    private var responseHeaderReceived = false
    private var pendingResponseHeader = [UInt8]()

    init(_ inner: ByteStream) {
        self.inner = inner
    }

    func send(_ data: Data) async throws {
        try await inner.send(data)
    }

    func receive() async throws -> Data? {
        while true {
            guard let data = try await inner.receive() else { return nil }
            if data.isEmpty { continue }
            if let payload = processResponseHeader(data) {
                return payload
            }
        }
    }

    func close() {
        inner.close()
    }

    /// `data` without the response header; nil while the header is not
    /// complete yet, or when this read held nothing but header.
    func processResponseHeader(_ data: Data) -> Data? {
        lock.lock()
        defer { lock.unlock() }

        if responseHeaderReceived { return data }

        var combined = pendingResponseHeader
        combined.append(contentsOf: data)

        if combined.count < 2 {
            pendingResponseHeader = combined
            return nil
        }
        if combined[0] != VlessProtocol.version {
            // No VLESS response header: everything buffered is payload.
            responseHeaderReceived = true
            pendingResponseHeader = []
            return Data(combined)
        }
        let headerLength = 2 + Int(combined[1])
        if combined.count < headerLength {
            pendingResponseHeader = combined
            return nil
        }
        responseHeaderReceived = true
        pendingResponseHeader = []
        if combined.count > headerLength {
            return Data(combined[headerLength...])
        }
        return nil
    }
}

/// VLESS UDP: each datagram travels with a 2-byte length prefix over the
/// stream, which strips the response header underneath.
final class VlessUdpConnection: DatagramStream, @unchecked Sendable {
    private let inner: ByteStream
    private let lock = NSLock()
    private let state = UdpBufferState()

    /// `inner` is the VLESS stream (response header already handled).
    init(_ inner: ByteStream) {
        self.inner = inner
    }

    func send(_ packet: Data) async throws {
        if packet.count > UdpFraming.maxPacketLength {
            // The length field cannot carry it; drop it as the network would.
            Log.debug("VLESS UDP: dropping a \(packet.count)-byte datagram")
            return
        }
        try await inner.send(UdpFraming.frame(packet))
    }

    func receive() async throws -> Data? {
        while true {
            if let packet = nextPacket(appending: nil) { return packet }
            guard let data = try await inner.receive() else { return nil }
            if let packet = nextPacket(appending: data) { return packet }
        }
    }

    func close() {
        lock.lock()
        state.clear()
        lock.unlock()
        inner.close()
    }

    private func nextPacket(appending data: Data?) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let data = data {
            state.append(data)
        }
        return UdpFraming.extract(state)
    }
}
