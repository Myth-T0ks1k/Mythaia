import Foundation

/// UDP over an AnyTLS stream, in sing-box's udp-over-tcp v2 framing.
///
/// AnyTLS has no datagram mode of its own. Instead a stream is opened to the
/// reserved name `sp.v2.udp-over-tcp.arpa`, which the server recognises and
/// treats as a UDP association rather than a TCP connect.
///
/// The framing has two forms and this uses the connected one: a single
/// request naming the destination, after which every datagram is just a
/// length and its bytes. The unconnected form repeats an address on each
/// packet — and numbers address families differently there (0x00/0x01/0x02)
/// from the request (0x01/0x03/0x04, as SOCKS5 does). Only the request form
/// is used here, so the SOCKS5 numbering is the only one on the wire.
final class AnyTlsUdpConnection: DatagramStream, @unchecked Sendable {
    private let stream: ByteStream
    private let destinationHost: String
    private let destinationPort: UInt16
    private let lock = NSLock()
    private var requestSent = false
    private var buffer = [UInt8]()

    init(_ stream: ByteStream, destinationHost: String, destinationPort: UInt16) {
        self.stream = stream
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }

    func send(_ packet: Data) async throws {
        if packet.count > 0xFFFF {
            Log.debug("AnyTLS UDP: dropping a \(packet.count)-byte datagram")
            return
        }
        try await stream.send(Data(frame(packet)))
    }

    /// One datagram. A stream read has nothing to do with datagram
    /// boundaries, so this keeps what it has and only returns once a whole
    /// length-prefixed packet is in hand.
    func receive() async throws -> Data? {
        while true {
            if let packet = nextPacket(appending: nil) { return packet }
            guard let chunk = try await stream.receive() else { return nil }
            if let packet = nextPacket(appending: chunk) { return packet }
        }
    }

    func close() {
        stream.close()
    }

    /// The request (first datagram only), then the length and the datagram.
    func frame(_ packet: Data) -> [UInt8] {
        var out = [UInt8]()
        lock.lock()
        if !requestSent {
            requestSent = true
            // isConnect = 1, then the destination in SOCKS5 address form.
            out.append(1)
            out.append(contentsOf: AnyTlsProtocol.encodeAddress(host: destinationHost, port: destinationPort))
        }
        lock.unlock()
        out.append(UInt8(truncatingIfNeeded: packet.count >> 8))
        out.append(UInt8(truncatingIfNeeded: packet.count))
        out.append(contentsOf: packet)
        return out
    }

    private func nextPacket(appending chunk: Data?) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if let chunk = chunk {
            buffer.append(contentsOf: chunk)
        }
        if buffer.count < 2 { return nil }
        let size = (Int(buffer[0]) << 8) | Int(buffer[1])
        if buffer.count < 2 + size { return nil }
        let packet = Data(buffer[2..<(2 + size)])
        buffer.removeFirst(2 + size)
        return packet
    }
}
