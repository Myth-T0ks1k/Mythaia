import Foundation

/// UDP over a VLESS or VMess stream: each packet is prefixed with a 2-byte
/// big-endian length.
enum UdpFraming {
    /// The largest datagram the length field can describe.
    static let maxPacketLength = 0xFFFF

    static func frame(_ data: Data) -> Data {
        let length = data.count
        var framed = Data(capacity: 2 + length)
        framed.append(UInt8(truncatingIfNeeded: length >> 8))
        framed.append(UInt8(truncatingIfNeeded: length))
        framed.append(data)
        return framed
    }

    /// The next whole packet in `state`, or nil until one has arrived.
    static func extract(_ state: UdpBufferState) -> Data? {
        let available = state.buffer.count - state.offset
        if available < 2 { return nil }

        let high = Int(state.buffer[state.offset])
        let low = Int(state.buffer[state.offset + 1])
        let length = (high << 8) | low
        if available < 2 + length { return nil }

        let packetStart = state.offset + 2
        let packet = Data(state.buffer[packetStart..<(packetStart + length)])
        state.offset = packetStart + length

        if state.offset > 8192 {
            state.buffer = Array(state.buffer[state.offset...])
            state.offset = 0
        }
        return packet
    }
}

final class UdpBufferState {
    var buffer: [UInt8] = []
    var offset = 0

    func append(_ data: Data) {
        if buffer.isEmpty || offset >= buffer.count {
            // Everything before was consumed: the new chunk starts at 0.
            // Leaving the old offset here read every later frame from the
            // middle of the chunk — the first few UDP replies of a flow
            // arrived and the rest were lost, which is what broke voice
            // calls over VLESS and VMess.
            offset = 0
            buffer = [UInt8](data)
        } else {
            let remaining = Array(buffer[offset...])
            offset = 0
            buffer = remaining + [UInt8](data)
        }
    }

    func clear() {
        buffer = []
        offset = 0
    }
}
