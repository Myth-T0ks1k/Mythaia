import Foundation

/// A NaiveProxy CONNECT tunnel with NaiveProxy's padding on its first eight
/// reads and writes when the server negotiated variant 1; afterwards the data
/// passes through unframed.
///
/// Client to server: payloads under 100 bytes get padding biased towards
/// [255 - length, 255]; payloads of 400–1024 bytes are split into 200–300
/// byte pieces. Server to client: uniform padding in [0, 255].
final class NaiveProxyConnection: ByteStream, @unchecked Sendable {
    /// The most one padded frame carries: its length field is 16 bits.
    static let maxPaddingPayload = 65535

    private let tunnel: ByteStream
    private let paddingType: NaivePaddingNegotiator.PaddingType
    private let framer = NaivePaddingFramer()
    private let lock = NSLock()
    private var onClose: (() -> Void)?

    /// `onClose` runs once, when this side closes the tunnel.
    init(_ tunnel: ByteStream, paddingType: NaivePaddingNegotiator.PaddingType, onClose: (() -> Void)? = nil) {
        self.tunnel = tunnel
        self.paddingType = paddingType
        self.onClose = onClose
    }

    /// Send padding as Chrome's NaiveProxy client does it.
    static func generateSendPaddingSize(_ payloadSize: Int) -> Int {
        if payloadSize < 100 {
            return Int.random(in: (255 - payloadSize)...255)
        }
        return Int.random(in: 0...255)
    }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        let bytes = [UInt8](data)
        if paddingType != .variant1 || !writePaddingActive() {
            try await tunnel.send(data)
            return
        }
        if bytes.count >= 400 && bytes.count <= 1024 {
            try await sendFragmented(bytes)
            return
        }
        var offset = 0
        while offset < bytes.count {
            // A padded frame's length field is 16 bits; bigger payloads go
            // in pieces, each padded while padding lasts.
            let take = min(NaiveProxyConnection.maxPaddingPayload, bytes.count - offset)
            let piece = Array(bytes[offset..<(offset + take)])
            offset += take
            if let framed = frame(piece) {
                try await tunnel.send(Data(framed))
            } else {
                try await tunnel.send(Data(piece))
            }
        }
    }

    /// 400–1024 bytes, cut into 200–300 byte padded pieces while padding
    /// lasts; what is left after it goes as it is.
    private func sendFragmented(_ bytes: [UInt8]) async throws {
        var offset = 0
        while offset < bytes.count {
            let remaining = bytes.count - offset
            let chunkSize = remaining <= 300 ? remaining : Int.random(in: 200...300)
            let chunk = Array(bytes[offset..<(offset + chunkSize)])
            guard let framed = frame(chunk) else {
                try await tunnel.send(Data(bytes[offset...]))
                return
            }
            try await tunnel.send(Data(framed))
            offset += chunkSize
        }
    }

    func receive() async throws -> Data? {
        while true {
            guard let data = try await tunnel.receive() else { return nil }
            if data.isEmpty { continue }
            if paddingType != .variant1 {
                return data
            }
            let payload = unpad([UInt8](data))
            switch payload {
            case .passThrough:
                return data
            case .payload(let bytes):
                if !bytes.isEmpty {
                    return Data(bytes)
                }
                // A frame of pure padding: read on.
            }
        }
    }

    func close() {
        lock.lock()
        let handler = onClose
        onClose = nil
        lock.unlock()
        tunnel.close()
        handler?()
    }

    private enum Unpadded {
        case passThrough
        case payload([UInt8])
    }

    private func writePaddingActive() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return framer.isWritePaddingActive
    }

    /// One padded frame, or nil once write padding is over.
    private func frame(_ payload: [UInt8]) -> [UInt8]? {
        lock.lock()
        defer { lock.unlock() }
        guard framer.isWritePaddingActive else { return nil }
        let padding = NaiveProxyConnection.generateSendPaddingSize(payload.count)
        return framer.write(payload, paddingSize: padding)
    }

    private func unpad(_ data: [UInt8]) -> Unpadded {
        lock.lock()
        defer { lock.unlock() }
        guard framer.isReadPaddingActive else { return .passThrough }
        var out = [UInt8]()
        _ = framer.read(data, into: &out)
        return .payload(out)
    }
}
