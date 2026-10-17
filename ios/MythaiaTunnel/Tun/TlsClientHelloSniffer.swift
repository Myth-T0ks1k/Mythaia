import Foundation

/// An incremental, bounds-checked parser that takes the SNI host name out of
/// a TLS ClientHello. It lets domain rules apply to traffic that reaches the
/// tunnel by real IP (hard-coded addresses, apps with their own DNS), where
/// no fake IP names the domain.
///
/// Strictly passive: it buffers at most `bufferLimit` bytes, walks the
/// record, handshake and extension structure with explicit bounds checks,
/// and stops as soon as the first byte rules out TLS or the server_name
/// extension is reached.
final class TlsClientHelloSniffer {

    enum State: Equatable {
        /// More bytes are needed to decide.
        case needMore
        /// The first bytes are not a TLS handshake record (0x16).
        case notTls
        /// The SNI of a well-formed ClientHello, lowercased.
        case found(String)
        /// TLS-shaped, but no SNI to be had: malformed, no server_name, or
        /// the buffer cap was reached. The IP's route stands.
        case unavailable
    }

    private let bufferLimit: Int
    private var buffer: [UInt8] = []
    private(set) var state: State = .needMore

    init(bufferLimit: Int = TunConstants.tlsSnifferBufferLimit) {
        self.bufferLimit = bufferLimit
    }

    /// Appends `data` and advances the parse. Once a final state is reached
    /// further calls change nothing.
    func feed(_ data: [UInt8]) -> State {
        if state != .needMore || data.isEmpty { return state }

        // Rejecting on the first byte keeps the buffer empty for every
        // protocol that is not TLS.
        if buffer.isEmpty && data[0] != 0x16 {
            state = .notTls
            return state
        }

        buffer.append(contentsOf: data)
        if buffer.count > bufferLimit {
            state = .unavailable
            buffer = []
            return state
        }

        state = parse()
        if state != .needMore {
            buffer = []
        }
        return state
    }

    /// Record layer: content type (1), legacy version (2), length (2), fragment.
    private func parse() -> State {
        if buffer.count < 5 { return .needMore }
        if buffer[0] != 0x16 { return .unavailable }

        // RFC 8446 5.1: a record fragment is at most 2^14 bytes.
        let fragmentLength = (Int(buffer[3]) << 8) | Int(buffer[4])
        if fragmentLength <= 0 || fragmentLength > 16_384 { return .unavailable }

        let recordEnd = 5 + fragmentLength
        if buffer.count < recordEnd { return .needMore }
        return parseHandshake(start: 5, end: recordEnd)
    }

    /// Handshake layer: message type (1), length (3), body.
    private func parseHandshake(start: Int, end: Int) -> State {
        var cursor = Cursor(start: start, end: end)
        guard let messageType = cursor.readU8(buffer), messageType == 0x01 else { return .unavailable }
        guard let bodyLength = cursor.readU24(buffer) else { return .unavailable }
        let bodyEnd = cursor.position + bodyLength
        if bodyEnd > end { return .unavailable }
        return parseClientHello(start: cursor.position, end: bodyEnd)
    }

    /// ClientHello body: legacy version (2), random (32), session id (u8
    /// length), cipher suites (u16 length), compression methods (u8 length),
    /// extensions (u16 length).
    private func parseClientHello(start: Int, end: Int) -> State {
        var cursor = Cursor(start: start, end: end)
        if !cursor.skip(2 + 32) { return .unavailable }
        guard let sessionIdLength = cursor.readU8(buffer), cursor.skip(sessionIdLength) else { return .unavailable }
        guard let suitesLength = cursor.readU16(buffer), cursor.skip(suitesLength) else { return .unavailable }
        guard let compressionLength = cursor.readU8(buffer), cursor.skip(compressionLength) else { return .unavailable }
        guard let extensionsLength = cursor.readU16(buffer) else { return .unavailable }
        let extensionsEnd = cursor.position + extensionsLength
        if extensionsEnd > end { return .unavailable }
        return parseExtensions(start: cursor.position, end: extensionsEnd)
    }

    /// Walks the extension list for server_name (type 0).
    private func parseExtensions(start: Int, end: Int) -> State {
        var cursor = Cursor(start: start, end: end)
        while !cursor.isAtEnd {
            guard let extensionType = cursor.readU16(buffer) else { return .unavailable }
            guard let extensionLength = cursor.readU16(buffer) else { return .unavailable }
            let extensionEnd = cursor.position + extensionLength
            if extensionEnd > end { return .unavailable }
            if extensionType == 0x0000 {
                if let name = parseServerNameList(start: cursor.position, end: extensionEnd) {
                    return .found(name)
                }
                return .unavailable
            }
            cursor.position = extensionEnd
        }
        return .unavailable
    }

    /// server_name: a u16-length list of (name type (1), u16-length name);
    /// type 0 is a host name, ASCII per RFC 6066.
    private func parseServerNameList(start: Int, end: Int) -> String? {
        var cursor = Cursor(start: start, end: end)
        guard let listLength = cursor.readU16(buffer) else { return nil }
        let listEnd = cursor.position + listLength
        if listEnd > end { return nil }
        while cursor.position < listEnd {
            guard let nameType = cursor.readU8(buffer) else { return nil }
            guard let nameLength = cursor.readU16(buffer) else { return nil }
            let nameEnd = cursor.position + nameLength
            if nameEnd > listEnd { return nil }
            if nameType == 0x00 && nameLength > 0 {
                let bytes = buffer[cursor.position..<nameEnd]
                return String(decoding: bytes, as: UTF8.self).lowercased()
            }
            cursor.position = nameEnd
        }
        return nil
    }

    private struct Cursor {
        var position: Int
        let end: Int

        init(start: Int, end: Int) {
            self.position = start
            self.end = end
        }

        var isAtEnd: Bool { position >= end }

        mutating func skip(_ count: Int) -> Bool {
            if count < 0 || position + count > end { return false }
            position += count
            return true
        }

        mutating func readU8(_ data: [UInt8]) -> Int? {
            if position >= end { return nil }
            let value = Int(data[position])
            position += 1
            return value
        }

        mutating func readU16(_ data: [UInt8]) -> Int? {
            if position + 2 > end { return nil }
            let value = (Int(data[position]) << 8) | Int(data[position + 1])
            position += 2
            return value
        }

        mutating func readU24(_ data: [UInt8]) -> Int? {
            if position + 3 > end { return nil }
            let high = Int(data[position]) << 16
            let middle = Int(data[position + 1]) << 8
            let value = high | middle | Int(data[position + 2])
            position += 3
            return value
        }
    }
}

/// What a VLESS or VMess dial waits for before it sends its request, so the
/// request and the app's opening bytes leave as one message (see
/// `TunConstants.firstDataWaitMs`).
///
/// Some servers read that first message as the client's TLS ClientHello and
/// close the connection when it is cut short. A browser's ClientHello with a
/// post-quantum key share is about 1.8 KB, two TCP segments, so dialling on
/// the first segment broke every HTTPS page in Chrome through such a server.
enum FirstData {
    /// True once `size` bytes starting with `header` (at least the first 5,
    /// when there are that many) are worth sending with the request: any
    /// bytes that are not a TLS handshake record, or a whole first record.
    static func isComplete(header: [UInt8], size: Int) -> Bool {
        if size <= 0 || header.isEmpty { return false }
        if header[0] != 0x16 { return true }
        if size < 5 || header.count < 5 { return false }
        let length = (Int(header[3]) << 8) | Int(header[4])
        return size >= 5 + length
    }
}
