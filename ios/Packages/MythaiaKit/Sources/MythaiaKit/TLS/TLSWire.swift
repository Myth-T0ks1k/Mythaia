import Foundation
import Security

/// Big-endian writer for TLS structures. It works on `[UInt8]` so every
/// offset is zero-based; a `Data` slice keeps its parent's indices and has
/// caught out more than one parser.
struct TLSByteWriter {
    private(set) var bytes: [UInt8] = []

    init() {}

    mutating func u8(_ value: Int) {
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u16(_ value: Int) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func u24(_ value: Int) {
        bytes.append(UInt8(truncatingIfNeeded: value >> 16))
        bytes.append(UInt8(truncatingIfNeeded: value >> 8))
        bytes.append(UInt8(truncatingIfNeeded: value))
    }

    mutating func append(_ other: [UInt8]) {
        bytes.append(contentsOf: other)
    }
}

/// Bounds-checked big-endian reader. Every read that would run past `end`
/// throws instead of trapping: the bytes come from the network, and a length
/// field that lies must end the handshake, not the process.
struct TLSByteReader {
    let bytes: [UInt8]
    private(set) var offset: Int
    let end: Int
    /// What is being read, for the error message.
    let context: String

    init(_ bytes: [UInt8], context: String, from start: Int = 0, to limit: Int? = nil) {
        let startOffset = max(0, start)
        let wanted = limit ?? bytes.count
        self.bytes = bytes
        self.context = context
        self.offset = startOffset
        self.end = min(max(wanted, startOffset), bytes.count)
    }

    var remaining: Int { end - offset }
    var isAtEnd: Bool { offset >= end }

    mutating func u8() throws -> Int {
        try need(1)
        let value = Int(bytes[offset])
        offset += 1
        return value
    }

    mutating func u16() throws -> Int {
        try need(2)
        let value = TLSWire.u16(bytes, offset)
        offset += 2
        return value
    }

    mutating func u24() throws -> Int {
        try need(3)
        let value = TLSWire.u24(bytes, offset)
        offset += 3
        return value
    }

    mutating func take(_ count: Int) throws -> [UInt8] {
        try need(count)
        let out = Array(bytes[offset..<(offset + count)])
        offset += count
        return out
    }

    mutating func skip(_ count: Int) throws {
        try need(count)
        offset += count
    }

    private func need(_ count: Int) throws {
        if count < 0 || offset + count > end {
            throw MythaiaError.tls("malformed \(context)")
        }
    }
}

/// Small shared helpers for the TLS code.
enum TLSWire {
    static func u16(_ bytes: [UInt8], _ index: Int) -> Int {
        let high = Int(bytes[index]) << 8
        let low = Int(bytes[index + 1])
        return high | low
    }

    static func u24(_ bytes: [UInt8], _ index: Int) -> Int {
        let high = Int(bytes[index]) << 16
        let middle = Int(bytes[index + 1]) << 8
        let low = Int(bytes[index + 2])
        return high | middle | low
    }

    static func u16Bytes(_ value: Int) -> [UInt8] {
        return [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    /// Comparison whose time depends only on the length, not on where the
    /// inputs first differ: Finished values and MACs are compared with it.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var difference: UInt8 = 0
        for index in 0..<a.count {
            difference |= a[index] ^ b[index]
        }
        return difference == 0
    }

    /// Bytes from the system's secure generator.
    static func randomBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        if count == 0 { return out }
        let status = out.withUnsafeMutableBytes { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        if status != errSecSuccess {
            // SecRandomCopyBytes does not fail in practice; the system
            // generator is the same source underneath.
            var generator = SystemRandomNumberGenerator()
            for index in 0..<count {
                out[index] = UInt8.random(in: UInt8.min...UInt8.max, using: &generator)
            }
        }
        return out
    }

    /// A 16-bit codepoint the way the RFCs write it, "0x1301".
    static func codepoint(_ value: Int) -> String {
        let digits = String(value & 0xFFFF, radix: 16)
        let padding = String(repeating: "0", count: max(0, 4 - digits.count))
        return "0x" + padding + digits
    }

    static func hex(_ bytes: [UInt8]) -> String {
        let digits = Array("0123456789abcdef")
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return out
    }

    /// The 12-byte AEAD nonce: the IV with the 64-bit sequence number XORed
    /// into its last eight bytes (RFC 8446 §5.3).
    static func xorNonce(_ iv: [UInt8], _ sequence: UInt64) -> [UInt8] {
        var nonce = iv
        let base = nonce.count - 8
        for index in 0..<8 {
            let shift = UInt64((7 - index) * 8)
            let byte = UInt8(truncatingIfNeeded: sequence >> shift)
            nonce[base + index] ^= byte
        }
        return nonce
    }
}

/// A TLS alert as a person can read it.
enum TLSAlert {
    static func describe(level: Int, description: Int) -> String {
        let name: String
        switch description {
        case 0: name = "close_notify"
        case 10: name = "unexpected_message"
        case 20: name = "bad_record_mac"
        case 40: name = "handshake_failure"
        case 42: name = "bad_certificate"
        case 43: name = "unsupported_certificate"
        case 45: name = "certificate_expired"
        case 46: name = "certificate_unknown"
        case 47: name = "illegal_parameter"
        case 48: name = "unknown_ca"
        case 50: name = "decode_error"
        case 51: name = "decrypt_error"
        case 70: name = "protocol_version"
        case 71: name = "insufficient_security"
        case 80: name = "internal_error"
        case 86: name = "inappropriate_fallback"
        case 90: name = "user_canceled"
        case 109: name = "missing_extension"
        case 110: name = "unsupported_extension"
        case 112: name = "unrecognized_name"
        case 116: name = "certificate_required"
        case 120: name = "no_application_protocol"
        default: name = "alert \(description)"
        }
        let kind = level == 1 ? "warning" : "fatal"
        return "\(kind) \(name)"
    }
}

/// A flag set once from any thread, read from any other.
final class TLSOnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// The handshake's deadline.
///
/// A server that takes the connection and then says nothing (a filter
/// dropping the hello, a stalled path) would otherwise hold the dial, and
/// whoever waits on it, for good. The watchdog closes the stream from the
/// outside, which is what wakes a receive with nothing to read; the failure
/// that causes is reported as the timeout it is.
enum TLSHandshakeDeadline {
    static func run<T>(
        on stream: ByteStream,
        seconds: Double,
        what: String,
        _ body: () async throws -> T
    ) async throws -> T {
        let expired = TLSOnceFlag()
        let nanoseconds = UInt64(seconds * 1_000_000_000)
        let watchdog = Task {
            do {
                try await Task.sleep(nanoseconds: nanoseconds)
            } catch {
                return
            }
            expired.set()
            stream.close()
        }
        defer { watchdog.cancel() }
        do {
            return try await body()
        } catch {
            if expired.isSet {
                throw MythaiaError.timeout(what)
            }
            throw error
        }
    }
}
