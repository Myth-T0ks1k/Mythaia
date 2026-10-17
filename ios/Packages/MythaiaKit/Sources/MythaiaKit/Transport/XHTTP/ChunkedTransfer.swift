import Foundation

enum XHttpError: Error, LocalizedError, Equatable, TransportErrorConvertible {
    case setupFailed(String)
    case httpError(String)
    case connectionClosed

    var message: String {
        switch self {
        case .setupFailed(let reason):
            return "XHTTP setup failed: \(reason)"
        case .httpError(let reason):
            return "XHTTP HTTP error: \(reason)"
        case .connectionClosed:
            return "XHTTP connection closed"
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
}

/// Stateful decoder of chunked transfer encoding (RFC 9112 §7.1): bytes are
/// fed as they arrive and chunks taken out as they complete.
final class ChunkedTransferDecoder {
    /// The most that may wait for a chunk to complete, and so the largest
    /// chunk accepted. Without a cap, a body that was never chunked (a proxy
    /// that unchunked it, an error page) was buffered without end and the
    /// reader hung for ever on "need more".
    static let maxPendingBytes = 4 * 1024 * 1024

    /// A chunk size line is a few hex digits and maybe an extension; longer is not one.
    private static let maxSizeLine = 1024

    private var buffer: [UInt8] = []
    private(set) var isFinished = false

    init() {}

    func feed(_ data: Data) throws {
        if buffer.count + data.count > ChunkedTransferDecoder.maxPendingBytes {
            throw XHttpError.httpError("chunked body: more than \(ChunkedTransferDecoder.maxPendingBytes) bytes pending")
        }
        buffer.append(contentsOf: data)
    }

    /// The next chunk's payload without its framing; nil when it is not
    /// complete yet, and nil at the zero-length terminator (then isFinished).
    /// Throws when the bytes are not chunked encoding at all.
    func nextChunk() throws -> Data? {
        if isFinished { return nil }

        guard let lineEnd = findCRLF() else {
            if buffer.count > ChunkedTransferDecoder.maxSizeLine {
                throw XHttpError.httpError("chunked body: no chunk size line")
            }
            return nil
        }

        // The hex size, without any chunk extension after ";". A line that
        // is not one is a protocol error, not "need more": waiting on it
        // never ended.
        let sizeLine = String(decoding: buffer[0..<lineEnd], as: UTF8.self)
        let beforeExtension = sizeLine.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first ?? Substring("")
        let sizeText = beforeExtension.trimmingCharacters(in: .whitespaces)
        guard let chunkSize = Int64(sizeText, radix: 16) else {
            throw XHttpError.httpError("chunked body: bad chunk size line '\(String(sizeText.prefix(32)))'")
        }
        if chunkSize < 0 || chunkSize > Int64(ChunkedTransferDecoder.maxPendingBytes) {
            throw XHttpError.httpError("chunked body: chunk of \(chunkSize) bytes")
        }

        if chunkSize == 0 {
            isFinished = true
            // "0\r\n" and the empty line after it.
            let terminatorEnd = lineEnd + 4
            if buffer.count >= terminatorEnd {
                buffer.removeFirst(terminatorEnd)
            } else {
                buffer.removeAll()
            }
            return nil
        }

        let dataStart = lineEnd + 2
        let size = Int(chunkSize)
        let needed = dataStart + size + 2
        if buffer.count < needed { return nil }

        let chunk = Data(buffer[dataStart..<(dataStart + size)])
        buffer.removeFirst(needed)
        return chunk
    }

    private func findCRLF() -> Int? {
        if buffer.count < 2 { return nil }
        var i = 0
        while i < buffer.count - 1 {
            if buffer[i] == 0x0D && buffer[i + 1] == 0x0A { return i }
            i += 1
        }
        return nil
    }
}

/// Chunked transfer encoding (RFC 9112 §7.1).
enum ChunkedTransferEncoder {
    /// `data` as one chunk: `{hex size}\r\n{data}\r\n`. Never call it with
    /// nothing: an empty chunk is the terminator and ends the body.
    static func encode(_ data: Data) -> Data {
        var out = Data(String(data.count, radix: 16).utf8)
        out.append(contentsOf: [0x0D, 0x0A])
        out.append(data)
        out.append(contentsOf: [0x0D, 0x0A])
        return out
    }

    /// The zero-length terminator: `0\r\n\r\n`.
    static func encodeTerminator() -> Data {
        Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A])
    }
}
