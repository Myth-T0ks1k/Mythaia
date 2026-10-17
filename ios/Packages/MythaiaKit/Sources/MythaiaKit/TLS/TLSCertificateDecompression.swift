import Compression
import Foundation

/// Inflates a CompressedCertificate (RFC 8879).
///
/// The fingerprints offer certificate compression because the browsers they
/// copy do: Chrome asks for Brotli, Safari for zlib, Firefox for both. A
/// server that honours it (Cloudflare and Google do) sends no plain
/// Certificate at all, so without this there is nothing to verify. The
/// system's libcompression does both formats.
enum TLSCertificateDecompression {

    /// The Certificate message body inside `body` (algorithm(2) +
    /// uncompressed_length(3) + compressed_length(3) + data), or nil when it
    /// cannot be inflated.
    static func decompress(_ body: [UInt8]) -> [UInt8]? {
        if body.count < 8 { return nil }
        let algorithm = TLSWire.u16(body, 0)
        let uncompressedLength = TLSWire.u24(body, 2)
        let compressedLength = TLSWire.u24(body, 5)
        if 8 + compressedLength > body.count { return nil }
        if uncompressedLength <= 0 || uncompressedLength > (1 << 24) { return nil }
        let compressed = Array(body[8..<(8 + compressedLength)])

        switch algorithm {
        case 0x0001:
            // RFC 8879 means the zlib format (RFC 1950): a two-byte header in
            // front of raw DEFLATE, which is what libcompression's ZLIB
            // decodes. The Adler-32 trailer is not checked; the transcript
            // and the certificate's own signature cover the content anyway.
            if compressed.count < 3 { return nil }
            let cmf = Int(compressed[0])
            let flg = Int(compressed[1])
            let headerValid = (cmf & 0x0F) == 8 && (cmf * 256 + flg) % 31 == 0 && (flg & 0x20) == 0
            if !headerValid { return nil }
            return inflate(Array(compressed[2...]), algorithm: COMPRESSION_ZLIB, size: uncompressedLength)
        case 0x0002:
            return inflate(compressed, algorithm: COMPRESSION_BROTLI, size: uncompressedLength)
        default:
            Log.warning("TLS: unknown certificate compression algorithm \(TLSWire.codepoint(algorithm))")
            return nil
        }
    }

    private static func inflate(_ input: [UInt8], algorithm: compression_algorithm, size: Int) -> [UInt8]? {
        if input.isEmpty { return nil }
        var output = [UInt8](repeating: 0, count: size)
        let written = output.withUnsafeMutableBufferPointer { destination -> Int in
            return input.withUnsafeBufferPointer { source -> Int in
                guard let destinationBase = destination.baseAddress, let sourceBase = source.baseAddress else {
                    return 0
                }
                return compression_decode_buffer(destinationBase, size, sourceBase, input.count, nil, algorithm)
            }
        }
        if written <= 0 { return nil }
        return Array(output[0..<written])
    }
}
