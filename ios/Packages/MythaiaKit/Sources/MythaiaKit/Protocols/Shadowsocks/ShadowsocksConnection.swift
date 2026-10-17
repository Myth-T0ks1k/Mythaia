import Foundation

/// A Shadowsocks AEAD TCP stream.
///
/// The address header is prepended to the first write (encrypted as part of
/// the stream); an empty first write therefore emits a chunk holding just the
/// header, which is how the dialer flushes it at connect time. Shadowsocks
/// has no response header.
final class ShadowsocksConnection: ByteStream, @unchecked Sendable {
    private let inner: ByteStream
    private let writer: ShadowsocksAEADWriter
    private let reader: ShadowsocksAEADReader
    private let lock = NSLock()
    private var addressHeader: Data?

    init(_ inner: ByteStream, cipher: ShadowsocksCipher, masterKey: Data, addressHeader: Data) {
        self.inner = inner
        self.writer = ShadowsocksAEADWriter(cipher: cipher, masterKey: masterKey)
        self.reader = ShadowsocksAEADReader(cipher: cipher, masterKey: masterKey)
        self.addressHeader = addressHeader
    }

    func send(_ data: Data) async throws {
        let encrypted = try seal(data)
        if encrypted.isEmpty { return }
        try await inner.send(encrypted)
    }

    func receive() async throws -> Data? {
        while true {
            guard let data = try await inner.receive() else { return nil }
            if data.isEmpty { continue }
            let plaintext = try reader.open(data)
            // Empty means the reader needs more bytes for a whole chunk.
            if !plaintext.isEmpty { return plaintext }
        }
    }

    func close() {
        inner.close()
    }

    private func seal(_ data: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        var plaintext = Data()
        if let header = addressHeader {
            addressHeader = nil
            plaintext.append(header)
        }
        plaintext.append(data)
        return try writer.seal(plaintext)
    }
}
