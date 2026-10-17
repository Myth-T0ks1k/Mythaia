import Foundation

/// VMess body framing: a two-byte length, then one AEAD-sealed chunk, repeated.
///
/// With ChunkMasking the length is XORed with a SHAKE128 stream seeded by the
/// body IV, so an observer sees no plaintext sizes; with GlobalPadding the
/// same stream also decides how many random bytes follow each chunk, so the
/// sizes it does see mean nothing either.
///
/// Draw order is part of the wire format. v2ray's AuthenticationWriter.seal
/// calls NextPaddingLen() before sizeParser.Encode(), and its reader does the
/// same, so each chunk consumes the padding draw FIRST and the mask draw
/// second — two separate two-byte reads off the shared stream. It has to be
/// that way round: the encoded length includes the padding, so the padding
/// must already be known. Deriving both from one draw, or taking them in the
/// other order, desynchronises against a real server on the very first chunk
/// while still round-tripping perfectly against itself.
///
/// Both sides advance in lockstep, which is why a draw must never be taken
/// speculatively — decode() peeks on a copy and only consumes once the whole
/// chunk is present.
final class VmessChunkStream {
    /// GlobalPadding draws its length from the mask modulo this.
    private static let maxPadding = 64

    /// The largest chunk the two-byte length field can describe, and so the
    /// largest a peer may send. sing-box frames 16384-byte chunks and Xray
    /// reads whatever the field says; a tighter cap rejected a valid stream
    /// as "not plausible" on its first large chunk.
    private static let maxWireChunk = 0xFFFF

    /// What this side writes per chunk. Kept well under the field's maximum
    /// so the chunk fits any reader's buffer.
    private static let writeChunk = 16 * 1024 - 1

    enum Decoded: Equatable {
        /// Not enough bytes yet; call again once more have arrived.
        case needMore
        /// The peer sent its terminating empty chunk.
        case endOfStream
        case chunk(payload: Data, consumed: Int)
    }

    private let key: Data
    private let iv: [UInt8]
    private let security: VmessSecurity
    private let masking: Bool
    private let globalPadding: Bool
    private var shake: Shake128?
    private var count = 0
    private lazy var chachaKey: Data = VmessChunkStream.stretchChaChaKey(key)

    init(key: Data, iv: Data, security: VmessSecurity, masking: Bool, globalPadding: Bool) {
        self.key = key
        self.iv = [UInt8](iv)
        self.security = security
        self.masking = masking
        self.globalPadding = globalPadding
        if masking || globalPadding {
            self.shake = Shake128(seed: iv)
        } else {
            self.shake = nil
        }
    }

    /// The next two bytes of the shared stream, as an unsigned 16-bit value.
    /// Only called when the option that consumes it is on, so a caller never
    /// burns a draw the peer did not.
    private func nextDraw() -> Int {
        guard shake != nil else { return 0 }
        let bytes = shake!.squeeze(2)
        return (Int(bytes[0]) << 8) | Int(bytes[1])
    }

    /// The AEAD nonce for chunk `index`: a big-endian counter followed by ten
    /// bytes of the body IV.
    private func nonce(_ index: Int) -> Data {
        var out = [UInt8](repeating: 0, count: 12)
        out[0] = UInt8(truncatingIfNeeded: index >> 8)
        out[1] = UInt8(truncatingIfNeeded: index)
        for i in 2..<12 {
            out[i] = iv[i]
        }
        return Data(out)
    }

    /// ChaCha20-Poly1305 wants 32 bytes; VMess supplies 16, and the protocol
    /// stretches them as MD5(key) ‖ MD5(MD5(key)).
    static func stretchChaChaKey(_ key: Data) -> Data {
        let first = DigestHelper.md5(key)
        var out = first
        out.append(DigestHelper.md5(first))
        return out
    }

    private func seal(_ plaintext: Data, _ index: Int) throws -> Data {
        switch security {
        case .aes128Gcm:
            return try RawAEAD.aesGcmSeal(key: key, nonce: nonce(index), plaintext: plaintext)
        case .chacha20Poly1305:
            return try RawAEAD.chaChaPolySeal(key: chachaKey, nonce: nonce(index), plaintext: plaintext)
        case .plain, .zero:
            return plaintext
        }
    }

    private func open(_ ciphertext: Data, _ index: Int) -> Data? {
        switch security {
        case .aes128Gcm:
            return try? RawAEAD.aesGcmOpen(key: key, nonce: nonce(index), sealed: ciphertext)
        case .chacha20Poly1305:
            return try? RawAEAD.chaChaPolyOpen(key: chachaKey, nonce: nonce(index), sealed: ciphertext)
        case .plain, .zero:
            return ciphertext
        }
    }

    private var tagSize: Int {
        switch security {
        case .aes128Gcm, .chacha20Poly1305: return 16
        case .plain, .zero: return 0
        }
    }

    /// The most plaintext one chunk carries, leaving room for the tag and for
    /// the largest padding the mask stream can ask for.
    private var payloadPerChunk: Int {
        return VmessChunkStream.writeChunk - tagSize - VmessChunkStream.maxPadding
    }

    /// `plaintext` as one or more framed chunks, ready for the wire.
    ///
    /// Nothing in means nothing out: an empty chunk is the end-of-stream
    /// marker, so writing one here would close the stream by accident. Use
    /// `encodeTerminator` when that is what is meant.
    func encode(_ plaintext: Data) throws -> Data {
        if plaintext.isEmpty { return Data() }
        let bytes = [UInt8](plaintext)
        var out = Data()
        var offset = 0
        while offset < bytes.count {
            let take = min(payloadPerChunk, bytes.count - offset)
            try writeChunk(&out, Data(bytes[offset..<(offset + take)]))
            offset += take
        }
        return out
    }

    /// The empty chunk that tells the peer the stream is finished.
    func encodeTerminator() throws -> Data {
        var out = Data()
        try writeChunk(&out, Data())
        return out
    }

    private func writeChunk(_ out: inout Data, _ plaintext: Data) throws {
        // Padding draw first, then the mask draw — the order the peer reads
        // them in. See the class doc.
        let paddingLength = globalPadding ? nextDraw() % VmessChunkStream.maxPadding : 0
        let mask = masking ? nextDraw() : 0

        let sealed = try seal(plaintext, count)
        let onWire = sealed.count + paddingLength
        let length = masking ? (onWire ^ mask) : onWire

        out.append(UInt8(truncatingIfNeeded: length >> 8))
        out.append(UInt8(truncatingIfNeeded: length))
        out.append(sealed)
        if paddingLength > 0 {
            out.append(CryptoRandom.bytes(paddingLength))
        }
        count += 1
    }

    func decode(_ input: Data, from: Int) throws -> Decoded {
        return try decode([UInt8](input), from: from)
    }

    /// Reads one chunk from `input` at `from`.
    ///
    /// The chunk counter and the mask stream only advance on a complete
    /// chunk, so a partial read can be retried with more bytes and lands in
    /// the same place.
    func decode(_ input: [UInt8], from: Int) throws -> Decoded {
        if input.count - from < 2 { return .needMore }

        // Peek on a copy: the stream must not advance unless the whole chunk
        // is here. The order matches writeChunk and the peer — padding, then
        // mask.
        var peek = shake
        var paddingLength = 0
        var mask = 0
        if globalPadding, peek != nil {
            let b = peek!.squeeze(2)
            paddingLength = ((Int(b[0]) << 8) | Int(b[1])) % VmessChunkStream.maxPadding
        }
        if masking, peek != nil {
            let b = peek!.squeeze(2)
            mask = (Int(b[0]) << 8) | Int(b[1])
        }

        let raw = (Int(input[from]) << 8) | Int(input[from + 1])
        let onWire = masking ? (raw ^ mask) : raw

        if onWire < paddingLength || onWire > VmessChunkStream.maxWireChunk {
            throw MythaiaError.protocolError("VMess: chunk length \(onWire) is not plausible")
        }
        if input.count - from - 2 < onWire { return .needMore }

        let sealedLength = onWire - paddingLength
        // An empty payload seals to exactly the tag, or to nothing at all
        // when the body is unencrypted. Either is the end-of-stream marker.
        if (tagSize > 0 && sealedLength == tagSize) || sealedLength == 0 {
            advanceDraws()
            return .endOfStream
        }

        let sealed = Data(input[(from + 2)..<(from + 2 + sealedLength)])
        guard let payload = open(sealed, count) else {
            throw MythaiaError.protocolError("VMess: chunk failed authentication")
        }
        advanceDraws()
        count += 1
        return .chunk(payload: payload, consumed: 2 + onWire)
    }

    /// Consumes exactly the draws `decode` peeked.
    private func advanceDraws() {
        if globalPadding { _ = nextDraw() }
        if masking { _ = nextDraw() }
    }
}
