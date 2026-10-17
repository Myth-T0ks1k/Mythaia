import CryptoKit
import Foundation

/// TLS 1.3 key schedule primitives (RFC 8446 §7.1), on CryptoKit's HMAC and
/// SHA-2. HKDF is written out over HMAC rather than taken from CryptoKit's
/// `HKDF` so the extract and expand steps are visible and separately tested
/// against RFC 8448.
enum Tls13Crypto {

    /// HKDF-Extract: PRK = HMAC(salt, IKM). An empty salt is a zero block of
    /// the hash length, which HMAC treats the same as an empty key.
    static func hkdfExtract(_ hash: TLSHash, salt: [UInt8], ikm: [UInt8]) -> [UInt8] {
        let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: hash.length) : salt
        return hash.hmac(key: effectiveSalt, data: ikm)
    }

    /// HKDF-Expand: T(1) || T(2) || ... truncated to `length`.
    static func hkdfExpand(_ hash: TLSHash, prk: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(length)
        var previous: [UInt8] = []
        var counter: UInt8 = 1
        while out.count < length {
            var input = previous
            input.append(contentsOf: info)
            input.append(counter)
            previous = hash.hmac(key: prk, data: input)
            let wanted = min(previous.count, length - out.count)
            out.append(contentsOf: previous[0..<wanted])
            counter = counter &+ 1
        }
        return out
    }

    /// HKDF-Expand-Label:
    /// `info = Length(2) || len || "tls13 " || Label || len || Context`.
    ///
    /// The label is raw bytes: TLS's own labels are ASCII, but an exporter
    /// label is whatever the protocol above chooses.
    static func hkdfExpandLabel(
        _ hash: TLSHash,
        secret: [UInt8],
        label: [UInt8],
        context: [UInt8],
        length: Int
    ) -> [UInt8] {
        let fullLabel = Array("tls13 ".utf8) + label
        var info = TLSByteWriter()
        info.u16(length)
        info.u8(fullLabel.count)
        info.append(fullLabel)
        info.u8(context.count)
        info.append(context)
        return hkdfExpand(hash, prk: secret, info: info.bytes, length: length)
    }

    static func hkdfExpandLabel(
        _ hash: TLSHash,
        secret: [UInt8],
        label: String,
        context: [UInt8],
        length: Int
    ) -> [UInt8] {
        return hkdfExpandLabel(hash, secret: secret, label: Array(label.utf8), context: context, length: length)
    }

    /// Derive-Secret(Secret, Label, Messages), with the messages already hashed.
    static func deriveSecret(_ hash: TLSHash, secret: [UInt8], label: String, transcriptHash: [UInt8]) -> [UInt8] {
        return hkdfExpandLabel(hash, secret: secret, label: label, context: transcriptHash, length: hash.length)
    }

    /// Derive-Secret(Secret, Label, Messages).
    static func deriveSecret(_ hash: TLSHash, secret: [UInt8], label: String, messages: [UInt8]) -> [UInt8] {
        return deriveSecret(hash, secret: secret, label: label, transcriptHash: hash.digest(messages))
    }

    /// Early Secret without a PSK: HKDF-Extract(0, 0).
    static func earlySecret(_ hash: TLSHash) -> [UInt8] {
        let zeros = [UInt8](repeating: 0, count: hash.length)
        return hkdfExtract(hash, salt: [], ikm: zeros)
    }

    /// Handshake Secret = HKDF-Extract(Derive-Secret(early, "derived", ""), (EC)DHE).
    static func handshakeSecret(_ hash: TLSHash, sharedSecret: [UInt8]) -> [UInt8] {
        let derived = deriveSecret(hash, secret: earlySecret(hash), label: "derived", messages: [])
        return hkdfExtract(hash, salt: derived, ikm: sharedSecret)
    }

    /// Master Secret = HKDF-Extract(Derive-Secret(handshake, "derived", ""), 0).
    static func masterSecret(_ hash: TLSHash, handshakeSecret: [UInt8]) -> [UInt8] {
        let derived = deriveSecret(hash, secret: handshakeSecret, label: "derived", messages: [])
        let zeros = [UInt8](repeating: 0, count: hash.length)
        return hkdfExtract(hash, salt: derived, ikm: zeros)
    }

    /// The record key and IV a traffic secret expands to.
    static func trafficKeys(_ suite: Tls13Suite, secret: [UInt8]) -> (key: [UInt8], iv: [UInt8]) {
        let key = hkdfExpandLabel(suite.hash, secret: secret, label: "key", context: [], length: suite.keyLength)
        let iv = hkdfExpandLabel(suite.hash, secret: secret, label: "iv", context: [], length: 12)
        return (key, iv)
    }

    /// The next generation of a traffic secret, for KeyUpdate (RFC 8446 §7.2).
    static func nextTrafficSecret(_ hash: TLSHash, secret: [UInt8]) -> [UInt8] {
        return hkdfExpandLabel(hash, secret: secret, label: "traffic upd", context: [], length: hash.length)
    }

    /// Finished `verify_data` (RFC 8446 §4.4.4): HMAC over the transcript hash
    /// with a key expanded from the sender's handshake traffic secret.
    static func computeFinished(_ hash: TLSHash, trafficSecret: [UInt8], transcript: [UInt8]) -> [UInt8] {
        let finishedKey = hkdfExpandLabel(hash, secret: trafficSecret, label: "finished", context: [], length: hash.length)
        return hash.hmac(key: finishedKey, data: hash.digest(transcript))
    }

    /// The message_hash stand-in for the first ClientHello once the server
    /// sends a HelloRetryRequest (RFC 8446 §4.4.1).
    static func messageHash(_ hash: TLSHash, clientHello: [UInt8]) -> [UInt8] {
        let digest = hash.digest(clientHello)
        var out: [UInt8] = [0xFE, 0x00, 0x00, UInt8(digest.count)]
        out.append(contentsOf: digest)
        return out
    }
}
