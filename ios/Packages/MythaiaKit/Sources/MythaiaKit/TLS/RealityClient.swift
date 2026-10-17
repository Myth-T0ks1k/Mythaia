import CryptoKit
import Foundation

/// REALITY: a TLS 1.3 handshake that authenticates the client to the server
/// inside the ClientHello, and the server to the client inside its
/// certificate, while looking like an ordinary handshake with the site
/// named in SNI.
///
/// - The client's X25519 key share also serves an ECDH with the server's
///   static REALITY key; HKDF over that with the hello's random gives the
///   auth key.
/// - The first 16 bytes of the session id (version, time, short id) are
///   sealed with AES-GCM under the auth key, keyed by the random and bound to
///   the whole hello.
/// - The server, having recognised the client, answers with a temporary
///   Ed25519 certificate whose signature is HMAC-SHA512(auth key, its public
///   key); any other certificate means the client reached the real site, and
///   the handshake fails.
///
/// Spider mode (browsing the real site after a failed check, as Xray does)
/// is not done; the hybrid X25519MLKEM768 share is not offered, as CryptoKit
/// has no ML-KEM before iOS 26.
public enum RealityClient {
    /// How long a server gets to finish its side of the handshake.
    static let handshakeTimeout: Double = 20

    /// The version the session id announces: 26.4.25.
    static let protocolVersion: [UInt8] = [26, 4, 25, 0]

    /// Runs the REALITY handshake over `stream`, which the returned session
    /// then owns. On failure the stream is closed.
    public static func handshake(
        over stream: ByteStream,
        configuration: RealityConfiguration,
        alpn: [String]
    ) async throws -> ByteStream {
        return try await handshake(
            over: stream,
            serverName: configuration.serverName,
            publicKey: Array(configuration.publicKey),
            shortId: Array(configuration.shortId),
            fingerprint: configuration.fingerprint,
            alpn: alpn
        )
    }

    static func handshake(
        over stream: ByteStream,
        serverName: String,
        publicKey: [UInt8],
        shortId: [UInt8],
        fingerprint: TlsFingerprint,
        alpn: [String],
        now: Date = Date()
    ) async throws -> TLSSessionStream {
        do {
            return try await TLSHandshakeDeadline.run(on: stream, seconds: handshakeTimeout, what: "REALITY handshake") {
                try await performHandshake(
                    over: stream,
                    serverName: serverName,
                    publicKey: publicKey,
                    shortId: shortId,
                    fingerprint: fingerprint,
                    alpn: alpn,
                    now: now
                )
            }
        } catch {
            stream.close()
            throw error
        }
    }

    private static func performHandshake(
        over stream: ByteStream,
        serverName: String,
        publicKey: [UInt8],
        shortId: [UInt8],
        fingerprint: TlsFingerprint,
        alpn: [String],
        now: Date
    ) async throws -> TLSSessionStream {
        if publicKey.count != 32 {
            throw MythaiaError.invalidConfiguration("the REALITY public key must be 32 bytes")
        }
        if shortId.count > 8 {
            throw MythaiaError.invalidConfiguration("the REALITY short ID is longer than 8 bytes")
        }

        let random = TLSWire.randomBytes(32)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let x25519 = TLSKeyShare.x25519(ephemeral)
        let p256 = TLSKeyShare.p256(P256.KeyAgreement.PrivateKey())
        let resolved = TlsClientHelloBuilder.resolveFingerprint(fingerprint, random: random)
        let protocols: [String]? = alpn.isEmpty ? nil : alpn

        let sharedSecret = try X25519Crypto.agree(ephemeral, peerPublicKey: publicKey)
        let authKey = deriveAuthKey(sharedSecret: sharedSecret, random: random)
        let timestamp = UInt32(truncatingIfNeeded: Int64(now.timeIntervalSince1970))
        let plaintext = sessionIdPlaintext(shortId: shortId, timestamp: timestamp)

        // The hello is built twice from the same inputs: first with a zero
        // session id, as the AAD the server rebuilds, then with the sealed
        // one. Everything else in it is a function of the random and the
        // keys, so both builds agree byte for byte elsewhere.
        func build(_ sessionId: [UInt8]) -> [UInt8] {
            return TlsClientHelloBuilder.buildRawClientHello(
                fingerprint: resolved,
                random: random,
                sessionId: sessionId,
                serverName: serverName,
                publicKey: x25519.publicKey,
                alpn: protocols,
                p256PublicKey: p256.publicKey
            )
        }
        let helloForAAD = build([UInt8](repeating: 0, count: 32))
        let sealedSessionId = try sealSessionId(plaintext, authKey: authKey, random: random, aad: helloForAAD)
        let hello = build(sealedSessionId)
        if !TlsClientHelloBuilder.offersTls13(hello) {
            throw MythaiaError.unsupported("REALITY needs TLS 1.3, and the \(resolved.rawValue) fingerprint offers only TLS 1.2")
        }

        let offered = TlsClientHelloBuilder.keyShareGroups(in: hello)
        let shares = [x25519, p256].filter { offered.contains($0.group) }
        let driver = TLSHandshakeDriver(
            stream: stream,
            clientHello: hello,
            keyShares: shares,
            authentication: .reality(authKey: authKey),
            minVersion: nil,
            maxVersion: nil,
            allowsHelloRetry: false
        )
        return try await driver.run()
    }

    // MARK: Client authentication

    /// HKDF-SHA256 over the ECDH secret, salted with the first 20 bytes of the
    /// hello's random, info "REALITY": the 32-byte auth key.
    static func deriveAuthKey(sharedSecret: [UInt8], random: [UInt8]) -> [UInt8] {
        let salt = Array(random[0..<20])
        let prk = Tls13Crypto.hkdfExtract(.sha256, salt: salt, ikm: sharedSecret)
        return Tls13Crypto.hkdfExpand(.sha256, prk: prk, info: Array("REALITY".utf8), length: 32)
    }

    /// The 16 bytes sealed into the session id: version(4), Unix time in
    /// seconds(4), short id zero-padded to 8.
    static func sessionIdPlaintext(shortId: [UInt8], timestamp: UInt32) -> [UInt8] {
        var plaintext = protocolVersion
        plaintext.append(UInt8(truncatingIfNeeded: timestamp >> 24))
        plaintext.append(UInt8(truncatingIfNeeded: timestamp >> 16))
        plaintext.append(UInt8(truncatingIfNeeded: timestamp >> 8))
        plaintext.append(UInt8(truncatingIfNeeded: timestamp))
        var id = [UInt8](repeating: 0, count: 8)
        for index in 0..<min(shortId.count, 8) {
            id[index] = shortId[index]
        }
        plaintext.append(contentsOf: id)
        return plaintext
    }

    /// AES-256-GCM of the plaintext under the auth key, nonce random[20..<32],
    /// the zero-session-id hello as AAD: 16 bytes of ciphertext and the
    /// 16-byte tag, the 32-byte session id.
    static func sealSessionId(_ plaintext: [UInt8], authKey: [UInt8], random: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        let nonce = Array(random[20..<32])
        do {
            return try TLSAEAD.aesGCM.seal(key: SymmetricKey(data: authKey), nonce: nonce, plaintext: plaintext, aad: aad)
        } catch {
            throw MythaiaError.tls("could not seal the REALITY session id")
        }
    }

    // MARK: Server authentication

    /// Whether the first certificate of a Certificate message body is the
    /// server's REALITY certificate: Ed25519, signed with
    /// HMAC-SHA512(auth key, public key).
    ///
    /// False, not an error, for anything else: that is the real site's
    /// certificate, meaning the server did not recognise us.
    static func verifyRealityCertificate(_ certificateBody: [UInt8], authKey: [UInt8]) -> Bool {
        guard let der = extractFirstCertificate(certificateBody),
              let components = extractEd25519Components(der) else {
            return false
        }
        let expected = Array(HMAC<SHA512>.authenticationCode(for: components.publicKey, using: SymmetricKey(data: authKey)))
        return TLSWire.constantTimeEqual(expected, components.signature)
    }

    /// The first DER certificate of a TLS 1.3 Certificate message body:
    /// contextLen(1) + context + listLen(3) + [certLen(3) + DER + extLen(2) + ext]*.
    static func extractFirstCertificate(_ body: [UInt8]) -> [UInt8]? {
        if body.count < 4 { return nil }
        var offset = 1 + Int(body[0])
        if offset + 3 > body.count { return nil }
        offset += 3
        if offset + 3 > body.count { return nil }
        let length = TLSWire.u24(body, offset)
        offset += 3
        if offset + length > body.count { return nil }
        return Array(body[offset..<(offset + length)])
    }

    /// The Ed25519 public key and the signature value of a DER certificate,
    /// or nil when it is not Ed25519.
    ///
    /// The key is found by the OID 1.3.101.112 (06 03 2b 65 70) followed by
    /// the 33-byte BIT STRING header (03 21 00) inside the TBSCertificate; the
    /// signature is the BIT STRING after the signatureAlgorithm.
    static func extractEd25519Components(_ der: [UInt8]) -> (publicKey: [UInt8], signature: [UInt8])? {
        var offset = 0
        guard parseDERSequence(der, &offset) != nil else { return nil }
        let tbsStart = offset
        guard let tbsContentLength = parseDERSequence(der, &offset) else { return nil }
        let tbsEnd = offset + tbsContentLength
        if tbsEnd > der.count { return nil }

        let oid: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x70]
        var publicKey: [UInt8]?
        let searchEnd = tbsEnd - (oid.count + 3 + 32)
        var index = tbsStart
        while index <= searchEnd {
            var match = true
            for position in 0..<oid.count where der[index + position] != oid[position] {
                match = false
                break
            }
            if match {
                let afterOID = index + oid.count
                if der[afterOID] == 0x03 && der[afterOID + 1] == 0x21 && der[afterOID + 2] == 0x00 {
                    publicKey = Array(der[(afterOID + 3)..<(afterOID + 3 + 32)])
                    break
                }
            }
            index += 1
        }
        guard let key = publicKey else { return nil }

        offset = tbsEnd
        if offset >= der.count { return nil }
        guard let algorithmLength = parseDERSequence(der, &offset) else { return nil }
        offset += algorithmLength
        if offset >= der.count || der[offset] != 0x03 { return nil }
        offset += 1
        guard let signatureLength = parseDERLength(der, &offset) else { return nil }
        if signatureLength < 1 || offset + signatureLength > der.count { return nil }
        // Past the BIT STRING's unused-bits byte.
        let signature = Array(der[(offset + 1)..<(offset + signatureLength)])
        return (key, signature)
    }

    /// A SEQUENCE tag at `offset`: moves past tag and length and returns the
    /// content length.
    private static func parseDERSequence(_ data: [UInt8], _ offset: inout Int) -> Int? {
        if offset >= data.count || data[offset] != 0x30 { return nil }
        offset += 1
        return parseDERLength(data, &offset)
    }

    /// A DER length, short or long form (up to three length bytes).
    private static func parseDERLength(_ data: [UInt8], _ offset: inout Int) -> Int? {
        if offset >= data.count { return nil }
        let first = Int(data[offset])
        offset += 1
        if first < 0x80 { return first }
        let count = first & 0x7F
        if count == 0 || count > 3 || offset + count > data.count { return nil }
        var length = 0
        for _ in 0..<count {
            length = (length << 8) | Int(data[offset])
            offset += 1
        }
        return length
    }
}
