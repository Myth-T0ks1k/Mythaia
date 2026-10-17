import Foundation

/// Handshake traffic keys of both directions, and the secrets they come
/// from (the Finished keys are expanded from the secrets).
struct TlsHandshakeKeys {
    let clientKey: [UInt8]
    let clientIV: [UInt8]
    let serverKey: [UInt8]
    let serverIV: [UInt8]
    let clientTrafficSecret: [UInt8]
    let serverTrafficSecret: [UInt8]
}

/// Application traffic keys of both directions. The secrets are kept as well:
/// a KeyUpdate derives the next keys from them.
struct TlsApplicationKeys {
    let clientKey: [UInt8]
    let clientIV: [UInt8]
    let serverKey: [UInt8]
    let serverIV: [UInt8]
    let clientTrafficSecret: [UInt8]
    let serverTrafficSecret: [UInt8]
}

/// The TLS 1.3 key schedule for one negotiated suite.
struct Tls13KeyDerivation {
    let cipherSuite: Int
    let suite: Tls13Suite

    /// Throws for a suite this client did not offer.
    init(cipherSuite: Int) throws {
        guard let suite = Tls13Suite.forCode(cipherSuite) else {
            let text = TLSWire.codepoint(cipherSuite)
            throw MythaiaError.tls("server chose cipher suite \(text), which this client does not offer for TLS 1.3")
        }
        self.cipherSuite = cipherSuite
        self.suite = suite
    }

    var hashLength: Int { suite.hash.length }
    var keyLength: Int { suite.keyLength }

    /// The handshake secret and the handshake traffic keys, from the (EC)DHE
    /// shared secret and the transcript through the ServerHello.
    func deriveHandshakeKeys(sharedSecret: [UInt8], transcript: [UInt8]) -> (handshakeSecret: [UInt8], keys: TlsHandshakeKeys) {
        let hash = suite.hash
        let handshakeSecret = Tls13Crypto.handshakeSecret(hash, sharedSecret: sharedSecret)
        let transcriptHash = hash.digest(transcript)
        let clientSecret = Tls13Crypto.deriveSecret(hash, secret: handshakeSecret, label: "c hs traffic", transcriptHash: transcriptHash)
        let serverSecret = Tls13Crypto.deriveSecret(hash, secret: handshakeSecret, label: "s hs traffic", transcriptHash: transcriptHash)
        let client = Tls13Crypto.trafficKeys(suite, secret: clientSecret)
        let server = Tls13Crypto.trafficKeys(suite, secret: serverSecret)
        let keys = TlsHandshakeKeys(
            clientKey: client.key,
            clientIV: client.iv,
            serverKey: server.key,
            serverIV: server.iv,
            clientTrafficSecret: clientSecret,
            serverTrafficSecret: serverSecret
        )
        return (handshakeSecret, keys)
    }

    /// The application traffic keys, from the transcript through the server
    /// Finished.
    func deriveApplicationKeys(handshakeSecret: [UInt8], fullTranscript: [UInt8]) -> TlsApplicationKeys {
        let hash = suite.hash
        let masterSecret = Tls13Crypto.masterSecret(hash, handshakeSecret: handshakeSecret)
        let transcriptHash = hash.digest(fullTranscript)
        let clientSecret = Tls13Crypto.deriveSecret(hash, secret: masterSecret, label: "c ap traffic", transcriptHash: transcriptHash)
        let serverSecret = Tls13Crypto.deriveSecret(hash, secret: masterSecret, label: "s ap traffic", transcriptHash: transcriptHash)
        let client = Tls13Crypto.trafficKeys(suite, secret: clientSecret)
        let server = Tls13Crypto.trafficKeys(suite, secret: serverSecret)
        return TlsApplicationKeys(
            clientKey: client.key,
            clientIV: client.iv,
            serverKey: server.key,
            serverIV: server.iv,
            clientTrafficSecret: clientSecret,
            serverTrafficSecret: serverSecret
        )
    }

    func computeFinishedVerifyData(trafficSecret: [UInt8], transcript: [UInt8]) -> [UInt8] {
        return Tls13Crypto.computeFinished(suite.hash, trafficSecret: trafficSecret, transcript: transcript)
    }

    func transcriptHash(_ messages: [UInt8]) -> [UInt8] {
        return suite.hash.digest(messages)
    }
}
