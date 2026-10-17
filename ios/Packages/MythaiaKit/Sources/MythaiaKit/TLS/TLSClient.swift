import CryptoKit
import Foundation

/// Our own TLS 1.3 client, with a browser-fingerprinted ClientHello, over any
/// `ByteStream`: a TCP connection, or a stream through the previous hop of a
/// chain, where the system's TLS cannot reach.
///
/// TLS 1.3 only. When a server picks TLS 1.2 the handshake fails with "server
/// chose TLS 1.2": the TLS 1.2 record layer needs AES-CBC for half of the
/// suites the fingerprints offer, and CryptoKit has no CBC. A server reached
/// directly can use the system TLS instead (`SystemTLSStream`), which speaks
/// both. Not supported either: ECH, session resumption and 0-RTT.
public enum TLSClient {
    /// How long a server gets to finish its side of the handshake.
    static let handshakeTimeout: Double = 20

    /// Runs a handshake over `stream`, which the returned session then owns.
    /// On failure the stream is closed. The ClientHello goes out whole.
    public static func handshake(
        over stream: ByteStream,
        options: TLSClientOptions,
        fingerprint: TlsFingerprint
    ) async throws -> TLSSessionStream {
        return try await handshake(over: stream, options: options, fingerprint: fingerprint, fragment: nil)
    }

    /// The same, with the ClientHello record cut into several records sent
    /// with pauses between them, as `fragment` says (nil or switched off: in
    /// one piece).
    ///
    /// Only a direct dial is worth fragmenting: that is the connection a
    /// filter on the path can read. Inside another proxy there is no path to
    /// hide it from. `FragmentPolicy.effective(for:)` gives the setting that
    /// applies to a server.
    public static func handshake(
        over stream: ByteStream,
        options: TLSClientOptions,
        fingerprint: TlsFingerprint,
        fragment: FragmentSettings?
    ) async throws -> TLSSessionStream {
        let applied: FragmentSettings? = (fragment?.isEnabled ?? false) ? fragment : nil
        do {
            return try await TLSHandshakeDeadline.run(on: stream, seconds: handshakeTimeout, what: "TLS handshake") {
                try await performHandshake(over: stream, options: options, fingerprint: fingerprint, fragment: applied)
            }
        } catch {
            stream.close()
            throw error
        }
    }

    private static func performHandshake(
        over stream: ByteStream,
        options: TLSClientOptions,
        fingerprint: TlsFingerprint,
        fragment: FragmentSettings?
    ) async throws -> TLSSessionStream {
        if let maximum = options.maxVersion, maximum != .tls13 {
            throw MythaiaError.unsupported("a TLS 1.2 maximum here; this TLS client speaks TLS 1.3 only")
        }

        let random = TLSWire.randomBytes(32)
        let sessionId = TLSWire.randomBytes(32)
        let x25519 = TLSKeyShare.x25519(Curve25519.KeyAgreement.PrivateKey())
        let p256 = TLSKeyShare.p256(P256.KeyAgreement.PrivateKey())
        let resolved = TlsClientHelloBuilder.resolveFingerprint(fingerprint, random: random)
        let alpn: [String]? = options.alpn.isEmpty ? nil : options.alpn

        let hello = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: resolved,
            random: random,
            sessionId: sessionId,
            serverName: options.serverName,
            publicKey: x25519.publicKey,
            alpn: alpn,
            // The hybrid share would only make the hello bigger: CryptoKit has
            // no ML-KEM before iOS 26.
            omitPQKeyShares: true,
            p256PublicKey: p256.publicKey
        )
        if !TlsClientHelloBuilder.offersTls13(hello) {
            throw MythaiaError.unsupported("the \(resolved.rawValue) fingerprint offers only TLS 1.2; pick another fingerprint")
        }

        // Only the shares the fingerprint actually put in the hello count;
        // Chrome's, for one, carries no P-256 share.
        let offered = TlsClientHelloBuilder.keyShareGroups(in: hello)
        let shares = [x25519, p256].filter { offered.contains($0.group) }

        let driver = TLSHandshakeDriver(
            stream: stream,
            clientHello: hello,
            keyShares: shares,
            authentication: .certificate(
                serverName: options.serverName,
                allowInsecure: options.allowInsecure,
                pins: options.pinnedCertSHA256
            ),
            minVersion: options.minVersion,
            maxVersion: options.maxVersion,
            allowsHelloRetry: true,
            fragment: fragment
        )
        return try await driver.run()
    }
}
