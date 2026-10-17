import CryptoKit
import Foundation
import Network
import Security

/// How a TLS client presents itself and decides whether to trust the server.
/// Shared by the system TLS stack (SystemTLSStream) and the own TLS 1.3
/// client the REALITY and chain paths need.
public struct TLSClientOptions {
    /// The SNI, and the name the certificate must carry.
    public var serverName: String
    public var alpn: [String]
    /// Accept any certificate. A pin, when there is one, still decides.
    public var allowInsecure: Bool
    /// SHA-256 digests of certificates the server may present (`pcs=`). A
    /// match is trusted without a certificate authority, a mismatch fails
    /// even a CA-valid chain; empty means system trust only.
    public var pinnedCertSHA256: [Data]
    public var minVersion: TlsVersion?
    public var maxVersion: TlsVersion?

    public init(serverName: String, alpn: [String] = [], allowInsecure: Bool = false,
                pinnedCertSHA256: [Data] = [], minVersion: TlsVersion? = nil, maxVersion: TlsVersion? = nil) {
        self.serverName = serverName
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.pinnedCertSHA256 = pinnedCertSHA256
        self.minVersion = minVersion
        self.maxVersion = maxVersion
    }
}

/// TLS straight over a new TCP connection, done by the system's TLS stack.
/// For servers that need no fingerprinted ClientHello and no REALITY.
public final class SystemTLSStream: ByteStream, @unchecked Sendable {
    private let connection: TransportNWConnection

    /// The ALPN protocol the server chose; nil when it chose none.
    public let negotiatedALPN: String?

    private init(connection: TransportNWConnection, negotiatedALPN: String?) {
        self.connection = connection
        self.negotiatedALPN = negotiatedALPN
    }

    /// Connects and completes the handshake within `timeout`.
    public static func connect(host: String, port: UInt16, options: TLSClientOptions, timeout: Double = 10) async throws -> SystemTLSStream {
        let tls = NWProtocolTLS.Options()
        configure(tls.securityProtocolOptions, options: options)
        let parameters = TransportNWConnection.outboundParameters(tls: tls, timeout: timeout)
        let connection = try TransportNWConnection(host: host, port: port, parameters: parameters, what: "TLS")
        do {
            try await connection.start(timeout: timeout)
        } catch {
            connection.close()
            throw error
        }
        return SystemTLSStream(connection: connection, negotiatedALPN: connection.negotiatedALPN())
    }

    public func send(_ data: Data) async throws {
        try await connection.send(data)
    }

    public func receive() async throws -> Data? {
        try await connection.receive()
    }

    public func close() {
        connection.close()
    }

    private static let verifyQueue = DispatchQueue(label: "com.mythaia.transport.tls-verify")

    static func configure(_ options: sec_protocol_options_t, options settings: TLSClientOptions) {
        if !settings.serverName.isEmpty {
            sec_protocol_options_set_tls_server_name(options, settings.serverName)
        }
        for name in settings.alpn where !name.isEmpty {
            sec_protocol_options_add_tls_application_protocol(options, name)
        }
        if let minimum = settings.minVersion {
            sec_protocol_options_set_min_tls_protocol_version(options, protocolVersion(minimum))
        }
        if let maximum = settings.maxVersion {
            sec_protocol_options_set_max_tls_protocol_version(options, protocolVersion(maximum))
        }
        let pins = settings.pinnedCertSHA256
        let allowInsecure = settings.allowInsecure
        sec_protocol_options_set_verify_block(options, { _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            complete(SystemTLSStream.verify(secTrust, pins: pins, allowInsecure: allowInsecure))
        }, verifyQueue)
    }

    static func protocolVersion(_ version: TlsVersion) -> tls_protocol_version_t {
        switch version {
        case .tls12:
            return .TLSv12
        case .tls13:
            return .TLSv13
        }
    }

    /// The trust decision, in the order the own TLS client makes it: a pin
    /// is the whole decision (any certificate of the chain may match), then
    /// "allow insecure", then the system's evaluation, which checks the
    /// chain and that the certificate names the SNI.
    static func verify(_ trust: SecTrust, pins: [Data], allowInsecure: Bool) -> Bool {
        if !pins.isEmpty {
            let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
            for certificate in chain {
                let der = SecCertificateCopyData(certificate) as Data
                let digest = Data(SHA256.hash(data: der))
                if pins.contains(digest) {
                    return true
                }
            }
            Log.warning("TLS: no certificate of the server matches the pinned SHA-256")
            return false
        }
        // The server's own setting or the global one, as on Android: the
        // global "allow insecure" applies to every TLS connection.
        if allowInsecure || CertificatePolicy.allowInsecure {
            return true
        }
        var error: CFError?
        if SecTrustEvaluateWithError(trust, &error) {
            return true
        }
        // A certificate the user trusted by its fingerprint stands in for
        // the system's vouching.
        let trustedFingerprints = CertificatePolicy.trustedFingerprints
        if !trustedFingerprints.isEmpty,
           let leaf = ((SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []).first {
            let der = SecCertificateCopyData(leaf) as Data
            let hex = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
            if trustedFingerprints.contains(hex) {
                return true
            }
        }
        let reason = error.map { String(describing: $0) } ?? "unknown reason"
        Log.warning("TLS: certificate not trusted: \(reason)")
        return false
    }
}
