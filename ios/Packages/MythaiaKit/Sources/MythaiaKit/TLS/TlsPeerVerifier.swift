import CryptoKit
import Foundation
import Security

/// Deciding whether the peer on the other end is who it claims to be.
///
/// Three separate questions, all of which have to be answered yes: does a
/// recognised authority vouch for this certificate, is it valid for the name
/// we asked for, and does the peer actually hold its private key. Skip the
/// first two and any certificate will do; skip the third and anyone can
/// replay somebody else's. The first two are the system's trust evaluation
/// (`SecPolicyCreateSSL` folds the name check into it); the third is the
/// CertificateVerify signature over this handshake's transcript.
enum TlsPeerVerifier {

    /// Why verification failed, in terms a log line can use.
    struct Failure: Error, LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// RFC 8446 §4.4.3: the schemes a TLS 1.3 CertificateVerify may use. No
    /// PKCS#1 v1.5 and no SHA-1: those are TLS 1.2 leftovers a peer must not
    /// use here.
    static let tls13CertificateVerifySchemes: Set<Int> = [
        0x0403, 0x0503, 0x0603,     // ECDSA
        0x0804, 0x0805, 0x0806,     // RSA-PSS, RSAE key
        0x0809, 0x080A, 0x080B,     // RSA-PSS, PSS key
        0x0807, 0x0808,             // Ed25519, Ed448
    ]

    /// Parses a DER chain, in the order the peer sent it.
    static func parseChain(_ der: [[UInt8]]) throws -> [SecCertificate] {
        if der.isEmpty { throw Failure(message: "peer sent no certificate") }
        var chain: [SecCertificate] = []
        for entry in der {
            guard let certificate = SecCertificateCreateWithData(nil, Data(entry) as CFData) else {
                throw Failure(message: "certificate did not parse")
            }
            chain.append(certificate)
        }
        return chain
    }

    /// The content a server's CertificateVerify signs (RFC 8446 §4.4.3):
    /// 64 spaces, the context string, a zero byte, the transcript hash.
    static func certificateVerifyContent(_ transcriptHash: [UInt8]) -> [UInt8] {
        var content = [UInt8](repeating: 0x20, count: 64)
        content.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
        content.append(0x00)
        content.append(contentsOf: transcriptHash)
        return content
    }

    /// The Security framework algorithm for a TLS signature scheme.
    ///
    /// A scheme this table does not know must not be verified as if it were
    /// PKCS#1 SHA-256: the check would fail honestly at best and, with a
    /// matching key, pass a signature made under different rules. Ed25519 is
    /// verified with CryptoKit instead, and Ed448 not at all.
    static func secKeyAlgorithm(for scheme: Int) -> SecKeyAlgorithm? {
        switch scheme {
        case 0x0403: return .ecdsaSignatureMessageX962SHA256
        case 0x0503: return .ecdsaSignatureMessageX962SHA384
        case 0x0603: return .ecdsaSignatureMessageX962SHA512
        case 0x0804, 0x0809: return .rsaSignatureMessagePSSSHA256
        case 0x0805, 0x080A: return .rsaSignatureMessagePSSSHA384
        case 0x0806, 0x080B: return .rsaSignatureMessagePSSSHA512
        case 0x0401: return .rsaSignatureMessagePKCS1v15SHA256
        case 0x0501: return .rsaSignatureMessagePKCS1v15SHA384
        case 0x0601: return .rsaSignatureMessagePKCS1v15SHA512
        case 0x0201: return .rsaSignatureMessagePKCS1v15SHA1
        default: return nil
        }
    }

    /// Whether `signature` over `content` was made with the key in the
    /// certificate, under `scheme`.
    static func verifySignature(certificateDER: [UInt8], scheme: Int, signature: [UInt8], content: [UInt8]) -> Bool {
        if scheme == 0x0807 {
            guard let raw = ed25519PublicKey(certificateDER: certificateDER),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else {
                return false
            }
            return key.isValidSignature(signature, for: content)
        }
        guard let algorithm = secKeyAlgorithm(for: scheme),
              let certificate = SecCertificateCreateWithData(nil, Data(certificateDER) as CFData),
              let key = SecCertificateCopyKey(certificate) else {
            return false
        }
        if !SecKeyIsAlgorithmSupported(key, .verify, algorithm) {
            return false
        }
        let signedData = Data(content) as CFData
        let signatureData = Data(signature) as CFData
        return SecKeyVerifySignature(key, algorithm, signedData, signatureData, nil)
    }

    /// The raw Ed25519 public key of a certificate: the 32 bytes after the
    /// algorithm OID 1.3.101.112 and the BIT STRING header in its
    /// SubjectPublicKeyInfo. The Security framework has no Ed25519 keys.
    static func ed25519PublicKey(certificateDER der: [UInt8]) -> [UInt8]? {
        let marker: [UInt8] = [0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00]
        if der.count < marker.count + 32 { return nil }
        let last = der.count - marker.count - 32
        var index = 0
        while index <= last {
            var match = true
            for offset in 0..<marker.count where der[index + offset] != marker[offset] {
                match = false
                break
            }
            if match {
                let start = index + marker.count
                return Array(der[start..<(start + 32)])
            }
            index += 1
        }
        return nil
    }

    static func sha256(_ bytes: [UInt8]) -> [UInt8] {
        return Array(SHA256.hash(data: bytes))
    }

    /// Whether the certificate's SHA-256 is one of `pins`. Every pin is
    /// compared, without stopping at a match.
    static func matchesPin(_ certificateDER: [UInt8], pins: [Data]) -> Bool {
        let candidate = sha256(certificateDER)
        var matched = false
        for pin in pins {
            if TLSWire.constantTimeEqual(candidate, Array(pin)) { matched = true }
        }
        return matched
    }

    /// Whether the user trusted this exact certificate in the settings.
    static func isUserTrusted(_ certificateDER: [UInt8]) -> Bool {
        let trusted = CertificatePolicy.trustedFingerprints
        if trusted.isEmpty { return false }
        let candidate = Array(TLSWire.hex(sha256(certificateDER)).utf8)
        var matched = false
        for entry in trusted {
            if TLSWire.constantTimeEqual(candidate, Array(entry.utf8)) { matched = true }
        }
        return matched
    }

    /// The system's verdict on the chain for `serverName`: nil when trusted,
    /// otherwise why not. Evaluation may fetch missing intermediates, so it
    /// runs on a dispatch queue, off the cooperative pool.
    static func evaluateSystemTrust(_ chain: [SecCertificate], serverName: String) async -> String? {
        let checkedName: String
        if TLSHostName.isIpLiteral(serverName) {
            checkedName = serverName
        } else {
            checkedName = TLSHostName.asciiName(serverName)
        }
        let hostName: CFString? = checkedName.isEmpty ? nil : (checkedName as CFString)
        let policy = SecPolicyCreateSSL(true, hostName)
        var trustObject: SecTrust?
        let status = SecTrustCreateWithCertificates(chain as CFArray, policy, &trustObject)
        guard status == errSecSuccess, let trust = trustObject else {
            return "could not evaluate the certificate (status \(status))"
        }
        let verdict: String? = await withCheckedContinuation { (continuation: CheckedContinuation<String?, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                var error: CFError?
                if SecTrustEvaluateWithError(trust, &error) {
                    continuation.resume(returning: nil)
                    return
                }
                var reason = "not trusted"
                if let error = error {
                    reason = CFErrorCopyDescription(error) as String
                }
                continuation.resume(returning: reason)
            }
        }
        return verdict
    }

    /// The whole certificate decision for an ordinary TLS server.
    ///
    /// A pinned certificate is the whole decision: trusted without a CA when
    /// it matches, refused even with a valid chain when it does not. Without
    /// pins the system decides, with the user's own trusted fingerprints as
    /// the fallback. Either way the CertificateVerify signature must check
    /// out against the leaf.
    static func verifyServer(
        certificates: [[UInt8]],
        serverName: String,
        pins: [Data],
        signedTranscriptHash: [UInt8]?,
        scheme: Int,
        signature: [UInt8]?
    ) async throws {
        guard let leaf = certificates.first else {
            throw MythaiaError.tls("certificate validation failed: no server certificates received")
        }

        if !pins.isEmpty {
            var anyMatches = false
            for certificate in certificates where matchesPin(certificate, pins: pins) {
                anyMatches = true
            }
            if !anyMatches {
                throw MythaiaError.tls("certificate does not match the pinned SHA-256")
            }
        } else {
            var failure: String?
            do {
                let chain = try parseChain(certificates)
                failure = await evaluateSystemTrust(chain, serverName: serverName)
            } catch let error as Failure {
                failure = error.message
            }
            if let reason = failure, !isUserTrusted(leaf) {
                throw MythaiaError.tls("certificate not trusted by the system or the user: \(reason)")
            }
        }

        // RFC 8446 §4.4.3: the chain alone proves nothing, anyone who has
        // seen it can replay it; the signature over this handshake's
        // transcript is what ties it to the key holder.
        guard let transcriptHash = signedTranscriptHash, let signatureBytes = signature else {
            throw MythaiaError.tls("server sent no usable CertificateVerify")
        }
        if !tls13CertificateVerifySchemes.contains(scheme) {
            throw MythaiaError.tls("CertificateVerify uses a scheme TLS 1.3 forbids: \(TLSWire.codepoint(scheme))")
        }
        let content = certificateVerifyContent(transcriptHash)
        if !verifySignature(certificateDER: leaf, scheme: scheme, signature: signatureBytes, content: content) {
            throw MythaiaError.tls("CertificateVerify signature verification failed")
        }
    }
}
