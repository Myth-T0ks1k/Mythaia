import CryptoKit
import Foundation

/// What the TLS handshake asks of the QUIC engine underneath it. The live
/// connection answers through the C bridge; tests pass a recorder, or nothing
/// for input that must be refused before any key is touched.
///
/// Every call returns 0 on success, as the bridge does.
protocol QuicHandshakeSink: AnyObject {
    func setCipherSuite(_ suite: Int) -> Int32
    func installKeys(level: Int, rx: [UInt8], tx: [UInt8]) -> Int32
    func setRemoteTransportParameters(_ raw: [UInt8]) -> Int32
    func submitCrypto(level: Int, data: [UInt8]) -> Int32
    func handshakeCompleted()
}

/// The TLS 1.3 handshake, as QUIC uses it.
///
/// QUIC does not run TLS over a record layer; it carries the handshake messages
/// in CRYPTO frames and asks TLS only for keys. So this is a TLS client with
/// the record layer taken out: ngtcp2 hands it bytes, it hands back messages
/// to submit and secrets to install, and it never sees a packet.
///
/// Three things differ from the TCP client in TLS/, and only three: the
/// ClientHello carries a `quic_transport_parameters` extension, keys are
/// installed per encryption level rather than into a record layer, and the
/// traffic secrets are handed to ngtcp2 rather than used here — the
/// `quic key`, `quic iv` and `quic hp` expansions happen inside the library.
/// The key schedule, the fingerprinted ClientHello and the certificate checks
/// are the TLS client's own.
///
/// Not thread-safe: the connection drives it from its engine queue only.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class QuicTlsHandler {
    /// How far the handshake has got. `verifying` is the wait for the
    /// certificate check, which the system trust evaluation makes
    /// asynchronous; nothing is installed for 1-RTT until it passes.
    enum Phase {
        case initial
        case helloSent
        case serverHelloSeen
        case verifying
        case established
        case failed
    }

    /// What `processCryptoData` wants the caller to do next.
    enum Outcome {
        case ok
        case needMore
        case failed
    }

    /// The bridge's own level numbering (cquic.h), translated to ngtcp2's enum
    /// in C. Deliberately not ngtcp2's values: that enum has been renumbered
    /// once already, and a constant that silently survived the change installs
    /// handshake keys as 1-RTT keys with nothing to show for it.
    static let levelInitial = 0
    static let levelHandshake = 1
    static let levelApplication = 2

    private static let serverHello: UInt8 = 2
    private static let newSessionTicket: UInt8 = 4
    private static let encryptedExtensions: UInt8 = 8
    private static let certificate: UInt8 = 11
    private static let certificateVerify: UInt8 = 15
    private static let finished: UInt8 = 20
    private static let compressedCertificate: UInt8 = 25

    private static let extensionAlpn = 0x0010

    /// What the certificate check needs, handed to the connection to run
    /// asynchronously.
    struct Verification {
        let certificates: [[UInt8]]
        let serverName: String
        let pins: [Data]
        let signedTranscriptHash: [UInt8]?
        let scheme: Int
        let signature: [UInt8]?
    }

    private let serverName: String
    private let alpn: [String]
    private let tuning: QuicTuning
    private let fingerprint: TlsFingerprint
    private let allowInsecure: Bool
    private let pins: [Data]
    private let verifyName: String?

    private(set) var phase: Phase = .initial
    /// Why the handshake failed, for a caller that wants to say something useful.
    private(set) var failure: String?
    /// The cipher suite the server chose, once it has.
    private(set) var cipherSuite = 0
    /// The protocol the server picked from what was offered.
    private(set) var negotiatedAlpn: String?
    /// What the server advertised, available after EncryptedExtensions.
    private(set) var peerTransportParameters: [QuicTuning.TransportParameter] = []
    /// The certificate chain the server presented, in wire order.
    private(set) var serverCertificates: [[UInt8]] = []
    /// The check the connection must run before `completeVerification`.
    private(set) var pendingVerification: Verification?

    /// The local transport parameters in wire form, as ngtcp2 encodes them
    /// for the connection. Set before the hello is built; the tuning's own
    /// list is the fallback and lacks the connection id a server insists on.
    var localTransportParameters: [UInt8]?

    private let x25519 = TLSKeyShare.x25519(Curve25519.KeyAgreement.PrivateKey())
    private let p256 = TLSKeyShare.p256(P256.KeyAgreement.PrivateKey())
    private var keyShares: [TLSKeyShare] = []

    /// Every handshake message exchanged, in order — the TLS transcript.
    private var transcript: [UInt8] = []
    /// The transcript CertificateVerify signs: everything up to but not itself.
    private var transcriptBeforeCertificateVerify: [UInt8]?
    private var certificateVerifyScheme = 0
    private var certificateVerifySignature: [UInt8]?
    /// Handshake bytes that did not yet form a whole message.
    private var pending: [UInt8] = []

    private var keyDerivation: Tls13KeyDerivation?
    private var handshakeSecret: [UInt8]?
    private var clientHandshakeSecret: [UInt8]?
    private var serverHandshakeSecret: [UInt8]?
    private var clientHello: [UInt8]?

    /// What the server Finished produced, held until the certificate check
    /// lets it be installed.
    private struct Commit {
        let clientApplicationSecret: [UInt8]
        let serverApplicationSecret: [UInt8]
        let clientFinished: [UInt8]
        let exporterMasterSecret: [UInt8]
    }
    private var commit: Commit?

    /// Set with the application keys; what `exportKeyingMaterial` derives from.
    private var exporterMasterSecret: [UInt8]?

    init(
        serverName: String,
        alpn: [String],
        tuning: QuicTuning,
        fingerprint: TlsFingerprint = .chrome133,
        allowInsecure: Bool = false,
        pinnedCertSha256: [String]? = nil,
        verifyName: String? = nil
    ) {
        self.serverName = serverName
        self.alpn = alpn
        self.tuning = tuning
        self.fingerprint = fingerprint
        self.allowInsecure = allowInsecure
        self.pins = Dialer.pinnedDigests(pinnedCertSha256)
        self.verifyName = verifyName.flatMap { $0.isEmpty ? nil : $0 }
    }

    // MARK: - Outbound

    /// The ClientHello, built once and remembered.
    ///
    /// ngtcp2 asks for it through `client_initial`, and may ask again if the
    /// first Initial packet is lost — the same bytes must come back, since the
    /// transcript is already committed to them.
    func buildClientHello() -> [UInt8]? {
        if let hello = clientHello { return hello }
        if phase != .initial { return nil }

        let parameters = localTransportParameters ?? QuicTransportParameters.encode(tuning.advertisedParameters)
        let random = TLSWire.randomBytes(32)
        let raw = TlsClientHelloBuilder.buildRawClientHello(
            fingerprint: fingerprint,
            random: random,
            // RFC 9001 §8.4: no middlebox compatibility mode over QUIC, so
            // the legacy session id stays empty, as every QUIC client sends it.
            sessionId: [],
            serverName: serverName,
            publicKey: x25519.publicKey,
            alpn: alpn.isEmpty ? nil : alpn,
            // QUIC has no room for a post-quantum key share in the first
            // datagram, and the extra flight it would cost is the opposite of
            // what a low-latency transport is for.
            omitPQKeyShares: true,
            p256PublicKey: p256.publicKey
        )
        guard let hello = QuicTlsHandler.quicClientHello(raw, transportParameters: parameters) else {
            _ = fail("could not build the ClientHello")
            return nil
        }
        // Only the shares the fingerprint actually put in the hello count.
        let offered = TlsClientHelloBuilder.keyShareGroups(in: hello)
        keyShares = [x25519, p256].filter { offered.contains($0.group) }

        transcript.append(contentsOf: hello)
        clientHello = hello
        phase = .helloSent
        return hello
    }

    /// A browser-fingerprinted hello made fit for QUIC.
    ///
    /// `supported_versions` keeps only TLS 1.3 (and GREASE): RFC 9001 §4.2
    /// forbids offering older versions over QUIC, and Go's TLS — every
    /// Hysteria and TUIC server — answers a browser-shaped list with a
    /// `protocol_version` alert. The transport parameters are appended after
    /// the fingerprint's own extensions, and the padding extension, which only
    /// sizes a hello to a fingerprint's TCP shape, is dropped.
    static func quicClientHello(_ raw: [UInt8], transportParameters: [UInt8]) -> [UInt8]? {
        guard let parsed = try? TlsClientHelloBuilder.parse(raw) else { return nil }
        var extensions = TLSByteWriter()
        for entry in parsed.extensions {
            if entry.type == 0x0015 { continue }
            if entry.type == 0x002B {
                var versions: [Int] = []
                var index = 1
                while index + 2 <= entry.body.count {
                    let version = TLSWire.u16(entry.body, index)
                    let grease = (version & 0x0F0F) == 0x0A0A && (version >> 8) == (version & 0xFF)
                    if version == 0x0304 || grease { versions.append(version) }
                    index += 2
                }
                if !versions.contains(0x0304) { versions.append(0x0304) }
                extensions.u16(0x002B)
                extensions.u16(1 + 2 * versions.count)
                extensions.u8(2 * versions.count)
                for version in versions { extensions.u16(version) }
                continue
            }
            extensions.u16(entry.type)
            extensions.u16(entry.body.count)
            extensions.append(entry.body)
        }
        extensions.append(QuicTransportParameters.asExtension(transportParameters))

        var hello = TLSByteWriter()
        hello.u8(0x01)
        hello.u24(0)
        hello.u16(0x0303)
        hello.append(parsed.random)
        hello.u8(parsed.sessionId.count)
        hello.append(parsed.sessionId)
        hello.u16(parsed.cipherSuites.count)
        hello.append(parsed.cipherSuites)
        hello.u8(0x01)
        hello.u8(0x00)
        hello.u16(extensions.bytes.count)
        hello.append(extensions.bytes)
        var bytes = hello.bytes
        let length = bytes.count - 4
        bytes[1] = UInt8(truncatingIfNeeded: length >> 16)
        bytes[2] = UInt8(truncatingIfNeeded: length >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: length)
        return bytes
    }

    // MARK: - Inbound

    /// Consumes handshake bytes from one encryption level.
    ///
    /// Bytes that do not complete a message are kept for the next call: a
    /// CRYPTO frame is not a message boundary, and a ServerHello can arrive
    /// split across two of them.
    func processCryptoData(_ data: [UInt8], sink: QuicHandshakeSink?) -> Outcome {
        if phase == .failed { return .failed }
        pending.append(contentsOf: data)

        while pending.count >= 4 {
            let type = pending[0]
            let length = TLSWire.u24(pending, 1)

            // The length field is 24 bits, but nothing in a TLS 1.3 handshake
            // legitimately approaches that. The cap is not in the RFC; it is
            // here so a corrupt length cannot ask for a 16 MB allocation.
            if length > 0xFFFF {
                return fail("handshake message of \(length) bytes (type \(type))")
            }
            let total = 4 + length
            if pending.count < total { return .needMore }

            let message = Array(pending[0..<total])
            pending = Array(pending[total...])

            // CertificateVerify signs the transcript before itself, so the
            // snapshot is taken before the message is appended; the server
            // Finished is checked the same way, inside its handler.
            if type == QuicTlsHandler.certificateVerify {
                transcriptBeforeCertificateVerify = transcript
            }
            let transcriptBefore = transcript
            transcript.append(contentsOf: message)

            let body = Array(message[4...])
            let outcome: Outcome
            switch type {
            case QuicTlsHandler.serverHello:
                outcome = processServerHello(message, sink: sink)
            case QuicTlsHandler.encryptedExtensions:
                outcome = processEncryptedExtensions(body, sink: sink)
            case QuicTlsHandler.certificate:
                outcome = processCertificate(body)
            case QuicTlsHandler.compressedCertificate:
                // RFC 8879; the transcript takes the message compressed.
                if let inflated = TLSCertificateDecompression.decompress(body) {
                    outcome = processCertificate(inflated)
                } else {
                    outcome = fail("could not decompress the server's certificate")
                }
            case QuicTlsHandler.certificateVerify:
                outcome = processCertificateVerify(body)
            case QuicTlsHandler.finished:
                outcome = processServerFinished(body, transcriptBefore: transcriptBefore, sink: sink)
            case QuicTlsHandler.newSessionTicket:
                outcome = .ok
            default:
                // TLS 1.3 adds message types over time; one this client does
                // not know is stepped over rather than fatal.
                outcome = .ok
            }
            if outcome == .failed { return .failed }
        }

        // Leftover bytes are leftover bytes whether or not they reach a header
        // length; saying ok below four and needMore above it would be the same
        // state described two ways.
        return pending.isEmpty ? .ok : .needMore
    }

    // MARK: - Messages

    private func processServerHello(_ message: [UInt8], sink: QuicHandshakeSink?) -> Outcome {
        // legacy_version(2) random(32) session_id_len(1)
        if message.count < 4 + 35 {
            return fail("ServerHello is \(message.count - 4) bytes")
        }
        let hello: TLSServerHello
        do {
            hello = try TLSServerHello(message: message)
        } catch {
            return fail("malformed ServerHello")
        }
        cipherSuite = hello.cipherSuite
        guard let suite = Tls13Suite.forCode(hello.cipherSuite) else {
            return fail("server chose cipher suite \(TLSWire.codepoint(hello.cipherSuite))")
        }
        if hello.isHelloRetryRequest {
            return fail("server sent a HelloRetryRequest, which this QUIC client does not follow")
        }
        if let version = hello.selectedVersion, version != 0x0304 {
            return fail("server chose TLS version \(TLSWire.codepoint(version)) over QUIC")
        }
        guard let peer = hello.keyShare,
              let ours = keyShares.first(where: { $0.group == peer.group }) else {
            return fail("ServerHello has no usable key share")
        }
        let shared: [UInt8]
        do {
            shared = try ours.sharedSecret(peer: peer.key)
        } catch {
            return fail("key agreement failed: \(error.localizedDescription)")
        }
        guard let sink = sink else { return fail("no QUIC connection to install keys into") }

        // The suite has to reach ngtcp2 before any key does: the crypto
        // backend carries it as the TLS native handle and everything else
        // reads it back.
        if sink.setCipherSuite(suite.code) != 0 {
            return fail("ngtcp2 refused cipher suite \(TLSWire.codepoint(suite.code))")
        }
        let derivation: Tls13KeyDerivation
        do {
            derivation = try Tls13KeyDerivation(cipherSuite: suite.code)
        } catch {
            return fail("server chose cipher suite \(TLSWire.codepoint(suite.code))")
        }
        keyDerivation = derivation
        let derived = derivation.deriveHandshakeKeys(sharedSecret: shared, transcript: transcript)
        handshakeSecret = derived.handshakeSecret
        clientHandshakeSecret = derived.keys.clientTrafficSecret
        serverHandshakeSecret = derived.keys.serverTrafficSecret

        // The traffic secrets, not the expanded keys: ngtcp2 runs its own
        // `quic key` / `quic iv` / `quic hp` expansion over these.
        if sink.installKeys(level: QuicTlsHandler.levelHandshake,
                            rx: derived.keys.serverTrafficSecret,
                            tx: derived.keys.clientTrafficSecret) != 0 {
            return fail("ngtcp2 refused the handshake keys")
        }
        phase = .serverHelloSeen
        return .ok
    }

    /// The peer's transport parameters ride in EncryptedExtensions. Anything
    /// unreadable there is the server's half of the transport contract, so it
    /// is a reason to stop rather than to carry on with defaults.
    private func processEncryptedExtensions(_ body: [UInt8], sink: QuicHandshakeSink?) -> Outcome {
        if body.count < 2 { return .ok }
        let total = TLSWire.u16(body, 0)
        var at = 2
        let end = min(2 + total, body.count)
        while at + 4 <= end {
            let type = TLSWire.u16(body, at)
            let length = TLSWire.u16(body, at + 2)
            at += 4
            if at + length > end { break }
            let value = Array(body[at..<(at + length)])

            if type == QuicTransportParameters.extensionType {
                guard let parsed = QuicTransportParameters.decode(value) else {
                    return fail("server sent malformed transport parameters")
                }
                peerTransportParameters = parsed
                // ngtcp2 is the authority on these — it enforces the limits.
                guard let sink = sink, sink.setRemoteTransportParameters(value) == 0 else {
                    return fail("ngtcp2 refused the peer transport parameters")
                }
            }
            if type == QuicTlsHandler.extensionAlpn {
                negotiatedAlpn = QuicTlsHandler.readAlpn(value)
                if !alpn.isEmpty {
                    guard let chosen = negotiatedAlpn, alpn.contains(chosen) else {
                        return fail("server selected ALPN '\(negotiatedAlpn ?? "")', which was not offered")
                    }
                }
            }
            at += length
        }
        return .ok
    }

    /// Collects the chain; it is checked at the server Finished.
    private func processCertificate(_ body: [UInt8]) -> Outcome {
        do {
            serverCertificates = try TLSHandshakeDriver.parseCertificateMessage(body)
        } catch {
            return fail("malformed server certificate message")
        }
        return .ok
    }

    /// Keeps the signature; it is checked once the whole chain has arrived.
    private func processCertificateVerify(_ body: [UInt8]) -> Outcome {
        if body.count < 4 { return fail("CertificateVerify is \(body.count) bytes") }
        certificateVerifyScheme = TLSWire.u16(body, 0)
        let length = TLSWire.u16(body, 2)
        if 4 + length > body.count { return fail("CertificateVerify signature runs past the message") }
        certificateVerifySignature = Array(body[4..<(4 + length)])
        return .ok
    }

    /// Verifies the server's Finished and prepares the application keys.
    ///
    /// The verify data covers the transcript up to but not including the
    /// Finished itself. The application secrets are derived over the
    /// transcript through the server Finished (RFC 8446 §7.1); the earlier
    /// snapshot only verifies the Finished, and keys derived over it would be
    /// keys the server does not share.
    private func processServerFinished(_ body: [UInt8], transcriptBefore: [UInt8], sink: QuicHandshakeSink?) -> Outcome {
        guard let derivation = keyDerivation, let secret = handshakeSecret else {
            return fail("Finished arrived before ServerHello")
        }
        guard let serverSecret = serverHandshakeSecret, let clientSecret = clientHandshakeSecret else {
            return fail("Finished arrived before ServerHello")
        }
        if phase != .serverHelloSeen {
            return fail("unexpected server Finished")
        }
        let expected = derivation.computeFinishedVerifyData(trafficSecret: serverSecret, transcript: transcriptBefore)
        if !TLSWire.constantTimeEqual(body, expected) {
            return fail("server Finished verify data did not match")
        }

        let application = derivation.deriveApplicationKeys(handshakeSecret: secret, fullTranscript: transcript)
        let hash = derivation.suite.hash
        let master = Tls13Crypto.masterSecret(hash, handshakeSecret: secret)
        // Same transcript as the application secrets: an exporter taken over a
        // different one is a value the peer does not have.
        let exporter = Tls13Crypto.deriveSecret(hash, secret: master, label: "exp master",
                                                transcriptHash: hash.digest(transcript))
        let verifyData = derivation.computeFinishedVerifyData(trafficSecret: clientSecret, transcript: transcript)
        var finishedMessage = TLSByteWriter()
        finishedMessage.u8(Int(QuicTlsHandler.finished))
        finishedMessage.u24(verifyData.count)
        finishedMessage.append(verifyData)
        commit = Commit(
            clientApplicationSecret: application.clientTrafficSecret,
            serverApplicationSecret: application.serverTrafficSecret,
            clientFinished: finishedMessage.bytes,
            exporterMasterSecret: exporter
        )

        // "Allow insecure", for this server or for all of them, skips the
        // check entirely. A pin decides on its own: it is the user's narrower
        // trust decision for this one server.
        let skipsCheck = allowInsecure || CertificatePolicy.allowInsecure
        if pins.isEmpty && skipsCheck {
            return install(sink: sink)
        }
        pendingVerification = Verification(
            certificates: serverCertificates,
            serverName: verifyName ?? serverName,
            pins: pins,
            signedTranscriptHash: transcriptBeforeCertificateVerify.map { derivation.transcriptHash($0) },
            scheme: certificateVerifyScheme,
            signature: certificateVerifySignature
        )
        phase = .verifying
        return .ok
    }

    /// The outcome of the certificate check the connection ran. Without it
    /// the handshake authenticates nothing: anyone able to complete an ECDHE
    /// exchange — which is anyone at all — would be accepted.
    func completeVerification(_ error: Error?, sink: QuicHandshakeSink?) -> Outcome {
        guard phase == .verifying else { return phase == .failed ? .failed : .ok }
        pendingVerification = nil
        if let error = error {
            let reason: String
            if let mythaia = error as? MythaiaError, case .tls(let why) = mythaia {
                reason = why
            } else {
                reason = "certificate check failed: \(error.localizedDescription)"
            }
            return fail(reason)
        }
        return install(sink: sink)
    }

    /// Installs the 1-RTT keys, sends the client Finished and tells ngtcp2
    /// the handshake is done — strictly after the server has been verified:
    /// this is what promotes the connection to carrying application data.
    private func install(sink: QuicHandshakeSink?) -> Outcome {
        guard let commit = commit else { return fail("no application secrets") }
        guard let sink = sink else { return fail("no QUIC connection to install keys into") }
        if sink.installKeys(level: QuicTlsHandler.levelApplication,
                            rx: commit.serverApplicationSecret,
                            tx: commit.clientApplicationSecret) != 0 {
            return fail("ngtcp2 refused the application keys")
        }
        if sink.submitCrypto(level: QuicTlsHandler.levelHandshake, data: commit.clientFinished) != 0 {
            return fail("ngtcp2 refused the client Finished")
        }
        transcript.append(contentsOf: commit.clientFinished)
        exporterMasterSecret = commit.exporterMasterSecret
        self.commit = nil
        sink.handshakeCompleted()
        phase = .established
        return .ok
    }

    /// Keying material bound to this session (RFC 8446 §7.5, RFC 5705).
    ///
    /// TUIC turns its password into a token this way, so a token captured on
    /// one connection proves nothing on another. Nil before the handshake is
    /// established, since the secret it derives from is not usable yet.
    func exportKeyingMaterial(label: [UInt8], context: [UInt8], length: Int) -> [UInt8]? {
        guard let secret = exporterMasterSecret, let derivation = keyDerivation else { return nil }
        return QuicTlsHandler.exportKeyingMaterial(derivation.suite.hash, exporterMasterSecret: secret,
                                                   label: label, context: context, length: length)
    }

    /// TLS-Exporter(label, context, length) =
    /// HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
    /// "exporter", Hash(context), length). The label is raw bytes: TUIC's is
    /// a UUID's sixteen bytes, not text.
    static func exportKeyingMaterial(_ hash: TLSHash, exporterMasterSecret: [UInt8],
                                     label: [UInt8], context: [UInt8], length: Int) -> [UInt8] {
        let derived = Tls13Crypto.hkdfExpandLabel(hash, secret: exporterMasterSecret, label: label,
                                                  context: hash.digest([]), length: hash.length)
        return Tls13Crypto.hkdfExpandLabel(hash, secret: derived, label: Array("exporter".utf8),
                                           context: hash.digest(context), length: length)
    }

    /// The single protocol name in an ALPN extension, or nil.
    private static func readAlpn(_ value: [UInt8]) -> String? {
        // list length(2) name length(1) name
        if value.count < 3 { return nil }
        let nameLength = Int(value[2])
        if nameLength == 0 || 3 + nameLength > value.count { return nil }
        return String(decoding: value[3..<(3 + nameLength)], as: UTF8.self)
    }

    private func fail(_ reason: String) -> Outcome {
        if failure == nil {
            failure = reason
            Log.warning("[QUIC-TLS] \(reason)")
        }
        phase = .failed
        pendingVerification = nil
        commit = nil
        return .failed
    }
}
