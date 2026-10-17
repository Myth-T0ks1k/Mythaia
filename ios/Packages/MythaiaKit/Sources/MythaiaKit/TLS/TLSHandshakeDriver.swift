import CryptoKit
import Foundation

/// How the server proves who it is.
enum TLSServerAuthentication {
    /// Ordinary TLS: the certificate chain, the name on it and the
    /// CertificateVerify signature, unless "allow insecure" waives them. A
    /// pinned certificate is checked even then.
    case certificate(serverName: String, allowInsecure: Bool, pins: [Data])
    /// REALITY: the server's temporary certificate is signed with an HMAC
    /// under the key both sides derived from the ClientHello.
    case reality(authKey: [UInt8])
}

/// A handshake message with its 4-byte header; the transcript takes the
/// message whole.
struct TLSHandshakeMessage {
    let type: UInt8
    let bytes: [UInt8]

    var body: [UInt8] { Array(bytes[4...]) }
}

/// Reassembles handshake messages from record payloads: one message may span
/// records (a long certificate chain does) and one record may hold several.
struct TLSHandshakeBuffer {
    private var pending: [UInt8] = []

    var isEmpty: Bool { pending.isEmpty }

    mutating func append(_ bytes: [UInt8]) throws {
        pending.append(contentsOf: bytes)
        if pending.count > 1 << 20 {
            throw MythaiaError.tls("handshake message too large")
        }
    }

    mutating func next() -> TLSHandshakeMessage? {
        if pending.count < 4 { return nil }
        let length = TLSWire.u24(pending, 1)
        if pending.count < 4 + length { return nil }
        let bytes = Array(pending[0..<(4 + length)])
        pending.removeFirst(4 + length)
        return TLSHandshakeMessage(type: bytes[0], bytes: bytes)
    }
}

/// A ServerHello or HelloRetryRequest, read.
struct TLSServerHello {
    /// SHA-256("HelloRetryRequest"), the random that marks a HelloRetryRequest
    /// (RFC 8446 §4.1.3).
    static let helloRetryRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]

    let legacyVersion: Int
    let random: [UInt8]
    let cipherSuite: Int
    /// From supported_versions; nil means the server did not send it (TLS 1.2 or older).
    let selectedVersion: Int?
    /// A ServerHello's key_share entry.
    let keyShare: (group: Int, key: [UInt8])?
    /// A HelloRetryRequest's key_share: the group it wants.
    let selectedGroup: Int?
    let cookie: [UInt8]?

    var isHelloRetryRequest: Bool { random == TLSServerHello.helloRetryRandom }

    init(message: [UInt8]) throws {
        var reader = TLSByteReader(message, context: "ServerHello", from: 4)
        let parsedLegacyVersion = try reader.u16()
        let parsedRandom = try reader.take(32)
        let sessionIdLength = try reader.u8()
        try reader.skip(sessionIdLength)
        let parsedSuite = try reader.u16()
        _ = try reader.u8()
        let retry = parsedRandom == TLSServerHello.helloRetryRandom

        var version: Int?
        var share: (group: Int, key: [UInt8])?
        var group: Int?
        var parsedCookie: [UInt8]?
        if !reader.isAtEnd {
            let extensionsLength = try reader.u16()
            let start = reader.offset
            if start + extensionsLength > message.count {
                throw MythaiaError.tls("malformed ServerHello extensions")
            }
            var extensions = TLSByteReader(message, context: "ServerHello extensions", from: start, to: start + extensionsLength)
            while !extensions.isAtEnd {
                let type = try extensions.u16()
                let length = try extensions.u16()
                let bodyStart = extensions.offset
                try extensions.skip(length)
                var body = TLSByteReader(message, context: "ServerHello extension", from: bodyStart, to: bodyStart + length)
                switch type {
                case 0x002B:
                    version = try body.u16()
                case 0x0033:
                    if retry {
                        group = try body.u16()
                    } else {
                        let shareGroup = try body.u16()
                        let keyLength = try body.u16()
                        let key = try body.take(keyLength)
                        share = (group: shareGroup, key: key)
                    }
                case 0x002C:
                    let cookieLength = try body.u16()
                    parsedCookie = try body.take(cookieLength)
                default:
                    break
                }
            }
        }

        self.legacyVersion = parsedLegacyVersion
        self.random = parsedRandom
        self.cipherSuite = parsedSuite
        self.selectedVersion = version
        self.keyShare = share
        self.selectedGroup = group
        self.cookie = parsedCookie
    }
}

/// Drives one TLS 1.3 handshake over a stream, for `TLSClient` and
/// `RealityClient` alike: send the hello, follow a HelloRetryRequest when
/// allowed, derive the keys, read the server's encrypted flight, check who
/// the server is, answer with Finished. The result owns the stream.
final class TLSHandshakeDriver {
    private let stream: ByteStream
    private let reader: StreamReader
    private var clientHello: [UInt8]
    private var keyShares: [TLSKeyShare]
    private let authentication: TLSServerAuthentication
    private let minVersion: TlsVersion?
    private let maxVersion: TlsVersion?
    private let allowsHelloRetry: Bool
    private let offeredALPN: [String]

    private var transcript: [UInt8] = []
    private var plaintext = TLSHandshakeBuffer()
    private var receivedAnything = false
    private var sentChangeCipherSpec = false

    /// The 1-byte ChangeCipherSpec record of middlebox compatibility mode
    /// (RFC 8446 §D.4), sent once before the client's second flight.
    private static let changeCipherSpec: [UInt8] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]

    init(
        stream: ByteStream,
        clientHello: [UInt8],
        keyShares: [TLSKeyShare],
        authentication: TLSServerAuthentication,
        minVersion: TlsVersion?,
        maxVersion: TlsVersion?,
        allowsHelloRetry: Bool
    ) {
        self.stream = stream
        self.reader = StreamReader(stream)
        self.clientHello = clientHello
        self.keyShares = keyShares
        self.authentication = authentication
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.allowsHelloRetry = allowsHelloRetry
        self.offeredALPN = TLSHandshakeDriver.alpnProtocols(in: clientHello)
    }

    func run() async throws -> TLSSessionStream {
        try await stream.send(Data(TlsClientHelloBuilder.wrapInTLSRecord(clientHello)))
        transcript = clientHello

        let (serverHello, serverHelloBytes, retrySuite) = try await awaitServerHello()
        try checkVersion(serverHello)
        let derivation = try Tls13KeyDerivation(cipherSuite: serverHello.cipherSuite)
        if let retrySuite = retrySuite, retrySuite != serverHello.cipherSuite {
            throw MythaiaError.tls("server changed the cipher suite after its HelloRetryRequest")
        }
        guard let serverShare = serverHello.keyShare else {
            throw MythaiaError.tls("server sent no key share")
        }
        guard let ourShare = keyShares.first(where: { $0.group == serverShare.group }) else {
            throw MythaiaError.tls("server chose TLS 1.3 with key share group \(TLSWire.codepoint(serverShare.group)), which was not offered")
        }
        let sharedSecret = try ourShare.sharedSecret(peer: serverShare.key)
        if !plaintext.isEmpty {
            throw MythaiaError.tls("handshake data after the ServerHello in the clear")
        }
        transcript.append(contentsOf: serverHelloBytes)

        let suite = derivation.suite
        let handshake = derivation.deriveHandshakeKeys(sharedSecret: sharedSecret, transcript: transcript)
        let keys = handshake.keys
        var serverCipher = TLSRecordCipher(suite: suite, key: keys.serverKey, iv: keys.serverIV)

        var encrypted = TLSHandshakeBuffer()
        var certificates: [[UInt8]] = []
        var certificateBody: [UInt8]?
        var certificateRequestContext: [UInt8]?
        var signedTranscriptHash: [UInt8]?
        var verifyScheme = 0
        var verifySignature: [UInt8]?
        var negotiatedALPN: String?
        var finished = false

        while !finished {
            let record = try await readRecord()
            switch record.type {
            case 0x14:
                continue
            case 0x15:
                throw TLSHandshakeDriver.alertError(record.body)
            case 0x17:
                break
            default:
                throw MythaiaError.tls("unexpected plaintext record (type \(record.type)) during the handshake")
            }

            let opened: (contentType: UInt8, content: [UInt8])
            do {
                opened = try serverCipher.open(header: record.header, body: record.body)
            } catch {
                // Wrong keys or a corrupted record: nothing after it opens
                // either, so the handshake ends here.
                throw MythaiaError.tls("could not decrypt a handshake record")
            }
            if opened.contentType == 0x15 {
                throw TLSHandshakeDriver.alertError(opened.content)
            }
            if opened.contentType != 0x16 {
                throw MythaiaError.tls("unexpected record (type \(opened.contentType)) during the handshake")
            }
            try encrypted.append(opened.content)

            while let message = encrypted.next() {
                switch message.type {
                case 8: // EncryptedExtensions
                    negotiatedALPN = try parseEncryptedExtensions(message.body)
                    transcript.append(contentsOf: message.bytes)
                case 13: // CertificateRequest
                    certificateRequestContext = try TLSHandshakeDriver.certificateRequestContext(message.body)
                    transcript.append(contentsOf: message.bytes)
                case 11: // Certificate
                    certificateBody = message.body
                    certificates = try TLSHandshakeDriver.parseCertificateMessage(message.body)
                    transcript.append(contentsOf: message.bytes)
                case 25: // CompressedCertificate (RFC 8879); the transcript takes it compressed
                    if let inflated = TLSCertificateDecompression.decompress(message.body) {
                        certificateBody = inflated
                        certificates = try TLSHandshakeDriver.parseCertificateMessage(inflated)
                    } else {
                        Log.warning("TLS: could not decompress the server's CompressedCertificate")
                    }
                    transcript.append(contentsOf: message.bytes)
                case 15: // CertificateVerify signs the transcript before it
                    signedTranscriptHash = derivation.transcriptHash(transcript)
                    let body = message.body
                    if body.count >= 4 {
                        verifyScheme = TLSWire.u16(body, 0)
                        let signatureLength = TLSWire.u16(body, 2)
                        if body.count >= 4 + signatureLength {
                            verifySignature = Array(body[4..<(4 + signatureLength)])
                        }
                    }
                    transcript.append(contentsOf: message.bytes)
                case 20: // Finished, checked against the transcript before it
                    let expected = derivation.computeFinishedVerifyData(trafficSecret: keys.serverTrafficSecret, transcript: transcript)
                    if !TLSWire.constantTimeEqual(message.body, expected) {
                        throw MythaiaError.tls("server Finished verify data mismatch")
                    }
                    transcript.append(contentsOf: message.bytes)
                    finished = true
                default:
                    transcript.append(contentsOf: message.bytes)
                }
                if finished { break }
            }
            // The server's next records are under the application keys, so
            // Finished has to end its record.
            if finished && !encrypted.isEmpty {
                throw MythaiaError.tls("handshake data after the server Finished")
            }
        }

        switch authentication {
        case .certificate(let serverName, let allowInsecure, let pins):
            // "Allow insecure", for this server or for all of them, skips the
            // check entirely. A pin decides on its own: it is the user's
            // narrower trust decision for this one server.
            let skipsCheck = allowInsecure || CertificatePolicy.allowInsecure
            if !pins.isEmpty || !skipsCheck {
                try await TlsPeerVerifier.verifyServer(
                    certificates: certificates,
                    serverName: serverName,
                    pins: pins,
                    signedTranscriptHash: signedTranscriptHash,
                    scheme: verifyScheme,
                    signature: verifySignature
                )
            }
        case .reality(let authKey):
            guard let body = certificateBody, RealityClient.verifyRealityCertificate(body, authKey: authKey) else {
                throw MythaiaError.tls("REALITY server authentication failed")
            }
        }

        let applicationKeys = derivation.deriveApplicationKeys(handshakeSecret: handshake.handshakeSecret, fullTranscript: transcript)

        var flight: [UInt8] = []
        if !sentChangeCipherSpec {
            flight.append(contentsOf: TLSHandshakeDriver.changeCipherSpec)
        }
        var clientMessages: [UInt8] = []
        if let context = certificateRequestContext {
            // An empty Certificate: there is no client certificate to give
            // (RFC 8446 §4.4.2), and the server decides whether that will do.
            var certificate = TLSByteWriter()
            certificate.u8(11)
            certificate.u24(1 + context.count + 3)
            certificate.u8(context.count)
            certificate.append(context)
            certificate.u24(0)
            clientMessages.append(contentsOf: certificate.bytes)
            transcript.append(contentsOf: certificate.bytes)
        }
        let verifyData = derivation.computeFinishedVerifyData(trafficSecret: keys.clientTrafficSecret, transcript: transcript)
        var finishedMessage = TLSByteWriter()
        finishedMessage.u8(20)
        finishedMessage.u24(verifyData.count)
        finishedMessage.append(verifyData)
        clientMessages.append(contentsOf: finishedMessage.bytes)

        var clientCipher = TLSRecordCipher(suite: suite, key: keys.clientKey, iv: keys.clientIV)
        flight.append(contentsOf: try clientCipher.seal(clientMessages, contentType: 0x16))
        try await stream.send(Data(flight))

        // Records the server sent after its Finished (a NewSessionTicket,
        // early data) are already in the reader; they belong to the session.
        let leftover = Array(reader.drain())
        return TLSSessionStream(
            inner: stream,
            suite: suite,
            keys: applicationKeys,
            leftover: leftover,
            negotiatedALPN: negotiatedALPN
        )
    }

    // MARK: ServerHello and HelloRetryRequest

    /// Reads up to the ServerHello, answering one HelloRetryRequest on the
    /// way when that is allowed. Returns the suite the retry named, if any.
    private func awaitServerHello() async throws -> (TLSServerHello, [UInt8], Int?) {
        var retrySuite: Int?
        while true {
            let message = try await nextPlaintextMessage()
            if message.type != 2 {
                throw MythaiaError.tls("expected a ServerHello, got handshake message \(message.type)")
            }
            let parsed = try TLSServerHello(message: message.bytes)
            if !parsed.isHelloRetryRequest {
                return (parsed, message.bytes, retrySuite)
            }
            if !allowsHelloRetry {
                throw MythaiaError.tls("server sent a HelloRetryRequest, which REALITY cannot follow")
            }
            if retrySuite != nil {
                throw MythaiaError.tls("server sent a second HelloRetryRequest")
            }
            if !plaintext.isEmpty {
                throw MythaiaError.tls("handshake data after the HelloRetryRequest")
            }
            try checkVersion(parsed)
            let derivation = try Tls13KeyDerivation(cipherSuite: parsed.cipherSuite)
            retrySuite = parsed.cipherSuite

            try prepareRetry(parsed)
            // RFC 8446 §4.4.1: the first ClientHello is replaced in the
            // transcript by a message_hash of it.
            var newTranscript = Tls13Crypto.messageHash(derivation.suite.hash, clientHello: transcript)
            newTranscript.append(contentsOf: message.bytes)
            newTranscript.append(contentsOf: clientHello)
            transcript = newTranscript

            var flight = TLSHandshakeDriver.changeCipherSpec
            var record: [UInt8] = [0x16, 0x03, 0x03]
            record.append(contentsOf: TLSWire.u16Bytes(clientHello.count))
            record.append(contentsOf: clientHello)
            flight.append(contentsOf: record)
            sentChangeCipherSpec = true
            try await stream.send(Data(flight))
        }
    }

    /// The second ClientHello: a fresh share for the group the server wants,
    /// its cookie echoed.
    private func prepareRetry(_ retry: TLSServerHello) throws {
        var replacement: (group: Int, key: [UInt8])?
        if let group = retry.selectedGroup {
            if !TLSHandshakeDriver.supportedGroups(in: clientHello).contains(group) {
                throw MythaiaError.tls("HelloRetryRequest asks for group \(TLSWire.codepoint(group)), which was not offered")
            }
            if keyShares.contains(where: { $0.group == group }) {
                throw MythaiaError.tls("HelloRetryRequest asks for a group that already had a key share")
            }
            guard let share = TLSKeyShare.generate(group: group) else {
                throw MythaiaError.tls("server asks for key share group \(TLSWire.codepoint(group)), which this client cannot do")
            }
            keyShares = [share]
            replacement = (group: group, key: share.publicKey)
        } else if retry.cookie == nil {
            throw MythaiaError.tls("HelloRetryRequest asks for nothing")
        }
        clientHello = try TlsClientHelloBuilder.retryClientHello(clientHello, keyShare: replacement, cookie: retry.cookie)
    }

    /// Enforces the configured minimum and maximum, then TLS 1.3 itself.
    private func checkVersion(_ hello: TLSServerHello) throws {
        let negotiated = hello.selectedVersion ?? hello.legacyVersion
        let known = negotiated == 0x0303 || negotiated == 0x0304
        if known {
            if let minimum = minVersion, negotiated < TLSHandshakeDriver.wireValue(minimum) {
                let wanted = TLSHandshakeDriver.versionName(TLSHandshakeDriver.wireValue(minimum))
                throw MythaiaError.tls("negotiated \(TLSHandshakeDriver.versionName(negotiated)) is below the minimum \(wanted)")
            }
            if let maximum = maxVersion, negotiated > TLSHandshakeDriver.wireValue(maximum) {
                let wanted = TLSHandshakeDriver.versionName(TLSHandshakeDriver.wireValue(maximum))
                throw MythaiaError.tls("negotiated \(TLSHandshakeDriver.versionName(negotiated)) exceeds the maximum \(wanted)")
            }
        }
        if negotiated == 0x0303 {
            throw MythaiaError.tls("server chose TLS 1.2")
        }
        if negotiated != 0x0304 {
            throw MythaiaError.tls("server chose an unsupported TLS version \(TLSWire.codepoint(negotiated))")
        }
    }

    static func wireValue(_ version: TlsVersion) -> Int {
        return version.value
    }

    static func versionName(_ wire: Int) -> String {
        switch wire {
        case 0x0304: return "TLS 1.3"
        case 0x0303: return "TLS 1.2"
        default: return TLSWire.codepoint(wire)
        }
    }

    // MARK: Records

    private struct Record {
        let type: UInt8
        let header: [UInt8]
        let body: [UInt8]
    }

    private func readRecord() async throws -> Record {
        let header: [UInt8]
        let body: [UInt8]
        do {
            let headerData = try await reader.readExactly(5)
            header = Array(headerData)
            let type = header[0]
            if type < 0x14 || type > 0x17 || header[1] != 0x03 {
                if !receivedAnything {
                    throw MythaiaError.tls("server did not answer with TLS (first byte \(type))")
                }
                throw MythaiaError.tls("unexpected record type \(type) during the handshake")
            }
            receivedAnything = true
            let length = TLSWire.u16(header, 3)
            if length > 16384 + 2048 {
                throw MythaiaError.tls("record too long (\(length) bytes)")
            }
            let bodyData = try await reader.readExactly(length)
            body = Array(bodyData)
        } catch let error as MythaiaError {
            if error == .closed {
                if receivedAnything {
                    throw MythaiaError.tls("connection closed during the handshake")
                }
                throw MythaiaError.tls("no response from the server (connection closed)")
            }
            throw error
        }
        return Record(type: header[0], header: header, body: body)
    }

    /// The next handshake message sent in the clear (the ServerHello or a
    /// HelloRetryRequest).
    private func nextPlaintextMessage() async throws -> TLSHandshakeMessage {
        while true {
            if let message = plaintext.next() { return message }
            let record = try await readRecord()
            switch record.type {
            case 0x16:
                try plaintext.append(record.body)
            case 0x15:
                throw TLSHandshakeDriver.alertError(record.body)
            case 0x14:
                // A compatibility-mode ChangeCipherSpec, after a HelloRetryRequest.
                continue
            default:
                throw MythaiaError.tls("server answered with record type \(record.type) instead of a ServerHello")
            }
        }
    }

    static func alertError(_ body: [UInt8]) -> MythaiaError {
        let level = body.count > 0 ? Int(body[0]) : 2
        let description = body.count > 1 ? Int(body[1]) : -1
        return MythaiaError.tls("server sent alert: \(TLSAlert.describe(level: level, description: description))")
    }

    // MARK: Message parsing

    /// The ALPN protocol the server picked, which must be one we offered.
    private func parseEncryptedExtensions(_ body: [UInt8]) throws -> String? {
        var reader = TLSByteReader(body, context: "EncryptedExtensions")
        let total = try reader.u16()
        var extensions = TLSByteReader(body, context: "EncryptedExtensions", from: 2, to: 2 + total)
        var chosen: String?
        while !extensions.isAtEnd {
            let type = try extensions.u16()
            let length = try extensions.u16()
            let data = try extensions.take(length)
            if type == 0x0010 {
                var list = TLSByteReader(data, context: "ALPN")
                _ = try list.u16()
                let nameLength = try list.u8()
                let name = try list.take(nameLength)
                chosen = String(decoding: name, as: UTF8.self)
            }
        }
        if let protocolName = chosen, !offeredALPN.contains(protocolName) {
            throw MythaiaError.tls("server chose ALPN \(protocolName), which was not offered")
        }
        return chosen
    }

    /// The DER certificates of a TLS 1.3 Certificate message body:
    /// context(1+n), list length(3), then per entry DER(3+n) and
    /// extensions(2+n).
    static func parseCertificateMessage(_ body: [UInt8]) throws -> [[UInt8]] {
        var reader = TLSByteReader(body, context: "Certificate")
        let contextLength = try reader.u8()
        try reader.skip(contextLength)
        let listLength = try reader.u24()
        let start = reader.offset
        var list = TLSByteReader(body, context: "Certificate list", from: start, to: start + listLength)
        var certificates: [[UInt8]] = []
        while !list.isAtEnd {
            let certificateLength = try list.u24()
            certificates.append(try list.take(certificateLength))
            let extensionsLength = try list.u16()
            try list.skip(extensionsLength)
        }
        return certificates
    }

    static func certificateRequestContext(_ body: [UInt8]) throws -> [UInt8] {
        var reader = TLSByteReader(body, context: "CertificateRequest")
        let length = try reader.u8()
        return try reader.take(length)
    }

    static func alpnProtocols(in hello: [UInt8]) -> [String] {
        guard let body = TlsClientHelloBuilder.extensionBody(in: hello, type: 0x0010), body.count >= 2 else { return [] }
        var reader = TLSByteReader(body, context: "ALPN", from: 2)
        var names: [String] = []
        while !reader.isAtEnd {
            guard let length = try? reader.u8(), let name = try? reader.take(length) else { break }
            names.append(String(decoding: name, as: UTF8.self))
        }
        return names
    }

    static func supportedGroups(in hello: [UInt8]) -> [Int] {
        guard let body = TlsClientHelloBuilder.extensionBody(in: hello, type: 0x000A), body.count >= 2 else { return [] }
        var reader = TLSByteReader(body, context: "supported_groups", from: 2)
        var groups: [Int] = []
        while !reader.isAtEnd {
            guard let group = try? reader.u16() else { break }
            groups.append(group)
        }
        return groups
    }
}
