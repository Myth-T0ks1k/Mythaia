import CryptoKit
import XCTest
@testable import MythaiaKit

// MARK: - Shared test support

/// Hex test vectors; anything that is not a hex digit is skipped, so vectors
/// may be split across lines.
enum TLSTestHex {
    static func bytes(_ text: String) -> [UInt8] {
        var out: [UInt8] = []
        var high: UInt8?
        for scalar in text.unicodeScalars {
            let value: UInt8
            switch scalar.value {
            case 0x30...0x39: value = UInt8(scalar.value - 0x30)
            case 0x61...0x66: value = UInt8(scalar.value - 0x61 + 10)
            case 0x41...0x46: value = UInt8(scalar.value - 0x41 + 10)
            default: continue
            }
            if let first = high {
                out.append((first << 4) | value)
                high = nil
            } else {
                high = value
            }
        }
        return out
    }
}

/// Certificates and signatures made with an independent X.509 and
/// signature implementation. The P-256 certificate is self-signed for
/// "self-signed.example"; every signature is over the CertificateVerify
/// content for a transcript hash of 32 bytes of 0x99.
enum TLSTestFixtures {
    static let p256Scalar = "5398a2ad79ed072b6b6dff7a0e17e6e078b297eb6460e1fdd22eeca7c0ada1cd"
    static let p256Certificate = base64("""
        MIIBTzCB9qADAgECAgQBI0VnMAoGCCqGSM49BAMCMB4xHDAaBgNVBAMME3NlbGYtc2lnbmVkLmV4YW1wbGUwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMT\
        AxMDAwMDAwWjAeMRwwGgYDVQQDDBNzZWxmLXNpZ25lZC5leGFtcGxlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErgSEyKjJFURlpwiXfc0c6UWC\
        q5Ua8p4oWCJndDlBCCwDa5Np0a6Gp24VNzOnAq/uMwQrbPwj2FNEBCD/b2jreaMiMCAwHgYDVR0RBBcwFYITc2VsZi1zaWduZWQuZXhhbXBsZTAKBg\
        gqhkjOPQQDAgNIADBFAiAlUJAnW5lnAaolI11wLESwU3qSYSrvcGdb9m+IkNF+GQIhAOtAscUt6jgCwNVuwGL0RFRVqJcSYQnHgg9tEW56EDZ9
        """)
    static let p256CertificateSHA256 = "1dc6e3b77392b16a2b6b12cd1dcc02e4e73950f73bf4890d0ef90d87e5532382"
    static let p256Signature = """
        304502207950faed006284b71eccb0671421defc8f6d809744817b803e3b997c7f144314022100a0d0d9f30646d932f8ff17676bedfc4bca\
        57a9cde5fc6613d948dcecf21c654e
        """

    static let rsaCertificate = base64("""
        MIICxDCCAaygAwIBAgIEASNFZzANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtyc2EuZXhhbXBsZTAeFw0yNjAxMDEwMDAwMDBaFw00NjAxMDEwMD\
        AwMDBaMBYxFDASBgNVBAMMC3JzYS5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvhsLepTnd8YL12J1iT9pSPZCcV7nemCb\
        PTjwrFQpMSKM4WIOJvuUIZc2jHx1hePqEMDAQIOOLEjh7PpvU5jcn9j2Gs0ZZo1WVZfHv6xKtzGXLmIhIIgupvXzGB8N++Y3OlClpbqLvK+W5qT9OK\
        YMKdOLb86V7KVqs6dfLOb2IeXW5TpcPQOeDpCF25Fkk0+UM5IqvJkou6epTos3cF3cQEUlzwI2wogtrRYWWF+dyLUafNfZQNeuNbiTnybOSBAE+jog\
        8x2DLj9SYAPV3QBog/LzGmmktquf/8Xgs66cUPqfJhTOVnn+PagapMQZkoTYKxHx06DSKaOm9NYlgWPuowIDAQABoxowGDAWBgNVHREEDzANggtyc2\
        EuZXhhbXBsZTANBgkqhkiG9w0BAQsFAAOCAQEAGgxgmlv9B7ftd4kLp1ALTMZeWjGaB7tEVGsflyzZCzCaFTkB2W1/SecQv1WxwzmLDuDXgduw3yjH\
        X8o//lyHqGmCpUMUyBDqPWPm77hddEms/RPLrvEJQ5oy/AR5jtb9WwnzQlQFP4Ydo8LVvMTkn6/zD3+sEC2/6NJlfqFmaHKq+VmZk3bjO6RdLx69zq\
        ErXy2i2pFm08a74mmEwpBbQzxtzGcctI+qGMm4+9YxCjFY0PxmQLbR6mtpMpkg455r7Kf3GcAbSmjt6v3gc9spf24kYYC9Zw9CG6gsZtUujLyPCAQm\
        jGRj5sa3EEwrK/Ay7CoUtqoX7diX3tylAQPRgg==
        """)
    static let rsaPSSSignature = """
        bb24b504bcc7a241eddc7fdbfb6ba06a023cb5ee9f7c6bdf0bc89acb1af988c9487610dd31ebc1a220a4f03d2d5c8f240faf6cca3fc067b290d3\
        2ff68e19b70fb39aed366188b76d73d688655b5dfabdbd01dec309d7995f9de14a594ff67632887a960bdd4fd68bf7b2eb1c0f62eed5c9146964\
        04c55844b822a28b57dc82872c220c35cbff6a3039fe5f460757e283516dd47aba5df7a87a2598a0088357d20aaaf48b2ffbd7f1f9710f9c61d2\
        7e2b6394904071a622a7e94203b50a73cdade42b04b2c814ea2af791dd2d91bbd88c844fae8814d34c73a698b9505a9d93550de8f9eb04cc7c02\
        23b18117e594d6a9b84a9e126b08db6316d851effd0c1a32
        """

    static let ed25519Certificate = base64("""
        MIH0MIGnoAMCAQICBAEjRWcwBQYDK2VwMBUxEzARBgNVBAMMCmVkLmV4YW1wbGUwHhcNMjYwMTAxMDAwMDAwWhcNNDYwMTAxMDAwMDAwWjAVMRMwEQ\
        YDVQQDDAplZC5leGFtcGxlMCowBQYDK2VwAyEAT1M95M273Izx46qlf9k2twLWfvqFUH+bQ3gb149jruijGTAXMBUGA1UdEQQOMAyCCmVkLmV4YW1w\
        bGUwBQYDK2VwA0EA4ireOUczVvfUc/7aDQWOjYaRqpKxctSFPmdzJ5ojXAyNzrFuPRW+Qo9DmeslkNNTq98PH6q8mappq2wjtpYGDg==
        """)
    static let ed25519Signature = """
        20f2bd4a8ce8034f071f84c8374d6816b5977c2220f9d084d6d21e7b1a3db9cea12c76a30952349c2ebbfc84304746aa85880b14406c871c773b\
        a607948c9f0a
        """
    static let ed25519PublicKey = "4f533de4cdbbdc8cf1e3aaa57fd936b702d67efa85507f9b43781bd78f63aee8"
    /// The certificate's own signature value, its last 64 bytes.
    static let ed25519CertificateSignature = """
        e22ade39473356f7d473feda0d058e8d8691aa92b172d4853e6773279a235c0c8dceb16e3d15be428f4399eb2590d353abdf0f1faabc99aa69ab\
        6c23b696060e
        """

    static func base64(_ text: String) -> [UInt8] {
        let compact = text.filter { !$0.isWhitespace }
        return Array(Data(base64Encoded: compact) ?? Data())
    }

    /// RFC 8446 §4.4.3 content for the transcript hash the fixtures signed,
    /// written out here rather than taken from the client.
    static var signedContent: [UInt8] {
        var content = [UInt8](repeating: 0x20, count: 64)
        content.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
        content.append(0x00)
        content.append(contentsOf: [UInt8](repeating: 0x99, count: 32))
        return content
    }
}

/// One direction of an in-memory pipe. Data pushed before `close()` can
/// still be read; after it, reads end with nil, like a TCP FIN.
final class TLSTestQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var chunks: [Data] = []
    private var waiter: CheckedContinuation<Data?, Never>?
    private var closed = false

    func push(_ data: Data) -> Bool {
        lock.lock()
        if closed {
            lock.unlock()
            return false
        }
        if let waiting = waiter {
            waiter = nil
            lock.unlock()
            waiting.resume(returning: data)
            return true
        }
        chunks.append(data)
        lock.unlock()
        return true
    }

    func pop() async -> Data? {
        return await withCheckedContinuation { (continuation: CheckedContinuation<Data?, Never>) in
            lock.lock()
            if !chunks.isEmpty {
                let next = chunks.removeFirst()
                lock.unlock()
                continuation.resume(returning: next)
                return
            }
            if closed {
                lock.unlock()
                continuation.resume(returning: nil)
                return
            }
            waiter = continuation
            lock.unlock()
        }
    }

    func close() {
        lock.lock()
        closed = true
        let waiting = waiter
        waiter = nil
        lock.unlock()
        waiting?.resume(returning: nil)
    }
}

/// One end of an in-memory connection. With a chunk size, every send is cut
/// into pieces of that size, so parsers see records split at every offset.
final class TLSTestStream: ByteStream, @unchecked Sendable {
    private let inbound: TLSTestQueue
    private let outbound: TLSTestQueue
    private let chunkSize: Int
    private let lock = NSLock()
    private var sent: [UInt8] = []

    init(inbound: TLSTestQueue, outbound: TLSTestQueue, chunkSize: Int) {
        self.inbound = inbound
        self.outbound = outbound
        self.chunkSize = chunkSize
    }

    /// Everything this end has sent so far.
    var sentBytes: [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return sent
    }

    private func remember(_ bytes: [UInt8]) {
        lock.lock()
        sent.append(contentsOf: bytes)
        lock.unlock()
    }

    func send(_ data: Data) async throws {
        let bytes = [UInt8](data)
        remember(bytes)
        var offset = 0
        while offset < bytes.count {
            let end = chunkSize > 0 ? min(offset + chunkSize, bytes.count) : bytes.count
            if !outbound.push(Data(bytes[offset..<end])) {
                throw MythaiaError.closed
            }
            offset = end
        }
    }

    func receive() async throws -> Data? {
        return await inbound.pop()
    }

    func close() {
        inbound.close()
        outbound.close()
    }
}

/// An in-memory `ByteStream` pair: what one end sends, the other receives.
enum TLSTestStreams {
    static func pair(chunkSize: Int = 0) -> (client: TLSTestStream, server: TLSTestStream) {
        let toServer = TLSTestQueue()
        let toClient = TLSTestQueue()
        let client = TLSTestStream(inbound: toClient, outbound: toServer, chunkSize: chunkSize)
        let server = TLSTestStream(inbound: toServer, outbound: toClient, chunkSize: chunkSize)
        return (client, server)
    }
}

struct TLSTestError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// Server-side record protection, written separately from the client's
/// record layer so the two check each other.
struct TLSTestCipher {
    private let key: SymmetricKey
    private let iv: [UInt8]
    private let chacha: Bool
    private var sequence: UInt64 = 0

    init(suite: Int, key: [UInt8], iv: [UInt8]) {
        self.key = SymmetricKey(data: key)
        self.iv = iv
        self.chacha = suite == 0x1303
    }

    init(suite: Int, trafficSecret: [UInt8]) throws {
        guard let parameters = Tls13Suite.forCode(suite) else { throw TLSTestError("unknown suite") }
        let keys = Tls13Crypto.trafficKeys(parameters, secret: trafficSecret)
        self.init(suite: suite, key: keys.key, iv: keys.iv)
    }

    private func nonce() -> [UInt8] {
        var out = iv
        for index in 0..<8 {
            let shift = UInt64(56 - 8 * index)
            out[4 + index] ^= UInt8((sequence >> shift) & 0xFF)
        }
        return out
    }

    mutating func seal(_ content: [UInt8], type: UInt8, padding: Int = 0) throws -> [UInt8] {
        var inner = content
        inner.append(type)
        inner.append(contentsOf: [UInt8](repeating: 0, count: padding))
        let length = inner.count + 16
        let header: [UInt8] = [0x17, 0x03, 0x03, UInt8(length >> 8), UInt8(length & 0xFF)]
        var sealed: [UInt8]
        if chacha {
            let box = try ChaChaPoly.seal(inner, using: key, nonce: try ChaChaPoly.Nonce(data: nonce()), authenticating: header)
            sealed = Array(box.ciphertext)
            sealed.append(contentsOf: Array(box.tag))
        } else {
            let box = try AES.GCM.seal(inner, using: key, nonce: try AES.GCM.Nonce(data: nonce()), authenticating: header)
            sealed = Array(box.ciphertext)
            sealed.append(contentsOf: Array(box.tag))
        }
        sequence += 1
        return header + sealed
    }

    mutating func open(header: [UInt8], body: [UInt8]) throws -> (type: UInt8, content: [UInt8]) {
        if body.count < 17 { throw TLSTestError("record too short") }
        let ciphertext = Array(body[0..<(body.count - 16)])
        let tag = Array(body[(body.count - 16)...])
        let plain: [UInt8]
        if chacha {
            let box = try ChaChaPoly.SealedBox(nonce: try ChaChaPoly.Nonce(data: nonce()), ciphertext: ciphertext, tag: tag)
            plain = Array(try ChaChaPoly.open(box, using: key, authenticating: header))
        } else {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce()), ciphertext: ciphertext, tag: tag)
            plain = Array(try AES.GCM.open(box, using: key, authenticating: header))
        }
        sequence += 1
        var end = plain.count - 1
        while end >= 0 && plain[end] == 0 { end -= 1 }
        if end < 0 { throw TLSTestError("no content type") }
        return (plain[end], Array(plain[0..<end]))
    }
}

/// Reads whole TLS records off a stream.
final class TLSTestRecordReader {
    private let stream: ByteStream
    private var buffer: [UInt8] = []

    init(_ stream: ByteStream) {
        self.stream = stream
    }

    func next() async throws -> (type: UInt8, header: [UInt8], body: [UInt8])? {
        while true {
            if buffer.count >= 5 {
                let length = (Int(buffer[3]) << 8) | Int(buffer[4])
                if buffer.count >= 5 + length {
                    let header = Array(buffer[0..<5])
                    let body = Array(buffer[5..<(5 + length)])
                    buffer.removeFirst(5 + length)
                    return (header[0], header, body)
                }
            }
            guard let chunk = try await stream.receive() else { return nil }
            buffer.append(contentsOf: chunk)
        }
    }
}

/// A small TLS 1.3 server for the tests: one handshake as RFC 8446 lays it
/// out, with switches for the cases the client has to survive or refuse.
/// It shares the key schedule with the client (that is pinned by the
/// RFC 8448 vectors) but has its own record protection and message layout.
final class TLSTestServer: @unchecked Sendable {
    struct Options {
        var cipherSuite = 0x1301
        var alpn: String?
        var keyShareGroup = 0x001D
        var helloRetryGroup: Int?
        var helloRetryCookie: [UInt8]?
        var answerTls12 = false
        var alertInsteadOfHello: Int?
        var closeAfterClientHello = false
        var requestClientCertificate = false
        var corruptSignature = false
        var corruptFinished = false
        var splitCertificate = false
        var realityPrivateKey: Curve25519.KeyAgreement.PrivateKey?
        var realityShortId: [UInt8] = []
    }

    static let changeCipherSpec: [UInt8] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]

    let stream: TLSTestStream
    let options: Options
    private let records: TLSTestRecordReader
    private(set) var firstClientHello: [UInt8] = []
    private(set) var secondClientHello: [UInt8]?
    private(set) var realityPlaintext: [UInt8]?
    private(set) var clientKeyUpdates = 0
    private(set) var largestClientRecord = 0
    private(set) var sawCloseNotify = false
    private var serverApp: TLSTestCipher?
    private var clientApp: TLSTestCipher?
    private var serverAppSecret: [UInt8] = []
    private var clientAppSecret: [UInt8] = []

    init(stream: TLSTestStream, options: Options) {
        self.stream = stream
        self.options = options
        self.records = TLSTestRecordReader(stream)
    }

    private static func message(_ type: UInt8, _ body: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [type, UInt8((body.count >> 16) & 0xFF), UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)]
        out.append(contentsOf: body)
        return out
    }

    private func sendPlainHandshake(_ message: [UInt8]) async throws {
        var record: [UInt8] = [0x16, 0x03, 0x03, UInt8(message.count >> 8), UInt8(message.count & 0xFF)]
        record.append(contentsOf: message)
        try await stream.send(Data(record))
    }

    private func readClientHello() async throws -> [UInt8] {
        var pending: [UInt8] = []
        while true {
            if pending.count >= 4 {
                let length = (Int(pending[1]) << 16) | (Int(pending[2]) << 8) | Int(pending[3])
                if pending.count >= 4 + length {
                    if pending[0] != 0x01 { throw TLSTestError("expected a ClientHello") }
                    return Array(pending[0..<(4 + length)])
                }
            }
            guard let record = try await records.next() else { throw TLSTestError("client closed before its hello") }
            if record.type == 0x14 { continue }
            if record.type != 0x16 { throw TLSTestError("unexpected record \(record.type) before the hello") }
            pending.append(contentsOf: record.body)
        }
    }

    static func keyShares(in hello: [UInt8]) -> [(group: Int, key: [UInt8])] {
        guard let body = TlsClientHelloBuilder.extensionBody(in: hello, type: 0x0033) else { return [] }
        var shares: [(group: Int, key: [UInt8])] = []
        var index = 2
        while index + 4 <= body.count {
            let group = (Int(body[index]) << 8) | Int(body[index + 1])
            let length = (Int(body[index + 2]) << 8) | Int(body[index + 3])
            if index + 4 + length > body.count { break }
            shares.append((group: group, key: Array(body[(index + 4)..<(index + 4 + length)])))
            index += 4 + length
        }
        return shares
    }

    func handshake() async throws {
        let hello1 = try await readClientHello()
        firstClientHello = hello1
        if options.closeAfterClientHello {
            stream.close()
            return
        }
        if let description = options.alertInsteadOfHello {
            try await stream.send(Data([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, UInt8(description)]))
            return
        }
        // legacy_session_id sits right after type(1) length(3) version(2) random(32).
        let sessionIdLength = Int(hello1[38])
        let sessionId = Array(hello1[39..<(39 + sessionIdLength)])

        if options.answerTls12 {
            var body: [UInt8] = [0x03, 0x03]
            body.append(contentsOf: [UInt8](repeating: 0x42, count: 32))
            body.append(UInt8(sessionId.count))
            body.append(contentsOf: sessionId)
            body.append(contentsOf: [0xC0, 0x2F, 0x00])
            body.append(contentsOf: [0x00, 0x05, 0xFF, 0x01, 0x00, 0x01, 0x00])
            try await sendPlainHandshake(TLSTestServer.message(2, body))
            return
        }

        let suiteCode = options.cipherSuite
        guard let suite = Tls13Suite.forCode(suiteCode) else { throw TLSTestError("unknown suite") }
        var transcript = hello1
        var hello = hello1
        var group = options.keyShareGroup

        if let retryGroup = options.helloRetryGroup {
            group = retryGroup
            var extensions: [UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]
            extensions.append(contentsOf: [0x00, 0x33, 0x00, 0x02, UInt8(retryGroup >> 8), UInt8(retryGroup & 0xFF)])
            if let cookie = options.helloRetryCookie {
                extensions.append(contentsOf: [0x00, 0x2C, 0x00, UInt8(cookie.count + 2), 0x00, UInt8(cookie.count)])
                extensions.append(contentsOf: cookie)
            }
            // The HelloRetryRequest random is SHA-256("HelloRetryRequest").
            let retryRandom = Array(SHA256.hash(data: Array("HelloRetryRequest".utf8)))
            var body: [UInt8] = [0x03, 0x03]
            body.append(contentsOf: retryRandom)
            body.append(UInt8(sessionId.count))
            body.append(contentsOf: sessionId)
            body.append(contentsOf: [UInt8(suiteCode >> 8), UInt8(suiteCode & 0xFF), 0x00])
            body.append(contentsOf: [0x00, UInt8(extensions.count)])
            body.append(contentsOf: extensions)
            let retry = TLSTestServer.message(2, body)
            try await sendPlainHandshake(retry)
            try await stream.send(Data(TLSTestServer.changeCipherSpec))
            var stand: [UInt8] = [0xFE, 0x00, 0x00, UInt8(suite.hash.length)]
            stand.append(contentsOf: suite.hash.digest(hello1))
            transcript = stand + retry
            hello = try await readClientHello()
            secondClientHello = hello
            transcript.append(contentsOf: hello)
        }

        let shares = TLSTestServer.keyShares(in: hello)
        guard let clientShare = shares.first(where: { $0.group == group }) else {
            throw TLSTestError("client sent no share for group \(group)")
        }
        var realityAuthKey: [UInt8]?
        if let realityKey = options.realityPrivateKey {
            realityAuthKey = authenticateReality(hello, key: realityKey, shares: shares)
        }
        guard let serverShare = TLSKeyShare.generate(group: group) else { throw TLSTestError("group") }
        let shared = try serverShare.sharedSecret(peer: clientShare.key)

        let publicKey = serverShare.publicKey
        var extensions: [UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]
        extensions.append(contentsOf: [0x00, 0x33, UInt8((publicKey.count + 4) >> 8), UInt8((publicKey.count + 4) & 0xFF)])
        extensions.append(contentsOf: [UInt8(group >> 8), UInt8(group & 0xFF), UInt8(publicKey.count >> 8), UInt8(publicKey.count & 0xFF)])
        extensions.append(contentsOf: publicKey)
        var body: [UInt8] = [0x03, 0x03]
        body.append(contentsOf: TLSWire.randomBytes(32))
        body.append(UInt8(sessionId.count))
        body.append(contentsOf: sessionId)
        body.append(contentsOf: [UInt8(suiteCode >> 8), UInt8(suiteCode & 0xFF), 0x00])
        body.append(contentsOf: [UInt8(extensions.count >> 8), UInt8(extensions.count & 0xFF)])
        body.append(contentsOf: extensions)
        let serverHello = TLSTestServer.message(2, body)
        try await sendPlainHandshake(serverHello)
        if options.helloRetryGroup == nil {
            try await stream.send(Data(TLSTestServer.changeCipherSpec))
        }
        transcript.append(contentsOf: serverHello)

        let derivation = try Tls13KeyDerivation(cipherSuite: suiteCode)
        let handshake = derivation.deriveHandshakeKeys(sharedSecret: shared, transcript: transcript)
        var serverCipher = TLSTestCipher(suite: suiteCode, key: handshake.keys.serverKey, iv: handshake.keys.serverIV)
        var clientCipher = TLSTestCipher(suite: suiteCode, key: handshake.keys.clientKey, iv: handshake.keys.clientIV)

        // EncryptedExtensions, with ALPN when the client offered ours.
        let offered = TLSHandshakeDriver.alpnProtocols(in: hello)
        var encryptedExtensionsBody: [UInt8] = [0x00, 0x00]
        if let chosen = options.alpn, offered.contains(chosen) {
            let name = Array(chosen.utf8)
            var alpnExtension: [UInt8] = [0x00, 0x10, 0x00, UInt8(name.count + 3), 0x00, UInt8(name.count + 1), UInt8(name.count)]
            alpnExtension.append(contentsOf: name)
            encryptedExtensionsBody = [0x00, UInt8(alpnExtension.count)] + alpnExtension
        }
        let encryptedExtensions = TLSTestServer.message(8, encryptedExtensionsBody)
        transcript.append(contentsOf: encryptedExtensions)
        var firstRecord = encryptedExtensions

        if options.requestClientCertificate {
            // context "ab", signature_algorithms { ecdsa_secp256r1_sha256 }
            let requestBody: [UInt8] = [0x02, 0x61, 0x62, 0x00, 0x08, 0x00, 0x0D, 0x00, 0x04, 0x00, 0x02, 0x04, 0x03]
            let request = TLSTestServer.message(13, requestBody)
            transcript.append(contentsOf: request)
            firstRecord.append(contentsOf: request)
        }

        let leaf: [UInt8]
        if let authKey = realityAuthKey {
            leaf = TLSTestServer.realityCertificate(authKey: authKey)
        } else {
            leaf = TLSTestFixtures.p256Certificate
        }
        var entry: [UInt8] = [UInt8(leaf.count >> 16), UInt8((leaf.count >> 8) & 0xFF), UInt8(leaf.count & 0xFF)]
        entry.append(contentsOf: leaf)
        entry.append(contentsOf: [0x00, 0x00])
        var certificateBody: [UInt8] = [0x00, UInt8(entry.count >> 16), UInt8((entry.count >> 8) & 0xFF), UInt8(entry.count & 0xFF)]
        certificateBody.append(contentsOf: entry)
        let certificate = TLSTestServer.message(11, certificateBody)
        transcript.append(contentsOf: certificate)

        var flight: [UInt8] = []
        if options.splitCertificate {
            let half = certificate.count / 2
            flight.append(contentsOf: try serverCipher.seal(firstRecord + Array(certificate[0..<half]), type: 0x16))
            flight.append(contentsOf: try serverCipher.seal(Array(certificate[half...]), type: 0x16, padding: 5))
        } else {
            flight.append(contentsOf: try serverCipher.seal(firstRecord + certificate, type: 0x16))
        }

        var content = [UInt8](repeating: 0x20, count: 64)
        content.append(contentsOf: Array("TLS 1.3, server CertificateVerify".utf8))
        content.append(0x00)
        content.append(contentsOf: suite.hash.digest(transcript))
        var scheme = 0x0403
        var signature: [UInt8]
        if realityAuthKey != nil {
            // REALITY's client does not check this signature.
            scheme = 0x0807
            signature = [UInt8](repeating: 0x5A, count: 64)
        } else {
            let key = try P256.Signing.PrivateKey(rawRepresentation: TLSTestHex.bytes(TLSTestFixtures.p256Scalar))
            signature = Array(try key.signature(for: content).derRepresentation)
            if options.corruptSignature {
                signature[signature.count - 1] ^= 0x01
            }
        }
        var verifyBody: [UInt8] = [UInt8(scheme >> 8), UInt8(scheme & 0xFF), UInt8(signature.count >> 8), UInt8(signature.count & 0xFF)]
        verifyBody.append(contentsOf: signature)
        let certificateVerify = TLSTestServer.message(15, verifyBody)
        transcript.append(contentsOf: certificateVerify)
        flight.append(contentsOf: try serverCipher.seal(certificateVerify, type: 0x16))

        var verifyData = derivation.computeFinishedVerifyData(trafficSecret: handshake.keys.serverTrafficSecret, transcript: transcript)
        if options.corruptFinished {
            verifyData[0] ^= 0xFF
        }
        let finished = TLSTestServer.message(20, verifyData)
        transcript.append(contentsOf: finished)
        flight.append(contentsOf: try serverCipher.seal(finished, type: 0x16, padding: 2))
        try await stream.send(Data(flight))

        let application = derivation.deriveApplicationKeys(handshakeSecret: handshake.handshakeSecret, fullTranscript: transcript)

        // The client's flight: [ChangeCipherSpec], [empty Certificate], Finished.
        var expectingCertificate = options.requestClientCertificate
        var pending: [UInt8] = []
        var done = false
        while !done {
            guard let record = try await records.next() else { throw TLSTestError("client closed before its Finished") }
            if record.type == 0x14 { continue }
            if record.type != 0x17 { throw TLSTestError("unexpected client record \(record.type)") }
            let opened = try clientCipher.open(header: record.header, body: record.body)
            if opened.type != 0x16 { throw TLSTestError("unexpected inner type \(opened.type)") }
            pending.append(contentsOf: opened.content)
            while pending.count >= 4 && !done {
                let length = (Int(pending[1]) << 16) | (Int(pending[2]) << 8) | Int(pending[3])
                if pending.count < 4 + length { break }
                let message = Array(pending[0..<(4 + length)])
                pending.removeFirst(4 + length)
                if message[0] == 11 && expectingCertificate {
                    if Array(message[4...]) != [0x02, 0x61, 0x62, 0x00, 0x00, 0x00] {
                        throw TLSTestError("client Certificate is not the empty one")
                    }
                    transcript.append(contentsOf: message)
                    expectingCertificate = false
                } else if message[0] == 20 {
                    if expectingCertificate { throw TLSTestError("client sent no Certificate") }
                    let expected = derivation.computeFinishedVerifyData(trafficSecret: handshake.keys.clientTrafficSecret, transcript: transcript)
                    if Array(message[4...]) != expected { throw TLSTestError("client Finished mismatch") }
                    done = true
                } else {
                    throw TLSTestError("unexpected client handshake message \(message[0])")
                }
            }
        }

        serverAppSecret = application.serverTrafficSecret
        clientAppSecret = application.clientTrafficSecret
        serverApp = TLSTestCipher(suite: suiteCode, key: application.serverKey, iv: application.serverIV)
        clientApp = TLSTestCipher(suite: suiteCode, key: application.clientKey, iv: application.clientIV)
    }

    /// Checks the REALITY session id with an independent derivation
    /// (CryptoKit's HKDF); returns the auth key when the client is ours.
    private func authenticateReality(
        _ hello: [UInt8],
        key: Curve25519.KeyAgreement.PrivateKey,
        shares: [(group: Int, key: [UInt8])]
    ) -> [UInt8]? {
        guard let share = shares.first(where: { $0.group == 0x001D }), hello.count > 71, hello[38] == 32 else { return nil }
        guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: share.key),
              let secret = try? key.sharedSecretFromKeyAgreement(with: peer) else { return nil }
        let random = Array(hello[6..<38])
        let authKey = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Array(random[0..<20]),
            sharedInfo: Array("REALITY".utf8),
            outputByteCount: 32
        )
        let sessionId = Array(hello[39..<71])
        var aad = hello
        for index in 39..<71 { aad[index] = 0 }
        guard let nonce = try? AES.GCM.Nonce(data: Array(random[20..<32])),
              let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: Array(sessionId[0..<16]), tag: Array(sessionId[16..<32])),
              let opened = try? AES.GCM.open(box, using: authKey, authenticating: aad) else {
            return nil
        }
        let plaintext = Array(opened)
        var expectedId = [UInt8](repeating: 0, count: 8)
        for index in 0..<min(8, options.realityShortId.count) {
            expectedId[index] = options.realityShortId[index]
        }
        if plaintext.count != 16 || Array(plaintext[8..<16]) != expectedId { return nil }
        realityPlaintext = plaintext
        return authKey.withUnsafeBytes { Array($0) }
    }

    /// What a REALITY server sends: an Ed25519 certificate whose signature
    /// value is replaced by HMAC-SHA512(auth key, its public key).
    static func realityCertificate(authKey: [UInt8]) -> [UInt8] {
        var der = TLSTestFixtures.ed25519Certificate
        let publicKey = TLSTestHex.bytes(TLSTestFixtures.ed25519PublicKey)
        let mac = Array(HMAC<SHA512>.authenticationCode(for: publicKey, using: SymmetricKey(data: authKey)))
        der.replaceSubrange((der.count - 64)..<der.count, with: mac)
        return der
    }

    // MARK: After the handshake

    func send(_ bytes: [UInt8]) async throws {
        guard var cipher = serverApp else { throw TLSTestError("no session") }
        let record = try cipher.seal(bytes, type: 0x17, padding: 1)
        serverApp = cipher
        try await stream.send(Data(record))
    }

    func sendRaw(_ bytes: [UInt8]) async throws {
        try await stream.send(Data(bytes))
    }

    func sendTicket() async throws {
        guard var cipher = serverApp else { throw TLSTestError("no session") }
        // lifetime(4) age_add(4) nonce(1+1) ticket(2+4) extensions(2)
        let body: [UInt8] = [0x00, 0x00, 0x1C, 0x20, 0x01, 0x02, 0x03, 0x04, 0x01, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00]
        let record = try cipher.seal(TLSTestServer.message(4, body), type: 0x16)
        serverApp = cipher
        try await stream.send(Data(record))
    }

    /// Sends KeyUpdate under the current keys, then moves to the next ones.
    func sendKeyUpdate(requestPeerUpdate: Bool) async throws {
        guard var cipher = serverApp else { throw TLSTestError("no session") }
        let record = try cipher.seal(TLSTestServer.message(24, [requestPeerUpdate ? 1 : 0]), type: 0x16)
        serverAppSecret = Tls13Crypto.nextTrafficSecret(Tls13Suite.forCode(options.cipherSuite)?.hash ?? .sha256, secret: serverAppSecret)
        serverApp = try TLSTestCipher(suite: options.cipherSuite, trafficSecret: serverAppSecret)
        try await stream.send(Data(record))
    }

    func sendCloseNotify() async throws {
        guard var cipher = serverApp else { throw TLSTestError("no session") }
        let record = try cipher.seal([0x01, 0x00], type: 0x15)
        serverApp = cipher
        try await stream.send(Data(record))
    }

    /// The next application data from the client; nil at close_notify or EOF.
    func receive() async throws -> [UInt8]? {
        while true {
            guard let record = try await records.next() else { return nil }
            if record.type != 0x17 { continue }
            guard var cipher = clientApp else { throw TLSTestError("no session") }
            let opened = try cipher.open(header: record.header, body: record.body)
            clientApp = cipher
            switch opened.type {
            case 0x17:
                largestClientRecord = max(largestClientRecord, opened.content.count)
                return opened.content
            case 0x16:
                if opened.content.first == 24 {
                    clientKeyUpdates += 1
                    let hash = Tls13Suite.forCode(options.cipherSuite)?.hash ?? .sha256
                    clientAppSecret = Tls13Crypto.nextTrafficSecret(hash, secret: clientAppSecret)
                    clientApp = try TLSTestCipher(suite: options.cipherSuite, trafficSecret: clientAppSecret)
                }
            case 0x15:
                if opened.content.count >= 2 && opened.content[1] == 0 {
                    sawCloseNotify = true
                    return nil
                }
                throw TLSTestError("client sent alert \(opened.content)")
            default:
                throw TLSTestError("unexpected inner type \(opened.type)")
            }
        }
    }
}

// MARK: - Handshake tests

/// Full handshakes of `TLSClient` against the test server over an in-memory
/// pipe: certificate decisions ("allow insecure", pins, the user's trusted
/// fingerprints), every suite and fingerprint, HelloRetryRequest, TLS 1.2
/// refusal, alerts, post-handshake messages and the record layer.
final class TLSHandshakeTests: XCTestCase {

    private let host = "self-signed.example"

    override func tearDown() {
        CertificatePolicy.setAllowInsecure(false)
        CertificatePolicy.setTrustedFingerprints([])
        super.tearDown()
    }

    private func options(
        insecure: Bool = false,
        pins: [Data] = [],
        minVersion: TlsVersion? = nil
    ) -> TLSClientOptions {
        return TLSClientOptions(
            serverName: host,
            alpn: ["h2", "http/1.1"],
            allowInsecure: insecure,
            pinnedCertSHA256: pins,
            minVersion: minVersion
        )
    }

    private var rightPin: Data { Data(TLSTestHex.bytes(TLSTestFixtures.p256CertificateSHA256)) }
    private var wrongPin: Data { Data([UInt8](repeating: 0, count: 32)) }

    /// One handshake; the server's own failure surfaces too.
    private func connect(
        _ clientOptions: TLSClientOptions,
        fingerprint: TlsFingerprint = .chrome133,
        server serverOptions: TLSTestServer.Options = TLSTestServer.Options(),
        chunkSize: Int = 0
    ) async throws -> (client: TLSSessionStream, server: TLSTestServer) {
        let ends = TLSTestStreams.pair(chunkSize: chunkSize)
        let server = TLSTestServer(stream: ends.server, options: serverOptions)
        let serverTask = Task { try await server.handshake() }
        do {
            let session = try await TLSClient.handshake(over: ends.client, options: clientOptions, fingerprint: fingerprint)
            try await serverTask.value
            return (session, server)
        } catch {
            ends.server.close()
            _ = try? await serverTask.value
            throw error
        }
    }

    /// The error text of a handshake that must fail, or nil when it succeeded.
    private func failure(
        _ clientOptions: TLSClientOptions,
        fingerprint: TlsFingerprint = .chrome133,
        server serverOptions: TLSTestServer.Options = TLSTestServer.Options()
    ) async -> String? {
        do {
            let result = try await connect(clientOptions, fingerprint: fingerprint, server: serverOptions)
            result.client.close()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func assertEcho(_ session: TLSSessionStream, _ server: TLSTestServer, file: StaticString = #filePath, line: UInt = #line) async throws {
        try await session.send(Data("ping".utf8))
        let atServer = try await server.receive()
        XCTAssertEqual(atServer, Array("ping".utf8), file: file, line: line)
        try await server.send(Array("pong".utf8))
        let atClient = try await session.receive()
        XCTAssertEqual(atClient, Data("pong".utf8), file: file, line: line)
    }

    // -- Certificate decisions --

    func testAnUntrustedCertificateIsRefusedByDefault() async {
        let error = await failure(options())
        XCTAssertNotNil(error)
        XCTAssertTrue(error?.contains("not trusted") ?? false, error ?? "")
    }

    func testAllowInsecureOnTheServerAcceptsIt() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.alpn = "h2"
        let result = try await connect(options(insecure: true), server: serverOptions)
        XCTAssertEqual(result.client.negotiatedALPN, "h2")
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testTheGlobalAllowInsecureAcceptsItToo() async throws {
        CertificatePolicy.setAllowInsecure(true)
        let result = try await connect(options())
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testARightPinIsEnoughWithoutAllowInsecure() async throws {
        let result = try await connect(options(pins: [rightPin]))
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testAWrongPinIsRefusedEvenWithAllowInsecureOnTheServer() async {
        let error = await failure(options(insecure: true, pins: [wrongPin]))
        XCTAssertTrue(error?.contains("pinned") ?? false, error ?? "allow insecure cancelled the pin")
    }

    func testAWrongPinIsRefusedEvenWithTheGlobalAllowInsecure() async {
        CertificatePolicy.setAllowInsecure(true)
        let error = await failure(options(pins: [wrongPin]))
        XCTAssertTrue(error?.contains("pinned") ?? false, error ?? "the global switch cancelled a server's pin")
    }

    func testARightPinStillConnectsWithAllowInsecureOn() async throws {
        let result = try await connect(options(insecure: true, pins: [rightPin]))
        result.client.close()
    }

    func testAFingerprintTheUserTrustedIsAccepted() async throws {
        CertificatePolicy.setTrustedFingerprints([TLSTestFixtures.p256CertificateSHA256.uppercased()])
        let result = try await connect(options())
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testABadCertificateVerifyIsRefusedEvenWithTheRightPin() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.corruptSignature = true
        let error = await failure(options(pins: [rightPin]), server: serverOptions)
        XCTAssertTrue(error?.contains("CertificateVerify") ?? false, error ?? "a forged signature was accepted")
    }

    func testABadServerFinishedIsRefused() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.corruptFinished = true
        let error = await failure(options(insecure: true), server: serverOptions)
        XCTAssertTrue(error?.contains("Finished") ?? false, error ?? "a wrong Finished was accepted")
    }

    // -- Negotiation --

    func testEverySuiteCarriesData() async throws {
        for suite in [0x1301, 0x1302, 0x1303] {
            var serverOptions = TLSTestServer.Options()
            serverOptions.cipherSuite = suite
            let result = try await connect(options(insecure: true), server: serverOptions)
            try await assertEcho(result.client, result.server)
            result.client.close()
        }
    }

    func testEveryTls13FingerprintCompletesAHandshake() async throws {
        let fingerprints: [TlsFingerprint] = [
            .chrome133, .firefox148, .safari26, .ios14, .edge85, .qq11,
            .chrome120, .firefox120, .safari16, .edge106, .random,
        ]
        for fingerprint in fingerprints {
            let result = try await connect(options(insecure: true), fingerprint: fingerprint)
            try await assertEcho(result.client, result.server)
            result.client.close()
        }
    }

    func testATls12OnlyFingerprintIsRefusedUpFront() async {
        let error = await failure(options(insecure: true), fingerprint: .android11)
        XCTAssertTrue(error?.contains("TLS 1.2") ?? false, error ?? "")
    }

    func testFirefoxP256ShareIsUsable() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.keyShareGroup = 0x0017
        let result = try await connect(options(insecure: true), fingerprint: .firefox148, server: serverOptions)
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testHelloRetryRequestForP256() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.helloRetryGroup = 0x0017
        serverOptions.helloRetryCookie = [0x01, 0x02, 0x03, 0x04]
        serverOptions.alpn = "http/1.1"
        let result = try await connect(options(pins: [rightPin]), server: serverOptions)
        XCTAssertEqual(result.client.negotiatedALPN, "http/1.1")
        try await assertEcho(result.client, result.server)

        let first = result.server.firstClientHello
        let second = try XCTUnwrap(result.server.secondClientHello)
        XCTAssertEqual(TlsClientHelloBuilder.keyShareGroups(in: second), [0x0017])
        XCTAssertEqual(TlsClientHelloBuilder.extensionBody(in: second, type: 0x002C), [0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        // Same random and session id: it is the same hello, retried.
        XCTAssertEqual(Array(second[6..<71]), Array(first[6..<71]))
        result.client.close()
    }

    func testAServerChoosingTls12FailsClearly() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.answerTls12 = true
        let error = await failure(options(insecure: true), server: serverOptions)
        XCTAssertEqual(error, MythaiaError.tls("server chose TLS 1.2").localizedDescription)
    }

    func testTheMinimumVersionIsEnforced() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.answerTls12 = true
        let error = await failure(options(insecure: true, minVersion: .tls13), server: serverOptions)
        XCTAssertTrue(error?.contains("below the minimum") ?? false, error ?? "")
    }

    func testAServerAlertIsReported() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.alertInsteadOfHello = 40
        let error = await failure(options(insecure: true), server: serverOptions)
        XCTAssertTrue(error?.contains("handshake_failure") ?? false, error ?? "")
    }

    func testAServerThatHangsUpIsReported() async {
        var serverOptions = TLSTestServer.Options()
        serverOptions.closeAfterClientHello = true
        let error = await failure(options(insecure: true), server: serverOptions)
        XCTAssertTrue(error?.contains("no response") ?? false, error ?? "")
    }

    func testAClientCertificateRequestGetsAnEmptyCertificate() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.requestClientCertificate = true
        let result = try await connect(options(insecure: true), server: serverOptions)
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    // -- Records --

    func testEverythingSplitIntoSevenBytePieces() async throws {
        var serverOptions = TLSTestServer.Options()
        serverOptions.splitCertificate = true
        serverOptions.alpn = "h2"
        let result = try await connect(options(pins: [rightPin]), server: serverOptions, chunkSize: 7)
        XCTAssertEqual(result.client.negotiatedALPN, "h2")
        try await assertEcho(result.client, result.server)
        result.client.close()
    }

    func testALargeWriteGoesOutInRecordsOfAtMost16K() async throws {
        let result = try await connect(options(insecure: true))
        let payload = (0..<40_000).map { UInt8(truncatingIfNeeded: $0 * 7) }
        try await result.client.send(Data(payload))
        var received: [UInt8] = []
        while received.count < payload.count {
            guard let piece = try await result.server.receive() else { break }
            received.append(contentsOf: piece)
        }
        XCTAssertEqual(received, payload)
        XCTAssertEqual(result.server.largestClientRecord, 16384)
        result.client.close()
    }

    func testTicketAndKeyUpdateAreHandled() async throws {
        let result = try await connect(options(insecure: true))
        try await result.server.sendTicket()
        try await result.server.sendKeyUpdate(requestPeerUpdate: true)
        try await result.server.send(Array("after update".utf8))
        let atClient = try await result.client.receive()
        XCTAssertEqual(atClient, Data("after update".utf8))

        // The client owes a KeyUpdate of its own before its next record.
        try await result.client.send(Data("reply".utf8))
        let atServer = try await result.server.receive()
        XCTAssertEqual(atServer, Array("reply".utf8))
        XCTAssertEqual(result.server.clientKeyUpdates, 1)

        try await result.client.send(Data("again".utf8))
        let again = try await result.server.receive()
        XCTAssertEqual(again, Array("again".utf8))
        XCTAssertEqual(result.server.clientKeyUpdates, 1)
        result.client.close()
    }

    func testCloseNotifyFromTheServerEndsTheStream() async throws {
        let result = try await connect(options(insecure: true))
        try await result.server.send(Array("last".utf8))
        try await result.server.sendCloseNotify()
        var collected = Data()
        while let piece = try await result.client.receive() {
            collected.append(piece)
        }
        XCTAssertEqual(collected, Data("last".utf8))
        result.client.close()
    }

    func testClosingSendsCloseNotify() async throws {
        let result = try await connect(options(insecure: true))
        result.client.close()
        let end = try await result.server.receive()
        XCTAssertNil(end)
        XCTAssertTrue(result.server.sawCloseNotify)
    }

    func testARecordThatDoesNotDecryptCarriesItsRawBytes() async throws {
        let result = try await connect(options(insecure: true))
        var garbage: [UInt8] = [0x17, 0x03, 0x03, 0x00, 0x14]
        garbage.append(contentsOf: [UInt8](repeating: 0xAB, count: 20))
        try await result.server.sendRaw(garbage)
        do {
            _ = try await result.client.receive()
            XCTFail("a record that does not decrypt was accepted")
        } catch let error as TLSDecryptionFailed {
            XCTAssertEqual(Array(error.rawData), garbage)
        }
        // After that the stream carries raw bytes both ways (Vision's direct copy).
        try await result.server.sendRaw([0x01, 0x02, 0x03])
        let raw = try await result.client.receiveRaw()
        XCTAssertEqual(raw, Data([0x01, 0x02, 0x03]))
        try await result.client.sendRaw(Data([0x09]))
        result.client.close()
    }

    func testSendAfterCloseFails() async throws {
        let result = try await connect(options(insecure: true))
        result.client.close()
        do {
            try await result.client.send(Data("late".utf8))
            XCTFail("a send after close succeeded")
        } catch {
            XCTAssertEqual(error as? MythaiaError, MythaiaError.closed)
        }
    }
}
