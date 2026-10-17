import Foundation
import Network

/**
 * A small HTTPS/1.1 GET that connects to one host while naming another.
 *
 * URLSession cannot do this: it derives the SNI and the `Host` header from
 * the URL, and neither can be pointed elsewhere. Network.framework can set
 * the SNI on its own, so a subscription behind a blocked domain is fetched by
 * dialling the front (a CDN edge, an IP) with the front's name in the
 * ClientHello and the panel's name only inside the encrypted request.
 *
 * The same request can also go through one of the user's servers (`via`),
 * which is how a subscription whose panel is blocked outright still updates:
 * the server dials the panel, and TLS runs end to end inside the tunnel.
 *
 * Deliberately minimal: one request, `Connection: close`, no redirects
 * followed (a redirect would leave the front), no compression asked for.
 */
enum FrontedHttpClient {

    struct Response {
        let status: Int
        /// Names lower-cased.
        let headers: [String: String]
        let body: Data

        func header(_ name: String) -> String? {
            headers[name.lowercased()]
        }
    }

    public static let defaultTimeout: Double = 30
    private static let maxHeaderBytes = 64 * 1024

    /**
     * - Parameters:
     *   - url: the subscription URL; its host goes in the `Host` header.
     *   - sni: the name presented in TLS and used to verify the certificate.
     *   - target: `host` or `host:port` to actually connect to.
     *   - via: a server of the user's to send the request through, or nil to
     *     connect directly. Only with `via` may `url` be plain `http`.
     */
    static func get(
        url: URL,
        sni: String,
        target: String,
        extraHeaders: [(String, String)],
        allowInsecure: Bool,
        maxBody: Int,
        via: ProxyConfiguration? = nil,
        timeout: Double = defaultTimeout
    ) async throws -> Response {
        let https = url.scheme?.lowercased() == "https"
        guard https || via != nil else {
            throw MythaiaError.invalidConfiguration("plain HTTP needs a server to go through")
        }
        let defaultPort = https ? 443 : 80
        let urlPort = url.port
        let (targetHost, targetPort) = splitTarget(target, defaultPort: urlPort ?? defaultPort)
        guard let port = UInt16(exactly: targetPort), port > 0 else {
            throw MythaiaError.invalidConfiguration("Invalid port: \(targetPort)")
        }

        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var path = components?.percentEncodedPath ?? ""
        if path.isEmpty { path = "/" }
        if let query = components?.percentEncodedQuery { path += "?" + query }
        let host = bareHost(url)
        let bracketed = host.utf8.contains(UInt8(ascii: ":")) ? "[\(host)]" : host
        var hostHeader = bracketed
        if let explicit = urlPort, explicit != defaultPort { hostHeader += ":\(explicit)" }

        var request = "GET \(path) HTTP/1.1\r\n"
        request += "Host: \(hostHeader)\r\n"
        request += "User-Agent: Mythaia\r\n"
        request += "Accept: */*\r\n"
        for (name, value) in extraHeaders { request += "\(name): \(value)\r\n" }
        request += "Connection: close\r\n\r\n"
        let requestBytes = Data(request.utf8)

        let opened = FrontedStreams()
        defer { opened.closeAll() }
        return try await withTimeout(timeout, target) { () async throws -> Response in
            try await withTaskCancellationHandler(operation: { () async throws -> Response in
                let stream: ByteStream
                if let server = via {
                    stream = try await ViaServerHTTP.open(
                        through: server,
                        host: targetHost,
                        port: port,
                        tlsServerName: https ? sni : nil,
                        allowInsecure: allowInsecure,
                        timeout: timeout,
                        opened: opened
                    )
                } else {
                    let connection = FrontedTLSConnection(
                        host: targetHost,
                        port: port,
                        serverName: sni,
                        alpn: ["http/1.1"],
                        allowInsecure: allowInsecure,
                        connectTimeout: timeout
                    )
                    opened.add(connection)
                    try await connection.start()
                    stream = connection
                }
                try await stream.send(requestBytes)
                return try await FrontedHttpClient.readResponse(stream, maxBody: maxBody)
            }, onCancel: {
                opened.closeAll()
            })
        }
    }

    /// The URL's host without IPv6 brackets.
    static func bareHost(_ url: URL) -> String {
        let host = url.host ?? ""
        if LinkText.hasPrefix(host, "[") && LinkText.hasSuffix(host, "]") {
            return LinkText.removeSuffix(LinkText.removePrefix(host, "["), "]")
        }
        return host
    }

    static func splitTarget(_ target: String, defaultPort: Int) -> (String, Int) {
        let t = LinkText.trim(target)
        let bytes = Array(t.utf8)
        if bytes.first == UInt8(ascii: "["), let close = bytes.firstIndex(of: UInt8(ascii: "]")), close > 0 {
            let host = LinkText.string(bytes[1..<close])
            let rest = LinkText.removePrefix(LinkText.string(bytes[(close + 1)...]), ":")
            return (host, Int(rest) ?? defaultPort)
        }
        // One colon is host:port; more than one is a bare IPv6 literal.
        if let colon = bytes.lastIndex(of: UInt8(ascii: ":")), colon > 0, bytes.firstIndex(of: UInt8(ascii: ":")) == colon {
            if let port = Int(LinkText.string(bytes[(colon + 1)...])) {
                return (LinkText.string(bytes[..<colon]), port)
            }
        }
        return (t, defaultPort)
    }

    // MARK: - Reading the response

    static func readResponse(_ stream: ByteStream, maxBody: Int) async throws -> Response {
        var buffer: [UInt8] = []
        var headerEnd = -1
        while headerEnd < 0 {
            guard let chunk = try await stream.receive() else { break }
            let searchFrom = max(0, buffer.count - 3)
            buffer.append(contentsOf: chunk)
            headerEnd = LinkText.indexOf(buffer, crlfcrlf, from: searchFrom) ?? -1
            if headerEnd < 0 && buffer.count > maxHeaderBytes {
                throw MythaiaError.connectFailed("Response headers too large")
            }
        }
        if headerEnd < 0 { throw MythaiaError.connectFailed("Connection closed before headers") }

        let headerText = String(bytes: buffer[..<headerEnd], encoding: .isoLatin1) ?? ""
        let lines = headerText.components(separatedBy: "\r\n")
        let statusLine = lines.first ?? ""
        let statusParts = LinkText.split(statusLine, UInt8(ascii: " "))
        guard statusParts.count > 1, let status = Int(statusParts[1]) else {
            throw MythaiaError.connectFailed("Malformed status line")
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), colon > line.startIndex else { continue }
            let name = LinkText.trim(String(line[..<colon])).lowercased()
            let value = LinkText.trim(String(line[line.index(after: colon)...]))
            headers[name] = value
        }

        var body = Array(buffer[(headerEnd + 4)...])
        let contentLength = headers["content-length"].flatMap { Int($0) }
        let chunked = headers["transfer-encoding"]?.lowercased().contains("chunked") == true

        func ensureBounded() throws {
            if body.count > maxBody {
                throw MythaiaError.connectFailed("Response larger than \(maxBody) bytes")
            }
        }

        if chunked {
            // The full check walks the whole body, so it only runs once the
            // tail looks like the end of one; before the gate it ran after
            // every TLS record, quadratic in the body size.
            while !(mayEndChunkedBody(body) && chunkedComplete(body)) {
                guard let chunk = try await stream.receive() else { break }
                body.append(contentsOf: chunk)
                try ensureBounded()
            }
            return Response(status: status, headers: headers, body: try decodeChunked(body))
        }

        if let length = contentLength {
            while body.count < length {
                guard let chunk = try await stream.receive() else { break }
                body.append(contentsOf: chunk)
                try ensureBounded()
            }
            let bytes = body.count > length ? Array(body[..<max(0, length)]) : body
            return Response(status: status, headers: headers, body: Data(bytes))
        }

        // Neither: the body runs until the server closes. A connection torn
        // down instead of closed cleanly ends it the same way; nothing in the
        // response could have said how long it was meant to be.
        while true {
            let chunk: Data?
            do {
                chunk = try await stream.receive()
            } catch {
                if Task.isCancelled { throw error }
                break
            }
            guard let data = chunk else { break }
            body.append(contentsOf: data)
            try ensureBounded()
        }
        return Response(status: status, headers: headers, body: Data(body))
    }

    private static let crlfcrlf: [UInt8] = [13, 10, 13, 10]
    private static let cr: UInt8 = 13
    private static let lf: UInt8 = 10

    /// How far back from the end a zero-size chunk line is looked for; trailers, if any, sit in between.
    private static let chunkEndWindow = 4096

    /**
     * Whether `body` could be a complete chunked body: it ends with the blank
     * line that closes one, and a line that is just `0` (or `0;extension`)
     * sits within the last stretch. Chunk data can mimic that, so it is a
     * gate in front of `chunkedComplete`, not a replacement for it.
     */
    private static func mayEndChunkedBody(_ body: [UInt8]) -> Bool {
        let n = body.count
        if n < 5 { return false }
        if body[n - 4] != cr || body[n - 3] != lf || body[n - 2] != cr || body[n - 1] != lf { return false }
        let earliest = max(0, n - chunkEndWindow)
        var i = n - 5
        while i >= earliest {
            if body[i] == UInt8(ascii: "0") && (i == 0 || body[i - 1] == lf) {
                let next = body[i + 1]
                if next == cr || next == UInt8(ascii: ";") { return true }
            }
            i -= 1
        }
        return false
    }

    /// True once the terminating zero-length chunk has arrived.
    private static func chunkedComplete(_ bytes: [UInt8]) -> Bool {
        (try? decodeChunked(bytes)) != nil
    }

    static func decodeChunked(_ bytes: [UInt8]) throws -> Data {
        var out: [UInt8] = []
        var pos = 0
        while true {
            guard let lineEnd = LinkText.indexOf(bytes, [cr, lf], from: pos) else {
                throw MythaiaError.connectFailed("incomplete chunk size")
            }
            let line = String(bytes: bytes[pos..<lineEnd], encoding: .isoLatin1) ?? ""
            let sizeText = LinkText.trim(line.components(separatedBy: ";").first ?? "")
            guard let size = Int(sizeText, radix: 16), size >= 0 else {
                throw MythaiaError.connectFailed("bad chunk size")
            }
            pos = lineEnd + 2
            if size == 0 { return Data(out) }
            if size > bytes.count || pos + size + 2 > bytes.count {
                throw MythaiaError.connectFailed("incomplete chunk")
            }
            out.append(contentsOf: bytes[pos..<(pos + size)])
            pos += size + 2
        }
    }

    /// The front and why it failed, as the error a user sees names it.
    static func describe(_ target: String, _ error: Error) -> String {
        let why = ShareLinkParams.message(error)
        Log.warning("Front \(target) failed: \(why)")
        if let mythaia = error as? MythaiaError, case .connectFailed(let detail) = mythaia {
            return "\(target): \(detail)"
        }
        if let mythaia = error as? MythaiaError, case .timeout = mythaia {
            return "\(target): timed out"
        }
        return "\(target): \(why)"
    }
}

/// The streams one fetch opened, closed together when it ends or is cancelled.
final class FrontedStreams: @unchecked Sendable {
    private let lock = NSLock()
    private var streams: [ByteStream] = []
    private var closed = false

    func add(_ stream: ByteStream) {
        lock.lock()
        if closed {
            lock.unlock()
            stream.close()
            return
        }
        streams.append(stream)
        lock.unlock()
    }

    func closeAll() {
        lock.lock()
        let all = streams
        streams = []
        closed = true
        lock.unlock()
        for stream in all.reversed() { stream.close() }
    }
}

/// A TLS connection over Network.framework with its own server name, for fronting.
final class FrontedTLSConnection: ByteStream {
    private let connection: NWConnection
    private let queue: DispatchQueue

    init(host: String, port: UInt16, serverName: String, alpn: [String], allowInsecure: Bool, connectTimeout: Double) {
        let queue = DispatchQueue(label: "com.mythaia.fronted-http")
        self.queue = queue
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        sec_protocol_options_set_tls_server_name(options, serverName)
        for protocolName in alpn {
            sec_protocol_options_add_tls_application_protocol(options, protocolName)
        }
        if allowInsecure {
            sec_protocol_options_set_verify_block(options, { _, _, complete in
                complete(true)
            }, queue)
        }
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = max(1, Int(connectTimeout.rounded(.up)))
        let parameters = NWParameters(tls: tls, tcp: tcp)
        // Fronting must reach the front itself with the name it chose; a
        // system proxy in between would make the connection on its own terms.
        parameters.preferNoProxies = true
        let endpointPort = NWEndpoint.Port(rawValue: port) ?? .https
        connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
    }

    func start() async throws {
        let once = FrontedResumeOnce()
        let conn = connection
        let queue = self.queue
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            conn.stateUpdateHandler = { [weak conn] state in
                switch state {
                case .ready:
                    if once.claim() { continuation.resume() }
                case .failed(let error):
                    if once.claim() { continuation.resume(throwing: FrontedTLSConnection.describe(error)) }
                case .waiting(let error):
                    // A one-shot fetch does not wait for the network to come back.
                    if once.claim() { continuation.resume(throwing: FrontedTLSConnection.describe(error)) }
                    conn?.cancel()
                case .cancelled:
                    if once.claim() { continuation.resume(throwing: MythaiaError.closed) }
                default:
                    break
                }
            }
            conn.start(queue: queue)
        }
    }

    private static func describe(_ error: NWError) -> MythaiaError {
        switch error {
        case .tls(let status):
            return MythaiaError.tls("handshake failed (\(status))")
        default:
            return MythaiaError.connectFailed(error.localizedDescription)
        }
    }

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: FrontedTLSConnection.describe(error))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    func receive() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let data = data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if let error = error {
                    continuation.resume(throwing: FrontedTLSConnection.describe(error))
                } else {
                    // Complete, or nothing more will come: either way the end.
                    _ = isComplete
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    func close() {
        connection.cancel()
    }
}

/// Lets exactly one of several callbacks resume a continuation.
final class FrontedResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
