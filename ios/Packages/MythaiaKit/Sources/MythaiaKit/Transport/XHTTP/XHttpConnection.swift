import Foundation

/// An XHTTP tunnel in one of its three modes:
/// - stream-one: one POST whose body is the upload and whose response is the download;
/// - stream-up: a GET for the download and one long POST for the upload;
/// - packet-up: a GET for the download, and every upload batch a POST of its own
///   with a sequence number.
///
/// Over HTTP/1.1 a request with an endless body ties up its connection, so the
/// upload of stream-up and packet-up dials a second one. Over HTTP/2 every
/// request is a stream of one connection.
final class XHttpConnection: ByteStream, @unchecked Sendable {
    let configuration: XHttpConfiguration
    let mode: XHttpMode
    let sessionId: String

    /// HTTP/1.1: the download (or stream-one) connection.
    private let download: ByteStream?
    /// HTTP/1.1, stream-up and packet-up: dials the upload connection.
    private let uploadFactory: (() async throws -> ByteStream)?
    /// HTTP/2: the connection every request is a stream of.
    private let session: Http2Session?

    private let lock = NSLock()
    private var connected = true
    private var upload: ByteStream?
    private var uploadDrainTask: Task<Void, Never>?
    private var chunkedDecoder = ChunkedTransferDecoder()
    private var nextSeq: Int64 = 0

    /// HTTP/2: the download GET, or stream-one's single POST.
    private var pooledDownload: Http2Stream?
    /// HTTP/2 stream-up: the upload POST.
    private var pooledUpload: Http2Stream?
    /// HTTP/2 packet-up: the POSTs whose reply has not ended them yet. close()
    /// ends them, so a reply that never comes cannot leave a stream behind.
    private var pooledPosts: [ObjectIdentifier: Http2Stream] = [:]
    private var h2StreamClosed = false

    // Packet-up batching: each send() appends to the queue and waits until
    // the batched POST has been written; one flush at a time drains the
    // queue into one POST per scMinPostsIntervalMs. Essential for UDP, where
    // each datagram would otherwise become its own HTTP request.
    private var packetUpQueue: [(Data, TransportDeferred<Void>)] = []
    private var packetUpFlushPending = false
    private var packetUpLastFlushTime: UInt64 = 0
    private var flushTask: Task<Void, Never>?

    /// Over HTTP/1.1: `download` carries the first request; `uploadFactory`
    /// dials the upload connection stream-up and packet-up need.
    init(download: ByteStream, configuration: XHttpConfiguration, mode: XHttpMode, sessionId: String,
         uploadFactory: (() async throws -> ByteStream)?) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.download = download
        self.uploadFactory = uploadFactory
        self.session = nil
    }

    /// Over HTTP/2: every request a stream of `session`, which the tunnel owns.
    init(session: Http2Session, configuration: XHttpConfiguration, mode: XHttpMode, sessionId: String) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.download = nil
        self.uploadFactory = nil
        self.session = session
    }

    var isConnected: Bool {
        lock.lock()
        let alive = connected
        let stream = pooledDownload
        lock.unlock()
        if !alive { return false }
        if session != nil, let stream = stream {
            return stream.isConnected
        }
        return true
    }

    // MARK: - Setup

    /// Sends the first requests. Over HTTP/1.1 this waits for the download's
    /// response head; over HTTP/2 nothing waits for a response: a CDN that
    /// holds the download's headers until the backend has data would
    /// otherwise wait for an upload that is never sent.
    func performSetup() async throws {
        if session != nil {
            try await performPooledSetup()
        } else if mode == .streamOne {
            try await performStreamOneSetup()
        } else if mode == .streamUp {
            try await performStreamUpSetup()
        } else {
            try await performPacketUpSetup()
        }
    }

    private func performPooledSetup() async throws {
        guard let session = session else { return }
        if mode == .streamOne {
            let stream = try await session.acquireStream("xhttp")
            setPooled(download: stream)
            try await stream.openRequest(encodeH2RequestHeaders(method: "POST", includeMeta: false), endStream: false, awaitResponse: false)
            return
        }
        // stream-up and packet-up: the download is a GET with no body.
        let download = try await session.acquireStream("xhttp")
        setPooled(download: download)
        try await download.openRequest(encodeH2RequestHeaders(method: "GET", includeMeta: true), endStream: true, awaitResponse: false)
        if mode == .streamUp {
            let upload = try await session.acquireStream("xhttp")
            setPooled(upload: upload)
            try await upload.openRequest(encodeH2UploadHeaders(seq: nil, contentLength: nil), endStream: false, awaitResponse: false)
        }
    }

    private func setPooled(download stream: Http2Stream) {
        lock.lock()
        pooledDownload = stream
        lock.unlock()
    }

    private func setPooled(upload stream: Http2Stream) {
        lock.lock()
        pooledUpload = stream
        lock.unlock()
    }

    private func downloadStream() throws -> ByteStream {
        guard let stream = download else { throw XHttpError.connectionClosed }
        return stream
    }

    private func performStreamOneSetup() async throws {
        let path = configuration.normalizedPath
        // stream-one: no session id.
        var request = buildRequestLine(method: configuration.uplinkHTTPMethod, path: path, queryParts: [queryParamsForMeta(seq: nil)])
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(userAgent)\r\n"
        applyPadding(into: &request, forPath: path)
        request += "Transfer-Encoding: chunked\r\n"
        if !configuration.noGrpcHeader {
            request += "Content-Type: application/grpc\r\n"
        }
        appendCustomHeaders(into: &request)
        request += "\r\n"

        try await downloadStream().send(Data(request.utf8))
        try await receiveResponseHeaders()
    }

    /// The GET on the download connection, then the upload connection and
    /// its streaming POST with chunked encoding.
    private func performStreamUpSetup() async throws {
        try await downloadStream().send(buildDownloadGETRequest())
        try await receiveResponseHeaders()

        guard let factory = uploadFactory else {
            throw XHttpError.setupFailed("No upload connection factory for stream-up")
        }
        let up = try await factory()
        guard storeUpload(up) else {
            up.close()
            throw XHttpError.connectionClosed
        }
        try await up.send(buildStreamUpPOSTRequest())
    }

    private func performPacketUpSetup() async throws {
        try await downloadStream().send(buildDownloadGETRequest())
        try await receiveResponseHeaders()

        guard let factory = uploadFactory else {
            throw XHttpError.setupFailed("No upload connection factory")
        }
        let up = try await factory()
        guard storeUpload(up) else {
            up.close()
            throw XHttpError.connectionClosed
        }
        // The POSTs' responses are read and dropped as they come; left
        // unread they fill the receive buffer and stall the uploads.
        let drain = Task {
            while true {
                do {
                    guard let data = try await up.receive(), !data.isEmpty else { return }
                } catch {
                    return
                }
            }
        }
        lock.lock()
        uploadDrainTask = drain
        lock.unlock()
    }

    private func storeUpload(_ stream: ByteStream) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if !connected { return false }
        upload = stream
        return true
    }

    private func currentUpload() -> ByteStream? {
        lock.lock()
        defer { lock.unlock() }
        return upload
    }

    /// Reads the download's response head; the status must be 200. What
    /// follows the head is the start of the chunked body.
    private func receiveResponseHeaders() async throws {
        let stream = try downloadStream()
        var buffer: [UInt8] = []
        while true {
            guard let data = try await stream.receive(), !data.isEmpty else {
                throw XHttpError.setupFailed("Empty response from server")
            }
            buffer.append(contentsOf: data)
            guard let end = TransportEncoding.headerEnd(buffer) else {
                if buffer.count > 64 * 1024 {
                    throw XHttpError.setupFailed("response head longer than 64 KB")
                }
                continue
            }
            let leftover = Array(buffer[(end + 4)...])
            if !leftover.isEmpty {
                try feedDecoder(Data(leftover))
            }
            let head = String(decoding: buffer[0..<end], as: UTF8.self)
            let firstLine = head.components(separatedBy: "\r\n").first ?? ""
            if !firstLine.contains("200") {
                throw XHttpError.httpError("Expected HTTP 200, got: \(firstLine)")
            }
            return
        }
    }

    // MARK: - HTTP/1.1 requests

    private var userAgent: String {
        configuration.headers["User-Agent"] ?? WebSocketConnection.chromeUserAgent
    }

    /// The configured headers but User-Agent, in a fixed order.
    private func appendCustomHeaders(into request: inout String) {
        for key in configuration.headers.keys.sorted() where key != "User-Agent" {
            request += "\(key): \(configuration.headers[key] ?? "")\r\n"
        }
    }

    /// Without obfs mode: `Referer: https://{host}{path}?x_padding=XXX...`.
    /// With it: the padding in a header, a cookie, the query (added by
    /// buildRequestLine) or a URL in a header, as configured.
    private func applyPadding(into request: inout String, forPath path: String) {
        let padding = configuration.generatePadding()
        if !configuration.xPaddingObfsMode {
            request += "Referer: https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
            return
        }
        switch configuration.xPaddingPlacement {
        case .header:
            request += "\(configuration.xPaddingHeader): \(padding)\r\n"
        case .queryInHeader:
            request += "\(configuration.xPaddingHeader): https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
        case .cookie:
            request += "Cookie: \(configuration.xPaddingKey)=\(padding)\r\n"
        default:
            break
        }
    }

    private func applySessionId(into headers: inout String, path: inout String) {
        if sessionId.isEmpty { return }
        let key = configuration.normalizedSessionKey
        switch configuration.sessionPlacement {
        case .path:
            path = XHttpConnection.appendToPath(path, sessionId)
        case .header:
            headers += "\(key): \(sessionId)\r\n"
        case .cookie:
            headers += "Cookie: \(key)=\(sessionId)\r\n"
        default:
            // The query is queryParamsForMeta's.
            break
        }
    }

    private func applySeq(into headers: inout String, path: inout String, seq: Int64) {
        let key = configuration.normalizedSeqKey
        switch configuration.seqPlacement {
        case .path:
            path = XHttpConnection.appendToPath(path, String(seq))
        case .header:
            headers += "\(key): \(seq)\r\n"
        case .cookie:
            headers += "Cookie: \(key)=\(seq)\r\n"
        default:
            break
        }
    }

    /// The query parameters for a session id and sequence number placed in the query.
    private func queryParamsForMeta(seq: Int64?) -> String {
        var parts: [String] = []
        if !sessionId.isEmpty && configuration.sessionPlacement == .query {
            parts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if let seq = seq, configuration.seqPlacement == .query {
            parts.append("\(configuration.normalizedSeqKey)=\(seq)")
        }
        return parts.joined(separator: "&")
    }

    static func appendToPath(_ path: String, _ segment: String) -> String {
        path.hasSuffix("/") ? path + segment : path + "/" + segment
    }

    private func buildRequestLine(method: String, path: String, queryParts: [String]) -> String {
        var url = path
        var allQuery = queryParts.filter { !$0.isEmpty }
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            allQuery.insert(configQuery, at: 0)
        }
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            allQuery.append("\(configuration.xPaddingKey)=\(configuration.generatePadding())")
        }
        if !allQuery.isEmpty {
            url += "?" + allQuery.joined(separator: "&")
        }
        return "\(method) \(url) HTTP/1.1\r\n"
    }

    /// The download GET of packet-up and stream-up, the session id where the
    /// configuration puts it.
    func buildDownloadGETRequest() -> Data {
        var path = configuration.normalizedPath
        var metaHeaders = ""
        applySessionId(into: &metaHeaders, path: &path)
        if !path.hasSuffix("/") { path += "/" }
        var request = buildRequestLine(method: "GET", path: path, queryParts: [queryParamsForMeta(seq: nil)])
        request += metaHeaders
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(userAgent)\r\n"
        applyPadding(into: &request, forPath: path)
        appendCustomHeaders(into: &request)
        request += "\r\n"
        return Data(request.utf8)
    }

    /// stream-up's upload POST: the session id where configured, no
    /// sequence number, chunked transfer.
    private func buildStreamUpPOSTRequest() -> Data {
        var path = configuration.normalizedPath
        var metaHeaders = ""
        applySessionId(into: &metaHeaders, path: &path)
        if !path.hasSuffix("/") { path += "/" }
        var request = buildRequestLine(method: configuration.uplinkHTTPMethod, path: path, queryParts: [queryParamsForMeta(seq: nil)])
        request += metaHeaders
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(userAgent)\r\n"
        applyPadding(into: &request, forPath: path)
        request += "Transfer-Encoding: chunked\r\n"
        if !configuration.noGrpcHeader {
            request += "Content-Type: application/grpc\r\n"
        }
        appendCustomHeaders(into: &request)
        request += "\r\n"
        return Data(request.utf8)
    }

    /// One packet-up POST with sequence number `seq`. The data goes in the
    /// body, or base64url in headers or a cookie, as uplinkDataPlacement says.
    func buildSinglePost(_ data: Data, seq: Int64) -> Data {
        var path = configuration.normalizedPath
        var metaHeaders = ""
        applySessionId(into: &metaHeaders, path: &path)
        applySeq(into: &metaHeaders, path: &path, seq: seq)

        var body = data
        if configuration.uplinkDataPlacement != .body {
            let encoded = TransportEncoding.base64URL(data)
            let chunkSize = configuration.uplinkChunkSize > 0 ? configuration.uplinkChunkSize : max(1, encoded.count)
            let key = configuration.uplinkDataKey
            switch configuration.uplinkDataPlacement {
            case .header:
                let characters = Array(encoded)
                var index = 0
                var chunkIndex = 0
                while index < characters.count {
                    let end = min(index + chunkSize, characters.count)
                    metaHeaders += "\(key)-\(chunkIndex): \(String(characters[index..<end]))\r\n"
                    index = end
                    chunkIndex += 1
                }
                metaHeaders += "\(key)-Length: \(encoded.count)\r\n"
                metaHeaders += "\(key)-Upstream: 1\r\n"
            case .cookie:
                metaHeaders += "Cookie: \(key)=\(encoded)\r\n"
            default:
                break
            }
            body = Data()
        }

        var request = buildRequestLine(method: configuration.uplinkHTTPMethod, path: path, queryParts: [queryParamsForMeta(seq: seq)])
        request += metaHeaders
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(userAgent)\r\n"
        applyPadding(into: &request, forPath: path)
        request += "Content-Length: \(body.count)\r\n"
        request += "Connection: keep-alive\r\n"
        appendCustomHeaders(into: &request)
        request += "\r\n"

        var out = Data(request.utf8)
        out.append(body)
        return out
    }

    // MARK: - HTTP/2 requests

    /// The header block of stream-one's POST, or of the download GET of
    /// stream-up and packet-up (`includeMeta`: with the session id).
    func encodeH2RequestHeaders(method: String, includeMeta: Bool) -> Data {
        var block: [UInt8] = []
        // Pseudo-headers in this order: :authority, :method, :path, :scheme.
        XHttpConnection.appendLiteral(&block, nameIndex: 1, value: configuration.host)
        // GET and POST are static-table entries 2 and 3.
        block.append(method == "GET" ? 0x82 : 0x83)

        var path = configuration.normalizedPath
        if includeMeta && !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = XHttpConnection.appendToPath(path, sessionId)
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            queryParts.append(configQuery)
        }
        if includeMeta && !sessionId.isEmpty && configuration.sessionPlacement == .query {
            queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if !queryParts.isEmpty {
            path += "?" + queryParts.joined(separator: "&")
        }

        if path == "/" {
            // :path / is static-table entry 4.
            block.append(0x84)
        } else {
            XHttpConnection.appendLiteral(&block, nameIndex: 4, value: path)
        }
        // :scheme https, static-table entry 7.
        block.append(0x87)

        if method != "GET" && !configuration.noGrpcHeader {
            XHttpConnection.appendLiteral(&block, nameIndex: 31, value: "application/grpc")
        }

        if includeMeta && !sessionId.isEmpty {
            let key = configuration.normalizedSessionKey
            switch configuration.sessionPlacement {
            case .header:
                XHttpConnection.appendNewName(&block, name: key.lowercased(), value: sessionId)
            case .cookie:
                XHttpConnection.appendLiteral(&block, nameIndex: 32, value: "\(key)=\(sessionId)")
            default:
                // The path and the query are done above.
                break
            }
        }

        appendH2CommonHeaders(&block)
        return Data(block)
    }

    /// The header block of an upload POST: stream-up's (no `seq`) or a
    /// packet-up one (`seq` and its `contentLength`).
    func encodeH2UploadHeaders(seq: Int64?, contentLength: Int?) -> Data {
        var block: [UInt8] = []
        XHttpConnection.appendLiteral(&block, nameIndex: 1, value: configuration.host)

        let method = configuration.uplinkHTTPMethod
        switch method {
        case "POST":
            block.append(0x83)
        case "GET":
            block.append(0x82)
        default:
            XHttpConnection.appendLiteral(&block, nameIndex: 2, value: method)
        }

        var path = configuration.normalizedPath
        if !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = XHttpConnection.appendToPath(path, sessionId)
        }
        if let seq = seq, configuration.seqPlacement == .path {
            path = XHttpConnection.appendToPath(path, String(seq))
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            queryParts.append(configQuery)
        }
        if !sessionId.isEmpty && configuration.sessionPlacement == .query {
            queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if let seq = seq, configuration.seqPlacement == .query {
            queryParts.append("\(configuration.normalizedSeqKey)=\(seq)")
        }
        if !queryParts.isEmpty {
            path += "?" + queryParts.joined(separator: "&")
        }
        XHttpConnection.appendLiteral(&block, nameIndex: 4, value: path)
        block.append(0x87)

        // content-type only for stream-up (no seq), not for packet-up.
        if seq == nil && !configuration.noGrpcHeader {
            XHttpConnection.appendLiteral(&block, nameIndex: 31, value: "application/grpc")
        }
        if let contentLength = contentLength {
            XHttpConnection.appendLiteral(&block, nameIndex: 28, value: String(contentLength))
        }

        if !sessionId.isEmpty {
            let key = configuration.normalizedSessionKey
            switch configuration.sessionPlacement {
            case .header:
                XHttpConnection.appendNewName(&block, name: key.lowercased(), value: sessionId)
            case .cookie:
                XHttpConnection.appendLiteral(&block, nameIndex: 32, value: "\(key)=\(sessionId)")
            default:
                break
            }
        }

        if let seq = seq {
            let key = configuration.normalizedSeqKey
            switch configuration.seqPlacement {
            case .header:
                XHttpConnection.appendNewName(&block, name: key.lowercased(), value: String(seq))
            case .cookie:
                XHttpConnection.appendLiteral(&block, nameIndex: 32, value: "\(key)=\(seq)")
            default:
                break
            }
        }

        appendH2CommonHeaders(&block)
        return Data(block)
    }

    /// Hop-by-hop headers HTTP/2 forbids, and those written separately.
    private static let h2ForbiddenHeaders: Set<String> = [
        "host", "connection", "proxy-connection", "transfer-encoding",
        "upgrade", "keep-alive", "content-length", "user-agent",
    ]

    /// user-agent, the padding, then the configured headers.
    private func appendH2CommonHeaders(_ block: inout [UInt8]) {
        XHttpConnection.appendLiteral(&block, nameIndex: 58, value: userAgent)

        let padding = configuration.generatePadding()
        let paddingPath = configuration.normalizedPath
        if !configuration.xPaddingObfsMode {
            // referer, static-table entry 51.
            let referer = "https://\(configuration.host)\(paddingPath)?x_padding=\(padding)"
            XHttpConnection.appendLiteral(&block, nameIndex: 51, value: referer)
        } else {
            switch configuration.xPaddingPlacement {
            case .header:
                XHttpConnection.appendNewName(&block, name: configuration.xPaddingHeader.lowercased(), value: padding)
            case .queryInHeader:
                let value = "https://\(configuration.host)\(paddingPath)?\(configuration.xPaddingKey)=\(padding)"
                XHttpConnection.appendNewName(&block, name: configuration.xPaddingHeader.lowercased(), value: value)
            case .cookie:
                XHttpConnection.appendLiteral(&block, nameIndex: 32, value: "\(configuration.xPaddingKey)=\(padding)")
            default:
                break
            }
        }

        for key in configuration.headers.keys.sorted() {
            let lower = key.lowercased()
            if XHttpConnection.h2ForbiddenHeaders.contains(lower) { continue }
            XHttpConnection.appendNewName(&block, name: lower, value: configuration.headers[key] ?? "")
        }
    }

    /// Literal with incremental indexing, the name a static-table entry.
    private static func appendLiteral(_ block: inout [UInt8], nameIndex: Int, value: String) {
        block.append(contentsOf: HpackEncoder.literalWithIndexing(nameIndex: nameIndex))
        block.append(contentsOf: HpackEncoder.encodeString(value))
    }

    /// Literal with incremental indexing and a new name.
    private static func appendNewName(_ block: inout [UInt8], name: String, value: String) {
        block.append(0x40)
        block.append(contentsOf: HpackEncoder.encodeString(name))
        block.append(contentsOf: HpackEncoder.encodeString(value))
    }

    // MARK: - Data

    func send(_ data: Data) async throws {
        // An empty chunk would be chunked encoding's terminator, and an empty
        // POST carries nothing.
        if data.isEmpty { return }
        if mode == .packetUp {
            try await enqueuePacketUpSend(data)
            return
        }
        if session != nil {
            // stream-up sends on its upload POST, stream-one on its one stream.
            guard let stream = (mode == .streamUp ? pooledUploadStream() : pooledDownloadStream()) else {
                throw XHttpError.connectionClosed
            }
            try await stream.sendData(data)
            return
        }
        if mode == .streamOne {
            try await downloadStream().send(ChunkedTransferEncoder.encode(data))
        } else {
            guard let up = currentUpload() else {
                throw XHttpError.setupFailed("Upload connection not established")
            }
            try await up.send(ChunkedTransferEncoder.encode(data))
        }
    }

    private func pooledDownloadStream() -> Http2Stream? {
        lock.lock()
        defer { lock.unlock() }
        return pooledDownload
    }

    private func pooledUploadStream() -> Http2Stream? {
        lock.lock()
        defer { lock.unlock() }
        return pooledUpload
    }

    func receive() async throws -> Data? {
        if session != nil {
            guard let stream = pooledDownloadStream() else { return nil }
            let data = try await stream.receiveData()
            if data == nil { markH2Closed() }
            return data
        }

        if let chunk = try nextDecodedChunk() { return chunk }
        if decoderFinished { return nil }

        let stream = try downloadStream()
        while true {
            guard let data = try await stream.receive(), !data.isEmpty else {
                return nil
            }
            try feedDecoder(data)
            if let chunk = try nextDecodedChunk() { return chunk }
            if decoderFinished { return nil }
        }
    }

    private func markH2Closed() {
        lock.lock()
        h2StreamClosed = true
        lock.unlock()
    }

    private func feedDecoder(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        try chunkedDecoder.feed(data)
    }

    private func nextDecodedChunk() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return try chunkedDecoder.nextChunk()
    }

    private var decoderFinished: Bool {
        lock.lock()
        defer { lock.unlock() }
        return chunkedDecoder.isFinished
    }

    // MARK: - Packet-up

    private struct PacketBatch {
        let data: Data
        let completions: [TransportDeferred<Void>]
        let seq: Int64
    }

    /// Queues a write for the next batched POST and waits until it went out.
    /// Without the batching every send (every UDP datagram in particular)
    /// became its own HTTP request: a lot of overhead per packet and, on
    /// HTTP/2, a fast walk through the stream ids.
    private func enqueuePacketUpSend(_ data: Data) async throws {
        let completion = TransportDeferred<Void>()
        if try enqueue(data, completion) {
            schedulePacketUpFlush()
        }
        try await completion.wait()
    }

    private func enqueue(_ data: Data, _ completion: TransportDeferred<Void>) throws -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if !connected || (session != nil && h2StreamClosed) {
            throw XHttpError.connectionClosed
        }
        packetUpQueue.append((data, completion))
        if packetUpFlushPending { return false }
        packetUpFlushPending = true
        return true
    }

    /// A flush, scMinPostsIntervalMs after the last one began.
    private func schedulePacketUpFlush() {
        let interval = Int64(configuration.scMinPostsIntervalMs)
        let elapsed = millisecondsSinceLastFlush()
        let task = Task {
            if interval > 0 && elapsed < interval {
                try? await Task.sleep(nanoseconds: UInt64(interval - elapsed) * 1_000_000)
            }
            await self.flushPacketUpBatch()
        }
        lock.lock()
        flushTask = task
        lock.unlock()
    }

    private func millisecondsSinceLastFlush() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        if packetUpLastFlushTime == 0 { return Int64.max }
        let now = transportMonotonicNanos()
        if now < packetUpLastFlushTime { return 0 }
        return Int64((now - packetUpLastFlushTime) / 1_000_000)
    }

    /// Sends what is queued, up to scMaxEachPostBytes, as one POST, then
    /// carries on with the next batch if more was queued meanwhile.
    private func flushPacketUpBatch() async {
        guard let batch = takePacketBatch() else { return }
        var failure: Error?
        do {
            if session != nil {
                try await sendH2PacketUp(batch.data, firstSeq: batch.seq)
            } else {
                try await sendPacketUpHTTP11(batch.data, firstSeq: batch.seq)
            }
        } catch {
            failure = error
        }
        for completion in batch.completions {
            if let failure = failure {
                completion.fail(failure)
            } else {
                completion.complete(())
            }
        }
        if chainAfterFlush(failed: failure != nil) {
            schedulePacketUpFlush()
        }
    }

    private func takePacketBatch() -> PacketBatch? {
        lock.lock()
        if !connected || (session != nil && h2StreamClosed) {
            let pending = packetUpQueue
            packetUpQueue = []
            packetUpFlushPending = false
            lock.unlock()
            for (_, completion) in pending {
                completion.fail(XHttpError.connectionClosed)
            }
            return nil
        }
        if packetUpQueue.isEmpty {
            packetUpFlushPending = false
            lock.unlock()
            return nil
        }
        // The first write may exceed the limit on its own (it is split into
        // several POSTs below); otherwise stop before the limit so the next
        // flush picks up where this one left off.
        let maxSize = max(1, configuration.scMaxEachPostBytes)
        var size = 0
        var taken = 0
        while taken < packetUpQueue.count {
            let next = packetUpQueue[taken].0.count
            if taken > 0 && size + next > maxSize { break }
            size += next
            taken += 1
        }
        let collected = Array(packetUpQueue[0..<taken])
        packetUpQueue.removeFirst(taken)
        var merged = Data(capacity: size)
        for (chunk, _) in collected {
            merged.append(chunk)
        }
        let seq = nextSeq
        nextSeq += 1
        packetUpLastFlushTime = transportMonotonicNanos()
        lock.unlock()
        return PacketBatch(data: merged, completions: collected.map { $0.1 }, seq: seq)
    }

    private func chainAfterFlush(failed: Bool) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if failed || packetUpQueue.isEmpty {
            packetUpFlushPending = false
            return false
        }
        // packetUpFlushPending stays set: the next flush is already ours.
        return true
    }

    private func takeNextSeq() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        let seq = nextSeq
        nextSeq += 1
        return seq
    }

    /// `data` in pieces of at most scMaxEachPostBytes, the server's limit for
    /// one POST, each with its own sequence number.
    private func packetPieces(_ data: Data, firstSeq: Int64) -> [(Data, Int64)] {
        let bytes = [UInt8](data)
        let maxSize = max(1, configuration.scMaxEachPostBytes)
        if bytes.count <= maxSize { return [(data, firstSeq)] }
        var pieces: [(Data, Int64)] = []
        var offset = 0
        var seq = firstSeq
        while offset < bytes.count {
            let end = min(offset + maxSize, bytes.count)
            pieces.append((Data(bytes[offset..<end]), seq))
            offset = end
            if offset < bytes.count { seq = takeNextSeq() }
        }
        return pieces
    }

    /// HTTP/1.1: the POSTs go out back to back on the upload connection;
    /// their responses are drained by the task performPacketUpSetup started.
    private func sendPacketUpHTTP11(_ data: Data, firstSeq: Int64) async throws {
        guard let up = currentUpload() else {
            throw XHttpError.setupFailed("Upload connection not established")
        }
        for (piece, seq) in packetPieces(data, firstSeq: firstSeq) {
            try await up.send(buildSinglePost(piece, seq: seq))
        }
    }

    private func sendH2PacketUp(_ data: Data, firstSeq: Int64) async throws {
        for (piece, seq) in packetPieces(data, firstSeq: firstSeq) {
            try await sendH2Post(piece, seq: seq)
        }
    }

    /// One POST as a stream of the connection. Its reply (an empty 200) ends
    /// the stream by itself; nothing waits for it.
    private func sendH2Post(_ data: Data, seq: Int64) async throws {
        guard let session = session else { throw XHttpError.connectionClosed }
        let post = try await session.acquireStream("xhttp")
        guard registerPost(post) else {
            post.close()
            throw XHttpError.connectionClosed
        }
        do {
            try await post.openRequest(encodeH2UploadHeaders(seq: seq, contentLength: data.count),
                                       endStream: data.isEmpty, awaitResponse: false)
            if !data.isEmpty {
                try await post.sendLastData(data)
            }
        } catch {
            // A failure or a cancellation mid-send: RST_STREAM, so the
            // connection gets the slot back.
            unregisterPost(post)
            post.close()
            throw error
        }
        // Reads the reply out until the server ends the stream: that credits
        // the connection window for any body and drops the stream when done.
        Task {
            do {
                while true {
                    let chunk = try await post.receiveData()
                    if chunk == nil { break }
                }
            } catch {
                // A refused POST does not take the download down with it.
            }
            self.unregisterPost(post)
            post.close()
        }
    }

    private func registerPost(_ post: Http2Stream) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if !connected { return false }
        pooledPosts[ObjectIdentifier(post)] = post
        return true
    }

    private func unregisterPost(_ post: Http2Stream) {
        lock.lock()
        pooledPosts.removeValue(forKey: ObjectIdentifier(post))
        lock.unlock()
    }

    // MARK: - Close

    func close() {
        lock.lock()
        connected = false
        h2StreamClosed = true
        chunkedDecoder = ChunkedTransferDecoder()
        let posts = Array(pooledPosts.values)
        pooledPosts.removeAll()
        let up = upload
        upload = nil
        let pending = packetUpQueue
        packetUpQueue = []
        packetUpFlushPending = false
        let drain = uploadDrainTask
        uploadDrainTask = nil
        let flush = flushTask
        flushTask = nil
        let downloadRequest = pooledDownload
        let uploadRequest = pooledUpload
        lock.unlock()

        for (_, completion) in pending {
            completion.fail(XHttpError.connectionClosed)
        }
        drain?.cancel()
        flush?.cancel()
        download?.close()
        up?.close()
        downloadRequest?.close()
        uploadRequest?.close()
        for post in posts {
            post.close()
        }
        session?.close()
    }
}
