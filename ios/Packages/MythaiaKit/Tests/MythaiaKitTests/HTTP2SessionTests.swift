import Foundation
import XCTest
@testable import MythaiaKit

/// The server end of a session under test. What it sends goes straight into
/// the client's inbox, in call order; what the client sends is parsed into
/// frames as it arrives, the connection preface skipped.
final class HTTP2TestServer: @unchecked Sendable {
    static let prefaceSize = 24

    let pair = MemoryStreamPair()
    private let lock = NSLock()
    private let parsed = Http2Buffer()
    private var prefaceSkipped = false
    private var frames: [Http2Frame] = []
    private var reader: Task<Void, Never>?

    init() {
        let server = pair.server
        reader = Task { [weak self] in
            while true {
                guard let data = try? await server.receive() else { return }
                self?.ingest(data)
            }
        }
    }

    private func ingest(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        parsed.append(data)
        if !prefaceSkipped {
            if parsed.available < HTTP2TestServer.prefaceSize { return }
            parsed.skip(HTTP2TestServer.prefaceSize)
            prefaceSkipped = true
        }
        while let frame = Http2Framer.deserialize(parsed) {
            frames.append(frame)
        }
    }

    func serverSends(_ frame: Http2Frame) {
        pair.client.inject(Http2Framer.serialize(frame))
    }

    /// Every frame the client has sent so far.
    var sentFrames: [Http2Frame] {
        lock.lock()
        defer { lock.unlock() }
        return frames
    }

    func awaitFrame(timeout: Double = 3, _ match: (Http2Frame) -> Bool) async -> Http2Frame? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let frame = sentFrames.first(where: match) { return frame }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return nil
    }

    /// Every frame sent before this PING has been routed once its ACK is back.
    func awaitRouted() async -> Bool {
        let opaque = Data((0..<8).map { UInt8($0 * 17 + 3) })
        serverSends(Http2Framer.pingFrame(opaque))
        let ack = await awaitFrame { $0.type == .ping && $0.hasFlag(Http2FrameFlags.ack) && $0.payload == opaque }
        return ack != nil
    }

    func stop() {
        reader?.cancel()
        pair.client.close()
        pair.server.close()
    }
}

/// An Http2Session against a scripted server: what the connection does with
/// the frames real servers send.
final class HTTP2SessionTests: XCTestCase {

    private var sessions: [Http2Session] = []
    private var servers: [HTTP2TestServer] = []

    override func tearDown() {
        for session in sessions {
            session.close()
        }
        for server in servers {
            server.stop()
        }
        sessions = []
        servers = []
        super.tearDown()
    }

    private func hex(_ text: String) -> Data {
        TransportTestSupport.hex(text)
    }

    private func readySession(
        profile: Http2SessionProfile = .naive,
        keepalive: Bool = false,
        keepaliveIdleMs: Int64 = Http2Session.defaultKeepaliveIdleMs,
        keepaliveTimeoutMs: Int64 = Http2Session.defaultKeepaliveTimeoutMs
    ) -> (Http2Session, HTTP2TestServer) {
        let server = HTTP2TestServer()
        // The handshake waits for the server's SETTINGS.
        server.serverSends(Http2Framer.settingsFrame([]))
        let client = server.pair.client
        let session = Http2Session(profile: profile, keepalive: keepalive, keepaliveIdleMs: keepaliveIdleMs,
                                   keepaliveTimeoutMs: keepaliveTimeoutMs, dial: { client })
        sessions.append(session)
        servers.append(server)
        return (session, server)
    }

    private let requestHeaders = HpackEncoder.encodeHeaderBlock([
        HpackHeader(":method", "POST"),
        HpackHeader(":scheme", "https"),
        HpackHeader(":path", "/"),
        HpackHeader(":authority", "example.com"),
    ])

    /// A request stream, opened as gRPC and XHTTP open theirs: without
    /// waiting for the response.
    private func openRequest(_ session: Http2Session) async throws -> Http2Stream {
        let stream = try await session.acquireStream("test")
        try await stream.openRequest(requestHeaders, endStream: false, awaitResponse: false)
        return stream
    }

    private func goawayFrame(lastStreamID: Int, errorCode: Int) -> Http2Frame {
        var payload = Http2Framer.uint32Bytes(lastStreamID)
        payload.append(contentsOf: Http2Framer.uint32Bytes(errorCode))
        return Http2Frame(type: .goaway, flags: 0, streamID: 0, payload: Data(payload))
    }

    /// `x-foo: bar` as a literal with incremental indexing: it lands in the dynamic table at 62.
    private var insertXFoo: Data { hex("40 05 782d666f6f 03 626172") }

    private func isProtocolError(_ error: Error?) -> Bool {
        if case .some(.protocolError(_)) = error as? Http2Error { return true }
        return false
    }

    private func isConnectionFailed(_ error: Error?) -> Bool {
        if case .some(.connectionFailed(_)) = error as? Http2Error { return true }
        return false
    }

    private func readAll(_ stream: Http2Stream) async throws {
        while true {
            let chunk = try await stream.receiveData()
            if chunk == nil { return }
        }
    }

    // MARK: - HPACK state is per connection

    func testAHeaderBlockForAStreamAlreadyClosedHereStillFeedsTheHPACKTable() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session) // 1
        let gone = try await openRequest(session) // 3
        // Closed on our side; the server's reply for it was already on its way.
        gone.close()

        server.serverSends(Http2Framer.headersFrame(streamID: 3, headerBlock: insertXFoo))
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: hex("88"))) // :status 200
        // The trailers refer to the entry the dropped stream's block inserted.
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: hex("be"), endStream: true))

        let end = try await stream.receiveData()
        XCTAssertNil(end)
        XCTAssertEqual(stream.trailers, [HpackHeader("x-foo", "bar")])
    }

    func testAHeaderBlockThatDoesNotDecodeIsAConnectionError() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        // Index 100: nothing there. The table's state is unknowable after this.
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: hex("e4")))
        let error = await TransportTestSupport.error { _ = try await stream.receiveData() }
        XCTAssertTrue(isProtocolError(error), "\(String(describing: error))")
        let closed = await TransportTestSupport.waitUntil { session.isClosed }
        XCTAssertTrue(closed)
    }

    // MARK: - Padding, priority, CONTINUATION

    func testPaddedAndPrioritisedHeadersDecodeWithoutThosePaddingAndPriorityBytes() async throws {
        let (session, server) = readySession()
        let stream = try await session.acquireStream("test")
        let headers = requestHeaders
        let opened = Task { try await stream.openRequest(headers, endStream: false, awaitResponse: true) }
        let sent = await server.awaitFrame { $0.type == .headers && $0.streamID == 1 }
        XCTAssertNotNil(sent)

        // Pad length 3, a 5-byte priority block, `:status 200`, three bytes of padding.
        let payload = hex("03 0000000010 88 000000")
        let flags = Http2FrameFlags.endHeaders | Http2FrameFlags.padded | Http2FrameFlags.priority
        server.serverSends(Http2Frame(type: .headers, flags: flags, streamID: 1, payload: payload))

        try await opened.value
        XCTAssertTrue(stream.isConnected)
    }

    func testPaddedDataReachesTheApplicationWithoutItsPadding() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        var payload = hex("04")
        payload.append(Data("hello".utf8))
        payload.append(Data(count: 4))
        server.serverSends(Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: payload))
        let data = try await stream.receiveData()
        XCTAssertEqual(data, Data("hello".utf8))
    }

    func testPaddingLongerThanTheFrameIsAConnectionError() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(Http2Frame(type: .data, flags: Http2FrameFlags.padded, streamID: 1, payload: hex("09 61")))
        let error = await TransportTestSupport.error { _ = try await stream.receiveData() }
        XCTAssertTrue(isProtocolError(error), "\(String(describing: error))")
        let closed = await TransportTestSupport.waitUntil { session.isClosed }
        XCTAssertTrue(closed)
    }

    func testAHeaderBlockSplitOverContinuationIsDecodedOnceWhole() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        // `:status 200`, then `grpc-status: 7` as a literal with incremental
        // indexing, cut in the middle of the name: a gRPC Trailers-Only reply.
        let block = TransportTestSupport.bytes("88 40 0b 677270632d737461747573 01 37")
        server.serverSends(Http2Frame(type: .headers, flags: Http2FrameFlags.endStream, streamID: 1, payload: Data(block[0..<5])))
        server.serverSends(Http2Frame(type: .continuation, flags: Http2FrameFlags.endHeaders, streamID: 1, payload: Data(block[5...])))

        let end = try await stream.receiveData()
        XCTAssertNil(end)
        XCTAssertEqual(stream.trailers, [HpackHeader(":status", "200"), HpackHeader("grpc-status", "7")])
        // ...which the gRPC reader reports as the failure it is, not a clean end.
        let error = await TransportTestSupport.error { _ = try await GrpcTunnelStream(stream: stream, session: nil).receive() }
        XCTAssertEqual((error as? GrpcError)?.status, 7, "\(String(describing: error))")
    }

    func testAnotherFrameInsideAHeaderBlockIsAConnectionError() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(Http2Frame(type: .headers, flags: 0, streamID: 1, payload: hex("88")))
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: Data("x".utf8)))
        let error = await TransportTestSupport.error { _ = try await stream.receiveData() }
        XCTAssertTrue(isProtocolError(error), "\(String(describing: error))")
        let closed = await TransportTestSupport.waitUntil { session.isClosed }
        XCTAssertTrue(closed)
    }

    // MARK: - The end of a stream is reported for what it was

    func testAStreamResetMidDownloadFailsTheReaderInsteadOfEndingItCleanly() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: Data("part".utf8)))
        server.serverSends(Http2Framer.rstStreamFrame(streamID: 1, errorCode: Http2Framer.ErrorCode.cancel))
        // Whatever arrived before the reset may still be read; the end is the error.
        let error = await TransportTestSupport.error { try await self.readAll(stream) }
        XCTAssertEqual(error as? Http2Error, .streamReset(1))
        XCTAssertFalse(session.isClosed)
    }

    func testGoawayFailsTheStreamsTheServerNeverTookWithARetryableError() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(goawayFrame(lastStreamID: 0, errorCode: Http2Framer.ErrorCode.noError))
        let error = await TransportTestSupport.error { try await self.readAll(stream) }
        XCTAssertEqual(error as? Http2Error, .goaway)
        let closed = await TransportTestSupport.waitUntil { session.isClosed }
        XCTAssertTrue(closed)
    }

    func testARefusedRequestFailsItsReader() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(Http2Framer.headersFrame(streamID: 1, headerBlock: hex("8d"), endStream: true)) // :status 404
        let error = await TransportTestSupport.error { _ = try await stream.receiveData() }
        XCTAssertEqual(error as? Http2Error, .tunnelFailed("404"))
    }

    func testEndStreamIsStillACleanEndWithTheDataBeforeIt() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: Data("all".utf8)))
        server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: Data(), endStream: true))
        let data = try await stream.receiveData()
        XCTAssertEqual(data, Data("all".utf8))
        let end = try await stream.receiveData()
        XCTAssertNil(end)
    }

    // MARK: - Flow control

    func testDataNobodyReadsIsStillCreditedToTheConnectionWindow() async throws {
        // A small connection threshold stands in for the 64 MB of the real profile.
        let profile = Http2SessionProfile(settings: [], streamReceiveWindow: 1 << 24, connectionWindowIncrement: 1 << 20,
                                          connectionUpdateThreshold: 64 * 1024, headerTableSize: 4096, eagerStart: false)
        let (session, server) = readySession(profile: profile)
        let stream = try await openRequest(session)
        let chunk = Data(count: 1024)

        // 32 KB buffered on a stream the application then closes unread...
        for _ in 0..<32 {
            server.serverSends(Http2Framer.dataFrame(streamID: 1, payload: chunk))
        }
        let routed = await server.awaitRouted()
        XCTAssertTrue(routed)
        stream.close()
        // ...and 32 KB for a stream that is not there at all.
        for _ in 0..<32 {
            server.serverSends(Http2Framer.dataFrame(streamID: 7, payload: chunk))
        }

        // Together they reach the threshold, which is when the window is replenished.
        let update = await server.awaitFrame {
            $0.type == .windowUpdate && $0.streamID == 0 && Http2Framer.parseWindowUpdate($0.payload) == 64 * 1024
        }
        XCTAssertNotNil(update, "no WINDOW_UPDATE for the discarded data")
        // And the closed stream was reset, so the server stops sending on it.
        let reset = await server.awaitFrame { $0.type == .rstStream && $0.streamID == 1 }
        XCTAssertNotNil(reset)
    }

    func testASenderWaitsForTheServersWindowUpdate() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        // The default connection window is 65,535 bytes: 70,000 do not fit.
        let payload = Data(repeating: 0x7A, count: 70_000)
        let sending = Task { try await stream.sendData(payload) }

        let firstPart = await TransportTestSupport.waitUntil { self.dataBytes(server, streamID: 1) == 65_535 }
        XCTAssertTrue(firstPart)
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(dataBytes(server, streamID: 1), 65_535)

        server.serverSends(Http2Framer.windowUpdateFrame(streamID: 0, increment: 10_000))
        server.serverSends(Http2Framer.windowUpdateFrame(streamID: 1, increment: 10_000))
        try await sending.value
        let all = await TransportTestSupport.waitUntil { self.dataBytes(server, streamID: 1) == 70_000 }
        XCTAssertTrue(all)
    }

    private func dataBytes(_ server: HTTP2TestServer, streamID: Int) -> Int {
        server.sentFrames.filter { $0.type == .data && $0.streamID == streamID }.reduce(0) { $0 + $1.payload.count }
    }

    // MARK: - Lifecycle

    func testCloseDuringTheDialCancelsTheConnectionItWasWaitingFor() async throws {
        let server = HTTP2TestServer()
        servers.append(server)
        server.serverSends(Http2Framer.settingsFrame([]))
        let client = server.pair.client
        let dialStarted = TransportDeferred<Void>()
        let dialGate = TransportDeferred<Void>()
        let session = Http2Session(dial: {
            dialStarted.complete(())
            try await dialGate.wait()
            return client
        })
        sessions.append(session)

        let acquiring = Task { try await session.acquireStream("test") }
        try await dialStarted.wait()
        session.close()
        dialGate.complete(())

        let error = await TransportTestSupport.error { _ = try await acquiring.value }
        XCTAssertTrue(isConnectionFailed(error), "\(String(describing: error))")
        let cancelled = await TransportTestSupport.waitUntil { client.isClosed }
        XCTAssertTrue(cancelled)
        XCTAssertTrue(session.isClosed)
        XCTAssertFalse(session.hasCapacity)
    }

    func testASilentServerIsPingedAndThenGivenUpOn() async throws {
        let (session, server) = readySession(keepalive: true, keepaliveIdleMs: 200, keepaliveTimeoutMs: 200)
        let stream = try await openRequest(session)
        let ping = await server.awaitFrame { $0.type == .ping && !$0.hasFlag(Http2FrameFlags.ack) }
        XCTAssertNotNil(ping, "no keepalive PING")
        let closed = await TransportTestSupport.waitUntil { session.isClosed }
        XCTAssertTrue(closed)
        let error = await TransportTestSupport.error { _ = try await stream.receiveData() }
        XCTAssertTrue(isConnectionFailed(error), "\(String(describing: error))")
    }

    func testAServerThatAnswersTheKeepaliveKeepsTheConnection() async throws {
        let (session, server) = readySession(keepalive: true, keepaliveIdleMs: 100, keepaliveTimeoutMs: 200)
        _ = try await openRequest(session)
        let deadline = Date().addingTimeInterval(0.8)
        var answered = 0
        while Date() < deadline {
            let pings = server.sentFrames.filter { $0.type == .ping && !$0.hasFlag(Http2FrameFlags.ack) }
            while answered < pings.count {
                server.serverSends(Http2Framer.pingAckFrame(pings[answered].payload))
                answered += 1
            }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertGreaterThanOrEqual(answered, 1, "no keepalive PING in 800 ms")
        XCTAssertFalse(session.isClosed)
    }

    func testTheEndOfTheStreamIDSpaceClosesTheConnectionToNewStreams() async throws {
        let (session, _) = readySession()
        _ = try await openRequest(session)
        session.nextStreamID = 0x7FFF_FFFF
        let last = try await openRequest(session)
        XCTAssertEqual(last.streamID, 0x7FFF_FFFF)

        XCTAssertFalse(session.hasCapacity)
        XCTAssertNil(session.tryReserveStream("x"))
        let error = await TransportTestSupport.error { _ = try await session.acquireStream("x") }
        XCTAssertEqual(error as? Http2Error, .goaway)
    }

    func testTwoSendersOnOneStreamDoNotInterleaveTheirFrames() async throws {
        let (session, server) = readySession()
        let stream = try await openRequest(session)
        let a = Data(repeating: 0x61, count: 20_000)
        let b = Data(repeating: 0x62, count: 20_000)
        let first = Task { try await stream.sendData(a) }
        let second = Task { try await stream.sendData(b) }
        try await first.value
        try await second.value

        let all = await TransportTestSupport.waitUntil { self.dataBytes(server, streamID: 1) == 40_000 }
        XCTAssertTrue(all)
        let sent = server.sentFrames.filter { $0.type == .data && $0.streamID == 1 }
        XCTAssertEqual(sent.count, 4)
        let order = sent.compactMap { $0.payload.first }
        XCTAssertTrue(order == [0x61, 0x61, 0x62, 0x62] || order == [0x62, 0x62, 0x61, 0x61], "\(order)")
        var joined = Data()
        for frame in sent where frame.payload.first == 0x61 {
            joined.append(frame.payload)
        }
        XCTAssertEqual(joined, a)
    }

    // MARK: - The profile Xray's clients use

    func testAnEagerSessionOpensItsFirstStreamBeforeTheServersSettings() async throws {
        let server = HTTP2TestServer()
        servers.append(server)
        let client = server.pair.client
        let session = Http2Session(profile: .xrayClient(streamWindow: 4_194_304), dial: { client })
        sessions.append(session)

        // No SETTINGS from the server yet, and still the request goes out.
        _ = try await openRequest(session)
        let headers = await server.awaitFrame { $0.type == .headers && $0.streamID == 1 }
        XCTAssertNotNil(headers)

        // What the session opened with: no push, a 4 MB stream window, a 10 MB
        // header list, then a 1 GB connection window.
        let frames = server.sentFrames
        XCTAssertEqual(frames.first?.type, .settings)
        XCTAssertEqual(frames.first?.payload, hex("0002 00000000 0004 00400000 0006 00a00000"))
        XCTAssertEqual(frames.dropFirst().first?.type, .windowUpdate)
        XCTAssertEqual(frames.dropFirst().first.flatMap { Http2Framer.parseWindowUpdate($0.payload) }, 1_073_741_824)

        let settingsSeen = Task { try await session.awaitServerSettings() }
        server.serverSends(Http2Framer.settingsFrame([(0x4, 1_048_576)]))
        try await settingsSeen.value
        let ack = await server.awaitFrame { $0.type == .settings && $0.hasFlag(Http2FrameFlags.ack) }
        XCTAssertNotNil(ack)
        XCTAssertEqual(session.serverInitialWindowSize, 1_048_576)
    }
}
