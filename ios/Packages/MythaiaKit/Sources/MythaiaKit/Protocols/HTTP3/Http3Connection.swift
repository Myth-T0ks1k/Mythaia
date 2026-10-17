import Foundation

/// HTTP/3 over a QUIC connection.
///
/// Almost all of HTTP/3 is bookkeeping around two facts: each request gets its
/// own QUIC stream, and both ends must open a unidirectional control stream
/// and announce their settings on it before anything else counts. Get the
/// second one wrong and a compliant server closes the connection without
/// explaining why.
///
/// A narrow client — enough to carry a request and read the response, which
/// is what the protocols above it need. No push, no dynamic QPACK table, no
/// server-initiated requests.
///
/// Derived from the Anywhere reference implementation (GPL-3.0),
/// Copyright (C) 2026 NodePassProject.
final class Http3Connection: @unchecked Sendable {
    private let quic: QuicConnection
    /// What goes in our SETTINGS; see `Http3Framer.plainClientSettings`.
    private let settings: [Http3Setting]
    private let lock = NSLock()
    /// Our control stream, which stays open for the life of the connection:
    /// closing a control stream is a connection error in HTTP/3, not a tidy-up.
    private var controlStream: QuicStream?
    private var started = false

    init(quic: QuicConnection, settings: [Http3Setting] = Http3Framer.clientSettings) {
        self.quic = quic
        self.settings = settings
    }

    var isConnected: Bool { quic.isConnected }

    /// Brings HTTP/3 up over an already-connected QUIC connection: the control
    /// stream's type and SETTINGS go in one write, so a lost packet cannot
    /// separate them into a stream of unknown type.
    func start() async throws {
        lock.lock()
        if started {
            lock.unlock()
            return
        }
        started = true
        lock.unlock()
        guard quic.isConnected else { throw MythaiaError.closed }
        guard let control = quic.openUniStream() else {
            throw MythaiaError.protocolError("HTTP/3: no credit for a control stream")
        }
        lock.lock()
        controlStream = control
        lock.unlock()
        let opening = Http3Framer.uniStreamType(Http3Framer.streamTypeControl) + Http3Framer.clientSettingsFrame(settings)
        try await control.send(Data(opening))
    }

    /// Sends one request and returns the stream carrying its response. The
    /// headers go out at once; the body, if any, follows on the same stream.
    func request(headers: [UInt8], body: [UInt8]? = nil, fin: Bool = false) async throws -> QuicStream {
        guard let stream = quic.openStream() else {
            throw MythaiaError.protocolError("HTTP/3: no stream credit for a request")
        }
        do {
            try await stream.send(Data(Http3Framer.headersFrame(headers)))
            if let body = body, !body.isEmpty {
                try await stream.send(Data(Http3Framer.dataFrame(body)))
            }
            if fin {
                try await stream.finish()
            }
        } catch {
            stream.close()
            throw error
        }
        return stream
    }

    func close() {
        lock.lock()
        let control = controlStream
        controlStream = nil
        lock.unlock()
        control?.close()
    }
}
