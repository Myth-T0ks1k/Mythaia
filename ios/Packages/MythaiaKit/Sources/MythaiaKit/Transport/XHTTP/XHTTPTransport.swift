import Foundation

/// Xray's XHTTP transport (SplitHTTP): the tunnel as ordinary HTTP requests,
/// over HTTP/1.1 or HTTP/2. HTTP/3 needs QUIC under it and is not offered.
public enum XHTTPTransport {
    /// `dial` opens a fresh secured connection to the server; XHTTP may need several.
    ///
    /// `alpn` is the protocol the connections speak, as their TLS handshake
    /// settled it: "h2" for HTTP/2, anything else (or nil, plain TCP) for
    /// HTTP/1.1, "h3" refused. Over HTTP/2 every request is a stream of the
    /// first connection; over HTTP/1.1 stream-up and packet-up dial a second
    /// one for the upload. `authority` is the Host when the configuration
    /// names none. Mode "auto" is packet-up.
    public static func open(configuration: XHttpConfiguration, authority: String, alpn: String?,
                            dial: @escaping () async throws -> ByteStream) async throws -> ByteStream {
        let speaking = alpn?.lowercased()
        if speaking == "h3" {
            throw MythaiaError.unsupported("XHTTP over HTTP/3")
        }

        var settings = configuration
        if settings.host.isEmpty {
            settings.host = authority
        }
        let mode: XHttpMode = settings.mode == .auto ? .packetUp : settings.mode
        let sessionId = (mode == .packetUp || mode == .streamUp) ? UUID().uuidString.lowercased() : ""

        let first: ByteStream
        do {
            first = try await dial()
        } catch {
            throw TransportErrors.map(error)
        }

        if speaking == "h2" {
            let session = Http2Session(profile: .xrayClient(streamWindow: GrpcCodec.defaultStreamWindow),
                                       keepalive: true, dial: { first })
            let connection = XHttpConnection(session: session, configuration: settings, mode: mode, sessionId: sessionId)
            do {
                try await connection.performSetup()
                // Until the server's SETTINGS nothing proves an HTTP/2 server
                // answered; what else might be there fails here, not on the
                // first read.
                try await session.awaitServerSettings()
                return TransportErrorMappingStream(connection)
            } catch {
                connection.close()
                first.close()
                throw TransportErrors.map(error)
            }
        }

        let needsUpload = mode == .packetUp || mode == .streamUp
        let connection = XHttpConnection(download: first, configuration: settings, mode: mode, sessionId: sessionId,
                                         uploadFactory: needsUpload ? dial : nil)
        do {
            try await connection.performSetup()
            return TransportErrorMappingStream(connection)
        } catch {
            connection.close()
            throw TransportErrors.map(error)
        }
    }
}
